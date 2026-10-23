package sinks

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

func testEvent() (*event.Event, []*rules.Rule) {
	rs, err := rules.Parse([]byte("id: trap\nseverity: high\non_match: [alert, page]\nrunbook: https://rb.example/trap\nmatch: {kind: tripwire.hit}\n"))
	if err != nil {
		panic(err)
	}
	e := &event.Event{ID: "evt-123", TS: time.Date(2026, 10, 21, 11, 0, 0, 0, time.UTC),
		Source: "trap", SourceID: "s1", Subject: "gw", Kind: event.KindTripwireHit, Decision: event.DecisionObserve,
		Attrs: map[string]any{"host": "evil.example", "decoy_kind": "env", "token": "SECRETVALUE", "prompt": "PROMPTTEXT"}}
	return e, rules.Evaluate(rs, e)
}

func run(t *testing.T, d *Dispatcher, e *event.Event, m []*rules.Rule) {
	t.Helper()
	d.Backoff = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)
	d.Observe(e, m)
	cancel()
	select {
	case <-d.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop")
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestDeliver(t *testing.T) {
	var mu sync.Mutex
	var hook, slack []byte
	mk := func(dst *[]byte) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("content type %q", r.Header.Get("Content-Type"))
			}
			mu.Lock()
			*dst = b
			mu.Unlock()
		}))
	}
	hs, ss := mk(&hook), mk(&slack)
	defer hs.Close()
	defer ss.Close()
	env := map[string]string{"H": hs.URL, "S": ss.URL}
	d := New([]Spec{{"webhook", "H"}, {"slack", "S"}}, quiet(), func(k string) string { return env[k] })
	var out bytes.Buffer
	d.Stdout = &out
	e, m := testEvent()
	run(t, d, e, m)

	var a Alert
	if err := json.Unmarshal(hook, &a); err != nil {
		t.Fatalf("webhook body: %v", err)
	}
	if a.TraceID != "evt-123" || !a.Page || a.Severity != "high" || a.Runbook != "https://rb.example/trap" ||
		a.Done != "nothing blocked (monitor mode)" || a.RuleID != "trap" {
		t.Errorf("alert %+v", a)
	}
	var s struct {
		Text   string
		Blocks []struct {
			Type string
			Text struct{ Type, Text string }
		}
	}
	if err := json.Unmarshal(slack, &s); err != nil {
		t.Fatalf("slack body: %v", err)
	}
	if len(s.Blocks) != 1 || s.Blocks[0].Type != "section" || s.Blocks[0].Text.Type != "mrkdwn" || s.Blocks[0].Text.Text != s.Text {
		t.Errorf("slack shape %+v", s)
	}
	for name, txt := range map[string]string{"slack": s.Text, "webhook": string(hook), "stdout": out.String()} {
		if !strings.Contains(txt, "evt-123") || !strings.Contains(txt, "evil.example") || !strings.Contains(txt, "env") {
			t.Errorf("%s missing trace, host or decoy kind: %s", name, txt)
		}
		if strings.Contains(txt, "SECRETVALUE") || strings.Contains(txt, "PROMPTTEXT") {
			t.Errorf("%s leaks attrs: %s", name, txt)
		}
	}
	if d.Sent.Load() != 3 || d.Failed.Load() != 0 {
		t.Errorf("sent %d failed %d", d.Sent.Load(), d.Failed.Load())
	}
}

func TestRetry(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			http.Error(w, "boom", 500)
		}
	}))
	defer srv.Close()
	d := New([]Spec{{"webhook", "H"}}, quiet(), func(string) string { return srv.URL })
	d.Stdout = io.Discard
	e, m := testEvent()
	run(t, d, e, m)
	if n.Load() != 3 || d.Failed.Load() != 0 {
		t.Errorf("calls %d failed %d", n.Load(), d.Failed.Load())
	}

	n.Store(-100) // always 500
	d2 := New([]Spec{{"webhook", "H"}}, quiet(), func(string) string { return srv.URL })
	d2.Stdout = io.Discard
	run(t, d2, e, m)
	if d2.Failed.Load() != 1 {
		t.Errorf("failed %d, want 1", d2.Failed.Load())
	}
}

func TestMissingEnvSkipped(t *testing.T) {
	var logs bytes.Buffer
	d := New([]Spec{{"slack", "NO_SUCH_ENV"}}, slog.New(slog.NewTextHandler(&logs, nil)), func(string) string { return "" })
	if d.Skipped.Load() != 1 || len(d.sinks) != 1 || d.sinks[0].name != "stdout" {
		t.Errorf("skipped %d sinks %d", d.Skipped.Load(), len(d.sinks))
	}
	if !strings.Contains(logs.String(), "NO_SUCH_ENV") {
		t.Errorf("log lacks env name: %s", logs.String())
	}
}

func TestQueueFullAndNoAlertAction(t *testing.T) {
	d := New(nil, quiet(), nil)
	for i := 0; i < queueSize+5; i++ {
		d.Send(Alert{TraceID: "x"})
	}
	if d.Dropped.Load() != 5 {
		t.Errorf("dropped %d", d.Dropped.Load())
	}
	e, _ := testEvent()
	rs, _ := rules.Parse([]byte("id: b\nseverity: low\non_match: [block]\nmatch: {kind: tripwire.hit}\n"))
	d2 := New(nil, quiet(), nil)
	d2.Observe(e, rs)
	if d2.Queued.Load() != 0 {
		t.Error("block-only rule queued an alert")
	}
}
