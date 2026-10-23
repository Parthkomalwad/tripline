package watcher

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

const watcherChain = `
id: chain
correlate:
  within: 5m
  sequence:
    - kind: secret.read
    - kind: egress.connect
      decision_in: [deny]
severity: critical
on_match: [alert]
`

func TestStartCorrelation(t *testing.T) {
	rs, err := rules.Parse([]byte(watcherChain))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	ts := time.Now()
	mk := func(id string, k event.Kind, d event.Decision, at time.Duration) *event.Event {
		return &event.Event{ID: id, TS: ts.Add(at), Source: "s", SourceID: "s1", Subject: "gw", Kind: k, Decision: d}
	}

	ctx, stop := context.WithCancel(context.Background())
	w := &Watcher{Log: log}
	w.SetRules(rs)
	StartCorrelation(ctx, w, dir, log, func(rules.Chain) { t.Error("no chain expected yet") })
	if err := w.Ingest("s1", mk("a", event.KindSecretRead, event.DecisionNone, 0)); err != nil {
		t.Fatal(err)
	}
	stop() // shutdown saves state
	file := filepath.Join(dir, "correlation.json")
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(file); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A restarted watcher completes the chain from the saved partial.
	var got []rules.Chain
	w2 := &Watcher{Log: log}
	w2.SetRules(rs)
	StartCorrelation(context.Background(), w2, dir, log, func(c rules.Chain) { got = append(got, c) })
	if err := w2.Ingest("s1", mk("b", event.KindEgressConnect, event.DecisionDeny, 2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].TraceID() != "a" {
		t.Fatalf("chains = %+v", got)
	}
}
