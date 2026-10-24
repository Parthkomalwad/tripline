package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
)

func ev(id string) event.Event {
	// Second precision keeps every event the same length, so byte caps are exact.
	return event.Event{ID: id, TS: time.Now().UTC().Truncate(time.Second), Source: "sensor.egress", SourceID: "s1",
		Subject: "s1", Kind: event.KindEgressConnect, Decision: event.DecisionAllow}
}

type recv struct {
	mu   sync.Mutex
	ids  []string
	auth string
}

func (r *recv) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	var evs []event.Event
	_ = json.Unmarshal(b, &evs)
	r.mu.Lock()
	r.auth = req.Header.Get("Authorization")
	for _, e := range evs {
		r.ids = append(r.ids, e.ID)
	}
	r.mu.Unlock()
	w.Write([]byte(`{"accepted":1}`))
}

func (r *recv) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ids...)
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func TestSendAndHeartbeat(t *testing.T) {
	r := &recv{}
	srv := httptest.NewServer(r)
	defer srv.Close()
	c := New(Config{URL: srv.URL, Token: "tok", Source: "sensor.egress", SourceID: "s1", Subject: "s1",
		FlushEvery: 10 * time.Millisecond, HeartbeatEvery: 30 * time.Millisecond})
	defer c.Close()
	c.Send(ev("evt_a"))
	waitFor(t, func() bool { return len(r.got()) >= 2 }) // event plus a heartbeat
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.auth != "Bearer tok" {
		t.Fatalf("auth header %q", r.auth)
	}
}

func TestBufferThenResend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "buf.jsonl")
	r := &recv{}
	var mu sync.Mutex
	down := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		mu.Lock()
		d := down
		mu.Unlock()
		if d {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		r.ServeHTTP(w, q)
	}))
	defer srv.Close()
	c := New(Config{URL: srv.URL, Token: "tok", SourceID: "s1", BufferPath: path, BufferMax: 1 << 20,
		FlushEvery: 10 * time.Millisecond, HeartbeatEvery: time.Hour})
	defer c.Close()
	c.Send(ev("evt_1"))
	c.Send(ev("evt_2"))
	waitFor(t, func() bool { fi, err := os.Stat(path); return err == nil && fi.Size() > 0 })
	mu.Lock()
	down = false
	mu.Unlock()
	c.Send(ev("evt_3"))
	waitFor(t, func() bool { return len(r.got()) == 3 })
	if got := r.got(); got[0] != "evt_1" || got[2] != "evt_3" {
		t.Fatalf("order %v", got)
	}
	waitFor(t, func() bool { _, err := os.Stat(path); return os.IsNotExist(err) })
}

func TestBufferCapDropsOldest(t *testing.T) {
	b := &buffer{path: filepath.Join(t.TempDir(), "b.jsonl")}
	one, _ := json.Marshal(ev("evt_0"))
	b.max = int64(len(one)+1) * 3
	var evs []event.Event
	for _, id := range []string{"evt_0", "evt_1", "evt_2", "evt_3", "evt_4"} {
		evs = append(evs, ev(id))
	}
	if err := b.replace(evs); err != nil {
		t.Fatal(err)
	}
	got, _ := b.load()
	if len(got) != 3 || got[0].ID != "evt_2" || b.dropped.Load() != 2 {
		t.Fatalf("got %d events dropped %d", len(got), b.dropped.Load())
	}
}
