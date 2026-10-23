// Package selftest runs scheduled probes that prove tripline's own protections
// still work, and records each run as a selftest.result event.
package selftest

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
	"github.com/Parthkomalwad/tripline/internal/sinks"
	"github.com/Parthkomalwad/tripline/internal/tripwire"
)

// Probe results.
const (
	Pass = "pass"
	Fail = "fail"
	Skip = "skip"
)

const (
	source   = "watcher.selftest"
	sourceID = "watcher-selftest"
	// DefaultAllowHost is the allowlisted target of the egress-allow probe.
	DefaultAllowHost = "api.anthropic.com:443"
)

// Sensor is one egress sensor to probe. ID is its source_id.
type Sensor struct {
	ID       string `yaml:"id"`
	ProxyURL string `yaml:"proxy_url"`
}

// Runner schedules the probes. Fill the exported fields, register Observe on
// the watcher, then call Start.
type Runner struct {
	Sensors   []Sensor
	AllowHost string
	Interval  time.Duration
	Ingest    func(sensorID string, e *event.Event) error // (*watcher.Watcher).Ingest
	Alert     func(sinks.Alert)                           // (*sinks.Dispatcher).Send
	Registry  *tripwire.Registry
	Trap      http.Handler
	Log       *slog.Logger

	// Tests may change these.
	FirstDelay  time.Duration // default 10s
	DenyTimeout time.Duration // default 30s
	Now         func() time.Time

	mu      sync.Mutex
	waiters []*waiter
}

type waiter struct {
	match func(*event.Event) bool
	ch    chan struct{}
}

// Observe is a watcher observer. It must not block.
func (r *Runner) Observe(e *event.Event, _ []*rules.Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	keep := r.waiters[:0]
	for _, w := range r.waiters {
		if w.match(e) {
			close(w.ch)
			continue
		}
		keep = append(keep, w)
	}
	r.waiters = keep
}

// expect registers interest in an event. Call it before the action that
// causes the event.
func (r *Runner) expect(match func(*event.Event) bool) *waiter {
	w := &waiter{match, make(chan struct{})}
	r.mu.Lock()
	r.waiters = append(r.waiters, w)
	r.mu.Unlock()
	return w
}

func (r *Runner) await(w *waiter, timeout time.Duration) bool {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-w.ch:
		return true
	case <-t.C:
		r.mu.Lock()
		defer r.mu.Unlock()
		for i, x := range r.waiters {
			if x == w {
				r.waiters = append(r.waiters[:i], r.waiters[i+1:]...)
				break
			}
		}
		return false
	}
}

// Start runs the probes 10 seconds after the call and then every Interval,
// until ctx ends.
func (r *Runner) Start(ctx context.Context) {
	if r.FirstDelay == 0 {
		r.FirstDelay = 10 * time.Second
	}
	if r.Interval == 0 {
		r.Interval = time.Hour
	}
	go func() {
		t := time.NewTimer(r.FirstDelay)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.RunAll()
				t.Reset(r.Interval)
			}
		}
	}()
}

// RunAll runs every probe once and records the results.
func (r *Runner) RunAll() {
	for _, s := range r.Sensors {
		res, why := r.egressDeny(s)
		r.record("egress-deny", s.ID, res, why)
		res, why = r.egressAllow(s)
		r.record("egress-allow", s.ID, res, why)
	}
	res, why := r.trapAlive()
	r.record("trap-alive", "", res, why)
	r.record("bundle-current", "", Skip, "bundles arrive in M3") // ponytail: stub until M3
}

// record emits the selftest.result event and alerts on failure.
func (r *Runner) record(probe, sensorID, result, reason string) {
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	e := &event.Event{
		ID: fmt.Sprintf("evt_st_%d_%s_%s", now.UnixNano(), probe, sensorID), TS: now.UTC(),
		Source: source, SourceID: sourceID, Subject: sourceID,
		Kind: event.KindSelftestResult, Decision: event.DecisionNone,
		Attrs: map[string]any{"probe": probe, "result": result, "sensor_id": sensorID, "reason": reason},
	}
	if err := r.Ingest(sourceID, e); err != nil {
		r.Log.Error("selftest result not recorded", "probe", probe, "err", err)
	}
	if result != Fail {
		return
	}
	r.Log.Error("selftest failed", "probe", probe, "sensor_id", sensorID, "reason", reason)
	r.Alert(sinks.Alert{
		TraceID: e.ID, TS: e.TS, RuleID: "selftest." + probe, Severity: "high", Subject: sensorID,
		What: fmt.Sprintf("Self-test %s failed (sensor %q): %s", probe, sensorID, reason),
		Done: "nothing; this check only reports",
		Todo: "Check that the sensor and the trap are running and can reach the watcher. A failed check means a protection may be off.",
	})
}
