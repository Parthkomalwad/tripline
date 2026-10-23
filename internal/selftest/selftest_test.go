package selftest

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
	"github.com/Parthkomalwad/tripline/internal/sensor/egress"
	"github.com/Parthkomalwad/tripline/internal/sinks"
	"github.com/Parthkomalwad/tripline/internal/tripwire"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// rig is a runner wired like the watcher: Ingest feeds the observers.
type rig struct {
	r      *Runner
	mu     sync.Mutex
	events []*event.Event
	alerts []sinks.Alert
}

func newRig(t *testing.T) *rig {
	t.Helper()
	g := &rig{}
	reg, err := tripwire.LoadRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	g.r = &Runner{Registry: reg, Log: quiet, DenyTimeout: 2 * time.Second,
		Ingest: func(_ string, e *event.Event) error {
			if err := e.Validate(); err != nil {
				return err
			}
			g.mu.Lock()
			g.events = append(g.events, e)
			g.mu.Unlock()
			g.r.Observe(e, nil)
			return nil
		},
		Alert: func(a sinks.Alert) { g.mu.Lock(); g.alerts = append(g.alerts, a); g.mu.Unlock() },
	}
	g.r.Trap = &tripwire.Handler{Registry: reg, Log: quiet,
		Ingest: func(id string, e *event.Event) error { return g.r.Ingest(id, e) }}
	return g
}

func (g *rig) results() []*event.Event {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []*event.Event
	for _, e := range g.events {
		if e.Kind == event.KindSelftestResult {
			out = append(out, e)
		}
	}
	return out
}

// proxy starts an egress proxy whose events reach the runner. Pass mode ""
// for no rules (fail open, everything allowed).
func (g *rig) proxy(t *testing.T, id, mode, allowed string, deliver bool) string {
	t.Helper()
	send := func(e event.Event) {
		if deliver {
			g.r.Observe(&e, nil)
		}
	}
	p := egress.New(egress.Config{ID: id, Profile: "gateway-strict", FailMode: "open"}, send, quiet)
	if mode != "" {
		rs, err := rules.Parse([]byte(`id: egress-allowlist
applies_to: { source: sensor.egress, profile: gateway-strict }
match: { kind: egress.connect, host_not_in: ["` + allowed + `"] }
severity: high
mode: ` + mode + `
on_match: [alert, block]
`))
		if err != nil {
			t.Fatal(err)
		}
		p.SetRules(rs)
	}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return srv.URL
}

func listener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().String()
}

func TestEgressDenyPasses(t *testing.T) {
	for _, mode := range []string{"monitor", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			g := newRig(t)
			u := g.proxy(t, "gw1", mode, "api.anthropic.com", true)
			res, why := g.r.egressDeny(Sensor{"gw1", u})
			if res != Pass {
				t.Fatalf("%s: %s", res, why)
			}
		})
	}
}

func TestEgressDenyFailsWhenEventNeverArrives(t *testing.T) {
	g := newRig(t)
	g.r.DenyTimeout = 100 * time.Millisecond
	u := g.proxy(t, "gw1", "enforce", "api.anthropic.com", false)
	res, why := g.r.egressDeny(Sensor{"gw1", u})
	if res != Fail || !strings.Contains(why, "within") {
		t.Fatalf("%s: %s", res, why)
	}
	if len(g.r.waiters) != 0 {
		t.Fatal("waiter leaked")
	}
}

func TestEgressDenyIgnoresOtherSensor(t *testing.T) {
	g := newRig(t)
	g.r.DenyTimeout = 100 * time.Millisecond
	u := g.proxy(t, "other", "enforce", "api.anthropic.com", true)
	if res, _ := g.r.egressDeny(Sensor{"gw1", u}); res != Fail {
		t.Fatal("event from another sensor must not count")
	}
}

func TestEgressDenyFailsWhenAllowed(t *testing.T) {
	g := newRig(t)
	g.r.DenyTimeout = 100 * time.Millisecond
	u := g.proxy(t, "gw1", "", "", true) // no rules: decision allow
	if res, _ := g.r.egressDeny(Sensor{"gw1", u}); res != Fail {
		t.Fatal("an allow decision must fail the probe")
	}
}

func TestEgressAllow(t *testing.T) {
	g := newRig(t)
	target := listener(t)
	host, _, _ := net.SplitHostPort(target)
	g.r.AllowHost = target
	u := g.proxy(t, "gw1", "enforce", host, true)
	if res, why := g.r.egressAllow(Sensor{"gw1", u}); res != Pass {
		t.Fatalf("%s: %s", res, why)
	}
	u = g.proxy(t, "gw2", "enforce", "api.anthropic.com", true) // target not allowed
	if res, _ := g.r.egressAllow(Sensor{"gw2", u}); res != Fail {
		t.Fatal("denied allow-host must fail")
	}
}

func TestTrapAliveNoAlert(t *testing.T) {
	g := newRig(t)
	for i := 0; i < 2; i++ { // second run reuses the decoy
		if res, why := g.r.trapAlive(); res != Pass {
			t.Fatalf("%s: %s", res, why)
		}
	}
	n := 0
	for _, e := range g.events {
		if e.Kind == event.KindTripwireHit {
			n++
		}
	}
	if n != 2 || len(g.alerts) != 0 {
		t.Fatalf("hits %d alerts %d", n, len(g.alerts))
	}
	decoys := 0
	if _, ok := g.r.Registry.Selftest(); ok {
		decoys++
	}
	if decoys != 1 {
		t.Fatal("selftest decoy not registered")
	}
}

func TestRunAllRecordsAndAlertsOnFailure(t *testing.T) {
	g := newRig(t)
	g.r.DenyTimeout = 50 * time.Millisecond
	target := listener(t)
	g.r.AllowHost = target
	g.r.Sensors = []Sensor{{"gw1", g.proxy(t, "gw1", "enforce", "api.anthropic.com", false)}} // events dropped
	g.r.RunAll()
	got := map[string]string{}
	for _, e := range g.results() {
		got[e.Attrs["probe"].(string)] = e.Attrs["result"].(string)
		if e.Source != "watcher.selftest" || e.SourceID != "watcher-selftest" {
			t.Fatalf("bad source %+v", e)
		}
	}
	want := map[string]string{"egress-deny": Fail, "egress-allow": Fail, "trap-alive": Pass, "bundle-current": Skip}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(g.alerts) != 2 || g.alerts[0].Severity != "high" || g.alerts[0].What == "" || g.alerts[0].Done == "" || g.alerts[0].Todo == "" {
		t.Fatalf("alerts %+v", g.alerts)
	}
}

func TestStartRunsAfterFirstDelay(t *testing.T) {
	g := newRig(t)
	g.r.FirstDelay, g.r.Interval = 10*time.Millisecond, time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.r.Start(ctx)
	for i := 0; i < 200 && len(g.results()) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if len(g.results()) == 0 {
		t.Fatal("no run")
	}
}

func TestSelftestEventsNeverAlert(t *testing.T) {
	d := sinks.New(nil, quiet, func(string) string { return "" })
	rs, err := rules.Parse([]byte(`id: any-hit
severity: critical
on_match: [alert]
match:
  kind: tripwire.hit
`))
	if err != nil {
		t.Fatal(err)
	}
	e := &event.Event{Kind: event.KindTripwireHit, Attrs: map[string]any{"selftest": true}}
	d.Observe(e, rs)
	if d.Queued.Load() != 0 {
		t.Fatal("selftest event alerted")
	}
	e.Attrs["selftest"] = false
	d.Observe(e, rs)
	if d.Queued.Load() != 1 {
		t.Fatal("real event must alert")
	}
}

func TestProxyRespondsPerDecision(t *testing.T) {
	g := newRig(t)
	for mode, want := range map[string]int{"enforce": http.StatusForbidden, "monitor": http.StatusBadGateway} {
		u := g.proxy(t, "gw1", mode, "api.anthropic.com", true)
		code, err := connect(u, egress.SelftestHost+":443")
		if err != nil || code != want {
			t.Fatalf("%s: %d %v, want %d", mode, code, err, want)
		}
	}
}
