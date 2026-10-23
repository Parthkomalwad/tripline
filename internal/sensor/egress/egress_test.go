package egress

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Parthkomalwad/tripline/internal/client"
	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func ruleSet(t *testing.T, mode, allowed string) []*rules.Rule {
	t.Helper()
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
	return rs
}

type sink struct {
	mu  sync.Mutex
	evs []event.Event
}

func (s *sink) send(e event.Event) { s.mu.Lock(); s.evs = append(s.evs, e); s.mu.Unlock() }
func (s *sink) all() []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]event.Event(nil), s.evs...)
}

func newProxy(send func(event.Event)) (*Proxy, *httptest.Server) {
	p := New(Config{ID: "gw1", Profile: "gateway-strict", FailMode: "open"}, send, quiet)
	p.IdleTimeout = 2 * time.Second
	return p, httptest.NewServer(p)
}

// echoServer listens on a local port and echoes every byte back.
func echoServer(t *testing.T) string {
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
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// connect sends CONNECT through the proxy and returns the status and the conn.
func connect(t *testing.T, proxyURL, target string) (int, net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(proxyURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, c, br
}

func echoes(t *testing.T, c net.Conn, br *bufio.Reader) {
	t.Helper()
	io.WriteString(c, "ping\n")
	line, err := br.ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Fatalf("tunnel echo %q err %v", line, err)
	}
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

func TestConnectAllowedTunnels(t *testing.T) {
	addr := echoServer(t)
	s := &sink{}
	p, srv := newProxy(s.send)
	defer srv.Close()
	p.SetRules(ruleSet(t, "enforce", "127.0.0.1"))
	code, c, br := connect(t, srv.URL, addr)
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	echoes(t, c, br)
	evs := s.all()
	if len(evs) != 1 || evs[0].Decision != event.DecisionAllow || evs[0].Kind != event.KindEgressConnect {
		t.Fatalf("events %+v", evs)
	}
	if evs[0].Validate() != nil {
		t.Fatal(evs[0].Validate())
	}
}

func TestEnforceDenies(t *testing.T) {
	s := &sink{}
	p, srv := newProxy(s.send)
	defer srv.Close()
	p.SetRules(ruleSet(t, "enforce", "api.anthropic.com"))
	code, _, _ := connect(t, srv.URL, "evil.example:443")
	if code != http.StatusForbidden {
		t.Fatalf("status %d", code)
	}
	evs := s.all()
	if len(evs) != 1 || evs[0].Decision != event.DecisionDeny || evs[0].RuleID != "egress-allowlist" ||
		evs[0].Attrs["host"] != "evil.example" || evs[0].Attrs["port"] != 443 {
		t.Fatalf("events %+v", evs)
	}
}

func TestMonitorTunnelsAndObserves(t *testing.T) {
	addr := echoServer(t)
	s := &sink{}
	p, srv := newProxy(s.send)
	defer srv.Close()
	p.SetRules(ruleSet(t, "monitor", "api.anthropic.com"))
	code, c, br := connect(t, srv.URL, addr)
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	echoes(t, c, br)
	if evs := s.all(); len(evs) != 1 || evs[0].Decision != event.DecisionObserve {
		t.Fatalf("events %+v", evs)
	}
}

func TestNonConnectIs405AndBadPortIs400(t *testing.T) {
	p, srv := newProxy(func(event.Event) {})
	defer srv.Close()
	p.SetRules(ruleSet(t, "enforce", "x"))
	resp, err := http.Get(srv.URL + "/")
	if err != nil || resp.StatusCode != 405 {
		t.Fatalf("GET: %v %v", resp, err)
	}
	if code, _, _ := connect(t, srv.URL, "example.com:0"); code != 400 {
		t.Fatalf("port 0 status %d", code)
	}
}

func TestAggregation(t *testing.T) {
	s := &sink{}
	p, srv := newProxy(s.send)
	defer srv.Close()
	p.SetRules(ruleSet(t, "enforce", "api.anthropic.com"))
	for i := 0; i < 5; i++ {
		connect(t, srv.URL, "evil.example:443")
	}
	connect(t, srv.URL, "other.example:443") // different host, own event
	if n := len(s.all()); n != 2 {
		t.Fatalf("want 2 immediate events, got %d", n)
	}
	p.flushAgg(time.Now()) // window still open: nothing yet
	if n := len(s.all()); n != 2 {
		t.Fatalf("flush inside window sent events: %d", n)
	}
	p.flushAgg(time.Now().Add(2 * time.Minute))
	evs := s.all()
	if len(evs) != 3 {
		t.Fatalf("want 3 events, got %d", len(evs))
	}
	last := evs[2]
	if last.Attrs["host"] != "evil.example" || last.Attrs["count"] != 4 || last.Attrs["aggregated"] != true {
		t.Fatalf("summary %+v", last)
	}
}

func TestFailModeNoRules(t *testing.T) {
	addr := echoServer(t)
	p, srv := newProxy(func(event.Event) {})
	defer srv.Close()
	code, c, br := connect(t, srv.URL, addr) // fail_mode open: allow all
	if code != 200 {
		t.Fatalf("open: status %d", code)
	}
	echoes(t, c, br)
	p.cfg.FailMode = "closed"
	if code, _, _ := connect(t, srv.URL, addr); code != 403 {
		t.Fatalf("closed: status %d", code)
	}
}

func TestRunFailOpenEmitsCritical(t *testing.T) {
	var mu sync.Mutex
	var got []event.Event
	watcher := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var evs []event.Event
		json.NewDecoder(r.Body).Decode(&evs)
		mu.Lock()
		got = append(got, evs...)
		mu.Unlock()
		w.Write([]byte(`{}`))
	}))
	defer watcher.Close()
	t.Setenv("TEST_SENSOR_TOKEN", "tok")
	dir := t.TempDir()
	cfg := &Config{ID: "gw1", WatcherURL: watcher.URL, TokenEnv: "TEST_SENSOR_TOKEN", Listen: "127.0.0.1:0",
		Profile: "gateway-strict", RulesFile: filepath.Join(dir, "missing.yaml"), StateDir: dir,
		BufferMaxBytes: 1 << 20, FailMode: "open"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- Run(ctx, cfg, quiet) }()
	waitFor(t, func() bool {
		cancel() // client.Close at shutdown flushes the queue
		select {
		case <-done:
			return true
		case <-time.After(20 * time.Millisecond):
			return false
		}
	})
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Kind != event.KindBundleRejected || got[0].Attrs["severity"] != "critical" {
		t.Fatalf("events %+v", got)
	}
}

// TestWatcherDownEnforcementContinues kills the watcher before any traffic.
// Deny still works, events reach the disk buffer, and arrive when it returns.
func TestWatcherDownEnforcementContinues(t *testing.T) {
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := probe.Addr().String()
	probe.Close() // nothing listens on addr now

	bufPath := filepath.Join(t.TempDir(), "events.jsonl")
	cl := client.New(client.Config{URL: "http://" + addr, Token: "tok", Source: sourceName, SourceID: "gw1",
		Subject: "gw1", BufferPath: bufPath, BufferMax: 1 << 20, FlushEvery: 10 * time.Millisecond,
		HeartbeatEvery: time.Hour, Log: quiet})
	defer cl.Close()
	p, srv := newProxy(cl.Send)
	defer srv.Close()
	p.SetRules(ruleSet(t, "enforce", "api.anthropic.com"))

	for i := 0; i < 2; i++ {
		if code, _, _ := connect(t, srv.URL, "evil.example:443"); code != 403 {
			t.Fatalf("watcher down: status %d", code)
		}
	}
	waitFor(t, func() bool { fi, err := os.Stat(bufPath); return err == nil && fi.Size() > 0 })

	var mu sync.Mutex
	var got []event.Event
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skip("cannot reuse port:", err)
	}
	w := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var evs []event.Event
		json.NewDecoder(r.Body).Decode(&evs)
		mu.Lock()
		got = append(got, evs...)
		mu.Unlock()
		rw.Write([]byte(`{}`))
	}))
	w.Listener = ln
	w.Start()
	defer w.Close()

	connect(t, srv.URL, "evil.example:443") // triggers a flush after the watcher returns
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) >= 1 && func() bool { _, err := os.Stat(bufPath); return os.IsNotExist(err) }()
	})
	mu.Lock()
	defer mu.Unlock()
	if got[0].Decision != event.DecisionDeny {
		t.Fatalf("delivered %+v", got[0])
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(path, []byte("watcher: {state_dir: x, unknown_key: 1}\nsensor:\n  id: s1\n  watcher_url: http://w\n  token_env: T\n  profile: gateway-strict\n  rules_file: r.yaml\n  state_dir: d\n"), 0o600)
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8080" || c.BufferMaxBytes != 50<<20 || c.FailMode != "open" {
		t.Fatalf("defaults %+v", c)
	}
	os.WriteFile(path, []byte("sensor: {id: s1, fail_mode: maybe}\n"), 0o600)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("bad fail_mode accepted")
	}
}

func TestStarterRulesLoad(t *testing.T) {
	rs, err := LoadRules("../../../rules/profiles/gateway-strict.yaml")
	if err != nil || len(rs) != 1 || rs[0].Mode != rules.ModeMonitor {
		t.Fatalf("%v %v", rs, err)
	}
}

func TestHistogram(t *testing.T) {
	var h Histogram
	h.Observe(500 * time.Microsecond)
	h.Observe(5 * time.Second)
	cum, _ := h.Snapshot()
	if cum[0] != 1 || cum[len(cum)-1] != 2 {
		t.Fatalf("%v", cum)
	}
}
