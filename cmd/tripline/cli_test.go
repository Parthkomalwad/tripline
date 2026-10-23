package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Parthkomalwad/tripline/internal/watcher"
)

func do(args ...string) (int, string, string) {
	var o, e bytes.Buffer
	code := run(args, &o, &e)
	return code, o.String(), e.String()
}

func writeCfg(t *testing.T, status string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	y := "watcher:\n  state_dir: " + filepath.ToSlash(filepath.Join(dir, "state")) + "\n  status_page: " + status + "\n"
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSensorAddTwiceFails(t *testing.T) {
	cfg := writeCfg(t, "127.0.0.1:1")
	code, out, errOut := do("sensor", "add", "-config", cfg, "s1")
	if code != 0 || !strings.HasPrefix(strings.TrimSpace(out), "tlsen_") || !strings.Contains(errOut, "securely") {
		t.Fatalf("first add = %d %q %q", code, out, errOut)
	}
	code, out, _ = do("sensor", "add", "-config", cfg, "s1")
	if code != 1 || out != "" {
		t.Errorf("second add = %d %q, want 1 and no token", code, out)
	}
}

func TestInit(t *testing.T) {
	dir := t.TempDir()
	code, out, errOut := do("init", "-dir", dir)
	if code != 0 || !strings.Contains(out, "tlsen_") {
		t.Fatalf("init = %d %q %q", code, out, errOut)
	}
	cfg, err := watcher.LoadConfig(filepath.Join(dir, "tripline.yaml"))
	if err != nil {
		t.Fatalf("starter config does not load: %v", err)
	}
	if cfg.Watcher.TrapListen == "" || cfg.Watcher.RulesFile == "" {
		t.Errorf("trap_listen or rules_file missing: %+v", cfg.Watcher)
	}
	if _, err := os.Stat(filepath.Join(dir, "tripline-state", "sensors.json")); err != nil {
		t.Errorf("no sensor token file: %v", err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "tripline.yaml"))
	code, out, _ = do("init", "-dir", dir)
	after, _ := os.ReadFile(filepath.Join(dir, "tripline.yaml"))
	if code != 1 || out != "" || !bytes.Equal(before, after) {
		t.Errorf("second init = %d %q, want refusal", code, out)
	}
}

const statusJSON = `{"bundle_version":3,
"sources":[{"source_id":"a1","source":"claude-code","last_heartbeat":"2026-01-01T00:00:00Z","silent":true},
{"source_id":"b2","source":"mcp","last_heartbeat":"2026-01-01T00:01:00Z","silent":false}],
"coverage":[{"sensor_type":"file","active":1,"gap":false},{"sensor_type":"network","active":0,"gap":true}],
"selftest_pass_rate_7d":null,
"recent_alerts":[{"ts":"t1","rule_id":"r1","severity":"high","trace_id":"trace-abc","subject":"sub1"}],
"events_rejected":2}`

func TestStatusRenders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status.json" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(statusJSON))
	}))
	defer srv.Close()
	cfg := writeCfg(t, strings.TrimPrefix(srv.URL, "http://"))
	code, out, errOut := do("status", "-config", cfg)
	if code != 0 {
		t.Fatalf("status = %d %q", code, errOut)
	}
	for _, want := range []string{"a1 (claude-code)", "SILENT", "network: NOT WATCHED", "file: watched", "trace=trace-abc", "no data"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "b2 (mcp) last heartbeat 2026-01-01T00:01:00Z  SILENT") {
		t.Errorf("non-silent source flagged:\n%s", out)
	}
}

func TestStatusUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := strings.TrimPrefix(srv.URL, "http://")
	srv.Close()
	code, out, errOut := do("status", "-config", writeCfg(t, addr))
	if code != 1 || out != "" || !strings.Contains(errOut, "unreachable") {
		t.Errorf("status = %d %q %q", code, out, errOut)
	}
}
