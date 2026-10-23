package watcher

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeadmanSurvives500(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(500)
	}))
	defer srv.Close()
	var logs bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(&logs, nil))
	go deadman(ctx, srv.URL+"/secret-path", 10*time.Millisecond, log)
	deadline := time.Now().Add(2 * time.Second)
	for n.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if n.Load() < 3 {
		t.Fatalf("pings = %d, want >= 3 after 500s", n.Load())
	}
	if strings.Contains(logs.String(), "secret-path") || strings.Contains(logs.String(), srv.URL) {
		t.Errorf("log leaks URL: %s", logs.String())
	}
}

func TestDeadmanUnreachableDoesNotLeakURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL + "/secret-path"
	srv.Close()
	var logs bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	deadman(ctx, u, time.Hour, slog.New(slog.NewTextHandler(&logs, nil)))
	if !strings.Contains(logs.String(), "ping failed") || strings.Contains(logs.String(), "secret-path") {
		t.Errorf("log = %q", logs.String())
	}
}

func TestDeadmanEmptyEnvLogsError(t *testing.T) {
	t.Setenv("TL_TEST_DEADMAN", "")
	var logs bytes.Buffer
	cfg := &Config{}
	cfg.Watcher.HeartbeatPingURLEnv = "TL_TEST_DEADMAN"
	StartDeadman(context.Background(), cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if !strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("log = %q, want error", logs.String())
	}
}
