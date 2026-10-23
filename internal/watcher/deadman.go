package watcher

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"
)

const deadmanEvery = 60 * time.Second

// StartDeadman pings the URL named by watcher.heartbeat_ping_url_env every
// 60 seconds, so an outside service can alert when the watcher stops. It
// does nothing when no variable name is configured.
func StartDeadman(ctx context.Context, cfg *Config, log *slog.Logger) {
	name := cfg.Watcher.HeartbeatPingURLEnv
	if name == "" {
		return
	}
	u := os.Getenv(name)
	if u == "" {
		log.Error("dead man's switch disabled: env var is empty", "env", name)
		return
	}
	go deadman(ctx, u, deadmanEvery, log)
}

// deadman pings now and then every interval. The URL is a secret: it never
// reaches a log line.
func deadman(ctx context.Context, u string, every time.Duration, log *slog.Logger) {
	client := &http.Client{Timeout: 10 * time.Second}
	ping := func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			log.Error("dead man's switch ping failed", "err", "invalid url")
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err // drop the URL from the message
			}
			log.Error("dead man's switch ping failed", "err", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Error("dead man's switch ping failed", "status", resp.StatusCode)
		}
	}
	ping()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ping()
		}
	}
}
