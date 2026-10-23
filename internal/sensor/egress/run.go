package egress

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Parthkomalwad/tripline/internal/client"
	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

// LoadRules reads and parses the rules file. An empty file is an error.
func LoadRules(path string) ([]*rules.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rs, err := rules.Parse(data)
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, errors.New("no rules in file")
	}
	return rs, nil
}

// Run starts the event client and the proxy and blocks until ctx ends.
func Run(ctx context.Context, cfg *Config, log *slog.Logger) error {
	token, err := client.TokenFromEnv(cfg.TokenEnv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	cl := client.New(client.Config{
		URL: cfg.WatcherURL, Token: token, Source: sourceName, SourceID: cfg.ID, Subject: cfg.ID,
		BufferPath: filepath.Join(cfg.StateDir, "events.jsonl"), BufferMax: cfg.BufferMaxBytes, Log: log,
	})
	defer cl.Close()
	p := New(*cfg, cl.Send, log)

	if rs, err := LoadRules(cfg.RulesFile); err != nil {
		log.Error("no valid rules", "file", cfg.RulesFile, "err", err, "fail_mode", cfg.FailMode)
		if cfg.FailMode == "open" {
			cl.Send(event.Event{ID: client.NewID(), TS: time.Now().UTC(), Source: sourceName,
				SourceID: cfg.ID, Subject: cfg.ID, Kind: event.KindBundleRejected, Decision: event.DecisionNone,
				Attrs: map[string]any{"severity": "critical", "fail_mode": "open",
					"reason": "no valid rules at startup, allowing all"}})
		}
	} else {
		p.SetRules(rs)
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case now := <-t.C:
				p.flushAgg(now)
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { <-ctx.Done(); _ = srv.Close() }()
	log.Info("egress sensor listening", "addr", ln.Addr().String(), "profile", cfg.Profile, "fail_mode", cfg.FailMode)
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
