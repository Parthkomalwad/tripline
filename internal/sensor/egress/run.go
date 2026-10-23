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

	"github.com/Parthkomalwad/tripline/internal/bundle"
	"github.com/Parthkomalwad/tripline/internal/client"
	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/floor"
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
	var puller *Puller
	var version func() int64
	if cfg.TrustFile != "" {
		trust, err := bundle.LoadTrust(cfg.TrustFile)
		if err != nil {
			return err
		}
		puller = &Puller{URL: cfg.WatcherURL, Token: token, Trust: trust, StateDir: cfg.StateDir,
			SourceID: cfg.ID, Log: log, HTTP: &http.Client{Timeout: 10 * time.Second}, Now: time.Now}
		version = puller.Version
	}
	cl := client.New(client.Config{
		URL: cfg.WatcherURL, Token: token, Source: sourceName, SourceID: cfg.ID, Subject: cfg.ID,
		BufferPath: filepath.Join(cfg.StateDir, "events.jsonl"), BufferMax: cfg.BufferMaxBytes, Log: log,
		BundleVersion: version,
	})
	defer cl.Close()
	p := New(*cfg, cl.Send, log)

	if puller != nil {
		// Floor rules apply until the first verified bundle arrives.
		p.SetRules(floor.Rules())
		puller.Apply, puller.Send = p.SetRules, cl.Send
		if err := puller.Load(); err != nil {
			log.Error("stored bundle rejected; using floor rules until a verified bundle arrives", "err", err)
		}
		go puller.Run(ctx)
	} else if rs, err := LoadRules(cfg.RulesFile); err != nil {
		log.Error("no valid rules", "file", cfg.RulesFile, "err", err, "fail_mode", cfg.FailMode)
		if cfg.FailMode == "open" {
			cl.Send(event.Event{ID: client.NewID(), TS: time.Now().UTC(), Source: sourceName,
				SourceID: cfg.ID, Subject: cfg.ID, Kind: event.KindBundleRejected, Decision: event.DecisionNone,
				Attrs: map[string]any{"severity": "critical", "fail_mode": "open",
					"reason": "no valid rules at startup, allowing all"}})
		}
	} else if merged, err := floor.Merge(rs); err != nil {
		return fmt.Errorf("%s: %w", cfg.RulesFile, err)
	} else {
		p.SetRules(merged)
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
