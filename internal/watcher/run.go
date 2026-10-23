package watcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Parthkomalwad/tripline/internal/audit"
	"github.com/Parthkomalwad/tripline/internal/rules"
	"github.com/Parthkomalwad/tripline/internal/sinks"
	"github.com/Parthkomalwad/tripline/internal/tripwire"
)

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
}

// Run starts the watcher and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg *Config, log *slog.Logger) error {
	if err := os.MkdirAll(cfg.Watcher.StateDir, 0o700); err != nil {
		return err
	}
	tokens, err := LoadTokens(cfg.Watcher.StateDir)
	if err != nil {
		return err
	}
	StartDeadman(ctx, cfg, log)
	w := &Watcher{Tokens: tokens, Log: log}
	al, err := audit.Open(filepath.Join(cfg.Watcher.StateDir, "audit.jsonl"))
	if err != nil {
		return err
	}
	obs, rej, stopAudit := al.Async(log)
	defer stopAudit()
	w.Observe(obs)
	w.ObserveRejects(rej)
	if f := cfg.Watcher.RulesFile; f != "" {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		rs, err := rules.Parse(data)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		w.SetRules(rs)
	}

	// TODO(M3): connect chains to alerts and audit.
	StartCorrelation(ctx, w, cfg.Watcher.StateDir, log, func(c rules.Chain) { log.Warn("chain", "rule", c.RuleID, "trace", c.TraceID()) })

	reg, err := tripwire.LoadRegistry(cfg.Watcher.StateDir)
	if err != nil {
		return err
	}
	trap := &tripwire.Handler{Registry: reg, Ingest: w.Ingest, Log: log}

	alerts := startSinks(ctx, w, cfg)
	alerts.Add("audit", func(a sinks.Alert) error { return al.Append("alert", a) })

	state := NewState()
	if err := state.Load(cfg.Watcher.StateDir); err != nil {
		return err
	}
	state.OnSilent = func(sourceID string) { alerts.Send(sinks.SilentAlert(sourceID, time.Now())) }
	state.Attach(w)
	go state.Loop(ctx, cfg.Watcher.StateDir, log)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/events", w.HandleEvents)
	srvs := []*http.Server{newServer(cfg.Watcher.Listen, mux), newServer(cfg.Watcher.StatusPage, state.StatusHandler())}
	if cfg.Watcher.TrapListen == "" {
		mux.Handle("/trap/", trap)
	} else {
		srvs = append(srvs, newServer(cfg.Watcher.TrapListen, trap))
	}
	errc := make(chan error, len(srvs))
	for _, srv := range srvs {
		go func() { errc <- srv.ListenAndServe() }()
		log.Info("watcher listening", "addr", srv.Addr)
	}

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range srvs {
		if err := srv.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	return nil
}
