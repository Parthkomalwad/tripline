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
	"github.com/Parthkomalwad/tripline/internal/bundle"
	"github.com/Parthkomalwad/tripline/internal/floor"
	"github.com/Parthkomalwad/tripline/internal/rules"
	"github.com/Parthkomalwad/tripline/internal/selftest"
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

	corr := StartCorrelation(ctx, w, cfg.Watcher.StateDir, log, func(c rules.Chain) { alerts.Send(sinks.ChainAlert(c)) })
	apply := func(rs []*rules.Rule, version int) {
		w.SetRules(rs)
		corr.SetRules(rs)
		state.SetBundleVersion(int64(version))
	}
	apply(floor.Rules(), 0)

	mux := http.NewServeMux()
	var staleBundles func() []string
	switch {
	case cfg.Trust.File != "":
		trust, err := bundle.LoadTrust(cfg.Trust.File)
		if err != nil {
			return err
		}
		b := &Bundles{Trust: trust, File: cfg.Watcher.BundleFile, StateDir: cfg.Watcher.StateDir,
			Apply: apply, Audit: al.Append, Alert: alerts.Send, Log: log, Now: time.Now}
		if err := b.Load(); err != nil {
			return err
		}
		go b.Run(ctx)
		mux.HandleFunc("/v1/bundle", b.Handler(tokens))
		staleBundles = func() []string { return state.StaleBundles(int64(b.Version())) }
	case cfg.Watcher.RulesFile != "":
		data, err := os.ReadFile(cfg.Watcher.RulesFile)
		if err != nil {
			return err
		}
		rs, err := rules.Parse(data)
		if err != nil {
			return fmt.Errorf("%s: %w", cfg.Watcher.RulesFile, err)
		}
		merged, err := floor.Merge(rs)
		if err != nil {
			return fmt.Errorf("%s: %w", cfg.Watcher.RulesFile, err)
		}
		log.Warn("using unsigned rules_file; set trust.file and bundle_file for signed bundles", "file", cfg.Watcher.RulesFile)
		apply(merged, 0)
	}

	st := &selftest.Runner{Sensors: cfg.Selftest.Sensors, AllowHost: cfg.Selftest.AllowHost, Interval: cfg.Selftest.Interval,
		Ingest: w.Ingest, Alert: alerts.Send, Registry: reg, Trap: trap, Log: log, StaleBundles: staleBundles}
	w.Observe(st.Observe)
	st.Start(ctx)
	go state.Loop(ctx, cfg.Watcher.StateDir, log)

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
