package watcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Parthkomalwad/tripline/internal/rules"
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
	w := &Watcher{Tokens: tokens, Log: log}
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

	state := NewState()
	if err := state.Load(cfg.Watcher.StateDir); err != nil {
		return err
	}
	state.Attach(w)
	go state.Loop(ctx, cfg.Watcher.StateDir, log)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/events", w.HandleEvents)
	srv := newServer(cfg.Watcher.Listen, mux)
	statusSrv := newServer(cfg.Watcher.StatusPage, state.StatusHandler())
	defer statusSrv.Close()
	errc := make(chan error, 2)
	go func() { errc <- srv.ListenAndServe() }()
	go func() { errc <- statusSrv.ListenAndServe() }()
	log.Info("watcher listening", "addr", cfg.Watcher.Listen)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
