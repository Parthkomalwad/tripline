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
)

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

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/events", w.HandleEvents)
	srv := &http.Server{
		Addr:              cfg.Watcher.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
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
