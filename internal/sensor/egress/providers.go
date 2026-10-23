package egress

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/sensor/egress/provider"
)

// startProviders starts the provider-mode listener when "providers" is set.
// A bad key or a busy port is a startup error.
func startProviders(ctx context.Context, cfg *Config, send func(event.Event), log *slog.Logger) error {
	if !cfg.Providers.Any() {
		return nil
	}
	h, err := provider.New(provider.Options{Providers: cfg.Providers, Source: sourceName,
		SourceID: cfg.ID, Send: send, Log: log})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.ProviderListen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	go func() {
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			log.Error("provider listener stopped", "err", err)
		}
	}()
	log.Info("provider mode listening", "addr", ln.Addr().String())
	return nil
}
