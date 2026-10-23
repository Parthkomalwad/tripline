package watcher

import (
	"context"
	"os"

	"github.com/Parthkomalwad/tripline/internal/sinks"
)

// startSinks wires alert delivery to the watcher. Stdout is always on.
func startSinks(ctx context.Context, w *Watcher, cfg *Config) *sinks.Dispatcher {
	var specs []sinks.Spec
	for _, s := range cfg.Sinks {
		env := s.WebhookURLEnv
		if s.Type == "webhook" {
			env = s.URLEnv
		}
		specs = append(specs, sinks.Spec{Type: s.Type, URLEnv: env})
	}
	d := sinks.New(specs, w.Log, os.Getenv)
	d.Start(ctx)
	w.Observe(d.Observe)
	return d
}
