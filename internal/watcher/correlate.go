package watcher

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

// StartCorrelation runs the correlation rules that SetRules loaded. It loads
// <stateDir>/correlation.json, registers an observer and calls onChain for
// each completed chain. onChain runs inside ingest, so it must not block.
// State is saved every 10s when changed, and once more when ctx ends.
func StartCorrelation(ctx context.Context, w *Watcher, stateDir string, log *slog.Logger, onChain func(rules.Chain)) *rules.Correlator {
	w.mu.RLock()
	c := rules.NewCorrelator(w.rules)
	w.mu.RUnlock()
	file := filepath.Join(stateDir, "correlation.json")
	if data, err := os.ReadFile(file); err == nil {
		if err := c.Load(bytes.NewReader(data)); err != nil {
			log.Error("correlation state unreadable, starting empty", "file", file, "err", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		log.Error("correlation state not read", "file", file, "err", err)
	}
	w.Observe(func(e *event.Event, _ []*rules.Rule) {
		for _, ch := range c.Observe(e) {
			onChain(ch)
		}
	})
	save := func() {
		var buf bytes.Buffer
		err := c.Save(&buf)
		if err == nil {
			err = writeAtomic(file, buf.Bytes())
		}
		if err != nil {
			log.Error("correlation state not saved", "file", file, "err", err)
		}
	}
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if c.TakeDirty() {
					save()
				}
			case <-ctx.Done():
				save()
				return
			}
		}
	}()
	return c
}

func writeAtomic(file string, data []byte) error {
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}
