package watcher

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Parthkomalwad/tripline/internal/bundle"
	"github.com/Parthkomalwad/tripline/internal/floor"
	"github.com/Parthkomalwad/tripline/internal/rules"
	"github.com/Parthkomalwad/tripline/internal/sinks"
)

const appliedBundleFile = "bundle.applied.yaml"

// Bundles applies signed rule bundles. It re-reads the bundle file on a
// ticker, verifies each new version, records every outcome in the audit log
// and serves the applied bundle to sensors.
type Bundles struct {
	Trust    *bundle.Trust
	File     string // where operators drop new signed bundles
	StateDir string
	Apply    func([]*rules.Rule, int) // called with floor+bundle rules
	Audit    func(typ string, data any) error
	Alert    func(sinks.Alert)
	Log      *slog.Logger
	Now      func() time.Time

	mu       sync.RWMutex
	applied  *bundle.Applied
	raw      []byte // applied bundle bytes, served to sensors
	pending  []byte
	loosened bool   // the pending bundle loosens rules
	seen     []byte // last file content handled, so a rejection is not repeated
}

// Load applies the last applied bundle from the state directory. It is
// verified again, so an edited state file is rejected.
func (b *Bundles) Load() error {
	data, err := os.ReadFile(filepath.Join(b.StateDir, appliedBundleFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	bd, err := bundle.Verify(data, b.Trust, nil, b.Now())
	if err != nil {
		return fmt.Errorf("applied bundle in state dir: %w", err)
	}
	return b.apply(bd, data, false)
}

// Check handles the bundle file once: new content is verified, and a pending
// bundle is applied when its effective time arrives.
func (b *Bundles) Check() {
	now := b.Now()
	b.mu.Lock()
	pending, loosened := b.pending, b.loosened
	b.mu.Unlock()
	if pending != nil {
		if bd, err := bundle.Verify(pending, b.Trust, b.current(), now); err == nil && !bd.Pending {
			b.mu.Lock()
			b.pending = nil
			b.mu.Unlock()
			if err := b.apply(bd, pending, loosened); err != nil {
				b.Log.Error("bundle apply failed", "version", bd.Version, "err", err)
			}
		}
	}

	data, err := os.ReadFile(b.File)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		b.Log.Error("bundle file not read", "file", b.File, "err", err)
		return
	}
	b.mu.Lock()
	if bytes.Equal(data, b.seen) {
		b.mu.Unlock()
		return
	}
	b.seen = data
	b.mu.Unlock()

	bd, out := bundle.Check(data, b.Trust, b.current(), now)
	b.record(out)
	if !out.Accepted {
		sev := "high"
		if out.Critical {
			sev = "critical"
		}
		b.Alert(sinks.BundleAlert(sev,
			fmt.Sprintf("Rule bundle version %d was rejected: %s (%s)", out.Version, out.Reason, out.Detail),
			"the bundle was not applied; the current rules stay in force",
			"Find out who produced this bundle. If it was not expected, treat the signing keys or the delivery path as compromised.",
			out.Version, now))
		return
	}
	loosens := loosening(out.Changes)
	if out.Pending {
		b.mu.Lock()
		b.pending, b.loosened = data, loosens
		b.mu.Unlock()
		if loosens {
			b.Alert(sinks.BundleAlert("high",
				fmt.Sprintf("Rule bundle version %d loosens rules and takes effect at %s: %s", out.Version, bd.EffectiveAt.UTC().Format(time.RFC3339), changeText(out.Changes)),
				"nothing yet; the current rules stay in force until the effective time",
				"Confirm this change was intended. To stop it, publish a newer bundle without the loosening before the effective time.",
				out.Version, now))
		}
		return
	}
	if err := b.apply(bd, data, loosens); err != nil {
		b.Log.Error("bundle apply failed", "version", bd.Version, "err", err)
	}
}

func (b *Bundles) apply(bd *bundle.Bundle, data []byte, loosens bool) error {
	rs, err := bd.ParseRules()
	if err != nil {
		return err
	}
	merged, err := floor.Merge(rs)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(b.StateDir, appliedBundleFile), data); err != nil {
		return err
	}
	b.mu.Lock()
	b.applied, b.raw = bd.Applied(), data
	b.mu.Unlock()
	b.Apply(merged, bd.Version)
	b.Log.Info("bundle applied", "version", bd.Version, "rules", len(merged))
	if loosens {
		b.Alert(sinks.BundleAlert("high",
			fmt.Sprintf("Rule bundle version %d is now in effect and loosens rules: %s", bd.Version, changeText(bd.Changes)),
			"the looser rules are now enforced",
			"Confirm this change was intended.",
			bd.Version, b.Now()))
	}
	return nil
}

func (b *Bundles) record(out bundle.Outcome) {
	typ := "bundle.rejected"
	if out.Accepted {
		typ = "bundle.accepted"
	}
	if err := b.Audit(typ, out); err != nil {
		b.Log.Error("bundle outcome not audited", "err", err)
	}
}

func (b *Bundles) current() *bundle.Applied {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.applied
}

// Version is the applied bundle version, 0 when none.
func (b *Bundles) Version() int {
	if a := b.current(); a != nil {
		return a.Version
	}
	return 0
}

// Run checks the bundle file every 30 seconds until ctx ends.
func (b *Bundles) Run(ctx context.Context) {
	b.Check()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			b.Check()
		case <-ctx.Done():
			return
		}
	}
}

// Handler serves GET /v1/bundle to authenticated sensors. Sensors verify the
// bundle themselves, so this endpoint is not trusted for integrity.
func (b *Bundles) Handler(tokens *Tokens) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if _, known := tokens.Lookup(token); !ok || !known {
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			return
		}
		b.mu.RLock()
		raw := b.raw
		b.mu.RUnlock()
		if raw == nil {
			http.Error(rw, "no bundle applied", http.StatusNotFound)
			return
		}
		rw.Header().Set("Content-Type", "application/yaml")
		_, _ = rw.Write(raw)
	}
}

func loosening(cs []bundle.Change) bool {
	for _, c := range cs {
		if c.Dir == bundle.Loosen {
			return true
		}
	}
	return false
}

func changeText(cs []bundle.Change) string {
	var parts []string
	for _, c := range cs {
		if c.Dir == bundle.Loosen {
			parts = append(parts, c.RuleID+": "+c.Detail)
		}
	}
	return strings.Join(parts, "; ")
}
