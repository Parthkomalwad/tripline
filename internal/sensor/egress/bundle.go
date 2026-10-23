package egress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Parthkomalwad/tripline/internal/bundle"
	"github.com/Parthkomalwad/tripline/internal/client"
	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/floor"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

const appliedBundleFile = "bundle.applied.yaml"

// Puller fetches the signed bundle from the watcher and applies it only after
// its own verification with the sensor's trust file. The watcher is not
// trusted: a bundle it serves must be signed, newer, keep the floor rules and
// respect the loosening delay. On any failure the last verified bundle stays
// in force.
type Puller struct {
	URL      string // watcher base URL
	Token    string
	Trust    *bundle.Trust
	StateDir string
	SourceID string
	Apply    func([]*rules.Rule)
	Send     func(event.Event)
	Log      *slog.Logger
	HTTP     *http.Client
	Now      func() time.Time

	mu      sync.Mutex
	applied *bundle.Applied
	raw     []byte
	seen    []byte
	version atomic.Int64
}

// Version is the applied bundle version, for heartbeats.
func (p *Puller) Version() int64 { return p.version.Load() }

// Load applies the last verified bundle from the state directory.
func (p *Puller) Load() error {
	data, err := os.ReadFile(filepath.Join(p.StateDir, appliedBundleFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	b, err := bundle.Verify(data, p.Trust, nil, p.Now())
	if err != nil {
		return fmt.Errorf("applied bundle in state dir: %w", err)
	}
	return p.apply(b, data)
}

// Fetch gets the watcher's bundle once and applies it if it verifies.
func (p *Puller) Fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(p.URL, "/")+"/v1/bundle", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bundle fetch: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	p.mu.Lock()
	same := bytes.Equal(data, p.raw) || bytes.Equal(data, p.seen)
	p.seen = data
	current := p.applied
	p.mu.Unlock()
	if same {
		return nil
	}
	b, out := bundle.Check(data, p.Trust, current, p.Now())
	if !out.Accepted || out.Pending {
		reason := string(out.Reason)
		if out.Pending {
			reason = "not yet effective"
		}
		p.event(event.KindBundleRejected, out.Version, map[string]any{"reason": reason})
		return nil
	}
	return p.apply(b, data)
}

func (p *Puller) apply(b *bundle.Bundle, data []byte) error {
	rs, err := b.ParseRules()
	if err != nil {
		return err
	}
	merged, err := floor.Merge(rs)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(p.StateDir, appliedBundleFile), data, 0o600); err != nil {
		return err
	}
	p.mu.Lock()
	p.applied, p.raw = b.Applied(), data
	p.mu.Unlock()
	p.version.Store(int64(b.Version))
	p.Apply(merged)
	p.event(event.KindBundleApplied, b.Version, nil)
	p.Log.Info("bundle applied", "version", b.Version)
	return nil
}

func (p *Puller) event(kind event.Kind, version int, attrs map[string]any) {
	p.Send(event.Event{ID: client.NewID(), TS: p.Now().UTC(), Source: sourceName, SourceID: p.SourceID,
		Subject: p.SourceID, Kind: kind, Decision: event.DecisionNone, BundleVersion: int64(version), Attrs: attrs})
}

// Run fetches every 30 seconds until ctx ends. Errors are logged; the last
// verified bundle stays in force.
func (p *Puller) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		if err := p.Fetch(ctx); err != nil && ctx.Err() == nil {
			p.Log.Warn("bundle fetch failed; keeping last verified bundle", "err", err)
		}
		select {
		case <-t.C:
		case <-ctx.Done():
			return
		}
	}
}
