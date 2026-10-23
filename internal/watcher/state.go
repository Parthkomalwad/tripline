package watcher

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

const (
	silentAfter    = 5 * time.Minute
	silentInterval = 30 * time.Second
	persistEvery   = 10 * time.Second
	maxRecent      = 50
)

// SensorTypes are the source types that coverage reports on.
var SensorTypes = []string{
	"sensor.egress", "hook.claude-code", "hook.cursor", "node.falco", "keyusage", "watcher.trap",
}

// sourceInfo is what the state keeps per source_id. It is also the format of
// heartbeats.json.
type sourceInfo struct {
	Source        string    `json:"source"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	LastEvent     time.Time `json:"last_event"`
	Events        int64     `json:"-"`
}

// liveness is the time that decides silence: the last heartbeat, or the last
// event for a source that never sent a heartbeat.
func (s *sourceInfo) liveness() time.Time {
	if s.LastHeartbeat.IsZero() {
		return s.LastEvent
	}
	return s.LastHeartbeat
}

// Alert is one entry in the recent alerts list.
type Alert struct {
	TS       time.Time `json:"ts"`
	RuleID   string    `json:"rule_id"`
	Severity string    `json:"severity"`
	TraceID  string    `json:"trace_id"`
	Subject  string    `json:"subject"`
}

type eventKey struct{ kind, decision, source string }
type matchKey struct{ rule, mode string }
type alertKey struct{ severity, rule string }

// State is the observed state of the watcher: sources, counters and recent
// alerts. It is safe for concurrent use.
type State struct {
	// Now is the clock. Tests replace it.
	Now func() time.Time
	// OnSilent is called once each time a source becomes silent.
	OnSilent func(sourceID string)

	mu       sync.Mutex
	sources  map[string]*sourceInfo
	notified map[string]bool // sources already reported silent
	dirty    bool
	events   map[eventKey]int64
	matches  map[matchKey]int64
	alerts   map[alertKey]int64
	recent   []Alert // newest first
	rejected int64
	bundle   int64
}

// NewState returns an empty state that uses the wall clock.
func NewState() *State {
	return &State{
		Now:      time.Now,
		sources:  map[string]*sourceInfo{},
		notified: map[string]bool{},
		events:   map[eventKey]int64{},
		matches:  map[matchKey]int64{},
		alerts:   map[alertKey]int64{},
	}
}

// Attach registers the state as an observer on w.
func (s *State) Attach(w *Watcher) {
	w.Observe(s.observe)
	w.ObserveRejects(func(string, string) {
		s.mu.Lock()
		s.rejected++
		s.mu.Unlock()
	})
}

func (s *State) observe(e *event.Event, matched []*rules.Rule) {
	now := s.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.sources[e.SourceID]
	if src == nil {
		src = &sourceInfo{}
		s.sources[e.SourceID] = src
		s.dirty = true
	}
	src.Source = e.Source
	src.LastEvent = now
	src.Events++
	if e.Kind == event.KindHeartbeat {
		src.LastHeartbeat = now
		delete(s.notified, e.SourceID)
		s.dirty = true
	}
	s.events[eventKey{string(e.Kind), string(e.Decision), e.Source}]++
	for _, r := range matched {
		s.matches[matchKey{r.ID, string(r.Mode)}]++
		if !hasAlertAction(r) {
			continue
		}
		s.alerts[alertKey{string(r.Severity), r.ID}]++
		a := Alert{TS: e.TS, RuleID: r.ID, Severity: string(r.Severity), TraceID: e.ID, Subject: e.Subject}
		s.recent = append([]Alert{a}, s.recent...)
		if len(s.recent) > maxRecent {
			s.recent = s.recent[:maxRecent]
		}
	}
}

func hasAlertAction(r *rules.Rule) bool {
	for _, a := range r.OnMatch {
		if a == "alert" || a == "page" {
			return true
		}
	}
	return false
}

// SetBundleVersion records the active rule bundle version.
func (s *State) SetBundleVersion(v int64) {
	s.mu.Lock()
	s.bundle = v
	s.mu.Unlock()
}

// Silent returns the sorted ids of sources with no heartbeat for 5 minutes.
func (s *State) Silent(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.silentLocked(now)
}

func (s *State) silentLocked(now time.Time) []string {
	var out []string
	for id, src := range s.sources {
		if now.Sub(src.liveness()) >= silentAfter {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// CheckSilent calls OnSilent once for each source that turned silent since
// the last check.
func (s *State) CheckSilent() {
	s.mu.Lock()
	var fresh []string
	for _, id := range s.silentLocked(s.Now()) {
		if !s.notified[id] {
			s.notified[id] = true
			fresh = append(fresh, id)
		}
	}
	s.mu.Unlock()
	if s.OnSilent != nil {
		for _, id := range fresh {
			s.OnSilent(id)
		}
	}
}

const heartbeatsFile = "heartbeats.json"

// Load reads dir/heartbeats.json. A missing file is not an error.
func (s *State) Load(dir string) error {
	data, err := os.ReadFile(filepath.Join(dir, heartbeatsFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	m := map[string]*sourceInfo{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, src := range m {
		if src != nil && s.sources[id] == nil {
			s.sources[id] = src
		}
	}
	return nil
}

// Save writes dir/heartbeats.json if the sources changed since the last save.
func (s *State) Save(dir string) error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	data, err := json.Marshal(s.sources)
	s.dirty = false
	s.mu.Unlock()
	if err == nil {
		tmp := filepath.Join(dir, heartbeatsFile+".tmp")
		if err = os.WriteFile(tmp, data, 0o600); err == nil {
			err = os.Rename(tmp, filepath.Join(dir, heartbeatsFile))
		}
	}
	if err != nil {
		s.mu.Lock()
		s.dirty = true // retry on the next tick
		s.mu.Unlock()
	}
	return err
}

// Loop checks for silent sources every 30 seconds and saves heartbeats at
// most every 10 seconds, until ctx is cancelled.
func (s *State) Loop(ctx context.Context, dir string, log *slog.Logger) {
	silent := time.NewTicker(silentInterval)
	save := time.NewTicker(persistEvery)
	defer silent.Stop()
	defer save.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := s.Save(dir); err != nil {
				log.Error("save heartbeats", "err", err)
			}
			return
		case <-silent.C:
			s.CheckSilent()
		case <-save.C:
			if err := s.Save(dir); err != nil {
				log.Error("save heartbeats", "err", err)
			}
		}
	}
}
