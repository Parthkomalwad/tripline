package watcher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

const (
	maxBody  = 1 << 20 // 1 MiB per batch
	maxBatch = 1000
)

// Observer receives each accepted event with the rules it matched. Audit,
// alerts, metrics and heartbeats each register one. Observers must not block.
type Observer func(e *event.Event, matched []*rules.Rule)

// RejectObserver receives each rejected event, for audit and metrics.
type RejectObserver func(sensorID string, reason string)

// Watcher holds the ingest state shared by all HTTP handlers.
type Watcher struct {
	Tokens *Tokens
	Log    *slog.Logger

	mu        sync.RWMutex
	rules     []*rules.Rule
	observers []Observer
	rejects   []RejectObserver
}

// SetRules replaces the active rule set.
func (w *Watcher) SetRules(rs []*rules.Rule) {
	w.mu.Lock()
	w.rules = rs
	w.mu.Unlock()
}

// Observe registers an observer for accepted events.
func (w *Watcher) Observe(o Observer) {
	w.mu.Lock()
	w.observers = append(w.observers, o)
	w.mu.Unlock()
}

// ObserveRejects registers an observer for rejected events.
func (w *Watcher) ObserveRejects(o RejectObserver) {
	w.mu.Lock()
	w.rejects = append(w.rejects, o)
	w.mu.Unlock()
}

// Ingest evaluates one already-authenticated event and notifies observers.
// Trap and webhook handlers call it directly.
func (w *Watcher) Ingest(sensorID string, e *event.Event) error {
	err := e.Validate()
	if err == nil && e.SourceID != sensorID {
		err = fmt.Errorf("source_id %q does not match the authenticated sensor", e.SourceID)
	}
	if err != nil {
		w.reject(sensorID, err)
		return err
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	matched := rules.Evaluate(w.rules, e)
	for _, o := range w.observers {
		o(e, matched)
	}
	return nil
}

func (w *Watcher) reject(sensorID string, err error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, o := range w.rejects {
		o(sensorID, err.Error())
	}
}

type ingestResult struct {
	Accepted int           `json:"accepted"`
	Rejected []rejectEntry `json:"rejected,omitempty"`
}

type rejectEntry struct {
	Index int    `json:"index"`
	Error string `json:"error"`
}

// HandleEvents serves POST /v1/events: a JSON array of events from one
// sensor, authenticated with that sensor's bearer token.
func (w *Watcher) HandleEvents(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		rw.Header().Set("Allow", http.MethodPost)
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	sensorID, known := w.Tokens.Lookup(token)
	if !ok || !known {
		// Do not log the token value.
		w.Log.Warn("ingest: unauthenticated request", "remote", r.RemoteAddr)
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}
	var batch []json.RawMessage
	dec := json.NewDecoder(http.MaxBytesReader(rw, r.Body, maxBody))
	if err := dec.Decode(&batch); err != nil {
		http.Error(rw, "body must be a JSON array of events, at most 1 MiB", http.StatusBadRequest)
		return
	}
	if len(batch) > maxBatch {
		http.Error(rw, fmt.Sprintf("at most %d events per batch", maxBatch), http.StatusRequestEntityTooLarge)
		return
	}
	res := ingestResult{}
	for i, raw := range batch {
		var e event.Event
		err := strictUnmarshal(raw, &e)
		if err == nil {
			err = w.Ingest(sensorID, &e)
		} else {
			w.reject(sensorID, err)
		}
		if err != nil {
			res.Rejected = append(res.Rejected, rejectEntry{i, err.Error()})
			continue
		}
		res.Accepted++
	}
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(res)
}

func strictUnmarshal(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
