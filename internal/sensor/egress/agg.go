package egress

import (
	"sync"
	"time"

	"github.com/Parthkomalwad/tripline/internal/client"
	"github.com/Parthkomalwad/tripline/internal/event"
)

type aggKey struct {
	host     string
	port     int
	decision event.Decision
}

type aggEntry struct {
	start  time.Time
	repeat int // connections after the first, not yet reported
	ruleID string
}

// aggregator limits event volume. The first connection of a (host, port,
// decision) in a window is reported at once, with count 1, so a deny alert
// is not held back. Repeats in the same window are reported later as one
// event with attrs.count and attrs.aggregated.
type aggregator struct {
	mu      sync.Mutex
	window  time.Duration
	entries map[aggKey]*aggEntry
}

// record returns true if the caller must emit an event now (first in window).
func (a *aggregator) record(k aggKey, ruleID string, now time.Time) (first bool, summary *aggKey, n int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	en := a.entries[k]
	if en != nil && now.Sub(en.start) < a.window {
		en.repeat++
		return false, nil, 0
	}
	if en != nil && en.repeat > 0 { // old window ended with repeats unreported
		kk, nn := k, en.repeat
		summary, n = &kk, nn
	}
	a.entries[k] = &aggEntry{start: now, ruleID: ruleID}
	return true, summary, n
}

// expire returns the summaries of windows that ended before now.
func (a *aggregator) expire(now time.Time) (out []aggSummary) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, en := range a.entries {
		if now.Sub(en.start) < a.window {
			continue
		}
		if en.repeat > 0 {
			out = append(out, aggSummary{k, en.ruleID, en.repeat})
		}
		delete(a.entries, k)
	}
	return out
}

type aggSummary struct {
	key    aggKey
	ruleID string
	count  int
}

func (p *Proxy) newEvent(k aggKey, ruleID string, count int, aggregated bool) event.Event {
	attrs := map[string]any{"host": k.host, "port": k.port, "profile": p.cfg.Profile, "count": count}
	if aggregated {
		attrs["aggregated"] = true
	}
	return event.Event{ID: client.NewID(), TS: time.Now().UTC(), Source: sourceName,
		SourceID: p.cfg.ID, Subject: p.cfg.ID, Kind: event.KindEgressConnect,
		Attrs: attrs, Decision: k.decision, RuleID: ruleID}
}

// report records one decided connection and sends events as needed.
func (p *Proxy) report(host string, port int, v verdict) {
	k := aggKey{host, port, v.decision}
	first, sum, n := p.agg.record(k, v.ruleID, time.Now())
	if sum != nil {
		p.send(p.newEvent(*sum, v.ruleID, n, true))
	}
	if first {
		p.send(p.newEvent(k, v.ruleID, 1, false))
	}
}

// flushAgg sends the repeat counts of windows that have ended.
func (p *Proxy) flushAgg(now time.Time) {
	for _, s := range p.agg.expire(now) {
		p.send(p.newEvent(s.key, s.ruleID, s.count, true))
	}
}
