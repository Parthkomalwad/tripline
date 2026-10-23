package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
)

// Default bounds on partial chains held in memory.
const (
	DefaultPerKey = 64
	DefaultMax    = 4096
)

// Correlate is the body of a correlation rule: ordered steps for one subject
// inside a time window that starts at step 1.
type Correlate struct {
	Same     string           `yaml:"same"`
	Within   time.Duration    `yaml:"within"`
	Sequence []map[string]any `yaml:"sequence"`

	steps []*Rule // each step reuses single-rule matching
}

func (c *Correlate) compile() error {
	if c.Same == "" {
		c.Same = "subject"
	}
	if c.Same != "subject" {
		return fmt.Errorf("correlate.same: only %q is supported, got %q", "subject", c.Same)
	}
	if c.Within <= 0 {
		return errors.New("correlate.within: required and positive")
	}
	if len(c.Sequence) < 2 {
		return errors.New("correlate.sequence: need at least 2 steps")
	}
	c.steps = c.steps[:0]
	for i, m := range c.Sequence {
		if len(m) == 0 {
			return fmt.Errorf("correlate.sequence[%d]: empty step", i)
		}
		conds, err := compileConds(m)
		if err != nil {
			return fmt.Errorf("correlate.sequence[%d]: %w", i, err)
		}
		c.steps = append(c.steps, &Rule{conds: conds})
	}
	return nil
}

// Chain is a completed correlation.
type Chain struct {
	RuleID   string    `json:"rule_id"`
	Severity Severity  `json:"severity"`
	Key      string    `json:"key"`
	EventIDs []string  `json:"event_ids"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Rule     *Rule     `json:"-"`
}

// TraceID is the ID of the first event in the chain.
func (c Chain) TraceID() string { return c.EventIDs[0] }

// partial is a chain that has matched some steps but not all.
type partial struct {
	Rule  string    `json:"rule"`
	Key   string    `json:"key"`
	IDs   []string  `json:"ids"` // one per matched step
	Start time.Time `json:"start"`
	Last  time.Time `json:"last"`
}

// Correlator tracks partial chains per subject. It is safe for concurrent use.
type Correlator struct {
	// PerKey and Max bound the partial chains per subject and overall.
	PerKey, Max int
	// Now is the clock for Load. Tests replace it.
	Now func() time.Time

	mu      sync.Mutex
	rules   []*Rule
	byID    map[string]*Rule
	parts   []*partial // oldest first
	evicted int64
	dirty   bool
}

// NewCorrelator keeps only the correlation rules from rs.
func NewCorrelator(rs []*Rule) *Correlator {
	c := &Correlator{PerKey: DefaultPerKey, Max: DefaultMax, Now: time.Now, byID: map[string]*Rule{}}
	for _, r := range rs {
		if r.Correlate != nil {
			c.rules = append(c.rules, r)
			c.byID[r.ID] = r
		}
	}
	return c
}

// Evicted counts partial chains dropped because of the memory bounds.
func (c *Correlator) Evicted() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evicted
}

// Pending returns the number of partial chains held.
func (c *Correlator) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.parts)
}

// TakeDirty reports whether state changed since the last call.
func (c *Correlator) TakeDirty() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.dirty
	c.dirty = false
	return d
}

// Observe feeds one event and returns the chains it completed. One event
// completes at most one chain per rule and subject: the oldest partial.
// Time comes from event timestamps, so replays behave like live traffic.
func (c *Correlator) Observe(e *event.Event) []Chain {
	c.mu.Lock()
	defer c.mu.Unlock()
	// ponytail: linear scans, bounded by Max; index by key if Max grows large.
	kept := c.parts[:0]
	for _, p := range c.parts {
		if e.TS.Sub(p.Start) > c.byID[p.Rule].Correlate.Within {
			c.dirty = true // expired
			continue
		}
		kept = append(kept, p)
	}
	c.parts = kept
	var out []Chain
	for _, r := range c.rules {
		if ch, ok := c.step(r, e); ok {
			out = append(out, ch)
		}
	}
	return out
}

// step advances the partials of rule r on event e, or starts a new one.
func (c *Correlator) step(r *Rule, e *event.Event) (Chain, bool) {
	cor := r.Correlate
	var done *partial
	kept := c.parts[:0]
	for _, p := range c.parts {
		next := len(p.IDs)
		if p.Rule == r.ID && p.Key == e.Subject && !e.TS.Before(p.Last) && cor.steps[next].Matches(e) {
			c.dirty = true
			ids := append(p.IDs[:next:next], e.ID)
			if next == len(cor.steps)-1 {
				if done == nil {
					done = &partial{Key: p.Key, IDs: ids, Start: p.Start}
				}
				continue // completed partials leave the table
			}
			p = &partial{Rule: p.Rule, Key: p.Key, IDs: ids, Start: p.Start, Last: e.TS}
		}
		kept = append(kept, p)
	}
	c.parts = kept
	if done != nil {
		return Chain{RuleID: r.ID, Severity: r.Severity, Key: done.Key,
			EventIDs: done.IDs, Start: done.Start, End: e.TS, Rule: r}, true
	}
	if cor.steps[0].Matches(e) {
		c.parts = append(c.parts, &partial{Rule: r.ID, Key: e.Subject, IDs: []string{e.ID}, Start: e.TS, Last: e.TS})
		c.dirty = true
		c.bound(r.ID, e.Subject)
	}
	return Chain{}, false
}

// bound evicts the oldest partials when a subject or the table is over its cap.
func (c *Correlator) bound(rule, key string) {
	n := 0
	for _, p := range c.parts {
		if p.Rule == rule && p.Key == key {
			n++
		}
	}
	for i := 0; n > c.PerKey && i < len(c.parts); {
		if p := c.parts[i]; p.Rule == rule && p.Key == key {
			c.drop(i)
			n--
		} else {
			i++
		}
	}
	for len(c.parts) > c.Max {
		c.drop(0)
	}
}

func (c *Correlator) drop(i int) {
	c.parts = append(c.parts[:i], c.parts[i+1:]...)
	c.evicted++
}

type saved struct {
	Partials []*partial `json:"partials"`
}

// Save writes the partial chains as JSON.
func (c *Correlator) Save(w io.Writer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return json.NewEncoder(w).Encode(saved{c.parts})
}

// Load replaces the partial chains with saved ones. It drops expired
// partials and partials of rules that no longer exist or changed shape.
func (c *Correlator) Load(r io.Reader) error {
	var in saved
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.Now()
	c.parts = nil
	for _, p := range in.Partials {
		rule := c.byID[p.Rule]
		if rule == nil || len(p.IDs) == 0 || len(p.IDs) >= len(rule.Correlate.steps) ||
			now.Sub(p.Start) > rule.Correlate.Within {
			continue
		}
		c.parts = append(c.parts, p)
	}
	return nil
}

// SetRules replaces the correlation rules, for example when a new bundle is
// applied. Partial chains whose rule no longer exists are dropped.
func (c *Correlator) SetRules(rs []*Rule) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules, c.byID = nil, map[string]*Rule{}
	for _, r := range rs {
		if r.Correlate != nil {
			c.rules = append(c.rules, r)
			c.byID[r.ID] = r
		}
	}
	kept := c.parts[:0]
	for _, p := range c.parts {
		if c.byID[p.Rule] != nil {
			kept = append(kept, p)
		}
	}
	c.parts = kept
	c.dirty = true
}
