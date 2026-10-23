package egress

import (
	"slices"
	"sync"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

const sourceName = "sensor.egress"

// ruleState holds the active rules. Until SetRules or SetNoRules runs, the
// proxy has no rules and applies fail_mode.
type ruleState struct {
	mu     sync.RWMutex
	rules  []*rules.Rule
	loaded bool
}

// SetRules replaces the active rules. It is safe for concurrent use. M3 will
// call it with rules from a verified bundle.
func (p *Proxy) SetRules(rs []*rules.Rule) {
	p.rs.mu.Lock()
	p.rs.rules, p.rs.loaded = rs, true
	p.rs.mu.Unlock()
}

// verdict is the outcome of one decision.
type verdict struct {
	decision event.Decision
	ruleID   string
}

// decide evaluates the rules for one CONNECT. Deny needs a matched rule in
// enforce mode with "block" in on_match. Any other match is observe.
func (p *Proxy) decide(host string, port int) verdict {
	start := time.Now()
	defer func() { p.Latency.Observe(time.Since(start)) }()

	p.rs.mu.RLock()
	rs, loaded := p.rs.rules, p.rs.loaded
	p.rs.mu.RUnlock()
	if !loaded {
		if p.cfg.FailMode == "closed" {
			return verdict{event.DecisionDeny, "fail-closed"}
		}
		return verdict{event.DecisionAllow, ""}
	}
	e := &event.Event{Source: sourceName, SourceID: p.cfg.ID, Subject: p.cfg.ID,
		Kind: event.KindEgressConnect, Attrs: map[string]any{"host": host, "port": port, "profile": p.cfg.Profile}}
	v := verdict{decision: event.DecisionAllow}
	for _, r := range rules.Evaluate(rs, e) {
		if r.Mode == rules.ModeEnforce && slices.Contains(r.OnMatch, "block") {
			return verdict{event.DecisionDeny, r.ID}
		}
		if v.decision == event.DecisionAllow {
			v = verdict{event.DecisionObserve, r.ID}
		}
	}
	return v
}
