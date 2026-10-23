// Package rules parses rules and evaluates them against single events.
// Correlation rules live in correlate.go.
package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/lookalike"
)

// Mode says whether a rule only records (monitor) or also blocks (enforce).
type Mode string

const (
	ModeMonitor Mode = "monitor"
	ModeEnforce Mode = "enforce"
)

// Severity orders alerts.
type Severity string

var severities = []Severity{"low", "medium", "high", "critical"}

var actions = map[string]bool{"alert": true, "page": true, "block": true, "runbook": true}

// Rule is one single-event rule.
type Rule struct {
	ID          string            `yaml:"id"`
	Description string            `yaml:"description"`
	AppliesTo   map[string]string `yaml:"applies_to"`
	Match       map[string]any    `yaml:"match"`
	Severity    Severity          `yaml:"severity"`
	Mode        Mode              `yaml:"mode"`
	Floor       bool              `yaml:"floor"`
	OnMatch     []string          `yaml:"on_match"`
	Runbook     string            `yaml:"runbook"`
	Correlate   *Correlate        `yaml:"correlate"`

	conds []cond
}

type op int

const (
	opEq op = iota
	opIn
	opNotIn
	opGlob
	opLookalike
)

// Suffixes are checked in this order, so "_not_in" wins over "_in".
var suffixes = []struct {
	s  string
	op op
}{{"_not_in", opNotIn}, {"_in", opIn}, {"_glob", opGlob}, {"_lookalike_of", opLookalike}}

type cond struct {
	field  string
	op     op
	values []string
}

// Parse reads a YAML stream of one or more rules and checks each one.
// Unknown fields and operators are errors, so a typo cannot disable a rule.
func Parse(data []byte) ([]*Rule, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var out []*Rule
	seen := map[string]bool{}
	for {
		r := &Rule{}
		err := dec.Decode(r)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if err := r.compile(); err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("rule %q: duplicate id", r.ID)
		}
		seen[r.ID] = true
		out = append(out, r)
	}
}

func (r *Rule) compile() error {
	if r.ID == "" {
		return errors.New("id: required")
	}
	if r.Mode == "" {
		r.Mode = ModeMonitor // watch-only by default
	}
	if r.Mode != ModeMonitor && r.Mode != ModeEnforce {
		return fmt.Errorf("mode: unknown %q", r.Mode)
	}
	if !slices.Contains(severities, r.Severity) {
		return fmt.Errorf("severity: unknown %q", r.Severity)
	}
	if len(r.OnMatch) == 0 {
		return errors.New("on_match: required")
	}
	for _, a := range r.OnMatch {
		if !actions[a] {
			return fmt.Errorf("on_match: unknown action %q", a)
		}
	}
	if r.Correlate != nil {
		if len(r.Match) > 0 {
			return errors.New("correlate: cannot be combined with match")
		}
		return r.Correlate.compile()
	}
	if len(r.Match) == 0 {
		return errors.New("match: required")
	}
	var err error
	r.conds, err = compileConds(r.Match)
	return err
}

// compileConds turns a match map into conditions. Single rules and
// correlation steps share it.
func compileConds(match map[string]any) ([]cond, error) {
	var conds []cond
	for key, raw := range match {
		c := cond{field: key, op: opEq}
		for _, s := range suffixes {
			if f, ok := strings.CutSuffix(key, s.s); ok {
				c.field, c.op = f, s.op
				break
			}
		}
		_, isList := raw.([]any)
		vals, err := strs(raw, c.op == opIn || c.op == opNotIn || c.op == opLookalike || (c.op == opGlob && isList))
		if err != nil {
			return nil, fmt.Errorf("match.%s: %w", key, err)
		}
		if c.op == opGlob {
			for _, v := range vals {
				if _, err := path.Match(v, ""); err != nil {
					return nil, fmt.Errorf("match.%s: bad pattern %q", key, v)
				}
			}
		}
		c.values = vals
		conds = append(conds, c)
	}
	return conds, nil
}

func strs(raw any, list bool) ([]string, error) {
	if !list {
		switch v := raw.(type) {
		case string:
			return []string{v}, nil
		case int, bool:
			return []string{fmt.Sprint(v)}, nil
		}
		return nil, errors.New("want a scalar")
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, errors.New("want a list")
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, err := strs(it, false)
		if err != nil {
			return nil, err
		}
		out = append(out, s[0])
	}
	return out, nil
}

// Matches reports whether the event matches the rule. A field that the event
// does not have never matches, so "host_not_in" does not fire on events
// without a host.
func (r *Rule) Matches(e *event.Event) bool {
	if r.Correlate != nil {
		return false // chains match through a Correlator, never a single event
	}
	for k, want := range r.AppliesTo {
		if got, ok := field(e, k); !ok || got != norm(k, want) {
			return false
		}
	}
	for _, c := range r.conds {
		got, ok := field(e, c.field)
		if !ok {
			return false
		}
		var hit bool
		switch c.op {
		case opEq:
			hit = got == norm(c.field, c.values[0])
		case opIn, opNotIn:
			hit = slices.ContainsFunc(c.values, func(v string) bool { return got == norm(c.field, v) })
			if c.op == opNotIn {
				hit = !hit
			}
		case opGlob:
			hit = slices.ContainsFunc(c.values, func(v string) bool { m, _ := path.Match(v, got); return m })
		case opLookalike:
			_, hit = lookalike.Check(got, c.values)
		}
		if !hit {
			return false
		}
	}
	return true
}

// Evaluate returns every rule that matches the event, in rule order.
func Evaluate(rs []*Rule, e *event.Event) []*Rule {
	var out []*Rule
	for _, r := range rs {
		if r.Matches(e) {
			out = append(out, r)
		}
	}
	return out
}

// field reads a top-level event field, or else an attribute.
func field(e *event.Event, name string) (string, bool) {
	switch name {
	case "kind":
		return string(e.Kind), true
	case "source":
		return e.Source, true
	case "source_id":
		return e.SourceID, true
	case "subject":
		return e.Subject, true
	case "decision":
		return string(e.Decision), true
	}
	v, ok := e.Attrs[name]
	if !ok {
		return "", false
	}
	return norm(name, fmt.Sprint(v)), true
}

// norm makes host names compare without case or a trailing dot.
func norm(field, v string) string {
	if field == "host" {
		return strings.TrimSuffix(strings.ToLower(v), ".")
	}
	return v
}
