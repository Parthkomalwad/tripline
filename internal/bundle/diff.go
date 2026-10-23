package bundle

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/Parthkomalwad/tripline/internal/floor"
)

// Direction says whether a change makes detection stronger or weaker.
type Direction string

const (
	Tighten Direction = "tighten"
	Loosen  Direction = "loosen"
)

// Change is one classified difference between two bundles.
type Change struct {
	RuleID string
	Dir    Direction
	Detail string
}

// Diff compares rule lists by id and classifies each change.
//
//	removed rule                                  loosen   (added rule: tighten)
//	mode enforce -> monitor                       loosen   (monitor -> enforce: tighten)
//	severity lowered                              loosen   (raised: tighten)
//	X_not_in (allowlist) gains entries            loosen   (loses entries: tighten)
//	X_in (deny list) loses entries                loosen   (gains entries: tighten)
//	correlate.within lengthened                   loosen   (shortened: tighten)
//	on_match action removed                       loosen   (added: tighten)
//
// Any other change to match, applies_to or correlate counts as loosening,
// because it cannot be shown to be tighter. Description and runbook changes
// are ignored.
func Diff(old, new []map[string]any) []Change {
	var out []Change
	oldBy := byID(old)
	newBy := byID(new)
	for _, o := range old {
		id := idOf(o)
		n, ok := newBy[id]
		if !ok {
			out = append(out, Change{id, Loosen, "rule removed"})
			continue
		}
		out = append(out, diffRule(id, o, n)...)
	}
	for _, n := range new {
		if _, ok := oldBy[idOf(n)]; !ok {
			out = append(out, Change{idOf(n), Tighten, "rule added"})
		}
	}
	return out
}

func idOf(m map[string]any) string { s, _ := m["id"].(string); return s }

func byID(rs []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, r := range rs {
		out[idOf(r)] = r
	}
	return out
}

func diffRule(id string, o, n map[string]any) []Change {
	var out []Change
	add := func(d Direction, f string, a ...any) { out = append(out, Change{id, d, fmt.Sprintf(f, a...)}) }

	om, nm := mode(o), mode(n)
	if om != nm {
		if om == "enforce" {
			add(Loosen, "mode enforce -> monitor")
		} else {
			add(Tighten, "mode monitor -> enforce")
		}
	}
	os, ns := fmt.Sprint(o["severity"]), fmt.Sprint(n["severity"])
	if r, s := floor.SeverityRank(os), floor.SeverityRank(ns); s < r {
		add(Loosen, "severity %s -> %s", os, ns)
	} else if s > r {
		add(Tighten, "severity %s -> %s", os, ns)
	}
	for _, a := range diffList(o["on_match"], n["on_match"]) {
		add(a.dir, "on_match %s", a.text)
	}
	diffMatch(o["match"], n["match"], add)
	if !reflect.DeepEqual(o["applies_to"], n["applies_to"]) {
		add(Loosen, "applies_to changed")
	}
	diffCorrelate(o["correlate"], n["correlate"], add)
	return out
}

func mode(m map[string]any) string {
	if s, _ := m["mode"].(string); s != "" {
		return s
	}
	return "monitor"
}

type listChange struct {
	dir  Direction
	text string
}

// diffList reports entries added and removed, with the direction of an
// "adding is tighter" list such as on_match.
func diffList(o, n any) []listChange {
	var out []listChange
	ol, nl := strList(o), strList(n)
	for _, v := range ol {
		if !slices.Contains(nl, v) {
			out = append(out, listChange{Loosen, "removed " + v})
		}
	}
	for _, v := range nl {
		if !slices.Contains(ol, v) {
			out = append(out, listChange{Tighten, "added " + v})
		}
	}
	return out
}

func strList(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		out := make([]string, len(x))
		for i, e := range x {
			out[i] = fmt.Sprint(e)
		}
		return out
	}
	return []string{fmt.Sprint(v)}
}

func diffMatch(o, n any, add func(Direction, string, ...any)) {
	om, _ := o.(map[string]any)
	nm, _ := n.(map[string]any)
	keys := map[string]bool{}
	for k := range om {
		keys[k] = true
	}
	for k := range nm {
		keys[k] = true
	}
	for _, k := range slices.Sorted(maps.Keys(keys)) {
		ov, oin := om[k]
		nv, nin := nm[k]
		switch {
		case oin && nin && reflect.DeepEqual(ov, nv):
		case !oin || !nin:
			add(Loosen, "match.%s condition added or removed", k)
		case strings.HasSuffix(k, "_not_in"): // allowlist: more entries means fewer hits
			for _, c := range diffList(ov, nv) {
				add(flip(c.dir), "match.%s %s", k, c.text)
			}
		case strings.HasSuffix(k, "_in"): // deny list: fewer entries means fewer hits
			for _, c := range diffList(ov, nv) {
				add(c.dir, "match.%s %s", k, c.text)
			}
		default:
			add(Loosen, "match.%s changed", k)
		}
	}
}

func flip(d Direction) Direction {
	if d == Tighten {
		return Loosen
	}
	return Tighten
}

// diffCorrelate handles correlate.within generically. Any other difference in
// the correlate mapping counts as loosening.
func diffCorrelate(o, n any, add func(Direction, string, ...any)) {
	om, _ := o.(map[string]any)
	nm, _ := n.(map[string]any)
	if om == nil && nm == nil {
		return
	}
	ow, nw := within(om), within(nm)
	switch {
	case ow != nw && om != nil && nm != nil && ow > 0 && nw > 0:
		if nw > ow {
			add(Loosen, "correlate.within %s -> %s", ow, nw)
		} else {
			add(Tighten, "correlate.within %s -> %s", ow, nw)
		}
	case ow != nw:
		add(Loosen, "correlate.within changed")
	}
	if !reflect.DeepEqual(strip(om), strip(nm)) {
		add(Loosen, "correlate changed")
	}
}

func within(m map[string]any) time.Duration {
	s, _ := m["within"].(string)
	d, _ := time.ParseDuration(s)
	return d
}

func strip(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if k != "within" {
			out[k] = v
		}
	}
	return out
}
