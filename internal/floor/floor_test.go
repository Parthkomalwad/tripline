package floor

import (
	"strings"
	"testing"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

func parse(t *testing.T, src string) []*rules.Rule {
	t.Helper()
	rs, err := rules.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestFloorRulesLoad(t *testing.T) {
	var ids []string
	for _, r := range Rules() {
		if !r.Floor {
			t.Errorf("%s: Floor flag not set", r.ID)
		}
		ids = append(ids, r.ID)
	}
	if got := strings.Join(ids, ","); got != "tripwire-hit,floor-credential-read,floor-lookalike" {
		t.Fatalf("ids = %s", got)
	}
}

func TestCredentialRead(t *testing.T) {
	var cred *rules.Rule
	for _, r := range Rules() {
		if r.ID == "floor-credential-read" {
			cred = r
		}
	}
	for path, want := range map[string]bool{
		"~/.aws/credentials":    true,
		"/home/app/.ssh/id_rsa": true,
		"/home/app/.env.local":  true,
		"prod.env":              true,
		"/home/app/readme":      false,
	} {
		e := &event.Event{Kind: event.KindSecretRead, Attrs: map[string]any{"path": path}}
		if got := cred.Matches(e); got != want {
			t.Errorf("%s: matches %v, want %v", path, got, want)
		}
	}
}

func TestMergeAndCheck(t *testing.T) {
	extra := "id: extra\nseverity: low\non_match: [alert]\nmatch: {kind: heartbeat}\n"
	merged, err := Merge(parse(t, extra))
	if err != nil || len(merged) != len(Rules())+1 || merged[len(merged)-1].ID != "extra" {
		t.Fatalf("merge: %d rules, %v", len(merged), err)
	}
	trap := "id: tripwire-hit\nseverity: %s\nmode: %s\non_match: [alert]\nmatch: {kind: tripwire.hit, selftest: false}\n"
	for name, tc := range map[string]struct {
		sev, mode string
		ok        bool
	}{
		"same":           {"critical", "monitor", true},
		"enforce":        {"critical", "enforce", true},
		"lower severity": {"high", "monitor", false},
	} {
		src := strings.Replace(strings.Replace(trap, "%s", tc.sev, 1), "%s", tc.mode, 1)
		_, err := Merge(parse(t, src))
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A tighter copy replaces the floor rule instead of duplicating it.
	m, _ := Merge(parse(t, strings.Replace(strings.Replace(trap, "%s", "critical", 1), "%s", "enforce", 1)))
	if len(m) != len(Rules()) || m[0].Mode != rules.ModeEnforce {
		t.Fatalf("replace: %d rules, mode %s", len(m), m[0].Mode)
	}
}

func TestFloorLookalikeMatches(t *testing.T) {
	e := &event.Event{Kind: event.KindEgressConnect, Attrs: map[string]any{"host": "litellm.dev"}}
	var ids []string
	for _, r := range rules.Evaluate(Rules(), e) {
		ids = append(ids, r.ID)
	}
	if !strings.Contains(strings.Join(ids, ","), "floor-lookalike") {
		t.Errorf("litellm.dev matched %v, want floor-lookalike", ids)
	}
	e.Attrs["host"] = "api.anthropic.com"
	for _, r := range rules.Evaluate(Rules(), e) {
		if r.ID == "floor-lookalike" {
			t.Error("api.anthropic.com matched floor-lookalike")
		}
	}
}
