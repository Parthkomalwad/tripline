package rules

import (
	"os"
	"testing"

	"github.com/Parthkomalwad/tripline/internal/event"
)

func TestLookalikeProfile(t *testing.T) {
	data, err := os.ReadFile("../../rules/profiles/lookalike.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := Parse(data)
	if err != nil || len(rs) != 1 {
		t.Fatalf("parse: %v, %d rules", err, len(rs))
	}
	for host, want := range map[string]bool{
		"litellm.dev": true, "api.anthropic.com": false, "evil.com": false, "10.0.0.1": false,
	} {
		e := ev(event.KindEgressConnect, map[string]any{"host": host})
		if got := rs[0].Matches(e); got != want {
			t.Errorf("%s: matches = %v, want %v", host, got, want)
		}
	}
	if rs[0].Matches(ev(event.KindEgressConnect, map[string]any{})) {
		t.Error("event without host must not match")
	}
	if _, err := Parse([]byte("id: x\nseverity: low\non_match: [alert]\nmatch: {host_lookalike_of: a.com}\n")); err == nil {
		t.Error("scalar for _lookalike_of must be an error")
	}
}
