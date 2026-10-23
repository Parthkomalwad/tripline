package floor

import (
	"testing"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

func TestForeignCredentialMatches(t *testing.T) {
	var got *rules.Rule
	for _, r := range Rules() {
		if r.ID == "floor-foreign-credential" {
			got = r
		}
	}
	e := &event.Event{Kind: event.KindProviderRequest, Decision: event.DecisionDeny,
		Attrs: map[string]any{"provider": "openai", "reason": "foreign credential", "fingerprint": "sk-a-0123456789ab"}}
	if !got.Matches(e) || got.Severity != "critical" {
		t.Fatalf("rule %+v does not match %+v", got, e)
	}
	e.Attrs["reason"] = "other"
	if got.Matches(e) {
		t.Error("matched an event with another reason")
	}
}
