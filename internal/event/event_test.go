package event

import (
	"strings"
	"testing"
	"time"
)

func valid() Event {
	return Event{
		ID: "evt_1", TS: time.Date(2026, 10, 21, 11, 47, 2, 0, time.UTC),
		Source: "sensor.egress", SourceID: "gw-prod-sensor-1", Subject: "ai-gateway-prod",
		Kind: KindEgressConnect, Decision: DecisionDeny,
		Attrs: map[string]any{"host": "litellm.dev", "port": 443},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Event)
		err    string
	}{
		{"valid", func(*Event) {}, ""},
		{"no id", func(e *Event) { e.ID = "" }, "id: required"},
		{"bad subject", func(e *Event) { e.Subject = "a b" }, "subject: invalid"},
		{"long source", func(e *Event) { e.Source = strings.Repeat("a", 257) }, "source: invalid"},
		{"no ts", func(e *Event) { e.TS = time.Time{} }, "ts: required"},
		{"bad kind", func(e *Event) { e.Kind = "x" }, "kind: unknown"},
		{"bad decision", func(e *Event) { e.Decision = "" }, "decision: unknown"},
		{"bad attr key", func(e *Event) { e.Attrs["a b"] = 1 }, "attrs: invalid key"},
		{"long attr", func(e *Event) { e.Attrs["host"] = strings.Repeat("a", 257) }, "attrs.host"},
		{"negative bundle", func(e *Event) { e.BundleVersion = -1 }, "bundle_version"},
	}
	for _, tc := range tests {
		e := valid()
		tc.change(&e)
		err := e.Validate()
		if tc.err == "" && err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
		if tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%s: error %v, want %q", tc.name, err, tc.err)
		}
	}
}
