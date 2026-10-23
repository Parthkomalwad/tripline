package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
)

const specRules = `
id: egress-allowlist
description: AI gateway may only reach approved provider endpoints.
applies_to: { source: sensor.egress, profile: gateway-strict }
match:
  kind: egress.connect
  host_not_in: ["api.anthropic.com", "api.openai.com"]
severity: high
mode: monitor
floor: false
on_match: [alert, block]
---
id: env-read
match:
  kind: secret.read
  path_glob: ["/home/*/.env*"]
severity: critical
on_match: [alert]
`

func ev(kind event.Kind, attrs map[string]any) *event.Event {
	return &event.Event{
		ID: "e", TS: time.Now(), Source: "sensor.egress", SourceID: "s1", Subject: "gw",
		Kind: kind, Decision: event.DecisionNone, Attrs: attrs,
	}
}

func TestEvaluate(t *testing.T) {
	rs, err := Parse([]byte(specRules))
	if err != nil {
		t.Fatal(err)
	}
	if rs[1].Mode != ModeMonitor {
		t.Errorf("default mode = %q, want monitor", rs[1].Mode)
	}
	tests := []struct {
		name string
		e    *event.Event
		want string
	}{
		{"lookalike host", ev(event.KindEgressConnect, map[string]any{"host": "litellm.dev", "profile": "gateway-strict"}), "egress-allowlist"},
		{"allowed host, mixed case and dot", ev(event.KindEgressConnect, map[string]any{"host": "API.Anthropic.com.", "profile": "gateway-strict"}), ""},
		{"other profile", ev(event.KindEgressConnect, map[string]any{"host": "litellm.dev", "profile": "agent-browsing"}), ""},
		{"no host attr", ev(event.KindEgressConnect, map[string]any{"profile": "gateway-strict"}), ""},
		{"env read", ev(event.KindSecretRead, map[string]any{"path": "/home/app/.env.backup"}), "env-read"},
		{"other read", ev(event.KindSecretRead, map[string]any{"path": "/home/app/readme"}), ""},
	}
	for _, tc := range tests {
		var got []string
		for _, r := range Evaluate(rs, tc.e) {
			got = append(got, r.ID)
		}
		if strings.Join(got, ",") != tc.want {
			t.Errorf("%s: matched %v, want %q", tc.name, got, tc.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	base := "id: r\nseverity: high\non_match: [alert]\nmatch: {kind: heartbeat}\n"
	tests := []struct{ name, yaml, err string }{
		{"unknown field", base + "matc: {}\n", "matc"},
		{"no id", strings.Replace(base, "id: r", "id: ''", 1), "id: required"},
		{"bad mode", base + "mode: block\n", "mode"},
		{"bad severity", strings.Replace(base, "high", "huge", 1), "severity"},
		{"bad action", strings.Replace(base, "[alert]", "[rotate]", 1), "action"},
		{"no match", strings.Replace(base, "match: {kind: heartbeat}\n", "", 1), "match: required"},
		{"in needs list", strings.Replace(base, "{kind: heartbeat}", "{kind_in: heartbeat}", 1), "want a list"},
		{"bad glob", strings.Replace(base, "{kind: heartbeat}", "{path_glob: ['[']}", 1), "bad pattern"},
		{"duplicate", base + "---\n" + base, "duplicate"},
	}
	for _, tc := range tests {
		_, err := Parse([]byte(tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%s: error %v, want %q", tc.name, err, tc.err)
		}
	}
}
