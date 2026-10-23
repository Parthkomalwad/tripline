// Package event defines the event that every sensor, hook, connector and
// self-test sends to the watcher.
package event

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Kind is the type of an event.
type Kind string

const (
	KindHeartbeat       Kind = "heartbeat"
	KindEgressConnect   Kind = "egress.connect"
	KindProviderRequest Kind = "egress.provider_request"
	KindSecretRead      Kind = "secret.read"
	KindHookToolCall    Kind = "hook.tool_call"
	KindTripwireHit     Kind = "tripwire.hit"
	KindKeyUsageAnomaly Kind = "keyusage.anomaly"
	KindSelftestResult  Kind = "selftest.result"
	KindBundleApplied   Kind = "bundle.applied"
	KindBundleRejected  Kind = "bundle.rejected"
)

var kinds = map[Kind]bool{
	KindHeartbeat: true, KindEgressConnect: true, KindProviderRequest: true,
	KindSecretRead: true, KindHookToolCall: true, KindTripwireHit: true,
	KindKeyUsageAnomaly: true, KindSelftestResult: true,
	KindBundleApplied: true, KindBundleRejected: true,
}

// Decision is what a sensor did, or would have done in monitor mode.
type Decision string

const (
	DecisionAllow   Decision = "allow"
	DecisionDeny    Decision = "deny"
	DecisionObserve Decision = "observe" // monitor mode: would have denied
	DecisionNone    Decision = "none"
)

var decisions = map[Decision]bool{
	DecisionAllow: true, DecisionDeny: true, DecisionObserve: true, DecisionNone: true,
}

// Event is the unit of data that flows to the watcher. It holds metadata
// only: never secret values, prompts or responses.
type Event struct {
	ID            string         `json:"id"`
	TS            time.Time      `json:"ts"`
	Source        string         `json:"source"`
	SourceID      string         `json:"source_id"`
	Subject       string         `json:"subject"`
	Kind          Kind           `json:"kind"`
	Attrs         map[string]any `json:"attrs,omitempty"`
	Decision      Decision       `json:"decision"`
	RuleID        string         `json:"rule_id,omitempty"`
	BundleVersion int64          `json:"bundle_version,omitempty"`
}

// Limits keep one event small, so a bad sensor cannot fill the watcher.
const (
	maxFieldLen = 256
	maxAttrs    = 32
)

var name = regexp.MustCompile(`^[A-Za-z0-9._:/-]+$`)

// Validate returns an error that names the first invalid field.
func (e *Event) Validate() error {
	for _, f := range []struct{ field, val string }{
		{"id", e.ID}, {"source", e.Source}, {"source_id", e.SourceID}, {"subject", e.Subject},
	} {
		if f.val == "" {
			return fmt.Errorf("%s: required", f.field)
		}
		if len(f.val) > maxFieldLen || !name.MatchString(f.val) {
			return fmt.Errorf("%s: invalid", f.field)
		}
	}
	if e.TS.IsZero() {
		return errors.New("ts: required")
	}
	if !kinds[e.Kind] {
		return fmt.Errorf("kind: unknown %q", e.Kind)
	}
	if !decisions[e.Decision] {
		return fmt.Errorf("decision: unknown %q", e.Decision)
	}
	if len(e.Attrs) > maxAttrs {
		return fmt.Errorf("attrs: more than %d", maxAttrs)
	}
	for k, v := range e.Attrs {
		if len(k) > maxFieldLen || !name.MatchString(k) {
			return fmt.Errorf("attrs: invalid key %q", k)
		}
		if s, ok := v.(string); ok && len(s) > maxFieldLen {
			return fmt.Errorf("attrs.%s: longer than %d", k, maxFieldLen)
		}
	}
	if e.BundleVersion < 0 {
		return errors.New("bundle_version: negative")
	}
	return nil
}
