// Package sinks builds alerts from matched rules and delivers them to
// stdout, a generic webhook and Slack. Alert text holds metadata only.
package sinks

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

// Alert says what happened, what was already done and what a human must do.
type Alert struct {
	TraceID  string    `json:"trace_id"` // the ID of the triggering event
	TS       time.Time `json:"ts"`
	RuleID   string    `json:"rule_id"`
	Severity string    `json:"severity"`
	Page     bool      `json:"page"` // true when the rule has the "page" action
	Subject  string    `json:"subject"`
	What     string    `json:"what"`
	Done     string    `json:"done"`
	Todo     string    `json:"todo"`
	Runbook  string    `json:"runbook,omitempty"`
}

// safeAttrs are the only attrs that may appear in alert text.
var safeAttrs = []string{"host", "path", "decoy_kind", "fingerprint"}

// NewAlert builds the alert for an event that matched a rule.
func NewAlert(e *event.Event, r *rules.Rule) Alert {
	what := fmt.Sprintf("Rule %s matched a %s event from %s", r.ID, e.Kind, e.Source)
	if r.Description != "" {
		what = r.Description + ". " + what
	}
	for _, k := range safeAttrs {
		if v, ok := e.Attrs[k]; ok {
			what += fmt.Sprintf(" (%s=%v)", k, v)
		}
	}
	done := "nothing blocked (monitor mode)"
	switch {
	case e.Decision == event.DecisionDeny:
		done = "the sensor blocked the action"
	case r.Mode != rules.ModeMonitor:
		done = "nothing blocked (the sensor did not deny this event)"
	}
	todo := fmt.Sprintf("Review trace %s in the audit log. Rotate any exposed credential.", e.ID)
	if fp, ok := e.Attrs["fingerprint"]; ok {
		todo = fmt.Sprintf("Rotate the key with fingerprint %v. Review trace %s in the audit log.", fp, e.ID)
	}
	return Alert{
		TraceID: e.ID, TS: e.TS, RuleID: r.ID, Severity: string(r.Severity),
		Page: slices.Contains(r.OnMatch, "page"), Subject: e.Subject,
		What: what, Done: done, Todo: todo, Runbook: r.Runbook,
	}
}

// Text renders the alert as plain text.
func (a Alert) Text() string {
	var b strings.Builder
	p := "ALERT"
	if a.Page {
		p = "PAGE"
	}
	fmt.Fprintf(&b, "[%s %s] %s (subject %s)\nWhat: %s\nDone: %s\nTo do: %s\nTrace: %s",
		p, a.Severity, a.RuleID, a.Subject, a.What, a.Done, a.Todo, a.TraceID)
	if a.Runbook != "" {
		b.WriteString("\nRunbook: " + a.Runbook)
	}
	return b.String()
}
