package rules

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
)

const chainRule = `
id: chain-steal-then-send
description: Secret read followed by an unapproved connection on the same subject.
correlate:
  same: subject
  within: 5m
  sequence:
    - kind: secret.read
    - kind: egress.connect
      decision_in: [deny, observe]
severity: critical
on_match: [alert, page]
`

var t0 = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func cev(id, subject string, kind event.Kind, d event.Decision, at time.Duration) *event.Event {
	return &event.Event{ID: id, TS: t0.Add(at), Source: "s", SourceID: "s1", Subject: subject, Kind: kind, Decision: d}
}

func newCor(t *testing.T) *Correlator {
	t.Helper()
	rs, err := Parse([]byte(chainRule))
	if err != nil {
		t.Fatal(err)
	}
	c := NewCorrelator(rs)
	c.Now = func() time.Time { return t0.Add(time.Minute) }
	return c
}

func feed(c *Correlator, es ...*event.Event) (n int, last []Chain) {
	for _, e := range es {
		if ch := c.Observe(e); len(ch) > 0 {
			n += len(ch)
			last = ch
		}
	}
	return
}

func TestCorrelate(t *testing.T) {
	read, conn := event.KindSecretRead, event.KindEgressConnect
	none, deny, allow := event.DecisionNone, event.DecisionDeny, event.DecisionAllow
	tests := []struct {
		name string
		es   []*event.Event
		want int
	}{
		{"spec chain", []*event.Event{cev("a", "gw", read, none, 0), cev("b", "gw", conn, deny, time.Minute)}, 1},
		{"observe counts", []*event.Event{cev("a", "gw", read, none, 0), cev("b", "gw", conn, event.DecisionObserve, 1)}, 1},
		{"wrong order", []*event.Event{cev("b", "gw", conn, deny, 0), cev("a", "gw", read, none, time.Second)}, 0},
		{"different subjects", []*event.Event{cev("a", "gw", read, none, 0), cev("b", "other", conn, deny, time.Second)}, 0},
		{"outside window", []*event.Event{cev("a", "gw", read, none, 0), cev("b", "gw", conn, deny, 5*time.Minute+time.Second)}, 0},
		{"decision filter", []*event.Event{cev("a", "gw", read, none, 0), cev("b", "gw", conn, allow, time.Second)}, 0},
		{"level 3: 2s apart", []*event.Event{cev("a", "gw", read, none, 0), cev("b", "gw", conn, deny, 2*time.Second)}, 1},
		{"one chain for repeated reads", []*event.Event{cev("a", "gw", read, none, 0), cev("a2", "gw", read, none, time.Second), cev("b", "gw", conn, deny, 2*time.Second)}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, last := feed(newCor(t), tc.es...)
			if n != tc.want {
				t.Fatalf("chains = %d, want %d", n, tc.want)
			}
			if n == 0 {
				return
			}
			ch := last[0]
			if ch.RuleID != "chain-steal-then-send" || ch.Severity != "critical" || ch.Key != "gw" {
				t.Errorf("chain = %+v", ch)
			}
			if ch.TraceID() != "a" || len(ch.EventIDs) != 2 || ch.EventIDs[1] != "b" {
				t.Errorf("ids = %v", ch.EventIDs)
			}
			if !ch.Start.Equal(t0) || !ch.End.Equal(tc.es[len(tc.es)-1].TS) {
				t.Errorf("times = %v %v", ch.Start, ch.End)
			}
		})
	}
}

func TestCorrelateEviction(t *testing.T) {
	c := newCor(t)
	c.PerKey, c.Max = 3, 5
	for i := range 6 {
		c.Observe(cev("r", "gw", event.KindSecretRead, event.DecisionNone, time.Duration(i)*time.Second))
	}
	if c.Pending() != 3 || c.Evicted() != 3 {
		t.Fatalf("pending=%d evicted=%d, want 3 and 3", c.Pending(), c.Evicted())
	}
	for _, s := range []string{"a", "b", "c"} { // three subjects hit the global cap of 5
		for i := range 2 {
			c.Observe(cev("r", s, event.KindSecretRead, event.DecisionNone, time.Duration(10+i)*time.Second))
		}
	}
	if c.Pending() != 5 {
		t.Fatalf("pending = %d, want 5", c.Pending())
	}
}

func TestCorrelateExpiresPartials(t *testing.T) {
	c := newCor(t)
	c.Observe(cev("a", "gw", event.KindSecretRead, event.DecisionNone, 0))
	c.Observe(cev("x", "zzz", event.KindHeartbeat, event.DecisionNone, 6*time.Minute))
	if c.Pending() != 0 {
		t.Fatalf("pending = %d, want 0", c.Pending())
	}
}

func TestCorrelateSaveLoad(t *testing.T) {
	c := newCor(t)
	c.Observe(cev("a", "gw", event.KindSecretRead, event.DecisionNone, 0))
	if !c.TakeDirty() || c.TakeDirty() {
		t.Fatal("dirty flag should be set once")
	}
	var buf bytes.Buffer
	if err := c.Save(&buf); err != nil {
		t.Fatal(err)
	}
	saved := buf.String()

	c2 := newCor(t)
	if err := c2.Load(strings.NewReader(saved)); err != nil {
		t.Fatal(err)
	}
	n, last := feed(c2, cev("b", "gw", event.KindEgressConnect, event.DecisionDeny, 2*time.Minute))
	if n != 1 || last[0].TraceID() != "a" {
		t.Fatalf("chain after load = %d %+v", n, last)
	}

	c3 := newCor(t)
	c3.Now = func() time.Time { return t0.Add(10 * time.Minute) }
	if err := c3.Load(strings.NewReader(saved)); err != nil {
		t.Fatal(err)
	}
	if c3.Pending() != 0 {
		t.Fatalf("expired partial kept: %d", c3.Pending())
	}
}

func TestEvaluateSkipsCorrelationRule(t *testing.T) {
	rs, err := Parse([]byte(chainRule + "---" + specRules))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range Evaluate(rs, cev("a", "gw", event.KindSecretRead, event.DecisionNone, 0)) {
		if r.ID == "chain-steal-then-send" {
			t.Fatal("correlation rule matched a single event")
		}
	}
}

func TestCorrelateParseErrors(t *testing.T) {
	bad := map[string]string{
		"same other": strings.Replace(chainRule, "same: subject", "same: source_id", 1),
		"no within":  strings.Replace(chainRule, "within: 5m", "", 1),
		"one step":   strings.Replace(chainRule, "    - kind: egress.connect\n      decision_in: [deny, observe]\n", "", 1),
		"bad op":     strings.Replace(chainRule, "decision_in: [deny, observe]", "decision_in: deny", 1),
		"with match": chainRule + "match: {kind: secret.read}\n",
	}
	for name, y := range bad {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
