package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var t0 = time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

type signer struct {
	id   string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newSigners(t *testing.T, n int) []signer {
	t.Helper()
	var out []signer
	for i := range n {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, signer{fmt.Sprintf("key-%d", i), priv, pub})
	}
	return out
}

func trustFor(t *testing.T, ss []signer, extra string) *Trust {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(extra + "keys:\n")
	for _, s := range ss {
		fmt.Fprintf(&sb, "  - key_id: %s\n    public_key: %s\n    owner: o\n", s.id, base64.StdEncoding.EncodeToString(s.pub))
	}
	tr, err := ParseTrust([]byte(sb.String()))
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func rule(id, sev, mode, notIn string) map[string]any {
	return map[string]any{
		"id": id, "severity": sev, "mode": mode, "on_match": []any{"alert"},
		"match": map[string]any{"kind": "egress.connect", "host_not_in": []any{notIn}},
	}
}

// mk builds a bundle created at t0 that takes effect after delay.
func mk(version int, delay time.Duration, rs ...map[string]any) *Bundle {
	return &Bundle{Version: version, CreatedAt: t0, EffectiveAt: t0.Add(delay), Signers: []string{"a", "b"}, Rules: rs}
}

func signed(t *testing.T, b *Bundle, ss ...signer) []byte {
	t.Helper()
	for _, s := range ss {
		if err := b.Sign(s.id, s.priv); err != nil {
			t.Fatal(err)
		}
	}
	data, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func reasonOf(t *testing.T, err error) Reason {
	t.Helper()
	var r *RejectError
	if !errors.As(err, &r) {
		t.Fatalf("want RejectError, got %v", err)
	}
	return r.Reason
}

func TestSignatureCounting(t *testing.T) {
	ss := newSigners(t, 3)
	tr := trustFor(t, ss, "")
	base := func() *Bundle { return mk(1, 0, rule("r1", "high", "enforce", "a.com")) }

	if _, err := Verify(signed(t, base(), ss[0], ss[2]), tr, nil, t0); err != nil {
		t.Fatalf("2 of 3: %v", err)
	}
	_, err := Verify(signed(t, base(), ss[0]), tr, nil, t0)
	if reasonOf(t, err) != ReasonUnsigned {
		t.Fatalf("1 sig: %v", err)
	}
	// The same key signing twice, written as two list entries, counts once.
	b := base()
	_ = b.Sign(ss[0].id, ss[0].priv)
	b.Signatures = append(b.Signatures, b.Signatures[0])
	data, _ := b.Marshal()
	if _, err := Verify(data, tr, nil, t0); reasonOf(t, err) != ReasonUnsigned {
		t.Fatalf("dup sig: %v", err)
	}
	// A valid signature from a key that is not in the trust file does not count.
	other := newSigners(t, 1)[0]
	other.id = "stranger"
	if _, err := Verify(signed(t, base(), ss[0], other), tr, nil, t0); reasonOf(t, err) != ReasonUnsigned {
		t.Fatalf("untrusted key: %v", err)
	}
}

func TestTamperAfterSigning(t *testing.T) {
	ss := newSigners(t, 3)
	tr := trustFor(t, ss, "")
	data := signed(t, mk(1, 0, rule("r1", "high", "enforce", "a.com")), ss[0], ss[1])
	for _, edit := range [][2]string{{"a.com", "evil.com"}, {"severity: high", "severity: low"}, {"version: 1", "version: 9"}} {
		bad := strings.Replace(string(data), edit[0], edit[1], 1)
		if bad == string(data) {
			t.Fatalf("edit %v did not apply", edit)
		}
		if _, err := Verify([]byte(bad), tr, nil, t0); reasonOf(t, err) != ReasonUnsigned {
			t.Fatalf("tamper %v: %v", edit, err)
		}
	}
}

func TestPayloadIgnoresKeyOrder(t *testing.T) {
	a := mk(1, 0, map[string]any{"id": "x", "match": map[string]any{"a": 1, "b": 2}})
	b := mk(1, 0, map[string]any{"match": map[string]any{"b": 2, "a": 1}, "id": "x"})
	pa, _ := a.Payload()
	pb, _ := b.Payload()
	if string(pa) != string(pb) || !strings.HasPrefix(string(pa), "tripline-bundle-v1\n") {
		t.Fatalf("payloads differ:\n%s\n%s", pa, pb)
	}
	// Survives a YAML round trip.
	data, _ := a.Marshal()
	c, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if pc, _ := c.Payload(); string(pc) != string(pa) {
		t.Fatalf("round trip changed payload:\n%s\n%s", pa, pc)
	}
}

func TestVerifyPolicy(t *testing.T) {
	ss := newSigners(t, 3)
	tr := trustFor(t, ss, "")
	r1 := rule("r1", "high", "enforce", "a.com")
	cur := &Applied{Version: 5, Rules: []map[string]any{r1}}
	floorRule := func(sev, mode string) map[string]any {
		return map[string]any{"id": "tripwire-hit", "severity": sev, "mode": mode, "on_match": []any{"alert", "runbook"},
			"match": map[string]any{"kind": "tripwire.hit", "selftest": false}}
	}
	curFloor := &Applied{Version: 5, Rules: []map[string]any{r1, floorRule("critical", "monitor")}}
	loosened := rule("r1", "high", "monitor", "a.com")

	tests := []struct {
		name    string
		b       *Bundle
		cur     *Applied
		now     time.Time
		want    Reason // empty means accepted
		pending bool
	}{
		{"first bundle", mk(1, 0, r1), nil, t0, "", false},
		{"rollback equal", mk(5, 0, r1), cur, t0, ReasonRollback, false},
		{"rollback lower", mk(4, 0, r1), cur, t0, ReasonRollback, false},
		{"newer", mk(6, 0, r1), cur, t0, "", false},
		{"floor severity lowered", mk(6, 0, r1, floorRule("low", "monitor")), cur, t0, ReasonFloor, false},
		{"floor match changed", mk(6, 0, map[string]any{"id": "tripwire-hit", "severity": "critical", "on_match": []any{"alert"},
			"match": map[string]any{"kind": "tripwire.hit"}}), cur, t0, ReasonFloor, false},
		{"floor tightened to enforce", mk(6, 0, r1, floorRule("critical", "enforce")), cur, t0, "", false},
		{"floor removed", mk(6, 0, r1), curFloor, t0, ReasonFloor, false},
		{"floor kept", mk(6, 0, r1, floorRule("critical", "monitor")), curFloor, t0, "", false},
		{"loosen 2h under 24h policy", mk(6, 2*time.Hour, loosened), cur, t0, ReasonEarlyLoosening, false},
		{"loosen 25h", mk(6, 25*time.Hour, loosened), cur, t0, "", true},
		{"rule removed immediate", mk(6, 0), cur, t0, ReasonEarlyLoosening, false},
		{"tighten immediate", mk(6, 0, r1, rule("r2", "low", "monitor", "x")), cur, t0, "", false},
		{"tighten scheduled", mk(6, time.Hour, r1, rule("r2", "low", "monitor", "x")), cur, t0, "", true},
		{"effective passed", mk(6, time.Hour, r1), cur, t0.Add(2 * time.Hour), "", false},
		{"created in future", mk(6, 0, r1), cur, t0.Add(-time.Hour), ReasonBadTime, false},
		{"effective before created", mk(6, -time.Hour, r1), cur, t0, ReasonBadTime, false},
		{"zero times", &Bundle{Version: 6, Rules: []map[string]any{r1}}, cur, t0, ReasonBadTime, false},
		{"bad rule", mk(6, 0, map[string]any{"id": "bad"}), cur, t0, ReasonMalformed, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := signed(t, tc.b, ss[0], ss[1])
			b, err := Verify(data, tr, tc.cur, tc.now)
			if tc.want != "" {
				if got := reasonOf(t, err); got != tc.want {
					t.Fatalf("reason %q (%v), want %q", got, err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if b.Pending != tc.pending {
				t.Fatalf("pending %v, want %v", b.Pending, tc.pending)
			}
		})
	}
}

func TestLooseningDelayConfig(t *testing.T) {
	ss := newSigners(t, 2)
	if _, err := ParseTrust([]byte(trustYAML(ss, "loosening_delay: 30m\n"))); err == nil {
		t.Fatal("delay under 1h must be rejected")
	}
	tr := trustFor(t, ss, "loosening_delay: 2h\n")
	cur := &Applied{Version: 1, Rules: []map[string]any{rule("r1", "high", "enforce", "a.com")}}
	loose := rule("r1", "high", "monitor", "a.com")
	if _, err := Verify(signed(t, mk(2, 3*time.Hour, loose), ss[0], ss[1]), tr, cur, t0); err != nil {
		t.Fatalf("3h under 2h policy: %v", err)
	}
	if _, err := Verify(signed(t, mk(2, time.Hour, loose), ss[0], ss[1]), tr, cur, t0); reasonOf(t, err) != ReasonEarlyLoosening {
		t.Fatalf("1h under 2h policy: %v", err)
	}
}

func trustYAML(ss []signer, extra string) string {
	s := extra + "keys:\n"
	for _, k := range ss {
		s += fmt.Sprintf("  - key_id: %s\n    public_key: %s\n", k.id, base64.StdEncoding.EncodeToString(k.pub))
	}
	return s
}

func TestTrustValidation(t *testing.T) {
	ss := newSigners(t, 1)
	for name, y := range map[string]string{
		"required above keys": trustYAML(ss, "required_signatures: 3\n"),
		"bad key":             "keys:\n  - {key_id: a, public_key: AAAA}\nrequired_signatures: 1\n",
		"unknown field":       trustYAML(ss, "required_signatures: 1\nfoo: 1\n"),
	} {
		if _, err := ParseTrust([]byte(y)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	two := newSigners(t, 2)
	tr, err := ParseTrust([]byte(trustYAML(two, "")))
	if err != nil || tr.RequiredSignatures != 2 || tr.LooseningDelay != 24*time.Hour {
		t.Fatalf("defaults: %+v %v", tr, err)
	}
}

func TestCheckOutcome(t *testing.T) {
	ss := newSigners(t, 2)
	tr := trustFor(t, ss, "")
	r1 := rule("r1", "high", "enforce", "a.com")
	cur := &Applied{Version: 1, Rules: []map[string]any{r1}}

	b, o := Check(signed(t, mk(2, 0, r1, rule("r2", "low", "monitor", "x")), ss[0], ss[1]), tr, cur, t0)
	if !o.Accepted || o.Version != 2 || b == nil || len(o.Changes) != 1 || o.Changes[0].Dir != Tighten {
		t.Fatalf("accepted: %+v", o)
	}
	_, o = Check(signed(t, mk(3, 0, r1), ss[0]), tr, cur, t0)
	if o.Accepted || o.Reason != ReasonUnsigned || o.Version != 3 {
		t.Fatalf("rejected: %+v", o)
	}
	fl := map[string]any{"id": "tripwire-hit", "severity": "low", "on_match": []any{"alert"}, "match": map[string]any{"kind": "tripwire.hit", "selftest": false}}
	_, o = Check(signed(t, mk(3, 0, r1, fl), ss[0], ss[1]), tr, cur, t0)
	if o.Accepted || o.Reason != ReasonFloor || !o.Critical {
		t.Fatalf("floor: %+v", o)
	}
	_, o = Check([]byte("not: [valid"), tr, cur, t0)
	if o.Accepted || o.Reason != ReasonMalformed {
		t.Fatalf("malformed: %+v", o)
	}
}

func TestDiffClassification(t *testing.T) {
	mkRule := func(mods map[string]any) map[string]any {
		r := map[string]any{"id": "r", "severity": "high", "mode": "enforce", "on_match": []any{"alert"},
			"match":     map[string]any{"kind": "egress.connect", "host_not_in": []any{"a.com"}, "path_in": []any{"/x", "/y"}},
			"correlate": map[string]any{"within": "5m"}}
		for k, v := range mods {
			r[k] = v
		}
		return r
	}
	match := func(m map[string]any) map[string]any { return map[string]any{"match": m} }
	tests := []struct {
		name string
		old  []map[string]any
		new  []map[string]any
		want []Direction
	}{
		{"same", []map[string]any{mkRule(nil)}, []map[string]any{mkRule(nil)}, nil},
		{"rule removed", []map[string]any{mkRule(nil)}, nil, []Direction{Loosen}},
		{"rule added", nil, []map[string]any{mkRule(nil)}, []Direction{Tighten}},
		{"enforce to monitor", []map[string]any{mkRule(nil)}, []map[string]any{mkRule(map[string]any{"mode": "monitor"})}, []Direction{Loosen}},
		{"monitor to enforce", []map[string]any{mkRule(map[string]any{"mode": "monitor"})}, []map[string]any{mkRule(nil)}, []Direction{Tighten}},
		{"severity lowered", []map[string]any{mkRule(nil)}, []map[string]any{mkRule(map[string]any{"severity": "low"})}, []Direction{Loosen}},
		{"severity raised", []map[string]any{mkRule(nil)}, []map[string]any{mkRule(map[string]any{"severity": "critical"})}, []Direction{Tighten}},
		{"allowlist widened", []map[string]any{mkRule(nil)},
			[]map[string]any{mkRule(match(map[string]any{"kind": "egress.connect", "host_not_in": []any{"a.com", "b.com"}, "path_in": []any{"/x", "/y"}}))}, []Direction{Loosen}},
		{"allowlist narrowed", []map[string]any{mkRule(nil)},
			[]map[string]any{mkRule(match(map[string]any{"kind": "egress.connect", "host_not_in": []any{}, "path_in": []any{"/x", "/y"}}))}, []Direction{Tighten}},
		{"deny list shrunk", []map[string]any{mkRule(nil)},
			[]map[string]any{mkRule(match(map[string]any{"kind": "egress.connect", "host_not_in": []any{"a.com"}, "path_in": []any{"/x"}}))}, []Direction{Loosen}},
		{"deny list grown", []map[string]any{mkRule(nil)},
			[]map[string]any{mkRule(match(map[string]any{"kind": "egress.connect", "host_not_in": []any{"a.com"}, "path_in": []any{"/x", "/y", "/z"}}))}, []Direction{Tighten}},
		{"condition removed (conservative)", []map[string]any{mkRule(nil)},
			[]map[string]any{mkRule(match(map[string]any{"kind": "egress.connect", "host_not_in": []any{"a.com"}}))}, []Direction{Loosen}},
		{"within lengthened", []map[string]any{mkRule(nil)}, []map[string]any{mkRule(map[string]any{"correlate": map[string]any{"within": "10m"}})}, []Direction{Loosen}},
		{"within shortened", []map[string]any{mkRule(nil)}, []map[string]any{mkRule(map[string]any{"correlate": map[string]any{"within": "1m"}})}, []Direction{Tighten}},
		{"action added", []map[string]any{mkRule(nil)}, []map[string]any{mkRule(map[string]any{"on_match": []any{"alert", "page"}})}, []Direction{Tighten}},
		{"action removed", []map[string]any{mkRule(nil)}, []map[string]any{mkRule(map[string]any{"on_match": []any{"page"}})}, []Direction{Loosen, Tighten}},
		{"description only", []map[string]any{mkRule(nil)}, []map[string]any{mkRule(map[string]any{"description": "new"})}, nil},
		{"mixed", []map[string]any{mkRule(nil)}, []map[string]any{mkRule(map[string]any{"severity": "critical", "mode": "monitor"})}, []Direction{Loosen, Tighten}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []Direction
			for _, c := range Diff(tc.old, tc.new) {
				got = append(got, c.Dir)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("got %v, want %v: %+v", got, tc.want, Diff(tc.old, tc.new))
			}
		})
	}
}

// Rules parsed from YAML must diff the same as hand-built maps.
func TestDiffFromYAML(t *testing.T) {
	var a, b map[string]any
	_ = yaml.Unmarshal([]byte("id: r\nmatch: {host_not_in: [a.com]}\n"), &a)
	_ = yaml.Unmarshal([]byte("id: r\nmatch: {host_not_in: [a.com, b.com]}\n"), &b)
	cs := Diff([]map[string]any{a}, []map[string]any{b})
	if len(cs) != 1 || cs[0].Dir != Loosen {
		t.Fatalf("%+v", cs)
	}
}
