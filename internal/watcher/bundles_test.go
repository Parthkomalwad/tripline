package watcher

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Parthkomalwad/tripline/internal/bundle"
	"github.com/Parthkomalwad/tripline/internal/rules"
	"github.com/Parthkomalwad/tripline/internal/sinks"
)

type bundleLab struct {
	t       *testing.T
	dir     string
	keys    map[string]ed25519.PrivateKey
	b       *Bundles
	alerts  []sinks.Alert
	audit   []string
	version int
	now     time.Time
}

func newBundleLab(t *testing.T) *bundleLab {
	l := &bundleLab{t: t, dir: t.TempDir(), keys: map[string]ed25519.PrivateKey{}, now: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	var trust strings.Builder
	trust.WriteString("required_signatures: 2\nkeys:\n")
	for _, id := range []string{"maya", "raj", "lee"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		l.keys[id] = priv
		fmt.Fprintf(&trust, "  - {key_id: %s, public_key: %s}\n", id, base64.StdEncoding.EncodeToString(pub))
	}
	tr, err := bundle.ParseTrust([]byte(trust.String()))
	if err != nil {
		t.Fatal(err)
	}
	l.b = &Bundles{
		Trust: tr, File: filepath.Join(l.dir, "bundle.yaml"), StateDir: l.dir,
		Apply: func(_ []*rules.Rule, v int) { l.version = v },
		Audit: func(typ string, _ any) error { l.audit = append(l.audit, typ); return nil },
		Alert: func(a sinks.Alert) { l.alerts = append(l.alerts, a) },
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:   func() time.Time { return l.now },
	}
	return l
}

const ruleHigh = "{id: egress-allowlist, severity: high, mode: enforce, on_match: [alert, block], match: {kind: egress.connect, host_not_in: [api.anthropic.com]}}"

// publish writes a bundle signed by the given keys and runs one check.
func (l *bundleLab) publish(version int, delay time.Duration, rulesYAML string, signers ...string) {
	l.t.Helper()
	src := fmt.Sprintf("version: %d\ncreated_at: %s\neffective_at: %s\nsigners: [%s]\nrules: [%s]\n",
		version, l.now.Format(time.RFC3339), l.now.Add(delay).Format(time.RFC3339), strings.Join(signers, ", "), rulesYAML)
	b, err := bundle.Parse([]byte(src))
	if err != nil {
		l.t.Fatal(err)
	}
	for _, s := range signers {
		if err := b.Sign(s, l.keys[s]); err != nil {
			l.t.Fatal(err)
		}
	}
	data, err := b.Marshal()
	if err != nil {
		l.t.Fatal(err)
	}
	if err := os.WriteFile(l.b.File, data, 0o600); err != nil {
		l.t.Fatal(err)
	}
	l.alerts = nil
	l.b.Check()
}

func TestBundlesDoneWhen(t *testing.T) {
	l := newBundleLab(t)
	l.publish(1, 0, ruleHigh, "maya", "raj")
	if l.version != 1 || len(l.alerts) != 0 {
		t.Fatalf("v1: applied %d alerts %v", l.version, l.alerts)
	}

	reject := []struct {
		name     string
		version  int
		delay    time.Duration
		rules    string
		signers  []string
		severity string
	}{
		{"unsigned", 2, 0, ruleHigh, nil, "high"},
		{"one signature", 2, 0, ruleHigh, []string{"maya"}, "high"},
		{"older", 1, 0, ruleHigh, []string{"maya", "raj"}, "high"},
		{"floor weakened", 2, 0, ruleHigh + ", {id: tripwire-hit, severity: low, on_match: [alert], match: {kind: tripwire.hit, selftest: false}}", []string{"maya", "raj"}, "critical"},
		{"early loosening", 2, time.Hour, strings.Replace(ruleHigh, "mode: enforce", "mode: monitor", 1), []string{"maya", "raj"}, "high"},
	}
	for _, tc := range reject {
		l.publish(tc.version, tc.delay, tc.rules, tc.signers...)
		if l.version != 1 {
			t.Errorf("%s: applied version %d", tc.name, l.version)
		}
		if len(l.alerts) != 1 || l.alerts[0].Severity != tc.severity {
			t.Errorf("%s: alerts %+v, want one %s alert", tc.name, l.alerts, tc.severity)
		}
		if last := l.audit[len(l.audit)-1]; last != "bundle.rejected" {
			t.Errorf("%s: last audit entry %q", tc.name, last)
		}
	}

	// Loosening with a long enough delay is announced, then applied later.
	l.publish(3, 25*time.Hour, strings.Replace(ruleHigh, "mode: enforce", "mode: monitor", 1), "raj", "lee")
	if l.version != 1 || len(l.alerts) != 1 || !strings.Contains(l.alerts[0].What, "takes effect") {
		t.Fatalf("pending loosening: version %d alerts %+v", l.version, l.alerts)
	}
	l.now = l.now.Add(26 * time.Hour)
	l.alerts = nil
	l.b.Check()
	if l.version != 3 || len(l.alerts) != 1 || !strings.Contains(l.alerts[0].What, "now in effect") {
		t.Errorf("loosening in effect: version %d alerts %+v", l.version, l.alerts)
	}
}

func TestBundlesReloadAndServe(t *testing.T) {
	l := newBundleLab(t)
	l.publish(1, 0, ruleHigh, "maya", "raj")

	again := newBundleLab(t)
	again.b.Trust, again.b.StateDir = l.b.Trust, l.dir
	if err := again.b.Load(); err != nil || again.version != 1 {
		t.Fatalf("reload: version %d err %v", again.version, err)
	}

	applied := filepath.Join(l.dir, appliedBundleFile)
	data, _ := os.ReadFile(applied)
	os.WriteFile(applied, []byte(strings.Replace(string(data), "high", "low", 1)), 0o600)
	if err := again.b.Load(); err == nil {
		t.Error("edited applied bundle accepted on load")
	}

	tokens, _ := LoadTokens(t.TempDir())
	token, _ := tokens.Add("s1")
	h := l.b.Handler(tokens)
	for _, tc := range []struct {
		token string
		code  int
	}{{"", 401}, {"tlsen_x", 401}, {token, 200}} {
		req := httptest.NewRequest(http.MethodGet, "/v1/bundle", nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != tc.code {
			t.Errorf("token %q: code %d, want %d", tc.token, rec.Code, tc.code)
		}
	}
}
