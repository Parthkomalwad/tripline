package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const bundleBody = `version: 3
created_at: %s
effective_at: %s
signers: [maya, raj]
rules:
  - id: r1
    severity: high
    on_match: [alert]
    match: {kind: egress.connect, host_not_in: [a.com]}
`

func TestRulesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ts := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	bundlePath := filepath.Join(dir, "bundle.yaml")
	if err := os.WriteFile(bundlePath, []byte(strings.NewReplacer("%s", ts).Replace(bundleBody)), 0o644); err != nil {
		t.Fatal(err)
	}

	trust := "required_signatures: 2\nkeys:\n"
	for _, id := range []string{"maya-2026", "raj-2026"} {
		code, out, errOut := do("rules", "keygen", "-id", id, "-out", dir, "-owner", id)
		if code != 0 || !strings.Contains(out, "key_id: "+id) {
			t.Fatalf("keygen = %d %q %q", code, out, errOut)
		}
		_, snippet, _ := strings.Cut(out, ":\n")
		trust += snippet
		if runtime.GOOS != "windows" {
			if fi, err := os.Stat(filepath.Join(dir, id+".key")); err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("private key mode: %v %v", fi, err)
			}
		}
	}
	// keygen never overwrites an existing key.
	if code, _, _ := do("rules", "keygen", "-id", "maya-2026", "-out", dir); code != 1 {
		t.Errorf("second keygen = %d, want 1", code)
	}
	trustPath := filepath.Join(dir, "trust.yaml")
	if err := os.WriteFile(trustPath, []byte(trust), 0o644); err != nil {
		t.Fatal(err)
	}

	if code, _, _ := do("rules", "verify", "-trust", trustPath, bundlePath); code != 1 {
		t.Fatalf("unsigned bundle verified: %d", code)
	}
	for _, id := range []string{"maya-2026", "raj-2026"} {
		if code, _, errOut := do("rules", "sign", "-key", filepath.Join(dir, id+".key"), "-in", bundlePath); code != 0 {
			t.Fatalf("sign = %d %q", code, errOut)
		}
	}
	code, out, errOut := do("rules", "verify", "-trust", trustPath, bundlePath)
	if code != 0 || !strings.Contains(out, "ok: version 3") {
		t.Fatalf("verify = %d %q %q", code, out, errOut)
	}
	// Re-signing replaces the signature instead of adding a second one.
	do("rules", "sign", "-key", filepath.Join(dir, "maya-2026.key"), "-in", bundlePath)
	data, _ := os.ReadFile(bundlePath)
	if n := strings.Count(string(data), "key_id: maya-2026"); n != 1 {
		t.Errorf("maya signatures = %d, want 1", n)
	}
	if code, _, _ := do("rules", "verify", "-trust", trustPath, "-current", "3", bundlePath); code != 1 {
		t.Error("rollback verified")
	}
	if err := os.WriteFile(bundlePath, []byte(strings.Replace(string(data), "a.com", "evil.com", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := do("rules", "verify", "-trust", trustPath, bundlePath); code != 1 {
		t.Error("tampered bundle verified")
	}
}

func TestRulesDiff(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old.yaml")
	nw := filepath.Join(dir, "new.yaml")
	ts := "2026-10-24T09:00:00Z"
	body := strings.NewReplacer("%s", ts).Replace(bundleBody)
	_ = os.WriteFile(old, []byte(body), 0o644)
	_ = os.WriteFile(nw, []byte(strings.Replace(body, "a.com]", "a.com, b.com]", 1)), 0o644)
	code, out, _ := do("rules", "diff", old, nw)
	if code != 0 || !strings.Contains(out, "loosen") || !strings.Contains(out, "r1") {
		t.Fatalf("diff = %d %q", code, out)
	}
}
