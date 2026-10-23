package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Parthkomalwad/tripline/internal/audit"
)

func TestAuditVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Append("event", map[string]int{"i": 1})
	l.Append("event", map[string]int{"i": 2})
	l.Close()

	var out, errb bytes.Buffer
	if code := run([]string{"audit", "verify", "-file", path}, &out, &errb); code != 0 || out.String() != "ok: 2 entries\n" {
		t.Fatalf("valid: code=%d out=%q err=%q", code, out.String(), errb.String())
	}
	b, _ := os.ReadFile(path)
	os.WriteFile(path, bytes.Replace(b, []byte(`"i":1`), []byte(`"i":9`), 1), 0o600)
	out.Reset()
	errb.Reset()
	if code := run([]string{"audit", "verify", "-file", path}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "seq 1") {
		t.Fatalf("tampered: code=%d err=%q", code, errb.String())
	}
}
