package main

import (
	"debug/buildinfo"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestSBOMMatchesBuildinfo(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := filepath.Join(t.TempDir(), "tripline")
	cmd := exec.Command("go", "build", "-o", bin, "../../../cmd/tripline")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	bi, err := buildinfo.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(build(bi, "tripline", "v1.2.3", "abc123", time.Unix(0, 0)))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	// Required document fields (SPDX 2.3 clause 6).
	for k, want := range map[string]string{
		"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
	} {
		if m[k] != want {
			t.Errorf("%s = %v, want %s", k, m[k], want)
		}
	}
	for _, k := range []string{"name", "documentNamespace", "creationInfo", "packages", "relationships"} {
		if m[k] == nil || m[k] == "" {
			t.Errorf("missing %s", k)
		}
	}
	ci := m["creationInfo"].(map[string]any)
	if ci["created"] != "1970-01-01T00:00:00Z" || len(ci["creators"].([]any)) == 0 {
		t.Errorf("bad creationInfo: %v", ci)
	}

	// Required package fields (clause 7) and module list equal to buildinfo.
	got := map[string]string{}
	ids := map[string]bool{}
	for _, p := range m["packages"].([]any) {
		p := p.(map[string]any)
		for _, k := range []string{"name", "SPDXID", "downloadLocation"} {
			if s, _ := p[k].(string); s == "" {
				t.Errorf("package %v missing %s", p["name"], k)
			}
		}
		id := p["SPDXID"].(string)
		if ids[id] {
			t.Errorf("duplicate SPDXID %s", id)
		}
		ids[id] = true
		v, _ := p["versionInfo"].(string)
		got[p["name"].(string)] = v
	}
	if len(bi.Deps) == 0 {
		t.Fatal("binary has no deps; module list check is empty")
	}
	if len(got) != len(bi.Deps)+1 {
		t.Errorf("got %d packages, want %d", len(got), len(bi.Deps)+1)
	}
	for _, d := range bi.Deps {
		if got[d.Path] != d.Version {
			t.Errorf("dep %s: got %q, want %q", d.Path, got[d.Path], d.Version)
		}
	}
	if got["tripline"] != "v1.2.3" {
		t.Errorf("main version = %q", got["tripline"])
	}

	// Every relationship points at a known package; the document describes the main one.
	describes := false
	for _, r := range m["relationships"].([]any) {
		r := r.(map[string]any)
		if !ids[r["relatedSpdxElement"].(string)] {
			t.Errorf("unknown related element %v", r)
		}
		if r["relationshipType"] == "DESCRIBES" {
			describes = true
		}
	}
	if !describes {
		t.Error("no DESCRIBES relationship")
	}
}
