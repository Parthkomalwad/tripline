package tripwire

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

func setup(t *testing.T) (*Handler, *Registry, *[]*event.Event) {
	t.Helper()
	reg, err := LoadRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var got []*event.Event
	h := &Handler{Registry: reg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Ingest: func(id string, e *event.Event) error {
			if err := e.Validate(); err != nil {
				return err
			}
			got = append(got, e)
			return nil
		}}
	return h, reg, &got
}

func do(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("User-Agent", strings.Repeat("u", 300))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUnknownToken(t *testing.T) {
	h, _, got := setup(t)
	for _, p := range []string{"/trap/nope/v1/models", "/trap/", "/other"} {
		if rec := do(h, "GET", p, ""); rec.Code != 404 {
			t.Errorf("%s: code %d", p, rec.Code)
		}
	}
	if len(*got) != 0 {
		t.Fatal("event for unknown token")
	}
}

func TestKnownToken(t *testing.T) {
	h, reg, got := setup(t)
	d, err := reg.Add("gateway-config", `C:\Users\a b\config.yaml`, false)
	if err != nil {
		t.Fatal(err)
	}
	secret := "SECRETBODY"
	rec := do(h, "POST", "/trap/"+d.Token+"/v1/chat/completions", secret+strings.Repeat("x", 5000))
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "invalid_api_key") {
		t.Fatalf("response %d %s", rec.Code, rec.Body)
	}
	if len(*got) != 1 {
		t.Fatalf("events: %d", len(*got))
	}
	e := (*got)[0]
	if e.Kind != event.KindTripwireHit || e.Attrs["token_fp"] != Fingerprint(d.Token) || e.Attrs["selftest"] != false {
		t.Fatalf("event %+v", e)
	}
	if len(e.Attrs["user_agent"].(string)) != 128 {
		t.Error("user agent not truncated")
	}
	// Neither the raw token nor any body byte may appear in the event.
	if s := fmt.Sprintf("%+v", *e); strings.Contains(s, d.Token) || strings.Contains(s, secret) {
		t.Fatalf("leak in %s", s)
	}
}

func TestSelftestDoesNotMatchRule(t *testing.T) {
	h, reg, got := setup(t)
	rs, err := rules.Parse([]byte(DefaultRule))
	if err != nil {
		t.Fatal(err)
	}
	real, _ := reg.Add("gateway-config", "/a", false)
	self, _ := reg.Add("selftest", "/b", true)
	do(h, "GET", "/trap/"+real.Token+"/x", "")
	do(h, "GET", "/trap/"+self.Token+"/x", "")
	if len(*got) != 2 {
		t.Fatalf("events %d", len(*got))
	}
	if len(rules.Evaluate(rs, (*got)[0])) != 1 {
		t.Error("real hit must match")
	}
	if len(rules.Evaluate(rs, (*got)[1])) != 0 {
		t.Error("self-test hit must not match")
	}
}

func TestGenerate(t *testing.T) {
	state, out := t.TempDir(), filepath.Join(t.TempDir(), "decoys")
	ds, err := Generate(state, "https://trap.example.com/", out)
	if err != nil || len(ds) != 2 {
		t.Fatalf("%v %v", ds, err)
	}
	for _, d := range ds {
		data, err := os.ReadFile(d.Location)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "https://trap.example.com/trap/"+d.Token+"/v1") {
			t.Errorf("%s lacks trap url", d.Location)
		}
		if strings.Contains(string(data), "sk-") {
			t.Error("mimics a provider key")
		}
	}
	reg, _ := LoadRegistry(state)
	if _, ok := reg.Lookup(ds[0].Token); !ok {
		t.Error("not in registry")
	}
	if _, err := Generate(state, "https://trap.example.com", out); err == nil {
		t.Fatal("overwrote existing files")
	}
}
