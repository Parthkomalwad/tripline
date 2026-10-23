package watcher

import (
	"encoding/json"
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

func newWatcher(t *testing.T) (*Watcher, string) {
	t.Helper()
	dir := t.TempDir()
	tok, err := LoadTokens(dir)
	if err != nil {
		t.Fatal(err)
	}
	token, err := tok.Add("s1")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := rules.Parse([]byte("id: hb\nseverity: low\non_match: [alert]\nmatch: {kind: heartbeat}\n"))
	if err != nil {
		t.Fatal(err)
	}
	w := &Watcher{Tokens: tok, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w.SetRules(rs)
	return w, token
}

func post(w *Watcher, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	w.HandleEvents(rec, req)
	return rec
}

const goodEvent = `{"id":"e1","ts":"2026-10-21T11:47:02Z","source":"sensor.egress","source_id":"s1","subject":"gw","kind":"heartbeat","decision":"none"}`

func TestHandleEvents(t *testing.T) {
	w, token := newWatcher(t)
	var got []string
	w.Observe(func(e *event.Event, m []*rules.Rule) {
		for _, r := range m {
			got = append(got, e.ID+":"+r.ID)
		}
	})
	rejects := 0
	w.ObserveRejects(func(string, string) { rejects++ })

	if rec := post(w, "", "[]"); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: code %d", rec.Code)
	}
	if rec := post(w, "tlsen_wrong", "[]"); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: code %d", rec.Code)
	}
	if rec := post(w, token, "{}"); rec.Code != http.StatusBadRequest {
		t.Errorf("object body: code %d", rec.Code)
	}

	spoofed := strings.Replace(goodEvent, `"s1"`, `"other"`, 1)
	extra := strings.Replace(goodEvent, `"id"`, `"secret":"x","id"`, 1)
	rec := post(w, token, "["+goodEvent+","+spoofed+","+extra+"]")
	if rec.Code != http.StatusOK {
		t.Fatalf("batch: code %d %s", rec.Code, rec.Body)
	}
	var res ingestResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Accepted != 1 || len(res.Rejected) != 2 || rejects != 2 {
		t.Errorf("accepted %d rejected %v observed rejects %d", res.Accepted, res.Rejected, rejects)
	}
	if strings.Join(got, ",") != "e1:hb" {
		t.Errorf("observed %v", got)
	}
}

func TestTokensStoredHashed(t *testing.T) {
	dir := t.TempDir()
	tok, _ := LoadTokens(dir)
	token, err := tok.Add("s1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tok.Add("s1"); err == nil {
		t.Error("duplicate sensor id accepted")
	}
	if _, err := tok.Add("bad id"); err == nil {
		t.Error("invalid sensor id accepted")
	}
	data, _ := os.ReadFile(filepath.Join(dir, tokensFile))
	if strings.Contains(string(data), token) || strings.Contains(string(data), strings.TrimPrefix(token, tokenPrefix)) {
		t.Error("token file contains the plain token")
	}
	reloaded, _ := LoadTokens(dir)
	if id, ok := reloaded.Lookup(token); !ok || id != "s1" {
		t.Errorf("lookup after reload = %q %v", id, ok)
	}
}
