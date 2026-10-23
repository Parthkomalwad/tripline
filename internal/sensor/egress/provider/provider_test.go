package provider

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/floor"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

const realKey, realOrg = "sk-REAL-upstream-key-1234", "org-real"

type rig struct {
	h     *httptest.Server
	mu    sync.Mutex
	evs   []event.Event
	seen  chan *http.Request // what the upstream received
	reply http.HandlerFunc
}

func (g *rig) events() []event.Event {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]event.Event(nil), g.evs...)
}

func newRig(t *testing.T) *rig {
	t.Helper()
	g := &rig{seen: make(chan *http.Request, 4)}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.seen <- r
		g.reply(w, r)
	}))
	t.Cleanup(up.Close)
	keyFile := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(keyFile, []byte(realKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := New(Options{
		Providers: Providers{Anthropic: &Key{KeyFile: keyFile}, OpenAI: &Key{KeyFile: keyFile, Organization: realOrg}},
		Source:    "sensor.egress", SourceID: "gw", Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Send: func(e event.Event) { g.mu.Lock(); g.evs = append(g.evs, e); g.mu.Unlock() },
		// The same fake upstream stands in for both providers.
		Upstream: map[string]string{"anthropic": up.URL, "openai": up.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	g.h = httptest.NewServer(h)
	t.Cleanup(g.h.Close)
	return g
}

func (g *rig) do(t *testing.T, method, p, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, g.h.URL+p, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestInjectsKeyAndDropsClientAuth(t *testing.T) {
	g := newRig(t)
	g.reply = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }
	resp := g.do(t, "POST", "/openai/v1/chat/completions", `{"model":"gpt-x"}`, map[string]string{
		"Anthropic-Version": "2026-10-21", "Accept-Encoding": "gzip"})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	up := <-g.seen
	if up.Header.Get("Authorization") != "Bearer "+realKey || up.Header.Get("OpenAI-Organization") != realOrg {
		t.Errorf("upstream headers %v", up.Header)
	}
	if up.URL.Path != "/v1/chat/completions" || up.Header.Get("Anthropic-Version") != "2026-10-21" {
		t.Errorf("path %q headers %v", up.URL.Path, up.Header)
	}
	if up.Header.Get("Accept-Encoding") == "gzip, deflate" {
		t.Error("client Accept-Encoding forwarded")
	}
}

func TestForeignCredentialRejected(t *testing.T) {
	cases := []struct {
		name, path string
		hdr        map[string]string
	}{
		{"authorization", "/anthropic/v1/messages", map[string]string{"Authorization": "Bearer sk-ATTACKER-secret"}},
		{"x-api-key", "/anthropic/v1/messages", map[string]string{"X-Api-Key": "sk-ATTACKER-secret"}},
		{"org", "/openai/v1/responses", map[string]string{"OpenAI-Organization": "org-attacker"}},
		{"project", "/openai/v1/responses", map[string]string{"OpenAI-Project": "proj-attacker"}},
		{"workspace", "/anthropic/v1/messages", map[string]string{"Anthropic-Workspace-Id": "wrkspc_attacker"}},
		{"query", "/openai/v1/models?api_key=sk-ATTACKER-secret", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newRig(t)
			g.reply = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }
			resp := g.do(t, "POST", c.path, `{"model":"m"}`, c.hdr)
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status %d, want 403", resp.StatusCode)
			}
			select {
			case <-g.seen:
				t.Fatal("request reached upstream")
			default:
			}
			evs := g.events()
			if len(evs) != 1 || evs[0].Decision != event.DecisionDeny || evs[0].Kind != event.KindProviderRequest {
				t.Fatalf("events %+v", evs)
			}
			a := evs[0].Attrs
			b, _ := json.Marshal(evs[0])
			if strings.Contains(string(b), "ATTACKER-secret") || strings.Contains(string(b), "sk-ATTACKER-secret") {
				t.Errorf("event holds the key: %s", b)
			}
			if a["reason"] != "foreign credential" || a["fingerprint"] == "" || a["fingerprint"] == nil {
				t.Errorf("attrs %v", a)
			}
			// The floor rule must alert critical on this event.
			var hit bool
			for _, r := range rules.Evaluate(floor.Rules(), &evs[0]) {
				hit = hit || (r.ID == "floor-foreign-credential" && r.Severity == "critical")
			}
			if !hit {
				t.Error("floor-foreign-credential did not match")
			}
		})
	}
}

func TestModelAndTokensFromJSON(t *testing.T) {
	for _, c := range []struct {
		name, path, resp string
		in, out          int
	}{
		{"anthropic", "/anthropic/v1/messages", `{"usage":{"input_tokens":11,"output_tokens":7}}`, 11, 7},
		{"chat", "/openai/v1/chat/completions", `{"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`, 5, 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := newRig(t)
			g.reply = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, c.resp)
			}
			resp := g.do(t, "POST", c.path, `{"model":"model-42","messages":[{"content":"SECRET PROMPT"}]}`, nil)
			body, _ := io.ReadAll(resp.Body)
			if string(body) != c.resp {
				t.Errorf("client body %q", body) // response is replayed unchanged
			}
			evs := g.events()
			if len(evs) != 1 {
				t.Fatalf("events %+v", evs)
			}
			a := evs[0].Attrs
			if a["model"] != "model-42" || a["status"] != 200 || a["input_tokens"] != c.in || a["output_tokens"] != c.out {
				t.Errorf("attrs %v", a)
			}
			if a["latency_ms"] == nil || a["method"] != "POST" || a["path"] != "/"+strings.SplitN(c.path, "/", 3)[2] {
				t.Errorf("attrs %v", a)
			}
			if b, _ := json.Marshal(evs[0]); strings.Contains(string(b), "SECRET PROMPT") || strings.Contains(string(b), c.resp) {
				t.Errorf("body in event: %s", b)
			}
		})
	}
}

func TestBodyReplayedUpstream(t *testing.T) {
	got := make(chan string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
	}))
	defer up.Close()
	t.Setenv("TL_TEST_KEY", realKey)
	h, err := New(Options{Providers: Providers{Anthropic: &Key{KeyEnv: "TL_TEST_KEY"}}, Send: func(event.Event) {},
		Upstream: map[string]string{"anthropic": up.URL}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	const body = `{"model":"m","stream":true,"messages":["hello"]}`
	resp, err := http.Post(srv.URL+"/anthropic/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if s := <-got; s != body {
		t.Errorf("upstream got %q", s)
	}
}

func TestStreamPassesThroughUnbuffered(t *testing.T) {
	g := newRig(t)
	release := make(chan struct{})
	g.reply = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}\n\n")
		w.(http.Flusher).Flush()
		<-release // the stream stays open until the client has the first chunk
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}
	resp := g.do(t, "POST", "/openai/v1/chat/completions", `{"model":"m","stream":true}`, nil)
	buf := make([]byte, 20)
	done := make(chan struct{})
	go func() { _, _ = io.ReadFull(resp.Body, buf); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("first chunk was buffered")
	}
	close(release)
	_, _ = io.Copy(io.Discard, resp.Body)
	evs := g.events()
	if len(evs) != 1 {
		t.Fatalf("events %+v", evs)
	}
	if _, ok := evs[0].Attrs["input_tokens"]; ok {
		t.Errorf("stream has token counts: %v", evs[0].Attrs)
	}
	if _, ok := evs[0].Attrs["output_tokens"]; ok {
		t.Errorf("stream has token counts: %v", evs[0].Attrs)
	}
}

func TestUnknownPrefixAndBadPath(t *testing.T) {
	g := newRig(t)
	g.reply = func(w http.ResponseWriter, r *http.Request) {}
	for p, want := range map[string]int{"/other/v1/x": 404, "/": 404, "/anthropic/../openai/x": 400, "/anthropic//x": 400} {
		if got := g.do(t, "GET", p, "", nil).StatusCode; got != want {
			t.Errorf("%s: %d, want %d", p, got, want)
		}
	}
	if len(g.events()) != 0 {
		t.Error("events for unrouted requests")
	}
}

func TestClientHostCannotChangeUpstream(t *testing.T) {
	g := newRig(t)
	g.reply = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }
	req, _ := http.NewRequest("GET", g.h.URL+"/anthropic/v1/models", nil)
	req.Host = "evil.example.com"
	req.Header.Set("X-Forwarded-Host", "evil.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	up := <-g.seen
	if strings.Contains(up.Host, "evil") || up.Header.Get("X-Forwarded-Host") != "" {
		t.Errorf("upstream saw Host %q, headers %v", up.Host, up.Header)
	}
}

func TestOfficialHostsAreFixed(t *testing.T) {
	if official["anthropic"] != "https://api.anthropic.com" || official["openai"] != "https://api.openai.com" {
		t.Errorf("official = %v", official)
	}
}

func TestKeyConfig(t *testing.T) {
	for name, k := range map[string]*Key{
		"none": {}, "both": {KeyFile: "a", KeyEnv: "B"}, "missing env": {KeyEnv: "TL_NOT_SET_XYZ"},
		"missing file": {KeyFile: filepath.Join(t.TempDir(), "nope")},
	} {
		if _, err := New(Options{Providers: Providers{OpenAI: k}}); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := New(Options{Providers: Providers{Anthropic: &Key{KeyEnv: "X", Project: "p"}}}); err == nil {
		t.Error("anthropic project: want error")
	}
}
