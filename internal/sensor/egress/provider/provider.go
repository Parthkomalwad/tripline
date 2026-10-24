// Package provider is provider mode: a plain-HTTP listener for the AI
// gateway that pins the tenant. It rejects any request that carries its own
// credential, injects the real key, and forwards over TLS to the official
// host. It records metadata only. Bodies are never logged or stored.
//
// Verified from the official docs (fetched 2026-10-24):
//
// Anthropic, https://platform.claude.com/docs/en/api/overview
// (redirected from https://docs.anthropic.com/en/api/overview):
//
//	"The Claude API is a RESTful API at `https://api.anthropic.com`"
//	"`Authorization` | `Bearer <token>`, where `<token>` is your API key ..."
//	"`x-api-key` | Your API key from Console. Legacy fallback for `Authorization`, still supported"
//	"`anthropic-workspace-id` | ID of the workspace the request runs in"
//	"`anthropic-version` | API version ... Required: Yes"
//
// Messages: POST /v1/messages, https://platform.claude.com/docs/en/api/messages/create
//
//	Request fields: `model`, `stream`. Response `usage`: `input_tokens`
//	("The number of input tokens which were used."), `output_tokens`.
//	Streaming: `message_start` carries a Message with usage; `message_delta`
//	carries cumulative `usage`. We do not parse streams.
//
// OpenAI, https://platform.openai.com/docs/api-reference/authentication
// (the fetcher got 403 there; the same text was read at
// https://developers.openai.com/api/reference/overview):
//
//	"Authorization: Bearer OPENAI_API_KEY_OR_ACCESS_TOKEN"
//	"OpenAI-Organization" and "OpenAI-Project" request headers
//	examples use the base URL https://api.openai.com/v1/
//
// Chat Completions: POST /chat/completions. Usage fields `prompt_tokens`,
// `completion_tokens`, `total_tokens`. A stream reports usage only in an
// extra last chunk when `stream_options.include_usage` is set
// (https://developers.openai.com/api/reference/resources/chat).
// Responses: POST /responses. Usage fields `input_tokens`, `output_tokens`,
// `total_tokens`
// (https://developers.openai.com/api/reference/resources/responses/methods/create).
//
// The sensor injects "Authorization: Bearer <key>" for both providers, the
// primary documented form. Anthropic's x-api-key is the legacy fallback, so
// a client that sends it still presents a foreign credential.
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/Parthkomalwad/tripline/internal/client"
	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/tripwire"
)

// Official upstreams. Tests replace them through Options.Upstream.
var official = map[string]string{
	"anthropic": "https://api.anthropic.com",
	"openai":    "https://api.openai.com",
}

const (
	maxReqPeek    = 1 << 20 // request bytes read to find "model"
	maxRespRead   = 8 << 20 // largest non-streaming response read for "usage"
	reasonForeign = "foreign credential"
)

// foreignHeaders carry a credential or tenant id for either provider.
// Legitimate traffic in this mode carries none of them.
var foreignHeaders = []string{"Authorization", "Proxy-Authorization", "X-Api-Key", "Api-Key",
	"OpenAI-Organization", "OpenAI-Project", "Anthropic-Workspace-Id"}

// foreignQuery are query parameter names that carry a key.
var foreignQuery = []string{"key", "api_key", "api-key", "apikey", "x-api-key", "access_token", "token"}

// Options configure New.
type Options struct {
	Providers Providers
	Source    string // event source, for example "sensor.egress"
	SourceID  string
	Send      func(event.Event) // must not block
	Log       *slog.Logger
	Upstream  map[string]string // test override of the official base URLs
}

type route struct {
	name, key, org, project string
	target                  *url.URL
	proxy                   *httputil.ReverseProxy
}

// Handler serves /anthropic/... and /openai/....
type Handler struct {
	o      Options
	routes map[string]*route
}

// New reads the keys once and builds the handler.
func New(o Options) (*Handler, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	h := &Handler{o: o, routes: map[string]*route{}}
	for name, k := range map[string]*Key{"anthropic": o.Providers.Anthropic, "openai": o.Providers.OpenAI} {
		if k == nil {
			continue
		}
		key, err := k.load(name, o.Log)
		if err != nil {
			return nil, err
		}
		base := official[name]
		if u := o.Upstream[name]; u != "" {
			base = u
		}
		t, err := url.Parse(base)
		if err != nil {
			return nil, err
		}
		rt := &route{name: name, key: key, org: k.Organization, project: k.Project, target: t}
		rt.proxy = &httputil.ReverseProxy{Rewrite: rt.rewrite, FlushInterval: -1,
			ModifyResponse: h.modify, ErrorHandler: h.fail}
		h.routes[name] = rt
	}
	return h, nil
}

type ctxKey struct{}

// meta is the per-request data kept until the response arrives.
type meta struct {
	route  *route
	method string
	path   string
	model  string
	start  time.Time
}

func metaOf(r *http.Request) *meta { return r.Context().Value(ctxKey{}).(*meta) }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	rt := h.routes[name]
	if rt == nil {
		http.NotFound(w, r)
		return
	}
	rest = "/" + rest
	if path.Clean(rest) != rest { // no "..", "//" or "." segments
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	if fp, found := foreignCredential(r); found {
		h.emit(event.DecisionDeny, &meta{route: rt, method: r.Method, path: rest},
			map[string]any{"reason": reasonForeign, "fingerprint": fp})
		http.Error(w, "blocked by tripline: request carries a credential", http.StatusForbidden)
		return
	}
	m := &meta{route: rt, method: r.Method, path: rest, start: time.Now()}
	if r.Method == http.MethodPost && r.Body != nil {
		m.model = peekModel(r)
	}
	r.URL.Path, r.URL.RawPath = rest, ""
	rt.proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, m)))
}

// foreignCredential returns a fingerprint of the first credential found.
// The value itself is never kept.
func foreignCredential(r *http.Request) (string, bool) {
	for _, n := range foreignHeaders {
		if v, ok := r.Header[http.CanonicalHeaderKey(n)]; ok {
			s := ""
			if len(v) > 0 {
				s = strings.TrimSpace(strings.TrimPrefix(v[0], "Bearer "))
			}
			return tripwire.Fingerprint(s), true
		}
	}
	for k, v := range r.URL.Query() {
		for _, n := range foreignQuery {
			if strings.EqualFold(k, n) {
				return tripwire.Fingerprint(strings.Join(v, "")), true
			}
		}
	}
	return "", false
}

// replay returns a body that yields buf, then the rest of body.
func replay(buf []byte, body io.ReadCloser) io.ReadCloser {
	return struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), body), body}
}

// peekModel reads up to maxReqPeek bytes, decodes only "model", and replays
// the bytes upstream. The body is never kept. ponytail: a body over the cap
// is not parsed, so its model is absent. Use a token scanner if that matters.
func peekModel(r *http.Request) string {
	buf, _ := io.ReadAll(io.LimitReader(r.Body, maxReqPeek+1))
	r.Body = replay(buf, r.Body)
	if len(buf) > maxReqPeek {
		return ""
	}
	var b struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(buf, &b) != nil {
		return ""
	}
	return clip(b.Model)
}

// rewrite pins the upstream and the credentials. It never reads the client
// Host. ReverseProxy removes hop-by-hop headers and X-Forwarded-*.
func (rt *route) rewrite(pr *httputil.ProxyRequest) {
	out := pr.Out
	out.URL.Scheme, out.URL.Host = rt.target.Scheme, rt.target.Host
	out.URL.Path = strings.TrimSuffix(rt.target.Path, "/") + pr.In.URL.Path
	out.Host = rt.target.Host
	for _, n := range foreignHeaders {
		out.Header.Del(n)
	}
	out.Header.Del("Accept-Encoding") // the transport then decodes, so usage is readable
	out.Header.Set("Authorization", "Bearer "+rt.key)
	if rt.org != "" {
		out.Header.Set("OpenAI-Organization", rt.org)
	}
	if rt.project != "" {
		out.Header.Set("OpenAI-Project", rt.project)
	}
}

// modify records the event. A JSON body is read (capped) for usage and
// replayed. Anything else, streams included, passes through unread: token
// counts are absent and latency is time to response headers.
func (h *Handler) modify(resp *http.Response) error {
	m := metaOf(resp.Request)
	attrs := map[string]any{"status": resp.StatusCode}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") && resp.ContentLength <= maxRespRead {
		buf, err := io.ReadAll(io.LimitReader(resp.Body, maxRespRead+1))
		resp.Body = replay(buf, resp.Body)
		if err == nil && len(buf) <= maxRespRead {
			addUsage(attrs, buf)
		}
	}
	h.emit(event.DecisionAllow, m, attrs)
	return nil
}

// addUsage copies token counts from a response "usage" object, when present.
func addUsage(attrs map[string]any, body []byte) {
	var u struct {
		Usage *struct {
			InputTokens      *int `json:"input_tokens"`
			OutputTokens     *int `json:"output_tokens"`
			PromptTokens     *int `json:"prompt_tokens"`
			CompletionTokens *int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(body, &u) != nil || u.Usage == nil {
		return
	}
	in, out := u.Usage.InputTokens, u.Usage.OutputTokens
	if in == nil {
		in = u.Usage.PromptTokens
	}
	if out == nil {
		out = u.Usage.CompletionTokens
	}
	if in != nil {
		attrs["input_tokens"] = *in
	}
	if out != nil {
		attrs["output_tokens"] = *out
	}
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	h.o.Log.Error("provider upstream error", "err", err)
	h.emit(event.DecisionAllow, metaOf(r), map[string]any{"status": http.StatusBadGateway, "error": "upstream"})
	http.Error(w, "upstream error", http.StatusBadGateway)
}

// emit sends one egress.provider_request event. Attrs never hold a body or key.
func (h *Handler) emit(d event.Decision, m *meta, extra map[string]any) {
	attrs := map[string]any{"provider": m.route.name, "method": m.method, "path": clip(m.path)}
	for k, v := range extra {
		attrs[k] = v
	}
	if m.model != "" {
		attrs["model"] = m.model
	}
	if !m.start.IsZero() {
		attrs["latency_ms"] = time.Since(m.start).Milliseconds()
	}
	h.o.Send(event.Event{ID: client.NewID(), TS: time.Now().UTC(), Source: h.o.Source,
		SourceID: h.o.SourceID, Subject: h.o.SourceID, Kind: event.KindProviderRequest,
		Decision: d, Attrs: attrs})
}

func clip(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
