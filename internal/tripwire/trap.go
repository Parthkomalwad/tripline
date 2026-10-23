package tripwire

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
)

// DefaultRule is the core rule for trap hits. Self-test hits do not match.
const DefaultRule = `id: tripwire-hit
description: A decoy was used. Someone or something read a planted file and tried it.
severity: critical
on_match: [alert, runbook]
match:
  kind: tripwire.hit
  selftest: false
`

const (
	sensor      = "watcher-trap"
	maxDrain    = 1024
	maxAgentLen = 128
	denied      = `{"error":{"message":"Incorrect API key provided.","type":"invalid_request_error","code":"invalid_api_key"}}` + "\n"
)

// Ingest is (*watcher.Watcher).Ingest.
type Ingest func(sensorID string, e *event.Event) error

// Handler serves /trap/<token>/... and reports each hit on a known token.
type Handler struct {
	Registry *Registry
	Ingest   Ingest
	Log      *slog.Logger
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/trap/")
	token, _, _ := strings.Cut(rest, "/")
	d, known := h.Registry.Lookup(token)
	if !ok || !known {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Read and drop at most 1 KiB. Never store the body.
	_, _ = io.CopyN(io.Discard, r.Body, maxDrain)

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	e := &event.Event{
		ID: "evt_" + randHex(8), TS: time.Now().UTC(),
		Source: "watcher.trap", SourceID: sensor, Subject: subject(d.Location),
		Kind: event.KindTripwireHit, Decision: event.DecisionNone,
		Attrs: map[string]any{
			"token_fp": Fingerprint(d.Token), "fingerprint": Fingerprint(d.Token), "decoy_kind": d.Kind, "remote_ip": ip,
			"method": r.Method, "path_len": len(r.URL.Path),
			"user_agent": truncate(r.UserAgent(), maxAgentLen), "selftest": d.Selftest,
		},
	}
	if err := h.Ingest(sensor, e); err != nil {
		h.Log.Error("trap hit not recorded", "err", err, "token_fp", Fingerprint(d.Token))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, denied)
}

// subject makes a location fit the event name rules.
func subject(loc string) string {
	s := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("._:/-", r):
			return r
		case r == '\\':
			return '/'
		}
		return '_'
	}, loc)
	if len(s) > 256 {
		s = s[len(s)-256:]
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "")
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
