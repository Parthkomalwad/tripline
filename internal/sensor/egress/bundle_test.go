package egress

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Parthkomalwad/tripline/internal/bundle"
	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

// TestPullerTrustsOnlyItsOwnVerification serves bundles from a fake watcher,
// including an older one, and checks the sensor applies only valid upgrades.
func TestPullerTrustsOnlyItsOwnVerification(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	keys := map[string]ed25519.PrivateKey{}
	trustYAML := "required_signatures: 2\nkeys:\n"
	for _, id := range []string{"maya", "raj"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		keys[id] = priv
		trustYAML += fmt.Sprintf("  - {key_id: %s, public_key: %s}\n", id, base64.StdEncoding.EncodeToString(pub))
	}
	trust, err := bundle.ParseTrust([]byte(trustYAML))
	if err != nil {
		t.Fatal(err)
	}
	signed := func(version int, signers ...string) []byte {
		src := fmt.Sprintf("version: %d\ncreated_at: %s\neffective_at: %s\nsigners: [maya, raj]\nrules: [{id: r%d, severity: high, on_match: [alert], match: {kind: egress.connect}}]\n",
			version, now.Format(time.RFC3339), now.Format(time.RFC3339), version)
		b, err := bundle.Parse([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range signers {
			b.Sign(s, keys[s])
		}
		data, _ := b.Marshal()
		return data
	}

	var mu sync.Mutex
	serve := signed(2, "maya", "raj")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Write(serve)
	}))
	defer srv.Close()

	var applied []string
	var kinds []event.Kind
	p := &Puller{URL: srv.URL, Token: "tlsen_x", Trust: trust, StateDir: t.TempDir(), SourceID: "s1",
		Apply: func(rs []*rules.Rule) {
			applied = nil
			for _, r := range rs {
				applied = append(applied, r.ID)
			}
		},
		Send: func(e event.Event) { kinds = append(kinds, e.Kind) },
		Log:  slog.New(slog.NewTextHandler(io.Discard, nil)), HTTP: srv.Client(), Now: func() time.Time { return now },
	}
	fetch := func(data []byte) {
		mu.Lock()
		serve = data
		mu.Unlock()
		if err := p.Fetch(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	fetch(signed(2, "maya", "raj"))
	if p.Version() != 2 || len(applied) == 0 || applied[len(applied)-1] != "r2" {
		t.Fatalf("v2 not applied: version %d rules %v", p.Version(), applied)
	}
	for _, bad := range []struct {
		name string
		data []byte
	}{{"older", signed(1, "maya", "raj")}, {"one signature", signed(3, "maya")}} {
		fetch(bad.data)
		if p.Version() != 2 {
			t.Errorf("%s: applied version %d", bad.name, p.Version())
		}
		if kinds[len(kinds)-1] != event.KindBundleRejected {
			t.Errorf("%s: last event %s, want bundle.rejected", bad.name, kinds[len(kinds)-1])
		}
	}
	if !containsID(applied, "floor-lookalike") {
		t.Errorf("floor rules missing from applied set %v", applied)
	}

	// A restarted sensor keeps the verified bundle without the watcher.
	srv.Close()
	again := &Puller{Trust: trust, StateDir: p.StateDir, SourceID: "s1", Apply: p.Apply, Send: p.Send, Log: p.Log, Now: p.Now}
	if err := again.Load(); err != nil || again.Version() != 2 {
		t.Errorf("reload: version %d err %v", again.Version(), err)
	}
}

func containsID(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
