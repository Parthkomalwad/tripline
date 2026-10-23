// Package tripwire plants decoys and serves the trap endpoint that detects
// their use.
package tripwire

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const registryFile = "decoys.json"

// tokenPrefix cannot collide with a real provider key format.
const tokenPrefix = "tltrap_"

// Decoy records one planted decoy. The token is a trap identifier, not a
// secret, so it is stored as-is.
type Decoy struct {
	Token     string    `json:"token"`
	Kind      string    `json:"kind"`
	Location  string    `json:"location"`
	CreatedAt time.Time `json:"created_at"`
	Selftest  bool      `json:"selftest"`
}

// Registry is the set of decoys in the state directory.
// ponytail: loaded once at start. A decoy added by `init` needs a watcher restart.
type Registry struct {
	mu     sync.RWMutex
	path   string
	decoys []Decoy
}

// LoadRegistry reads decoys.json. A missing file means no decoys yet.
func LoadRegistry(stateDir string) (*Registry, error) {
	r := &Registry{path: filepath.Join(stateDir, registryFile)}
	data, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	return r, json.Unmarshal(data, &r.decoys)
}

// Lookup returns the decoy for a token.
func (r *Registry) Lookup(token string) (Decoy, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, d := range r.decoys {
		if d.Token == token {
			return d, true
		}
	}
	return Decoy{}, false
}

// Selftest returns the decoy that the trap-alive probe uses.
func (r *Registry) Selftest() (Decoy, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, d := range r.decoys {
		if d.Selftest && d.Kind == "selftest" {
			return d, true
		}
	}
	return Decoy{}, false
}

// Add creates a decoy with a fresh token and saves the registry.
func (r *Registry) Add(kind, location string, selftest bool) (Decoy, error) {
	d := Decoy{Token: tokenPrefix + randString(16), Kind: kind, Location: location, CreatedAt: time.Now().UTC(), Selftest: selftest}
	r.mu.Lock()
	defer r.mu.Unlock()
	next := append(append([]Decoy(nil), r.decoys...), d)
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return Decoy{}, err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return Decoy{}, err
	}
	if err := os.Rename(tmp, r.path); err != nil {
		return Decoy{}, err
	}
	r.decoys = next
	return d, nil
}

func randString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the system random source failed: nothing safe to do
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Fingerprint is the first 4 characters plus a SHA-256 prefix. It identifies
// a token in events without repeating it.
func Fingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return token[:min(4, len(token))] + "-" + hex.EncodeToString(sum[:6])
}
