package watcher

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

const tokensFile = "sensors.json"

// tokenPrefix makes tripline tokens easy to find with secret scanners.
const tokenPrefix = "tlsen_"

var sensorID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Tokens maps the SHA-256 of each sensor bearer token to its sensor ID.
// Only hashes are stored on disk.
type Tokens struct {
	mu     sync.RWMutex
	path   string
	byHash map[string]string // hex sha256 -> sensor id
}

// LoadTokens reads the token file from the state directory. A missing file
// means no sensors yet.
func LoadTokens(stateDir string) (*Tokens, error) {
	t := &Tokens{path: filepath.Join(stateDir, tokensFile), byHash: map[string]string{}}
	data, err := os.ReadFile(t.path)
	if errors.Is(err, os.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &t.byHash); err != nil {
		return nil, fmt.Errorf("%s: %w", t.path, err)
	}
	return t, nil
}

// Add creates a token for a new sensor, saves its hash and returns the token.
// The caller shows the token once; it cannot be read back.
func (t *Tokens) Add(id string) (string, error) {
	if !sensorID.MatchString(id) {
		return "", fmt.Errorf("sensor id %q: use 1-64 letters, digits, '.', '_' or '-'", id)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := tokenPrefix + base64.RawURLEncoding.EncodeToString(b)

	t.mu.Lock()
	defer t.mu.Unlock()
	for _, existing := range t.byHash {
		if existing == id {
			return "", fmt.Errorf("sensor %q already exists", id)
		}
	}
	t.byHash[hash(token)] = id
	data, err := json.MarshalIndent(t.byHash, "", "  ")
	if err != nil {
		return "", err
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", err
	}
	return token, os.Rename(tmp, t.path)
}

// Lookup returns the sensor ID for a bearer token. Map lookup by hash does
// not leak the token through timing, because the attacker does not control
// the hash prefix.
func (t *Tokens) Lookup(token string) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	id, ok := t.byHash[hash(token)]
	return id, ok
}

func hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
