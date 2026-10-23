package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Loosening delay limits.
const (
	DefaultLooseningDelay = 24 * time.Hour
	MinLooseningDelay     = time.Hour
	DefaultRequired       = 2
)

// TrustKey is one trusted signer.
type TrustKey struct {
	KeyID     string `yaml:"key_id"`
	PublicKey string `yaml:"public_key"` // base64
	Owner     string `yaml:"owner"`
}

// Trust is the trust file. It should be root-owned and read-only to tripline.
type Trust struct {
	Keys               []TrustKey    `yaml:"keys"`
	RequiredSignatures int           `yaml:"required_signatures"`
	LooseningDelay     time.Duration `yaml:"loosening_delay"`

	pub map[string]ed25519.PublicKey
}

// LoadTrust reads and checks a trust file.
func LoadTrust(path string) (*Trust, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseTrust(data)
}

// ParseTrust checks keys and fills defaults.
func ParseTrust(data []byte) (*Trust, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	t := &Trust{}
	if err := dec.Decode(t); err != nil {
		return nil, err
	}
	if t.RequiredSignatures == 0 {
		t.RequiredSignatures = DefaultRequired
	}
	if t.LooseningDelay == 0 {
		t.LooseningDelay = DefaultLooseningDelay
	}
	if t.LooseningDelay < MinLooseningDelay {
		return nil, fmt.Errorf("loosening_delay: minimum is %s", MinLooseningDelay)
	}
	t.pub = map[string]ed25519.PublicKey{}
	for _, k := range t.Keys {
		raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %q: public_key must be a base64 Ed25519 key", k.KeyID)
		}
		if k.KeyID == "" || t.pub[k.KeyID] != nil {
			return nil, fmt.Errorf("key %q: empty or duplicate key_id", k.KeyID)
		}
		t.pub[k.KeyID] = raw
	}
	if t.RequiredSignatures < 1 || t.RequiredSignatures > len(t.Keys) {
		return nil, errors.New("required_signatures: must be between 1 and the number of keys")
	}
	return t, nil
}

// countValid counts distinct trusted key IDs with a valid signature.
func (t *Trust) countValid(payload []byte, sigs []Signature) int {
	seen := map[string]bool{}
	for _, s := range sigs {
		pub, ok := t.pub[s.KeyID]
		raw, err := base64.StdEncoding.DecodeString(s.Sig)
		if ok && err == nil && ed25519.Verify(pub, payload, raw) {
			seen[s.KeyID] = true
		}
	}
	return len(seen)
}
