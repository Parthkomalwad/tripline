// Package bundle parses, signs and verifies signed rule bundles. See
// docs/adr/0002-rule-bundle-signing.md.
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Parthkomalwad/tripline/internal/rules"
)

// Signature is one signer's Ed25519 signature over Payload.
type Signature struct {
	KeyID string `yaml:"key_id"`
	Sig   string `yaml:"sig"` // base64
}

// Bundle is a signed set of rules plus metadata.
type Bundle struct {
	Version     int              `yaml:"version"`
	CreatedAt   time.Time        `yaml:"created_at"`
	EffectiveAt time.Time        `yaml:"effective_at"`
	Signers     []string         `yaml:"signers"`
	Rules       []map[string]any `yaml:"rules"`
	Signatures  []Signature      `yaml:"signatures"`

	// Set by Verify.
	Pending bool     `yaml:"-"` // valid, but effective_at is in the future
	Changes []Change `yaml:"-"` // diff against the applied bundle
}

// Parse reads a bundle. Unknown fields are errors. It does not check
// signatures.
func Parse(data []byte) (*Bundle, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	b := &Bundle{}
	if err := dec.Decode(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Marshal writes the bundle as YAML.
func (b *Bundle) Marshal() ([]byte, error) { return yaml.Marshal(b) }

// payloadPrefix versions the signed byte form.
const payloadPrefix = "tripline-bundle-v1\n"

// Payload is the canonical byte form that signers sign: payloadPrefix, then
// one line of JSON with this field order: version, created_at, effective_at,
// signers, rules. Times are UTC RFC 3339 with second precision. Rule maps are
// marshaled by encoding/json, which sorts map keys, so the bytes do not
// depend on YAML key order or formatting. Signatures are not part of it.
func (b *Bundle) Payload() ([]byte, error) {
	signers, rs := b.Signers, b.Rules
	if signers == nil {
		signers = []string{}
	}
	if rs == nil {
		rs = []map[string]any{}
	}
	body, err := json.Marshal(struct {
		Version     int              `json:"version"`
		CreatedAt   string           `json:"created_at"`
		EffectiveAt string           `json:"effective_at"`
		Signers     []string         `json:"signers"`
		Rules       []map[string]any `json:"rules"`
	}{b.Version, ts(b.CreatedAt), ts(b.EffectiveAt), signers, rs})
	if err != nil {
		return nil, err
	}
	return append([]byte(payloadPrefix), body...), nil
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Sign adds or replaces the signature for keyID.
func (b *Bundle) Sign(keyID string, priv ed25519.PrivateKey) error {
	if keyID == "" {
		return errors.New("key id: required")
	}
	p, err := b.Payload()
	if err != nil {
		return err
	}
	s := Signature{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, p))}
	for i := range b.Signatures {
		if b.Signatures[i].KeyID == keyID {
			b.Signatures[i] = s
			return nil
		}
	}
	b.Signatures = append(b.Signatures, s)
	return nil
}

// ParseRules compiles the bundle rules with the rules package.
func (b *Bundle) ParseRules() ([]*rules.Rule, error) {
	var buf bytes.Buffer
	for _, m := range b.Rules {
		out, err := yaml.Marshal(m)
		if err != nil {
			return nil, err
		}
		buf.WriteString("---\n")
		buf.Write(out)
	}
	rs, err := rules.Parse(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	return rs, nil
}

// Applied is the bundle currently in force.
type Applied struct {
	Version int
	Rules   []map[string]any
}

// Applied returns b as the applied state.
func (b *Bundle) Applied() *Applied { return &Applied{Version: b.Version, Rules: b.Rules} }
