// Package floor holds the rules compiled into the binary. A bundle can add to
// them or tighten them. It can never remove or weaken them.
package floor

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/Parthkomalwad/tripline/internal/rules"
	"github.com/Parthkomalwad/tripline/internal/tripwire"
)

// credentialRead flags reads of credential files.
// ponytail: path.Match stops at "/", so the globs list common home layouts.
// A recursive glob or a sensor-normalized path would cover nested files.
const credentialRead = `id: floor-credential-read
description: A process read a credential file.
severity: critical
on_match: [alert, runbook]
match:
  kind: secret.read
  path_glob:
    - "~/.aws/*"
    - "~/.ssh/*"
    - "*.env*"
    - "/home/*/.aws/*"
    - "/home/*/.ssh/*"
    - "/home/*/.env*"
    - "/Users/*/.aws/*"
    - "/Users/*/.ssh/*"
    - "/Users/*/.env*"
    - "/root/.aws/*"
    - "/root/.ssh/*"
    - "/root/.env*"
`

// lookalike is a placeholder for lookalike detection on protected domains.
// The protected list is the floor minimum. Bundles can add domains in their
// own rules but cannot remove these.
const lookalike = `id: floor-lookalike
description: A connection went to a lookalike of a protected domain.
severity: critical
on_match: [alert, page]
match:
  kind: egress.connect
  host_lookalike_of: [anthropic.com, openai.com, pypi.org, pythonhosted.org, npmjs.org, github.com, githubusercontent.com, litellm.ai, huggingface.co]
`

// foreignCredential flags a provider-mode request that carried its own key or
// organization. The sensor always rejects these.
const foreignCredential = `id: floor-foreign-credential
description: A request to the provider listener carried a foreign credential.
severity: critical
on_match: [alert, page]
match:
  kind: egress.provider_request
  reason: foreign credential
`

// Heartbeat requirement: every source must send a heartbeat at least every
// 60 seconds. The watcher enforces it with source.silent alerts. It is not a
// rule, so a bundle cannot express or remove it.

var floorRules = mustParse(tripwire.DefaultRule + "---\n" + credentialRead + "---\n" + lookalike + "---\n" + foreignCredential)

func mustParse(src string) []*rules.Rule {
	rs, err := rules.Parse([]byte(src))
	if err != nil {
		panic("floor: " + err.Error()) // compiled-in YAML is wrong: a test catches this
	}
	for _, r := range rs {
		r.Floor = true
	}
	return rs
}

// Rules returns a copy of the floor rule list.
func Rules() []*rules.Rule { return slices.Clone(floorRules) }

var severities = []string{"low", "medium", "high", "critical"}

// SeverityRank orders severities. An unknown value ranks below "low".
func SeverityRank(s string) int { return slices.Index(severities, s) }

func modeRank(m rules.Mode) int {
	if m == rules.ModeEnforce {
		return 1
	}
	return 0
}

// Check rejects a bundle rule that reuses a floor ID and is weaker than the
// floor rule: lower severity, lower mode, or a different match.
func Check(bundle []*rules.Rule) error {
	for _, b := range bundle {
		for _, f := range floorRules {
			if b.ID != f.ID {
				continue
			}
			switch {
			case SeverityRank(string(b.Severity)) < SeverityRank(string(f.Severity)):
				return fmt.Errorf("floor rule %q: severity lowered to %s", f.ID, b.Severity)
			case modeRank(b.Mode) < modeRank(f.Mode):
				return fmt.Errorf("floor rule %q: mode lowered to %s", f.ID, b.Mode)
			case !reflect.DeepEqual(b.Match, f.Match) || !reflect.DeepEqual(b.AppliesTo, f.AppliesTo):
				return fmt.Errorf("floor rule %q: match changed", f.ID)
			}
		}
	}
	return nil
}

// Merge returns the floor rules followed by the bundle rules. A bundle rule
// with a floor ID replaces the floor rule only if Check accepts it.
func Merge(bundle []*rules.Rule) ([]*rules.Rule, error) {
	if err := Check(bundle); err != nil {
		return nil, err
	}
	out := Rules()
	for _, b := range bundle {
		if i := slices.IndexFunc(out, func(r *rules.Rule) bool { return r.ID == b.ID }); i >= 0 {
			b.Floor = true
			out[i] = b
			continue
		}
		out = append(out, b)
	}
	return out, nil
}
