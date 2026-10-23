# Rules

Rules are YAML. They live in git. A rule says which events matter and what to do. This page describes what the code supports today.

## Rule file

A rules file holds one or more rules. Separate them with `---`. The parser rejects unknown fields, unknown operators and duplicate IDs. A typo cannot turn a rule off quietly.

```yaml
id: egress-allowlist
description: AI gateway may only reach approved provider endpoints.
applies_to: { source: sensor.egress, profile: gateway-strict }
match:
  kind: egress.connect
  host_not_in: ["api.anthropic.com", "api.openai.com"]
severity: high
mode: monitor
on_match:
  - alert
  - block
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique name. |
| `description` | no | Plain text. |
| `applies_to` | no | Equality filters on event fields. All must hold. |
| `match` | yes (single rule) | Conditions on the event. All must hold. |
| `correlate` | yes (chain rule) | See "Correlation rules". Do not combine with `match`. |
| `severity` | yes | `low`, `medium`, `high` or `critical`. |
| `mode` | no | `monitor` (default) or `enforce`. |
| `floor` | no | Set by the binary for floor rules. A bundle cannot grant it. |
| `on_match` | yes | One or more actions: `alert`, `page`, `block`, `runbook`. |
| `runbook` | no | Text for the responder. |

`block` has an effect only in `enforce` mode, on a CONNECT seen by the egress sensor. In `monitor` mode the sensor allows the connection and records `decision: observe`.

## Match operators

A key in `match` is a field name, with an optional suffix. The suffix picks the operator.

| Key form | Operator | Value | Meaning |
|---|---|---|---|
| `field` | equal (`=`) | scalar | The field equals the value. |
| `field_in` | in | list | The field equals one entry. |
| `field_not_in` | not in | list | The field equals no entry. |
| `field_glob` | glob | scalar or list | The field matches one pattern. |
| `field_lookalike_of` | lookalike | list of domains | The host imitates one protected domain. |

The parser tests `_not_in` before `_in`. A field name cannot itself end in one of these suffixes.

The spec lists `host_in` and `host_not_in`. They are the `_in` and `_not_in` operators on the `host` field.

### Fields

A condition can read these event fields: `kind`, `source`, `source_id`, `subject`, `decision`. Any other name reads an attribute of the event, such as `host`, `port`, `profile`, `path` or `selftest`.

Event kinds: `heartbeat`, `egress.connect`, `egress.provider_request`, `secret.read`, `hook.tool_call`, `tripwire.hit`, `keyusage.anomaly`, `selftest.result`, `bundle.applied`, `bundle.rejected`. Only `egress.connect`, `tripwire.hit`, `selftest.result`, `heartbeat` and the bundle kinds have a sensor today. The others are planned.

### Rules for matching

- A host name compares in lower case, without a trailing dot.
- A field that the event does not have never matches. This holds for `_not_in` too.
- A scalar can be a string, a number or a boolean. Values compare as text.
- `_glob` uses Go `path.Match`. `*` matches any run of characters except `/`. There is no `**`. Write one pattern for each depth that you need.
- `_lookalike_of` flags a host that has a different registered domain, but is close to a protected one. It flags a label within edit distance 2, the same brand label under a different top-level domain, look-alike characters, and punycode labels. The host itself and its subdomains are not lookalikes. Raw IP addresses are not lookalikes. Registered domains come from the Public Suffix List compiled into the binary.
- A regular expression is not supported. The spec keeps the language small on purpose.

## Correlation rules

A correlation rule matches an ordered sequence of events for one subject inside a time window.

```yaml
id: chain-steal-then-send
description: Secret read followed by an unapproved connection on the same subject.
severity: critical
on_match: [alert, page]
correlate:
  same: subject
  within: 5m
  sequence:
    - kind: secret.read
    - kind: egress.connect
      decision_in: [deny, observe]
```

- `same` must be `subject`. This is the only join key.
- `within` is required. The window starts at the first step.
- `sequence` needs at least two steps. Each step uses the same operators as `match`.
- Steps must arrive in order. Time comes from the event timestamp.
- One event completes at most one chain for each rule and subject: the oldest one.
- The trace ID of a chain is the ID of its first event.
- The correlator keeps partial chains in memory and saves them, so a restart does not lose them. It drops expired partials on load.
- The bounds are 64 partial chains per rule and subject, and 4096 in total. The oldest are dropped first. The count of drops is kept.

The `secret.read` event needs the node sensor, which is planned. The rule loads today, but no source emits that event yet. A chain of `tripwire.hit` or `egress.connect` events works today.

## Floor rules

Floor rules are compiled into the binary (`internal/floor`). The watcher and the egress sensor always load them. A bundle can add rules. It can never remove a floor rule or weaken it.

| ID | Severity | Matches |
|---|---|---|
| `tripwire-hit` | critical | A `tripwire.hit` event that is not a self-test. Actions: `alert`, `runbook`. |
| `floor-credential-read` | critical | A `secret.read` event whose `path` matches a credential glob (`~/.aws/*`, `~/.ssh/*`, `*.env*`, and the same under `/home/*`, `/Users/*` and `/root`). Actions: `alert`, `runbook`. Needs the planned node sensor. |
| `floor-lookalike` | critical | An `egress.connect` event whose `host` imitates one of nine protected domains: `anthropic.com`, `openai.com`, `pypi.org`, `pythonhosted.org`, `npmjs.org`, `github.com`, `githubusercontent.com`, `litellm.ai`, `huggingface.co`. Actions: `alert`, `page`. |

The floor rules run in `monitor` mode. Only a bundle can raise a floor rule to `enforce`.

A bundle rule that reuses a floor ID may only raise the severity or the mode. Its `match` and `applies_to` must stay the same. A bundle that changes a floor rule in another way is rejected with a critical alert. A bundle that drops a floor rule that the applied bundle held is also rejected.

The heartbeat requirement is not a rule. The watcher marks a source silent after 5 minutes without an event or heartbeat, and alerts. A bundle cannot express or remove it. Sources send a heartbeat every 30 seconds.

The `rules/` directory holds profile rules: `rules/profiles/gateway-strict.yaml` (allowlist), `rules/profiles/lookalike.yaml` (blocks lookalikes) and `rules/core/protected-domains.yaml` (the domain list).

## Bundles

A bundle is one YAML file with all active rules, metadata and signatures. Ed25519 signs it. See `docs/adr/0002-rule-bundle-signing.md`.

```yaml
version: 14                     # integer, must rise on every bundle
created_at: 2026-10-22T09:00:00Z
effective_at: 2026-10-23T09:00:00Z
signers: [maya, raj]
rules:
  - id: egress-allowlist
    ...
signatures:
  - key_id: maya-2026
    sig: <base64>
  - key_id: raj-2026
    sig: <base64>
```

The signed bytes are the text `tripline-bundle-v1`, a newline, and one line of JSON. The JSON holds `version`, `created_at`, `effective_at`, `signers` and `rules`, in this order. YAML key order and formatting do not change the bytes. Signatures are not part of them.

### Trust file

```yaml
keys:
  - key_id: maya-2026
    public_key: <base64 Ed25519 public key>
    owner: Maya
required_signatures: 2   # default 2
loosening_delay: 24h     # default 24h, minimum 1h
```

The number of required signatures must be between 1 and the number of keys. Only distinct trusted key IDs with a valid signature count. A repeated signer counts once. Keep the file root-owned and read-only to the tripline user.

### Signing flow

```sh
tripline rules keygen -id maya-2026 -out keys -owner Maya
tripline rules sign   -key keys/maya-2026.key -in bundle.yaml
tripline rules sign   -key keys/raj-2026.key  -in bundle.yaml
tripline rules verify -trust trust.yaml -current 13 bundle.yaml
tripline rules diff   old-bundle.yaml bundle.yaml
```

- `keygen` writes `<id>.key` (private seed, mode 0600) and `<id>.pub`. It never overwrites a file.
- `sign` adds or replaces the signature for that key ID, and rewrites the file.
- `verify` runs every check and prints the changes. Use `-current` to set the applied version. It exits non-zero when it rejects the bundle. It prints `pending` when `effective_at` is in the future.
- `diff` classifies each rule change as `tighten` or `loosen`. It reads bundles without checking signatures.

### Checks on every bundle

The watcher and each sensor run these checks. The sensor does not trust the watcher.

1. The YAML parses with no unknown field.
2. Enough distinct trusted keys signed it (`insufficient_signatures`).
3. `version` is at least 1, and above the applied version (`rollback`).
4. `created_at` and `effective_at` are set, `effective_at` is not before `created_at`, and `created_at` is not more than 5 minutes ahead of the clock (`invalid_time`).
5. Every rule compiles (`malformed`).
6. No floor rule is weakened or dropped (`floor_weakened`). This raises a critical alert.
7. A bundle with loosening has `effective_at` at least `loosening_delay` after `created_at` (`early_loosening`).

The watcher writes every outcome to the audit log as `bundle.accepted` or `bundle.rejected`, with the reason and the changes. It stores no signatures or rule content in that entry. A rejected bundle raises an alert, and the current rules stay in force. A rejected bundle is not applied by sensors either.

A bundle with `effective_at` in the future is held as pending. It applies when the time arrives.

### Loosening

Loosening makes detection weaker. The check treats these changes as loosening:

- A rule is removed.
- `mode` goes from `enforce` to `monitor`.
- `severity` is lowered.
- An allowlist (`X_not_in`) gains entries.
- A deny list (`X_in`) loses entries.
- `correlate.within` is longer.
- An `on_match` action is removed.
- Any other change to `match`, `applies_to` or `correlate`, because it cannot be shown to be tighter.

Description and runbook changes are ignored. The reverse of each change is tightening. A rule added is tightening.

Tightening can take effect at once. Loosening needs the delay. The watcher alerts when it receives a loosening bundle that is pending, and again when it takes effect. To stop a pending loosening, publish a newer bundle without it before the effective time.

## Contribute an incident pack

An incident pack is a set of rules for one real incident. The directory `rules/incidents/` does not exist yet. A pull request creates it. Use one file per incident.

1. Name the file `rules/incidents/<yyyy>-<mm>-<short-name>.yaml`.
2. Put a comment at the top with the incident name, the date and a public source link.
3. Prefix each rule ID with the short name, for example `litellm-2026-10-lookalike`.
4. Use only the supported operators. Test with `tripline rules diff` and the Go tests in `internal/rules`.
5. Use `mode: monitor`. Let operators choose `enforce`.
6. Use indicators that the source publishes: domains, package names and versions. Never include a secret, a real credential or malware code.
7. Add a test event or a replay under `replays/` when you can.
8. Describe false positives in the file comment.

Maintainers review the pack. A pack does not become part of a signed bundle until the bundle signers publish it.

Open an issue before a large pack. See `CONTRIBUTING.md`.
