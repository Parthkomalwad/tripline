# aiwatch: technical build spec

> Assume something gets in. Make sure it leaves with nothing.

aiwatch is an open-source monitor for self-hosted AI systems (AI gateways such as LiteLLM, agents, MCP servers and coding agents). It does not try to predict attacks. It watches the few things every attack must do after it gets in: touch secrets, send them out, and use them. It alerts when those happen, proves through hourly self-tests that its own protections still work, and is built so that the security tool itself is hard to compromise.

This document is the build brief for an implementing agent (Claude Code) and for human contributors. "aiwatch" is a placeholder name; keep it in one constant and one module path so it can be renamed.

---

## Instructions for the implementing agent

Read this whole document before writing code. Then follow these working rules for the entire project.

1. **Build milestone by milestone** (see "Milestones"). Finish and test one milestone before starting the next. Stop at the end of each milestone, summarize what was built, list anything deferred, and wait for confirmation.
2. **Ask before adding any dependency.** The project's credibility depends on a small dependency tree. The Go standard library is the default. The only pre-approved third-party module is `gopkg.in/yaml.v3`. Propose anything else with a one-line justification.
3. **Verify external formats against official documentation before implementing them.** This applies to Claude Code hook input and output, Cursor hook input and output, Falco HTTP output, Slack webhook payloads, and any AI provider or cloud usage API. These formats change. Do not implement from memory. If documentation cannot be reached, stop and ask for it rather than guessing.
4. **Never store or log secret values or prompt/response bodies.** Store metadata only: who, what, where, when, which rule, which decision. Where a secret must be referenced, store a fingerprint (first 4 characters plus a SHA-256 prefix).
5. **Default to watch-only.** No component blocks traffic or rotates keys unless the configuration explicitly sets `mode: enforce`.
6. **Never fail silently.** Every component emits heartbeats. Every error path either retries, buffers or raises an event. A crashed component must be visible.
7. **Write tests with the code.** Unit tests for every rule type and parser; integration tests through docker compose for each milestone.
8. **Keep the attack replay harmless.** Replay containers simulate attacker behavior using decoy files and local sink services only. No real malware code, no real credentials, no traffic to the public internet.
9. **Do not commit secrets,** including test keys that look real. Generate test values at runtime.
10. **Small, reviewable commits** with clear messages. One concern per commit.

---

## Goals

- Detect the three post-compromise steps (secret access, data leaving, stolen key use) independently of how the attacker got in.
- Give high-confidence signals through tripwires (decoys nobody legitimately touches) and self-tests (scheduled attempts to break the system's own rules).
- Reach first value in 5 minutes (Level 1) without placing anything in the traffic path.
- Show coverage honestly, including what is not being watched.
- Make every alert traceable from signal to rule version to action to human acknowledgement, in a tamper-evident log.
- Fail safely: aiwatch going down must never take the user's AI systems down, and must always be noticed.
- Be hard to turn into the next supply-chain incident: one static binary, minimal dependencies, signed releases, signed rules.

## Non-goals

- No machine-learning classifiers in v0.x.
- No standalone dashboard product. Ship a small built-in status page, Prometheus metrics and a Grafana dashboard JSON.
- No TLS interception (no custom CA, no man-in-the-middle) in v0.x.
- No storage of prompts, responses or secret values.
- No auto-update mechanism.
- No pip or npm package that runs inside users' AI applications.
- No protection claims against attackers with root on a monitored host (see "Threat model").
- No data loss prevention for non-credential data (for example customer records leaking through allowed channels).

---

## Threat model

The full version lives in `docs/threat-model.md`. The implementing agent must keep this summary in mind for every design decision.

| Attacker | What aiwatch does | What it does not do |
|---|---|---|
| Malicious package inside the AI gateway (the LiteLLM 1.107.0 pattern: startup-hook stealer, exfiltration to a lookalike domain) | Detects credential-file reads (Level 3), detects and optionally blocks unknown or lookalike destinations (Level 2), injects real provider keys at the sensor so the gateway holds none (provider mode), detects decoy use (Level 1) | Prevent the package from running |
| Prompt-injected agent | Hooks deny dangerous tool calls and agent-config edits (Level 3); outbound profile limits uploads | Judge the meaning of prompts |
| Stolen API key used from attacker infrastructure | Flags anomalous key usage from provider and cloud logs (Level 1, delayed by provider log latency) | Detect in real time |
| Exfiltration through allowed services (attacker's own key sent to a real AI provider, push to attacker's GitHub) | Provider mode rejects requests carrying any key or organization ID other than the one the sensor injects (tenant pinning) | Inspect traffic in CONNECT mode beyond the hostname |
| Root on a monitored host | Off-host signals keep working: key usage, decoy use, heartbeat loss | Prevent local sensors from being killed or edited |
| Tampering with aiwatch rules | Signed bundles, rollback protection, delayed and announced loosening, compiled-in floor rules, self-tests | Survive theft of both signing keys |
| Compromise of an aiwatch maintainer account | Two-person release approval, keyless signing tied to CI identity, reproducible builds | Prevent a fully colluding set of maintainers |

---

## Architecture

aiwatch is one Go program compiled to a single static binary. It runs in different modes, and each mode is packaged for where it runs.

| Mode | Command | Packaging | Setup level |
|---|---|---|---|
| CLI | `aiwatch init`, `status`, `trace`, `audit verify`, `rules sign`, `rules verify` | Binary download, Homebrew tap | 1 |
| Watcher | `aiwatch watcher` | Container image | 1 |
| Egress sensor | `aiwatch sensor egress` | Container image (same image, different command) | 2 |
| Hook handler | `aiwatch hook claude-code`, `aiwatch hook cursor` | Binary on developer machines | 3 |
| Node sensor | Not reimplemented; Falco with aiwatch rules | Helm chart | 3 |

Data flows in one direction: sensors and hooks send **events** to the watcher; the watcher evaluates **rules**, correlates events into **chains**, writes everything to the **audit log**, and triggers **actions** (alert, block instruction, rotation runbook link). Sensors pull signed **rule bundles** from the watcher and keep enforcing the last verified bundle if the watcher is unreachable.

```text
 coding tools ─┐                                   ┌─> alert sinks (Slack, webhook, stdout)
 AI gateway ───┼─> sensors / hooks ──events──> watcher ─┼─> audit log (hash-chained JSONL)
 agents, MCP ──┤        ^                          │    ├─> status page + /metrics
 provider logs ┘        └──── signed rule bundles ─┘    └─> external heartbeat ping
```

### Repository layout

```text
aiwatch/
├── cmd/aiwatch/            # main package; subcommand dispatch only
├── internal/
│   ├── event/              # event schema, validation
│   ├── rules/              # rule schema, evaluation, correlation
│   ├── bundle/             # signing, verification, rollback and loosening checks
│   ├── floor/              # compiled-in floor rules
│   ├── audit/              # hash-chained log, verify
│   ├── watcher/            # ingest API, state, actions, status page, metrics
│   ├── sensor/egress/      # CONNECT proxy, provider mode, profiles, lookalike detection
│   ├── hooks/              # Claude Code and Cursor adapters
│   ├── tripwire/           # decoy generation and trap endpoints
│   ├── selftest/           # scheduled probes
│   ├── sinks/              # Slack, generic webhook, stdout
│   └── keyusage/           # connector interface and implementations
├── rules/
│   ├── core/               # default bundle source
│   ├── profiles/           # gateway-strict, agent-browsing
│   └── incidents/          # "was I hit?" packs, one file per incident
├── deploy/
│   ├── docker-compose/     # Level 2 example next to LiteLLM
│   ├── helm/               # Level 3 chart (watcher, Falco rules)
│   └── grafana/            # dashboard JSON
├── hooks/                  # generated hook config templates
├── replays/litellm-2026-10/ # harmless lab recreation
├── docs/                   # threat-model.md, quickstart.md, rules.md, operations.md
├── SECURITY.md
├── CONTRIBUTING.md
└── LICENSE                 # Apache-2.0
```

---

## Data model

### Event

Every sensor, hook, connector and self-test emits events in this shape. The watcher rejects events that fail validation and records the rejection.

```json
{
  "id": "evt_01J9...",
  "ts": "2026-10-21T11:47:02Z",
  "source": "sensor.egress",
  "source_id": "gw-prod-sensor-1",
  "subject": "ai-gateway-prod",
  "kind": "egress.connect",
  "attrs": {
    "host": "litellm.dev",
    "port": 443,
    "profile": "gateway-strict"
  },
  "decision": "deny",
  "rule_id": "egress-allowlist",
  "bundle_version": 14
}
```

| Field | Meaning |
|---|---|
| `subject` | The monitored system the event is about. Correlation groups by subject. |
| `kind` | One of: `heartbeat`, `egress.connect`, `egress.provider_request`, `secret.read`, `hook.tool_call`, `tripwire.hit`, `keyusage.anomaly`, `selftest.result`, `bundle.applied`, `bundle.rejected` |
| `decision` | `allow`, `deny`, `observe` (watch-only would-have-denied), or `none` |

### Rule

Rules are YAML, human-readable, and live in git. Example:

```yaml
id: egress-allowlist
description: AI gateway may only reach approved provider endpoints.
applies_to: { source: sensor.egress, profile: gateway-strict }
match:
  kind: egress.connect
  host_not_in: ["api.anthropic.com", "api.openai.com"]
severity: high
mode: monitor        # monitor | enforce
floor: false
on_match:
  - alert
  - block            # only effective when mode is enforce
```

Correlation rule example:

```yaml
id: chain-steal-then-send
description: Secret read followed by an unapproved connection on the same subject.
correlate:
  same: subject
  within: 5m
  sequence:
    - kind: secret.read
    - kind: egress.connect
      decision_in: [deny, observe]
severity: critical
on_match: [alert, page]
```

Supported match operators for v0.1: equality, `in`, `not_in`, `host_in`, `host_not_in`, `path_glob`, `lookalike_of` (see egress sensor). Keep the rule language small; do not add a general expression language.

### Rule bundle

A bundle is a single file containing all active rules plus metadata, signed with Ed25519 (Go standard library `crypto/ed25519`).

```yaml
version: 14                     # strictly increasing integer
created_at: 2026-10-22T09:00:00Z
effective_at: 2026-10-23T09:00:00Z
signers: [maya, raj]
rules: [ ... ]
signatures:
  - key_id: maya-2026
    sig: base64...
  - key_id: raj-2026
    sig: base64...
```

### Audit log entry

Append-only JSON Lines. Each entry includes the SHA-256 of the previous entry, so editing, inserting or deleting any line breaks verification.

```json
{"seq": 2041, "ts": "...", "type": "action", "data": {...}, "prev": "sha256:ab12...", "hash": "sha256:cd34..."}
```

---

## Components

### Watcher

The watcher is the brain. It must run separately from everything it watches.

- **Ingest API** on HTTP: `POST /v1/events` (batch of events). Authenticate each sensor with its own bearer token created by `aiwatch init` or `aiwatch sensor add`. Tokens are stored hashed. Optional mTLS is a later milestone.
- **Trap endpoints**: `/trap/<token>` returns a plausible error and records a `tripwire.hit` event. Used by decoys (see "Tripwires").
- **External webhook ingest**: `POST /v1/ingest/falco` and `POST /v1/ingest/canarytoken`, translating those formats into events. Verify the exact formats from official docs before implementing.
- **Rule evaluation and correlation** in memory, with a bounded window per subject. Persist state needed for correlation across restarts in a small local file.
- **Heartbeat tracking**: every source must send a heartbeat at least every 60 seconds. Missing for 5 minutes produces a `source.silent` alert.
- **External dead man's switch**: the watcher pings a user-configured URL every minute (compatible with common heartbeat services) so that something outside notices if the watcher itself stops.
- **Actions**: `alert` (to sinks), `page` (alert with high priority flag), `block` (instruct sensors through the rule bundle; the watcher never blocks directly), `runbook` (attach a runbook link). Automatic key rotation is out of scope for v0.1; alerts must name the keys to rotate by fingerprint and link the runbook.
- **Alert content**: every alert must state what happened, what was already done, and what the human needs to do, plus the trace ID.
- **Status page**: server-rendered HTML on a configurable address (default bind to localhost). Shows sources and last heartbeat, coverage per sensor type, self-test pass rate over the last 7 days, recent alerts, active bundle version. No JavaScript frameworks.
- **Metrics**: `/metrics` in Prometheus text exposition format, written with the standard library. Minimum set:

| Metric | Type |
|---|---|
| `aiwatch_events_total{kind,decision,source}` | counter |
| `aiwatch_alerts_total{severity,rule_id}` | counter |
| `aiwatch_selftest_runs_total{probe,result}` | counter |
| `aiwatch_source_last_heartbeat_seconds{source_id}` | gauge |
| `aiwatch_bundle_version` | gauge |
| `aiwatch_rule_matches_total{rule_id,mode}` | counter |
| `aiwatch_sensor_decision_latency_seconds` | histogram |

- **Weekly digest**: a scheduled summary sent to sinks: self-test pass count, tripwire touches, new destinations per subject, coverage gaps, alert count and resolution time.

### Egress sensor

A forward proxy placed between an AI gateway (or agent worker) and the internet. Applications use it through `HTTPS_PROXY` / `HTTP_PROXY` or by base URL in provider mode.

**CONNECT mode (milestone 2).** Handle HTTP `CONNECT` requests. Decide on hostname and port only; do not terminate TLS. Emit an `egress.connect` event for every new connection (aggregate repeated identical connections into counts per minute to limit volume).

**Profiles.** Each sensor runs one profile from the bundle:

| Profile | For | Behavior |
|---|---|---|
| `gateway-strict` | AI gateways | Only allowlisted provider hosts. Any other host is a high-severity match. Lookalikes are critical. |
| `agent-browsing` | Agents with web access | Any host allowed for reads. Flags lookalikes of known provider and package-registry hosts, raw IP destinations, and uploads above a size threshold. Never alerts merely for a new domain. |

**Lookalike detection.** For each destination, compare against a list of protected domains (providers, package registries, the gateway vendor's real domains). Flag when the registered domain differs but the label is within edit distance 2, shares the protected brand label with a different TLD (for example `litellm.dev` versus the real project domains), or contains homoglyphs after Unicode normalization. Keep the protected list in the rule bundle.

**Provider mode (milestone 5).** The gateway is configured to send provider traffic to the sensor over plain HTTP inside the private network, for example `http://aiwatch-sensor:8080/anthropic/...`. The sensor:

1. Rejects any request that already carries an API key or organization identifier (tenant pinning). Legitimate traffic never includes one in this mode.
2. Injects the real provider key, read from a file or environment variable available only to the sensor container.
3. Forwards upstream over TLS to the provider's official host.
4. Emits `egress.provider_request` events with model name, status code and token counts if present in response headers or body metadata, without storing bodies.

This makes the gateway hold no real provider keys. Verify each provider's authentication header names and base paths from official documentation before implementing.

**Enforcement.** In `monitor` mode the sensor allows everything and records `decision: observe` for would-be denials. In `enforce` mode it returns HTTP 403 for denied CONNECTs and requests.

**Failure behavior.** If the sensor cannot reach the watcher, it keeps enforcing the last verified bundle and buffers events on disk up to a configured size, then sends them when the watcher returns. The `fail_mode` setting (`open` or `closed`) controls what happens if the sensor cannot load any valid bundle at startup. Default: `open` with a critical alert.

### Tripwires

Generated by `aiwatch init`. Every decoy has a unique token so a hit identifies exactly where it was planted.

- **Decoy config files**: a plausible gateway or provider config file (for example a fake `config.yaml` or `.env.backup`) whose base URL points at the watcher's `/trap/<token>` endpoint. Tools or attackers that try the config reach the trap.
- **Decoy credential files**: files placed in likely-stolen locations, monitored by the node sensor at Level 3 (any read is an event).
- **Canarytokens integration**: document how to create a cloud-key canary with Thinkst Canarytokens and point its webhook at `/v1/ingest/canarytoken`. Do not claim that fake AI-provider keys alert on their own; they only alert if a provider offers usage visibility for them, which must be verified per provider.
- Decoy values must be random, clearly unique, and must not collide with real key formats in ways that could cause harm. Record every decoy's location and token in the watcher state.

### Self-tests

The watcher schedules probes (default hourly) and records each as a `selftest.result` event.

| Probe | Pass condition |
|---|---|
| `egress-deny` | A CONNECT to a reserved test host (for example `selftest.aiwatch.invalid`) through each strict sensor is denied (or observed in monitor mode) and the event arrives at the watcher within 30 seconds |
| `egress-allow` | A CONNECT to an allowlisted host succeeds through the sensor |
| `trap-alive` | A request to a test trap token produces a `tripwire.hit` event that is recognized as a self-test and not alerted |
| `bundle-current` | Every sensor reports the watcher's current bundle version |
| `secret-read` (Level 3) | A scheduled read of a dedicated self-test decoy file produces a `secret.read` event |

Any failed probe produces an alert. The self-test pass rate is the headline chart on the status page.

### Hook handler

`aiwatch hook claude-code` and `aiwatch hook cursor` read the hook event JSON from standard input, evaluate local rules from the last verified bundle, send an event to the watcher (non-blocking, with a short timeout), and write the decision in the format each tool expects. Verify both tools' current hook formats and exit-code semantics from official docs first.

Default rules for hooks:

- Deny writes to agent configuration files: `.claude/settings.json`, `.claude/settings.local.json`, `.cursor/hooks.json`, `CLAUDE.md` outside the repository root, editor settings files.
- Deny reads of credential files: `~/.aws/*`, `~/.ssh/*`, `**/.env*` outside the project, keychain exports.
- Flag shell commands that pipe downloads into a shell, or that install packages not in an allowlist.
- MCP tool pinning: record a SHA-256 of each MCP tool's name, description and canonicalized input schema on first approval; deny calls to a tool whose hash changed until re-approved.

`aiwatch init --hooks` generates managed-settings snippets for Claude Code and an enterprise `hooks.json` for Cursor, and documents where administrators place them.

### Node sensor

Do not write an eBPF sensor. Ship Falco rules and a Helm chart that installs Falco with HTTP output pointed at the watcher's `/v1/ingest/falco`. Rules cover: reads of credential paths and decoy files by AI workload processes, shells spawned by gateway processes, writes of `.pth` or `sitecustomize.py` files into Python site-packages at runtime, and connections to the cloud metadata address `169.254.169.254` from AI workloads.

### Key-usage connectors

Define a `keyusage.Connector` interface: `Poll(ctx, since) ([]event.Event, error)`. Implement connectors only after verifying the provider's official usage or audit API. Anomaly rules for v0.1 are simple and explainable: a key used from a network or region not seen in the previous 30 days, daily spend above 3x its 14-day median, a model never used before on that key. Document each connector's typical reporting delay in `docs/operations.md`.

---

## Rule integrity

These protections are what make aiwatch different. Implement them fully in milestone 3.

1. **Signed bundles.** Sensors and the watcher accept only bundles signed by the required number of keys (default 2 of N) listed in a trust file. The trust file path is configured at install and should be root-owned and read-only to the aiwatch process.
2. **Rollback protection.** Reject any bundle whose `version` is not greater than the currently applied version.
3. **Floor rules.** A small set of rules compiled into the binary (`internal/floor`) that a bundle can add to but never remove or set to monitor where they are enforced: credential-file read detection, decoy hit detection, lookalike detection on protected domains, heartbeat requirements. A bundle that attempts to weaken a floor rule is rejected with a critical alert.
4. **Delayed loosening.** The verifier computes a diff between the current and new bundle. A change is loosening if it removes a rule, switches `enforce` to `monitor`, widens an allowlist, lowers a severity or lengthens a correlation window. Tightening applies at `effective_at` immediately. Loosening requires `effective_at` at least 24 hours (configurable, minimum 1 hour) after `created_at`, and the watcher alerts on receipt and again when it takes effect.
5. **Every bundle change is an audit event,** including rejected bundles and the reason.

Provide `aiwatch rules sign`, `aiwatch rules verify` and `aiwatch rules diff` commands.

---

## Security of the aiwatch project itself

These requirements are part of milestone 0 and are not optional.

- Single static binary, `CGO_ENABLED=0`, minimal dependencies, `go.sum` committed, `go mod verify` in CI.
- Container images built from a minimal base (distroless static or scratch), run as non-root, read-only root filesystem, no shell.
- GitHub Actions: every third-party action pinned to a full commit SHA; `permissions:` set to the minimum per job; no third-party tool receives publish credentials.
- Releases built only in CI, from a protected `release` environment that requires approval from a second maintainer.
- Keyless signing of binaries and images (Sigstore cosign through GitHub OIDC), plus an SBOM and build provenance attestation for every release.
- Reproducible builds: document the exact build command; CI verifies two independent builds produce identical binaries.
- Documentation instructs users to deploy images by digest, never by tag, and to wait at least 3 days before adopting a new release unless it is a security fix.
- Dependency updates batched with a cooldown, never auto-merged.
- `SECURITY.md` with a private disclosure address, supported versions and response targets.

---

## Attack replay lab

`replays/litellm-2026-10/` recreates the shape of the October 2026 LiteLLM compromise harmlessly so anyone can see what aiwatch catches at each level.

- A `victim-gateway` container with a decoy credential file and a startup script that, after boot, reads the decoy file and attempts an HTTPS POST of its hash (not its contents) to `litellm.dev`.
- A local DNS override in the compose network resolves `litellm.dev` to a `sink` container. Nothing leaves the machine.
- A second stage simulates the attacker using a stolen decoy config that points at the watcher trap.
- `make replay LEVEL=1|2|3` runs the scenario with the matching aiwatch components and prints the expected and actual outcomes:

| Level | Expected outcome |
|---|---|
| 1 | Decoy use detected at the trap; breach confirmed; alert names keys to rotate |
| 2 | Connection to the lookalike domain observed (monitor) or denied (enforce); decoy never used |
| 3 | `secret.read` followed by the denied connection correlated into a critical chain within 5 seconds |

The replay doubles as an end-to-end integration test in CI.

---

## Milestones

Each milestone ends with passing tests, updated docs, and a stop for review.

| Milestone | Scope | Done when |
|---|---|---|
| M0: foundations | Repo layout, Apache-2.0 license, `SECURITY.md`, `CONTRIBUTING.md`, CI with pinned actions and minimal permissions, static build, container image, `go mod verify` | CI builds a signed test artifact; image runs as non-root on a read-only filesystem |
| M1: watcher and Level 1 | Event schema, ingest API with sensor tokens, rule engine (single-event rules), audit log with `aiwatch audit verify`, Slack and webhook sinks, heartbeats, dead man's switch ping, status page, `/metrics`, trap endpoints, decoy generation, `aiwatch init` and `aiwatch status` | A trap hit produces an alert with a trace ID; `aiwatch status` shows coverage including gaps; tampering with one audit line fails verification |
| M2: egress sensor | CONNECT proxy, profiles, lookalike detection, monitor and enforce modes, event aggregation, disk buffering, self-test probes | Replay Level 2 passes in monitor and enforce modes; killing the watcher does not stop enforcement |
| M3: rule integrity and correlation | Signed bundles, trust file, rollback protection, floor rules, delayed loosening, `rules sign/verify/diff`, correlation rules | Unsigned, older, floor-weakening and early-loosening bundles are each rejected with an alert; correlation test passes |
| M4: release v0.1 | Replay lab and CI job, quickstart, threat model, operations guide, Grafana dashboard JSON, reproducible release | A new user reaches the first `aiwatch status` screen in under 5 minutes following only the README |
| M5: provider mode | Key injection and tenant pinning for at least two providers, verified against official docs | The gateway runs with no provider keys; a request carrying a foreign key is rejected and alerted |
| M6: node sensor | Falco rules, Helm chart, Falco ingest | Replay Level 3 passes on a local Kubernetes cluster |
| M7: hooks | Claude Code and Cursor adapters, default hook rules, MCP tool pinning, managed-settings generation | A hook blocks an agent-config write and an MCP rug pull in tests built from the official formats |
| M8: key usage and digest | Connector interface, first verified connectors, anomaly rules, weekly digest | Digest is generated from real events; connector delay is documented |

---

## Configuration

One YAML file, kept in git, with secrets referenced by file path or environment variable name, never inline.

```yaml
watcher:
  listen: 127.0.0.1:7700
  status_page: 127.0.0.1:7701
  state_dir: /var/lib/aiwatch
  heartbeat_ping_url_env: AIWATCH_DEADMAN_URL
sinks:
  - type: slack
    webhook_url_env: AIWATCH_SLACK_WEBHOOK
  - type: webhook
    url_env: AIWATCH_WEBHOOK_URL
trust:
  file: /etc/aiwatch/trust.yaml
  required_signatures: 2
  loosening_delay: 24h
selftest:
  interval: 1h
digest:
  weekly: monday 09:00
```

---

## Documentation to write

- `README.md`: what it is in one paragraph, the 5-minute quickstart, a screenshot of the status page, links to the threat model and replay.
- `docs/threat-model.md`: the full version of the table above, written plainly, including every limitation.
- `docs/quickstart.md`: Level 1, 2 and 3 setup with exact commands.
- `docs/rules.md`: rule and bundle format, how to contribute an incident pack.
- `docs/operations.md`: failure modes, fail-open versus fail-closed guidance, break-glass procedure (time-limited, logged, auto-expiring rule relaxation), retention, connector delays, key rotation runbook template.
- `SECURITY.md` and `CONTRIBUTING.md`.

---

## Open questions

These need a human decision before or during the relevant milestone.

1. Final project name and module path.
2. Which two providers to support first in provider mode.
3. Whether the watcher should support SQLite for state in v0.1 or stay with flat files (flat files keep dependencies at zero).
4. Default loosening delay: 24 hours is safer; some teams may want shorter for development environments.
5. Whether to offer a hosted watcher later, and how to keep the self-hosted version fully featured if so.

Start with M0. Stop after it is complete and report back before beginning M1.
