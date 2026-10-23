# Threat model

This page says what tripline does against each attacker, and what it does not do. Read the limits before you rely on it.

tripline is pre-release. Parts marked "planned" do not exist yet.

## Core idea

tripline assumes that something gets in. It does not try to stop the first step. It watches for the steps that every attack must take next:

1. Secret access.
2. Data leaving the system.
3. Use of a stolen key.

## Attackers

| Attacker | What tripline does | What tripline does not do |
|---|---|---|
| Malicious package inside the AI gateway (the LiteLLM 1.107.0 pattern: startup-hook stealer, exfiltration to a lookalike domain) | Detects use of a decoy (built). Detects, and optionally blocks, unknown or lookalike destinations through the egress sensor (built). Detects credential-file reads (planned, Level 3). Injects real provider keys at the sensor so the gateway holds none (built, provider mode). | Prevent the package from running. |
| Prompt-injected agent | Denies dangerous tool calls and agent-config edits with hooks (planned, Level 3). The outbound profile limits where an agent can connect. | Judge the meaning of prompts. |
| Stolen API key used from attacker infrastructure | Flags unusual key use from provider and cloud logs (planned, key-usage connectors). | Detect it in real time. Provider logs arrive late. |
| Exfiltration through allowed services (an attacker key sent to a real AI provider, a push to an attacker repository) | Rejects requests that carry a key or organization ID other than the one the sensor injects (built, provider mode, Anthropic and OpenAI; see ADR 0004). | Inspect traffic in CONNECT mode beyond the host name. |
| Root on a monitored host | Keeps off-host signals working: decoy use at the trap, a missing heartbeat, and the dead man's switch. Key usage is planned. | Prevent local sensors from being killed or edited. |
| Tampering with tripline rules | Signed bundles, rollback protection, delayed and announced loosening, floor rules compiled into the binary (all built). Self-tests (built for the egress sensor and the trap). | Survive theft of enough signing keys. |
| Compromise of a tripline maintainer account | Planned release controls: two-person release approval, keyless signing tied to CI identity, reproducible builds. Today CI signs a test artifact only. | Stop a fully colluding set of maintainers. |

## What is built

| Defence | State |
|---|---|
| Decoy files and trap endpoint | Built |
| Egress sensor, CONNECT mode, monitor and enforce | Built |
| Lookalike detection | Built |
| Signed bundles, rollback protection, floor rules, delayed loosening | Built |
| Correlation rules | Built |
| Hash-chained audit log | Built |
| Self-tests for the egress sensor, the trap and bundle currency | Built |
| Heartbeats, silent-source alerts, dead man's switch ping | Built |
| Node sensor, credential-file read events | Planned (Falco, M6) |
| Hooks for Claude Code and Cursor | Planned (M7) |
| Provider mode and tenant pinning (Anthropic, OpenAI) | Built |
| Key-usage connectors and weekly digest | Planned (M8) |
| Canarytokens webhook endpoint | Planned |

## Limitations

Each item below is a known limit. None is hidden by the tool.

### The egress sensor

- **No TLS inspection.** tripline has no custom CA and does not decrypt traffic. It cannot see paths, headers or bodies.
- **CONNECT sees host names only.** The sensor decides on the host name and port from the CONNECT line. An attacker who sends data to an allowed host is not seen.
- **The proxy is voluntary.** The sensor sees only traffic that is sent to it. Malware can ignore `HTTPS_PROXY` and connect directly. Block direct egress with a firewall or network policy so that the proxy is the only route.
- **CONNECT only.** The sensor answers other methods with HTTP 405. It does not handle plain HTTP.
- **Host name, not IP.** A client that connects by IP address sends the IP in the CONNECT line. The allowlist does not name it. Rules treat a raw IP as an unknown host. The lookalike check never flags an IP.
- **Event aggregation.** The first connection to a host, port and decision in a minute is reported at once. Repeats in that minute are reported later, as one event with a count.
- **Monitor mode blocks nothing.** The default is monitor. Switch to enforce on purpose.
- **Fail-open default.** If a sensor in unsigned mode cannot load valid rules at start, it allows all traffic and reports a critical event. Set `fail_mode: closed` to deny instead. See `docs/operations.md`.

### Lookalike detection

- **Public Suffix List is compiled in.** tripline takes registered domains from the Public Suffix List inside the binary. A new suffix needs a tripline update.
- **Small homoglyph table.** The check folds a small set of Cyrillic, Greek and Latin look-alike characters, and decodes punycode. It does not use the full Unicode confusables data.
- **Fixed protected list.** The list holds nine domains by default. Add your own domains to your rules. A lookalike of a domain that is not on the list is not flagged by this check.
- **Subdomains are trusted.** Any subdomain of a protected domain is not a lookalike. A takeover of a real subdomain is not seen.

### Rules

- **`path_glob` has no `**`.** Matching uses Go `path.Match`. The `*` does not cross `/`. The credential-file floor rule lists common home layouts. A file nested deeper is not matched.
- **Small rule language.** Rules support equality, `_in`, `_not_in`, `_glob` and `_lookalike_of`. There is no regular expression and no expression language.
- **A missing field never matches.** A `_not_in` rule does not fire on an event that has no such field.
- **Correlation joins on `subject` only.** Two events from different subjects do not join.
- **Partial chains are bounded.** The correlator keeps up to 64 partial chains per rule and subject and 4096 in total. It drops the oldest when full, and counts the drops.
- **Conservative loosening check.** A change that cannot be shown to be tighter counts as loosening and waits for the delay. This can slow a harmless change.

### The audit log

- **Tail deletion is not detectable.** Each entry holds the hash of the entry before it. Editing, inserting or reordering an entry breaks the chain. Deleting the last entries leaves a valid chain. `tripline audit verify` cannot see it. Keep an external anchor, such as the latest hash copied to another system. See `docs/operations.md`.
- **Root can rewrite the whole file.** An attacker with root on the watcher host can rebuild a consistent chain. An off-host anchor is the defence.

### Hosts and keys

- **Root on the host defeats local sensors.** An attacker with root can stop, edit or bypass the sensor and the watcher. tripline makes no claim against that attacker. Off-host signals still work: decoy use at the trap, the missing heartbeat and the dead man's switch.
- **The trust file is the root of trust.** Keep it owned by root and read-only to the tripline user. An attacker who edits it can accept their own bundles.
- **Stolen keys.** An attacker who steals the required number of signing keys can publish bundles. A bundle that loosens rules still waits for the loosening delay while the watcher alerts. A bundle that tightens rules applies at once.
- **The status page and the ingest API have no user login.** Sensors authenticate with a bearer token. The status page is open to whoever can reach its address. Bind it to a local address or protect it yourself.
- **Sensor tokens are shared secrets.** A stolen token lets an attacker send false events as that sensor.

### Detection scope

- **Provider log latency (planned feature).** Key-usage detection will depend on the delay of each provider's usage logs. Expect minutes to hours, not seconds. Each connector will document its delay.
- **Decoys catch only use.** A decoy alerts when someone uses it. An attacker who reads a file and never uses the key is not seen at Level 1.
- **Fake provider keys.** A fake AI-provider key does not alert by itself. It alerts only when it points at the trap, or when the provider shows usage for it.
- **No data loss prevention.** tripline does not look for customer records or other non-credential data in allowed channels.
- **No machine learning.** Detection uses rules, decoys and self-tests.
- **Prompts and responses.** tripline never stores prompts, responses or secret values. It also cannot judge them.

### The project itself

- **No auto-update.** You update by hand. Wait at least 3 days before you adopt a release, unless it is a security fix. Deploy by digest. See `docs/operations.md`.
- **Release controls are planned.** The spec calls for reproducible builds, two-person release approval, an SBOM and provenance. CI today builds a static binary and the image, and signs a test artifact on pushes to `main`. The double-build check is not in place yet.

## Reporting a problem

Do not open a public issue for a security problem. See `SECURITY.md`.
