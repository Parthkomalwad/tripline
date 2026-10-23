# Quickstart

This guide sets up tripline at three levels. Level 1 and Level 2 exist today. Level 3 is planned.

tripline is pre-release. Use a test host first.

## Before you start

Install Go (the version in `go.mod`) and [just](https://github.com/casey/just). Then build the binary.

```sh
git clone https://github.com/Parthkomalwad/tripline.git
cd tripline
just build
export PATH="$PWD/bin:$PATH"
tripline version
```

The binary is static. Its dependencies are `gopkg.in/yaml.v3` and `golang.org/x/net` (the `publicsuffix` package only).

To build the container image instead, run `just image`. The image runs as user 65532 on a read-only root. A published image comes with the first release. Always deploy by digest. See `docs/operations.md`.

## Level 1: watcher, decoys and trap

Level 1 puts nothing in your traffic path. The watcher receives events and serves a trap. The decoys are files that point at the trap.

### 1. Create the config and the decoys

```sh
mkdir ~/tripline-demo
tripline init -dir ~/tripline-demo
cd ~/tripline-demo
```

`tripline init` writes these items:

- `tripline.yaml`: a watch-only config.
- `rules.yaml`: the `tripwire-hit` rule.
- `tripline-state/`: tokens and the decoy registry. The watcher adds the audit log here.
- `decoys/config.yaml` and `decoys/.env.backup`: two decoys, each with a unique token.

`init` prints a sensor token once. Store it in a secret manager. tripline cannot show it again.

`init` refuses to overwrite `tripline.yaml`. It never overwrites a decoy.

Use `-trap-url` to set the address that an attacker can reach. The default is `http://127.0.0.1:7702`.

### 2. Minimal Level 1 config

This is what `init` writes, without the comments.

```yaml
watcher:
  listen: 127.0.0.1:7700
  trap_listen: 127.0.0.1:7702
  status_page: 127.0.0.1:7701
  state_dir: ./tripline-state
  rules_file: ./rules.yaml
selftest:
  interval: 1h
```

The watcher rejects unknown keys. A typo stops the start.

Add alert sinks. Name the environment variable. Never write the URL in the file.

```yaml
sinks:
  - type: slack
    webhook_url_env: TRIPLINE_SLACK_WEBHOOK
  - type: webhook
    url_env: TRIPLINE_WEBHOOK_URL
```

Add a dead man's switch. The watcher pings the URL every 60 seconds. An outside service alerts when the pings stop.

```yaml
watcher:
  heartbeat_ping_url_env: TRIPLINE_DEADMAN_URL
```

Merge these keys into the sections above. Do not repeat a top-level key.

### 3. Start the watcher and read the status

```sh
tripline watcher -config tripline.yaml &
sleep 2
tripline status -config tripline.yaml
```

The status screen shows these items:

- The rule bundle version and the count of rejected events.
- The self-test pass rate.
- Every source, with its last heartbeat.
- The coverage per sensor type.
- The recent alerts.

A sensor type with no active source shows `NOT WATCHED`. Expect gaps. At Level 1 only the trap is active.

Use `tripline status -json` for the raw document. The same data is at `http://127.0.0.1:7701/` (web page), `/status.json` and `/metrics` (Prometheus text).

The status page has no login. Bind it to a local address, or put it behind your own access control.

### 4. Plant the decoys

Copy the decoys to places where an attacker looks. Examples: a backup of a gateway config folder, or a `.env.backup` next to a real `.env`. Do not put real keys in them.

Each decoy holds a fake key and a base URL on the trap. A tool that tries the config reaches the trap.

### 5. Trip the trap

```sh
. ./decoys/.env.backup
curl -i -H "Authorization: Bearer $OPENAI_API_KEY" "$OPENAI_BASE_URL/models"
tripline status -config tripline.yaml
```

The trap returns HTTP 401, like a provider. The watcher records a `tripwire.hit` event. The status screen lists a `tripwire-hit` alert with severity `critical` and a trace ID.

The trap stores no request body. It records a token fingerprint, the remote address, the method and a truncated user agent.

### 6. Check the audit log

```sh
tripline audit verify -config tripline.yaml
```

The command prints `ok: N entries`, or an error that names the entry where the chain breaks. See `docs/operations.md` for the limit of this check.

### 7. Canarytokens (not built)

The spec plans a `/v1/ingest/canarytoken` endpoint for Thinkst Canarytokens webhooks. That endpoint does not exist yet.

Fake AI-provider keys do not alert by themselves. They alert only if the provider shows usage for them. Check this for each provider.

## Level 2: egress sensor

The egress sensor is a forward proxy for HTTPS CONNECT. It decides on the host name and port. It does not decrypt TLS. Your AI gateway or agent uses it through `HTTPS_PROXY`.

The proxy is voluntary. A process that ignores `HTTPS_PROXY` bypasses it. Block direct egress at the network level, so that the proxy is the only route. See `docs/threat-model.md`.

### 1. Create a sensor token

```sh
tripline sensor add -config tripline.yaml gw-egress
```

The command prints the token once. Put it in an environment variable for the sensor.

```sh
export TRIPLINE_SENSOR_TOKEN=tlsen_...
```

### 2. Write the rules

Start in monitor mode. Copy the profile rules from the tripline repository. Separate the rules with `---`.

```sh
cd /path/to/tripline
{ cat rules/profiles/lookalike.yaml; echo '---'; cat rules/profiles/gateway-strict.yaml; } > ~/tripline-demo/rules.yaml
cd ~/tripline-demo
```

Edit the `host_not_in` list in `egress-allowlist`. Name the provider hosts that your gateway uses. Keep `mode: monitor`.

The `tripwire-hit` rule is a floor rule. It stays active when it is not in the file.

### 3. Minimal Level 2 config

Add a `sensor:` section to `tripline.yaml`. One file serves both programs.

```yaml
watcher:
  listen: 127.0.0.1:7700
  trap_listen: 127.0.0.1:7702
  status_page: 127.0.0.1:7701
  state_dir: ./tripline-state
  rules_file: ./rules.yaml
selftest:
  interval: 1h
  sensors:
    - id: gw-egress
      proxy_url: http://127.0.0.1:8080
sensor:
  id: gw-egress
  watcher_url: http://127.0.0.1:7700
  token_env: TRIPLINE_SENSOR_TOKEN
  listen: 127.0.0.1:8080
  profile: gateway-strict
  rules_file: ./rules.yaml
  state_dir: ./sensor-state
  buffer_max_bytes: 52428800
  fail_mode: open
```

Required `sensor` keys: `id`, `watcher_url`, `token_env`, `profile`, `state_dir`, and one of `rules_file` or `trust_file`. Defaults: `listen` is `127.0.0.1:8080`, `buffer_max_bytes` is 50 MiB, `fail_mode` is `open`.

The `selftest.sensors` list makes the watcher probe the sensor on each interval. Leave it out to skip the probes.

### 4. Start the sensor and route traffic

Restart the watcher with the new config. Then start the sensor.

```sh
tripline sensor egress -config tripline.yaml &
export HTTPS_PROXY=http://127.0.0.1:8080
```

The sensor handles only CONNECT. It answers other methods with HTTP 405. Plain HTTP through `HTTP_PROXY` does not work.

Test it.

```sh
curl -sS -o /dev/null -w '%{http_code}\n' https://example.com
tripline status -config tripline.yaml
```

In monitor mode the connection succeeds. The event has `decision: observe`. The status screen lists `sensor.egress` as watched.

### 5. Switch to enforce

Change `mode: monitor` to `mode: enforce` on the rules you want to block. A rule blocks only if `block` is in its `on_match`. The sensor then returns HTTP 403 for a denied CONNECT.

Run in monitor mode for several days first. Read the `observe` events. Add every legitimate host to the allowlist before you enforce.

With signed bundles (below), you change the mode in a new bundle. A change from `enforce` to `monitor` is loosening and waits for the delay.

### 6. Signed bundles

An unsigned `rules_file` is for development. The watcher logs a warning when it uses one. For production, use signed bundles. Two keys must sign by default.

Create two keys. Use two machines if you can.

```sh
tripline rules keygen -id maya-2026 -out keys -owner Maya
tripline rules keygen -id raj-2026 -out keys -owner Raj
```

Each command writes `<id>.key` (private, mode 0600) and `<id>.pub`. It prints a snippet for the trust file. Keep the private files off the watcher host. `keygen` never overwrites a key.

Write the trust file. Make it owned by root and read-only to the tripline user.

```yaml
keys:
  - key_id: maya-2026
    public_key: <base64 from keygen>
    owner: Maya
  - key_id: raj-2026
    public_key: <base64 from keygen>
    owner: Raj
required_signatures: 2
loosening_delay: 24h
```

Write the bundle. The `rules` list holds the rules as YAML mappings.

```yaml
version: 1
created_at: 2026-10-24T09:00:00Z
effective_at: 2026-10-24T09:00:00Z
signers: [maya, raj]
rules:
  - id: egress-allowlist
    applies_to: { source: sensor.egress, profile: gateway-strict }
    match:
      kind: egress.connect
      host_not_in: ["api.anthropic.com", "api.openai.com"]
    severity: high
    mode: monitor
    on_match: [alert, block]
```

Each signer signs the file in place, on a trusted machine. Then verify it.

```sh
tripline rules sign -key keys/maya-2026.key -in bundle.yaml
tripline rules sign -key keys/raj-2026.key  -in bundle.yaml
tripline rules verify -trust trust.yaml bundle.yaml
```

`sign` rewrites the file and drops YAML comments. Any later edit to a signed field breaks the signatures. Sign last.

Point the watcher and the sensor at the trust file and the bundle.

```yaml
watcher:
  bundle_file: ./bundle.yaml
trust:
  file: /etc/tripline/trust.yaml
sensor:
  trust_file: /etc/tripline/trust.yaml
```

Remove `rules_file` from the `watcher` and `sensor` sections. When `trust.file` is set, the watcher ignores `rules_file`.

The watcher reads `bundle_file` every 30 seconds. The sensor pulls the bundle from the watcher every 30 seconds. The sensor verifies it again with its own trust file. Until the first verified bundle arrives, the sensor uses the floor rules only.

The `trust.required_signatures` and `trust.loosening_delay` keys in `tripline.yaml` are accepted but not read. Set them in the trust file.

To publish a new version, follow these steps:

1. Raise `version` and set the times.
2. Sign with the required number of keys.
3. Run `tripline rules verify -trust trust.yaml -current <applied version> bundle.yaml`.
4. Copy the file to `bundle_file`.

Use `tripline rules diff old.yaml new.yaml` to see which changes loosen. Details are in `docs/rules.md`.

### 7. Run the replay

With Docker and Compose v2, run `just replay 2 monitor` and `just replay 2 enforce`. This is a harmless lab. See `replays/litellm-2026-10/README.md`.

## Level 3: node sensor and hooks (planned)

Level 3 is not built. The plan:

- A Falco rule set and a Falco ingest, to see credential-file reads on a node as `secret.read` events. Milestone 6.
- Hooks for Claude Code and Cursor, to deny dangerous tool calls and agent-config edits. Milestone 7.
- Correlation of a `secret.read` with a later unapproved connection. The correlation engine exists today. No sensor emits `secret.read` yet.

Provider mode (the sensor injects the real provider key) is milestone 5. Key-usage connectors and the weekly digest are milestone 8. None of these exist yet.
