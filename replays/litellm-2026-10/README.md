# Replay lab: LiteLLM compromise, October 2026

This lab recreates the shape of the attack. It uses decoy data and local containers only.

## What it simulates

A gateway container is compromised. The malicious code reads a credential file. It then sends data to `litellm.dev`, a lookalike of the real `litellm.ai`.

Levels 1 and 2 exist. Level 3 prints "not yet".

### Level 1: decoy use

No sensor takes part. Detection happens at the trap. The `MODE` argument is ignored.

1. `tripline init` runs in a one-shot container. It plants a decoy `config.yaml` and `.env.backup` in a shared volume. The `api_base` in the decoy points at the watcher trap, `http://watcher:7702`.
2. Stage 1, the stealer (`stealer.sh` in `victim-gateway`): reads the decoy config as its gateway config. It sends only the sha256 to `litellm.dev`. Nothing guards this path, so the sink sees the connection.
3. Stage 2, the attacker (`attacker.sh` in a separate `attacker` container): gets a copy of the stolen file. It sends one fake chat completion request to the `api_base` in it. That is the trap. No real provider is used.

| Check | Expected |
|---|---|
| Trap response | 401 |
| Audit log | `tripwire.hit` with `selftest` false |
| Audit log and watcher stdout | Alert for rule `tripwire-hit`, severity `critical`, `trace_id` equal to the hit event ID |
| Alert text | Names the decoy fingerprint to rotate |
| Audit log | No raw decoy token and no request body |

### Level 2: lookalike destination

| Mode | Expected result |
|---|---|
| monitor | The sensor lets the connection pass. The audit log holds `egress.connect` for `litellm.dev` with decision `observe`. Rule `egress-lookalike` matched. |
| enforce | The sensor returns 403. The audit log holds decision `deny`. The sink sees no connection. |

In both modes the check repeats after the watcher is killed. The sensor decides on its own, so the result must not change.

## Why it is harmless

- The compose network is `internal: true`. It has no route to the internet.
- `litellm.dev` is a network alias of the `sink` container. The name resolves only inside the lab.
- The decoy file holds random bytes made at run time. The victim sends only its sha256.
- The sink reads one byte and closes. It never speaks TLS and never replies.
- No real malware code and no real credential exist in this folder.
- The sensor token is made at run time with `tripline sensor add`. It is not stored in the repository.
- All tripline containers run as user 65532 with a read-only root, `cap_drop: ALL` and `no-new-privileges`.

The victim request ends in a TLS error, because the sink is plain TCP. This is expected. The proof is the CONNECT result and the sensor event.

## Run it

Docker with Compose v2 is required.

```
just replay 1
just replay 2 monitor
just replay 2 enforce
```

`just replay` builds `bin/tripline-linux-amd64` first. You can also run `bash replays/litellm-2026-10/run.sh 2 monitor` after `just build-linux`.

The script prints an EXPECTED and ACTUAL table and exits non-zero on any mismatch. It removes the containers and volumes at the end.

## Files

- `compose.yaml`: the lab services and the internal network.
- `config/tripline.yaml`: watcher and sensor config.
- `victim.sh`: the Level 2 decoy and the hash-only POST.
- `stealer.sh`, `attacker.sh`, `level1.sh`: the Level 1 stages and checks.
- `run.sh`: starts the lab, checks the results, cleans up.

The rules file is built at run time from `rules/profiles/lookalike.yaml` and `rules/profiles/gateway-strict.yaml`. The script sets the mode of every rule.
