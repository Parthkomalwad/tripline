# Replay lab: LiteLLM compromise, October 2026

This lab recreates the shape of the attack. It uses decoy data and local containers only.

## What it simulates

A gateway container is compromised. The malicious code reads a credential file. It then sends data to `litellm.dev`, a lookalike of the real `litellm.ai`.

Only Level 2 exists today. Levels 1 and 3 print "not yet".

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
just replay 2 monitor
just replay 2 enforce
```

`just replay` builds `bin/tripline-linux-amd64` first. You can also run `bash replays/litellm-2026-10/run.sh 2 monitor` after `just build-linux`.

The script prints an EXPECTED and ACTUAL table and exits non-zero on any mismatch. It removes the containers and volumes at the end.

## Files

- `compose.yaml`: the lab services and the internal network.
- `config/tripline.yaml`: watcher and sensor config.
- `victim.sh`: the decoy and the hash-only POST.
- `run.sh`: starts the lab, checks the results, cleans up.

The rules file is built at run time from `rules/profiles/lookalike.yaml` and `rules/profiles/gateway-strict.yaml`. The script sets the mode of every rule.
