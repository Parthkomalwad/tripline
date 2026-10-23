#!/bin/sh
# Level 1, stage 2: harmless stand-in for the attacker. It "tries the key" from
# the stolen decoy config: one fake chat request to the api_base in that file.
# That api_base is the tripline trap inside the lab. No real provider is used.
# Prints one line: trap=<http code>.
set -u
cfg=/work/stolen.yaml
base=$(sed -n 's/^ *api_base: *//p' "$cfg" | head -n 1)
key=$(sed -n 's/^ *api_key: *//p' "$cfg" | head -n 1)
[ -n "$base" ] && [ -n "$key" ] || { echo "no api_base or api_key" >&2; exit 3; }
curl -s -m 10 -o /dev/null -w 'trap=%{http_code}\n' \
  -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
  --data '{"model":"gpt-4o","messages":[{"role":"user","content":"tl-lab-body-marker"}]}' \
  "$base/chat/completions" || echo "trap=000"
