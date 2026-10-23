# Level 1 body. Sourced by run.sh after the shared setup (dc, victim, WORK).
# Decoy use is detected at the trap. No sensor takes part.
attacker() { dc exec -T attacker "$@"; }

dc build watcher
dc run --rm -T prep
# Plant the decoys with the real "tripline init" into the shared volumes.
dc run --rm -T --no-deps init >/dev/null
dc up -d watcher sink victim-gateway attacker

for _ in $(seq 1 30); do
  victim curl -fsS http://watcher:7701/status.json >/dev/null 2>&1 && break
  sleep 1
done

# Stage 1: the stealer reads the decoy config and sends only its hash.
victim sh /lab/stealer.sh >/dev/null || true
SINK=$([ "$(dc logs --no-color sink | grep -c 'sink: connection accepted' || true)" -gt 0 ] && echo yes || echo no)

# Stage 2: the attacker gets a copy of the file and tries the key.
victim cat /gateway/config.yaml | dc exec -T attacker sh -c 'cat > /work/stolen.yaml'
TOKEN=$(attacker sed -n 's/.*\/trap\/\([^\/]*\)\/.*/\1/p' /work/stolen.yaml | head -n 1 | tr -d '\r\n')
[ -n "$TOKEN" ] || { echo "no decoy token in stolen config" >&2; exit 1; }
# Same rule as tripwire.Fingerprint: first 4 chars, then 12 hex of the sha256.
FP="$(printf %.4s "$TOKEN")-$(printf %s "$TOKEN" | sha256sum | cut -c1-12)"
TRAP=$(attacker sh /lab/attacker.sh | sed -n 's/^trap=//p' | tail -n 1 | tr -d '\r\n')

HIT=""; ALERT=""
for _ in $(seq 1 20); do
  dc cp watcher:/state/audit.jsonl "$WORK/audit.jsonl" >/dev/null 2>&1 || true
  if [ -f "$WORK/audit.jsonl" ]; then
    HIT=$(grep '"kind":"tripwire.hit"' "$WORK/audit.jsonl" | grep '"selftest":false' | head -n 1 || true)
    ALERT=$(grep '"type":"alert"' "$WORK/audit.jsonl" | grep '"rule_id":"tripwire-hit"' | head -n 1 || true)
  fi
  [ -n "$HIT" ] && [ -n "$ALERT" ] && break
  sleep 2
done
EVID=$(printf '%s' "$HIT" | sed -n 's/.*"id":"\(evt_[0-9a-f]*\)".*/\1/p')
# has TEXT NEEDLE: yes when TEXT is not empty and holds NEEDLE.
has() { [ -n "$1" ] && printf '%s' "$1" | grep -qF -- "$2" && echo yes || echo no; }
count() { grep -cF -- "$1" "$WORK/audit.jsonl" 2>/dev/null || true; }

FAIL=0
row() { # name expected actual
  local ok=OK
  [ "$2" = "$3" ] || { ok=MISMATCH; FAIL=1; }
  printf '%-44s %-18s %-18s %s\n' "$1" "$2" "${3:-none}" "$ok"
}
printf '%-44s %-18s %-18s\n' CHECK EXPECTED ACTUAL
row "stealer hash reached litellm.dev (unguarded)" yes "$SINK"
row "trap HTTP status for the attacker" 401 "$TRAP"
row "audit: tripwire.hit with selftest false" yes "$([ -n "$HIT" ] && echo yes || echo no)"
row "audit: alert for rule tripwire-hit" yes "$([ -n "$ALERT" ] && echo yes || echo no)"
row "audit: alert severity critical" yes "$(has "$ALERT" '"severity":"critical"')"
row "audit: alert trace_id is the hit event id" yes "$([ -n "$EVID" ] && has "$ALERT" "\"trace_id\":\"$EVID\"" || echo no)"
row "alert names the decoy fingerprint to rotate" yes "$(has "$ALERT" "Rotate the key with fingerprint $FP")"
row "watcher stdout sink printed the alert" yes "$([ "$(dc logs --no-color watcher | grep -c '"rule_id":"tripwire-hit"' || true)" -gt 0 ] && echo yes || echo no)"
row "audit lines holding the raw decoy token" 0 "$(count "$TOKEN")"
row "audit lines holding the request body" 0 "$(count tl-lab-body-marker)"

[ "$FAIL" = 0 ] && echo "replay level $LEVEL: PASS" || { echo "replay level $LEVEL: FAIL"; exit 1; }
