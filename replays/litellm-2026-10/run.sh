#!/usr/bin/env bash
# Usage: run.sh LEVEL MODE   (LEVEL=2, MODE=monitor|enforce)
# Needs bin/tripline-linux-amd64 (just build-linux) and Docker Compose.
set -euo pipefail

LEVEL=${1:-2}
MODE=${2:-monitor}
case "$LEVEL" in
  2) ;;
  1 | 3) echo "level $LEVEL: not yet"; exit 2 ;;
  *) echo "usage: run.sh LEVEL MODE" >&2; exit 2 ;;
esac
case "$MODE" in
  monitor) WANT_DECISION=observe; WANT_CONNECT=200; WANT_SINK=yes ;;
  enforce) WANT_DECISION=deny; WANT_CONNECT=403; WANT_SINK=no ;;
  *) echo "mode must be monitor or enforce" >&2; exit 2 ;;
esac

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
[ -f "$ROOT/bin/tripline-linux-amd64" ] || { echo "missing bin/tripline-linux-amd64: run 'just build-linux'" >&2; exit 1; }

WORK=$(mktemp -d)
chmod 755 "$WORK"
export LAB_RULES_DIR=$WORK
export SENSOR_TOKEN=unset
dc() { docker compose -p "replay-$MODE" -f "$HERE/compose.yaml" "$@"; }
victim() { dc exec -T victim-gateway "$@"; }
cleanup() {
  rc=$?
  if [ "$rc" -ne 0 ]; then dc logs --no-color --tail 40 >&2 || true; fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

# Rules: lookalike first, so the lookalike rule is the one the event names.
# The mode of every rule is replaced by MODE.
{ cat "$ROOT/rules/profiles/lookalike.yaml"; echo; echo '---'; cat "$ROOT/rules/profiles/gateway-strict.yaml"; } |
  sed "s/^mode: monitor/mode: $MODE/" >"$WORK/rules.yaml"
[ "$(grep -c "^mode: $MODE" "$WORK/rules.yaml")" = 2 ] || { echo "mode substitution failed" >&2; exit 1; }
chmod 644 "$WORK/rules.yaml"

dc build watcher
dc run --rm -T prep
# The token is generated now, held in memory and in the compose environment
# of this run only. It is never written to a committed file.
SENSOR_TOKEN=$(dc run --rm -T --no-deps watcher sensor add -config /etc/tripline/tripline.yaml lab-egress 2>"$WORK/add.err" | tr -d '\r\n') ||
  { cat "$WORK/add.err" >&2; exit 1; }
case "$SENSOR_TOKEN" in tlsen_*) ;; *) cat "$WORK/add.err" >&2; echo "no sensor token" >&2; exit 1 ;; esac
export SENSOR_TOKEN
dc up -d

for _ in $(seq 1 30); do
  victim curl -fsS http://watcher:7701/status.json >/dev/null 2>&1 && break
  sleep 1
done

sink_seen() { [ "$(dc logs --no-color sink | grep -c 'sink: connection accepted' || true)" -gt 0 ] && echo yes || echo no; }
connect_of() { sed -n 's/.*connect=\([0-9]*\).*/\1/p' | tail -n 1; }

OUT=$(victim sh /lab/victim.sh || true)
CONNECT1=$(printf '%s\n' "$OUT" | connect_of)
SINK1=$(sink_seen)

# Wait for the sensor event to reach the audit log, then read it.
LINE=""
for _ in $(seq 1 20); do
  dc cp watcher:/state/audit.jsonl "$WORK/audit.jsonl" >/dev/null 2>&1 || true
  if [ -f "$WORK/audit.jsonl" ]; then
    LINE=$(grep '"kind":"egress.connect"' "$WORK/audit.jsonl" | grep '"host":"litellm.dev"' |
      grep "\"decision\":\"$WANT_DECISION\"" | head -n 1 || true)
  fi
  [ -n "$LINE" ] && break
  sleep 2
done
GOT_DECISION=$(printf '%s' "$LINE" | sed -n 's/.*"decision":"\([a-z]*\)".*/\1/p')
GOT_RULE=$(printf '%s' "$LINE" | sed -n 's/.*"rule_id":"\([^"]*\)".*/\1/p')
STATUS=$(victim curl -fsS http://watcher:7701/status.json || true)
REJECTED=$(printf '%s' "$STATUS" | sed -n 's/.*"events_rejected":\([0-9]*\).*/\1/p')

# Kill the watcher. The sensor must keep its decision.
dc kill watcher >/dev/null
sleep 1
OUT2=$(victim sh /lab/victim.sh || true)
CONNECT2=$(printf '%s\n' "$OUT2" | connect_of)
SINK2=$(sink_seen)

FAIL=0
row() { # name expected actual
  local ok=OK
  [ "$2" = "$3" ] || { ok=MISMATCH; FAIL=1; }
  printf '%-44s %-18s %-18s %s\n' "$1" "$2" "${3:-none}" "$ok"
}
printf '%-44s %-18s %-18s\n' CHECK EXPECTED ACTUAL
row "audit: egress.connect litellm.dev decision" "$WANT_DECISION" "$GOT_DECISION"
row "audit: deciding rule" egress-lookalike "$GOT_RULE"
row "watcher status.json events_rejected" 0 "$REJECTED"
row "victim CONNECT result" "$WANT_CONNECT" "$CONNECT1"
row "sink saw a connection" "$WANT_SINK" "$SINK1"
row "watcher killed: victim CONNECT result" "$WANT_CONNECT" "$CONNECT2"
row "watcher killed: sink saw a connection" "$WANT_SINK" "$SINK2"

[ "$FAIL" = 0 ] && echo "replay level $LEVEL $MODE: PASS" || { echo "replay level $LEVEL $MODE: FAIL"; exit 1; }
