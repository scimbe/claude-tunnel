#!/usr/bin/env bash
# Origin-key rotation smoke (issue #12): prove that after a zero-downtime origin
# key rotation, BOTH the old capability and the new capability (same routing
# token, different origin identity) complete a tunnel round-trip.
#
#   CENTRAL=<host> EDGE_CERT=/path/to/edge-cert.der ./scripts/rotation-smoke.sh
#
# Prereqs: built binaries (BIN=./target/debug), socat, curl, jq. Runs against an
# already-running central control plane (:8090) + edge (:4433).
set -euo pipefail

CENTRAL="${CENTRAL:?set CENTRAL=<host> (control plane :8090, edge :4433)}"
EDGE_CERT="${EDGE_CERT:?set EDGE_CERT=<path to edge-cert.der>}"
CP_URL="${CP_URL:-http://${CENTRAL}:8090}"
EDGE="${EDGE:-${CENTRAL}:4433}"
TENANT="${TENANT:-t1}"
ORIGIN_PORT="${ORIGIN_PORT:-8085}"
BIN="${BIN:-./target/debug}"
W="$(umask 077 && mktemp -d)"
chmod 700 "$W"
KEY="$W/origin.key"          # primary origin key (rotated in place)
DIR="$W/retired"            # retired-key dir (old identities served in the window)
CAP="$W/capability.bin"      # published capability (re-minted on rotate)
CAP_OLD="$W/cap-old.bin"     # snapshot of the pre-rotation capability
CAP_NEW="$W/cap-new.bin"     # snapshot of the post-rotation capability
SECRET="rotate-$(date +%s)"

step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31mROTATION FAIL: %s\033[0m\n' "$*" >&2; exit 1; }
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$W"; }
trap cleanup EXIT

[ -f "$EDGE_CERT" ] || fail "edge cert not found at $EDGE_CERT"
[ -x "$BIN/ct-agent" ] && [ -x "$BIN/ct-client" ] || fail "binaries not built (BIN=$BIN)"
command -v socat >/dev/null || fail "socat required"
command -v curl  >/dev/null || fail "curl required"
command -v jq >/dev/null || fail "jq required (apt-get install jq)"

mint_token() {
  curl --connect-timeout 5 --max-time 10 -fsS -X POST "$CP_URL/enroll/issue" -H 'content-type: application/json' \
    -d "{\"tenant\":\"$TENANT\"}" \
    | jq -r '.token // empty' 2>/dev/null
}
start_agent() {  # $1 = extra env note; serves with the current KEY/DIR/CAP
  CT_AGENT_CP_URL="$CP_URL" CT_AGENT_JOIN_TOKEN="$(mint_token)" CT_AGENT_ID="rot-$1" \
  CT_AGENT_EDGE="$EDGE" CT_AGENT_ORIGIN="127.0.0.1:${ORIGIN_PORT}" CT_AGENT_EDGE_CERT="$EDGE_CERT" \
  CT_AGENT_ORIGIN_KEY="$KEY" CT_AGENT_ORIGIN_KEY_DIR="$DIR" CT_AGENT_CAPABILITY_OUT="$CAP" \
    "$BIN/ct-agent" onboard >"$W/agent-$1.log" 2>&1 &
  AGENT_PID=$!; PIDS+=("$AGENT_PID")
}
client_ok() {  # $1 = capability file → returns 0 if round-trip OK
  CT_CLIENT_CAPABILITY="$1" CT_CLIENT_EDGE_CERT="$EDGE_CERT" CT_CLIENT_PAYLOAD="$SECRET" \
    "$BIN/ct-client" 2>&1 | grep -q "round-trip OK"
}

step "Starting one echo origin on 127.0.0.1:${ORIGIN_PORT}"
socat "TCP-LISTEN:${ORIGIN_PORT},reuseaddr,fork,bind=127.0.0.1" EXEC:/bin/cat >/dev/null 2>&1 &
PIDS+=($!); sleep 1; ok "Origin up."

step "Onboarding agent with the ORIGINAL origin identity"
start_agent orig
for _ in $(seq 1 30); do [ -s "$CAP" ] && break; sleep 0.5; done
[ -s "$CAP" ] || fail "agent did not publish a capability ($W/agent-orig.log)"
cp "$CAP" "$CAP_OLD"
ok "Agent serving the original identity; saved the OLD capability."

step "Client round-trip with the ORIGINAL capability"
client_ok "$CAP_OLD" || fail "baseline round-trip failed with the original capability"
ok "Original capability round-trips."

step "Rotating the origin key (same token, new origin; old key retired)"
kill "$AGENT_PID" 2>/dev/null || true; sleep 2
CT_AGENT_ORIGIN_KEY="$KEY" CT_AGENT_ORIGIN_KEY_DIR="$DIR" CT_AGENT_CAPABILITY_OUT="$CAP" \
  "$BIN/ct-agent" rotate >"$W/rotate.log" 2>&1 || fail "rotate failed ($W/rotate.log)"
cp "$CAP" "$CAP_NEW"
ls "$DIR"/retired-*.key >/dev/null 2>&1 || fail "rotate did not retire the old key into $DIR"
ok "Rotated: new capability saved; old key retired to the dir."

step "Restarting the agent to serve BOTH identities (rotation window)"
start_agent window
sleep 3
ok "Agent restarted with the retired-key dir."

step "OLD capability must still round-trip (client not yet migrated)"
client_ok "$CAP_OLD" || fail "OLD capability broke after rotation — window not honored"
ok "OLD capability still round-trips (routes via the preserved token, handshakes the retired key)."

step "NEW capability must round-trip (migrated client)"
client_ok "$CAP_NEW" || fail "NEW capability failed after rotation"
ok "NEW capability round-trips."

printf '\033[1;32mROTATION OK — old and new capabilities (same token, different origin) both tunnel\033[0m\n'
