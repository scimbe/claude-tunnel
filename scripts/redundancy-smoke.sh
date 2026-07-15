#!/usr/bin/env bash
# Agent-redundancy smoke (issue #8): prove a tunnel survives losing its serving
# agent. Brings up ONE echo origin and TWO agents sharing one identity (same
# routing token, #8 R4a), establishes a client round-trip, kills the agent
# currently serving, and re-runs the client — which must still succeed off the
# surviving agent (edge failover, #8 R1/R2).
#
#   CENTRAL=<host> EDGE_CERT=/path/to/edge-cert.der ./scripts/redundancy-smoke.sh
#
# Prereqs: built binaries (BIN=./target/debug), socat, curl. Runs against an
# already-running central control plane (:8090) + edge (:4433).
set -euo pipefail

CENTRAL="${CENTRAL:?set CENTRAL=<host> (control plane :8090, edge :4433)}"
EDGE_CERT="${EDGE_CERT:?set EDGE_CERT=<path to edge-cert.der>}"
CP_URL="${CP_URL:-http://${CENTRAL}:8090}"
EDGE="${EDGE:-${CENTRAL}:4433}"
TENANT="${TENANT:-t1}"
ORIGIN_PORT="${ORIGIN_PORT:-8083}"
BIN="${BIN:-./target/debug}"
W="$(mktemp -d)"
KEY="$W/origin.key"      # shared origin key (agent 1 creates, agent 2 loads)
CAP="$W/capability.bin"  # shared capability (same routing token)
SECRET="redundancy-$(date +%s)"

ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31mREDUNDANCY FAIL: %s\033[0m\n' "$*" >&2; exit 1; }
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$W"; }
trap cleanup EXIT

[ -f "$EDGE_CERT" ] || fail "edge cert not found at $EDGE_CERT"
[ -x "$BIN/ct-agent" ] && [ -x "$BIN/ct-client" ] || fail "binaries not built (BIN=$BIN)"
command -v socat >/dev/null || fail "socat required"
command -v curl  >/dev/null || fail "curl required"

mint_token() {
  curl -fsS -X POST "$CP_URL/enroll/issue" -H 'content-type: application/json' \
    -d "{\"tenant\":\"$TENANT\"}" | sed -n 's/.*"token":"\([0-9a-f]\{64\}\)".*/\1/p'
}
run_client() {  # → prints ct-client output; returns its exit code
  CT_CLIENT_CAPABILITY="$CAP" CT_CLIENT_EDGE_CERT="$EDGE_CERT" CT_CLIENT_PAYLOAD="$SECRET" \
    "$BIN/ct-client" 2>&1
}

step "Starting one echo origin on 127.0.0.1:${ORIGIN_PORT}"
socat "TCP-LISTEN:${ORIGIN_PORT},reuseaddr,fork,bind=127.0.0.1" EXEC:/bin/cat >/dev/null 2>&1 &
PIDS+=($!); sleep 1
ok "Echo origin up."

step "Onboarding agent 1 (primary — creates the shared identity)"
CT_AGENT_CP_URL="$CP_URL" CT_AGENT_JOIN_TOKEN="$(mint_token)" CT_AGENT_ID="redundant-1" \
CT_AGENT_EDGE="$EDGE" CT_AGENT_ORIGIN="127.0.0.1:${ORIGIN_PORT}" CT_AGENT_EDGE_CERT="$EDGE_CERT" \
CT_AGENT_ORIGIN_KEY="$KEY" CT_AGENT_CAPABILITY_OUT="$CAP" \
  "$BIN/ct-agent" onboard >"$W/agent1.log" 2>&1 &
A1=$!; PIDS+=($A1)
for _ in $(seq 1 30); do [ -s "$CAP" ] && break; sleep 0.5; done
[ -s "$CAP" ] || fail "agent 1 did not create the shared identity ($W/agent1.log)"
ok "Agent 1 onboarded; shared identity at $KEY + $CAP."

step "Onboarding agent 2 (redundant — loads the same identity, same origin)"
CT_AGENT_CP_URL="$CP_URL" CT_AGENT_JOIN_TOKEN="$(mint_token)" CT_AGENT_ID="redundant-2" \
CT_AGENT_EDGE="$EDGE" CT_AGENT_ORIGIN="127.0.0.1:${ORIGIN_PORT}" CT_AGENT_EDGE_CERT="$EDGE_CERT" \
CT_AGENT_ORIGIN_KEY="$KEY" CT_AGENT_CAPABILITY_OUT="$CAP" \
  "$BIN/ct-agent" onboard >"$W/agent2.log" 2>&1 &
A2=$!; PIDS+=($A2)
sleep 3
ok "Agent 2 onboarded; two agents now register the same routing token."

step "Client round-trip with both agents up"
OUT="$(run_client)" || true
printf '%s' "$OUT" | grep -q "round-trip OK" || fail "baseline tunnel failed: $OUT"
VIA="$(printf '%s' "$OUT" | sed -n 's/.*via=\([a-z]*\).*/\1/p' | head -1)"
ok "Baseline round-trip OK (via=${VIA:-?})."

step "Killing the most-recently-registered agent (agent 2, the one now serving)"
kill "$A2" 2>/dev/null || true
# Give the edge time to notice the drop and evict that registration.
sleep 6
ok "Agent 2 killed; edge should have evicted its registration."

step "Client round-trip after the serving agent died — must fail over to agent 1"
OUT2="$(run_client)" || true
if printf '%s' "$OUT2" | grep -q "round-trip OK"; then
  VIA2="$(printf '%s' "$OUT2" | sed -n 's/.*via=\([a-z]*\).*/\1/p' | head -1)"
  ok "Failover round-trip OK (via=${VIA2:-?}) — the tunnel survived losing an agent."
  printf '\033[1;32mREDUNDANCY OK — tunnel served by the surviving agent (via=%s)\033[0m\n' "${VIA2:-?}"
else
  fail "tunnel did NOT survive the agent kill: $OUT2"
fi
