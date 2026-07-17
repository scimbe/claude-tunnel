#!/usr/bin/env bash
# One-command cross-host end-to-end smoke (issue #6).
#
# Onboards an agent against a central control plane + edge, runs a client through
# the tunnel to a local echo origin, and reports the round-trip:
#   SMOKE OK via=<quic|tcp>      (exit 0)
#   SMOKE FAIL: <reason>         (exit 1)
#
# Required env:
#   CENTRAL    host of the control plane (:8090) and edge (:4433)
#   EDGE_CERT  path to the edge CA-root cert (edge-cert.der), copied from the
#              central host (it is public trust material, safe to distribute)
# Optional env:
#   CT_JOIN_TOKEN     a single-use join token (else one is minted via /enroll/issue)
#   TENANT (t1)  ORIGIN_PORT (8080)  AGENT_ID (smoke-agent)  PAYLOAD (hello-smoke)
#   BIN (./target/debug)              CT_CLIENT_FORCE_TCP=1  to force the TCP fallback
#
# Build the binaries first (hermetic):
#   docker run --rm -v "$PWD":/work -w /work rust:1-slim cargo build --workspace
set -euo pipefail

CENTRAL="${CENTRAL:?set CENTRAL=<host> (control plane :8090, edge :4433)}"
EDGE_CERT="${EDGE_CERT:?set EDGE_CERT=<path to edge-cert.der from the central host>}"
CP_URL="${CP_URL:-http://${CENTRAL}:8090}"
EDGE="${EDGE:-${CENTRAL}:4433}"
TENANT="${TENANT:-t1}"
ORIGIN_PORT="${ORIGIN_PORT:-8080}"
AGENT_ID="${AGENT_ID:-smoke-agent}"
PAYLOAD="${PAYLOAD:-hello-smoke}"
BIN="${BIN:-./target/debug}"
WORK="$(mktemp -d)"
chmod 700 "$WORK"
CAP="$WORK/capability.bin"

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }
terminate_tree() {
  local pid="$1"
  [ -n "${pid:-}" ] || return 0
  kill "$pid" 2>/dev/null || true
  sleep 0.5
  kill -9 "$pid" 2>/dev/null || true
}
cleanup() {
  terminate_tree "${AGENT_PID:-}"
  terminate_tree "${ORIGIN_PID:-}"
  rm -rf "$WORK"
}
trap cleanup EXIT

# Preconditions.
[ -f "$EDGE_CERT" ] || fail "edge cert not found at EDGE_CERT=$EDGE_CERT"
[ -x "$BIN/ct-agent" ] && [ -x "$BIN/ct-client" ] \
  || fail "binaries not built (expected $BIN/ct-agent and $BIN/ct-client) — build the workspace first"
command -v socat >/dev/null || fail "socat is required for the echo origin (apt-get install socat)"
command -v curl >/dev/null || fail "curl is required"
command -v jq >/dev/null || fail "jq is required for robust token parsing (apt-get install jq)"
command -v nc >/dev/null || fail "nc is required for origin readiness checks (apt-get install netcat-openbsd)"

# 1. Join token — use CT_JOIN_TOKEN or mint one from the control plane.
TOKEN="${CT_JOIN_TOKEN:-}"
if [ -z "$TOKEN" ]; then
  TOKEN="$(
    curl --connect-timeout 5 --max-time 10 -fsS -X POST "$CP_URL/enroll/issue" -H 'content-type: application/json' \
      -d "{\"tenant\":\"$TENANT\"}" \
      | jq -r '.token // empty' 2>/dev/null
  )" || true
  [ -n "$TOKEN" ] || fail "could not mint a join token at $CP_URL/enroll/issue"
fi

# 2. Local echo origin (TCP), so the tunnelled payload comes back unchanged.
socat "TCP-LISTEN:${ORIGIN_PORT},reuseaddr,fork" EXEC:cat >/dev/null 2>&1 &
ORIGIN_PID=$!
for _ in $(seq 1 20); do
  nc -z 127.0.0.1 "$ORIGIN_PORT" >/dev/null 2>&1 && break
  kill -0 "$ORIGIN_PID" 2>/dev/null || fail "local echo origin exited early"
  sleep 0.25
done
nc -z 127.0.0.1 "$ORIGIN_PORT" >/dev/null 2>&1 \
  || fail "local echo origin did not become ready on 127.0.0.1:${ORIGIN_PORT}"

# 3. Onboard + run the agent (it registers and serves; writes the capability).
CT_AGENT_CP_URL="$CP_URL" CT_AGENT_JOIN_TOKEN="$TOKEN" CT_AGENT_ID="$AGENT_ID" \
CT_AGENT_EDGE="$EDGE" CT_AGENT_ORIGIN="127.0.0.1:${ORIGIN_PORT}" \
CT_AGENT_EDGE_CERT="$EDGE_CERT" CT_AGENT_CAPABILITY_OUT="$CAP" \
  "$BIN/ct-agent" onboard >"$WORK/agent.log" 2>&1 &
AGENT_PID=$!

# Wait for the agent to write its capability (enroll + register).
for _ in $(seq 1 60); do
  [ -s "$CAP" ] && break
  kill -0 "$AGENT_PID" 2>/dev/null || fail "agent exited early (see $WORK/agent.log): $(tail -n20 "$WORK/agent.log" 2>/dev/null)"
  sleep 0.5
done
[ -s "$CAP" ] || fail "agent did not register within 30s (see $WORK/agent.log): $(tail -n20 "$WORK/agent.log" 2>/dev/null)"

# 4. Run the client through the tunnel and read the round-trip result.
OUT="$(CT_CLIENT_CAPABILITY="$CAP" CT_CLIENT_EDGE_CERT="$EDGE_CERT" CT_CLIENT_PAYLOAD="$PAYLOAD" \
        "$BIN/ct-client" 2>&1)" || true
VIA="$(printf '%s' "$OUT" | sed -n 's/.*via=\([a-z]*\).*/\1/p' | head -1)"

if printf '%s' "$OUT" | grep -q "round-trip OK"; then
  echo "SMOKE OK via=${VIA:-unknown}"
  exit 0
fi
printf '%s\n' "$OUT" >&2
fail "no tunnel round-trip (agent log tail): $(tail -n20 "$WORK/agent.log" 2>/dev/null)"
