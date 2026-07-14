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
CAP="$WORK/capability.bin"

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }
cleanup() {
  [ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null || true
  [ -n "${ORIGIN_PID:-}" ] && kill "$ORIGIN_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# Preconditions.
[ -f "$EDGE_CERT" ] || fail "edge cert not found at EDGE_CERT=$EDGE_CERT"
[ -x "$BIN/ct-agent" ] && [ -x "$BIN/ct-client" ] \
  || fail "binaries not built (expected $BIN/ct-agent and $BIN/ct-client) — build the workspace first"
command -v socat >/dev/null || fail "socat is required for the echo origin (apt-get install socat)"
command -v curl >/dev/null || fail "curl is required"

# 1. Join token — use CT_JOIN_TOKEN or mint one from the control plane.
TOKEN="${CT_JOIN_TOKEN:-}"
if [ -z "$TOKEN" ]; then
  TOKEN="$(curl -fsS -X POST "$CP_URL/enroll/issue" -H 'content-type: application/json' \
             -d "{\"tenant\":\"$TENANT\"}" \
           | sed -n 's/.*"token":"\([0-9a-f]\{64\}\)".*/\1/p')" || true
  [ -n "$TOKEN" ] || fail "could not mint a join token at $CP_URL/enroll/issue"
fi

# 2. Local echo origin (TCP), so the tunnelled payload comes back unchanged.
socat "TCP-LISTEN:${ORIGIN_PORT},reuseaddr,fork" EXEC:cat >/dev/null 2>&1 &
ORIGIN_PID=$!
sleep 1

# 3. Onboard + run the agent (it registers and serves; writes the capability).
CT_AGENT_CP_URL="$CP_URL" CT_AGENT_JOIN_TOKEN="$TOKEN" CT_AGENT_ID="$AGENT_ID" \
CT_AGENT_EDGE="$EDGE" CT_AGENT_ORIGIN="127.0.0.1:${ORIGIN_PORT}" \
CT_AGENT_EDGE_CERT="$EDGE_CERT" CT_AGENT_CAPABILITY_OUT="$CAP" \
  "$BIN/ct-agent" onboard >"$WORK/agent.log" 2>&1 &
AGENT_PID=$!

# Wait for the agent to write its capability (enroll + register).
for _ in $(seq 1 30); do [ -s "$CAP" ] && break; sleep 0.5; done
[ -s "$CAP" ] || fail "agent did not register within 15s (see $WORK/agent.log): $(tail -n2 "$WORK/agent.log" 2>/dev/null)"

# 4. Run the client through the tunnel and read the round-trip result.
OUT="$(CT_CLIENT_CAPABILITY="$CAP" CT_CLIENT_EDGE_CERT="$EDGE_CERT" CT_CLIENT_PAYLOAD="$PAYLOAD" \
        "$BIN/ct-client" 2>&1)" || true
VIA="$(printf '%s' "$OUT" | sed -n 's/.*via=\([a-z]*\).*/\1/p' | head -1)"

if printf '%s' "$OUT" | grep -q "round-trip OK"; then
  echo "SMOKE OK via=${VIA:-unknown}"
  exit 0
fi
printf '%s\n' "$OUT" >&2
fail "no tunnel round-trip (agent log: $WORK/agent.log)"
