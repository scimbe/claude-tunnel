#!/usr/bin/env bash
# provision-agents.sh (#145 Gap 2) — bulk-provision N agents in one command.
#
# Turns "provision N agents" from N rounds of manual work into a single control-plane call plus N
# ready-to-run agent env blocks. Mints COUNT single-use join tokens via the batch endpoint
# (`POST /enroll/issue-batch`, #145) and emits one runnable `ct-agent onboard` block per token, each
# with a distinct agent id + its own restart-safe state dir (#141).
#
# This covers the join-token + agent-config half of provisioning. Bulk **Keycloak account** creation
# is a separate step (blocked on no-SMTP → the admin-API path) and NOT done here; the multi-host
# capacity ceiling (#145 Gap 1) is likewise out of scope.
#
#   COUNT=25 TENANT=acme CP_URL=http://127.0.0.1:8090 CT_CP_EDGE_ADMIN_TOKEN=<hex> \
#     ./scripts/provision-agents.sh > agents.env
#
# Env:
#   COUNT                   required — how many agents to provision (1..=100, the endpoint's cap)
#   TENANT                  required — tenant the agents enrol under
#   CP_URL                  control-plane URL         (default http://127.0.0.1:8090)
#   CT_CP_EDGE_ADMIN_TOKEN  admin token gating issuance (#87); required if the CP is gated
#   ID_PREFIX               agent id prefix           (default "agent" → agent-0, agent-1, …)
#   EDGE                    edge host:port            (default 127.0.0.1:4433)
#   STATE_BASE              base dir for per-agent CT_AGENT_STATE_DIR (default /var/lib/ct-agent)
#
#   ./scripts/provision-agents.sh --selftest   # exercise the emission logic offline (no CP)
set -euo pipefail

die() { printf 'provision-agents: %s\n' "$*" >&2; exit 1; }

# Emit one ready-to-run agent env block per token read from stdin (one 64-hex token per line).
# Args: <prefix> <cp_url> <edge> <state_base>. Pure (no network) — this is what --selftest exercises.
emit_blocks() {
  local prefix="$1" cp="$2" edge="$3" state_base="$4" i=0 token
  while read -r token; do
    [ -n "$token" ] || continue
    printf '# agent %s-%s\n' "$prefix" "$i"
    printf 'CT_AGENT_CP_URL=%s CT_AGENT_JOIN_TOKEN=%s CT_AGENT_ID=%s-%s CT_AGENT_EDGE=%s CT_AGENT_STATE_DIR=%s/%s-%s ct-agent onboard\n\n' \
      "$cp" "$token" "$prefix" "$i" "$edge" "$state_base" "$prefix" "$i"
    i=$((i + 1))
  done
}

if [ "${1:-}" = "--selftest" ]; then
  # Emission logic only (no CP): three fake tokens → three distinct blocks, distinct ids + tokens.
  t0="$(printf 'aa%.0s' $(seq 1 32))"
  t1="$(printf 'bb%.0s' $(seq 1 32))"
  t2="$(printf 'cc%.0s' $(seq 1 32))"
  out="$(printf '%s\n%s\n%s\n' "$t0" "$t1" "$t2" | emit_blocks demo http://cp:8090 edge:4433 /var/lib/ct-agent)"
  [ "$(printf '%s\n' "$out" | grep -c '^# agent demo-')" -eq 3 ] || die "selftest: expected 3 agent blocks"
  printf '%s\n' "$out" | grep -q "CT_AGENT_ID=demo-0 " || die "selftest: demo-0 block missing"
  printf '%s\n' "$out" | grep -q "CT_AGENT_ID=demo-2 " || die "selftest: demo-2 block missing"
  printf '%s\n' "$out" | grep -q "CT_AGENT_JOIN_TOKEN=$t0 " || die "selftest: token 0 not placed in its block"
  printf '%s\n' "$out" | grep -q "CT_AGENT_STATE_DIR=/var/lib/ct-agent/demo-1 " || die "selftest: per-agent state dir missing"
  echo "provision-agents: selftest OK (3 distinct runnable blocks emitted)"
  exit 0
fi

COUNT="${COUNT:-}"
TENANT="${TENANT:-}"
CP_URL="${CP_URL:-http://127.0.0.1:8090}"
ADMIN_TOKEN="${CT_CP_EDGE_ADMIN_TOKEN:-}"
ID_PREFIX="${ID_PREFIX:-agent}"
EDGE="${EDGE:-127.0.0.1:4433}"
STATE_BASE="${STATE_BASE:-/var/lib/ct-agent}"

[ -n "$COUNT" ] || die "COUNT is required (how many agents to provision, 1..=100)"
[ -n "$TENANT" ] || die "TENANT is required"
command -v curl >/dev/null || die "curl not found"

# Mint COUNT single-use join tokens in ONE admin call (#145 /enroll/issue-batch). The admin-token
# header (#87) is presented when set; an ungated dev CP ignores it, a gated one requires it.
resp="$(curl -fsS -X POST "$CP_URL/enroll/issue-batch" \
  -H 'content-type: application/json' \
  -H "x-ct-admin-token: $ADMIN_TOKEN" \
  -d "{\"tenant\":\"$TENANT\",\"count\":$COUNT}")" \
  || die "batch mint failed at $CP_URL/enroll/issue-batch (if gated per #87, set CT_CP_EDGE_ADMIN_TOKEN; count must be 1..=100)"

# Extract the 64-hex tokens from the JSON {"tokens":[...]} and emit one runnable agent block each.
tokens="$(printf '%s\n' "$resp" | grep -oE '[0-9a-f]{64}' || true)"
[ -n "$tokens" ] || die "no tokens in the batch response: $resp"
printf '%s\n' "$tokens" | emit_blocks "$ID_PREFIX" "$CP_URL" "$EDGE" "$STATE_BASE"
