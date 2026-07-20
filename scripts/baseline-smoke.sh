#!/usr/bin/env bash
# Direct-baseline compose smoke (#51 FF2 harness). Brings up the direct-connection
# baseline testbed (docker-compose.baseline.yml) over a small netem delay and, for
# BOTH direct TCP and direct QUIC, asserts the client emitted a well-formed
# `RESULT <csv_row>` latency sample — non-empty, 12 columns, positive mean — and
# that scripts/tabulate.py parses the emitted rows (prepended with mode,pow as the
# sweep does) into a results table, exercising the overhead column.
#
# This verifies the HARNESS, not the science: the few-iteration numbers it prints
# are smoke sanity values, NOT a thesis result. The real FF2 baseline is the full
# `SWEEP_APPEND=1 scripts/sweep.sh --baseline` run the author performs.
#
#   scripts/baseline-smoke.sh
#
# Prereqs: docker + compose (BuildKit for the cached image build).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$REPO_ROOT/docker/docker-compose.baseline.yml")
DELAY="${SMOKE_DELAY:-20ms}"
ITER="${SMOKE_ITERATIONS:-5}"

ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31mBASELINE SMOKE FAIL: %s\033[0m\n' "$*" >&2; "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true; exit 1; }

W="$(umask 077 && mktemp -d)"
cleanup() { "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT

command -v docker >/dev/null || fail "docker required"

# One direct-baseline condition → the client's RESULT csv_row (12 columns).
run_proto() {  # $1=proto $2=target
    local proto="$1" target="$2" out row
    out=$(DIRECT_PROTO="$proto" DIRECT_TARGET="$target" \
          EDGE_DELAY="$DELAY" CLIENT_ITERATIONS="$ITER" \
          "${COMPOSE[@]}" up --no-build --abort-on-container-exit --exit-code-from client 2>&1 || true)
    row=$(printf '%s\n' "$out" | grep -m1 'RESULT ' | sed 's/.*RESULT //' | tr -d '\r')
    "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
    [ -n "$row" ] || { printf '%s\n' "$out" | tail -20 >&2; fail "$proto: no RESULT row emitted"; }
    local ncol; ncol=$(printf '%s' "$row" | awk -F, '{print NF}')
    [ "$ncol" = "12" ] || fail "$proto: expected 12 columns, got $ncol ($row)"
    # mean_ms is column 5 (delay,loss,rate,n,mean_ms,...); must be a positive number.
    local mean; mean=$(printf '%s' "$row" | cut -d, -f5)
    awk -v m="$mean" 'BEGIN{exit !(m+0>0)}' || fail "$proto: mean_ms not positive ($row)"
    ok "$proto: well-formed RESULT (n=$(printf '%s' "$row" | cut -d, -f4), mean_ms=$mean over $DELAY netem) [SMOKE VALUE, not a thesis result]"
    printf '%s\n' "direct-$proto,-,$row" >> "$W/rows.csv"
}

step "Building baseline testbed image (release; cached after first run) ..."
"${COMPOSE[@]}" build >/dev/null
ok "Image built."

step "Direct TCP baseline over $DELAY netem ($ITER iters)"
run_proto tcp 10.5.0.3:8080

step "Direct QUIC baseline over $DELAY netem ($ITER iters)"
run_proto quic 10.5.0.2:4433

step "Asserting the emitted rows parse through tabulate.py (with overhead column)"
# Prepend the sweep header + a smoke tunnel row so the overhead column is exercised.
{
  echo "mode,pow,delay,loss,rate,n,mean_ms,min_ms,max_ms,p50_ms,p95_ms,stddev_ms,ci95_ms,p99_ms"
  # A synthetic tunnel row (SMOKE VALUE, not a measurement) so tabulate has a row
  # to annotate with overhead vs. the real direct-tcp baseline just measured.
  echo "single,8,$DELAY,,,${ITER},999.000,999.000,999.000,999.000,999.000,0.000,0.000,999.000"
  cat "$W/rows.csv"
} > "$W/combined.csv"
TABLE_CSV="$W/combined.csv" TABLE_MD="$W/out.md" TABLE_TEX="$W/out.tex" python3 "$REPO_ROOT/scripts/tabulate.py" >/dev/null \
    || fail "tabulate.py failed to parse the emitted baseline rows"
grep -q "Overhead" "$W/out.md" || fail "tabulate.py did not emit an overhead column for the baseline rows"
ok "tabulate.py parsed the baseline rows and produced the overhead column."

printf '\n\033[1;32mBASELINE SMOKE OK — direct-tcp + direct-quic emit well-formed, tabulate-parseable rows.\033[0m\n'
