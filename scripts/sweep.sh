#!/usr/bin/env bash
# M6.2 — netem sweep.
#
# Runs the Docker testbed across a delay/loss/bandwidth matrix, collecting the
# tunnel round-trip latency stats (emitted by ct-client bench mode as a
# "RESULT <csv_row>" line) into a CSV for the thesis evaluation (M6).
#
# The image is built once; link impairment is applied at runtime via the
# EDGE_{DELAY,LOSS,RATE} env (netem-entrypoint.sh), so no rebuild per condition.
#
# Usage:
#   scripts/sweep.sh                     # default matrix → docs/thesis/data/latency.csv
#   SWEEP_ITERATIONS=50 scripts/sweep.sh
#   SWEEP_DELAYS="0ms 50ms" SWEEP_LOSSES="0% 2%" SWEEP_RATES="10mbit" scripts/sweep.sh
#   SWEEP_OUT=/tmp/x.csv SWEEP_DELAYS="20ms" SWEEP_LOSSES="0%" scripts/sweep.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$REPO_ROOT/docker/docker-compose.yml")

OUT="${SWEEP_OUT:-$REPO_ROOT/docs/thesis/data/latency.csv}"
ITER="${SWEEP_ITERATIONS:-20}"
# Space-separated matrix axes. An empty RATES axis means "unlimited bandwidth".
DELAYS="${SWEEP_DELAYS:-0ms 20ms 50ms 100ms}"
LOSSES="${SWEEP_LOSSES:-0% 1% 5%}"
RATES="${SWEEP_RATES:-}"

HEADER="delay,loss,rate,n,mean_ms,min_ms,max_ms,p50_ms,p95_ms"

mkdir -p "$(dirname "$OUT")"
echo "$HEADER" > "$OUT"

echo "sweep: building testbed image ..."
"${COMPOSE[@]}" build >/dev/null

run_condition() {
    local delay="$1" loss="$2" rate="$3"
    echo "sweep: delay=${delay:-none} loss=${loss:-none} rate=${rate:-none} (${ITER} iters)"
    local out row
    out=$(EDGE_DELAY="$delay" EDGE_LOSS="$loss" EDGE_RATE="$rate" CLIENT_ITERATIONS="$ITER" \
          "${COMPOSE[@]}" up --no-build --abort-on-container-exit --exit-code-from client 2>&1 || true)
    row=$(printf '%s\n' "$out" | grep -m1 'RESULT ' | sed 's/.*RESULT //' | tr -d '\r')
    "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
    if [ -n "$row" ]; then
        echo "$row" >> "$OUT"
        echo "  -> $row"
    else
        echo "  !! no RESULT row — condition failed, skipping"
    fi
}

for delay in $DELAYS; do
    for loss in $LOSSES; do
        if [ -z "$RATES" ]; then
            run_condition "$delay" "$loss" ""
        else
            for rate in $RATES; do
                run_condition "$delay" "$loss" "$rate"
            done
        fi
    done
done

echo "sweep: wrote $(( $(wc -l < "$OUT") - 1 )) rows to $OUT"
