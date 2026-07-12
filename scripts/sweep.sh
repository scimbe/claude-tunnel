#!/usr/bin/env bash
# M6.2 / M16.2 — netem parameter sweep.
#
# Runs the Docker testbed across a PoW-difficulty × delay × loss × bandwidth
# matrix, collecting the tunnel round-trip latency stats (emitted by ct-client
# bench mode as a "RESULT <csv_row>" line) into a CSV for the thesis evaluation.
# The client's csv_row carries the M16 statistics (stddev, 95% CI, p99); this
# script prepends the PoW-difficulty axis it varied.
#
# The image is built once; link impairment and PoW difficulty are applied at
# runtime via env (netem-entrypoint.sh + EDGE_POW_DIFFICULTY), so there is no
# rebuild per condition.
#
# Usage:
#   scripts/sweep.sh                     # default matrix → docs/thesis/data/latency.csv
#   SWEEP_ITERATIONS=100 scripts/sweep.sh
#   SWEEP_POWS="8 16 20" scripts/sweep.sh                 # PoW-difficulty study
#   SWEEP_DELAYS="0ms 50ms" SWEEP_LOSSES="0% 2%" SWEEP_RATES="10mbit" scripts/sweep.sh
#   SWEEP_OUT=/tmp/x.csv SWEEP_DELAYS="20ms" SWEEP_LOSSES="0%" scripts/sweep.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$REPO_ROOT/docker/docker-compose.yml")

OUT="${SWEEP_OUT:-$REPO_ROOT/docs/thesis/data/latency.csv}"
ITER="${SWEEP_ITERATIONS:-30}"
# Space-separated matrix axes. An empty RATES axis means "unlimited bandwidth".
# MODES selects the client bench path: "single" (one-shot) or "stream"
# (full-duplex). "udp" needs its own overlay + bench variant (M16.2c).
MODES="${SWEEP_MODES:-single}"
POWS="${SWEEP_POWS:-8}"
DELAYS="${SWEEP_DELAYS:-0ms 20ms 50ms 100ms}"
LOSSES="${SWEEP_LOSSES:-0% 1% 5%}"
RATES="${SWEEP_RATES:-}"

# mode,pow prepended to the client's 12-column csv_row (delay..p99_ms).
HEADER="mode,pow,delay,loss,rate,n,mean_ms,min_ms,max_ms,p50_ms,p95_ms,stddev_ms,ci95_ms,p99_ms"

mkdir -p "$(dirname "$OUT")"
echo "$HEADER" > "$OUT"

echo "sweep: building testbed image ..."
"${COMPOSE[@]}" build >/dev/null

run_condition() {
    local mode="$1" pow="$2" delay="$3" loss="$4" rate="$5"
    echo "sweep: mode=$mode pow=$pow delay=${delay:-none} loss=${loss:-none} rate=${rate:-none} (${ITER} iters)"
    # UDP mode needs the fixed-port echo Origin + agent-in-UDP overlay.
    local compose=("${COMPOSE[@]}")
    if [ "$mode" = "udp" ]; then
        compose+=(-f "$REPO_ROOT/docker/docker-compose.udpbench.yml")
    fi
    local out row
    out=$(BENCH_MODE="$mode" EDGE_POW_DIFFICULTY="$pow" \
          EDGE_DELAY="$delay" EDGE_LOSS="$loss" EDGE_RATE="$rate" \
          CLIENT_ITERATIONS="$ITER" \
          "${compose[@]}" up --no-build --abort-on-container-exit --exit-code-from client 2>&1 || true)
    row=$(printf '%s\n' "$out" | grep -m1 'RESULT ' | sed 's/.*RESULT //' | tr -d '\r')
    "${compose[@]}" down -v >/dev/null 2>&1 || true
    if [ -n "$row" ]; then
        echo "$mode,$pow,$row" >> "$OUT"
        echo "  -> $mode,$pow,$row"
    else
        echo "  !! no RESULT row — condition failed, skipping"
    fi
}

for mode in $MODES; do
    for pow in $POWS; do
        for delay in $DELAYS; do
            for loss in $LOSSES; do
                if [ -z "$RATES" ]; then
                    run_condition "$mode" "$pow" "$delay" "$loss" ""
                else
                    for rate in $RATES; do
                        run_condition "$mode" "$pow" "$delay" "$loss" "$rate"
                    done
                fi
            done
        done
    done
done

echo "sweep: wrote $(( $(wc -l < "$OUT") - 1 )) rows to $OUT"
