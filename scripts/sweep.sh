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
#
# Direct-connection baseline for FF2 (#51) — same grid, no tunnel/edge hop, direct
# QUIC + direct TCP over the SAME netem path; emits mode=direct-tcp/direct-quic
# rows in the identical CSV format so tabulate.py diffs tunnel − baseline:
#   scripts/sweep.sh --baseline          # direct-tcp + direct-quic → latency-baseline.csv
#   SWEEP_APPEND=1 scripts/sweep.sh --baseline   # append baseline rows to latency.csv
#   SWEEP_BASELINE_PROTOS="tcp" SWEEP_DELAYS="20ms" SWEEP_LOSSES="0%" scripts/sweep.sh --baseline
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --baseline selects the direct-connection (no-tunnel) measurement path.
BASELINE=0
for arg in "$@"; do
    case "$arg" in
        --baseline) BASELINE=1 ;;
        *) echo "sweep: unknown arg '$arg'" >&2; exit 2 ;;
    esac
done

if [ "$BASELINE" = "1" ]; then
    COMPOSE=(docker compose -f "$REPO_ROOT/docker/docker-compose.baseline.yml")
else
    COMPOSE=(docker compose -f "$REPO_ROOT/docker/docker-compose.yml")
fi

# The baseline path defaults to its own file so it never clobbers tunnel rows;
# SWEEP_APPEND=1 instead appends into the (existing) tunnel CSV for a combined diff.
if [ "$BASELINE" = "1" ]; then
    OUT="${SWEEP_OUT:-$REPO_ROOT/docs/thesis/data/latency-baseline.csv}"
else
    OUT="${SWEEP_OUT:-$REPO_ROOT/docs/thesis/data/latency.csv}"
fi
ITER="${SWEEP_ITERATIONS:-30}"
# Space-separated matrix axes. An empty RATES axis means "unlimited bandwidth".
# MODES selects the client bench path: "single" (one-shot) or "stream"
# (full-duplex). "udp" needs its own overlay + bench variant (M16.2c).
MODES="${SWEEP_MODES:-single}"
POWS="${SWEEP_POWS:-8}"
DELAYS="${SWEEP_DELAYS:-0ms 20ms 50ms 100ms}"
LOSSES="${SWEEP_LOSSES:-0% 1% 5%}"
RATES="${SWEEP_RATES:-}"
# Baseline protocols: direct TCP (to the socat origin) and direct QUIC (to quic_echo).
BASELINE_PROTOS="${SWEEP_BASELINE_PROTOS:-tcp quic}"

# mode,pow prepended to the client's 12-column csv_row (delay..p99_ms).
HEADER="mode,pow,delay,loss,rate,n,mean_ms,min_ms,max_ms,p50_ms,p95_ms,stddev_ms,ci95_ms,p99_ms"

mkdir -p "$(dirname "$OUT")"
# Append mode keeps existing rows (e.g. tunnel rows) and reuses their header; a
# fresh run (or a missing file) writes the header first.
if [ "${SWEEP_APPEND:-0}" = "1" ] && [ -f "$OUT" ]; then
    echo "sweep: appending to existing $OUT"
else
    echo "$HEADER" > "$OUT"
fi

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

# One direct-baseline condition: same netem shaping on the server hop, no tunnel.
# Writes a row with mode=direct-<proto> and pow="-" (no PoW in the direct path).
run_baseline_condition() {
    local proto="$1" delay="$2" loss="$3" rate="$4"
    local target
    if [ "$proto" = "quic" ]; then target="10.5.0.2:4433"; else target="10.5.0.3:8080"; fi
    echo "sweep: baseline proto=$proto delay=${delay:-none} loss=${loss:-none} rate=${rate:-none} (${ITER} iters)"
    local out row
    out=$(DIRECT_PROTO="$proto" DIRECT_TARGET="$target" \
          EDGE_DELAY="$delay" EDGE_LOSS="$loss" EDGE_RATE="$rate" \
          CLIENT_ITERATIONS="$ITER" \
          "${COMPOSE[@]}" up --no-build --abort-on-container-exit --exit-code-from client 2>&1 || true)
    row=$(printf '%s\n' "$out" | grep -m1 'RESULT ' | sed 's/.*RESULT //' | tr -d '\r')
    "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
    if [ -n "$row" ]; then
        echo "direct-$proto,-,$row" >> "$OUT"
        echo "  -> direct-$proto,-,$row"
    else
        echo "  !! no RESULT row — condition failed, skipping"
    fi
}

if [ "$BASELINE" = "1" ]; then
    for proto in $BASELINE_PROTOS; do
        for delay in $DELAYS; do
            for loss in $LOSSES; do
                if [ -z "$RATES" ]; then
                    run_baseline_condition "$proto" "$delay" "$loss" ""
                else
                    for rate in $RATES; do
                        run_baseline_condition "$proto" "$delay" "$loss" "$rate"
                    done
                fi
            done
        done
    done
else
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
fi

echo "sweep: wrote $(( $(wc -l < "$OUT") - 1 )) rows to $OUT"
