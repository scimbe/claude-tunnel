#!/usr/bin/env sh
# Test-coverage gate (issue #21).
#
# Measures workspace line/function/region coverage inside the hermetic
# rust:1-slim container via cargo-llvm-cov, installing it into a persistent cargo
# cache on first run (subsequent runs reuse it). By default it measures LIBRARY
# code only: the thin main.rs / bin/* CLI entrypoints read 0% under `cargo test`
# — they are exercised by the shell smokes (e2e-smoke.sh, redundancy-smoke.sh,
# rotation-smoke.sh), not unit tests — so they are excluded from the denominator,
# matching the coverage scope decided for #20.
#
#   ./scripts/coverage.sh                        # lib-only summary + 95% line gate
#   COVERAGE_MIN=90 ./scripts/coverage.sh        # custom line threshold
#   COVERAGE_SCOPE=all ./scripts/coverage.sh     # include the entrypoints
#   COVERAGE_PKG=ct-agent ./scripts/coverage.sh  # a single crate
#
# Exit code: 0 if line coverage >= COVERAGE_MIN, non-zero otherwise (wire into CI
# as a coverage gate). Override the cache location with CT_CARGO_CACHE.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="${CT_CARGO_CACHE:-$HOME/.cache/ct-cargo}"
MIN="${COVERAGE_MIN:-95}"
SCOPE="${COVERAGE_SCOPE:-lib}"
PKG="${COVERAGE_PKG:-}"
mkdir -p "$CACHE"

# lib-only scope excludes the thin entrypoints from the coverage denominator.
IGNORE=""
[ "$SCOPE" = "lib" ] && IGNORE='--ignore-filename-regex (bin/|main\.rs)'
# Whole workspace unless a single package is requested.
SEL="--workspace"
[ -n "$PKG" ] && SEL="-p $PKG"

exec docker run --rm -v "$ROOT":/work -w /work -u "$(id -u):$(id -g)" \
  -v "$CACHE":/tmp/cargo \
  -e CARGO_HOME=/tmp/cargo -e HOME=/tmp \
  -e SEL="$SEL" -e IGNORE="$IGNORE" -e MIN="$MIN" rust:1-slim \
  sh -c '
    rustup component add llvm-tools-preview >/dev/null 2>&1 || true
    [ -x /tmp/cargo/bin/cargo-llvm-cov ] || cargo install cargo-llvm-cov --locked
    # Word-splitting on $SEL/$IGNORE is intentional (each holds flag+value, no spaces within).
    # shellcheck disable=SC2086
    cargo llvm-cov $SEL --summary-only --fail-under-lines "$MIN" $IGNORE
  '
