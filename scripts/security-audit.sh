#!/usr/bin/env sh
# Dependency vulnerability audit (M23.2).
#
# Runs cargo-audit against the committed Cargo.lock inside the hermetic
# rust:1-slim container, installing cargo-audit into a persistent cargo cache on
# first run (subsequent runs reuse it). The advisory database is fetched fresh
# from RustSec each run. The exit code is cargo-audit's own: 0 = clean, non-zero
# = advisories found (wire this into CI to fail the build on new advisories).
#
#   ./scripts/security-audit.sh
#
# Override the cache location with CT_CARGO_CACHE.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="${CT_CARGO_CACHE:-$HOME/.cache/ct-cargo}"
mkdir -p "$CACHE"

exec docker run --rm -v "$ROOT":/work -w /work -u "$(id -u):$(id -g)" \
  -v "$CACHE":/tmp/cargo \
  -e CARGO_HOME=/tmp/cargo -e HOME=/tmp rust:1-slim \
  sh -c '
    if [ ! -x /tmp/cargo/bin/cargo-audit ]; then
      cargo install cargo-audit --locked
    fi
    cargo audit
  '
