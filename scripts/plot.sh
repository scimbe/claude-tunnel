#!/usr/bin/env bash
# M6.3 — render the thesis figures from the sweep CSV inside a python container
# (no host install; docker-only per the workspace rules).
#
# Usage:
#   scripts/plot.sh                                  # docs/thesis/data/latency.csv
#   PLOT_CSV=docs/thesis/data/other.csv scripts/plot.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CSV="${PLOT_CSV:-docs/thesis/data/latency.csv}"

exec docker run --rm \
    -v "$REPO_ROOT":/work -w /work \
    -u "$(id -u):$(id -g)" \
    -e HOME=/tmp -e MPLCONFIGDIR=/tmp/mpl \
    -e PYTHONUSERBASE=/tmp/py -e PIP_CACHE_DIR=/tmp/pipcache \
    -e PLOT_CSV="$CSV" \
    python:3-slim \
    sh -c "pip install --user --quiet --disable-pip-version-check matplotlib >/dev/null && python scripts/plot.py"
