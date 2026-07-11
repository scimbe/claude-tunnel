#!/usr/bin/env bash
# M7.1 — build the thesis PDF inside a TeX Live container (docker-only).
# Builds a minimal TeX Live image once, then runs latexmk (which drives the
# pdflatex→biber→pdflatex passes). Output: docs/thesis/thesis.pdf
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "thesis: building TeX Live image (first run installs packages) ..."
docker build -q -f "$REPO_ROOT/docker/thesis.Dockerfile" -t ct-thesis "$REPO_ROOT/docker" >/dev/null

echo "thesis: compiling ..."
docker run --rm \
    -v "$REPO_ROOT/docs/thesis":/work -w /work \
    -u "$(id -u):$(id -g)" -e HOME=/tmp \
    ct-thesis \
    latexmk -pdf -interaction=nonstopmode -halt-on-error thesis.tex

echo "thesis: wrote docs/thesis/thesis.pdf"
