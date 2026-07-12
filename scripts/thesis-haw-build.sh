#!/usr/bin/env bash
# M17.1 — build the HAW-template-based thesis PDF inside the TeX Live container
# (docker-only). The official HAW style (docs/thesis/haw-template/.../style) uses
# classic BibTeX (dinat) + the glossaries package, so the sequence is
# pdflatex -> bibtex -> makeglossaries -> pdflatex -> pdflatex.
#
# Output: docs/thesis/haw-template/template-latex_thesis/ct_thesis/thesis.pdf
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TROOT="$REPO_ROOT/docs/thesis/haw-template/template-latex_thesis"

echo "thesis-haw: building TeX Live image (first run installs packages) ..."
docker build -q -f "$REPO_ROOT/docker/thesis.Dockerfile" -t ct-thesis "$REPO_ROOT/docker" >/dev/null

echo "thesis-haw: compiling ct_thesis ..."
docker run --rm \
    -v "$TROOT":/work -w /work/ct_thesis \
    -u "$(id -u):$(id -g)" -e HOME=/tmp \
    ct-thesis \
    sh -c 'set -e; \
        pdflatex -interaction=nonstopmode thesis.tex >/tmp/p1.log 2>&1 || true; \
        bibtex thesis >/tmp/bib.log 2>&1 || true; \
        makeglossaries thesis >/tmp/gls.log 2>&1 || true; \
        pdflatex -interaction=nonstopmode thesis.tex >/tmp/p2.log 2>&1 || true; \
        pdflatex -interaction=nonstopmode thesis.tex >/tmp/p3.log 2>&1; \
        echo "--- undefined refs/citations ---"; \
        grep -iE "undefined (reference|citation)|LaTeX Warning: Reference" thesis.log | sort -u | head; \
        echo "--- errors ---"; \
        grep -iE "^! |Fatal error|Emergency stop" thesis.log | head; \
        echo "--- output ---"; \
        grep -oE "Output written on thesis.pdf \([0-9]+ page" thesis.log | head -1; \
        test -f thesis.pdf && echo "PDF_OK"'

echo "thesis-haw: wrote $TROOT/ct_thesis/thesis.pdf"
