# Minimal, reproducible TeX Live for building the thesis (M7).
# Smaller and more controlled than the scheme-full texlive/texlive image:
# only the packages the scaffold needs (KOMA, biblatex+biber, ngerman, booktabs).
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        latexmk \
        biber \
        lmodern \
        texlive-latex-recommended \
        texlive-latex-extra \
        texlive-fonts-recommended \
        texlive-lang-german \
        texlive-bibtex-extra \
        texlive-science \
        texlive-pictures \
        texlive-fonts-extra \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
