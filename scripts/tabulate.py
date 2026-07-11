#!/usr/bin/env python3
"""M6.4 — turn the netem sweep CSV into thesis result tables.

Reads the sweep CSV (delay,loss,rate,n,mean_ms,min_ms,max_ms,p50_ms,p95_ms) and
emits two tables, sorted by (delay, loss):
  results-table.md   — GitHub-Markdown (for PROGRESS / review)
  results-table.tex  — LaTeX booktabs tabular (for the thesis, German headers)

Pure stdlib; run inside a python container via scripts/plot.sh's image (no deps).
"""
import csv
import os
import re

CSV = os.environ.get("TABLE_CSV", "docs/thesis/data/latency.csv")
OUT_MD = os.environ.get("TABLE_MD", "docs/thesis/data/results-table.md")
OUT_TEX = os.environ.get("TABLE_TEX", "docs/thesis/data/results-table.tex")


def num(s):
    m = re.match(r"\s*([\d.]+)", s or "")
    return float(m.group(1)) if m else 0.0


def load():
    with open(CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    rows.sort(key=lambda r: (num(r["delay"]), num(r["loss"]), num(r["rate"])))
    return rows


def has_rate(rows):
    return any((r.get("rate") or "").strip() for r in rows)


def fmt(r, k):
    return f"{float(r[k]):.1f}"


def write_md(rows, rate_col):
    head = ["Verzögerung", "Verlust"]
    if rate_col:
        head.append("Rate")
    head += ["n", "Mittel (ms)", "p50 (ms)", "p95 (ms)", "Min (ms)", "Max (ms)"]
    align = ["---"] * len(head)
    lines = ["| " + " | ".join(head) + " |", "| " + " | ".join(align) + " |"]
    for r in rows:
        cells = [r["delay"] or "0ms", r["loss"] or "0%"]
        if rate_col:
            cells.append(r["rate"] or "—")
        cells += [r["n"], fmt(r, "mean_ms"), fmt(r, "p50_ms"),
                  fmt(r, "p95_ms"), fmt(r, "min_ms"), fmt(r, "max_ms")]
        lines.append("| " + " | ".join(cells) + " |")
    with open(OUT_MD, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("tabulate: wrote", OUT_MD)


def tex_esc(s):
    return s.replace("%", r"\%").replace("_", r"\_")


def write_tex(rows, rate_col):
    cols = "ll" + ("l" if rate_col else "") + "rrrrrr"
    head = ["Verzögerung", "Verlust"]
    if rate_col:
        head.append("Rate")
    head += ["$n$", "Mittel", "p50", "p95", "Min", "Max"]
    unit = [""] * (3 if rate_col else 2) + ["", "(ms)", "(ms)", "(ms)", "(ms)", "(ms)"]
    out = [
        r"\begin{table}[t]",
        r"  \centering",
        r"  \caption{Tunnel-Roundtrip-Latenz unter emulierten Netzbedingungen (\texttt{tc netem}).}",
        r"  \label{tab:latency}",
        r"  \begin{tabular}{" + cols + "}",
        r"    \toprule",
        "    " + " & ".join(tex_esc(h) for h in head) + r" \\",
        "    " + " & ".join(unit) + r" \\",
        r"    \midrule",
    ]
    for r in rows:
        cells = [tex_esc(r["delay"] or "0ms"), tex_esc(r["loss"] or "0%")]
        if rate_col:
            cells.append(tex_esc(r["rate"] or "--"))
        cells += [r["n"], fmt(r, "mean_ms"), fmt(r, "p50_ms"),
                  fmt(r, "p95_ms"), fmt(r, "min_ms"), fmt(r, "max_ms")]
        out.append("    " + " & ".join(cells) + r" \\")
    out += [r"    \bottomrule", r"  \end{tabular}", r"\end{table}"]
    with open(OUT_TEX, "w") as f:
        f.write("\n".join(out) + "\n")
    print("tabulate: wrote", OUT_TEX)


def main():
    rows = load()
    rate_col = has_rate(rows)
    write_md(rows, rate_col)
    write_tex(rows, rate_col)


if __name__ == "__main__":
    main()
