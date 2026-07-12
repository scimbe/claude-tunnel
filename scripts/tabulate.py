#!/usr/bin/env python3
"""M6.4 / M16.4 — turn the netem sweep CSV into thesis result tables.

Reads the sweep CSV. The M16 CSV carries a leading ``mode`` column
(single/stream/udp) and the statistics columns ``stddev_ms``, ``ci95_ms``,
``p99_ms``; older M6 CSVs without them still work (mode defaults to "single",
missing stats render as "-"). Emits two tables, grouped by (mode, delay, loss):

  results-table.md   — GitHub-Markdown (for PROGRESS / review)
  results-table.tex  — LaTeX booktabs tabular (for the thesis, German headers)

Each row reports the mean with its 95% confidence interval (mean +/- ci95) plus
the p50/p95/p99 percentiles. Pure stdlib; run inside a python container.
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


def mode_of(r):
    return (r.get("mode") or "single").strip() or "single"


def load():
    with open(CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    rows.sort(key=lambda r: (mode_of(r), num(r["delay"]), num(r["loss"]), num(r["rate"])))
    return rows


def has_rate(rows):
    return any((r.get("rate") or "").strip() for r in rows)


def has_mode(rows):
    return any((r.get("mode") or "").strip() for r in rows)


def f1(r, k):
    v = r.get(k)
    return f"{float(v):.1f}" if v not in (None, "") else "-"


def mean_ci(r):
    """'mean +/- ci95' when the CI is present, else just the mean."""
    m = f1(r, "mean_ms")
    ci = r.get("ci95_ms")
    return f"{m} +/- {float(ci):.1f}" if ci not in (None, "") else m


def write_md(rows, mode_col, rate_col):
    head = (["Modus"] if mode_col else []) + ["Verzögerung", "Verlust"]
    if rate_col:
        head.append("Rate")
    head += ["n", "Mittel±KI (ms)", "p50 (ms)", "p95 (ms)", "p99 (ms)"]
    align = ["---"] * len(head)
    lines = ["| " + " | ".join(head) + " |", "| " + " | ".join(align) + " |"]
    for r in rows:
        cells = ([mode_of(r)] if mode_col else []) + [r["delay"] or "0ms", r["loss"] or "0%"]
        if rate_col:
            cells.append(r["rate"] or "—")
        cells += [r["n"], mean_ci(r), f1(r, "p50_ms"), f1(r, "p95_ms"), f1(r, "p99_ms")]
        lines.append("| " + " | ".join(cells) + " |")
    with open(OUT_MD, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("tabulate: wrote", OUT_MD)


def tex_esc(s):
    return s.replace("%", r"\%").replace("_", r"\_")


def tex_mean_ci(r):
    m = f1(r, "mean_ms")
    ci = r.get("ci95_ms")
    return f"{m} $\\pm$ {float(ci):.1f}" if ci not in (None, "") else m


def write_tex(rows, mode_col, rate_col):
    cols = ("l" if mode_col else "") + "ll" + ("l" if rate_col else "") + "rrrrr"
    head = (["Modus"] if mode_col else []) + ["Verzögerung", "Verlust"]
    if rate_col:
        head.append("Rate")
    head += ["$n$", r"Mittel $\pm$ KI", "p50", "p95", "p99"]
    lead = 3 if rate_col else 2
    lead += 1 if mode_col else 0
    unit = [""] * lead + ["", "(ms)", "(ms)", "(ms)", "(ms)"]
    out = [
        r"\begin{table}[t]",
        r"  \centering",
        r"  \caption{Tunnel-Roundtrip-Latenz je Betriebsart unter emulierten "
        r"Netzbedingungen (\texttt{tc netem}); Mittel mit 95\%-Konfidenzintervall.}",
        r"  \label{tab:latency}",
        r"  \begin{tabular}{" + cols + "}",
        r"    \toprule",
        "    " + " & ".join(head) + r" \\",
        "    " + " & ".join(unit) + r" \\",
        r"    \midrule",
    ]
    for r in rows:
        cells = ([tex_esc(mode_of(r))] if mode_col else [])
        cells += [tex_esc(r["delay"] or "0ms"), tex_esc(r["loss"] or "0%")]
        if rate_col:
            cells.append(tex_esc(r["rate"] or "--"))
        cells += [r["n"], tex_mean_ci(r), f1(r, "p50_ms"), f1(r, "p95_ms"), f1(r, "p99_ms")]
        out.append("    " + " & ".join(cells) + r" \\")
    out += [r"    \bottomrule", r"  \end{tabular}", r"\end{table}"]
    with open(OUT_TEX, "w") as f:
        f.write("\n".join(out) + "\n")
    print("tabulate: wrote", OUT_TEX)


def main():
    rows = load()
    mode_col = has_mode(rows)
    rate_col = has_rate(rows)
    write_md(rows, mode_col, rate_col)
    write_tex(rows, mode_col, rate_col)


if __name__ == "__main__":
    main()
