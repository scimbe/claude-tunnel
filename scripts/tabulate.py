#!/usr/bin/env python3
"""M6.4 / M16.4 — turn the netem sweep CSV into thesis result tables.

Reads the sweep CSV. The M16 CSV carries a leading ``mode`` column
(single/stream/udp) and the statistics columns ``stddev_ms``, ``ci95_ms``,
``p99_ms``; older M6 CSVs without them still work (mode defaults to "single",
missing stats render as "-"). Emits two tables, grouped by (mode, delay, loss):

  results-table.md   — GitHub-Markdown (for PROGRESS / review)
  results-table.tex  — LaTeX booktabs tabular (for the thesis, German headers)

Each row reports the mean plus the robust p50/p95 percentiles. The symmetric
normal 95% CI and the p99 are intentionally omitted (#52): the loss-regime
distributions are strongly right-skewed, so a symmetric mean +/- ci95 is
methodologically wrong (it can imply negative latency), and p99 at n=30 coincides
with the sample maximum and is not a stable quantile. Pure stdlib; run in a
python container.
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


def is_direct(r):
    return mode_of(r).startswith("direct-")


def cond_key(r):
    """The netem-condition key a tunnel row and its direct baseline share."""
    return (r.get("delay") or "", r.get("loss") or "", r.get("rate") or "")


def baseline_means(rows, baseline_mode):
    """Map netem condition → mean_ms for the chosen direct-baseline mode (#51 FF2).

    Returns {} when the baseline mode is absent, which disables the overhead
    column so tunnel-only CSVs render exactly as before.
    """
    out = {}
    for r in rows:
        if mode_of(r) == baseline_mode and r.get("mean_ms") not in (None, ""):
            out[cond_key(r)] = float(r["mean_ms"])
    return out


def overhead_cell(r, bmap, dash):
    """Overhead (ms) of a tunnel row vs. its direct baseline; `dash` otherwise
    (direct rows are the baseline itself; unmatched tunnel rows have no baseline)."""
    if is_direct(r):
        return dash
    base = bmap.get(cond_key(r))
    if base is None or r.get("mean_ms") in (None, ""):
        return dash
    return f"{float(r['mean_ms']) - base:.1f}"


def f1(r, k):
    v = r.get(k)
    return f"{float(v):.1f}" if v not in (None, "") else "-"


def write_md(rows, mode_col, rate_col, oh):
    head = (["Modus"] if mode_col else []) + ["Verzögerung", "Verlust"]
    if rate_col:
        head.append("Rate")
    head += ["n", "Mittel (ms)", "p50 (ms)", "p95 (ms)"]
    if oh:
        head.append("Overhead ggü. direkt (ms)")
    align = ["---"] * len(head)
    lines = ["| " + " | ".join(head) + " |", "| " + " | ".join(align) + " |"]
    for r in rows:
        cells = ([mode_of(r)] if mode_col else []) + [r["delay"] or "0ms", r["loss"] or "0%"]
        if rate_col:
            cells.append(r["rate"] or "—")
        cells += [r["n"], f1(r, "mean_ms"), f1(r, "p50_ms"), f1(r, "p95_ms")]
        if oh:
            cells.append(overhead_cell(r, oh[0], "—"))
        lines.append("| " + " | ".join(cells) + " |")
    with open(OUT_MD, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("tabulate: wrote", OUT_MD)


def tex_esc(s):
    return s.replace("%", r"\%").replace("_", r"\_")


def write_tex(rows, mode_col, rate_col, oh):
    cols = ("l" if mode_col else "") + "ll" + ("l" if rate_col else "") + "rrrr" + ("r" if oh else "")
    head = (["Modus"] if mode_col else []) + ["Verzögerung", "Verlust"]
    if rate_col:
        head.append("Rate")
    head += ["$n$", "Mittel", "p50", "p95"]
    if oh:
        head.append("Overhead")
    lead = 3 if rate_col else 2
    lead += 1 if mode_col else 0
    unit = [""] * lead + ["", "(ms)", "(ms)", "(ms)"] + (["(ms)"] if oh else [])
    caption = (
        r"Tunnel-Roundtrip-Latenz je Betriebsart unter emulierten "
        r"Netzbedingungen (\texttt{tc netem}); Median~(p50) und p95 als robuste "
        r"Tail-Metriken. Auf ein symmetrisches Normal-Konfidenzintervall wird wegen "
        r"der Rechtsschiefe der Verlustverteilungen verzichtet, und das p99 f\"allt "
        r"bei $n=30$ mit dem Stichprobenmaximum zusammen; beide werden nicht "
        r"berichtet."
    )
    if oh:
        caption += (
            r" Die Spalte \emph{Overhead} ist die Differenz des Mittels gegen\"uber "
            r"der direkten Verbindung (\texttt{" + tex_esc(oh[1]) + r"}) bei "
            r"gleicher Netzbedingung."
        )
    out = [
        r"\begin{table}[t]",
        r"  \centering",
        r"  \caption{" + caption + r"}",
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
        cells += [r["n"], f1(r, "mean_ms"), f1(r, "p50_ms"), f1(r, "p95_ms")]
        if oh:
            cells.append(overhead_cell(r, oh[0], "--"))
        out.append("    " + " & ".join(cells) + r" \\")
    out += [r"    \bottomrule", r"  \end{tabular}", r"\end{table}"]
    with open(OUT_TEX, "w") as f:
        f.write("\n".join(out) + "\n")
    print("tabulate: wrote", OUT_TEX)


def main():
    rows = load()
    mode_col = has_mode(rows)
    rate_col = has_rate(rows)
    # FF2 (#51): when direct-baseline rows are present, annotate tunnel rows with
    # their overhead vs. the chosen direct baseline (default direct-tcp). Absent
    # baseline rows → oh is None → output is byte-identical to a tunnel-only run.
    baseline_mode = os.environ.get("OVERHEAD_BASELINE", "direct-tcp")
    bmap = baseline_means(rows, baseline_mode)
    oh = (bmap, baseline_mode) if bmap and any(not is_direct(r) for r in rows) else None
    write_md(rows, mode_col, rate_col, oh)
    write_tex(rows, mode_col, rate_col, oh)


if __name__ == "__main__":
    main()
