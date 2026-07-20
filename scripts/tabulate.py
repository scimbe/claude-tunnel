#!/usr/bin/env python3
"""M6.4 / M16.4 — turn the netem sweep CSV into thesis result tables.

Reads the sweep CSV. The M16 CSV carries a leading ``mode`` column
(single/stream/udp) and the statistics columns ``stddev_ms``, ``ci95_ms``,
``p99_ms``; older M6 CSVs without them still work (mode defaults to "single",
missing stats render as "-"). Emits two tables, grouped by (mode, delay, loss):

  results-table.md   — GitHub-Markdown (for PROGRESS / review)
  results-table.tex  — LaTeX booktabs tabular (for the thesis, German headers)

Each row reports the mean plus the robust p50/p95 percentiles. Instead of the
symmetric normal 95% CI (which is methodologically wrong on the strongly
right-skewed loss-regime distributions — a mean +/- 1.96*sigma/sqrt(n) interval
can dip below zero), we report a **bootstrap-percentile 95% CI for the mean**
(#52): resample the raw per-iteration latencies with replacement, and take the
2.5/97.5 percentiles of the resampled means. This needs the raw samples, carried
by the CSV's trailing ``samples_ms`` column; when that column is absent (older
tunnel-only CSVs) the CI columns degrade away and the table renders as before.
The p99 stays omitted: at n=30 it coincides with the sample maximum and is not a
stable quantile.

The bootstrap uses a FIXED seed (``BOOTSTRAP_SEED``) so the reported interval is
reproducible. Pure stdlib (``random`` for the resampling); run in a python
container.

Self-test: ``python3 scripts/tabulate.py --selftest`` validates the bootstrap
estimator against a synthetic right-skewed fixture (no measurement data).
"""
import csv
import os
import random
import re
import sys

# Bootstrap-percentile CI parameters (#52). 10000 resamples is the usual default
# for a stable percentile interval; the fixed seed makes the reported CI
# reproducible across runs.
BOOTSTRAP_RESAMPLES = 10000
BOOTSTRAP_SEED = 52

CSV = os.environ.get("TABLE_CSV", "docs/thesis/data/latency.csv")
OUT_MD = os.environ.get("TABLE_MD", "docs/thesis/data/results-table.md")
OUT_TEX = os.environ.get("TABLE_TEX", "docs/thesis/data/results-table.tex")


def num(s):
    m = re.match(r"\s*([\d.]+)", s or "")
    return float(m.group(1)) if m else 0.0


def parse_samples(r):
    """Raw per-iteration latencies (ms) from the space-separated ``samples_ms``
    field; ``[]`` when the column is absent or empty (older CSVs)."""
    out = []
    for tok in (r.get("samples_ms") or "").split():
        try:
            out.append(float(tok))
        except ValueError:
            pass
    return out


def has_samples(rows):
    return any(parse_samples(r) for r in rows)


def _percentile(sorted_vals, p):
    """Linear-interpolation ``p``-percentile of an already-sorted list."""
    n = len(sorted_vals)
    if n == 1:
        return sorted_vals[0]
    rank = (p / 100.0) * (n - 1)
    lo = int(rank)
    if lo + 1 < n:
        return sorted_vals[lo] + (rank - lo) * (sorted_vals[lo + 1] - sorted_vals[lo])
    return sorted_vals[lo]


def bootstrap_ci_mean(samples, resamples=BOOTSTRAP_RESAMPLES, seed=BOOTSTRAP_SEED):
    """Bootstrap-percentile 95% CI for the mean of ``samples``.

    Resamples the raw samples with replacement ``resamples`` times and returns the
    (2.5, 97.5) percentiles of the resampled means. Valid on right-skewed loss
    data where a symmetric mean +/- 1.96*sigma/sqrt(n) interval is not (that one
    can imply negative latency). The fixed ``seed`` makes the interval
    reproducible. Returns ``None`` for n < 2 (no interval from a single sample).
    """
    n = len(samples)
    if n < 2:
        return None
    rng = random.Random(seed)
    means = []
    for _ in range(resamples):
        acc = 0.0
        for _ in range(n):
            acc += samples[rng.randrange(n)]
        means.append(acc / n)
    means.sort()
    return _percentile(means, 2.5), _percentile(means, 97.5)


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


def ci_cell(r, dash, fmt):
    """Rendered bootstrap CI ``[lo, hi]`` for a row, or ``dash`` when the row has
    no raw samples. ``fmt`` is "md" (plain) or "tex" (math bracket)."""
    lo, hi = r.get("_ci_lo"), r.get("_ci_hi")
    if lo is None or hi is None:
        return dash
    if fmt == "tex":
        return f"$[{lo:.1f},\\,{hi:.1f}]$"
    return f"[{lo:.1f}, {hi:.1f}]"


def write_md(rows, mode_col, rate_col, oh, show_ci):
    head = (["Modus"] if mode_col else []) + ["Verzögerung", "Verlust"]
    if rate_col:
        head.append("Rate")
    head += ["n", "Mittel (ms)"]
    if show_ci:
        head.append("95%-Bootstrap-KI (ms)")
    head += ["p50 (ms)", "p95 (ms)"]
    if oh:
        head.append("Overhead ggü. direkt (ms)")
    align = ["---"] * len(head)
    lines = ["| " + " | ".join(head) + " |", "| " + " | ".join(align) + " |"]
    for r in rows:
        cells = ([mode_of(r)] if mode_col else []) + [r["delay"] or "0ms", r["loss"] or "0%"]
        if rate_col:
            cells.append(r["rate"] or "—")
        cells += [r["n"], f1(r, "mean_ms")]
        if show_ci:
            cells.append(ci_cell(r, "—", "md"))
        cells += [f1(r, "p50_ms"), f1(r, "p95_ms")]
        if oh:
            cells.append(overhead_cell(r, oh[0], "—"))
        lines.append("| " + " | ".join(cells) + " |")
    with open(OUT_MD, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("tabulate: wrote", OUT_MD)


def tex_esc(s):
    return s.replace("%", r"\%").replace("_", r"\_")


def write_tex(rows, mode_col, rate_col, oh, show_ci):
    stat_cols = "rrrrr" if show_ci else "rrrr"
    cols = ("l" if mode_col else "") + "ll" + ("l" if rate_col else "") + stat_cols + ("r" if oh else "")
    head = (["Modus"] if mode_col else []) + ["Verzögerung", "Verlust"]
    if rate_col:
        head.append("Rate")
    head += ["$n$", "Mittel"]
    if show_ci:
        head.append(r"95\%-KI")
    head += ["p50", "p95"]
    if oh:
        head.append("Overhead")
    lead = 3 if rate_col else 2
    lead += 1 if mode_col else 0
    stat_unit = ["", "(ms)"] + (["(ms)"] if show_ci else []) + ["(ms)", "(ms)"]
    unit = [""] * lead + stat_unit + (["(ms)"] if oh else [])
    if show_ci:
        caption = (
            r"Tunnel-Roundtrip-Latenz je Betriebsart unter emulierten "
            r"Netzbedingungen (\texttt{tc netem}); Median~(p50) und p95 als robuste "
            r"Tail-Metriken. Das 95\%-Konfidenzintervall ist ein "
            r"Bootstrap-Perzentil-Intervall f\"ur den Mittelwert (10000 "
            r"Resamples der Roh-Latenzen, 2{,}5/97{,}5-Perzentil der "
            r"Bootstrap-Mittel); ein symmetrisches Normal-KI wird wegen der "
            r"Rechtsschiefe der Verlustverteilungen vermieden, und das p99 f\"allt "
            r"bei $n=30$ mit dem Stichprobenmaximum zusammen und wird nicht "
            r"berichtet."
        )
    else:
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
        cells += [r["n"], f1(r, "mean_ms")]
        if show_ci:
            cells.append(ci_cell(r, "--", "tex"))
        cells += [f1(r, "p50_ms"), f1(r, "p95_ms")]
        if oh:
            cells.append(overhead_cell(r, oh[0], "--"))
        out.append("    " + " & ".join(cells) + r" \\")
    out += [r"    \bottomrule", r"  \end{tabular}", r"\end{table}"]
    with open(OUT_TEX, "w") as f:
        f.write("\n".join(out) + "\n")
    print("tabulate: wrote", OUT_TEX)


def annotate_ci(rows):
    """Attach the bootstrap-percentile CI (``_ci_lo``/``_ci_hi``) to each row that
    carries raw samples. Rows without samples get ``None`` and render as a dash."""
    for r in rows:
        s = parse_samples(r)
        ci = bootstrap_ci_mean(s) if s else None
        r["_ci_lo"], r["_ci_hi"] = ci if ci else (None, None)


def selftest():
    """Validate the bootstrap estimator against a synthetic right-skewed sample.

    The fixture below is a TEST FIXTURE ONLY — a synthetic, exponential-like
    right-skewed sample, NOT a measurement result. It exercises the estimator's
    invariants: a non-negative lower bound, a bracketed and right-asymmetric
    interval, and reproducibility under the fixed seed.
    """
    fixture = [1.0, 1.1, 1.2, 1.3, 1.5, 1.8, 2.1, 2.6, 3.3, 4.5, 6.8, 11.0, 22.0]
    mean = sum(fixture) / len(fixture)
    lo, hi = bootstrap_ci_mean(fixture)
    assert lo >= 0.0, f"CI lower bound must be non-negative, got {lo}"
    assert lo < mean < hi, f"CI [{lo}, {hi}] must bracket the mean {mean}"
    assert (hi - mean) > (mean - lo), (
        f"right-skewed sample → CI should be asymmetric (upper wider): "
        f"lower={mean - lo:.3f} upper={hi - mean:.3f}"
    )
    lo2, hi2 = bootstrap_ci_mean(fixture)
    assert (lo, hi) == (lo2, hi2), "CI must be reproducible under the fixed seed"
    print(
        f"tabulate selftest OK: fixture mean={mean:.3f} ms, "
        f"bootstrap 95%-CI=[{lo:.3f}, {hi:.3f}] ms "
        f"(non-negative, bracketed, right-asymmetric, reproducible)"
    )


def main():
    rows = load()
    annotate_ci(rows)
    show_ci = has_samples(rows)
    mode_col = has_mode(rows)
    rate_col = has_rate(rows)
    # FF2 (#51): when direct-baseline rows are present, annotate tunnel rows with
    # their overhead vs. the chosen direct baseline (default direct-tcp). Absent
    # baseline rows → oh is None → output is byte-identical to a tunnel-only run.
    baseline_mode = os.environ.get("OVERHEAD_BASELINE", "direct-tcp")
    bmap = baseline_means(rows, baseline_mode)
    oh = (bmap, baseline_mode) if bmap and any(not is_direct(r) for r in rows) else None
    write_md(rows, mode_col, rate_col, oh, show_ci)
    write_tex(rows, mode_col, rate_col, oh, show_ci)


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        selftest()
    else:
        main()
