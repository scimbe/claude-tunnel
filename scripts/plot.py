#!/usr/bin/env python3
"""M6.3 / M16.4 — render thesis evaluation figures from the netem sweep CSV.

Reads the sweep output and renders PNG figures next to it. Runs headless (Agg);
intended to run inside a python container via scripts/plot.sh (no host install).

The M16 CSV carries a ``mode`` column (single/stream/udp); older CSVs without it
are treated as a single mode. Figures:

  latency-vs-delay.png  — mean round-trip vs edge delay for the reference mode,
                          one series per loss, p95 as the upper error bar.
  latency-vs-loss.png   — mean round-trip vs packet loss for the reference mode
                          (only when the sweep covers >1 distinct loss value).
  latency-by-mode.png   — mode comparison: mean round-trip vs edge delay, one
                          series per mode at a fixed loss (only when >1 mode).
"""
import csv
import os
import re
import sys
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

DATA = os.environ.get("PLOT_CSV", "docs/thesis/data/latency.csv")
OUTDIR = os.path.dirname(DATA) or "."


def num(s):
    """Leading number of a netem value like '20ms', '5%', '10mbit' -> float."""
    m = re.match(r"\s*([\d.]+)", s or "")
    return float(m.group(1)) if m else 0.0


def mode_of(r):
    return (r.get("mode") or "single").strip() or "single"


def modes(rows):
    seen = []
    for r in rows:
        m = mode_of(r)
        if m not in seen:
            seen.append(m)
    return seen


def reference_mode(rows):
    ms = modes(rows)
    return "single" if "single" in ms else ms[0]


def load(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print("plot: no rows in", path)
        sys.exit(1)
    return rows


def plot_vs_delay(rows, mode):
    sub = [r for r in rows if mode_of(r) == mode]
    by_loss = defaultdict(list)
    for r in sub:
        by_loss[r["loss"]].append((num(r["delay"]), float(r["mean_ms"]), float(r["p95_ms"])))

    plt.figure(figsize=(6, 4))
    for loss, pts in sorted(by_loss.items(), key=lambda kv: num(kv[0])):
        pts.sort()
        xs = [p[0] for p in pts]
        means = [p[1] for p in pts]
        upper = [max(0.0, p[2] - p[1]) for p in pts]
        plt.errorbar(
            xs, means, yerr=[[0] * len(means), upper],
            marker="o", capsize=3, label=f"Verlust {loss or '0%'}",
        )
    plt.xlabel("Edge-Verzögerung (ms)")
    plt.ylabel("Tunnel-Roundtrip (ms)")
    plt.title(f"Latenz vs. Netzwerkverzögerung (Modus: {mode})")
    plt.legend()
    plt.grid(True, alpha=0.3)
    out = os.path.join(OUTDIR, "latency-vs-delay.png")
    plt.tight_layout()
    plt.savefig(out, dpi=120)
    plt.close()
    print("plot: wrote", out)


def plot_vs_loss(rows, mode):
    sub = [r for r in rows if mode_of(r) == mode]
    losses = {num(r["loss"]) for r in sub}
    if len(losses) < 2:
        print("plot: <2 distinct loss values, skipping latency-vs-loss")
        return
    by_delay = defaultdict(list)
    for r in sub:
        by_delay[r["delay"]].append((num(r["loss"]), float(r["mean_ms"])))

    plt.figure(figsize=(6, 4))
    for delay, pts in sorted(by_delay.items(), key=lambda kv: num(kv[0])):
        pts.sort()
        xs = [p[0] for p in pts]
        means = [p[1] for p in pts]
        plt.plot(xs, means, marker="o", label=f"Verzögerung {delay or '0ms'}")
    plt.xlabel("Paketverlust (%)")
    plt.ylabel("Tunnel-Roundtrip (ms)")
    plt.title(f"Latenz vs. Paketverlust (Modus: {mode})")
    plt.legend()
    plt.grid(True, alpha=0.3)
    out = os.path.join(OUTDIR, "latency-vs-loss.png")
    plt.tight_layout()
    plt.savefig(out, dpi=120)
    plt.close()
    print("plot: wrote", out)


def plot_by_mode(rows, loss="0%"):
    ms = modes(rows)
    if len(ms) < 2:
        print("plot: <2 modes, skipping latency-by-mode")
        return
    plt.figure(figsize=(6, 4))
    plotted = False
    for m in ms:
        pts = [
            (num(r["delay"]), float(r["mean_ms"]))
            for r in rows
            if mode_of(r) == m and (r["loss"] or "0%") == loss
        ]
        if not pts:
            continue
        pts.sort()
        xs = [p[0] for p in pts]
        means = [p[1] for p in pts]
        plt.plot(xs, means, marker="o", label=m)
        plotted = True
    if not plotted:
        print(f"plot: no rows at loss={loss}, skipping latency-by-mode")
        plt.close()
        return
    plt.xlabel("Edge-Verzögerung (ms)")
    plt.ylabel("Tunnel-Roundtrip (ms)")
    plt.title(f"Latenz je Betriebsart (Verlust {loss})")
    plt.legend()
    plt.grid(True, alpha=0.3)
    out = os.path.join(OUTDIR, "latency-by-mode.png")
    plt.tight_layout()
    plt.savefig(out, dpi=120)
    plt.close()
    print("plot: wrote", out)


def main():
    rows = load(DATA)
    ref = reference_mode(rows)
    plot_vs_delay(rows, ref)
    plot_vs_loss(rows, ref)
    plot_by_mode(rows, "0%")


if __name__ == "__main__":
    main()
