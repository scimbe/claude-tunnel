#!/usr/bin/env python3
"""M6.3 — render thesis evaluation figures from the netem sweep CSV.

Reads the sweep output (delay,loss,rate,n,mean_ms,min_ms,max_ms,p50_ms,p95_ms)
and renders PNG figures next to it. Runs headless (Agg); intended to be executed
inside a python container via scripts/plot.sh (no host install).

Figures:
  latency-vs-delay.png  — mean round-trip vs edge delay, one series per loss,
                          p95 as the upper error bar.
  latency-vs-loss.png   — mean round-trip vs packet loss (only when the sweep
                          covers >1 distinct loss value).
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


def load(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print("plot: no rows in", path)
        sys.exit(1)
    return rows


def plot_vs_delay(rows):
    by_loss = defaultdict(list)
    for r in rows:
        by_loss[r["loss"]].append((num(r["delay"]), float(r["mean_ms"]), float(r["p95_ms"])))

    plt.figure(figsize=(6, 4))
    for loss, pts in sorted(by_loss.items(), key=lambda kv: num(kv[0])):
        pts.sort()
        xs = [p[0] for p in pts]
        means = [p[1] for p in pts]
        upper = [max(0.0, p[2] - p[1]) for p in pts]
        plt.errorbar(
            xs, means, yerr=[[0] * len(means), upper],
            marker="o", capsize=3, label=f"Verlust {loss}",
        )
    plt.xlabel("Edge-Verzögerung (ms)")
    plt.ylabel("Tunnel-Roundtrip (ms)")
    plt.title("Latenz vs. Netzwerkverzögerung")
    plt.legend()
    plt.grid(True, alpha=0.3)
    out = os.path.join(OUTDIR, "latency-vs-delay.png")
    plt.tight_layout()
    plt.savefig(out, dpi=120)
    plt.close()
    print("plot: wrote", out)


def plot_vs_loss(rows):
    by_delay = defaultdict(list)
    for r in rows:
        by_delay[r["delay"]].append((num(r["loss"]), float(r["mean_ms"])))
    losses = {num(r["loss"]) for r in rows}
    if len(losses) < 2:
        print("plot: <2 distinct loss values, skipping latency-vs-loss")
        return

    plt.figure(figsize=(6, 4))
    for delay, pts in sorted(by_delay.items(), key=lambda kv: num(kv[0])):
        pts.sort()
        xs = [p[0] for p in pts]
        means = [p[1] for p in pts]
        plt.plot(xs, means, marker="o", label=f"Verzögerung {delay}")
    plt.xlabel("Paketverlust (%)")
    plt.ylabel("Tunnel-Roundtrip (ms)")
    plt.title("Latenz vs. Paketverlust")
    plt.legend()
    plt.grid(True, alpha=0.3)
    out = os.path.join(OUTDIR, "latency-vs-loss.png")
    plt.tight_layout()
    plt.savefig(out, dpi=120)
    plt.close()
    print("plot: wrote", out)


def main():
    rows = load(DATA)
    plot_vs_delay(rows)
    plot_vs_loss(rows)


if __name__ == "__main__":
    main()
