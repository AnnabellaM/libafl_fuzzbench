#!/usr/bin/env python3
"""
Plot branch coverage over time for each fuzzer on each target.

Reads coverage_timeseries.csv files produced by run_coverage_timeseries.sh and
generates a figure with one subplot per target, one line per fuzzer (mean over
trials), and a shaded band for ±1 std across trials.

Usage:
    python3 plot_coverage.py [--cov-dir out/coverage] [--out coverage.png]
                             [--targets "a b"] [--fuzzers "x y"]
"""

import argparse
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# ── CLI ──────────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser()
parser.add_argument("--cov-dir",  default="out/coverage",
                    help="Root coverage output directory")
parser.add_argument("--out",      default="coverage_over_time.png",
                    help="Output image path")
parser.add_argument("--targets",  default=None,
                    help="Space-separated list of targets (default: auto-detect)")
parser.add_argument("--fuzzers",  default=None,
                    help="Space-separated list of fuzzers (default: auto-detect)")
parser.add_argument("--interval", type=int, default=None,
                    help="Re-sample interval in minutes for plotting (default: auto)")
parser.add_argument("--hours",    type=float, default=None,
                    help="Trim x-axis to this many hours (default: auto)")
args = parser.parse_args()

cov_dir = Path(args.cov_dir)

# ── discover targets / fuzzers ───────────────────────────────────────────────

def discover(base: Path, level: int) -> list[str]:
    if not base.is_dir():
        return []
    return sorted(p.name for p in base.iterdir() if p.is_dir())

targets = args.targets.split() if args.targets else discover(cov_dir, 1)
fuzzers = args.fuzzers.split() if args.fuzzers else None  # discovered per target

# ── load data ────────────────────────────────────────────────────────────────

# data[target][fuzzer] = list of DataFrames (one per trial)
data: dict[str, dict[str, list[pd.DataFrame]]] = {}

for target in targets:
    target_dir = cov_dir / target
    if not target_dir.is_dir():
        continue
    fz_list = fuzzers if fuzzers else discover(target_dir, 2)
    data[target] = {}
    for fuzzer in fz_list:
        fuzzer_dir = target_dir / fuzzer
        if not fuzzer_dir.is_dir():
            continue
        dfs = []
        for trial_dir in sorted(fuzzer_dir.iterdir()):
            csv_path = trial_dir / "coverage_timeseries.csv"
            if csv_path.exists():
                df = pd.read_csv(csv_path)
                df["branch_pct"] = 100.0 * df["branch_covered"] / df["branch_total"]
                df["time_h"] = df["time_s"] / 3600
                dfs.append(df)
        if dfs:
            data[target][fuzzer] = dfs

# drop targets with no data
targets_with_data = [t for t in targets if data.get(t)]
if not targets_with_data:
    print("No coverage_timeseries.csv files found. Run run_coverage_timeseries.sh first.")
    raise SystemExit(1)

# ── plot ─────────────────────────────────────────────────────────────────────

COLORS = [
    "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728",
    "#9467bd", "#8c564b", "#e377c2", "#7f7f7f",
]

n_targets = len(targets_with_data)
ncols = min(n_targets, 2)
nrows = (n_targets + ncols - 1) // ncols

fig, axes = plt.subplots(nrows, ncols,
                         figsize=(7 * ncols, 4.5 * nrows),
                         squeeze=False)
fig.suptitle("Branch Coverage Over Time", fontsize=15, fontweight="bold", y=1.01)

for ax_idx, target in enumerate(targets_with_data):
    ax = axes[ax_idx // ncols][ax_idx % ncols]
    fz_data = data[target]

    all_fuzzers = sorted(fz_data.keys())
    for fz_idx, fuzzer in enumerate(all_fuzzers):
        color = COLORS[fz_idx % len(COLORS)]
        dfs   = fz_data[fuzzer]

        # Build a common time grid from all trials
        all_times = sorted({t for df in dfs for t in df["time_h"]})
        if args.hours:
            all_times = [t for t in all_times if t <= args.hours]

        # Interpolate each trial onto the common grid
        grid = np.array(all_times)
        interp_vals = []
        for df in dfs:
            df_sorted = df.sort_values("time_h")
            interp = np.interp(grid, df_sorted["time_h"], df_sorted["branch_pct"])
            interp_vals.append(interp)

        mat  = np.array(interp_vals)       # (n_trials, n_timepoints)
        mean = mat.mean(axis=0)
        std  = mat.std(axis=0)

        label = fuzzer.replace("_", " ")
        ax.plot(grid, mean, label=label, color=color, linewidth=1.8)
        ax.fill_between(grid, mean - std, mean + std,
                        color=color, alpha=0.15)

    ax.set_title(target, fontsize=12, fontweight="bold")
    ax.set_xlabel("Time (hours)")
    ax.set_ylabel("Branch coverage (%)")
    ax.legend(fontsize=8, loc="lower right")
    ax.grid(True, alpha=0.3)
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)

# Hide unused subplots
for ax_idx in range(n_targets, nrows * ncols):
    axes[ax_idx // ncols][ax_idx % ncols].set_visible(False)

plt.tight_layout()
out_path = args.out
plt.savefig(out_path, dpi=150, bbox_inches="tight")
print(f"Saved: {out_path}")
