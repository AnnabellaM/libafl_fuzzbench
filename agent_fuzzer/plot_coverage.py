#!/usr/bin/env python3
"""Plot coverage timeseries: agent_fuzzer vs generic."""
import csv
import os
import sys
import numpy as np

try:
    import matplotlib.pyplot as plt
except ImportError:
    print("pip install matplotlib")
    sys.exit(1)

TARGET = sys.argv[1] if len(sys.argv) > 1 else "libpcap"
COV_DIR = os.path.join(os.path.dirname(__file__), "exp_out", "coverage_ts", TARGET)

if not os.path.isdir(COV_DIR):
    print(f"No data at {COV_DIR}")
    sys.exit(1)

fig, ax = plt.subplots(figsize=(10, 6))
colors = {"generic": "#1f77b4", "agent_fuzzer": "#d62728"}
labels = {"generic": "Generic (baseline)", "agent_fuzzer": "Agent Fuzzer"}

for fuzzer in ["generic", "agent_fuzzer"]:
    fuzzer_dir = os.path.join(COV_DIR, fuzzer)
    if not os.path.isdir(fuzzer_dir):
        continue

    all_times = []
    all_coverages = []

    for trial_name in sorted(os.listdir(fuzzer_dir)):
        csv_path = os.path.join(fuzzer_dir, trial_name, "coverage_timeseries.csv")
        if not os.path.isfile(csv_path):
            continue

        times, coverages = [], []
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                times.append(int(row["time_s"]) / 3600)  # hours
                coverages.append(int(row["branch_covered"]))

        if times:
            all_times.append(times)
            all_coverages.append(coverages)
            ax.plot(times, coverages, color=colors.get(fuzzer, "gray"),
                    alpha=0.25, linewidth=0.8)

    if all_coverages:
        # Interpolate to common time grid and compute mean
        max_t = min(max(t) for t in all_times)
        grid = np.linspace(0, max_t, 200)
        interped = []
        for t, c in zip(all_times, all_coverages):
            interped.append(np.interp(grid, t, c))
        mean_cov = np.mean(interped, axis=0)
        ax.plot(grid, mean_cov, color=colors.get(fuzzer, "gray"),
                linewidth=2.5, label=f"{labels.get(fuzzer, fuzzer)} (n={len(all_coverages)})")

ax.set_xlabel("Time (hours)", fontsize=12)
ax.set_ylabel("Branch Coverage", fontsize=12)
ax.set_title(f"Coverage Over Time — {TARGET}", fontsize=14)
ax.legend(fontsize=11)
ax.grid(True, alpha=0.3)

out_path = os.path.join(os.path.dirname(__file__), "exp_out", f"{TARGET}_coverage.png")
fig.savefig(out_path, dpi=150, bbox_inches="tight")
print(f"Saved: {out_path}")
plt.close()
