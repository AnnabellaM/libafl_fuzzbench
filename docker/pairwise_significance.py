#!/usr/bin/env python3
"""
Pairwise significance tests for fuzzer comparison.

For every (fuzzer A, fuzzer B, target T), runs two tests on the 3 A-trials vs
3 B-trials:

  1. AUC exact permutation test
     - per-trial stat: trapezoidal integral of branch_covered over time_s
     - C(6,3)=20 label assignments; one-sided in observed direction; min p = 1/20

  2. Final-coverage Mann-Whitney U (exact, one-sided in observed direction)
     - per-trial stat: last branch_covered value from the timeseries CSV
     - exact method via scipy with alternative='greater' or 'less'

Gate for "interesting" (applied to each test independently):
    p <= p_gate  AND  |Δmean| / max(mean) >= mag_gate

Agreement summary: which pairs pass both, AUC-only, MW-only.

Input:  out/coverage_ts/<target>/<fuzzer>/trial<N>/coverage_timeseries.csv
Output: printed table; optional CSV via --out.
"""

import argparse
import csv
import itertools
from pathlib import Path

from scipy.stats import mannwhitneyu


DEFAULT_FUZZERS = [
    "naive", "cmplog", "value_profile", "value_profile_cmplog",
    "cov_accounting", "minimizer", "rand_scheduler", "weighted",
    "grimoire",
]
DEFAULT_TARGETS = ["bloaty", "lcms", "libpcap", "mbedtls", "sqlite3"]


def load_trial_stats(csv_path: Path):
    """Return (auc, final_coverage) or (None, None) if not usable."""
    if not csv_path.exists():
        return None, None
    rows = []
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            rows.append((int(row["time_s"]), int(row["branch_covered"])))
    if len(rows) < 2:
        return None, None
    auc = 0.0
    for (t0, c0), (t1, c1) in zip(rows, rows[1:]):
        auc += (t1 - t0) * (c0 + c1) / 2
    return auc, rows[-1][1]


def permutation_p(vals_a: list[float], vals_b: list[float]) -> float:
    """One-sided exact permutation p on mean difference (direction from data).

    With 3 vs 3, enumerates all C(6,3)=20 label assignments. Counts permutations
    whose (A_mean - B_mean) is at least as extreme as observed in the observed
    direction. Minimum achievable p = 1/20 = 0.05.
    """
    pool = list(vals_a) + list(vals_b)
    n_a = len(vals_a)
    obs = sum(vals_a) / n_a - sum(vals_b) / len(vals_b)

    count = 0
    total = 0
    for idx_a in itertools.combinations(range(len(pool)), n_a):
        set_a = set(idx_a)
        a = [pool[i] for i in range(len(pool)) if i in set_a]
        b = [pool[i] for i in range(len(pool)) if i not in set_a]
        diff = sum(a) / len(a) - sum(b) / len(b)
        if obs >= 0 and diff >= obs:
            count += 1
        elif obs < 0 and diff <= obs:
            count += 1
        total += 1
    return count / total


def mw_p(vals_a: list[float], vals_b: list[float]) -> float:
    """Exact one-sided Mann-Whitney U p-value in observed direction."""
    mean_a = sum(vals_a) / len(vals_a)
    mean_b = sum(vals_b) / len(vals_b)
    alt = "greater" if mean_a >= mean_b else "less"
    return mannwhitneyu(vals_a, vals_b, alternative=alt, method="exact").pvalue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", default="out/coverage_ts", type=Path)
    ap.add_argument("--targets", nargs="+", default=DEFAULT_TARGETS)
    ap.add_argument("--fuzzers", nargs="+", default=DEFAULT_FUZZERS)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--p-gate", type=float, default=0.05)
    ap.add_argument("--mag-gate", type=float, default=0.05,
                    help="|ΔAUC_mean| / max(AUC_mean) threshold (5%% default)")
    ap.add_argument("--out", type=Path, default=None,
                    help="optional CSV output of all interesting pairs")
    args = ap.parse_args()

    all_rows = []  # CSV rows for every evaluated pair
    agreement_counts = {"both": 0, "auc_only": 0, "mw_only": 0, "neither": 0}
    dir_conflict_count = 0

    for target in args.targets:
        print(f"\n=== {target} ===")

        fuzzer_stats: dict[str, tuple[list[float], list[float]]] = {}
        for fuzzer in args.fuzzers:
            aucs, finals = [], []
            for t in range(1, args.trials + 1):
                p = args.results_dir / target / fuzzer / f"trial{t}" / "coverage_timeseries.csv"
                a, f_ = load_trial_stats(p)
                if a is not None:
                    aucs.append(a)
                    finals.append(f_)
            if len(aucs) == args.trials:
                fuzzer_stats[fuzzer] = (aucs, finals)
            else:
                print(f"  (skipping {fuzzer}: only {len(aucs)}/{args.trials} trials)")

        interesting = []  # rows for printed table (passes at least one test)

        for a, b in itertools.combinations(fuzzer_stats.keys(), 2):
            aucs_a, finals_a = fuzzer_stats[a]
            aucs_b, finals_b = fuzzer_stats[b]

            # AUC test
            m_auc_a = sum(aucs_a) / len(aucs_a)
            m_auc_b = sum(aucs_b) / len(aucs_b)
            rel_auc = (abs(m_auc_a - m_auc_b) / max(m_auc_a, m_auc_b)
                       if max(m_auc_a, m_auc_b) > 0 else 0.0)
            p_auc = permutation_p(aucs_a, aucs_b)
            pass_auc = p_auc <= args.p_gate and rel_auc >= args.mag_gate

            # Final-coverage MW test
            m_fin_a = sum(finals_a) / len(finals_a)
            m_fin_b = sum(finals_b) / len(finals_b)
            rel_fin = (abs(m_fin_a - m_fin_b) / max(m_fin_a, m_fin_b)
                       if max(m_fin_a, m_fin_b) > 0 else 0.0)
            p_mw = mw_p(finals_a, finals_b)
            pass_mw = p_mw <= args.p_gate and rel_fin >= args.mag_gate

            # Label winner by AUC direction (the more stable of the two stats).
            if m_auc_a >= m_auc_b:
                winner, loser = a, b
                mw_auc, ml_auc = m_auc_a, m_auc_b
                mw_fin, ml_fin = m_fin_a, m_fin_b
            else:
                winner, loser = b, a
                mw_auc, ml_auc = m_auc_b, m_auc_a
                mw_fin, ml_fin = m_fin_b, m_fin_a

            # Flag early-lead / late-catchup cases: AUC says A wins, MW says B wins
            dir_conflict = mw_fin < ml_fin
            if dir_conflict:
                dir_conflict_count += 1

            verdict = ("both" if pass_auc and pass_mw
                       else "auc_only" if pass_auc
                       else "mw_only" if pass_mw
                       else "neither")
            agreement_counts[verdict] += 1

            all_rows.append([target, winner, loser,
                             f"{mw_auc:.6e}", f"{ml_auc:.6e}",
                             f"{rel_auc:.6f}", f"{p_auc:.4f}",
                             f"{mw_fin:.1f}", f"{ml_fin:.1f}",
                             f"{rel_fin:.6f}", f"{p_mw:.4f}",
                             verdict,
                             "yes" if dir_conflict else "no"])

            if verdict != "neither" or dir_conflict:
                interesting.append((winner, loser, rel_auc, p_auc,
                                    rel_fin, p_mw, verdict, dir_conflict))

        if not interesting:
            print("  no pairs pass either gate")
            continue
        interesting.sort(key=lambda r: (r[6] != "both", -max(r[2], r[4])))
        for win, lose, rel_auc, p_auc, rel_fin, p_mw, verdict, conflict in interesting:
            tag = {"both": "BOTH    ", "auc_only": "AUC only",
                   "mw_only": "MW only ", "neither": "--      "}[verdict]
            flag = " [DIR-CONFLICT]" if conflict else ""
            print(f"  [{tag}] {win:>22} > {lose:<22}  "
                  f"AUC(rel={rel_auc*100:5.1f}% p={p_auc:.3f})  "
                  f"MW(rel={rel_fin*100:5.1f}% p={p_mw:.3f}){flag}")

    # Agreement summary
    total = sum(agreement_counts.values())
    print("\n=== Agreement summary (all targets) ===")
    print(f"  pairs evaluated: {total}")
    print(f"  pass both tests: {agreement_counts['both']}")
    print(f"  pass AUC only:   {agreement_counts['auc_only']}")
    print(f"  pass MW only:    {agreement_counts['mw_only']}")
    print(f"  pass neither:    {agreement_counts['neither']}")
    passed_auc = agreement_counts["both"] + agreement_counts["auc_only"]
    passed_mw = agreement_counts["both"] + agreement_counts["mw_only"]
    if passed_auc + passed_mw > 0:
        jaccard = (agreement_counts["both"]
                   / (agreement_counts["both"] + agreement_counts["auc_only"]
                      + agreement_counts["mw_only"]))
        print(f"  jaccard agreement (pairs passing at least one): {jaccard:.3f}")

    print(f"  direction conflicts (AUC sign ≠ MW sign): {dir_conflict_count}")

    if args.out:
        with open(args.out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["target", "winner", "loser",
                        "winner_mean_auc", "loser_mean_auc",
                        "rel_delta_auc", "p_auc",
                        "winner_mean_final", "loser_mean_final",
                        "rel_delta_final", "p_mw",
                        "verdict", "dir_conflict"])
            w.writerows(all_rows)
        print(f"\nWrote {len(all_rows)} pair-rows to {args.out}")


if __name__ == "__main__":
    main()
