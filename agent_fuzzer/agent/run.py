#!/usr/bin/env python3
"""External agent for agent_fuzzer: LLM-based coverage plateau breaker.

Invoked by the fuzzer as: <agent-cmd> <agent_dir>

Pipeline:
  1. Collect coverage: run seeds against instrumented target (llvm-cov)
  2. Find frontier branches: one side 0, other side non-0
  3. Filter (negative rules) and prioritize (positive rules + heuristics)
  4. Per-branch resolution loop:
     - Pick cheapest untried strategy
     - LLM generates candidate seeds
     - Verify against target: did the branch flip?
     - Hit → save to results/; Miss → retry (up to 5x)
  5. Persist state (backlog, attempt counts) across agent cycles
  6. Signal done

Environment variables:
  FUZZ_BIN           - Path to coverage-instrumented target binary (required)
  ANTHROPIC_API_KEY  - API key for Claude (required for LLM strategies)
  AGENT_MODEL        - Claude model (default: claude-sonnet-4-20250514)
  AGENT_MAX_ATTEMPTS - Max attempts per branch (default: 5)
  AGENT_LOG          - Log file path (default: agent_dir/agent.log)
"""

import json
import os
import sys
import time
import traceback
from pathlib import Path

from coverage import (
    Branch,
    export_branches_json,
    extract_source_context,
    find_frontier_branches,
    get_source_report,
    run_seeds_coverage,
    verify_seed_hits_branch,
)
from rules import (
    apply_negative_rules,
    load_negative_rules,
    load_positive_rules,
    prioritize_branches,
)
from strategies import (
    generate_heuristic_seeds,
    get_available_strategies,
    run_strategy,
)


# ---------------------------------------------------------------------------
# Persistent state (survives across agent cycles)
# ---------------------------------------------------------------------------


def load_state(state_dir: Path) -> dict:
    """Load branch tracking state from previous cycles."""
    state_file = state_dir / "branches.json"
    cycle_file = state_dir / "cycle_count"

    state = {"branches": {}, "cycle": 0}
    if state_file.exists():
        with open(state_file) as f:
            state["branches"] = json.load(f)
    if cycle_file.exists():
        state["cycle"] = int(cycle_file.read_text().strip())
    return state


def save_state(state: dict, state_dir: Path):
    """Persist branch tracking state."""
    state_dir.mkdir(parents=True, exist_ok=True)
    with open(state_dir / "branches.json", "w") as f:
        json.dump(state["branches"], f, indent=2)
    (state_dir / "cycle_count").write_text(str(state["cycle"]))


def get_branch_state(state: dict, branch_id: str) -> dict:
    """Get or create tracking state for a branch."""
    if branch_id not in state["branches"]:
        state["branches"][branch_id] = {
            "attempts": 0,
            "strategies_tried": [],
            "last_attempt_cycle": -1,
            "status": "pending",  # pending | solved | deferred
        }
    return state["branches"][branch_id]


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


_log_file = None


def log(msg):
    print(f"[agent] {msg}", file=sys.stderr, flush=True)
    if _log_file:
        print(f"[agent] {msg}", file=_log_file, flush=True)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def read_seeds(seeds_dir: Path) -> dict[str, bytes]:
    """Read all seed files from the seeds directory."""
    seeds = {}
    if not seeds_dir.exists():
        return seeds
    for seed_file in sorted(seeds_dir.iterdir()):
        if seed_file.is_file():
            seeds[seed_file.name] = seed_file.read_bytes()
    return seeds


def main():
    global _log_file

    if len(sys.argv) < 2:
        print("Usage: run.py <agent_dir>", file=sys.stderr)
        sys.exit(1)

    agent_dir = Path(sys.argv[1])
    fuzz_bin = os.environ.get("FUZZ_BIN")

    if not fuzz_bin:
        log("FATAL: FUZZ_BIN environment variable not set")
        (agent_dir / "done").touch()
        sys.exit(1)

    # Set up logging
    log_path = os.environ.get("AGENT_LOG", str(agent_dir / "agent.log"))
    _log_file = open(log_path, "a")

    max_attempts = int(os.environ.get("AGENT_MAX_ATTEMPTS", "5"))

    try:
        t0 = time.time()
        log(f"=== Agent cycle started ===")
        log(f"agent_dir={agent_dir}, fuzz_bin={fuzz_bin}")

        # --- Read IPC ---
        request_path = agent_dir / "request.json"
        with open(request_path) as f:
            request = json.load(f)
        log(f"Request: {json.dumps(request)}")

        seeds_dir = Path(request["seeds_dir"])
        seeds = read_seeds(seeds_dir)
        log(f"Read {len(seeds)} seeds ({sum(len(v) for v in seeds.values())} bytes total)")

        if not seeds:
            log("No seeds to analyze, signaling done")
            (agent_dir / "done").touch()
            return

        # --- Set up directories ---
        coverage_dir = agent_dir / "coverage"
        coverage_dir.mkdir(parents=True, exist_ok=True)
        results_dir = agent_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        state_dir = agent_dir / "state"
        rules_dir = agent_dir / "rules"

        # --- Step 1: Collect coverage ---
        log("Step 1: Collecting coverage...")
        seed_paths = [str(seeds_dir / name) for name in sorted(seeds.keys())]
        profdata_path = run_seeds_coverage(
            fuzz_bin, seed_paths, coverage_dir, log_fn=log
        )

        if not profdata_path.exists():
            log("ERROR: Coverage collection failed, falling back to heuristics")
            _fallback_heuristic(seeds, results_dir)
            return

        # --- Step 2: Find frontier branches ---
        log("Step 2: Analyzing branches...")
        all_branches = export_branches_json(fuzz_bin, profdata_path)
        log(f"Total branches: {len(all_branches)}")

        frontier = find_frontier_branches(all_branches)
        log(f"Frontier branches (one-sided): {len(frontier)}")

        if not frontier:
            log("No frontier branches found, nothing to do")
            return

        # Get source report for context extraction
        source_report = get_source_report(fuzz_bin, profdata_path)
        # Save reports for debugging
        (coverage_dir / "report.json").write_text(
            json.dumps([{
                "id": b.id,
                "true": b.true_count,
                "false": b.false_count,
                "missing": b.missing_side,
            } for b in frontier], indent=2)
        )
        (coverage_dir / "report.txt").write_text(source_report)

        # --- Step 3: Filter and prioritize ---
        log("Step 3: Filtering and prioritizing...")
        neg_rules = load_negative_rules(rules_dir)
        pos_rules = load_positive_rules(rules_dir)
        log(f"Loaded {len(neg_rules)} negative rules, {len(pos_rules)} positive rules")

        # Build source contexts for all frontier branches
        source_contexts = {}
        for branch in frontier:
            source_contexts[branch.id] = extract_source_context(
                source_report, branch
            )

        # Apply negative rules
        frontier = apply_negative_rules(frontier, source_contexts, neg_rules, log)

        # Prioritize by positive rules + heuristics
        frontier = prioritize_branches(frontier, source_contexts, pos_rules)
        log(f"After filtering: {len(frontier)} branches to process")

        # --- Step 4: Load state ---
        state = load_state(state_dir)
        state["cycle"] += 1
        current_cycle = state["cycle"]
        log(f"Agent cycle: {current_cycle}")

        # --- Step 5: Per-branch resolution loop ---
        log("Step 5: Resolving branches...")
        solved_count = 0
        skipped_count = 0
        result_index = 0

        for i, branch in enumerate(frontier):
            bs = get_branch_state(state, branch.id)

            # Skip deferred branches
            if bs["status"] == "deferred":
                skipped_count += 1
                continue
            if bs["status"] == "solved":
                skipped_count += 1
                continue

            log(f"\n--- Branch {i+1}/{len(frontier)}: {branch.id} "
                f"(missing={branch.missing_side}, attempts={bs['attempts']}) ---")

            # Get available strategies
            available = get_available_strategies(
                branch, source_contexts.get(branch.id, ""), bs["strategies_tried"]
            )
            if not available:
                log(f"  All strategies exhausted, deferring")
                bs["status"] = "deferred"
                continue

            branch_solved = False
            for strategy_name in available:
                if bs["attempts"] >= max_attempts:
                    log(f"  Max attempts reached, deferring")
                    bs["status"] = "deferred"
                    break

                log(f"  Trying strategy: {strategy_name}")
                candidates = run_strategy(
                    strategy_name,
                    branch,
                    source_contexts.get(branch.id, ""),
                    seeds,
                    log,
                )
                bs["strategies_tried"].append(strategy_name)
                bs["last_attempt_cycle"] = current_cycle

                if not candidates:
                    log(f"  Strategy produced no candidates")
                    bs["attempts"] += 1
                    continue

                log(f"  Got {len(candidates)} candidates, verifying...")

                for j, candidate in enumerate(candidates):
                    bs["attempts"] += 1
                    hit = verify_seed_hits_branch(
                        fuzz_bin, candidate, branch, coverage_dir
                    )
                    if hit:
                        log(f"  SOLVED! Candidate {j} hit the branch")
                        result_path = results_dir / f"agent_seed_{result_index:04d}"
                        result_path.write_bytes(candidate)
                        result_index += 1
                        bs["status"] = "solved"
                        solved_count += 1
                        branch_solved = True
                        break
                    else:
                        log(f"  Candidate {j} missed")

                    if bs["attempts"] >= max_attempts:
                        break

                if branch_solved:
                    break

            if not branch_solved and bs["attempts"] >= max_attempts:
                bs["status"] = "deferred"

        # --- Step 6: Summary ---
        elapsed = time.time() - t0
        log(f"\n=== Agent cycle {current_cycle} complete ===")
        log(f"Solved: {solved_count}, Skipped: {skipped_count}, "
            f"Total frontier: {len(frontier)}")
        log(f"Results written: {result_index} seeds")
        log(f"Elapsed: {elapsed:.1f}s")

        # If no seeds generated via LLM, fall back to heuristics
        if result_index == 0:
            log("No branches solved, adding heuristic seeds as fallback")
            _fallback_heuristic(seeds, results_dir, start_index=result_index)

        # --- Step 7: Persist state ---
        save_state(state, state_dir)

    except Exception as e:
        log(f"FATAL: {e}")
        log(traceback.format_exc())
        # Try heuristic fallback on any error
        try:
            _fallback_heuristic(seeds, results_dir)
        except Exception:
            pass
    finally:
        (agent_dir / "done").touch()
        log("Signaled done.")
        if _log_file:
            _log_file.close()


def _fallback_heuristic(
    seeds: dict[str, bytes], results_dir: Path, start_index: int = 0
):
    """Write heuristic seeds as fallback."""
    results_dir.mkdir(parents=True, exist_ok=True)
    heuristic = generate_heuristic_seeds(seeds)
    for i, seed_bytes in enumerate(heuristic):
        path = results_dir / f"agent_seed_{start_index + i:04d}"
        path.write_bytes(seed_bytes)
    log(f"Wrote {len(heuristic)} heuristic fallback seeds")


if __name__ == "__main__":
    main()
