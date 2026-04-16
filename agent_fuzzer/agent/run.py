#!/usr/bin/env python3
"""Agent entrypoint: reactive plateau-breaker with 3 typed strategies.

Invoked by the fuzzer as:  run.py <agent_dir>

Protocol:
  in:  <agent_dir>/seeds/*            corpus exported by the fuzzer
       <agent_dir>/request.json       manifest
  out: <agent_dir>/results/seed_*     verified seeds that flip a blocker
       <agent_dir>/resolved_history.json   (write-only in day-1)
       <agent_dir>/done               signal file

Required environment:
  TARGET_NAME        e.g. libpcap, sqlite3 — picks docker/targets/Dockerfile.<T>.cov
  ANTHROPIC_API_KEY  for Claude

Optional:
  REPO_ROOT                default: inferred (../../ from this file)
  AGENT_MODEL              default: claude-opus-4-6
  AGENT_MAX_BLOCKERS       default: 8
  AGENT_SIDE_A_K           default: 5
  AGENT_BUDGET_SECS        default: 600 (wall-clock for phase 2)
  AGENT_SOURCE_FILTER      substring to restrict branches to target source
                           (e.g. "libpcap"); default: none (all files)
"""

import json
import os
import sys
import time
import traceback
from pathlib import Path

# Run either as script or module
sys.path.insert(0, str(Path(__file__).resolve().parent))

from call_context import (
    find_callers,
    find_enclosing_function,
    find_function_end,
    summarize_call_context,
)
from coverage import (
    ensure_image,
    fetch_source_file,
    find_blockers,
    parse_per_seed_jsons,
    prefetch_source_tree,
    prioritize_blockers,
    read_source_context,
    read_source_line,
    read_source_window,
    run_per_seed_coverage,
    verify_candidates_batch,
)
from strategies import STRATEGY_ORDER


def log(msg: str):
    print(msg, flush=True)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: run.py <agent_dir>", file=sys.stderr)
        return 2
    agent_dir = Path(sys.argv[1]).resolve()
    seeds_dir = agent_dir / "seeds"
    results_dir = agent_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    work_dir = agent_dir / "work"
    work_dir.mkdir(exist_ok=True)
    src_cache = work_dir / "src"
    done_file = agent_dir / "done"
    history_file = agent_dir / "resolved_history.json"

    target = os.environ.get("TARGET_NAME")
    if not target:
        log("[agent] TARGET_NAME not set — aborting")
        done_file.touch()
        return 1

    repo_root = Path(os.environ.get(
        "REPO_ROOT", Path(__file__).resolve().parents[2]
    )).resolve()
    source_filter = os.environ.get("AGENT_SOURCE_FILTER") or None
    max_blockers = int(os.environ.get("AGENT_MAX_BLOCKERS", "8"))
    side_a_k = int(os.environ.get("AGENT_SIDE_A_K", "5"))
    budget_secs = float(os.environ.get("AGENT_BUDGET_SECS", "600"))
    blocker_secs = float(os.environ.get("AGENT_BLOCKER_SECS", "90"))

    t0 = time.time()
    log(f"[agent] start  target={target}  repo={repo_root}  budget={budget_secs:.0f}s")

    seed_paths = sorted(p for p in seeds_dir.iterdir() if p.is_file())
    log(f"[agent] {len(seed_paths)} seeds in queue")
    if not seed_paths:
        done_file.touch()
        return 0

    # Phase 0: ensure docker image
    try:
        ensure_image(target, repo_root, log=log)
    except Exception as e:
        log(f"[agent] image build failed: {e}")
        done_file.touch()
        return 1

    # Phase 1: per-seed branch map
    log("[agent] phase 1: per-seed coverage")
    json_dir = run_per_seed_coverage(target, seeds_dir, work_dir / "cov", log=log)
    branch_index, per_seed = parse_per_seed_jsons(json_dir, source_filter)
    log(f"[agent]   {len(branch_index)} branches across {len(per_seed)} seeds")
    if not branch_index:
        log("[agent] no branches observed — aborting")
        done_file.touch()
        return 0

    blockers = find_blockers(branch_index, per_seed)
    log(f"[agent]   {len(blockers)} one-sided branches (blockers)")

    # Prefetch source tree for fast rule + source-context + call-site lookups.
    # Derive container root: explicit path in AGENT_SOURCE_FILTER, else /src/<target>.
    if source_filter and source_filter.startswith("/"):
        src_container_root = source_filter.rstrip("/")
    else:
        src_container_root = f"/src/{target}"
    prefetch_source_tree(target, src_container_root, src_cache, log=log)

    ranked = prioritize_blockers(
        blockers,
        line_fetcher=lambda br: read_source_line(target, br, src_cache),
        window_fetcher=lambda br: read_source_window(target, br, src_cache),
        corpus_size=len(per_seed),
        log=log,
    )
    if ranked:
        log(f"[agent]   top blocker affinity={ranked[0][3]} side_a={len(ranked[0][2])}")

    # Phase 2: breadth-first passes — each pass applies ONE strategy across
    # all still-unresolved blockers. Cheapest strategy runs first; harder
    # strategies only re-visit blockers that the earlier passes missed.
    log(f"[agent] phase 2: up to {max_blockers} blockers, passes="
        f"{[n for n, _ in STRATEGY_ORDER]}")

    # Pre-load side-A bytes + source context once per blocker.
    pending = []
    for branch, missing_side, side_a_names, affinity in ranked[:max_blockers]:
        if not side_a_names:
            continue
        side_a = []
        for name in side_a_names[:side_a_k]:
            try:
                side_a.append((name, (seeds_dir / name).read_bytes()))
            except OSError:
                continue
        if not side_a:
            continue
        source_ctx = read_source_context(target, branch, src_cache)
        # Gather call-site context: enclosing function + callers from src tree.
        call_ctx_str = None
        enclosing_range: tuple[int, int] | None = None
        try:
            local_src = fetch_source_file(target, branch.file, src_cache)
            if local_src is not None:
                enc = find_enclosing_function(local_src, branch.line_start)
                callers = []
                if enc:
                    tree_root = src_cache / src_container_root.lstrip("/")
                    callers = find_callers(
                        enc["name"], tree_root,
                        exclude_def_file=branch.file.split("/")[-1],
                        exclude_def_line=enc["signature_line"],
                    )
                    end_line = find_function_end(local_src, enc["signature_line"])
                    if end_line:
                        enclosing_range = (enc["signature_line"], end_line)
                call_ctx_str = summarize_call_context(enc, callers)
        except Exception as e:
            log(f"    call_ctx error for {branch.id}: {e}")
        pending.append({
            "branch": branch,
            "missing_side": missing_side,
            "affinity": affinity,
            "side_a": side_a,
            "source_ctx": source_ctx,
            "call_ctx": call_ctx_str,
            "enclosing_range": enclosing_range,
        })
    log(f"[agent]   {len(pending)} blockers have side-A witnesses")

    resolved = []
    seed_counter = 0
    budget_exhausted = False

    for pass_idx, (strat_name, strat_fn) in enumerate(STRATEGY_ORDER):
        if budget_exhausted or not pending:
            break
        log(f"[agent] pass {pass_idx+1}/{len(STRATEGY_ORDER)}: {strat_name}  "
            f"({len(pending)} blockers)")
        next_pending = []
        for b_idx, entry in enumerate(pending):
            elapsed = time.time() - t0
            if elapsed >= budget_secs:
                log(f"  cycle budget exhausted at pass {pass_idx+1} blocker {b_idx} "
                    f"({elapsed:.0f}s) — stop")
                # Remaining blockers carry forward only in the "still pending"
                # sense within this invocation; we're quitting the agent.
                next_pending.extend(pending[b_idx:])
                budget_exhausted = True
                break
            branch = entry["branch"]
            missing_side = entry["missing_side"]
            log(f"  [{b_idx+1}/{len(pending)}] {branch.id}  "
                f"missing={missing_side}  aff={entry['affinity']}")
            blocker_deadline = time.time() + blocker_secs
            try:
                candidates = strat_fn(branch, missing_side, entry["source_ctx"],
                                      entry["side_a"], log,
                                      call_ctx=entry.get("call_ctx"))
            except Exception as e:
                log(f"    strategy error: {e}")
                next_pending.append(entry)
                continue
            if time.time() >= blocker_deadline:
                log(f"    blocker budget ({blocker_secs:.0f}s) exceeded during LLM — skip verify")
                next_pending.append(entry)
                continue
            log(f"    {len(candidates)} candidates")
            if not candidates:
                next_pending.append(entry)
                continue
            vresults = verify_candidates_batch(
                target, candidates, branch, missing_side,
                work_dir / f"verify_p{pass_idx}_{b_idx}_{strat_name}",
                enclosing_range=entry.get("enclosing_range"),
            )
            n_flipped = sum(r.flipped for r in vresults)
            n_opposite = sum(r.took_opposite and not r.flipped for r in vresults)
            n_reached = sum(r.reached_func and not r.flipped and not r.took_opposite
                             for r in vresults)
            log(f"    verify: {n_flipped}/{len(vresults)} flipped  "
                f"{n_opposite} took-opposite  {n_reached} reached-func-only")
            flipped = False
            for c_idx, (cand, vr) in enumerate(zip(candidates, vresults)):
                if not vr.flipped:
                    continue
                seed_counter += 1
                out_path = results_dir / f"seed_{seed_counter:04d}"
                out_path.write_bytes(cand)
                log(f"    ✓ FLIPPED by {strat_name}#{c_idx} → {out_path.name}")
                resolved.append({
                    "pass": pass_idx + 1,
                    "strategy": strat_name,
                    "branch": branch.id,
                    "missing_side": missing_side,
                    "candidate_index": c_idx,
                    "seed_bytes": len(cand),
                    "output": out_path.name,
                })
                flipped = True
                break
            if not flipped:
                next_pending.append(entry)
        pending = next_pending
        log(f"[agent] pass {pass_idx+1} done: {len(pending)} still unresolved")

    # Phase 3: history (write-only in day-1)
    history_file.write_text(json.dumps(
        {"cycle_timestamp": int(t0), "resolved": resolved}, indent=2,
    ))

    elapsed = time.time() - t0
    log(f"[agent] done  resolved={len(resolved)}  wrote={seed_counter}  "
        f"elapsed={elapsed:.1f}s")
    done_file.touch()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        try:
            (Path(sys.argv[1]) / "done").touch()
        except Exception:
            pass
        sys.exit(1)
