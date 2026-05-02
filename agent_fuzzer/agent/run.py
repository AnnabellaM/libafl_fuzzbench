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
    harvest_incidental_flips,
    harvest_loop_coverage,
    parse_per_seed_jsons,
    prefetch_source_tree,
    prioritize_blockers,
    read_source_context,
    read_source_line,
    read_source_window,
    run_per_seed_coverage,
    verify_candidates_batch,
)
from reachability import (
    classify_context,
    extract_build_defines,
    read_harness,
)
from state import (
    add_to_backlog,
    append_session_to_history,
    auto_promote_backlog,
    is_discarded,
    load_state,
    mark_discarded,
    record_strategy_outcome,
    save_state,
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
    use_loop = os.environ.get("AGENT_USE_LOOP", "0") == "1"
    loop_parallel = int(os.environ.get("AGENT_LOOP_PARALLEL", "10"))
    loop_max_turns = int(os.environ.get("AGENT_LOOP_MAX_TURNS", "15"))
    loop_blocker_timeout = int(os.environ.get("AGENT_LOOP_TIMEOUT_SECS", "180"))
    loop_model = os.environ.get("AGENT_MODEL", "claude-opus-4-6")

    t0 = time.time()
    session_id = int(t0)
    log(f"[agent] start  target={target}  repo={repo_root}  "
        f"budget={budget_secs:.0f}s  session_id={session_id}")

    # Load cross-session state (backlog, discarded, strategy library, history).
    # Missing files → empty containers; legacy resolved_history.json is migrated.
    backlog, discarded, strategy_library, history = load_state(agent_dir)
    log(f"[agent] state: backlog={len(backlog)} discarded={len(discarded)} "
        f"strategies_tracked={len(strategy_library)} "
        f"history_sessions={len(history.get('sessions', []))}")

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

    # Cap the seed pool handed to phase-1 coverage. Per-seed coverage goes
    # through docker (~5ms of llvm-cov work + ~1-2 MB of JSON serialization
    # per seed), so N=15k seeds takes ~25 min — way beyond a plateau-break
    # budget. 500 representative seeds is enough to identify top blockers.
    seed_limit = int(os.environ.get("AGENT_SEED_LIMIT", "500"))
    sampled_dir = seeds_dir
    if seed_limit > 0 and len(seed_paths) > seed_limit:
        import random
        # Deterministic per-session sample: sort by mtime so we always keep
        # the most recent N, which are most likely to reflect current
        # fuzzer state and discovered structural patterns.
        by_mtime = sorted(seed_paths, key=lambda p: p.stat().st_mtime, reverse=True)
        recent = by_mtime[: seed_limit // 2]
        # Plus a random sample from the rest for diversity.
        rest = by_mtime[seed_limit // 2 :]
        random.Random(session_id).shuffle(rest)
        sampled = recent + rest[: seed_limit - len(recent)]
        sampled_dir = work_dir / "sampled_seeds"
        if sampled_dir.exists():
            import shutil as _sh
            _sh.rmtree(sampled_dir)
        sampled_dir.mkdir(parents=True)
        # Copy (not symlink) — docker container mounts sampled_dir and cannot
        # follow symlinks to absolute paths on the host.
        for p in sampled:
            try:
                (sampled_dir / p.name).write_bytes(p.read_bytes())
            except OSError as e:
                log(f"    sample copy skipped for {p.name}: {e}")
        log(f"[agent] seed pool capped: {len(seed_paths)} → "
            f"{len(sampled)} (AGENT_SEED_LIMIT={seed_limit})")

    # Phase 1: per-seed branch map
    log("[agent] phase 1: per-seed coverage")
    json_dir = run_per_seed_coverage(target, sampled_dir, work_dir / "cov", log=log)
    branch_index, per_seed = parse_per_seed_jsons(json_dir, source_filter)
    log(f"[agent]   {len(branch_index)} branches across {len(per_seed)} seeds")
    if not branch_index:
        log("[agent] no branches observed — aborting")
        done_file.touch()
        return 0

    # Backlog auto-promotion: any prior-session backlog entry whose missing
    # side is now covered by the current corpus is moved to resolved. Credit
    # lineage tracking lands in Stage C; here we only detect and record.
    backlog, promoted_entries = auto_promote_backlog(backlog, per_seed)
    if promoted_entries:
        log(f"[agent] auto-promoted {len(promoted_entries)} blockers from backlog:")
        for p in promoted_entries:
            log(f"    ↑ {p['branch_id']} missing={p['missing_side']} "
                f"(was backlogged in session {p.get('last_session_tried')})")

    blockers = find_blockers(branch_index, per_seed)
    log(f"[agent]   {len(blockers)} one-sided branches (blockers)")

    # Drop blockers already on discarded list — never retry.
    if discarded:
        pre = len(blockers)
        blockers = [b for b in blockers if not is_discarded(discarded, b[0].id)]
        dropped = pre - len(blockers)
        if dropped:
            log(f"[agent]   dropped {dropped} discarded blockers from pending")

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
        enclosing_name: str = ""
        enclosing_body: str = ""
        try:
            local_src = fetch_source_file(target, branch.file, src_cache)
            if local_src is not None:
                enc = find_enclosing_function(local_src, branch.line_start)
                callers = []
                if enc:
                    enclosing_name = enc.get("name", "")
                    tree_root = src_cache / src_container_root.lstrip("/")
                    callers = find_callers(
                        enc["name"], tree_root,
                        exclude_def_file=branch.file.split("/")[-1],
                        exclude_def_line=enc["signature_line"],
                    )
                    end_line = find_function_end(local_src, enc["signature_line"])
                    if end_line:
                        enclosing_range = (enc["signature_line"], end_line)
                        # Extract the enclosing function body for the
                        # reachability oracle (same content as the workspace
                        # `enclosing_function.c` the agent sees later).
                        try:
                            src_lines = local_src.read_text(errors="replace").splitlines()
                            body_lines = src_lines[enc["signature_line"] - 1 : end_line]
                            enclosing_body = "\n".join(body_lines)
                        except Exception:
                            pass
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
            "enclosing_name": enclosing_name,
            "enclosing_body": enclosing_body,
            # Accumulated during Phase 2; flushed to backlog on exit.
            "tried_strategies": [],
            "last_verify_result": None,
            "last_candidate": None,
        })
    log(f"[agent]   {len(pending)} blockers have side-A witnesses")

    # ── Reachability pre-filter ────────────────────────────────────────────
    # For each pending blocker: cheap defensive-assert scan first, then
    # single-turn LLM oracle. Unreachable verdicts feed directly into
    # `discarded.json` so subsequent sessions skip the same blocker for
    # free. Intra-session memo amortizes the oracle cost across blockers
    # that share a predicate shape inside the same enclosing function.
    if os.environ.get("AGENT_REACHABILITY", "1") == "1" and pending:
        # Locate the fuzz harness source. Explicit env overrides auto-discovery;
        # otherwise search the prefetched tree for a `*<FUZZ_BIN>*.c` file.
        harness_path_env = os.environ.get("AGENT_HARNESS_PATH")
        harness_text = ""
        harness_source = "(none)"
        if harness_path_env:
            harness_text = read_harness(Path(harness_path_env))
            harness_source = harness_path_env
        else:
            fuzz_bin = os.environ.get("FUZZ_BIN", "").strip()
            if fuzz_bin and src_cache.exists():
                candidates = list(src_cache.rglob(f"{fuzz_bin}.c")) \
                    or list(src_cache.rglob(f"*{fuzz_bin}*.c"))
                # Prefer files under a `fuzz/` directory.
                candidates.sort(key=lambda p: (0 if "/fuzz/" in str(p) else 1, len(str(p))))
                if candidates:
                    harness_text = read_harness(candidates[0])
                    harness_source = str(candidates[0])
        log(f"[agent] reachability harness: {harness_source}  ({len(harness_text)}c)")
        build_log = None
        for cand in (
            agent_dir.parent.parent / "build-agent.log",
            agent_dir.parent / "build-agent.log",
        ):
            if cand.exists():
                build_log = cand
                break
        build_defines = extract_build_defines(build_log) if build_log else []
        log(f"[agent] reachability pre-filter: build_log={'set' if build_log else 'NONE'}  "
            f"defines={len(build_defines)}")

        memo: dict = {}
        kept: list[dict] = []
        t_reach = time.time()
        # Local source tree for the dead-return callee filter. We already
        # prefetched to `src_cache / src_container_root.lstrip("/")`.
        source_tree = src_cache / src_container_root.lstrip("/")
        if not source_tree.exists():
            source_tree = None
        for e in pending:
            br = e["branch"]
            branch_src_text = (
                f"{br.file}:{br.line_start}\n"
                f"missing_side={e['missing_side']}\n\n"
                + e["source_ctx"]
            )
            v = classify_context(
                branch_src_text,
                e["enclosing_body"] or "[enclosing unavailable]",
                e["call_ctx"] or "",
                harness_text, build_defines,
                enclosing_name=e["enclosing_name"],
                branch_file=br.file,
                source_tree=source_tree,
                memo=memo,
                log=log,
            )
            if v.reachable:
                kept.append(e)
                continue
            # Record in discarded.json with category + evidence; next session
            # auto-skips. Evidence includes the oracle source so a later
            # reviewer can audit whether a verdict was cheap (substring),
            # memoized, or oracle-sourced.
            mark_discarded(
                discarded, br.id,
                reason=v.category or "unreachable",
                evidence=f"[{v.source}] {v.reason}",
                session_id=session_id,
            )
            log(f"  DROP {br.id}  [{v.source}/{v.category}] {v.reason[:140]}")
        reach_dt = time.time() - t_reach
        log(f"[agent] reachability: kept {len(kept)}/{len(pending)} "
            f"(dropped {len(pending) - len(kept)}, wall={reach_dt:.1f}s)")
        pending = kept

    resolved = []
    seed_counter = 0
    budget_exhausted = False
    # Ids of blockers auto-promoted via multi-target coverage harvest. Skipped
    # on subsequent blocker iterations and excluded from next-pass pending.
    harvested_ids: set[str] = set()

    # ── Phase 2 mode A: loop-based resolution (parallel resolve_blocker) ────
    if use_loop:
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from loop import resolve_blocker

        log(f"[agent] phase 2 (LOOP mode): {len(pending)} blockers × "
            f"parallel={loop_parallel}  max_turns={loop_max_turns}  "
            f"per_blocker_to={loop_blocker_timeout}s  budget={budget_secs:.0f}s")
        t_phase2 = time.time()
        pool = ThreadPoolExecutor(max_workers=loop_parallel)

        # Shared state for cross-blocker harvest across parallel agents.
        # `harvested_ids` captures both primary flips and incidental flips —
        # any entry listed here is already credited and should not be
        # re-attempted by a worker that hasn't started yet.
        loop_resolved_lock = threading.Lock()

        def _run_one(e):
            with loop_resolved_lock:
                if e["branch"].id in harvested_ids:
                    return e, None, "skipped_harvested"
            try:
                return e, resolve_blocker(
                    e, target=target, src_cache=src_cache,
                    work_dir=work_dir, model=loop_model,
                    max_turns=loop_max_turns,
                    timeout_secs=loop_blocker_timeout,
                    log=lambda m: log(f"  [{e['branch'].id}] {m}"),
                ), "ran"
            except Exception as ex:
                log(f"  resolve_blocker error on {e['branch'].id}: {ex}")
                return e, None, "error"

        futures = {pool.submit(_run_one, e): e for e in pending}
        try:
            for fut in as_completed(futures):
                if time.time() - t_phase2 >= budget_secs:
                    log(f"[agent] LOOP budget hit — cancelling pending workers")
                    budget_exhausted = True
                    break
                entry, trace, status = fut.result()
                entry["tried_strategies"].append("loop")
                if status == "skipped_harvested":
                    continue
                if trace is None:
                    continue
                with loop_resolved_lock:
                    if trace.flipped:
                        # Primary credit — this agent's winning seed.
                        seed_counter += 1
                        out_path = results_dir / f"seed_{seed_counter:04d}"
                        out_path.write_bytes(trace.winning_seed)
                        log(f"    ✓ FLIPPED {entry['branch'].id} → {out_path.name}")
                        resolved.append({
                            "pass": 1,
                            "strategy": "loop",
                            "branch": entry["branch"].id,
                            "missing_side": entry["missing_side"],
                            "attempts": len(trace.attempts),
                            "seed_bytes": len(trace.winning_seed),
                            "output": out_path.name,
                        })
                        harvested_ids.add(entry["branch"].id)
                        record_strategy_outcome(strategy_library, "loop", flipped=True)
                    else:
                        # Keep last verify result + candidate for backlog persistence.
                        from coverage import VerifyResult as _VR
                        last_vr = None
                        for a in reversed(trace.attempts):
                            res = (a.get("result") or {})
                            if isinstance(res, dict) and "flipped" in res:
                                last_vr = _VR(
                                    flipped=bool(res.get("flipped", False)),
                                    took_opposite=bool(res.get("took_opposite", False)),
                                    reached_func=bool(res.get("reached_func", False)),
                                    missing_side_count=int(res.get("missing_side_count", 0)),
                                    opposite_side_count=int(res.get("opposite_side_count", 0)),
                                    func_branches_hit=int(res.get("func_branches_hit", 0)),
                                )
                                break
                        entry["last_verify_result"] = last_vr
                        entry["last_candidate"] = trace.winning_seed or b""
                        record_strategy_outcome(strategy_library, "loop", flipped=False)

                    # Cross-blocker harvest: did any of this agent's candidates
                    # incidentally flip another still-pending blocker? Credit
                    # those too, and mark them harvested so a worker that
                    # hasn't started yet skips early.
                    if trace.coverage_dir:
                        unresolved = [
                            p for p in pending
                            if p["branch"].id not in harvested_ids
                            and p["branch"].id != entry["branch"].id
                        ]
                        exclude = set(harvested_ids) | {entry["branch"].id}
                        harvested = harvest_loop_coverage(
                            Path(trace.coverage_dir),
                            unresolved,
                            exclude_branch_ids=exclude,
                        )
                        for h_entry, h_seed in harvested:
                            seed_counter += 1
                            out_path = results_dir / f"seed_{seed_counter:04d}"
                            out_path.write_bytes(h_seed)
                            log(f"    ✓ HARVESTED {h_entry['branch'].id} "
                                f"← {entry['branch'].id} → {out_path.name}")
                            resolved.append({
                                "pass": 1,
                                "strategy": "loop:harvest",
                                "branch": h_entry["branch"].id,
                                "missing_side": h_entry["missing_side"],
                                "attempts": 0,
                                "seed_bytes": len(h_seed),
                                "output": out_path.name,
                                "harvested_from_primary": entry["branch"].id,
                            })
                            harvested_ids.add(h_entry["branch"].id)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        # Anything that didn't flip stays in `pending` for Phase 3 backlog.
        flipped_ids = {r["branch"] for r in resolved}
        pending = [e for e in pending if e["branch"].id not in flipped_ids]
        log(f"[agent] LOOP phase 2 done: flipped={len(resolved)}  "
            f"unresolved={len(pending)}  elapsed={time.time() - t_phase2:.0f}s")

    # ── Phase 2 mode B: legacy strategy-dispatch (STRATEGY_ORDER) ───────────
    for pass_idx, (strat_name, strat_fn) in enumerate(STRATEGY_ORDER if not use_loop else []):
        if budget_exhausted or not pending:
            break
        log(f"[agent] pass {pass_idx+1}/{len(STRATEGY_ORDER)}: {strat_name}  "
            f"({len(pending)} blockers)")
        next_pending = []
        for b_idx, entry in enumerate(pending):
            if entry["branch"].id in harvested_ids:
                continue
            elapsed = time.time() - t0
            if elapsed >= budget_secs:
                log(f"  cycle budget exhausted at pass {pass_idx+1} blocker {b_idx} "
                    f"({elapsed:.0f}s) — stop")
                # Remaining blockers carry forward only in the "still pending"
                # sense within this invocation; we're quitting the agent.
                next_pending.extend(
                    e for e in pending[b_idx:]
                    if e["branch"].id not in harvested_ids
                )
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
            verify_dir = work_dir / f"verify_p{pass_idx}_{b_idx}_{strat_name}"
            vresults = verify_candidates_batch(
                target, candidates, branch, missing_side, verify_dir,
                enclosing_range=entry.get("enclosing_range"),
            )
            # Track this verify attempt in the blocker entry (used if the
            # blocker ends up in backlog at session end).
            entry["tried_strategies"].append(strat_name)
            n_flipped = sum(r.flipped for r in vresults)
            n_opposite = sum(r.took_opposite and not r.flipped for r in vresults)
            n_reached = sum(r.reached_func and not r.flipped and not r.took_opposite
                             for r in vresults)
            log(f"    verify: {n_flipped}/{len(vresults)} flipped  "
                f"{n_opposite} took-opposite  {n_reached} reached-func-only")
            # Record closest near-miss candidate (highest opposite_side_count)
            # for backlog re-pick pivot hint in future sessions.
            best_idx = max(range(len(vresults)),
                           key=lambda i: vresults[i].opposite_side_count)
            entry["last_verify_result"] = vresults[best_idx]
            entry["last_candidate"] = candidates[best_idx]
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
                record_strategy_outcome(strategy_library, strat_name, flipped=True)
                flipped = True
                break
            if not flipped:
                record_strategy_outcome(strategy_library, strat_name, flipped=False)

            # Multi-target coverage harvest: scan this verify run's coverage
            # JSONs against all still-pending blockers and auto-promote any
            # incidentally flipped. One verify → many resolutions when the
            # candidate lands inside a switch that contains multiple pending
            # cases (e.g. the TK_IS/TK_LT/TK_GT cluster in sqlite3).
            harvest_exclude = {r["branch"] for r in resolved}
            harvest_exclude.add(branch.id)  # primary already accounted for
            harvest_exclude.update(harvested_ids)
            harvested = harvest_incidental_flips(
                candidates=candidates,
                verify_work_dir=verify_dir,
                pending=pending,
                exclude_branch_ids=harvest_exclude,
            )
            for h_entry, h_c_idx, h_cand_bytes in harvested:
                seed_counter += 1
                out_path = results_dir / f"seed_{seed_counter:04d}"
                out_path.write_bytes(h_cand_bytes)
                log(f"    ★ HARVESTED: {h_entry['branch'].id} "
                    f"(missing={h_entry['missing_side']}) via cand#{h_c_idx} of {strat_name} "
                    f"→ {out_path.name}")
                resolved.append({
                    "pass": pass_idx + 1,
                    "strategy": f"{strat_name}:harvest",
                    "branch": h_entry["branch"].id,
                    "missing_side": h_entry["missing_side"],
                    "candidate_index": h_c_idx,
                    "seed_bytes": len(h_cand_bytes),
                    "output": out_path.name,
                    "harvested_from_primary": branch.id,
                })
                harvested_ids.add(h_entry["branch"].id)

            if not flipped:
                next_pending.append(entry)
        pending = [e for e in next_pending if e["branch"].id not in harvested_ids]
        log(f"[agent] pass {pass_idx+1} done: {len(pending)} still unresolved")

    # Phase 3: persist state for the next session.
    #   1. Any pending blocker still unresolved (and not harvested) → backlog.
    #   2. Append this session's resolutions + promotions to resolve history.
    #   3. Write backlog.json / discarded.json / strategy_library.json /
    #      resolve_history.json under <agent_dir>/state/.
    for entry in pending:
        if entry["branch"].id in harvested_ids:
            continue
        add_to_backlog(
            backlog,
            branch=entry["branch"],
            missing_side=entry["missing_side"],
            session_id=session_id,
            tried_strategies=entry.get("tried_strategies") or [],
            last_verify_result=entry.get("last_verify_result"),
            last_candidate_bytes=entry.get("last_candidate"),
            enclosing_range=entry.get("enclosing_range"),
        )
    log(f"[agent] backlog: {len(backlog)} entries total "
        f"(+{len([e for e in pending if e['branch'].id not in harvested_ids])} "
        f"from this session)")

    append_session_to_history(
        history,
        session_id=session_id,
        cycle_timestamp=int(t0),
        resolved=resolved,
        promoted=promoted_entries,
    )
    save_state(agent_dir, backlog, discarded, strategy_library, history)
    log(f"[agent] state saved to {agent_dir / 'state'}")

    # Back-compat: also write the legacy top-level resolved_history.json
    # so existing inspection tools keep working.
    history_file.write_text(json.dumps(
        {"cycle_timestamp": int(t0), "resolved": resolved}, indent=2,
    ))

    elapsed = time.time() - t0
    log(f"[agent] done  resolved={len(resolved)}  "
        f"promoted_from_backlog={len(promoted_entries)}  "
        f"wrote={seed_counter}  elapsed={elapsed:.1f}s")
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
