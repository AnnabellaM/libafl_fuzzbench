#!/usr/bin/env python3
"""Preview blockers the agent would attempt, without LLM calls.

Usage: preview_blockers.py <agent_dir> [N=20]

Reuses cached per-seed coverage if present under <agent_dir>/work/cov/json/,
otherwise runs the per-seed container once.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from coverage import (
    ensure_image,
    find_blockers,
    parse_per_seed_jsons,
    read_source_context,
    run_per_seed_coverage,
)


def main():
    agent_dir = Path(sys.argv[1]).resolve()
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    target = os.environ["TARGET_NAME"]
    repo_root = Path(os.environ.get(
        "REPO_ROOT", Path(__file__).resolve().parents[2])).resolve()
    source_filter = os.environ.get("AGENT_SOURCE_FILTER") or None

    seeds_dir = agent_dir / "seeds"
    work_dir = agent_dir / "work"
    json_dir = work_dir / "cov" / "json"
    src_cache = work_dir / "src"

    ensure_image(target, repo_root)
    if not json_dir.is_dir() or not any(json_dir.iterdir()):
        json_dir = run_per_seed_coverage(target, seeds_dir, work_dir / "cov")

    branch_index, per_seed = parse_per_seed_jsons(json_dir, source_filter)
    blockers = find_blockers(branch_index, per_seed)
    print(f"{len(branch_index)} branches, {len(blockers)} blockers, "
          f"{len(per_seed)} seeds\n")

    for i, (branch, missing_side, side_a) in enumerate(blockers[:n]):
        print(f"[{i+1:>3}] {branch.file.split('/')[-1]}:{branch.line_start}:"
              f"{branch.col_start}  missing={missing_side}  side_a={len(side_a)}")
        # Show the source line
        try:
            src_path = work_dir / "src" / branch.file.replace("/", "_").lstrip("_")
            if src_path.exists():
                lines = src_path.read_text(errors="replace").splitlines()
            else:
                # fetch
                ctx = read_source_context(target, branch, src_cache, context_lines=0)
                # Extract center line from ctx
                for ln in ctx.splitlines():
                    if ln.strip().startswith(">>>"):
                        print(f"       {ln.strip()}")
                        break
                continue
            li = branch.line_start - 1
            if 0 <= li < len(lines):
                print(f"       {branch.line_start:>5}| {lines[li].strip()}")
        except Exception:
            pass


if __name__ == "__main__":
    main()
