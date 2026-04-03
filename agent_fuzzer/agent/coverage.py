"""LLVM coverage collection, branch analysis, and seed verification."""

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


LLVM_PROFDATA = os.environ.get("LLVM_PROFDATA", "llvm-profdata-18")
LLVM_COV = os.environ.get("LLVM_COV", "llvm-cov-18")


@dataclass
class Branch:
    """A single branch point in the target program."""

    file: str
    line_start: int
    col_start: int
    line_end: int
    col_end: int
    true_count: int
    false_count: int

    @property
    def id(self) -> str:
        return f"{self.file}:{self.line_start}:{self.col_start}"

    @property
    def is_frontier(self) -> bool:
        """One side taken, other side never taken."""
        return (self.true_count > 0) != (self.false_count > 0)

    @property
    def missing_side(self) -> str:
        """Which side has count == 0."""
        return "true" if self.true_count == 0 else "false"

    @property
    def hit_count(self) -> int:
        """Count on the taken side."""
        return max(self.true_count, self.false_count)


# ---------------------------------------------------------------------------
# Coverage collection
# ---------------------------------------------------------------------------


def run_seeds_coverage(
    fuzz_bin: str,
    seed_paths: list[str],
    work_dir: Path,
    batch_size: int = 500,
    log_fn=print,
) -> Path:
    """Run seeds against coverage binary, merge profiles, return profdata path.

    The binary must be compiled with -fprofile-instr-generate -fcoverage-mapping
    and linked with -fsanitize=fuzzer (libfuzzer entry point for replay).
    """
    profraw_dir = work_dir / "profraw"
    profraw_dir.mkdir(parents=True, exist_ok=True)

    # Run in batches
    batch = 0
    for i in range(0, len(seed_paths), batch_size):
        batch_files = seed_paths[i : i + batch_size]
        profraw_path = profraw_dir / f"{batch}.profraw"
        env = os.environ.copy()
        env["LLVM_PROFILE_FILE"] = str(profraw_path)
        try:
            subprocess.run(
                [fuzz_bin] + batch_files,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
            )
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass  # some seeds may crash, that's fine
        batch += 1

    log_fn(f"Ran {batch} batches across {len(seed_paths)} seeds")

    # Merge profiles
    profdata_path = work_dir / "merged.profdata"
    profraw_files = list(profraw_dir.glob("*.profraw"))
    if not profraw_files:
        log_fn("WARNING: No profraw files generated")
        return profdata_path

    subprocess.run(
        [LLVM_PROFDATA, "merge", "-sparse"]
        + [str(f) for f in profraw_files]
        + ["-o", str(profdata_path)],
        check=True,
    )
    log_fn(f"Merged {len(profraw_files)} profiles → {profdata_path}")
    return profdata_path


# ---------------------------------------------------------------------------
# Branch extraction
# ---------------------------------------------------------------------------


def export_branches_json(fuzz_bin: str, profdata_path: Path) -> list[Branch]:
    """Run llvm-cov export and parse branch data from JSON."""
    result = subprocess.run(
        [
            LLVM_COV, "export",
            fuzz_bin,
            f"-instr-profile={profdata_path}",
            "--format=json",
            "--show-branch-summary",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(result.stdout)

    branches = []
    for entry in data.get("data", []):
        for file_data in entry.get("files", []):
            filename = file_data.get("filename", "")
            for br in file_data.get("branches", []):
                # Branch format: [line_start, col_start, line_end, col_end,
                #                  exec_count, false_count, ...]
                if len(br) >= 6:
                    branches.append(Branch(
                        file=filename,
                        line_start=br[0],
                        col_start=br[1],
                        line_end=br[2],
                        col_end=br[3],
                        true_count=br[4],
                        false_count=br[5],
                    ))
    return branches


def get_source_report(fuzz_bin: str, profdata_path: Path) -> str:
    """Run llvm-cov show for human/LLM-readable source-annotated report."""
    result = subprocess.run(
        [
            LLVM_COV, "show",
            fuzz_bin,
            f"-instr-profile={profdata_path}",
            "-show-branches=count",
            "-show-line-counts",
            "-format=text",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def find_frontier_branches(branches: list[Branch]) -> list[Branch]:
    """Filter for one-sided branches (coverage frontier)."""
    return [b for b in branches if b.is_frontier]


# ---------------------------------------------------------------------------
# Source context extraction
# ---------------------------------------------------------------------------


def extract_source_context(
    source_report: str,
    branch: Branch,
    context_lines: int = 30,
) -> str:
    """Extract source context around a branch from llvm-cov show output.

    Returns annotated source lines (with hit counts) centered on the branch.
    """
    # Find the file section in the report
    lines = source_report.split("\n")
    in_file = False
    file_lines = []

    for line in lines:
        # llvm-cov show outputs file headers like: /path/to/file.c:
        if line.strip().endswith(":") and branch.file in line:
            in_file = True
            file_lines = []
            continue
        if in_file:
            # End of file section (next file header or summary)
            if line.strip().endswith(":") and "/" in line and not line.strip().startswith("|"):
                break
            file_lines.append(line)

    if not file_lines:
        # Fallback: try to read the source file directly
        return _read_source_context(branch, context_lines)

    # Find the branch line and extract context window
    target_line = branch.line_start
    # llvm-cov show lines are formatted as: "  LINE_NUM|  COUNT|source"
    start = max(0, target_line - context_lines - 1)
    end = min(len(file_lines), target_line + context_lines)
    context = file_lines[start:end]

    return f"=== {branch.file} around line {target_line} ===\n" + "\n".join(context)


def _read_source_context(branch: Branch, context_lines: int = 30) -> str:
    """Read raw source context directly from the file."""
    try:
        with open(branch.file) as f:
            lines = f.readlines()
    except (FileNotFoundError, PermissionError):
        return f"[Could not read source: {branch.file}]"

    start = max(0, branch.line_start - context_lines - 1)
    end = min(len(lines), branch.line_start + context_lines)
    numbered = [
        f"  {i+1:>5}| {lines[i].rstrip()}"
        for i in range(start, end)
    ]
    marker = f"  >>> FRONTIER BRANCH at line {branch.line_start}, col {branch.col_start}"
    marker += f" (missing {branch.missing_side} side) <<<"

    # Insert marker near the branch line
    insert_pos = branch.line_start - start - 1
    if 0 <= insert_pos < len(numbered):
        numbered.insert(insert_pos + 1, marker)

    return f"=== {branch.file} ===\n" + "\n".join(numbered)


# ---------------------------------------------------------------------------
# Seed verification
# ---------------------------------------------------------------------------


def verify_seed_hits_branch(
    fuzz_bin: str,
    seed_bytes: bytes,
    target_branch: Branch,
    work_dir: Path,
) -> bool:
    """Run a single seed and check if the target branch's missing side is now hit.

    Returns True if the previously-0 side now has count > 0.
    """
    verify_dir = work_dir / "verify"
    verify_dir.mkdir(parents=True, exist_ok=True)

    # Write seed to temp file
    seed_path = verify_dir / "candidate_seed"
    seed_path.write_bytes(seed_bytes)

    # Run with coverage
    profraw_path = verify_dir / "verify.profraw"
    env = os.environ.copy()
    env["LLVM_PROFILE_FILE"] = str(profraw_path)
    try:
        subprocess.run(
            [fuzz_bin, str(seed_path)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass

    if not profraw_path.exists():
        return False

    # Merge (single file, still needed for llvm-cov)
    profdata_path = verify_dir / "verify.profdata"
    try:
        subprocess.run(
            [LLVM_PROFDATA, "merge", "-sparse",
             str(profraw_path), "-o", str(profdata_path)],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        return False

    # Check branch coverage
    try:
        branches = export_branches_json(fuzz_bin, profdata_path)
    except subprocess.CalledProcessError:
        return False

    # Find our target branch
    for b in branches:
        if b.id == target_branch.id:
            if target_branch.missing_side == "true":
                return b.true_count > 0
            else:
                return b.false_count > 0

    return False
