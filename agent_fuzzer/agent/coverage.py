"""Docker-backed coverage: per-seed branch mapping, source extraction, verify."""

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"
PER_SEED_SCRIPT = SCRIPTS_DIR / "cov_per_seed.sh"


@dataclass(frozen=True)
class Branch:
    file: str
    line_start: int
    col_start: int
    line_end: int
    col_end: int

    @property
    def id(self) -> str:
        return f"{self.file}:{self.line_start}:{self.col_start}"


@dataclass
class VerifyResult:
    """Richer per-candidate signal — lets strategies (and invention) reason
    about HOW close a candidate got, not just pass/fail."""
    flipped: bool              # hit the missing side (success)
    took_opposite: bool        # hit the non-missing side (reached branch, wrong path)
    reached_func: bool         # any branch in enclosing function was hit
    missing_side_count: int
    opposite_side_count: int
    func_branches_hit: int     # how many branches in the enclosing func had count>0


def image_name(target: str) -> str:
    return f"agent-cov-{target}"


def _image_exists(name: str) -> bool:
    r = subprocess.run(
        ["docker", "image", "inspect", name],
        capture_output=True,
    )
    return r.returncode == 0


def ensure_image(target: str, repo_root: Path, log=print) -> str:
    """Ensure agent-cov-<target> exists; build it (and base) if missing."""
    tag = image_name(target)
    if _image_exists(tag):
        log(f"[cov] reusing image {tag}")
        return tag

    base_dockerfile = repo_root / "docker" / "Dockerfile.coverage-base"
    target_dockerfile = repo_root / "docker" / "targets" / f"Dockerfile.{target}.cov"
    if not target_dockerfile.exists():
        raise FileNotFoundError(f"missing {target_dockerfile}")

    if not _image_exists("libafl-coverage-base"):
        log("[cov] building libafl-coverage-base...")
        subprocess.run(
            ["docker", "build", "-f", str(base_dockerfile),
             "-t", "libafl-coverage-base", str(repo_root)],
            check=True,
        )

    log(f"[cov] building {tag} from {target_dockerfile.name}...")
    subprocess.run(
        ["docker", "build", "-f", str(target_dockerfile),
         "-t", tag, str(repo_root)],
        check=True,
    )
    return tag


# ── per-seed coverage ──────────────────────────────────────────────────────

def run_per_seed_coverage(
    target: str,
    seeds_dir: Path,
    out_dir: Path,
    log=print,
) -> Path:
    """Run the per-seed coverage container, return the dir of per-seed JSONs."""
    tag = image_name(target)
    out_dir.mkdir(parents=True, exist_ok=True)
    # Clean prior run's json dir so stale files don't leak
    json_dir = out_dir / "json"
    if json_dir.exists():
        shutil.rmtree(json_dir)

    cmd = [
        "docker", "run", "--rm",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{seeds_dir}:/seeds:ro",
        "-v", f"{out_dir}:/out",
        "-v", f"{PER_SEED_SCRIPT}:/cov_per_seed.sh:ro",
        "--entrypoint", "/cov_per_seed.sh",
        tag,
        "/seeds", "/out",
    ]
    log(f"[cov] per-seed container: {len(list(seeds_dir.iterdir()))} seeds")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.stdout.strip():
        log(f"  {r.stdout.strip()}")
    if r.returncode != 0:
        log(f"  container exit={r.returncode} stderr={r.stderr[:500]}")
    return json_dir


def parse_per_seed_jsons(
    json_dir: Path,
    source_filter: str | None = None,
) -> tuple[dict[str, Branch], dict[str, dict[str, tuple[int, int]]]]:
    """Return (branch_index, per_seed_counts).

    branch_index: id -> Branch
    per_seed_counts: seed_name -> id -> (true, false)
    """
    branch_index: dict[str, Branch] = {}
    per_seed: dict[str, dict[str, tuple[int, int]]] = {}
    if not json_dir.is_dir():
        return branch_index, per_seed

    for jf in sorted(json_dir.iterdir()):
        if not jf.is_file() or not jf.name.endswith(".json"):
            continue
        seed_name = jf.name[:-5]
        try:
            data = json.loads(jf.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        counts: dict[str, tuple[int, int]] = {}
        for entry in data.get("data", []):
            for fd in entry.get("files", []):
                fname = fd.get("filename", "")
                if source_filter and source_filter not in fname:
                    continue
                for br in fd.get("branches", []):
                    if len(br) < 6:
                        continue
                    b = Branch(fname, br[0], br[1], br[2], br[3])
                    branch_index[b.id] = b
                    counts[b.id] = (int(br[4]), int(br[5]))
        per_seed[seed_name] = counts
    return branch_index, per_seed


def find_blockers(
    branch_index: dict[str, Branch],
    per_seed: dict[str, dict[str, tuple[int, int]]],
) -> list[tuple[Branch, str, list[str]]]:
    """One-sided branches. Returns [(branch, missing_side, side_a_seed_names), ...].

    Unordered — prioritize_blockers() should be called to rank.
    """
    total: dict[str, tuple[int, int]] = {}
    for counts in per_seed.values():
        for bid, (t, f) in counts.items():
            pt, pf = total.get(bid, (0, 0))
            total[bid] = (pt + t, pf + f)

    blockers = []
    for bid, (t, f) in total.items():
        if (t > 0) == (f > 0):
            continue
        missing = "true" if t == 0 else "false"
        taken = "false" if missing == "true" else "true"
        side_a = [
            name for name, cc in per_seed.items()
            if ((taken == "true" and cc.get(bid, (0, 0))[0] > 0) or
                (taken == "false" and cc.get(bid, (0, 0))[1] > 0))
        ]
        blockers.append((branch_index[bid], missing, side_a))
    return blockers


# ── Negative-rule filter ───────────────────────────────────────────────────

# Path fragments that indicate non-productive code (generated, test scaffolding).
_PATH_EXCLUDES = ["/build/", "/testprogs/", "/tests/", "/test/",
                  "/fuzzing/", "/examples/", "/third_party/"]

# Lines matching any of these patterns are likely unproductive blockers:
# null-pointer checks (unreachable from harness), assertions, error returns.
_NEGATIVE_PATTERNS = [
    re.compile(r"==\s*(NULL|nullptr)\b"),
    re.compile(r"!=\s*(NULL|nullptr)\b"),
    re.compile(r"\bassert\s*\("),
    re.compile(r"\babort\s*\("),
    re.compile(r"\bpanic\s*\("),
    re.compile(r"\b_?exit\s*\("),
    re.compile(r"\bfatal\w*\s*\("),
    re.compile(r"return\s+(-1|NULL|nullptr|false)\b"),
    # pointer == 0 idioms like `if (pc == 0)` for named pointer-ish vars
    re.compile(r"\bif\s*\(\s*\w*(ptr|p|pc|buf|ctx|handle|fp)\s*==\s*0\s*\)", re.I),
    re.compile(r"\bif\s*\(\s*!\s*\w+\s*\)"),
]


_SEMANTIC_COMMENT_RE = re.compile(r"/\*|//")
_UPPER_IDENT_RE = re.compile(r"\b[A-Z_][A-Z0-9_]{3,}\b")
_STRING_CMP_RE = re.compile(
    r"(memcmp|strncmp|strcmp|strncasecmp|strcasecmp)\s*\(|==\s*[\"']"
)
_CASE_RE = re.compile(r"\bcase\s+[^:]+:")
_NAMED_EQ_RE = re.compile(r"==\s*[A-Z_][A-Z0-9_]*\b")


def semantic_affinity(window: str) -> int:
    """Score how answerable a blocker is via semantic_guess (source reading)."""
    s = 0
    if _SEMANTIC_COMMENT_RE.search(window):
        s += 2
    if _NAMED_EQ_RE.search(window):
        s += 2
    if _STRING_CMP_RE.search(window):
        s += 1
    if _CASE_RE.search(window):
        s += 1
    if _UPPER_IDENT_RE.search(window):
        s += 1
    return s


def prioritize_blockers(
    blockers: list[tuple[Branch, str, list[str]]],
    line_fetcher,
    window_fetcher,
    corpus_size: int,
    log=print,
) -> list[tuple[Branch, str, list[str], int]]:
    """Filter out unproductive blockers, rank the rest.

    Returns [(branch, missing_side, side_a, affinity), ...] sorted.

    line_fetcher(branch) -> single branch line
    window_fetcher(branch) -> multi-line context around the branch
    """
    kept_path = []
    drop_path = 0
    for b, m, sa in blockers:
        if any(p in b.file for p in _PATH_EXCLUDES):
            drop_path += 1
            continue
        kept_path.append((b, m, sa))

    kept_ratio = []
    drop_ratio = 0
    # Skip ratio filter for tiny corpora — 0.9*N rounds down to cover every
    # blocker, and the "nearly all seeds reach side-A" inference is meaningless
    # without a decent sample size.
    if corpus_size >= 10:
        ceil = int(corpus_size * 0.9)
        for b, m, sa in kept_path:
            if len(sa) >= ceil:
                drop_ratio += 1
                continue
            kept_ratio.append((b, m, sa))
    else:
        kept_ratio = kept_path

    kept_neg = []
    drop_neg = 0
    scored: list[tuple[Branch, str, list[str], int]] = []
    for b, m, sa in kept_ratio:
        try:
            line = line_fetcher(b)
        except Exception:
            line = ""
        if any(p.search(line) for p in _NEGATIVE_PATTERNS):
            drop_neg += 1
            continue
        kept_neg.append((b, m, sa))
        try:
            win = window_fetcher(b)
        except Exception:
            win = line
        scored.append((b, m, sa, semantic_affinity(win)))

    log(f"[cov] prioritize: drop path={drop_path} ratio={drop_ratio} "
        f"neg={drop_neg}  kept={len(scored)}/{len(blockers)}")

    mid = corpus_size / 2.0
    scored.sort(key=lambda x: (-x[3], abs(len(x[2]) - mid), x[0].id))
    return scored


# Back-compat shim; new code should use prioritize_blockers.
def filter_negative_blockers(blockers, source_fetcher, log=print):
    kept = []
    dropped = 0
    for br, miss, sa in blockers:
        try:
            line = source_fetcher(br)
        except Exception:
            line = ""
        if any(p.search(line) for p in _NEGATIVE_PATTERNS):
            dropped += 1
            continue
        kept.append((br, miss, sa))
    return kept, dropped


# ── source extraction (cached) ─────────────────────────────────────────────

def prefetch_source_tree(
    target: str, container_root: str, cache_dir: Path, log=print,
) -> bool:
    """Extract the source tree under container_root into cache_dir in ONE docker run.

    Creates a marker file so repeat calls are no-ops. Returns True on success.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / f".prefetched_{container_root.replace('/', '_').lstrip('_')}"
    if marker.exists():
        return True
    tag = image_name(target)
    log(f"[cov] prefetching {container_root} from {tag}...")
    # tar the dir from container stdout, untar into cache_dir
    r = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "tar",
         tag, "-C", "/", "-cf", "-", container_root.lstrip("/")],
        capture_output=True,
    )
    if r.returncode != 0:
        log(f"  prefetch failed: {r.stderr[:300]!r}")
        return False
    u = subprocess.run(
        ["tar", "-xf", "-", "-C", str(cache_dir)],
        input=r.stdout,
    )
    if u.returncode != 0:
        log("  untar failed")
        return False
    marker.touch()
    return True


def fetch_source_file(target: str, container_path: str, cache_dir: Path) -> Path | None:
    """Return local path for a container source file. Uses prefetch tree if present,
    falls back to single-file docker cat.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    # Prefetched layout: <cache_dir>/<container_path_without_leading_slash>
    tree_local = cache_dir / container_path.lstrip("/")
    if tree_local.exists():
        return tree_local
    # Legacy flat cache key (from single-file cat path)
    safe = container_path.replace("/", "_").lstrip("_")
    flat_local = cache_dir / safe
    if flat_local.exists():
        return flat_local
    tag = image_name(target)
    r = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "cat", tag, container_path],
        capture_output=True,
    )
    if r.returncode != 0:
        return None
    flat_local.write_bytes(r.stdout)
    return flat_local


def read_source_context(
    target: str,
    branch: Branch,
    cache_dir: Path,
    context_lines: int = 25,
) -> str:
    local = fetch_source_file(target, branch.file, cache_dir)
    if not local:
        return f"[could not fetch {branch.file}]"
    try:
        lines = local.read_text(errors="replace").splitlines()
    except OSError:
        return f"[could not read cached {local}]"
    start = max(0, branch.line_start - context_lines - 1)
    end = min(len(lines), branch.line_start + context_lines)
    out = []
    for i in range(start, end):
        marker = "  >>> " if (i + 1) == branch.line_start else "      "
        out.append(f"{marker}{i+1:>5}| {lines[i]}")
    return f"=== {branch.file}:{branch.line_start} ===\n" + "\n".join(out)


# ── verification ───────────────────────────────────────────────────────────

def verify_candidates_batch(
    target: str,
    candidates: list[bytes],
    target_branch: Branch,
    missing_side: str,
    work_dir: Path,
    enclosing_range: tuple[int, int] | None = None,
) -> list[VerifyResult]:
    """Run all candidates in one docker container, return per-candidate verify info.

    enclosing_range=(start_line, end_line) enables the `reached_func` and
    `func_branches_hit` signals — the coverage pipeline already produces the
    data; we just slice the branches list by line range.
    """
    if not candidates:
        return []
    work_dir.mkdir(parents=True, exist_ok=True)
    verify_seeds = work_dir / "seeds"
    if verify_seeds.exists():
        shutil.rmtree(verify_seeds)
    verify_seeds.mkdir()
    names = []
    for i, data in enumerate(candidates):
        name = f"cand_{i:03d}"
        (verify_seeds / name).write_bytes(data)
        names.append(name)

    out_dir = work_dir / "out"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir()

    tag = image_name(target)
    r = subprocess.run(
        [
            "docker", "run", "--rm",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{verify_seeds}:/seeds:ro",
            "-v", f"{out_dir}:/out",
            "-v", f"{PER_SEED_SCRIPT}:/cov_per_seed.sh:ro",
            "--entrypoint", "/cov_per_seed.sh",
            tag,
            "/seeds", "/out",
        ],
        capture_output=True, text=True,
    )
    empty = lambda: VerifyResult(False, False, False, 0, 0, 0)
    if r.returncode != 0:
        return [empty() for _ in candidates]

    results: list[VerifyResult] = []
    lo, hi = (enclosing_range if enclosing_range
              else (target_branch.line_start, target_branch.line_start))
    for name in names:
        json_file = out_dir / "json" / f"{name}.json"
        vr = empty()
        if json_file.exists():
            try:
                data = json.loads(json_file.read_text())
                for d_entry in data.get("data", []):
                    for fd in d_entry.get("files", []):
                        if fd.get("filename", "") != target_branch.file:
                            continue
                        for br in fd.get("branches", []):
                            if len(br) < 6:
                                continue
                            line, col = br[0], br[1]
                            t_cnt, f_cnt = br[4], br[5]
                            # Target-branch accounting
                            if (line, col) == (target_branch.line_start,
                                                target_branch.col_start):
                                miss = t_cnt if missing_side == "true" else f_cnt
                                opp = f_cnt if missing_side == "true" else t_cnt
                                vr.missing_side_count = miss
                                vr.opposite_side_count = opp
                                vr.flipped = miss > 0
                                vr.took_opposite = opp > 0
                            # Enclosing-function accounting
                            if lo <= line <= hi and (t_cnt > 0 or f_cnt > 0):
                                vr.func_branches_hit += 1
                                vr.reached_func = True
            except json.JSONDecodeError:
                pass
        results.append(vr)
    return results


def read_source_line(target: str, branch: Branch, cache_dir: Path) -> str:
    """Return just the branch's source line (for negative-rule filtering)."""
    local = fetch_source_file(target, branch.file, cache_dir)
    if not local:
        return ""
    try:
        lines = local.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    i = branch.line_start - 1
    return lines[i] if 0 <= i < len(lines) else ""


def read_source_window(
    target: str, branch: Branch, cache_dir: Path, radius: int = 5,
) -> str:
    """Return a small source window (for affinity scoring)."""
    local = fetch_source_file(target, branch.file, cache_dir)
    if not local:
        return ""
    try:
        lines = local.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    i = branch.line_start - 1
    lo = max(0, i - radius)
    hi = min(len(lines), i + radius + 1)
    return "\n".join(lines[lo:hi])
