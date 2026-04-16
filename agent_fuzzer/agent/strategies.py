"""Three typed strategies for blocker resolution.

All three consume side-A seeds as contrastive grounding (the pillar that
distinguishes this design from HyLLfuzz). Cheapest first, early-stop on
first flip:

    1. semantic_guess   — answer visible in source (constants, comments, enums)
    2. constraint_trace — lightweight backward symbolic reasoning
    3. structure_aware  — infer format, emit structurally-valid inputs
"""

import os
import re
import subprocess
from typing import Callable

from coverage import Branch

# Short model alias accepted by `claude -p` (opus|sonnet|haiku) or full id.
_MODEL = os.environ.get("AGENT_MODEL", "sonnet")
_TIMEOUT = int(os.environ.get("AGENT_LLM_TIMEOUT", "120"))


# ── LLM plumbing: `claude -p` routes via the Claude Code subscription ──────

def _call_llm(system: str, user: str, log: Callable) -> str:
    """Shell out to `claude -p`. No tools, single turn, plain text out."""
    combined = (
        f"{system}\n\n"
        "IMPORTANT: Respond with ONLY the <seed_hex>...</seed_hex> blocks. "
        "Do not call any tools — no reading files, no web searches, no code "
        "execution. Answer directly from the context provided.\n\n"
        f"---\n\n{user}"
    )
    cmd = [
        "claude", "-p",
        "--model", _MODEL,
        "--max-turns", "1",
        "--output-format", "text",
        "--disallowed-tools",
        "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch,NotebookEdit,Agent",
    ]
    log(f"    claude -p ({_MODEL}, {len(combined)}c in)...")
    try:
        r = subprocess.run(
            cmd, input=combined,
            capture_output=True, text=True, timeout=_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        log(f"    timeout after {_TIMEOUT}s")
        return ""
    if r.returncode != 0:
        err = r.stderr.strip() or r.stdout.strip() or "(no output)"
        log(f"    claude -p rc={r.returncode}  msg={err[:400]}")
        return ""
    text = r.stdout
    log(f"    out: {len(text)}c")
    return text


def _parse_seeds(text: str) -> list[bytes]:
    out = []
    for m in re.finditer(r"<seed_hex>\s*([0-9a-fA-F\s]+?)\s*</seed_hex>", text):
        try:
            b = bytes.fromhex(re.sub(r"\s+", "", m.group(1)))
        except ValueError:
            continue
        if b:
            out.append(b)
    return out


def _hex_dump(data: bytes, max_bytes: int = 192) -> str:
    shown = data[:max_bytes]
    lines = []
    for off in range(0, len(shown), 16):
        chunk = shown[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {off:04x}: {hx:<47}  {asc}")
    tail = f" (first {max_bytes} of {len(data)})" if len(data) > max_bytes else ""
    return f"[{len(data)} bytes{tail}]\n" + "\n".join(lines)


def _format_side_a(side_a: list[tuple[str, bytes]], max_each: int = 192) -> str:
    parts = []
    for name, data in side_a:
        parts.append(f"--- {name} ---\n{_hex_dump(data, max_each)}")
    return "\n\n".join(parts)


def _branch_header(branch: Branch, missing_side: str) -> str:
    return (
        f"Location: {branch.file}:{branch.line_start}:{branch.col_start}\n"
        f"Missing side: **{missing_side}** (never taken across the corpus)"
    )


# ── Strategy 1: Semantic Guess ─────────────────────────────────────────────

_SEM_SYS = """\
You are a binary fuzzing expert. A branch has never been taken. Your job is \
to read the source context and guess the input bytes that satisfy the \
condition, based on what the code visibly TELLS you: comments, variable/\
constant/enum names, string literals in comparisons, magic numbers.

You are given side-A seeds that reach this branch and take the opposite side \
— use them to understand how the input reaches the branch, then change only \
what the local condition demands.

Output ONLY <seed_hex>...</seed_hex> blocks. Hex bytes, whitespace allowed."""


def _has_semantic_clues(source_ctx: str) -> bool:
    if any(k in source_ctx for k in ['"', "'", "0x", "/*", "//", "case ",
                                      "MAGIC", "HEADER", "SIG", "VERSION",
                                      "TYPE", "FORMAT"]):
        return True
    return bool(re.search(r"[A-Z_]{4,}", source_ctx))


def semantic_guess(
    branch: Branch, missing_side: str, source_ctx: str,
    side_a: list[tuple[str, bytes]], log: Callable,
    call_ctx: str | None = None,
) -> list[bytes]:
    if not _has_semantic_clues(source_ctx):
        log("    semantic_guess: no obvious clues, skip")
        return []
    prompt = f"""## Untaken branch
{_branch_header(branch, missing_side)}

## Source context
{source_ctx}

## Side-A seeds (reach this branch, take OPPOSITE side)
{_format_side_a(side_a)}

## Task
Look for answers directly in the source: comments, constant/enum names, \
string literals, magic numbers. Keep the structural parts of the side-A \
seeds; change only what the local branch condition names or compares.

Emit 2-4 candidate seeds, each as <seed_hex>...</seed_hex>.
"""
    return _parse_seeds(_call_llm(_SEM_SYS, prompt, log))


# ── Strategy 2: Constraint Trace ───────────────────────────────────────────

_CT_SYS = """\
You are a program analysis expert performing lightweight symbolic reasoning. \
A branch has never been taken. Trace backward from the branch condition to \
the input bytes:

1. What variables does the condition test?
2. How are they derived from input bytes along the path reaching the branch?
3. What byte values at what offsets would flip the branch?

Use the side-A seeds as witnesses of the reaching path — they already show \
which parts of the input drive execution to this branch. Change only what \
the condition needs.

Output ONLY <seed_hex>...</seed_hex> blocks."""


def constraint_trace(
    branch: Branch, missing_side: str, source_ctx: str,
    side_a: list[tuple[str, bytes]], log: Callable,
    call_ctx: str | None = None,
) -> list[bytes]:
    prompt = f"""## Untaken branch
{_branch_header(branch, missing_side)}

## Source context (covered lines show the path reaching the branch)
{source_ctx}

## Side-A seeds (witnesses of the reaching path)
{_format_side_a(side_a)}

## Task
Perform backward constraint analysis:
1. Identify the exact condition at the branch.
2. Trace which input bytes flow into its operands (parsing, arithmetic, lookups).
3. Solve for byte values that make the condition take the **{missing_side}** side.

Emit 2-4 candidate seeds, each as <seed_hex>...</seed_hex>.
"""
    return _parse_seeds(_call_llm(_CT_SYS, prompt, log))


# ── Strategy 3: Structure Aware ────────────────────────────────────────────

_SA_SYS = """\
You are an expert in binary file formats and network protocols. A branch has \
never been taken. Infer the input format from source + the existing seed \
corpus, then generate structurally valid inputs that exercise the untaken \
side.

Consider: file format (headers/chunks/fields/checksums), protocol messages \
(type/length/value), serialization (TLV, JSON, XML, protobuf).

Output ONLY <seed_hex>...</seed_hex> blocks."""


def structure_aware(
    branch: Branch, missing_side: str, source_ctx: str,
    side_a: list[tuple[str, bytes]], log: Callable,
    call_ctx: str | None = None,
) -> list[bytes]:
    # Show up to 8 side-A seeds to help format inference
    shown = sorted(side_a, key=lambda kv: len(kv[1]))[:8]
    prompt = f"""## Untaken branch
{_branch_header(branch, missing_side)}

## Source context
{source_ctx}

## Existing corpus (side-A seeds — diverse examples of the format)
{_format_side_a(shown, max_each=256)}

## Task
1. Infer the input format from source and corpus.
2. Identify what structural element the **{missing_side}** branch requires \
   (a specific chunk type, field value, message kind, flag, length, …).
3. Generate structurally valid inputs that carry that element.

Emit 3-5 candidate seeds, each as <seed_hex>...</seed_hex>.
"""
    return _parse_seeds(_call_llm(_SA_SYS, prompt, log))


# ── Strategy 4: Grammar Aware ──────────────────────────────────────────────
# Stepping stone toward full strategy invention. Targets the class of blockers
# that stall the other three — branches predicated on enum-valued parser output
# (`case TK_VARIABLE:`, `case INLINEFUNC_foo:`, etc.). Byte-level reasoning
# is hopeless for these; the reasoning layer has to be the target's INPUT
# GRAMMAR (SQL, HTTP, pcap header schema, image format, …).

_GA_SYS = """\
You are an expert in programming language grammars, protocol schemas, and file \
formats. A branch has never been taken, and earlier byte-level strategies have \
already failed on it. This means the branch predicate almost certainly tests a \
property of PARSED / DECODED input — an AST node kind, a message type enum, a \
chunk tag, an opcode — not a raw byte value.

Your job:
1. From the source context, identify what high-level input category the missing \
   side requires (e.g. "a SQL expression whose AST op is TK_VARIABLE" = "a ? bind \
   parameter in SQL"; "a pcapng block with Block Type == BT_SHB"; "an HTTP method \
   token matching PATCH").
2. From the side-A seeds, infer which input language/format is actually in use.
3. Produce candidate seeds that, WHEN PARSED BY THE TARGET, grammatically belong \
   to that category. Generate inputs at the grammar level, not the byte level.

Output ONLY <seed_hex>...</seed_hex> blocks."""


def grammar_aware(
    branch: Branch, missing_side: str, source_ctx: str,
    side_a: list[tuple[str, bytes]], log: Callable,
    call_ctx: str | None = None,
) -> list[bytes]:
    shown = sorted(side_a, key=lambda kv: len(kv[1]))[:6]
    prompt = f"""## Untaken branch (earlier strategies failed)
{_branch_header(branch, missing_side)}

## Source context
{source_ctx}

## Corpus samples (as grammar exemplars — this is the input language)
{_format_side_a(shown, max_each=256)}

## Task
1. Identify the INPUT GRAMMAR of this target (SQL, HTTP, pcap/pcapng, a media \
   container, a protobuf-framed protocol, …) from the source + corpus.
2. Identify the grammatical element the **{missing_side}** branch demands. Name \
   it in the natural language of that grammar (e.g. "an INSERT statement using \
   OR REPLACE"; "a pcapng Interface Description Block"; "an HTTP request with \
   the CONNECT method").
3. Generate 3-5 candidate seeds that are SYNTACTICALLY VALID in that grammar \
   AND specifically exercise the named element. Keep the shape of side-A seeds \
   where possible — change only the grammatical slot the branch tests.

Emit 3-5 candidate seeds, each as <seed_hex>...</seed_hex>.
"""
    return _parse_seeds(_call_llm(_GA_SYS, prompt, log))


# ── Strategy 5: Call-Site Aware ────────────────────────────────────────────
# Handles the failure mode where a blocker's enclosing function is only
# invoked from a specific upstream construct (e.g. the sqlite3 DEFAULT-clause
# walker reached via CREATE TABLE ... DEFAULT). Grammar awareness alone isn't
# enough — the LLM also needs to know HOW the function is called.

_CS_SYS = """\
You are an expert in program analysis. A branch has never been taken, and \
earlier strategies (semantic / constraint / structure / grammar) all failed. \
That means the branch is inside a function whose INVOCATION context matters — \
generic inputs of the right grammar don't reach this function at all, OR they \
reach it only via paths that take the opposite side of the branch.

You are given:
- The branch and its enclosing function.
- Call sites of that enclosing function across the target source.
- Side-A seed corpus (inputs observed by the fuzzer).

Your job:
1. Read the call sites. Identify WHICH upstream invocation path could deliver \
   a value that flips the branch to the missing side. Be specific — name the \
   caller function and the input construct that reaches it.
2. Generate inputs that (a) drive execution down that upstream path AND (b) \
   satisfy the local branch condition once the enclosing function is entered.

Output ONLY <seed_hex>...</seed_hex> blocks. You may prefix each block with \
one short comment line explaining the path you're targeting."""


def call_site_aware(
    branch: Branch, missing_side: str, source_ctx: str,
    side_a: list[tuple[str, bytes]], log: Callable,
    call_ctx: str | None = None,
) -> list[bytes]:
    if not call_ctx:
        log("    call_site_aware: no call context, skip")
        return []
    shown = sorted(side_a, key=lambda kv: len(kv[1]))[:5]
    prompt = f"""## Untaken branch (earlier strategies failed)
{_branch_header(branch, missing_side)}

## Source context (around the branch)
{source_ctx}

## Call context (enclosing function + its callers)
{call_ctx}

## Corpus samples (what the fuzzer actually produces — note what's MISSING
##   from these inputs vs. what the call sites need)
{_format_side_a(shown, max_each=256)}

## Task
Trace: untaken branch ← enclosing function ← caller X ← input construct.

For each plausible upstream path, emit a candidate seed that rides it down to \
the branch AND flips the branch to **{missing_side}**. 3-6 candidates total, \
each as <seed_hex>...</seed_hex>.
"""
    return _parse_seeds(_call_llm(_CS_SYS, prompt, log))


# ── Dispatch order ─────────────────────────────────────────────────────────

STRATEGY_ORDER: list[tuple[str, Callable]] = [
    ("semantic_guess", semantic_guess),
    ("constraint_trace", constraint_trace),
    ("structure_aware", structure_aware),
    ("grammar_aware", grammar_aware),
    ("call_site_aware", call_site_aware),
]
