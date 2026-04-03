"""Multi-strategy seed generation for frontier branch resolution.

Strategies (cheapest first):
  1. semantic_guess   — answer visible in source: constants, comments, enums
  2. seed_mutation    — tweak the seed hitting the taken side
  3. constraint_trace — reason backward along hit path (lightweight symbolic)
  4. structure_aware  — guess based on input format knowledge

Each strategy takes a branch + context and returns candidate seed bytes,
or None if the strategy doesn't apply.
"""

import os
import re
from typing import Callable, Optional

from coverage import Branch


# ---------------------------------------------------------------------------
# Seed formatting helpers
# ---------------------------------------------------------------------------


def format_hex_dump(data: bytes, max_bytes: int = 256) -> str:
    """Format binary data as hex + ASCII dump."""
    display = data[:max_bytes]
    lines = []
    for off in range(0, len(display), 16):
        chunk = display[off : off + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {off:04x}: {hex_part:<48s}  {ascii_part}")
    return "\n".join(lines)


def format_seed_for_llm(name: str, data: bytes, max_bytes: int = 256) -> str:
    """Format a single seed for LLM display."""
    trunc = (
        f" (showing first {max_bytes} of {len(data)} bytes)"
        if len(data) > max_bytes
        else ""
    )
    return f"--- {name}  [{len(data)} bytes{trunc}] ---\n{format_hex_dump(data, max_bytes)}"


# ---------------------------------------------------------------------------
# Strategy interface
# ---------------------------------------------------------------------------

STRATEGY_ORDER = ["semantic_guess", "seed_mutation", "constraint_trace", "structure_aware"]


def get_available_strategies(
    branch: Branch,
    source_context: str,
    strategies_tried: list[str],
) -> list[str]:
    """Return strategies not yet tried for this branch, in priority order."""
    return [s for s in STRATEGY_ORDER if s not in strategies_tried]


# ---------------------------------------------------------------------------
# LLM client
# ---------------------------------------------------------------------------


def _call_llm(
    system_prompt: str,
    user_prompt: str,
    log_fn: Callable = print,
) -> str:
    """Call Claude API and return response text."""
    import anthropic

    client = anthropic.Anthropic()
    model = os.environ.get("AGENT_MODEL", "claude-sonnet-4-20250514")

    log_fn(f"  LLM call ({model}, prompt={len(user_prompt)} chars)...")
    response = client.messages.create(
        model=model,
        max_tokens=4096,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )
    text = response.content[0].text
    log_fn(f"  LLM response: {len(text)} chars, "
           f"{response.usage.input_tokens}in/{response.usage.output_tokens}out")
    return text


def _parse_seeds_from_response(text: str) -> list[bytes]:
    """Extract seed bytes from <seed_hex> tags."""
    pattern = re.compile(r"<seed_hex>\s*([0-9a-fA-F\s]+?)\s*</seed_hex>")
    seeds = []
    for match in pattern.finditer(text):
        clean = match.group(1).replace(" ", "").replace("\n", "").replace("\r", "")
        try:
            seed_bytes = bytes.fromhex(clean)
            if seed_bytes:
                seeds.append(seed_bytes)
        except ValueError:
            continue
    return seeds


# ---------------------------------------------------------------------------
# Strategy 1: Semantic Guess
# ---------------------------------------------------------------------------

SEMANTIC_SYSTEM = """\
You are a binary fuzzing expert. You are looking at a specific branch in a \
program that has never been taken. Your job is to examine the source code \
context — especially comments, variable names, constant names, enum values, \
string literals, and magic numbers — and directly guess what input bytes \
would satisfy the branch condition.

Focus on what the source code TELLS you. This strategy works best when the \
answer is directly visible in the code."""


def semantic_guess(
    branch: Branch,
    source_context: str,
    seeds: dict[str, bytes],
    log_fn: Callable = print,
) -> list[bytes]:
    """Strategy 1: Guess from visible semantics in source code.

    Works best when: comments, constants, enum names, string literals
    directly reveal the expected input.
    """
    # Quick check: does the source context have semantic clues?
    has_clues = any(
        indicator in source_context
        for indicator in ['"', "'", "0x", "/*", "//", "case ", "MAGIC", "HEADER",
                          "SIGNATURE", "VERSION", "TYPE", "FORMAT"]
    )
    if not has_clues and not re.search(r"[A-Z_]{4,}", source_context):
        return []  # No obvious semantic clues, skip this strategy

    prompt = f"""## Frontier Branch

The following branch has NEVER been taken ({branch.missing_side} side is always 0):

Location: {branch.id}
True-side count: {branch.true_count}
False-side count: {branch.false_count}
Missing side: {branch.missing_side}

## Source Context (with coverage annotations)

{source_context}

## Current Seeds (for reference)

"""
    # Show a few seeds for context
    shown = 0
    for name, data in sorted(seeds.items()):
        if shown >= 5:
            break
        prompt += format_seed_for_llm(name, data, 128) + "\n\n"
        shown += 1

    prompt += """## Task

Look at the source code carefully. Find clues in:
- Comments (e.g., "// expects 'PNG' header")
- Constant/variable names (e.g., `MAGIC_BYTES`, `expected_version`)
- String literals in comparisons
- Enum values in switch/case
- Magic numbers (0x...)

Generate 1-3 seed inputs that directly satisfy the branch condition.
Output each as:
<seed_hex>hex bytes</seed_hex>
"""

    text = _call_llm(SEMANTIC_SYSTEM, prompt, log_fn)
    return _parse_seeds_from_response(text)


# ---------------------------------------------------------------------------
# Strategy 2: Seed Mutation
# ---------------------------------------------------------------------------

MUTATION_SYSTEM = """\
You are a binary fuzzing expert. You have a seed input that reaches near a \
frontier branch but takes the wrong side. Your job is to modify specific \
bytes in the seed so that it takes the other side of the branch.

Think about:
- What bytes in the input influence the branch condition?
- How does the input flow through parsing/processing to reach this branch?
- What minimal change would flip the branch outcome?"""


def seed_mutation(
    branch: Branch,
    source_context: str,
    seeds: dict[str, bytes],
    log_fn: Callable = print,
) -> list[bytes]:
    """Strategy 2: Modify an existing seed to flip the branch.

    Works best when: we have a seed that reaches the branch (taken side),
    and the modification needed is localized.
    """
    if not seeds:
        return []

    # Pick a representative seed (prefer smaller ones)
    sorted_seeds = sorted(seeds.items(), key=lambda kv: len(kv[1]))
    best_name, best_data = sorted_seeds[0]

    prompt = f"""## Frontier Branch

Location: {branch.id}
True-side count: {branch.true_count}
False-side count: {branch.false_count}
Missing side: {branch.missing_side} (this side has NEVER been taken)

## Source Context

{source_context}

## Existing Seed (reaches near this branch)

{format_seed_for_llm(best_name, best_data, 512)}

## Task

Modify this seed so that the branch takes the **{branch.missing_side}** side.

Think step by step:
1. What condition controls this branch?
2. Which bytes in the input affect that condition?
3. What values would those bytes need to flip the branch?

Generate 2-5 modified versions of the seed.
Output each as:
<seed_hex>complete hex bytes of the modified seed</seed_hex>
"""

    text = _call_llm(MUTATION_SYSTEM, prompt, log_fn)
    return _parse_seeds_from_response(text)


# ---------------------------------------------------------------------------
# Strategy 3: Constraint Trace
# ---------------------------------------------------------------------------

CONSTRAINT_SYSTEM = """\
You are a program analysis expert performing lightweight symbolic reasoning. \
Given a frontier branch and the execution path leading to it, trace backward \
to understand what constraints the input must satisfy to reach and flip this \
branch.

Think like a symbolic execution engine:
- What variables influence the branch condition?
- How are those variables derived from the input bytes?
- What transformations (parsing, arithmetic, lookups) occur along the path?
- What input values satisfy the full constraint chain?"""


def constraint_trace(
    branch: Branch,
    source_context: str,
    seeds: dict[str, bytes],
    log_fn: Callable = print,
) -> list[bytes]:
    """Strategy 3: Trace constraints backward from the branch.

    Works best when: the branch condition depends on transformed/computed
    values rather than direct byte comparisons.
    """
    # Pick a seed for reference
    sorted_seeds = sorted(seeds.items(), key=lambda kv: len(kv[1]))
    ref_name, ref_data = sorted_seeds[0] if seeds else ("(none)", b"")

    prompt = f"""## Frontier Branch

Location: {branch.id}
Missing side: {branch.missing_side} (never taken)

## Source Context (with coverage — lines with count show the execution path)

{source_context}

## Reference Seed

{format_seed_for_llm(ref_name, ref_data, 512) if ref_data else "(no seeds available)"}

## Task

Perform backward constraint analysis:

1. **Identify the branch condition** — what expression is being tested?
2. **Trace data flow backward** — how do the variables in the condition relate to input bytes?
   Look at assignments, function calls, loops, and transformations on the execution path
   (lines with non-zero coverage counts).
3. **Derive input constraints** — what byte values at what offsets would satisfy the
   {branch.missing_side} branch?
4. **Generate seeds** that satisfy these constraints.

Generate 2-5 candidate seeds.
Output each as:
<seed_hex>complete hex bytes</seed_hex>
"""

    text = _call_llm(CONSTRAINT_SYSTEM, prompt, log_fn)
    return _parse_seeds_from_response(text)


# ---------------------------------------------------------------------------
# Strategy 4: Structure-Aware Guess
# ---------------------------------------------------------------------------

STRUCTURE_SYSTEM = """\
You are an expert in file formats and network protocols. Given a program's \
source code and a frontier branch, infer what input format the program \
expects and generate structurally valid inputs that exercise the untaken path.

Consider:
- Is this a file format parser? (headers, chunks, fields, checksums)
- Is this a network protocol handler? (message types, length fields, flags)
- Is this a data structure deserializer? (TLV, protobuf, JSON, XML)
- What structural elements does the untaken branch require?"""


def structure_aware(
    branch: Branch,
    source_context: str,
    seeds: dict[str, bytes],
    log_fn: Callable = print,
) -> list[bytes]:
    """Strategy 4: Guess based on inferred input structure/format.

    Works best when: the target is a format parser and the branch requires
    specific structural elements (headers, field types, lengths).
    """
    # Show multiple seeds to help infer format
    seed_display = ""
    shown = 0
    for name, data in sorted(seeds.items(), key=lambda kv: len(kv[1])):
        if shown >= 8:
            break
        seed_display += format_seed_for_llm(name, data, 256) + "\n\n"
        shown += 1

    prompt = f"""## Frontier Branch

Location: {branch.id}
Missing side: {branch.missing_side}

## Source Context

{source_context}

## Current Seed Corpus

{seed_display}

## Task

1. **Infer input format** — based on the source code and existing seeds, what format does
   this program expect? (file type, protocol, data structure)
2. **Identify structural requirement** — what structural element does the {branch.missing_side}
   branch require? (specific header, field type, chunk, flag, length encoding)
3. **Generate valid inputs** with the required structural elements.

Generate 3-5 structurally valid seeds targeting this branch.
Output each as:
<seed_hex>complete hex bytes</seed_hex>
"""

    text = _call_llm(STRUCTURE_SYSTEM, prompt, log_fn)
    return _parse_seeds_from_response(text)


# ---------------------------------------------------------------------------
# Strategy dispatch
# ---------------------------------------------------------------------------

STRATEGY_FNS = {
    "semantic_guess": semantic_guess,
    "seed_mutation": seed_mutation,
    "constraint_trace": constraint_trace,
    "structure_aware": structure_aware,
}


def run_strategy(
    strategy_name: str,
    branch: Branch,
    source_context: str,
    seeds: dict[str, bytes],
    log_fn: Callable = print,
) -> list[bytes]:
    """Run a named strategy and return candidate seeds."""
    fn = STRATEGY_FNS.get(strategy_name)
    if fn is None:
        log_fn(f"  Unknown strategy: {strategy_name}")
        return []
    try:
        return fn(branch, source_context, seeds, log_fn)
    except Exception as e:
        log_fn(f"  Strategy {strategy_name} failed: {e}")
        return []


# ---------------------------------------------------------------------------
# Heuristic fallback (no LLM needed)
# ---------------------------------------------------------------------------


def generate_heuristic_seeds(seeds: dict[str, bytes]) -> list[bytes]:
    """Generate seeds using heuristics when LLM is unavailable."""
    new_seeds = []

    # Common magic bytes / format headers
    magic_patterns = [
        b"\x7fELF", b"\x89PNG\r\n\x1a\n", b"GIF89a",
        b"\xff\xd8\xff\xe0", b"PK\x03\x04", b"\x1f\x8b\x08",
        b"BM", b"%PDF-1.", b"<?xml", b'{"', b"[",
        b"HTTP/1.1 ", b"GET / HTTP/1.1\r\n",
        b"\x00\x00\x00\x00", b"\xff\xff\xff\xff",
    ]
    new_seeds.extend(magic_patterns)

    # Boundary-value seeds
    for size in [1, 2, 4, 8, 16, 32, 64, 128, 256]:
        new_seeds.append(b"\x00" * size)
        new_seeds.append(b"\xff" * size)

    # Extend existing seeds
    existing = list(seeds.values())[:5]
    for seed in existing:
        if len(seed) < 1024:
            new_seeds.append(seed + b"\x00" * 16)
            new_seeds.append(seed + b"\xff" * 16)
            new_seeds.append(seed * 2)
            for pos in range(min(4, len(seed))):
                mutated = bytearray(seed)
                mutated[pos] ^= 0xFF
                new_seeds.append(bytes(mutated))

    return new_seeds
