"""Rule-based branch filtering and prioritization.

Rules are loaded from the rules/ directory:
  rules/negative/  — branches matching these are discarded (noise, error paths)
  rules/positive/  — branches matching these are prioritized (high semantic value)

Each rule file is a simple text format:
  - Lines starting with # are comments
  - Each non-empty, non-comment line is a pattern
  - Patterns are matched against branch context (file path, source line, etc.)

Example negative rule file (rules/negative/error_paths.txt):
  # Skip error handling / logging branches
  fprintf(stderr
  perror(
  abort()
  exit(1)
  __assert_fail

Example positive rule file (rules/positive/magic_bytes.txt):
  # Prioritize magic number comparisons
  == 0x
  magic
  header
  signature
"""

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from coverage import Branch


@dataclass
class Rule:
    """A single filtering rule."""

    pattern: str  # substring or regex pattern
    source: str  # which file this rule came from
    is_regex: bool = False

    def matches(self, text: str) -> bool:
        """Check if this rule matches the given text."""
        if self.is_regex:
            return bool(re.search(self.pattern, text, re.IGNORECASE))
        return self.pattern.lower() in text.lower()


def load_rules_from_dir(rules_dir: Path) -> list[Rule]:
    """Load all rules from a directory of rule files."""
    rules = []
    if not rules_dir.exists():
        return rules

    for rule_file in sorted(rules_dir.iterdir()):
        if not rule_file.is_file():
            continue
        if rule_file.suffix not in (".txt", ".rules", ""):
            continue

        with open(rule_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Lines starting with / are regex patterns
                if line.startswith("/") and line.endswith("/"):
                    rules.append(Rule(
                        pattern=line[1:-1],
                        source=rule_file.name,
                        is_regex=True,
                    ))
                else:
                    rules.append(Rule(pattern=line, source=rule_file.name))
    return rules


def load_negative_rules(rules_dir: Path) -> list[Rule]:
    """Load negative rules (branches to discard)."""
    return load_rules_from_dir(rules_dir / "negative")


def load_positive_rules(rules_dir: Path) -> list[Rule]:
    """Load positive rules (branches to prioritize)."""
    return load_rules_from_dir(rules_dir / "positive")


def get_branch_context_text(branch: Branch, source_context: str) -> str:
    """Combine branch metadata and source context into a single string for rule matching."""
    return f"{branch.file}:{branch.line_start} {source_context}"


def apply_negative_rules(
    branches: list[Branch],
    source_contexts: dict[str, str],
    rules: list[Rule],
    log_fn=print,
) -> list[Branch]:
    """Filter out branches matching any negative rule."""
    if not rules:
        return branches

    kept = []
    for branch in branches:
        context_text = get_branch_context_text(
            branch, source_contexts.get(branch.id, "")
        )
        matched = None
        for rule in rules:
            if rule.matches(context_text):
                matched = rule
                break
        if matched:
            log_fn(f"  Discarded {branch.id} — matched negative rule "
                   f"'{matched.pattern}' from {matched.source}")
        else:
            kept.append(branch)

    if len(kept) < len(branches):
        log_fn(f"Negative rules: {len(branches)} → {len(kept)} branches")
    return kept


def score_branch(
    branch: Branch,
    source_context: str,
    positive_rules: list[Rule],
) -> float:
    """Score a branch by positive rule matches and heuristics.

    Higher score = should be attempted first (easier to guess).
    """
    score = 0.0
    context_text = get_branch_context_text(branch, source_context)

    # Positive rule matches
    for rule in positive_rules:
        if rule.matches(context_text):
            score += 10.0

    # Built-in heuristics for semantic richness
    ctx_lower = source_context.lower()

    # Comments near the branch suggest human-readable context
    if "//" in source_context or "/*" in source_context:
        score += 3.0

    # String literals in comparisons (easy to guess)
    if '"' in source_context or "'" in source_context:
        score += 5.0

    # Named constants / enums (semantic clues)
    if re.search(r"[A-Z_]{3,}", source_context):
        score += 2.0

    # Magic number comparisons (0x...)
    if re.search(r"0x[0-9a-fA-F]+", source_context):
        score += 4.0

    # Switch/case statements (enum-like, guessable)
    if "switch" in ctx_lower or "case " in ctx_lower:
        score += 3.0

    # Simple equality checks (easier than range checks)
    if "==" in source_context:
        score += 1.0

    # Lower score for complex conditions
    if "&&" in source_context or "||" in source_context:
        score -= 1.0

    # Penalize branches in deeply nested code (harder to reach)
    indent = len(source_context) - len(source_context.lstrip())
    score -= indent * 0.1

    return score


def prioritize_branches(
    branches: list[Branch],
    source_contexts: dict[str, str],
    positive_rules: list[Rule],
) -> list[Branch]:
    """Sort branches by priority score (highest first)."""
    scored = [
        (score_branch(b, source_contexts.get(b.id, ""), positive_rules), b)
        for b in branches
    ]
    scored.sort(key=lambda x: -x[0])
    return [b for _, b in scored]
