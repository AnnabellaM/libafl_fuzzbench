"""Call-site discovery for blocker resolution.

Given a blocker branch, find its enclosing C function and grep the target
source tree for callers. The resulting context lets an LLM reason about HOW
the blocker's function is invoked — the axis that plain grammar awareness
lacks (see 2026-04-16 design memory).
"""

import re
import subprocess
from pathlib import Path


# Matches a plausible C function definition line: starts at column 0, has an
# identifier before '(' that isn't a control-flow keyword, and doesn't end in
# ';' (which would make it a declaration/prototype, not a definition).
_FUNC_NAME_RE = re.compile(r'^[\w\s\*]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
_SKIP_FIRST = {
    'if', 'while', 'for', 'switch', 'return', 'case', 'else', 'do', 'goto',
    'typedef', 'struct', 'enum', 'union', 'sizeof', 'static_assert',
}


def find_enclosing_function(file_path: Path, line_no: int,
                             max_back: int = 3000) -> dict | None:
    """Walk backward from line_no, return info on the nearest function definition.

    Returns {'name', 'signature_line', 'signature_text'} or None.
    """
    try:
        lines = file_path.read_text(errors='replace').splitlines()
    except OSError:
        return None
    if line_no <= 0 or line_no > len(lines):
        return None

    start = max(0, line_no - max_back)
    for i in range(line_no - 2, start - 1, -1):  # 0-indexed; start one line above
        raw = lines[i]
        if not raw or raw[0].isspace():
            continue
        stripped = raw.lstrip()
        if stripped.startswith(('#', '/', '*', '}', '{')):
            continue
        if raw.rstrip().endswith(';'):
            continue
        if '(' not in raw:
            continue
        first_tok = stripped.split(None, 1)[0]
        if first_tok in _SKIP_FIRST:
            continue
        m = _FUNC_NAME_RE.match(raw)
        if not m:
            continue
        name = m.group(1)
        if name in _SKIP_FIRST:
            continue
        # Walk further back to capture the preceding doc comment block. Stop at
        # the first non-comment, non-blank line (usually the previous function's
        # closing '}').
        doc_start = i
        j = i - 1
        in_block = False
        while j >= 0 and j >= i - 80:
            ln = lines[j].strip()
            if not ln:
                # Blank line within comment: keep going
                doc_start = j
                j -= 1
                continue
            if ln.startswith('*/'):
                in_block = True
                doc_start = j
                j -= 1
                continue
            if in_block:
                doc_start = j
                if ln.startswith('/*') or ln.startswith('/**'):
                    in_block = False
                    j -= 1
                    break
                j -= 1
                continue
            if ln.startswith('//') or ln.startswith('/*'):
                doc_start = j
                j -= 1
                continue
            break
        doc_block = "\n".join(lines[doc_start:i + 1]) if doc_start < i else ""
        return {
            'name': name,
            'signature_line': i + 1,
            'signature_text': raw.rstrip(),
            'doc_block': doc_block,
        }
    return None


def find_function_end(file_path: Path, signature_line: int,
                       max_forward: int = 4000) -> int | None:
    """From a function's signature line, walk forward counting braces and return
    the line number (1-indexed) of the matching closing '}'.

    Handles simple C: ignores braces inside // and /* ... */ comments and
    inside "..." / '...' string/char literals. Not perfect but good enough for
    amalgamated sqlite-style code.
    """
    try:
        lines = file_path.read_text(errors='replace').splitlines()
    except OSError:
        return None
    if signature_line <= 0 or signature_line > len(lines):
        return None
    end_max = min(len(lines), signature_line + max_forward)
    depth = 0
    seen_open = False
    in_block_comment = False
    for i in range(signature_line - 1, end_max):
        line = lines[i]
        j = 0
        in_line_comment = False
        in_str: str | None = None
        while j < len(line):
            c = line[j]
            nc = line[j + 1] if j + 1 < len(line) else ''
            if in_line_comment:
                break
            if in_block_comment:
                if c == '*' and nc == '/':
                    in_block_comment = False
                    j += 2
                    continue
                j += 1
                continue
            if in_str is not None:
                if c == '\\':
                    j += 2
                    continue
                if c == in_str:
                    in_str = None
                j += 1
                continue
            if c == '/' and nc == '/':
                in_line_comment = True
                break
            if c == '/' and nc == '*':
                in_block_comment = True
                j += 2
                continue
            if c == '"' or c == "'":
                in_str = c
                j += 1
                continue
            if c == '{':
                depth += 1
                seen_open = True
            elif c == '}':
                depth -= 1
                if seen_open and depth == 0:
                    return i + 1
            j += 1
    return None


def find_callers(func_name: str, src_root: Path, max_results: int = 6,
                  context: int = 2, exclude_def_file: str | None = None,
                  exclude_def_line: int | None = None,
                  exclude_path_substr: tuple[str, ...] = (
                      "/bld/sqlite3.c", "/bld/tsrc/",
                  )) -> list[dict]:
    """Grep src_root for call sites of func_name.

    Returns up to max_results dicts: {'file', 'line', 'snippet'} where snippet
    is a small context window. Skips the definition line itself.
    """
    if not src_root.exists() or not func_name:
        return []
    pattern = rf'\b{re.escape(func_name)}\s*\('
    try:
        r = subprocess.run(
            ['grep', '-rnE',
             '--include=*.c', '--include=*.h',
             '-A', str(context), '-B', str(context),
             pattern, str(src_root)],
            capture_output=True, text=True, timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    if r.returncode not in (0, 1):
        return []

    # grep with -A/-B emits groups separated by '--' lines, with 'file-lineno-' or
    # 'file:lineno:' prefixes. Parse into (file, lineno, block) tuples where
    # block is the full multi-line match snippet centered on the hit line.
    results: list[dict] = []
    by_file: dict[str, int] = {}
    cur_block: list[str] = []
    cur_hit: tuple[str, int] | None = None

    def flush():
        nonlocal cur_block, cur_hit
        if cur_hit is not None and cur_block:
            path, lineno = cur_hit
            # Skip amalgamated / duplicated source files so we don't show the
            # same call site twice (sqlite3 has both src/*.c and bld/sqlite3.c).
            if any(s in path for s in exclude_path_substr):
                cur_block = []
                cur_hit = None
                return
            # Skip the definition itself
            if (exclude_def_file and path.endswith(exclude_def_file)
                    and exclude_def_line is not None
                    and abs(lineno - exclude_def_line) <= 1):
                cur_block = []
                cur_hit = None
                return
            # Skip if the hit line itself is the function *definition* (not a
            # call). Identify the hit line in cur_block by its lineno prefix.
            hit_prefix = f"{lineno}: "
            hit_line = next((ln for ln in cur_block if ln.startswith(hit_prefix)), "")
            hit_text = hit_line[len(hit_prefix):] if hit_line else ""
            if re.search(rf'\b{re.escape(func_name)}\s*\(', hit_text):
                # Definitions look like `<ret_type> funcname(...) {` or end with '{'
                # Calls are preceded by '=' or standalone expression.
                stripped_hit = hit_text.strip()
                looks_like_def = (
                    stripped_hit.startswith(('static ', 'static\t', 'inline '))
                    or re.match(rf'^[A-Za-z_]\w*\s*\**\s*{re.escape(func_name)}\s*\(', stripped_hit)
                    and stripped_hit.rstrip().endswith(('{', ')'))
                    and ';' not in stripped_hit
                )
                if looks_like_def:
                    cur_block = []
                    cur_hit = None
                    return
            # Limit to 3 hits per file so we get diversity
            if by_file.get(path, 0) >= 3:
                cur_block = []
                cur_hit = None
                return
            by_file[path] = by_file.get(path, 0) + 1
            # Trim cache prefix from path (e.g. ".../work/src/src/sqlite3/src/expr.c"
            # → "src/expr.c") so the LLM sees clean container-relative paths.
            clean_path = path
            for marker in ("/work/src/", "/src/"):
                idx = clean_path.rfind(marker)
                if idx >= 0:
                    clean_path = clean_path[idx + len(marker):]
                    break
            results.append({
                'file': clean_path,
                'line': lineno,
                'snippet': '\n'.join(cur_block),
            })
        cur_block = []
        cur_hit = None

    for raw in r.stdout.splitlines():
        if raw == '--':
            flush()
            continue
        # Hit line: file:lineno:text  (context: file-lineno-text)
        # Take first two ':' or '-' as delimiters
        # grep prints '-' for context, ':' for match
        # so a hit line has two ':' at small positions.
        # Use a regex to peel off prefix.
        m = re.match(r'^(.+?)([:\-])(\d+)([:\-])(.*)$', raw)
        if not m:
            continue
        path, sep1, lineno_str, _sep2, text = m.groups()
        try:
            lineno = int(lineno_str)
        except ValueError:
            continue
        cur_block.append(f"{lineno}: {text}")
        if sep1 == ':' and cur_hit is None:
            cur_hit = (path, lineno)
    flush()

    return results[:max_results]


def summarize_call_context(enclosing: dict | None, callers: list[dict],
                            max_snippet_lines: int = 6) -> str:
    """Format enclosing function + callers for inclusion in an LLM prompt."""
    parts = []
    if enclosing:
        parts.append(
            f"**Enclosing function:** `{enclosing['name']}`  "
            f"(signature at line {enclosing['signature_line']})\n"
            f"    {enclosing['signature_text']}"
        )
        doc = enclosing.get('doc_block', '') or ''
        if doc.strip():
            parts.append(f"\n**Doc comment preceding `{enclosing['name']}`:**\n{doc}")
    else:
        parts.append("**Enclosing function:** (could not identify)")
    if callers:
        parts.append(f"\n**Call sites of `{enclosing['name']}` in the target source:**"
                     if enclosing else "\n**Call sites:**")
        for i, c in enumerate(callers, 1):
            lines = c['snippet'].splitlines()[:max_snippet_lines]
            parts.append(f"\n[{i}] {c['file']}:{c['line']}")
            for ln in lines:
                parts.append(f"    {ln}")
    else:
        parts.append("\n(no callers found — function may be invoked indirectly)")
    return "\n".join(parts)
