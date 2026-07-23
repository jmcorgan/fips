#!/usr/bin/env python3
"""Find shell functions that end in a logging call and whose status a caller tests.

A bash function's exit status is the status of its last command. A function
whose last statement is `echo`/`log`/`info`/... therefore returns 0 on every
path that reaches the end, and any caller written as `if func`, `func || fail`
or `func && ...` has a gate that cannot fire.

This is not hypothetical and not a style rule. Two instances were found in one
day in this tree:

  * `run_chaos` ended in `record`, whose own last statement is an `echo`, so
    every chaos row was unconditionally green from 2026-03-09.
  * `build_fips_for_e2e` ended in `log`, so a failed binary extraction left the
    previous run's cache in place and five end-to-end legs tested the previous
    commit's code and reported green — a green run certifying software that was
    never built.

Both were repaired individually. This exists so the next one is caught by a
gate rather than by a reader.

WHAT IT ENFORCES, stated precisely, because it is a convention and not a bug
hunt: a function whose exit status a caller tests must END WITH AN EXPLICIT
`return`. It must not leave its success value to be whatever the last logging
call happened to produce.

That is deliberately stricter than "has a bug". Every instance in the tree when
this check was written was in fact benign -- each failure path already returned
early, so the trailing `echo` reported a genuine success. The point is that
reading the function is the only way to know that, and the next edit that adds
an unguarded command before the final log turns a benign shape into the exact
defect above with nothing to notice it. An explicit terminal `return` costs one
line and makes the class unreachable.

WHAT IT DELIBERATELY DOES NOT FLAG: a function ending in a logging call whose
status nobody consumes. That is idiomatic and harmless — a reporting helper is
supposed to end by reporting. The defect needs both halves, and scoping on the
call sites rather than on the definitions is what keeps the finding list short
enough to stay read. Same reasoning as check-log-strings.py scoping on what a
grep reads rather than on what its file mentions.

Exit codes:
    0 — no function has both the shape and a status-testing caller
    1 — at least one does
    2 — the checker could not run (bad tree, unreadable file)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

TESTING = Path(__file__).resolve().parent

# Commands whose exit status is always 0 in practice and which exist to print.
# `record` and `skip` are project helpers that end in `echo` themselves, so a
# function ending in one of those inherits the same problem transitively.
LOG_COMMANDS = {
    "echo", "printf", "log", "info", "warn", "warning", "note", "stage",
    "pass", "ok", "record", "skip", "report", "summary", "header",
}

# Functions allowed to end in a logging call even though a caller tests them,
# each with the reason. Keep this list short: a long one means the check has
# been miscalibrated rather than satisfied.
ALLOWED: dict[str, str] = {}

FUNC_RE = re.compile(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{")


def function_bodies(lines: list[str]) -> list[tuple[str, int, list[str]]]:
    """Yield (name, start_line, body_lines) for each top-level function.

    Brace counting rather than a real parser. Good enough because the tree's
    functions are conventionally formatted, and a miscount fails safe: it
    produces a body that ends somewhere odd, which at worst misreads the last
    statement of one function rather than silently skipping every function.
    """
    out = []
    i = 0
    while i < len(lines):
        m = FUNC_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        depth = lines[i].count("{") - lines[i].count("}")
        body_start = i
        j = i + 1
        body: list[str] = []
        while j < len(lines) and depth > 0:
            depth += lines[j].count("{") - lines[j].count("}")
            if depth > 0:
                body.append(lines[j])
            j += 1
        out.append((name, body_start + 1, body))
        i = j
    return out


def last_statement(body: list[str]) -> str | None:
    """The last executable line of a function body, or None if there is none."""
    for line in reversed(body):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        return stripped
    return None


def leading_command(statement: str) -> str | None:
    """The command word a statement starts with, ignoring shell decoration."""
    s = statement.strip()
    # A trailing-log defect cannot hide behind these, and treating them as the
    # command word would miss the real one.
    for prefix in ("}", "fi", "done", "esac", "else", ";;"):
        if s == prefix or s.startswith(prefix + " "):
            return None
    s = s.lstrip("&|;( ")
    m = re.match(r"([A-Za-z_][A-Za-z0-9_\-]*)", s)
    return m.group(1) if m else None


def status_tested(name: str, all_text: str, defining_file: Path) -> list[str]:
    """Call sites that consume the function's exit status, as evidence strings."""
    patterns = [
        (rf"\bif\s+{re.escape(name)}\b", "if <fn>"),
        (rf"\bif\s+!\s+{re.escape(name)}\b", "if ! <fn>"),
        (rf"\bwhile\s+{re.escape(name)}\b", "while <fn>"),
        (rf"^\s*{re.escape(name)}\s+[^\n|&]*\|\|", "<fn> ||"),
        (rf"^\s*{re.escape(name)}\s*\|\|", "<fn> ||"),
        (rf"^\s*{re.escape(name)}\s+[^\n|&]*&&", "<fn> &&"),
        (rf"^\s*{re.escape(name)}\s*&&", "<fn> &&"),
        (rf"\bif\s+\S*\s*{re.escape(name)}\b.*;\s*then", "if ... <fn> ; then"),
    ]
    hits = []
    for pat, label in patterns:
        if re.search(pat, all_text, re.M):
            hits.append(label)
    return sorted(set(hits))


def main() -> int:
    sh_files = sorted(
        p for p in TESTING.rglob("*.sh")
        if "sim-results" not in p.parts and ".cache" not in p.parts
    )
    if not sh_files:
        print("trailing-log check: found no shell scripts to scan", file=sys.stderr)
        return 2

    corpus = {}
    for p in sh_files:
        try:
            corpus[p] = p.read_text(errors="replace")
        except OSError as e:
            print(f"trailing-log check: cannot read {p}: {e}", file=sys.stderr)
            return 2
    all_text = "\n".join(corpus.values())

    findings = []
    scanned = 0
    shaped = 0
    for path, text in corpus.items():
        lines = text.splitlines()
        for name, lineno, body in function_bodies(lines):
            scanned += 1
            stmt = last_statement(body)
            if stmt is None:
                continue
            cmd = leading_command(stmt)
            if cmd is None or cmd not in LOG_COMMANDS:
                continue
            shaped += 1
            if name in ALLOWED:
                continue
            callers = status_tested(name, all_text, path)
            if callers:
                rel = path.relative_to(TESTING.parent)
                findings.append((rel, lineno, name, cmd, callers, stmt))

    for rel, lineno, name, cmd, callers, stmt in sorted(findings):
        print(f"{rel}:{lineno}: {name}() has a caller that tests its status, "
              f"but ends in `{cmd}` rather than an explicit return")
        print(f"    last statement: {stmt[:100]}")
        print(f"    status consumed by: {', '.join(callers)}")
        print(f"    fix: add an explicit `return 0` as the last statement. Its "
              f"success value is currently whatever the log call returned, "
              f"which is 0 whatever the function did.")

    print(f"trailing-log check: {scanned} function(s) scanned, "
          f"{shaped} end in a logging call, {len(ALLOWED)} allowed, "
          f"{len(findings)} with a status-testing caller")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
