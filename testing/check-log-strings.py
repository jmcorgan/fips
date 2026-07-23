#!/usr/bin/env python3
"""Verify that every daemon log string a test matches on still exists in src/.

A test that greps the daemon's log for a message the daemon no longer emits
does not fail — it quietly stops observing anything, and an assertion built on
it (especially one expecting a count of zero) passes for the wrong reason.
That class has produced several findings, so it is checked mechanically here
rather than re-discovered by reading.

The check extracts the string literals that test code matches against daemon
log lines, reduces each to its longest literal run (patterns carry regex
syntax), and requires that run to appear somewhere under src/. Anything that
legitimately does not originate in src/ — runtime panic text, tracing's own
level tokens — must be named in ALLOWED with a reason, so the exceptions are
reviewable instead of invisible.

Usage: testing/check-log-strings.py [--verbose]
Exit:  0 all matched strings are live, 1 otherwise.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
TESTING = REPO / "testing"

# Strings matched against log text that do not come from src/, each with the
# reason it is legitimately absent. Anything here is exempt from the src/
# existence requirement — keep the list short and the reasons specific.
ALLOWED = {
    "panicked": "emitted by the Rust runtime's panic hook, not by our code",
    "PANIC": "panic-adjacent marker matched defensively alongside 'panicked'",
    "ERROR": "tracing's own level token, produced by the subscriber's formatter",
    " ERROR ": "tracing's own level token, produced by the subscriber's formatter",
    " WARN ": "tracing's own level token, produced by the subscriber's formatter",
    "Bootstrapped 100%": (
        "read from the tor-daemon container's log, not the fips daemon's — "
        "Tor's own bootstrap progress line"
    ),
    "panicked at": "the Rust runtime's panic hook writes this, not our code",
    "RUST_BACKTRACE": "the runtime's backtrace hint, printed alongside a panic",
    "fatal runtime error": "emitted by the Rust runtime on an abort",
}

# Shell helpers whose first argument is a pattern matched against daemon logs.
SHELL_HELPERS = ("count_log_pattern", "assert_zero_count")

# A literal run shorter than this is too weak to search for meaningfully.
MIN_ANCHOR = 8


META = set("[](){}?*+.^$")


def literal_anchors(pattern: str) -> list[str]:
    """Longest literal run of each alternation branch of a grep pattern.

    Walks the pattern rather than substituting, because escaping has to be
    resolved in the same pass as the split: `\\.` is a literal dot and ends
    nothing, while a bare `.` is a wildcard and ends the run. Unescaping first
    and splitting after would conflate the two and treat `directory.mode` as
    though it were literal text.
    """
    branches, current, i = [], [], 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            if nxt == "|":  # BRE alternation
                branches.append("".join(current))
                current = []
            elif nxt in "wsdbWSDB":  # a character class, not a literal
                current.append("\0")
            else:
                current.append(nxt)
            i += 2
            continue
        if ch == "|":  # ERE alternation
            branches.append("".join(current))
            current = []
        elif ch in META:
            current.append("\0")
        else:
            current.append(ch)
        i += 1
    branches.append("".join(current))

    anchors = []
    for branch in branches:
        runs = [r.strip() for r in branch.split("\0")]
        runs = [r for r in runs if r]
        if runs:
            anchors.append(max(runs, key=len))
    return anchors


def python_candidates() -> list[tuple[Path, int, str]]:
    """`"literal" in line` tests in testing/ python."""
    found = []
    for path in sorted(TESTING.rglob("*.py")):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for m in re.finditer(r'"([^"]+)"\s+in\s+line\b', line):
                found.append((path, n, m.group(1)))
    return found


def shell_candidates() -> list[tuple[Path, int, str]]:
    """Literal first argument to a log-matching shell helper."""
    helpers = "|".join(SHELL_HELPERS)
    # Quoted literal only; a variable argument is resolved elsewhere and is
    # reported as unscannable rather than silently skipped.
    literal = re.compile(rf"\b(?:{helpers})\s+(\"[^\"$]+\"|'[^']+')")
    variable = re.compile(rf"\b(?:{helpers})\s+[\"']?\$")
    found = []
    for path in sorted(TESTING.rglob("*.sh")):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for m in literal.finditer(line):
                found.append((path, n, m.group(1)[1:-1]))
            if variable.search(line):
                found.append((path, n, None))
    return found


def pattern_table_candidates() -> list[tuple[Path, int, str]]:
    """Bash associative-array keys used as log patterns.

    A suite that iterates a table of patterns into a log-matching helper hides
    every string behind a variable, so the helper rule above sees only
    `count_log_pattern "$pat"` and reports it unscannable. The keys are the
    patterns; read them where they are written.
    """
    key = re.compile(r'^\s*\[\s*"([^"$]+)"\s*\]=')
    found = []
    for path in sorted(TESTING.rglob("*.sh")):
        text = path.read_text(encoding="utf-8")
        if not any(h in text for h in SHELL_HELPERS):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            m = key.match(line)
            if m:
                found.append((path, n, m.group(1)))
    return found


def grep_candidates() -> list[tuple[Path, int, str]]:
    """Literal grep patterns whose input is daemon log text.

    Scoped by what the grep READS, not by what the file mentions. A suite
    greps several unrelated sources — its own analyzer output, fipsctl JSON,
    Tor's log, ping output — and only the daemon's log has to correspond to a
    string in src/. Two shapes qualify: a grep piped directly from
    `docker logs`, and a grep fed a variable that was assigned from it.
    """
    grep_lit = r"\bgrep\b[^|;]*?\s(\"[^\"$]+\"|'[^'$]+')"
    assign = re.compile(r"(\w+)=\"?\$\(\s*docker logs\b")
    found = []
    for path in sorted(TESTING.rglob("*.sh")):
        text = path.read_text(encoding="utf-8")
        if "docker logs" not in text:
            continue
        log_vars = set(assign.findall(text))
        # A grep reading one of those variables, by herestring or by pipe.
        var_alt = "|".join(re.escape(v) for v in log_vars) or r"\0"
        reads_var = re.compile(rf"[\"']?\$\{{?(?:{var_alt})\b")
        for n, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if "docker logs" not in line and not reads_var.search(line):
                continue
            for m in re.finditer(grep_lit, line):
                found.append((path, n, m.group(1)[1:-1]))
    return found


def main() -> int:
    verbose = "--verbose" in sys.argv
    src_text = "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in SRC.rglob("*.rs")
    )

    candidates = (
        python_candidates()
        + shell_candidates()
        + pattern_table_candidates()
        + grep_candidates()
    )
    dead, checked, exempt, unscannable = [], 0, 0, 0

    for path, lineno, raw in candidates:
        rel = path.relative_to(REPO)
        if raw is None:
            unscannable += 1
            if verbose:
                print(f"  skip {rel}:{lineno}: pattern comes from a variable")
            continue
        if raw in ALLOWED:
            exempt += 1
            if verbose:
                print(f"  allow {rel}:{lineno}: {raw!r} ({ALLOWED[raw]})")
            continue
        anchors = literal_anchors(raw)
        # An alternation may mix daemon strings with runtime ones, so the
        # allowlist applies per branch and not only to the whole pattern.
        if any(a in ALLOWED for a in anchors):
            exempt += 1
            if verbose:
                print(f"  allow {rel}:{lineno}: {raw!r} (branch in ALLOWED)")
            anchors = [a for a in anchors if a not in ALLOWED]
        usable = [a for a in anchors if len(a) >= MIN_ANCHOR]
        if not usable:
            unscannable += 1
            if verbose:
                print(f"  skip {rel}:{lineno}: {raw!r} has no literal run >= {MIN_ANCHOR}")
            continue
        checked += 1
        # Every alternation branch must be live: one dead branch is a matcher
        # that has silently narrowed.
        for anchor in usable:
            if anchor not in src_text:
                dead.append((rel, lineno, raw, anchor))
            elif verbose:
                print(f"  ok   {rel}:{lineno}: {anchor!r}")

    print(
        f"log-string check: {checked} matched, {exempt} allowed, "
        f"{unscannable} unscannable, {len(dead)} dead"
    )
    if dead:
        print("\nStrings matched against daemon logs that src/ never emits:\n")
        for rel, lineno, raw, anchor in dead:
            print(f"  {rel}:{lineno}")
            print(f"      pattern: {raw!r}")
            print(f"      missing: {anchor!r}")
        print(
            "\nEither correct the string to what the daemon emits, or add it to "
            "ALLOWED\nin this script with the reason it does not come from src/."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
