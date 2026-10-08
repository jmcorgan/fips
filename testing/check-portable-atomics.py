#!/usr/bin/env python3
"""Fail when non-test code under src/ uses the std 64-bit atomics.

`std::sync::atomic::AtomicU64` and `AtomicI64` exist only on targets with
64-bit atomics. The 32-bit MIPS targets the OpenWrt packages are meant to
cover (mips-unknown-linux-musl, mipsel-unknown-linux-musl) have none, so one
such use anywhere in the crate stops the whole crate building there. Code
that needs a 64-bit atomic uses `portable_atomic::AtomicU64` instead, which is
the std type where the target has one and a lock-based fallback where it does
not. No CI leg builds for MIPS yet, so without this check the first anyone
would hear of a new std use is a failed build on a router target.

What is flagged, read from the files committed at HEAD:

  * a `use` tree rooted at `std` or `core` that reaches
    `sync::atomic::AtomicU64` or `sync::atomic::AtomicI64`, in any form:
    a plain path, a grouped `{...}` list over one or several lines, a nested
    group such as `std::sync::{Arc, atomic::{AtomicU64, Ordering}}`, or a
    rename with `as`;
  * a glob import of `std::sync::atomic::*` or `core::sync::atomic::*`,
    because it brings both types in unnamed;
  * a path-qualified use such as `std::sync::atomic::AtomicU64::new(0)`, and
    `atomic::AtomicU64` after `use std::sync::atomic;`, anywhere in the text;
  * `sa::AtomicU64` where the file renames the module with
    `use std::sync::atomic as sa;` or `use std::sync::{atomic::{self as sa}}`.

Scope is src/, minus files under a `tests/` directory and files named
`tests.rs` or `*_tests.rs`, which are only ever built for the host. A
`#[cfg(test)]` module inside an ordinary file is NOT exempt: telling it apart
needs a Rust parser, and holding test code in those files to the same rule
costs nothing today (no such module uses the std types).

No file is exempt by name. `EXEMPT` holds any that must be, each with its
reason.

Known gaps, recorded rather than discovered: a std 64-bit atomic reached
through a re-export from another crate, or through a type alias defined
outside src/, is not seen; nor is one written with a macro that assembles the
path from pieces.

Exit codes:
    0 - no non-test file under src/ uses a std 64-bit atomic
    1 - at least one does; every hit is printed
    2 - the check could not look (not a git work tree, git failed, or src/
        matched no Rust files); never a pass
"""

from __future__ import annotations

import re
import subprocess
import sys

EXEMPT: dict[str, str] = {}

WIDE = ("AtomicU64", "AtomicI64")

USE_RE = re.compile(r"\buse\s+([^;]+);", re.S)
# Any `atomic::AtomicU64` whose `atomic` is not the tail of a longer name, so
# `portable_atomic::AtomicU64` is not matched and every std spelling is.
PATH_RE = re.compile(r"(?<![\w])atomic\s*::\s*(AtomicU64|AtomicI64)\b")


def git(*args: str) -> str:
    """Run a git command and return its stdout, exiting 2 if it fails."""
    proc = subprocess.run(["git", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"check-portable-atomics: git {' '.join(args)} failed: {proc.stderr.strip()}",
              file=sys.stderr)
        sys.exit(2)
    return proc.stdout


def is_test_path(path: str) -> bool:
    """True for files only ever built as part of the test harness."""
    parts = path.split("/")
    name = parts[-1]
    return "tests" in parts[:-1] or name == "tests.rs" or name.endswith("_tests.rs")


def split_top(text: str) -> list[str]:
    """Split a use-tree list on the commas that are not inside braces."""
    items, depth, cur = [], 0, []
    for ch in text:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == "," and depth == 0:
            items.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    items.append("".join(cur))
    return [i.strip() for i in items if i.strip()]


def flatten(tree: str, prefix: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    """Expand a use tree into the full paths it imports.

    A rename, written `name@alias` by the caller, stays on the last segment.
    """
    tree = re.sub(r"\s+", "", tree)
    brace = tree.find("{")
    if brace == -1:
        segs = tuple(s for s in tree.split("::") if s)
        return [prefix + segs]
    head = tuple(s for s in tree[:brace].split("::") if s)
    inner = tree[brace + 1:tree.rfind("}")]
    out = []
    for item in split_top(inner):
        if item == "self" or item.startswith("self@"):
            alias = item[len("self"):]
            out.append(prefix + head[:-1] + (head[-1] + alias,))
        else:
            out.extend(flatten(item, prefix + head))
    return out


def use_hits(text: str) -> list[tuple[int, str]]:
    """Return (line, imported path) for each std/core wide-atomic import."""
    hits = []
    for m in USE_RE.finditer(text):
        body = re.sub(r"\s+as\s+(\w+)", r"@\1", m.group(1))
        line = text.count("\n", 0, m.start()) + 1
        for path in flatten(body):
            if not path:
                continue
            last, _, alias = path[-1].partition("@")
            path = path[:-1] + (last,)
            if path[0] not in ("std", "core") or path[1:3] != ("sync", "atomic"):
                continue
            if len(path) == 3 and alias:
                hits.extend(alias_hits(text, alias, "::".join(path)))
            elif len(path) >= 4 and (path[3] in WIDE or path[3] == "*"):
                hits.append((line, "::".join(path[:4])))
    return hits


def alias_hits(text: str, alias: str, module: str) -> list[tuple[int, str]]:
    """Return (line, use) for each wide atomic named through a module alias."""
    hits = []
    pat = re.compile(r"(?<![\w])" + re.escape(alias) + r"\s*::\s*(AtomicU64|AtomicI64)\b")
    for m in pat.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        hits.append((line, f"{module}::{m.group(1)} as {alias}::{m.group(1)}"))
    return hits


def path_hits(text: str) -> list[tuple[int, str]]:
    """Return (line, matched text) for each path-qualified wide atomic."""
    hits = []
    for m in PATH_RE.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        hits.append((line, re.sub(r"\s+", "", m.group(0))))
    return hits


def main() -> int:
    """Scan the committed src/ tree and report every std wide-atomic use."""
    root = git("rev-parse", "--show-toplevel").strip()
    if not root:
        print("check-portable-atomics: empty work-tree root", file=sys.stderr)
        return 2
    files = [
        f for f in git("-C", root, "ls-tree", "-r", "--name-only", "HEAD", "--", "src/").splitlines()
        if f.endswith(".rs")
    ]
    if not files:
        print("check-portable-atomics: src/ matched no Rust files at HEAD", file=sys.stderr)
        return 2

    scanned = 0
    findings = []
    for path in files:
        if is_test_path(path) or path in EXEMPT:
            continue
        text = git("-C", root, "show", f"HEAD:{path}")
        scanned += 1
        seen = set()
        for line, what in use_hits(text) + path_hits(text):
            if (line, what) not in seen:
                seen.add((line, what))
                findings.append(f"{path}:{line}: {what}")

    if scanned == 0:
        print("check-portable-atomics: every file under src/ was excluded", file=sys.stderr)
        return 2

    if findings:
        for f in findings:
            print(f)
        print("", file=sys.stderr)
        print("check-portable-atomics: std 64-bit atomics do not exist on 32-bit MIPS, so the",
              file=sys.stderr)
        print("crate stops building there. Use portable_atomic::AtomicU64 (or AtomicI64).",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
