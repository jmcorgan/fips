#!/usr/bin/env python3
"""Ignored-test inventory guard.

An ignored test runs nowhere unless something runs it on purpose, so an
`#[ignore]` added without a record is a test that silently stopped gating.
Every ignored test in the workspace's Rust sources must have one entry in
testing/ignored-tests.txt saying why it is ignored, and every entry must still
name an ignored test. The known-defect entries are run by
testing/known-defect-lane.sh, which expects each of them to fail.

What this checks, statically and without building anything, so it sees the
tests every platform compiles, not only the host's:

  1. every `#[ignore ...]` attribute (and `cfg_attr(..., ignore ...)`) carries
     a non-empty reason, `#[ignore = "..."]`;
  2. every ignored test has exactly one inventory entry, matched by file and
     by the entry's test path ending in `::<fn name>`;
  3. every inventory entry matches an ignored test, so a test that was
     un-ignored, renamed or deleted takes its entry with it;
  4. every entry's class is one of CLASSES and its crate is the crate the
     file belongs to.

The test path's module prefix is not resolved here, since `#[path]` modules
make it a property of the build. The lane checks it for every test the host
compiles, by listing the ignored tests of each test binary.

Exit 0 = inventory and sources agree. Exit 1 = they do not; every problem is
printed. Exit 2 = the check could not look (not in a work tree, no Rust
sources found, the inventory unreadable); never treated as a pass.
"""

import pathlib
import re
import subprocess
import sys

CLASSES = {"environment", "benchmark", "long-running", "helper", "known-defect"}
INVENTORY = "testing/ignored-tests.txt"

ATTR = re.compile(r"^\s*#\[(?:ignore\b|cfg_attr\(.*\bignore\b)")
REASON = re.compile(r'\bignore\s*=\s*"([^"]*)"')
FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")


def crate_of(path):
    """The package a source file belongs to."""
    return "fips-core" if path.startswith("core/") else "fips-mesh"


def sites(root):
    """Yield (file, line, fn name or None, reason or None) per ignore attribute."""
    try:
        listed = subprocess.run(
            ["git", "ls-files", "--", "*.rs"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()
    except (OSError, subprocess.CalledProcessError) as err:
        print(f"check-ignored-tests: cannot list sources: {err}", file=sys.stderr)
        sys.exit(2)
    if not listed:
        print("check-ignored-tests: no Rust sources found", file=sys.stderr)
        sys.exit(2)
    for path in listed:
        lines = (root / path).read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if not ATTR.match(line):
                continue
            found = REASON.search(line)
            reason = found.group(1).strip() if found else None
            name = None
            for later in lines[i + 1 : i + 12]:
                match = FN.match(later)
                if match:
                    name = match.group(1)
                    break
            yield path, i + 1, name, reason


def inventory(root):
    """Parse the inventory into (line, class, crate, test path, file) rows."""
    try:
        text = (root / INVENTORY).read_text(encoding="utf-8")
    except OSError as err:
        print(f"check-ignored-tests: cannot read {INVENTORY}: {err}", file=sys.stderr)
        sys.exit(2)
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if line:
            rows.append((number, *line.split()))
    return rows


def main():
    """Compare the ignore attributes with the inventory and report."""
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        print("check-ignored-tests: not inside a git work tree", file=sys.stderr)
        return 2
    root = pathlib.Path(top)
    problems = []
    entries = inventory(root)
    matched = set()

    for row in entries:
        if len(row) != 5:
            problems.append(f"{INVENTORY}:{row[0]}: expected 4 fields, got {len(row) - 1}")
            continue
        number, klass, crate, test, path = row
        if klass not in CLASSES:
            problems.append(f"{INVENTORY}:{number}: unknown class {klass!r}")
        if crate != crate_of(path):
            problems.append(f"{INVENTORY}:{number}: {path} is in {crate_of(path)}, not {crate}")

    count = 0
    for path, line, name, reason in sites(root):
        count += 1
        where = f"{path}:{line}"
        if not reason:
            problems.append(f"{where}: #[ignore] without a reason; write #[ignore = \"why\"]")
        if name is None:
            problems.append(f"{where}: no test function follows the ignore attribute")
            continue
        hits = [
            row
            for row in entries
            if len(row) == 5 and row[4] == path and row[3].split("::")[-1] == name
        ]
        if not hits:
            problems.append(f"{where}: ignored test {name} has no entry in {INVENTORY}")
        elif len(hits) > 1:
            problems.append(f"{where}: ignored test {name} has {len(hits)} entries in {INVENTORY}")
        matched.update(row[0] for row in hits)

    for row in entries:
        if len(row) == 5 and row[0] not in matched:
            problems.append(
                f"{INVENTORY}:{row[0]}: {row[3]} names no ignored test in {row[4]}"
            )

    for problem in problems:
        print(problem)
    if problems:
        print(f"check-ignored-tests: {len(problems)} problem(s)")
        return 1
    print(f"check-ignored-tests: {count} ignored tests, each inventoried with a reason")
    return 0


if __name__ == "__main__":
    sys.exit(main())
