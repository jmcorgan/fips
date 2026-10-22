#!/usr/bin/env python3
"""Fail when a command gives a resource the generic CI label without the run label.

Every container, network, volume and image a local CI run creates carries
`com.corganlabs.fips-ci=1`, which marks it as CI's, and
`com.corganlabs.fips-ci.run=<run id>`, which says whose. The generic label is
shared by every run on the host, so ci-local.sh's teardown reaps by the run
label alone (ci-cleanup.sh --run-id): a resource carrying only the generic
label is never reaped by its own run. If the suite that made it is killed
before its own cleanup runs, the resource outlives the run, and the internal
builder, whose orphan sweep is skipped while any generic-labelled container is
up, stops sweeping for every run after it. A dns-resolver container left that
way stopped the sweep for three days in October 2026.

The labels a suite passes are spelled three ways in the tree, and each is read:
a literal `--label com.corganlabs.fips-ci=1`; a variable holding it
(`LABEL="com.corganlabs.fips-ci=1"` ... `--label "$LABEL"`); and an array
expanded into the command (`"${CI_LABELS[@]}"`, defined in
testing/lib/image-build.sh). Variables and arrays defined in testing/lib/*.sh
are visible to every file, since the suites source that library.

What is read: in sweep mode (no arguments), the files committed at HEAD that
are `*.sh`, `.github/workflows/*.yml` or `*.yaml`, or start with an sh or bash
shebang. File arguments replace the sweep and are read from disk, with the
libraries read from beside this file, which is how the check is tested against
uncommitted copies.

Lines whose first non-blank character is `#` are skipped, a trailing comment
is ignored, and backslash continuations are joined. The rules:

  1. a `docker run`, `docker create`, `docker build`, `docker buildx build`,
     `docker network create` or `docker volume create` whose `--label`
     values, after variables and arrays are expanded, include the generic
     label but no `com.corganlabs.fips-ci.run=` label;
  2. an array whose words include `--label` with the generic label but no
     `--label` with the run label, reported where the array is defined, since
     a helper that passes it on to docker is not a line rule 1 reads.

A finding names the physical line holding the generic label: the literal, the
variable reference or the array expansion.

Before reading anything, the check runs a self-test: planted cases for both
rules and for the shapes that must not be flagged. A wrong verdict there exits
2, so a run that passes has also shown that it can fail.

Known gaps, recorded rather than discovered: a label in a variable passed to a
helper function that runs docker is not followed through the call (rule 2
covers arrays, not scalars); docker's short `-l` flag is not read; a label
whose value is built from a variable assigned in a file that is neither the
same file nor testing/lib/*.sh is not resolved, and so is not seen as either
label; Python callers (chaos/sim/runner.py) and compose files are not read.
Compose services carry only the generic label by design: ci-local.sh names
every compose project per run and reaps by that prefix.

Exit codes:
    0 - nothing flagged
    1 - at least one finding; every one is printed
    2 - the check could not run (not a git work tree, git failed, no files,
        or a self-test verdict was wrong); never a pass
"""

from __future__ import annotations

import re
import shlex
import subprocess
import sys
from pathlib import Path

NAME = "check-ci-labels"
GENERIC = "com.corganlabs.fips-ci=1"
RUN = "com.corganlabs.fips-ci.run="
LIBRARY_DIR = "testing/lib/"

DOCKER_RE = re.compile(
    r"(?<![\w-])docker\s+(?:run|create|build|buildx\s+build|network\s+create"
    r"|volume\s+create)(?![\w-])")
SCALAR_RE = re.compile(
    r"(?:^|(?<=[\s;&|(]))(?:(?:local|declare|readonly|export|typeset)\s+(?:-\w+\s+)*)?"
    r"([A-Za-z_]\w*)=(?!\()(\"[^\"]*\"|'[^']*'|[^\s;&|]*)")
ARRAY_RE = re.compile(
    r"^\s*(?:(?:local|declare|readonly|typeset)\s+(?:-\w+\s+)*)?([A-Za-z_]\w*)\+?=\(")
VAR_RE = re.compile(r"\$\{([A-Za-z_]\w*)(?:[:]?[-=?+][^}]*)?\}|\$([A-Za-z_]\w*)")
ARRAY_USE_RE = re.compile(r"^\$\{([A-Za-z_]\w*)\[[@*]\]\}$")
SHEBANG_RE = re.compile(r"#!\s*(?:\S*/)?(?:env\s+(?:-\S+\s+)*)?(?:\S*/)?(?:ba|da|a)?sh(?:\s|$)")
DEPTH = 6


class Line:
    """One logical shell line: continuations joined, trailing comment dropped.

    `raw` holds the physical lines it came from and `first` the number of the
    first, so a finding can be reported at the physical line that holds it.
    """

    def __init__(self, first: int, raw: list[str], code: str):
        """Record the first physical line number, the physical lines and the code."""
        self.first = first
        self.raw = raw
        self.code = code

    def find(self, pattern: re.Pattern[str]) -> int:
        """Return the number of the first physical line matching PATTERN."""
        for i, text in enumerate(self.raw):
            if pattern.search(strip_comment(text)):
                return self.first + i
        return self.first


def strip_comment(line: str) -> str:
    """Return LINE without a trailing comment.

    A `#` starts a comment only outside quotes, at the start of the line or
    after whitespace, so `${#x}` and `$#` are kept.
    """
    quote = None
    prev = " "
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
        elif c == "#" and prev.isspace():
            return line[:i]
        prev = c
    return line


def logical_lines(text: str) -> list[Line]:
    """Return each logical line of TEXT that is not a whole-line comment."""
    phys = text.split("\n")
    out = []
    i = 0
    while i < len(phys):
        start = i
        line = phys[i]
        i += 1
        if line.lstrip().startswith("#"):
            continue
        raw = [line]
        code = strip_comment(line)
        while re.search(r"(?<!\\)(?:\\\\)*\\$", code) and i < len(phys):
            code = code[:-1] + " "
            nxt = phys[i]
            raw.append(nxt)
            i += 1
            if not nxt.lstrip().startswith("#"):
                code += strip_comment(nxt)
        out.append(Line(start + 1, raw, code))
    return out


def words(code: str) -> list[str]:
    """Split CODE into shell words, quotes removed.

    A line that does not split, such as one opening a quoted string that
    closes on a later line, falls back to whitespace splitting with quote
    characters dropped.
    """
    try:
        return shlex.split(code, comments=False, posix=True)
    except ValueError:
        return [w.replace('"', "").replace("'", "") for w in code.split()]


class Defs:
    """Scalar and array assignments, from one file and the libraries."""

    def __init__(self):
        """Start with no definitions."""
        self.scalars: dict[str, set[str]] = {}
        self.arrays: dict[str, list[tuple[int, list[str]]]] = {}

    def add_text(self, text: str) -> None:
        """Record every assignment in TEXT."""
        for ln in logical_lines(text):
            for m in SCALAR_RE.finditer(ln.code):
                value = m.group(2)
                if value[:1] in ("'", '"'):
                    value = value[1:-1]
                self.scalars.setdefault(m.group(1), set()).add(value)
        for line_no, name, body in arrays_in(text):
            self.arrays.setdefault(name, []).append((line_no, body))

    def expand(self, word: str, depth: int = 0) -> set[str]:
        """Return the texts WORD can expand to, through the known scalars.

        An unknown variable is left as written, so `${FIPS_CI_RUN_ID:-manual}`
        stays a run label.
        """
        if depth >= DEPTH:
            return {word}
        m = next((m for m in VAR_RE.finditer(word) if (m.group(1) or m.group(2)) in self.scalars),
                 None)
        if m is None:
            return {word}
        out: set[str] = set()
        for value in self.scalars[m.group(1) or m.group(2)]:
            out |= self.expand(word[:m.start()] + value + word[m.end():], depth + 1)
        return out

    def flatten(self, ws: list[str], depth: int = 0) -> list[tuple[str, str]]:
        """Expand array uses in WS; return (word, the word it came from) pairs."""
        out: list[tuple[str, str]] = []
        for w in ws:
            m = ARRAY_USE_RE.match(w)
            if m and m.group(1) in self.arrays and depth < DEPTH:
                for _, body in self.arrays[m.group(1)]:
                    out += [(x, w) for x, _ in self.flatten(body, depth + 1)]
            else:
                out.append((w, w))
        return out


def arrays_in(text: str) -> list[tuple[int, str, list[str]]]:
    """Return (line, name, words) for each array assignment in TEXT.

    The body runs from `NAME=(` to the `)` that closes it outside quotes,
    across physical lines, with comments dropped.
    """
    phys = text.split("\n")
    found = []
    for i, line in enumerate(phys):
        if line.lstrip().startswith("#"):
            continue
        m = ARRAY_RE.match(line)
        if not m:
            continue
        body, depth, quote, j, rest = [], 1, None, i, line[m.end():]
        while True:
            chunk = strip_comment(rest)
            for k, c in enumerate(chunk):
                if quote:
                    if c == quote:
                        quote = None
                elif c in ("'", '"'):
                    quote = c
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        body.append(chunk[:k])
                        break
            if depth == 0:
                break
            body.append(chunk.rstrip("\\"))
            j += 1
            if j >= len(phys):
                break
            rest = phys[j] if not phys[j].lstrip().startswith("#") else ""
        found.append((i + 1, m.group(1), words(" ".join(body))))
    return found


def label_values(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Return (value, source word) for each `--label` in PAIRS."""
    out = []
    for k, (w, src) in enumerate(pairs):
        if w == "--label" and k + 1 < len(pairs):
            out.append(pairs[k + 1])
        elif w.startswith("--label="):
            out.append((w[len("--label="):], src))
    return out


def classify(defs: Defs, values: list[tuple[str, str]]) -> tuple[list[str], bool]:
    """Return the source words that give the generic label, and whether any gives the run label."""
    generic, run = [], False
    for value, src in values:
        texts = defs.expand(value)
        if any(GENERIC in t for t in texts):
            generic.append(src)
        if any(RUN in t for t in texts):
            run = True
    return generic, run


def source_pattern(src: str) -> re.Pattern[str]:
    """Return a pattern finding the physical line that wrote SRC."""
    m = ARRAY_USE_RE.match(src)
    if m:
        return re.compile(r"\$\{" + re.escape(m.group(1)) + r"\[[@*]\]\}")
    m = VAR_RE.search(src)
    if m and GENERIC not in src:
        name = m.group(1) or m.group(2)
        return re.compile(r"\$\{?" + re.escape(name) + r"(?!\w)")
    return re.compile(re.escape(GENERIC))


def scan(text: str, libraries: list[str]) -> list[tuple[int, int]]:
    """Return the sorted (line, rule) findings for one file's text."""
    defs = Defs()
    for lib in libraries:
        defs.add_text(lib)
    defs.add_text(text)
    found: set[tuple[int, int]] = set()

    for ln in logical_lines(text):
        if not DOCKER_RE.search(ln.code):
            continue
        generic, run = classify(defs, label_values(defs.flatten(words(ln.code))))
        if generic and not run:
            found.add((ln.find(source_pattern(generic[0])), 1))

    for line_no, _, body in arrays_in(text):
        generic, run = classify(defs, label_values(defs.flatten(body)))
        if generic and not run:
            found.add((line_no, 2))
    return sorted(found)


RULES = {
    1: "a docker command gives the generic CI label without the run label",
    2: "an array of docker arguments holds the generic CI label without the run label",
}

LIB = ('CI_LABELS=(\n    --label com.corganlabs.fips-ci=1\n'
       '    --label "com.corganlabs.fips-ci.run=${FIPS_CI_RUN_ID:-manual}"\n)\n')

# (name, text, expected (line, rule) set). Every rule has a red here, and every
# shape the matchers must leave alone has a green, so a matcher that drifts in
# either direction fails the run before it reads the tree.
CASES: list[tuple[str, str, set[tuple[int, int]]]] = [
    ("literal generic only",
     'docker run -d --label com.corganlabs.fips-ci=1 img\n', {(1, 1)}),
    ("literal generic, quoted, --label= form",
     'docker run -d --label="com.corganlabs.fips-ci=1" img\n', {(1, 1)}),
    ("continued command, finding on the label's line",
     'docker run -d --name x \\\n    --label com.corganlabs.fips-ci=1 \\\n    img\n', {(2, 1)}),
    ("LABEL variable only",
     'LABEL="com.corganlabs.fips-ci=1"\ndocker create --label "$LABEL" img\n', {(2, 1)}),
    ("braced variable on a network create",
     'L=com.corganlabs.fips-ci=1\ndocker network create --label "${L}" n\n', {(2, 1)}),
    ("generic-only array, defined and used",
     'A=(\n    --label com.corganlabs.fips-ci=1\n)\ndocker run "${A[@]}" img\n', {(1, 2), (4, 1)}),
    ("docker build with the generic label",
     'docker build -t t --label com.corganlabs.fips-ci=1 .\n', {(1, 1)}),
    ("volume create through a variable",
     'C=com.corganlabs.fips-ci=1\ndocker volume create --label "$C" v\n', {(2, 1)}),
    ("run label removed from a two-line pair",
     'docker run --rm \\\n    --label com.corganlabs.fips-ci=1 \\\n    --name x img\n', {(2, 1)}),
    ("literal pair", 'docker run --label com.corganlabs.fips-ci=1 '
     '--label "com.corganlabs.fips-ci.run=${FIPS_CI_RUN_ID:-manual}" img\n', set()),
    ("library array", 'docker run -d "${CI_LABELS[@]}" img\n', set()),
    ("variable pair through a key variable",
     'G=com.corganlabs.fips-ci=1\nK=com.corganlabs.fips-ci.run\n'
     'docker volume create --label "$G" --label "$K=$P" v\n', set()),
    ("filter is not a label",
     'L=com.corganlabs.fips-ci=1\ndocker ps --filter "label=$L" -q\n', set()),
    ("reaper option on a non-docker line",
     'L=com.corganlabs.fips-ci=1\nbash ci-cleanup.sh --label "$L" --run-id x\n', set()),
    ("commented-out command",
     '# docker run --label com.corganlabs.fips-ci=1 img\n', set()),
    ("trailing comment", 'echo hi  # docker run --label com.corganlabs.fips-ci=1 img\n', set()),
    ("unlabelled container is not this check's", 'docker run --rm img\n', set()),
    ("library array passed to a helper", 'build_inline t "$df" . "${CI_LABELS[@]}"\n', set()),
    ("array holding both labels",
     'B=(\n    --label com.corganlabs.fips-ci=1  # generic\n'
     '    --label "com.corganlabs.fips-ci.run=$R"\n)\n', set()),
]


def selftest() -> list[str]:
    """Run the planted cases; return a message for each wrong verdict."""
    errors = []
    for name, text, want in CASES:
        got = set(scan(text, [LIB]))
        if got != want:
            errors.append(f"case '{name}': want {sorted(want)}, got {sorted(got)}")
    return errors


def git(root: str | None, *args: str) -> str:
    """Run a git command and return its stdout, exiting 2 if it fails."""
    cmd = ["git"] + (["-C", root] if root else []) + list(args)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"{NAME}: {' '.join(cmd)} failed: {proc.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    return proc.stdout


def wanted(path: str, first_line: str) -> bool:
    """True when PATH is a file the sweep reads."""
    workflow = path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))
    return path.endswith(".sh") or workflow or bool(SHEBANG_RE.match(first_line))


def committed_blobs(root: str) -> list[tuple[str, str]]:
    """Return (path, text) for each file at HEAD the sweep reads."""
    paths = []
    for entry in git(root, "ls-tree", "-r", "-z", "HEAD").split("\0"):
        meta, _, path = entry.partition("\t")
        if path and meta.split()[1] == "blob":
            paths.append(path)
    proc = subprocess.run(["git", "-C", root, "cat-file", "--batch"],
                          input="".join(f"HEAD:{p}\n" for p in paths).encode(),
                          capture_output=True)
    if proc.returncode != 0:
        print(f"{NAME}: git cat-file failed: {proc.stderr.decode().strip()}", file=sys.stderr)
        sys.exit(2)
    data, pos, out = proc.stdout, 0, []
    for p in paths:
        header_end = data.index(b"\n", pos)
        header = data[pos:header_end].split()
        if len(header) < 3 or header[1] != b"blob":
            print(f"{NAME}: unexpected object for {p}: {header!r}", file=sys.stderr)
            sys.exit(2)
        size = int(header[2])
        body = data[header_end + 1:header_end + 1 + size]
        pos = header_end + 1 + size + 1
        text = body.decode("utf-8", "replace")
        if wanted(p, text.split("\n", 1)[0]):
            out.append((p, text))
    return out


def main(argv: list[str]) -> int:
    """Self-test, then scan the committed tree (or the named files)."""
    if argv and argv[0] in ("-h", "--help"):
        print(f"usage: {NAME}.py [FILE...]\n"
              "  no FILE: read the files committed at HEAD\n"
              "  FILE...: read these files from disk instead (for testing the check)")
        return 0

    errors = selftest()
    if errors:
        for e in errors:
            print(f"{NAME}: self-test: {e}", file=sys.stderr)
        return 2

    if argv:
        files = []
        for a in argv:
            try:
                files.append((a, Path(a).read_text(errors="replace")))
            except OSError as e:
                print(f"{NAME}: cannot read {a}: {e}", file=sys.stderr)
                return 2
        lib_dir = Path(__file__).resolve().parent / "lib"
        libraries = [p.read_text(errors="replace") for p in sorted(lib_dir.glob("*.sh"))]
    else:
        root = git(None, "rev-parse", "--show-toplevel").strip()
        if not root:
            print(f"{NAME}: empty work-tree root", file=sys.stderr)
            return 2
        files = committed_blobs(root)
        libraries = [t for p, t in files
                     if p.startswith(LIBRARY_DIR) and p.endswith(".sh")
                     and "/" not in p[len(LIBRARY_DIR):]]
    if not files:
        print(f"{NAME}: no shell or workflow files to read", file=sys.stderr)
        return 2
    if not libraries:
        print(f"{NAME}: no {LIBRARY_DIR}*.sh libraries found; cannot resolve CI_LABELS",
              file=sys.stderr)
        return 2

    findings = []
    for path, text in files:
        for line, rule in scan(text, libraries):
            findings.append(f"{path}:{line}: rule {rule}: {RULES[rule]}")

    if findings:
        for f in findings:
            print(f)
        sys.stdout.flush()
        print("", file=sys.stderr)
        print(f"{NAME}: a resource with only {GENERIC} is not reaped by its run's",
              file=sys.stderr)
        print("teardown. Pass \"${CI_LABELS[@]}\" from testing/lib/image-build.sh, or add",
              file=sys.stderr)
        print("--label \"com.corganlabs.fips-ci.run=${FIPS_CI_RUN_ID:-manual}\".", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
