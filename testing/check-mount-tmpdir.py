#!/usr/bin/env python3
"""Fail when a bare `mktemp` result can become a `docker run` bind-mount source.

A bind-mount source is resolved by the Docker daemon in the host's mount
namespace, never in the caller's. Where the caller runs with a private /tmp
(systemd's PrivateTmp=, which the builder's CI worker sets), a directory from
a bare `mktemp -d` exists only for the caller: the daemon creates an empty one
at the same path on the host, and the container and the script then work in
two different directories without either saying so. A mounted `mktemp` file
fails the same way and arrives as a directory. Nothing on GitHub's runners
shows it, so without this check the first sign is a builder run that fails
for no visible reason.

The one sanctioned way to make such a directory is `shared_tmpdir ROOT NAME`
in testing/lib/image-build.sh, whose doc comment explains how to pick ROOT.

What is read: in sweep mode (no arguments), the files committed at HEAD that
are `*.sh`, `.github/workflows/*.yml` or `*.yaml`, or start with an sh or bash
shebang. File arguments replace the sweep and are read from disk, which is
how the check is tested against uncommitted copies.

Lines whose first non-blank character is `#` are skipped, a trailing comment
is ignored, and backslash continuations are joined; a finding names the
physical line of the match inside the joined line, and a marker is read from
that same line.

A bind-mount source is the shell word after a `-v` or `--volume` token,
quotes included, that (after one leading quote) begins with `$` and contains
`:/`; or a `--mount` with `type=bind` whose `source=` or `src=` begins with
`$`. The rules, per file:

  1. a mount source whose variable was assigned from a command substitution
     holding `mktemp` (directory or file), or from a function defined in the
     same file whose body holds one, directly or through assignments that
     name a tainted variable;
  2. in a file with any mount source, every `mktemp -d` (any short-option
     cluster holding `d`, or `--directory`) not marked on its line with
     `# mount-tmpdir: <reason>`. This covers sources reached through function
     arguments and loop variables, which rule 1 does not follow. A `mktemp`
     inside a quoted string that opens and closes on the same line, and is
     not inside a `$(...)` or backtick substitution there, is text such as an
     error message, not a command, and is not counted;
  3. a mount source made inline by `$(mktemp ...)`;
  4. a definition of `shared_tmpdir` anywhere but testing/lib/image-build.sh;
  5. a `shared_tmpdir` call whose ROOT literally starts with /tmp, /var/tmp
     or $TMPDIR.

testing/lib/image-build.sh is exempt from rules 1, 2, 3 and 5: it is the one
producer and has no mounts.

Before reading anything, the check runs a self-test: planted cases for every
rule and for the shapes that must not be flagged, and the helper itself (from
HEAD in sweep mode, from beside this file in file mode) run through bash
against a temporary directory. A wrong verdict there exits 2, so a run that
passes has also shown that it can fail.

Known gaps, recorded rather than discovered: rule 2 is per file, so a
directory made in one file and mounted by a script in another is not seen;
rule 5 reads only a literal ROOT, so `R=/tmp; shared_tmpdir "$R" x` passes;
Python `tempfile` in a script that mounts is not read; compose `volumes:`
entries are not read; mount flags carried in an unquoted variable
(`m="-v $d:/x"; docker run $m`) and a source joined to its flag with no space
(`-v"$d:/x"`) are not seen as mounts, so they neither trigger rule 1 nor make
the file one that rule 2 reads; a quoted string spanning several lines, such
as a multi-line `bash -c '...'` script, is read line by line as if unquoted,
so a `mktemp -d` inside one still counts for rule 2; run as root, the
self-test's unremovable-directory case is removable and so does not exercise
the failure it targets.

Exit codes:
    0 - nothing flagged
    1 - at least one finding; every one is printed
    2 - the check could not run (not a git work tree, git failed, no files,
        bash missing, or a self-test verdict was wrong); never a pass
"""

from __future__ import annotations

import bisect
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

NAME = "check-mount-tmpdir"
LIBRARY = "testing/lib/image-build.sh"
PROXY_LIBRARY = "testing/lib/build-proxy.sh"

FLAG_RE = re.compile(r"(?:^|(?<=[\s;&|(]))(-v|--volume)(?=[\s=])")
MOUNT_RE = re.compile(r"(?:^|(?<=[\s;&|(]))--mount(?=[\s=])")
ASSIGN_RE = re.compile(r"(?:^|(?<=[\s;&|(]))([A-Za-z_]\w*)=")
MKTEMP_RE = re.compile(r"(?<![\w.-])mktemp(?![\w-])")
SUBST_RE = re.compile(r"(\$\(|`)")
FUNC_RE = re.compile(r"^\s*(?:function\s+([A-Za-z_][\w-]*)|([A-Za-z_][\w-]*)\s*\(\s*\))")
DEF_RE = re.compile(r"(?:^|[\s;&|{])(?:function\s+shared_tmpdir(?![\w-])|shared_tmpdir\s*\(\s*\))")
CALL_RE = re.compile(r"(?<![\w-])shared_tmpdir(?![\w-])(?!\s*\(\s*\))")
MARKER_RE = re.compile(r"#\s*mount-tmpdir:(.*)$")
ROOT_RE = re.compile(r"(?:/tmp|/var/tmp)(?:/|$)|\$\{?TMPDIR(?!\w)")
SHEBANG_RE = re.compile(r"#!\s*(?:\S*/)?(?:env\s+(?:-\S+\s+)*)?(?:\S*/)?(?:ba|da|a)?sh(?:\s|$)")
STOP = set(";|&<>)")

RULES = {
    1: "bind-mount source made by mktemp; create it with shared_tmpdir",
    2: "mktemp -d in a file that bind-mounts; use shared_tmpdir, or mark a "
       "directory that is never mounted with '# mount-tmpdir: <reason>'",
    3: "bind-mount source made inline by mktemp; create it with shared_tmpdir",
    4: f"shared_tmpdir redefined; source {LIBRARY} instead",
    5: "shared_tmpdir root is the system temp directory, which the daemon may not see",
}


def read_word(s: str, i: int) -> tuple[str, int]:
    """Return the shell word starting at s[i] and the index just past it.

    The word ends at unquoted whitespace or a shell operator outside any
    `$(...)` or `${...}`, so quotes and command substitutions stay inside it.
    """
    stack: list[str] = []
    j, n = i, len(s)
    while j < n:
        c = s[j]
        top = stack[-1] if stack else None
        if top == "'":
            if c == "'":
                stack.pop()
            j += 1
            continue
        if c == "\\":
            j += 2
            continue
        if top == '"':
            if c == '"':
                stack.pop()
            elif c == "$" and s[j + 1:j + 2] in ("(", "{"):
                stack.append("$" + s[j + 1])
                j += 2
                continue
            j += 1
            continue
        if top is None and (c.isspace() or c in STOP):
            break
        if c in ("'", '"'):
            stack.append(c)
        elif c == "$" and s[j + 1:j + 2] in ("(", "{"):
            stack.append("$" + s[j + 1])
            j += 2
            continue
        elif c == "(" and top in ("$(", "("):
            stack.append("(")
        elif c == ")" and top in ("$(", "("):
            stack.pop()
        elif c == "}" and top == "${":
            stack.pop()
        j += 1
    return s[i:j], min(j, n)


def strip_comment(line: str) -> str:
    """Return the line without a trailing shell comment.

    A `#` starts a comment only outside quotes and substitutions, at the start
    of the line or after whitespace, so `${#x}` and `$#` are kept.
    """
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c.isspace() or c in STOP:
            i += 1
        elif c == "#":
            return line[:i]
        else:
            _, end = read_word(line, i)
            i = max(end, i + 1)
    return line


def words_after(code: str, i: int) -> list[str]:
    """Return the words of the simple command that continues at code[i]."""
    out = []
    n = len(code)
    while i < n:
        while i < n and code[i].isspace():
            i += 1
        if i >= n or code[i] in STOP:
            break
        word, i = read_word(code, i)
        if not word:
            break
        out.append(word)
    return out


class Line:
    """One logical shell line: continuations joined, trailing comment removed.

    `code` is the joined text; `raw` holds the physical lines it came from, so
    a match at any offset in `code` can be reported at its own physical line
    and checked for that line's marker.
    """

    def __init__(self, first: int, raw: list[str], code: str, breaks: list[int]):
        """Record the first physical line number and where each later one starts."""
        self.first = first
        self.raw = raw
        self.code = code
        self.breaks = breaks

    def at(self, pos: int) -> int:
        """Return the physical line number holding offset POS of `code`."""
        return self.first + bisect.bisect_right(self.breaks, pos)

    def raw_at(self, pos: int) -> str:
        """Return the physical line holding offset POS of `code`."""
        return self.raw[self.at(pos) - self.first]


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
        raw, breaks = [line], []
        while re.search(r"(?<!\\)(?:\\\\)*\\$", line) and i < len(phys):
            line = line[:-1] + " "
            breaks.append(len(line))
            line += phys[i]
            raw.append(phys[i])
            i += 1
        out.append(Line(start + 1, raw, strip_comment(line), breaks))
    return out


def unquote(word: str) -> str:
    """Drop one leading quote character."""
    return word[1:] if word[:1] in ("'", '"') else word


def lead_var(value: str) -> str | None:
    """Return the variable a `$...` word starts with, or None for `$(`."""
    m = re.match(r"\$\{?([A-Za-z_]\w*|\d+)", value)
    return m.group(1) if m else None


def mount_sources(code: str) -> list[tuple[int, str | None, str]]:
    """Return (offset, leading variable, word) for each bind-mount source."""
    found = []
    for m in FLAG_RE.finditer(code):
        i = m.end()
        while i < len(code) and (code[i].isspace() or code[i] == "="):
            i += 1
        word, _ = read_word(code, i)
        bare = unquote(word)
        if bare.startswith("$") and ":/" in word:
            found.append((m.start(), lead_var(bare), word))
    for m in MOUNT_RE.finditer(code):
        i = m.end()
        while i < len(code) and (code[i].isspace() or code[i] == "="):
            i += 1
        word, _ = read_word(code, i)
        fields = word.replace('"', "").replace("'", "").split(",")
        if "type=bind" not in fields:
            continue
        for f in fields:
            key, _, val = f.partition("=")
            if key in ("source", "src") and val.startswith("$"):
                found.append((m.start(), lead_var(val), word))
    return found


def quoted_at(code: str, pos: int) -> bool:
    """True when code[pos] is literal text inside quotes or a `${...}` word.

    Quotes and substitutions are tracked from the start of the logical line,
    so a `$(...)` or backtick substitution inside double quotes counts as
    code again, as the shell runs it.
    """
    stack: list[str] = []
    j = 0
    while j < pos:
        c = code[j]
        top = stack[-1] if stack else None
        if top == "'":
            if c == "'":
                stack.pop()
            j += 1
            continue
        if c == "\\":
            j += 2
            continue
        two = code[j:j + 2]
        if top == '"' and c == '"':
            stack.pop()
        elif top == "`" and c == "`":
            stack.pop()
        elif two in ("$(", "${"):
            stack.append(two)
            j += 2
            continue
        elif c == "`":
            stack.append(c)
        elif top != '"' and c in ("'", '"'):
            stack.append(c)
        elif top in ("$(", "(") and c == "(":
            stack.append(c)
        elif top in ("$(", "(") and c == ")":
            stack.pop()
        elif top == "${" and c == "}":
            stack.pop()
        j += 1
    return bool(stack) and stack[-1] in ("'", '"', "${")


def mktemp_args(code: str, end: int) -> list[str]:
    """Return the unquoted arguments of the `mktemp` ending at code[end].

    A backtick ends the substitution the command sits in, so the argument
    holding one is cut there and nothing after it belongs to `mktemp`.
    """
    args = []
    for word in words_after(code, end):
        bare = word.replace('"', "").replace("'", "")
        head, tick, _ = bare.partition("`")
        if head:
            args.append(head)
        if tick:
            break
    return args


def dir_mktemps(code: str) -> list[int]:
    """Return the offset of each `mktemp` command on a line that makes a directory."""
    out = []
    for m in MKTEMP_RE.finditer(code):
        if quoted_at(code, m.start()):
            continue
        if any(a == "--directory" or (re.fullmatch(r"-[A-Za-z]+", a) and "d" in a)
               for a in mktemp_args(code, m.end())):
            out.append(m.start())
    return out


def producers(lines: list[Line]) -> set[str]:
    """Return the functions defined in the file whose body holds `mktemp`."""
    names = set()
    for idx, ln in enumerate(lines):
        code = ln.code
        m = FUNC_RE.match(code)
        if not m:
            continue
        name = m.group(1) or m.group(2)
        rest = code[m.end():]
        if "{" in rest and rest.rstrip().endswith("}"):
            body = [rest]
        else:
            indent = len(code) - len(code.lstrip())
            body = []
            for later in (x.code for x in lines[idx + 1:]):
                if later.strip() == "}" and len(later) - len(later.lstrip()) == indent:
                    break
                body.append(later)
        if any(MKTEMP_RE.search(b) for b in body):
            names.add(name)
    return names


def tainted_vars(lines: list[Line]) -> set[str]:
    """Return the variables that hold a `mktemp` result, to a fixed point."""
    funcs = producers(lines)
    assigns = []
    for ln in lines:
        for m in ASSIGN_RE.finditer(ln.code):
            value, _ = read_word(ln.code, m.end())
            assigns.append((m.group(1), value))
    tainted: set[str] = set()
    for var, value in assigns:
        if SUBST_RE.search(value) and MKTEMP_RE.search(value):
            tainted.add(var)
        elif any(f in funcs for f in re.findall(r"\$\(\s*([A-Za-z_][\w-]*)", value)):
            tainted.add(var)
    changed = True
    while changed:
        changed = False
        for var, value in assigns:
            if var in tainted:
                continue
            if any(re.search(r"\$\{?" + re.escape(t) + r"(?!\w)", value) for t in tainted):
                tainted.add(var)
                changed = True
    return tainted


def scan(path: str, text: str) -> list[tuple[int, int]]:
    """Return the sorted (line, rule) findings for one file's text."""
    lines = logical_lines(text)
    library = path == LIBRARY
    found: set[tuple[int, int]] = set()

    for ln in lines:
        m = DEF_RE.search(ln.code)
        if m and not library:
            found.add((ln.at(m.start()), 4))
    if library:
        return sorted(found)

    tainted = tainted_vars(lines)
    has_mount = False
    for ln in lines:
        for pos, var, word in mount_sources(ln.code):
            has_mount = True
            if var is not None and var in tainted:
                found.add((ln.at(pos), 1))
            if re.search(r"\$\(\s*mktemp(?![\w-])", word):
                found.add((ln.at(pos), 3))
        for m in CALL_RE.finditer(ln.code):
            args = words_after(ln.code, m.end())
            if args and args[0] == "--sweep":
                args = args[1:]
            if args and ROOT_RE.match(args[0].replace('"', "").replace("'", "")):
                found.add((ln.at(m.start()), 5))

    if has_mount:
        for ln in lines:
            for pos in dir_mktemps(ln.code):
                mark = MARKER_RE.search(ln.raw_at(pos))
                if not (mark and mark.group(1).strip()):
                    found.add((ln.at(pos), 2))
    return sorted(found)


# (name, text, expected (line, rule) set). Every rule has a red here, and every
# shape the matchers must leave alone has a green, so a matcher that drifts in
# either direction fails the run before it reads the tree.
CASES: list[tuple[str, str, set[tuple[int, int]]]] = [
    ("direct mktemp -d mounted as \"$d:/x\"",
     'd=$(mktemp -d)\ndocker run -v "$d:/x" img\n', {(1, 2), (2, 1)}),
    ("direct mktemp -d mounted as \"$d\":/x",
     'd=$(mktemp -d)\ndocker run -v "$d":/x img\n', {(1, 2), (2, 1)}),
    ("derived one hop",
     'base=$(mktemp -d)\nd="$base/sub"\ndocker run -v "$d:/x" img\n', {(1, 2), (3, 1)}),
    ("--mount type=bind",
     'd=$(mktemp -d)\ndocker run --mount type=bind,source=$d,target=/x img\n', {(1, 2), (2, 1)}),
    ("local function producer",
     'mk() {\n    mktemp -d "/tmp/x.XXXXXX"\n}\nd="$(mk)"\ndocker run -v "$d:/x" img\n',
     {(2, 2), (5, 1)}),
    ("inline mktemp source",
     'docker run -v "$(mktemp -d):/x" img\n', {(1, 2), (1, 3)}),
    ("shared_tmpdir redefined",
     'shared_tmpdir() {\n    mkdir -p "$1"\n}\n', {(1, 4)}),
    ("argument route",
     'd=$(mktemp -d)\nstart() { docker run -v "$1:/x" img; }\nstart "$d"\n', {(1, 2)}),
    ("argument route through a backtick mktemp",
     'd=`mktemp -d`\nstart() { docker run -v "$1:/x" img; }\nstart "$d"\n', {(1, 2)}),
    ("backtick mktemp -d inside double quotes",
     'd="`mktemp -d`"\ndocker run -v "$PWD:/src" img\n', {(1, 2)}),
    ("mktemp -d substitution inside a double-quoted message",
     'echo "made $(mktemp -d)"\ndocker run -v "$PWD:/src" img\n', {(1, 2)}),
    ("mktemp -dt in a file with a mount",
     'd=$(mktemp -dt x)\ndocker run -v "$PWD:/src" img\n', {(1, 2)}),
    ("mktemp --directory in a file with a mount",
     'd=$(mktemp --directory)\ndocker run -v "$PWD:/src" img\n', {(1, 2)}),
    ("mktemp -p DIR -d in a file with a mount",
     'd=$(mktemp -p "$R" -d)\ndocker run -v "$PWD:/src" img\n', {(1, 2)}),
    ("marker with an empty reason",
     'd=$(mktemp -d)  # mount-tmpdir:\ndocker run -v "$PWD:/src" img\n', {(1, 2)}),
    ("mounted mktemp file",
     'f=$(mktemp)\ndocker run -v "$f:/etc/x.yaml" img\n', {(2, 1)}),
    ("continued docker run",
     'd=$(mktemp -d)\ndocker run --rm \\\n    -v "$d:/x" \\\n    img\n', {(1, 2), (3, 1)}),
    ("shared_tmpdir under ${TMPDIR:-/tmp}",
     'd=$(shared_tmpdir "${TMPDIR:-/tmp}" x)\ndocker run -v "$d:/x" img\n', {(1, 5)}),
    ("shared_tmpdir --sweep under /tmp",
     'd=$(shared_tmpdir --sweep /tmp/r x)\ndocker run -v "$d:/x" img\n', {(1, 5)}),
    ("shared_tmpdir result mounted",
     'd=$(shared_tmpdir "$R" x)\ndocker run -v "$d:/x" img\n', set()),
    ("shared_tmpdir --sweep in the output directory",
     'd=$(shared_tmpdir --sweep "$DEST_ABS" .name)\ndocker run -v "$d":/name img\n', set()),
    ("mktemp -d with no mount in the file", 'd=$(mktemp -d)\ncp a "$d"\n', set()),
    ("mktemp log never mounted",
     'log=$(mktemp)\ndocker run -v "$PWD:/src" img >"$log"\n', set()),
    ("awk -v is not a mount", 'f=$(mktemp)\nawk -v v="$f:/x" 1 in\n', set()),
    ("command -v is not a mount", 't=$(mktemp -d)\ncommand -v "$t" >/dev/null\n', set()),
    ("--volumes is not --volume",
     'd=$(mktemp -d)\ndocker compose down --volumes "$d:/x"\n', set()),
    ("commented-out mount", 'd=$(mktemp -d)\n# docker run -v "$d:/x" img\n', set()),
    ("mount in a trailing comment",
     'd=$(mktemp -d)\necho hi  # docker run -v "$d:/x" img\n', set()),
    ("mktemp -d in a double-quoted message",
     'echo "mktemp -d failed" >&2\ndocker run -v "$PWD:/src" img\n', set()),
    ("mktemp -d in a single-quoted message",
     "echo 'mktemp -d failed' >&2\ndocker run -v \"$PWD:/src\" img\n", set()),
    ("mktemp -d after a quoted message closes",
     'echo "x"; d=$(mktemp -d)\ndocker run -v "$PWD:/src" img\n', {(1, 2)}),
    ("backtick mktemp with no -d argument",
     'f=`mktemp` -d\ndocker run -v "$PWD:/src" img\n', set()),
    ("marked build context",
     'ctx="$(mktemp -d)"  # mount-tmpdir: build context\ndocker run -v "$PWD:/src" img\n',
     set()),
]


def selftest_rules() -> list[str]:
    """Run the planted cases; return a message for each wrong verdict."""
    errors = []
    for name, text, want in CASES:
        got = set(scan("selftest.sh", text))
        if got != want:
            errors.append(f"rule case '{name}': want {sorted(want)}, got {sorted(got)}")
    lib_text = ('shared_tmpdir() { mktemp -d "$1/x.XXXXXX"; }\n'
                'd=$(mktemp -d)\ndocker run -v "$d:/x" img\n')
    if scan(LIBRARY, lib_text):
        errors.append("rule case 'library exempt': flagged")
    return errors


def run_helper(src: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run shared_tmpdir from SRC under `set -euo pipefail` with ARGS."""
    script = 'set -euo pipefail; source "$1"; shift; shared_tmpdir "$@"'
    return subprocess.run(["bash", "-c", script, "helper", str(src), *args],
                          capture_output=True, text=True)


def age(path: Path, hours: float) -> None:
    """Back-date PATH's mtime by HOURS."""
    t = time.time() - hours * 3600
    os.utime(path, (t, t))


def new_dir(proc: subprocess.CompletedProcess[str], root: Path, name: str) -> bool:
    """True when the helper printed one existing ROOT/NAME.* directory."""
    out = proc.stdout.strip()
    return (proc.returncode == 0 and "\n" not in out and out.startswith(f"{root}/{name}.")
            and Path(out).is_dir())


def selftest_helper(helper_text: str, proxy_text: str) -> list[str]:
    """Run the helper through bash in a temporary directory.

    The directory is never a mount source, which is why it may live in the
    system temp directory, and it keeps the test free of any worktree state.
    """
    errors = []
    with tempfile.TemporaryDirectory(prefix=f"{NAME}-") as tmp:
        base = Path(tmp)
        src = base / "image-build.sh"
        src.write_text(helper_text)
        # image-build.sh sources build-proxy.sh from its own directory.
        (base / "build-proxy.sh").write_text(proxy_text)
        stuck_sub = None
        try:
            root = base / "plain"
            p = run_helper(src, str(root), "x")
            if not new_dir(p, root, "x") or p.stderr:
                errors.append(f"helper case 'creates ROOT/x.*': exit {p.returncode}, "
                              f"stdout {p.stdout!r}, stderr {p.stderr!r}")

            for label, args in (("empty ROOT", ("", "x")), ("NAME with '/'", (str(root), "a/b"))):
                p = run_helper(src, *args)
                if p.returncode != 2 or not p.stderr:
                    errors.append(f"helper case '{label}': want exit 2 with a message, "
                                  f"got exit {p.returncode}, stderr {p.stderr!r}")

            root = base / "sweep"
            (root / "x.old").mkdir(parents=True)
            (root / "x.new").mkdir()
            age(root / "x.old", 3)
            p = run_helper(src, "--sweep", str(root), "x")
            swept = not (root / "x.old").exists() and (root / "x.new").is_dir()
            if not new_dir(p, root, "x") or not swept:
                errors.append(f"helper case '--sweep removes only stale': exit {p.returncode}, "
                              f"x.old {'kept' if (root / 'x.old').exists() else 'gone'}, "
                              f"x.new {'kept' if (root / 'x.new').exists() else 'gone'}")

            root = base / "nosweep"
            (root / "x.old").mkdir(parents=True)
            age(root / "x.old", 3)
            p = run_helper(src, str(root), "x")
            if not new_dir(p, root, "x") or not (root / "x.old").is_dir():
                errors.append(f"helper case 'no sweep without --sweep': exit {p.returncode}, "
                              f"x.old {'kept' if (root / 'x.old').exists() else 'gone'}")

            root = base / "stuck"
            stuck_sub = root / "x.stuck" / "sub"
            stuck_sub.mkdir(parents=True)
            (stuck_sub / "file").write_text("held\n")
            stuck_sub.chmod(0o500)
            age(root / "x.stuck", 3)
            p = run_helper(src, "--sweep", str(root), "x")
            if not new_dir(p, root, "x") or p.stderr:
                errors.append(f"helper case 'unremovable stale dir is silent': exit "
                              f"{p.returncode}, stderr {p.stderr!r}")
        finally:
            if stuck_sub is not None and stuck_sub.exists():
                stuck_sub.chmod(0o700)
    return errors


def git(root: str | None, *args: str) -> str:
    """Run a git command and return its stdout, exiting 2 if it fails."""
    cmd = ["git"] + (["-C", root] if root else []) + list(args)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"{NAME}: {' '.join(cmd)} failed: {proc.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    return proc.stdout


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
        first = body.split(b"\n", 1)[0]
        workflow = p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))
        if p.endswith(".sh") or workflow or SHEBANG_RE.match(first.decode("utf-8", "replace")):
            out.append((p, body.decode("utf-8", "replace")))
    return out


def main(argv: list[str]) -> int:
    """Self-test, then scan the committed tree (or the named files)."""
    if argv and argv[0] in ("-h", "--help"):
        print(f"usage: {NAME}.py [FILE...]\n"
              "  no FILE: read the files committed at HEAD\n"
              "  FILE...: read these files from disk instead (for testing the check)")
        return 0
    if shutil.which("bash") is None:
        print(f"{NAME}: bash not found; cannot run the helper self-test", file=sys.stderr)
        return 2

    if argv:
        files = []
        for a in argv:
            try:
                files.append((a, Path(a).read_text(errors="replace")))
            except OSError as e:
                print(f"{NAME}: cannot read {a}: {e}", file=sys.stderr)
                return 2
        helper_text = (Path(__file__).resolve().parent / "lib" / "image-build.sh").read_text()
        proxy_text = (Path(__file__).resolve().parent / "lib" / "build-proxy.sh").read_text()
    else:
        root = git(None, "rev-parse", "--show-toplevel").strip()
        if not root:
            print(f"{NAME}: empty work-tree root", file=sys.stderr)
            return 2
        files = committed_blobs(root)
        helper_text = git(root, "show", f"HEAD:{LIBRARY}")
        proxy_text = git(root, "show", f"HEAD:{PROXY_LIBRARY}")

    errors = selftest_rules() + selftest_helper(helper_text, proxy_text)
    if errors:
        for e in errors:
            print(f"{NAME}: self-test: {e}", file=sys.stderr)
        return 2
    if not files:
        print(f"{NAME}: no shell or workflow files to read", file=sys.stderr)
        return 2

    findings = []
    for path, text in files:
        rel = path
        if argv:
            absolute = os.path.abspath(path)
            top = str(Path(__file__).resolve().parent.parent)
            if absolute.startswith(top + os.sep):
                rel = os.path.relpath(absolute, top)
        by_line: dict[int, list[int]] = {}
        for line, rule in scan(rel, text):
            by_line.setdefault(line, []).append(rule)
        for line, rules in by_line.items():
            what = "; ".join(f"rule {r}: {RULES[r]}" for r in rules)
            findings.append(f"{path}:{line}: {what}")

    if findings:
        for f in findings:
            print(f)
        print("", file=sys.stderr)
        print(f"{NAME}: a bind-mount source the Docker daemon cannot see becomes an empty",
              file=sys.stderr)
        print(f"directory on the host. Make it with shared_tmpdir from {LIBRARY}.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
