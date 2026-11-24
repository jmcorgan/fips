#!/usr/bin/env python3
"""Fail when the Nostr rendezvous machine reaches outside its fence.

src/nostr/machine/ is written `no_std`-clean by convention: it names `core`,
`alloc`, `fips_core` and a few allowed crates, and nothing else in the root
crate. Nothing builds it without `std`, so this check is what holds the fence.
It reads text, not types: it is a review aid that fails CI, not a proof. It
flags the names below and passes the rest, so a crate it does not name (`ring`,
say) passes it.

What is flagged, in each non-test `.rs` file under the module:

  * a path rooted at std, tokio, tracing, nostr_sdk, rand, libc, if_addrs,
    socket2 or arc_swap, anywhere in the code, and such a name at the root of
    a `use` tree whatever follows it (`::`, `as`, `;`, `,`, `}`), so an alias
    of a banned crate is flagged where it is made;
  * a `crate::` path outside `crate::nostr::machine` (matched at a path
    boundary, so `crate::nostr::machinery` is outside), and `crate` at the
    root of a `use` tree not followed by `::` (`use crate as root;`);
  * a leading chain of `super` and `self` segments with more `super`s than the
    file's depth below the module (machine/mod.rs is 0, machine/x.rs and
    machine/x/mod.rs are 1, ...), so the path would climb out of it; this
    covers `self::super::` and `use super as x;`;
  * a `super` inside a `use` group, flagged outright: write the full path;
  * `extern crate`, flagged outright: the module needs none, and one can alias
    a banned crate;
  * a `#[path = "..."]` attribute other than one to `tests/<file>.rs`, which
    could pull a shell file into the module unscanned, and any `path =` inside
    a `#[cfg_attr(...)]`, whatever its value: the module needs none;
  * a `mod` named `tests`, or carrying a `#[path]`, without `#[cfg(test)]`
    among its attributes, since its file is not scanned and would otherwise
    build into the module;
  * the macros that reach outside with no path written: println!, eprintln!,
    print!, eprint!, dbg!, thread_local! (std-only), instr_step! (the root's
    `#[macro_use]` instrumentation) and include! (pulls in unscanned code),
    also after a path (`core::include!`), and any of their names in a `use`
    item, so a macro imported under another name is flagged where it is.

Comments, string literals (plain, byte, C and their raw forms) and char literals are blanked
by one left-to-right scan before matching, keeping every offset, so a quote
inside a comment or a `'"'` literal cannot hide the code after it. A `use` item
is read whole, to its `;`, so a group wrapped over several lines is one item.
Files under a `tests/` directory or named `tests.rs` are skipped: they build
only for the host, which the `#[cfg(test)]` rule above holds. `EXEMPT` holds any other file that must be, each with its
reason.

Known gaps, recorded rather than discovered: an item reached through a
re-export or alias defined outside the module; a path a macro assembles, other
than the macros named above (a new `#[macro_use]` module in the root needs its
macros added to MACROS); a `std`-gated method on an allowed type; inside an
inline `mod` block, depth is one short, which errs toward red; a `use` tree the
parser cannot read is flagged, which also errs toward red; a nested `use`
group whose own root is `crate` or `super` (`use crate::{nostr::machine::x}`)
is flagged even when it stays inside, toward red again; a test module gated
by anything but exactly `#[cfg(test)]` (`#[cfg(all(test, x))]`) is flagged,
toward red.

Input: by default the files committed at HEAD under src/nostr/machine/ of the
repository holding the current directory; `--root DIR` reads a directory laid
out as the module instead (the fixtures in testing/nostr-machine/ use it).

Exit codes:
    0 - nothing flagged
    1 - something flagged; every hit is printed
    2 - the check could not look (git failed, or no Rust file was found);
        never a pass
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

MODULE = "src/nostr/machine/"
BANNED = ("std", "tokio", "tracing", "nostr_sdk", "rand", "libc", "if_addrs", "socket2", "arc_swap")
MACROS = ("println", "eprintln", "print", "eprint", "dbg", "thread_local", "instr_step", "include")
EXEMPT: dict[str, str] = {}
INSIDE = re.compile(r"crate::nostr::machine(?![\w])")
TESTPATH = re.compile(r"tests/[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*\.rs")
RAWSTR = re.compile(r'[bc]?r(#*)"')
CFGTEST = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
VIS = re.compile(r"(?:pub\s*(?:\([^()]*\))?|unsafe)$")
MODITEM = re.compile(r"(?<![\w])mod\s+(?:r#)?([A-Za-z_]\w*)\s*[;{]")
CHARLIT = re.compile(r"'(?:\\(?:u\{[0-9A-Fa-f]+\}|x[0-9A-Fa-f]{2}|.)|[^'\\\n])'")
TOKEN = re.compile(r"\s*(::|[{},;*]|[A-Za-z_][A-Za-z0-9_]*)")


def fail_look(msg: str) -> None:
    """Report that the check could not look, and exit 2."""
    print(f"check-nostr-machine: {msg}", file=sys.stderr)
    sys.exit(2)


def git(*args: str) -> str:
    """Run git and return its stdout, or report that the check could not look."""
    proc = subprocess.run(["git", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        fail_look(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def committed() -> dict[str, str]:
    """The module's committed files at HEAD, by path relative to the module."""
    top = git("rev-parse", "--show-toplevel").strip()
    if not top:
        fail_look("empty work-tree root")
    files = {}
    for path in git("-C", top, "ls-tree", "-r", "--name-only", "HEAD", "--", MODULE).splitlines():
        if path.endswith(".rs"):
            files[path[len(MODULE):]] = git("-C", top, "show", f"HEAD:{path}")
    return files


def from_root(root: pathlib.Path) -> dict[str, str]:
    """The `.rs` files under `root`, by path relative to it."""
    return {str(p.relative_to(root)): p.read_text() for p in sorted(root.rglob("*.rs"))}


def is_test_path(rel: str) -> bool:
    """True for files only ever built for the test harness."""
    parts = rel.split("/")
    return "tests" in parts[:-1] or parts[-1] == "tests.rs"


def depth(rel: str) -> int:
    """Module depth below the machine module."""
    parts = rel.split("/")
    if parts[-1] == "mod.rs":
        parts = parts[:-1]
    else:
        parts[-1] = parts[-1][:-3]
    return len(parts)


def blank(s: str) -> str:
    """Spaces in place of `s`, keeping its newlines."""
    return re.sub(r"[^\n]", " ", s)


def strip(text: str) -> str:
    """Blank comments and the contents of string and char literals, keeping offsets."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        word = i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_")
        raw = None if word else RAWSTR.match(text, i)
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(blank(text[i:j]))
            i = j
        elif text.startswith("/*", i):
            j, level = i + 2, 1
            while j < n and level:
                if text.startswith("/*", j):
                    level, j = level + 1, j + 2
                elif text.startswith("*/", j):
                    level, j = level - 1, j + 2
                else:
                    j += 1
            out.append(blank(text[i:j]))
            i = j
        elif raw:
            close = '"' + raw.group(1)
            j = text.find(close, raw.end())
            j = n if j < 0 else j
            out.append(raw.group(0) + blank(text[raw.end():j]) + text[j:j + len(close)])
            i = j + len(close)
        elif c == '"' or (not word and text[i:i + 2] in ('b"', 'c"')):
            k = i + (1 if c == '"' else 2)
            j = k
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:k] + blank(text[k:j]) + text[j:j + 1])
            i = j + 1
        elif c == "'" and (m := CHARLIT.match(text, i)):
            out.append("'" + blank(m.group(0)[1:-1]) + "'")
            i = m.end()
        else:
            out.append(c)
            i += 1
    return "".join(out)


def super_chain(segs: list[str]) -> int:
    """How many `super`s lead a path whose first segments are `segs`."""
    k = 0
    for s in segs:
        if s == "super":
            k += 1
        elif s != "self":
            break
    return k


def use_roots(item: str) -> list[tuple[list[str], str]]:
    """Each top-level tree of a `use` item: its leading segments and what ends them.

    Raises ValueError when the item cannot be read as a `use` tree.
    """
    toks = []
    pos = 0
    while pos < len(item):
        m = TOKEN.match(item, pos)
        if not m:
            if item[pos:].strip() == "":
                break
            raise ValueError(item[pos:pos + 20])
        toks.append(m.group(1))
        pos = m.end()
    if not toks or toks[0] != "use":
        raise ValueError(item)
    roots: list[tuple[list[str], str]] = []

    def tree(i: int, top: bool) -> int:
        """Read one tree at `toks[i]`, recording it when `top`; return the next index."""
        if toks[i] == "::":
            i += 1
        if toks[i] == "{":
            return group(i + 1, top)
        segs = []
        while re.fullmatch(r"[A-Za-z_]\w*", toks[i]) and toks[i] != "as":
            segs.append(toks[i])
            i += 1
            if toks[i] != "::":
                break
            i += 1
            if toks[i] == "{":
                if top:
                    roots.append((segs, "{"))
                return group(i + 1, False)
            if toks[i] == "*":
                if top:
                    roots.append((segs, "*"))
                return i + 1
        if not segs:
            raise ValueError(" ".join(toks))
        end = toks[i]
        if end == "as":
            i += 2
        if top:
            roots.append((segs, end))
        return i

    def group(i: int, top: bool) -> int:
        """Read a `{ ... }` group's trees from `toks[i]`; return the index after `}`."""
        while toks[i] != "}":
            i = tree(i, top)
            if toks[i] == ",":
                i += 1
            elif toks[i] != "}":
                raise ValueError(" ".join(toks))
        return i + 1

    i = tree(1, True)
    if toks[i] != ";":
        raise ValueError(" ".join(toks))
    return roots


def use_why(code: str, d: int) -> str | None:
    """Why a `use` item, joined onto one line, is flagged, or None."""
    m = re.search(r"\buse\b.*", code)
    try:
        roots = use_roots(m.group(0))
    except (ValueError, IndexError):
        return "use tree not understood"
    named = set(re.findall(r"[A-Za-z_]\w*", m.group(0))) & set(MACROS)
    if named:
        return f"{min(named)} imported by a use item"
    for segs, end in roots:
        head = segs[0]
        if head in BANNED:
            return f"{head} at the root of a use tree"
        if head == "crate" and len(segs) == 1 and end != "{":
            return "crate alias"
        if head in ("super", "self") and super_chain(segs) > d:
            return f"super chain of {super_chain(segs)} at depth {d}"
    return None


def path_why(code: str, d: int) -> str | None:
    """Why a line of code is flagged by the paths it names, or None."""
    # overlapping, so `use ::std` is read at `std` as well as at `use`
    for m in re.finditer(r"(?=(?<![\w:])(::)?([a-z_][a-z0-9_]*)\s*::)", code):
        head = m.group(2)
        rest = re.sub(r"\s+", "", code[m.start():]).lstrip(":")
        if head in BANNED:
            return f"{head} path"
        if head == "crate" and not INSIDE.match(rest):
            return "crate path outside the module"
        if head in ("super", "self"):
            if head == "super" and re.search(r"[{,]\s*$", code[:m.start()]):
                return "super inside a use group"
            k = super_chain(re.match(r"(?:(?:super|self)::)*", rest).group(0).split("::"))
            if k > d:
                return f"super chain of {k} at depth {d}"
    return None


def attributes(text: str) -> dict[int, int]:
    """Each attribute in blanked text, `#[...]` or `#![...]`, as start offset to end offset."""
    spans = {}
    for m in re.finditer(r"#\s*!?\s*\[", text):
        j, level = m.end(), 1
        while j < len(text) and level:
            level += {"[": 1, "]": -1}.get(text[j], 0)
            j += 1
        spans[m.start()] = j
    return spans


def mod_attrs(text: str, pos: int, by_end: dict[int, int]) -> list[str]:
    """The outer attributes of the item whose `mod` keyword is at `pos`, past its visibility."""
    own = []
    head = text[:pos].rstrip()
    while True:
        vis = VIS.search(head)
        if vis and (vis.start() == 0 or not (head[vis.start() - 1].isalnum() or head[vis.start() - 1] == "_")):
            head = head[:vis.start()].rstrip()
            continue
        start = by_end.get(len(head))
        if start is None:
            return own
        own.append(" ".join(text[start:len(head)].split()))
        head = text[:start].rstrip()


def hits(rel: str, raw: str) -> list[str]:
    """Every flagged line of one file."""
    d = depth(rel)
    text = strip(raw)
    out = []

    def flag(pos: int, why: str) -> None:
        """Record a hit at offset `pos`."""
        line = text.count("\n", 0, pos) + 1
        out.append((line, why, raw.splitlines()[line - 1].strip()))

    attrs = attributes(text)
    for start, end in attrs.items():
        body = text[start:end]
        if re.match(r"#\s*!?\s*\[\s*path\s*=", body):
            val = re.match(r'#\s*\[\s*path\s*=\s*"([^"]*)"\s*\]', raw[start:end])
            if not val or not TESTPATH.fullmatch(val.group(1)):
                flag(start, "path attribute outside tests/")
        elif re.match(r"#\s*!?\s*\[\s*cfg_attr\b", body) and re.search(r"(?<![\w])path\s*=(?!=)", body):
            flag(start, "path inside cfg_attr")
    for m in MODITEM.finditer(text):
        own = mod_attrs(text, m.start(), {e: s for s, e in attrs.items()})
        path = any(re.match(r"#\s*\[\s*path\b", a) for a in own)
        if (m.group(1) == "tests" or path) and not any(CFGTEST.fullmatch(a) for a in own):
            flag(m.start(), "test module without #[cfg(test)]")
    # a use item on one line, padded with newlines to keep numbering
    joined = re.sub(r"\buse\b[^;]*;", lambda u: " ".join(u.group(0).split()) + "\n" * u.group(0).count("\n"), text)
    for n, code in enumerate(joined.splitlines(), 1):
        why = None
        if re.search(r"\buse\b[^;]*;", code):
            why = use_why(code, d)
        why = why or path_why(code, d)
        if not why and re.search(r"\bextern\s+crate\b", code):
            why = "extern crate"
        if not why:
            mm = re.search(r"(?<![\w])(" + "|".join(MACROS) + r")\s*!", code)
            if mm:
                why = mm.group(1) + "!"
        if why:
            out.append((n, why, code.strip()))
    return [f"{rel}:{n}: {why}: {code}" for n, why, code in sorted(out)]


def main() -> int:
    """Run the check and return its exit status."""
    args = sys.argv[1:]
    if args[:1] == ["--root"] and len(args) == 2:
        files = from_root(pathlib.Path(args[1]))
        where = args[1]
    elif not args:
        files = committed()
        where = MODULE + " at HEAD"
    else:
        fail_look("usage: check-nostr-machine.py [--root DIR]")
    scanned = {r: t for r, t in files.items() if not is_test_path(r) and r not in EXEMPT}
    if not scanned:
        fail_look(f"no Rust file found in {where}")
    found = [h for r, t in sorted(scanned.items()) for h in hits(r, t)]
    for h in found:
        print(h)
    print(f"check-nostr-machine: {len(scanned)} files in {where}, {len(found)} flagged")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
