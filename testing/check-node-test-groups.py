#!/usr/bin/env python3
"""Fail when a node test that needs to run alone is outside its nextest group.

nextest runs each test in its own process, so an in-process lock cannot keep
two tests apart. `.config/nextest.toml` does it instead with two one-at-a-time
test groups, and this check keeps their membership honest:

  node-synthetic  every test module under src/node/tests/ that opens a real
                  socket, so a loaded host cannot drop a one-shot handshake
                  while another such test floods the loopback interface, and
                  so the control socket's shared default path (TCP 21210 on
                  Windows) is bound by one test at a time;
  node-large      every test that takes `lock_large_network_test()`, so the
                  100-node tests stay mutually exclusive across processes as
                  they are across threads.

Without it the groups are an allow-list that goes stale the day the next
socket test lands, and nothing says so until a loaded runner drops a packet.

A module needs node-synthetic when any function in it is flagged. A function
is flagged when its text (signature and body, comments and string contents
removed) uses a primitive, or calls a flagged function, computed to a fixpoint:

  primitives  a non-loopback transport (UdpTransport, TcpTransport,
              EthernetTransport, Ble*Transport); an OS socket type (UdpSocket,
              TcpListener, TcpStream, TcpSocket, socket2, libc::socket); a
              per-peer connected UDP socket (`open_connected_fd(`, which opens
              one, and ConnectedPeerSocket, which only wraps such a socket);
              and `.start()` and `run_rx_loop(` with its variants
              (`run_rx_loop_with_shutdown(` is where the bind happens), which
              bind through the node's Config, the control socket included.
  calls       `f(`, `path::f(` and `Type::f(` resolved through the module's own
              functions, its `use` items (aliases, groups and globs) and
              `super`/`self`/`crate::node::tests`/`crate::testutil` paths;
              `.f(` matches every scanned method named f whose impl type is
              named somewhere in the calling file (so a Vec's `.drain(` is not
              a test helper's); a bare `f` passed as an argument counts as a
              call.

The scanned files are the modules src/node/tests/mod.rs declares (names come
from the `mod` items, `#[path]` honoured, never from file names) and
src/testutil.rs, the crate's shared test helpers. A test's name is
node::tests::<module>[::<inline mod>...]::<fn>. node-large holds the tests
that call `lock_large_network_test(` directly or through a flagged helper.

Each profile's test-group overrides are checked in order, as nextest applies
them (the first matching override sets the group). The filters must have one
of two shapes, anchored and package-scoped, and anything else is a filter this
check cannot evaluate, so it exits 2 rather than guess:

  package(<pkg>) & test(/^node::tests::(m1|m2|...)::/)          node-synthetic
  package(<pkg>) & test(/^node::tests::(m::t1|m::t2|...)$/)     node-large

A module or test a filter names that this tree lacks is fine: one file serves
maint, master and next, and a name matching nothing is harmless. A module
named but present and not flagged is reported as a note, since another trunk
may flag it.

A function whose primitive use opens no socket (a transport built and never
started, say) is exempted in testing/node-test-groups/exemptions.toml, one
entry per function and primitive, each with its reason. An exemption with no
reason exits 2; one naming a function this tree lacks is a note, for the same
reason as above.

The pinned nextest version is checked too: `nextest-version.required` in the
config must equal the version of every `tool: nextest@<ver>` install step in
.github/workflows, and an unpinned one is a finding.

Exit 0: every flagged module and every lock holder is in its group, in both
profiles. Exit 1: a finding. Exit 2: the check could not run meaningfully:
no test modules, no flagged module, no lock holder, a filter of another shape,
a missing group, an unreadable file, an exemption without a reason, or no
nextest install step, so a moved directory or a reformatted filter cannot pass
vacuously.

`--survey` prints the membership with each flagged function's first reason,
for recording; `--root DIR` checks another tree (the fixtures use it).
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

GROUP_SOCKET = "node-synthetic"
GROUP_LARGE = "node-large"
PROFILES = ("default", "ci")
LOCK_FN = "lock_large_network_test"
TESTS_PREFIX = "node::tests::"

PRIMITIVES = [
    ("UdpTransport", re.compile(r"\bUdpTransport\b")),
    ("TcpTransport", re.compile(r"\bTcpTransport\b")),
    ("EthernetTransport", re.compile(r"\bEthernetTransport\b")),
    ("BleTransport", re.compile(r"\bBle\w*Transport\b")),
    ("UdpSocket", re.compile(r"\bUdpSocket\b")),
    ("TcpListener", re.compile(r"\bTcpListener\b")),
    ("TcpStream", re.compile(r"\bTcpStream\b")),
    ("TcpSocket", re.compile(r"\bTcpSocket\b")),
    ("socket2", re.compile(r"\bsocket2\b")),
    ("libc::socket", re.compile(r"\blibc\s*::\s*socket\s*\(")),
    ("open_connected_fd", re.compile(r"\bopen_connected_fd\s*\(")),
    ("ConnectedPeerSocket", re.compile(r"\bConnectedPeerSocket\b")),
    ("start()", re.compile(r"\.\s*start\s*\(\s*\)")),
    ("run_rx_loop", re.compile(r"\brun_rx_loop\w*\s*\(")),
]

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
SYNTH_RE = re.compile(
    r"^package\((?P<pkg>[A-Za-z0-9_-]+)\) & "
    r"test\(/\^node::tests::\((?P<alts>" + IDENT + r"(?:\|" + IDENT + r")*)\)::/\)$")
LARGE_RE = re.compile(
    r"^package\((?P<pkg>[A-Za-z0-9_-]+)\) & "
    r"test\(/\^node::tests::\((?P<alts>" + IDENT + r"(?:::" + IDENT + r")+"
    r"(?:\|" + IDENT + r"(?:::" + IDENT + r")+)*)\)\$/\)$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


class CannotCheck(Exception):
    """The input cannot be checked meaningfully; the check exits 2."""


# ── Lexing ──────────────────────────────────────────────────────────────────

def strip_rust(text: str) -> str:
    """Blank comments and string and char literal contents, keeping offsets.

    Every removed character becomes a space, except newlines, so a position in
    the result is the same position (and line) in the source.
    """
    out = list(text)
    n = len(text)
    i = 0

    def blank(start: int, end: int) -> None:
        """Blank text[start:end], keeping newlines."""
        for k in range(start, min(end, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            blank(i, end)
            i = end
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c in "rb" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            m = re.match(r'(?:br|r)(#*)"', text[i:])
            if m:
                close = '"' + m.group(1)
                end = text.find(close, i + m.end())
                end = n if end < 0 else end + len(close)
                blank(i, end)
                i = end
            elif text.startswith('b"', i):
                i = skip_string(text, i + 1, blank)
            elif text.startswith("b'", i):
                i = skip_char(text, i + 1, blank)
            else:
                i += 1
        elif c == '"':
            i = skip_string(text, i, blank)
        elif c == "'":
            i = skip_char(text, i, blank)
        else:
            i += 1
    return "".join(out)


def skip_string(text: str, start: int, blank: Callable[[int, int], None]) -> int:
    """Blank the ordinary string literal opening at `start`; return its end."""
    j = start + 1
    while j < len(text) and text[j] != '"':
        j += 2 if text[j] == "\\" else 1
    blank(start, j + 1)
    return j + 1


def skip_char(text: str, start: int, blank: Callable[[int, int], None]) -> int:
    """Blank a char literal at `start`, or step over a lifetime."""
    if start + 1 < len(text) and text[start + 1] == "\\":
        end = text.find("'", start + 2)
        end = len(text) if end < 0 else end + 1
        blank(start, end)
        return end
    if start + 2 < len(text) and text[start + 2] == "'":
        blank(start, start + 3)
        return start + 3
    return start + 1


def match_brace(text: str, open_at: int) -> int:
    """Return the index just past the brace matching the `{` at `open_at`."""
    depth = 0
    for k in range(open_at, len(text)):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return k + 1
    return len(text)


def line_of(text: str, pos: int) -> int:
    """1-based line number of offset `pos`."""
    return text.count("\n", 0, pos) + 1


# ── Model ───────────────────────────────────────────────────────────────────

@dataclass
class Func:
    """A function item in a scanned file."""

    module: str          # top-level test module name, "" for mod.rs, "testutil"
    name: str
    start: int
    end: int
    text: str            # stripped text from `fn` to the end of the body
    line: int
    inline: list[str]    # inline `mod` path within the file
    impl_type: str | None
    is_test: bool
    flagged: str | None = None   # first reason, once flagged
    large: str | None = None     # first reason it holds the large-network lock

    @property
    def key(self) -> str:
        """Module-qualified name used in reports and exemptions."""
        owner = [self.impl_type] if self.impl_type else []
        parts = [self.module or "<mod.rs>", *self.inline, *owner, self.name]
        return "::".join(parts)

    @property
    def test_name(self) -> str:
        """The test's name as nextest reports it."""
        parts = [p for p in (self.module, *self.inline, self.name) if p]
        return TESTS_PREFIX + "::".join(parts)


@dataclass
class Use:
    """One leaf of a `use` tree: a path, and an alias or None for a glob."""

    path: list[str]
    alias: str | None    # None means `path::*`
    depth: int           # inline-mod depth where the `use` sits


@dataclass
class Module:
    """A scanned file and what it defines and imports."""

    name: str
    path: Path
    text: str = ""
    funcs: list[Func] = field(default_factory=list)
    uses: list[Use] = field(default_factory=list)


def spans(text: str, pattern: re.Pattern) -> list[tuple[int, int, re.Match]]:
    """Each match of a `... {` header with the span of its braced block."""
    found = []
    for m in pattern.finditer(text):
        brace = m.end() - 1
        found.append((brace, match_brace(text, brace), m))
    return found


MOD_BLOCK_RE = re.compile(r"\bmod\s+(" + IDENT + r")\s*\{")
IMPL_RE = re.compile(r"(?m)^[ \t]*(?:unsafe\s+)?impl\b[^;{]*\{")
FN_RE = re.compile(r"\bfn\s+(" + IDENT + r")")
TEST_ATTR_RE = re.compile(r"#\[\s*(?:tokio\s*::\s*)?test\b")
USE_RE = re.compile(r"\buse\s+([^;]+);")


def impl_type(header: str) -> str | None:
    """The implementing type's last path segment from an `impl ... {` header."""
    body = header.strip()
    body = body[body.index("impl") + len("impl"):].rstrip("{").strip()
    if body.startswith("<"):
        depth = 0
        for k, ch in enumerate(body):
            depth += {"<": 1, ">": -1}.get(ch, 0)
            if depth == 0:
                body = body[k + 1:]
                break
    if re.search(r"\bfor\b", body):
        body = re.split(r"\bfor\b", body, maxsplit=1)[1]
    body = re.split(r"\bwhere\b", body)[0]
    names = re.findall(IDENT, body.split("<")[0])
    return names[-1] if names else None


def expand_use(tree: str, prefix: list[str]) -> list[tuple[list[str], str | None]]:
    """Expand a `use` tree into (path, alias) leaves; alias None means a glob."""
    tree = tree.strip()
    if not tree:
        return []
    m = re.match(r"^((?:" + IDENT + r"\s*::\s*)*)\{(.*)\}$", tree, re.S)
    if m:
        head = [s for s in re.split(r"\s*::\s*", m.group(1).strip()) if s]
        leaves: list[tuple[list[str], str | None]] = []
        for part in split_top(m.group(2)):
            leaves.extend(expand_use(part, prefix + head))
        return leaves
    if tree.endswith("*"):
        head = [s for s in re.split(r"\s*::\s*", tree[:-1].strip()) if s]
        return [(prefix + head, None)]
    alias_m = re.match(r"^(.*?)\s+as\s+(" + IDENT + r")$", tree, re.S)
    path_text, alias = (alias_m.group(1), alias_m.group(2)) if alias_m else (tree, None)
    path = prefix + [s for s in re.split(r"\s*::\s*", path_text.strip()) if s]
    if not path:
        return []
    if path[-1] == "self":
        path = path[:-1]
    return [(path, alias or path[-1])] if path else []


def split_top(text: str) -> list[str]:
    """Split a `use` group's contents on top-level commas."""
    parts, depth, cur = [], 0, []
    for ch in text:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return [p for p in (s.strip() for s in parts) if p]


def scan(mod: Module) -> None:
    """Fill a module's functions and `use` leaves from its stripped text."""
    text = mod.text
    inline = [(s, e, m.group(1)) for s, e, m in spans(text, MOD_BLOCK_RE)]
    impls = [(s, e, impl_type(m.group(0))) for s, e, m in spans(text, IMPL_RE)]
    tests = [m.start() for m in TEST_ATTR_RE.finditer(text)]

    def inline_path(pos: int) -> list[str]:
        """The inline `mod` blocks enclosing `pos`, outermost first."""
        return [name for s, e, name in sorted(inline) if s < pos < e]

    fn_starts = [m for m in FN_RE.finditer(text)]
    test_fns = set()
    for attr in tests:
        nxt = next((m.start() for m in fn_starts if m.start() > attr), None)
        if nxt is not None:
            test_fns.add(nxt)

    for m in fn_starts:
        depth, k, body = 0, m.end(), None
        while k < len(text):
            ch = text[k]
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
            elif depth == 0 and ch == ";":
                break
            elif depth == 0 and ch == "{":
                body = k
                break
            k += 1
        if body is None:
            continue
        end = match_brace(text, body)
        owner = [t for s, e, t in impls if s < m.start() < e]
        mod.funcs.append(Func(
            module=mod.name, name=m.group(1), start=m.start(), end=end,
            text=text[m.start():end], line=line_of(text, m.start()),
            inline=inline_path(m.start()), impl_type=owner[-1] if owner else None,
            is_test=m.start() in test_fns))

    for m in USE_RE.finditer(text):
        depth = len(inline_path(m.start()))
        for path, alias in expand_use(m.group(1), []):
            mod.uses.append(Use(path=path, alias=alias, depth=depth))


# ── Resolution ──────────────────────────────────────────────────────────────

class Tree:
    """The scanned modules and the call resolution between them."""

    def __init__(self, modules: dict[str, Module]) -> None:
        """Index the scanned methods by name and by implementing type."""
        self.modules = modules
        self.methods: dict[str, list[Func]] = {}
        self.by_type: dict[tuple[str, str], list[Func]] = {}
        for mod in modules.values():
            for f in mod.funcs:
                if f.impl_type:
                    self.methods.setdefault(f.name, []).append(f)
                    self.by_type.setdefault((f.impl_type, f.name), []).append(f)

    def module_for(self, base: str, depth: int, path: list[str]) -> str | None:
        """The scanned module a path names from inside `base`, or None.

        `base` is a top-level test module, "" for mod.rs (node::tests itself)
        or "testutil"; `depth` is how many inline `mod` blocks deep the path
        is written, so `super` first climbs out of those.
        """
        if not path:
            return base
        head, rest = path[0], path[1:]
        if head == "crate":
            if rest[:1] == ["testutil"] and "testutil" in self.modules:
                return self.module_for("testutil", 0, rest[1:])
            if rest[:2] == ["node", "tests"]:
                return self.module_for("", 0, rest[2:])
            return None
        if head == "self":
            return self.module_for(base, depth, rest)
        if head == "super":
            if depth > 0:
                return self.module_for(base, depth - 1, rest)
            if base in ("", "testutil"):
                return None
            return self.module_for("", 0, rest)
        if base == "" and depth == 0 and head in self.modules and head != "testutil":
            return self.module_for(head, 0, rest)
        return None

    def lookup(self, mod_name: str, name: str, seen: set[tuple[str, str]]) -> list[Func]:
        """Free functions `name` resolves to inside module `mod_name`."""
        if (mod_name, name) in seen or mod_name not in self.modules:
            return []
        seen.add((mod_name, name))
        mod = self.modules[mod_name]
        own = [f for f in mod.funcs if f.name == name and not f.impl_type]
        if own:
            return own
        found: list[Func] = []
        for use in mod.uses:
            if use.alias == name:
                target = self.module_for(mod_name, use.depth, use.path[:-1])
                if target is not None:
                    found += self.lookup(target, use.path[-1], seen)
        if found:
            return found
        for use in mod.uses:
            if use.alias is None:
                target = self.module_for(mod_name, use.depth, use.path)
                if target is not None:
                    found += self.lookup(target, name, seen)
        return found

    def callees(self, f: Func) -> list[Func]:
        """Every scanned function `f` may call."""
        out: list[Func] = []
        depth = len(f.inline)
        visible = self.modules[f.module].text
        after_name = f.text.index(f.name) + len(f.name)
        for m in CALL_RE.finditer(f.text, after_name):
            dot, qual, name = m.group(1), m.group(2), m.group(3)
            if dot:
                out += [c for c in self.methods.get(name, [])
                        if re.search(r"\b" + c.impl_type + r"\b", visible)]
                continue
            path = [s for s in re.split(r"\s*::\s*", qual.strip()) if s]
            if not path:
                out += self.lookup(f.module, name, set())
                continue
            target = self.module_for(f.module, depth, path)
            if target is not None:
                out += self.lookup(target, name, set())
            elif path[-1] == "Self" and f.impl_type:
                out += self.by_type.get((f.impl_type, name), [])
            else:
                out += self.by_type.get((path[-1], name), [])
        for m in FN_ARG_RE.finditer(f.text, after_name):
            out += self.lookup(f.module, m.group(1), set())
        return [c for c in out if c is not f]


CALL_RE = re.compile(r"(\.\s*)?((?:" + IDENT + r"\s*::\s*)*)(" + IDENT +
                     r")\s*(?:::\s*<[^()]*?>\s*)?\(")
FN_ARG_RE = re.compile(r"[(,]\s*(" + IDENT + r")\s*(?=[),])")


# ── Loading ─────────────────────────────────────────────────────────────────

MOD_DECL_RE = re.compile(
    r"((?:#\[[^\]]*\]\s*)*)(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(" + IDENT + r")\s*;")
PATH_ATTR_RE = re.compile(r'#\[\s*path\s*=\s*"([^"]*)"\s*\]')


def load_tree(root: Path) -> Tree:
    """Read src/node/tests/mod.rs, the modules it declares, and src/testutil.rs."""
    tests_dir = root / "src" / "node" / "tests"
    mod_rs = tests_dir / "mod.rs"
    try:
        raw = mod_rs.read_text()
    except OSError as e:
        raise CannotCheck(f"cannot read {mod_rs}: {e}") from e
    stripped = strip_rust(raw)
    modules: dict[str, Module] = {"": Module("", mod_rs, stripped)}
    for m in MOD_DECL_RE.finditer(stripped):
        attrs_raw = raw[m.start(1):m.end(1)]
        name = m.group(2)
        path_m = PATH_ATTR_RE.search(attrs_raw)
        if path_m:
            candidates = [tests_dir / path_m.group(1)]
        else:
            candidates = [tests_dir / f"{name}.rs", tests_dir / name / "mod.rs"]
        found = next((p for p in candidates if p.is_file()), None)
        if found is None:
            raise CannotCheck(f"mod.rs declares `mod {name};` but none of "
                              f"{', '.join(str(p) for p in candidates)} exists")
        modules[name] = Module(name, found, strip_rust(found.read_text()))
    if len(modules) == 1:
        raise CannotCheck(f"{mod_rs} declares no test modules")
    testutil = root / "src" / "testutil.rs"
    if testutil.is_file():
        modules["testutil"] = Module("testutil", testutil, strip_rust(testutil.read_text()))
    for mod in modules.values():
        scan(mod)
    return Tree(modules)


@dataclass
class Exemption:
    """A primitive use in one function that opens no socket."""

    key: str
    primitive: str
    reason: str


def load_exemptions(path: Path) -> list[Exemption]:
    """Read the exemption file; a missing file means no exemptions."""
    if not path.is_file():
        return []
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise CannotCheck(f"cannot read exemptions {path}: {e}") from e
    out = []
    known = {name for name, _ in PRIMITIVES}
    for entry in data.get("exempt", []):
        key, prim, reason = entry.get("fn"), entry.get("primitive"), entry.get("reason")
        if not key or prim not in known or not (reason or "").strip():
            raise CannotCheck(f"{path}: exemption {entry!r} needs fn, a primitive "
                              f"from {sorted(known)}, and a non-empty reason")
        out.append(Exemption(key, prim, reason.strip()))
    return out


# ── Flagging ────────────────────────────────────────────────────────────────

def flag(tree: Tree, exemptions: list[Exemption]) -> None:
    """Flag socket users and lock holders, each to a fixpoint."""
    exempt = {(e.key, e.primitive) for e in exemptions}
    funcs = [f for mod in tree.modules.values() for f in mod.funcs]
    calls = {id(f): tree.callees(f) for f in funcs}
    for f in funcs:
        for prim, pattern in PRIMITIVES:
            if (f.key, prim) in exempt:
                continue
            hit = pattern.search(f.text)
            if hit:
                f.flagged = f"uses {prim} (line {f.line + f.text.count(chr(10), 0, hit.start())})"
                break
        if re.search(r"\b" + LOCK_FN + r"\s*\(", f.text) and f.name != LOCK_FN:
            f.large = f"calls {LOCK_FN}()"
    changed = True
    while changed:
        changed = False
        for f in funcs:
            for c in calls[id(f)]:
                if f.flagged is None and c.flagged is not None:
                    f.flagged = f"calls {c.key}"
                    changed = True
                if f.large is None and c.large is not None and c.name != LOCK_FN:
                    f.large = f"calls {c.key}"
                    changed = True


# ── Config ──────────────────────────────────────────────────────────────────

@dataclass
class Override:
    """A test-group override, parsed into a matcher."""

    group: str
    pkg: str
    names: list[str]
    regex: re.Pattern

    def matches(self, pkg: str, test: str) -> bool:
        """Whether nextest would apply this override to the test."""
        return pkg == self.pkg and self.regex.search(test) is not None


def parse_filter(group: str, flt: str, where: str) -> Override:
    """Parse one of the two accepted filter shapes, or raise CannotCheck."""
    shape = {GROUP_SOCKET: SYNTH_RE, GROUP_LARGE: LARGE_RE}.get(group)
    m = shape.fullmatch(flt) if shape else None
    if not m:
        raise CannotCheck(
            f"{where}: filter {flt!r} for test-group {group!r} is not a shape this "
            "check can evaluate; expected "
            "package(<pkg>) & test(/^node::tests::(m1|m2)::/) for node-synthetic, "
            "package(<pkg>) & test(/^node::tests::(m::t1|m::t2)$/) for node-large")
    regex_src = re.search(r"test\(/(.*)/\)$", flt).group(1)
    return Override(group, m.group("pkg"), m.group("alts").split("|"), re.compile(regex_src))


def load_config(path: Path) -> tuple[dict[str, list[Override]], str, list[str]]:
    """Read both profiles' test-group overrides, in order, and the pinned version."""
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise CannotCheck(f"cannot read {path}: {e}") from e
    problems = []
    groups = data.get("test-groups", {})
    for g in (GROUP_SOCKET, GROUP_LARGE):
        if g not in groups:
            raise CannotCheck(f"{path}: [test-groups] has no {g}")
        if groups[g].get("max-threads") != 1:
            problems.append(f"{path}: test group {g} must have max-threads = 1, "
                            f"has {groups[g].get('max-threads')!r}")
    version = (data.get("nextest-version") or {})
    required = version.get("required") if isinstance(version, dict) else version
    if not isinstance(required, str) or not SEMVER_RE.match(required):
        raise CannotCheck(f"{path}: nextest-version.required must be an exact "
                          f"version, found {required!r}")
    profiles = {}
    for p in PROFILES:
        overrides = []
        for i, o in enumerate(data.get("profile", {}).get(p, {}).get("overrides", [])):
            if "test-group" not in o:
                continue
            where = f"{path} [profile.{p}] override {i + 1}"
            if "filter" not in o or "platform" in o:
                raise CannotCheck(f"{where}: a test-group override must have a filter "
                                  "and no platform for this check to evaluate it")
            overrides.append(parse_filter(o["test-group"], o["filter"], where))
        if not any(o.group == GROUP_SOCKET for o in overrides):
            raise CannotCheck(f"{path}: [profile.{p}] has no {GROUP_SOCKET} override")
        if not any(o.group == GROUP_LARGE for o in overrides):
            raise CannotCheck(f"{path}: [profile.{p}] has no {GROUP_LARGE} override")
        profiles[p] = overrides
    return profiles, required, problems


def check_pins(root: Path, required: str) -> list[str]:
    """Every nextest install step in the workflows pins the required version."""
    wf_dir = root / ".github" / "workflows"
    steps, problems = 0, []
    for wf in sorted(wf_dir.glob("*.y*ml")):
        for n, line in enumerate(wf.read_text().splitlines(), 1):
            m = re.match(r"^\s*tool:\s*(.+?)\s*$", line)
            if not m:
                continue
            for tool in (t.strip() for t in m.group(1).split(",")):
                if re.match(r"^(cargo-)?nextest(@|$)", tool):
                    steps += 1
                    if tool.split("@", 1)[-1] != required or "@" not in tool:
                        problems.append(
                            f"{wf.relative_to(root)}:{n}: installs {tool!r}; pin it to "
                            f"nextest@{required}, the version .config/nextest.toml requires")
    if steps == 0:
        raise CannotCheck(f"no `tool: nextest` install step in {wf_dir}; "
                          "cannot check the pinned version")
    return problems


def first_group(overrides: list[Override], pkg: str, test: str) -> str | None:
    """The group nextest would assign: the first matching override's."""
    return next((o.group for o in overrides if o.matches(pkg, test)), None)


# ── Main ────────────────────────────────────────────────────────────────────

def package_name(root: Path) -> str:
    """The root package's name from Cargo.toml."""
    try:
        return tomllib.loads((root / "Cargo.toml").read_text())["package"]["name"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as e:
        raise CannotCheck(f"cannot read the package name from {root / 'Cargo.toml'}: {e}") from e


def survey(tree: Tree, flagged_mods: dict[str, Func], holders: list[Func]) -> None:
    """Print the membership and the reason each module is in it."""
    test_mods = [m for m in tree.modules if m not in ("", "testutil")]
    print(f"test modules declared: {len(test_mods)}")
    print(f"node-synthetic ({len(flagged_mods)}):")
    for name in sorted(flagged_mods):
        f = flagged_mods[name]
        print(f"  {name}: {f.key} {f.flagged}")
    print(f"not flagged ({len(test_mods) - len(flagged_mods)}): "
          + " ".join(sorted(m for m in test_mods if m not in flagged_mods)))
    print(f"node-large ({len(holders)}):")
    for f in holders:
        print(f"  {f.test_name[len(TESTS_PREFIX):]}: {f.large}")
    helpers = [f for mod in tree.modules.values() for f in mod.funcs
               if f.flagged and not f.is_test]
    print(f"flagged helpers ({len(helpers)}):")
    for f in helpers:
        print(f"  {f.key}: {f.flagged}")


def run(root: Path, exemptions_path: Path, show_survey: bool) -> int:
    """Run the check against the tree at `root`; return the exit status."""
    pkg = package_name(root)
    tree = load_tree(root)
    exemptions = load_exemptions(exemptions_path)
    flag(tree, exemptions)
    keys = {f.key for mod in tree.modules.values() for f in mod.funcs}
    notes = [f"note: exemption for {e.key} matches no function in this tree"
             for e in exemptions if e.key not in keys]

    flagged_mods: dict[str, Func] = {}
    for name, mod in tree.modules.items():
        if name in ("", "testutil"):
            continue
        hit = next((f for f in mod.funcs if f.flagged), None)
        if hit:
            flagged_mods[name] = hit
    holders = [f for mod in tree.modules.values() for f in mod.funcs
               if f.is_test and f.large]
    if show_survey:
        survey(tree, flagged_mods, holders)
    if not flagged_mods:
        raise CannotCheck("no test module is flagged as using a socket; the scan "
                          "has stopped seeing the primitives, so it proves nothing")
    if not holders:
        raise CannotCheck(f"no test calls {LOCK_FN}(); the lock was renamed or "
                          "moved, so node-large cannot be checked")

    profiles, required, problems = load_config(root / ".config" / "nextest.toml")
    problems += check_pins(root, required)

    root_tests = [f for f in tree.modules[""].funcs if f.is_test and (f.flagged or f.large)]
    for f in root_tests:
        problems.append(f"{f.test_name} is a flagged test in mod.rs itself; a module "
                        "filter cannot place it, so move it into a test module")

    for p, overrides in profiles.items():
        listed = {n for o in overrides if o.group == GROUP_SOCKET for n in o.names}
        for name, mod in tree.modules.items():
            if name in ("", "testutil"):
                continue
            tests = [f for f in mod.funcs if f.is_test]
            if name in flagged_mods:
                why = flagged_mods[name]
                for f in tests:
                    want = GROUP_LARGE if f.large else GROUP_SOCKET
                    got = first_group(overrides, pkg, f.test_name)
                    if got != want:
                        problems.append(
                            f"[profile.{p}] {f.test_name} runs in {got or 'no group'}, "
                            f"needs {want}: module {name} is flagged ({why.key} {why.flagged})")
            elif name in listed and p == "ci":
                notes.append(f"note: {name} is named in {GROUP_SOCKET} but not flagged "
                             "in this tree (another trunk may flag it)")
        for f in holders:
            if f.module in flagged_mods:
                continue  # checked above
            got = first_group(overrides, pkg, f.test_name)
            if got != GROUP_LARGE:
                problems.append(f"[profile.{p}] {f.test_name} runs in {got or 'no group'}, "
                                f"needs {GROUP_LARGE}: it {f.large}")

    for n in notes:
        print(n)
    tests_in = sum(1 for m in flagged_mods for f in tree.modules[m].funcs if f.is_test)
    if problems:
        for msg in problems:
            print(f"FAIL {msg}")
        print(f"check-node-test-groups: {len(problems)} finding(s)")
        return 1
    print(f"check-node-test-groups: {len(flagged_mods)} socket module(s) "
          f"({tests_in} tests) in {GROUP_SOCKET}, {len(holders)} lock holder(s) in "
          f"{GROUP_LARGE}, both profiles; nextest pinned to {required}")
    return 0


def main() -> int:
    """Parse arguments and run the check."""
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=here.parent,
                    help="tree to check (default: this repository)")
    ap.add_argument("--exemptions", type=Path, default=None,
                    help="exemption file (default: <root>/testing/node-test-groups/"
                         "exemptions.toml)")
    ap.add_argument("--survey", action="store_true",
                    help="print the membership and each module's first reason")
    args = ap.parse_args()
    exemptions = args.exemptions or args.root / "testing" / "node-test-groups" / "exemptions.toml"
    try:
        return run(args.root, exemptions, args.survey)
    except CannotCheck as e:
        print(f"CANNOT CHECK {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
