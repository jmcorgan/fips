#!/usr/bin/env python3
"""Carried-test guard for the next line.

Every merge of master into next must carry master's tests, its mutation-lane
switches and its known-defect entries, or say why not. A merge that drops a
test without a record leaves the next line without the guard master has, and
nothing notices: the suite stays green because the test is no longer there.

This check reads three populations at the master commit last merged into
HEAD, and the same three in HEAD's work tree:

  test          every function under `#[test]` or `#[<crate>::test]` in a
                tracked `.rs` file that a build reaches from a crate root
                through `mod` declarations, by bare name;
  switch        every variant of `core/src/faults.rs`'s `faults!` list;
  known-defect  every `known-defect` entry of `testing/ignored-tests.txt`,
                by its test path.

and fails when

  1. a name on the merged master is neither in HEAD nor listed in
     testing/left-off-next.txt;
  2. a listed name is in HEAD (the entry is stale: the item was carried);
  3. a listed name is gone from the merged master (stale the other way);
  4. an entry's file is not where the merged master holds the name, its class
     is unknown, or a `replaced` entry names something HEAD does not hold;
  5. a name the merged master holds in more files than HEAD does has fewer
     entries than copies left off, or an entry names a file where HEAD holds
     the name. Copies are counted, not matched by path, so a test that moved
     file on the way to next still reads as carried;
  6. a tracked `.rs` file in the work tree holds a test and no `mod`
     declaration reaches it, live or compiled out.

An entry of class `open` passes, and is printed by name on every run: it is an
item the merge has not yet classed, held to be settled by the next merge.

The merged commit comes from HEAD's own history, never from a branch name: it
is the second parent of the newest merge on HEAD's first-parent line, which a
merge of master into next guarantees is there. The internal builder runs this
in a detached worktree whose local `master` and `origin/master` lag the
merge, and a development checkout's `origin/master` lags while the trunks are
unpushed, so a branch name would read the wrong commit. The check prints the
commit it used and the merge's subject, so a merge of something other than
master (a `maint` merged straight into next, as happened in 2026-04 and
2026-07) is visible at once; it then reds on every entry, which is loud and
safe.

Only files in the module tree are read. The crate roots are the targets of
every package with a tracked `Cargo.toml`, named or found as Cargo finds
them, and each `mod name;` is resolved as rustc resolves it, `#[path]`
included. A file a merge drops from the tree by losing its `mod` line, left
in place, is not built, so its tests read as absent and rule 6 names the
file. A module under `#[cfg(any())]` is not followed, and the attribute on a
test function drops that test, so a test that is in next's tree but never
built is not counted as carried.

It cannot say an entry's reason is true. A merge's review still checks that.

Known limits, recorded rather than discovered: copies of a name are counted,
not matched by path, so a test dropped in one file while another of its name
is added elsewhere is not seen; a test written by a macro is not seen, the
same limit check-ignored-tests.py has; `#[cfg(any())]` on an inline `mod name { ... }`
is not followed; every other `cfg` is read as built, so the populations are
those of every platform together. An out-of-line module declared inside an
inline `mod name { ... }`, one whose path comes from `#[cfg_attr]`, and one
declared by a macro are not resolved; none is in either tree today, and a
file one of them misses that holds a test reds under rule 6 rather than
passing.

Not mirrored in GitHub CI, on purpose: a pull request's checkout is a merge
whose second parent is the pull request's head, not master, and the default
shallow checkout holds no merge at all. See ci.yml's header.

Before reading anything, the check runs a self-test over planted
repositories, one case for every rule above and for the shapes that must pass;
a wrong verdict there exits 2, so a run that passes has also shown that it can
fail. `--self-test` runs the self-test alone.

Exit codes:
    0 - every item on the merged master is carried or listed truly
    1 - at least one problem; every one is printed
    2 - the check could not look (not in a git work tree, no merge on HEAD's
        first-parent line, git failed, an inventory, a `Cargo.toml` or the
        `faults!` list unreadable, no crate root found, the check itself
        crashed, or a self-test verdict was wrong); never a pass
"""

from __future__ import annotations

import contextlib
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

NAME = "check-carried"
INVENTORY = "testing/left-off-next.txt"
FAULTS = "core/src/faults.rs"
IGNORED = "testing/ignored-tests.txt"
KINDS = ("test", "switch", "known-defect")
CLASSES = ("no-site", "next-rule", "replaced", "open")

TEST_ATTR = re.compile(r"^\s*#\[(?:[A-Za-z_][A-Za-z0-9_]*::)?test\b")
FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")
DEAD_ATTR = re.compile(r"#\[cfg\(any\(\s*\)\)\]")
PATH_ATTR = re.compile(r'#\[path\s*=\s*"([^"]+)"\]')
MOD_DECL = re.compile(
    r"^\s*((?:#\[[^\]]*\]\s*)*)(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;"
)
MANIFEST = "Cargo.toml"
AUTO_ROOT = re.compile(r"(?:src/main|(?:src/bin|tests|examples|benches)/[^/]+(?:/main)?)\.rs")
FAULTS_OPEN = re.compile(r"^faults!\s*\{\s*$")
VARIANT = re.compile(r"^\s*([A-Z][A-Za-z0-9]*),\s*$")
FAULTS_FILLER = re.compile(r"^\s*(?://.*)?$")


class Unscannable(Exception):
    """The check could not look; reported as exit 2, never as a pass."""


def git(root: Path, *args: str, data: bytes | None = None) -> bytes:
    """Run git in `root` and return its standard output."""
    try:
        done = subprocess.run(
            ["git", *args], cwd=root, input=data, capture_output=True, check=True
        )
    except (OSError, subprocess.CalledProcessError) as err:
        detail = getattr(err, "stderr", b"") or b""
        raise Unscannable(
            f"git {' '.join(args)} failed: {err} {detail.decode(errors='replace').strip()}"
        ) from err
    return done.stdout


def merged_commit(root: Path) -> tuple[str, str]:
    """The master commit last merged into HEAD, and that merge's subject."""
    merge = git(root, "rev-list", "--first-parent", "--merges", "-n", "1", "HEAD")
    merge = merge.decode().strip()
    if not merge:
        raise Unscannable("no merge on HEAD's first-parent line, so no merged master to read")
    merged = git(root, "rev-parse", f"{merge}^2").decode().strip()
    subject = git(root, "log", "-1", "--format=%s", merge).decode().strip()
    return merged, subject


def committed_files(root: Path, commit: str) -> dict[str, str]:
    """Every `.rs` file and the two inventories at `commit`, by path."""
    listing = git(root, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0")
    wanted = []
    for entry in listing:
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        name = path.decode()
        if meta.split()[1] == b"blob" and is_scanned(name):
            wanted.append((name, meta.split()[2].decode()))
    if not wanted:
        return {}
    batch = git(root, "cat-file", "--batch", data="".join(f"{oid}\n" for _, oid in wanted).encode())
    out = {}
    pos = 0
    for name, _ in wanted:
        header_end = batch.index(b"\n", pos)
        size = int(batch[pos:header_end].split()[2])
        out[name] = batch[header_end + 1 : header_end + 1 + size].decode("utf-8", "replace")
        pos = header_end + 1 + size + 1
    return out


def work_files(root: Path) -> dict[str, str]:
    """Every tracked `.rs` file and the two inventories in the work tree, by path.

    An untracked file is left out: a stray copy on a development checkout
    must not read as the test being carried.
    """
    listed = git(root, "ls-files", "-z", "--cached")
    out = {}
    for raw in listed.split(b"\0"):
        name = raw.decode()
        if name and is_scanned(name) and (root / name).is_file():
            out[name] = (root / name).read_text(encoding="utf-8", errors="replace")
    return out


def is_scanned(path: str) -> bool:
    """Whether a path is one of the files the populations are read from."""
    return path.endswith(".rs") or path == IGNORED or path.rsplit("/", 1)[-1] == MANIFEST


def crate_roots(files: dict[str, str]) -> list[str]:
    """The root file of every target of every package among `files`.

    A package is a `Cargo.toml` with a `[package]` table, a workspace member
    or not. Its targets are those it names (`[lib]`, `[[bin]]`, `[[test]]`,
    `[[example]]`, `[[bench]]`, the build script) and those Cargo finds
    without being told: `src/lib.rs`, `src/main.rs`, `build.rs`, and a file or
    a `main.rs` directly under `src/bin`, `tests`, `examples` or `benches`.
    A root that is not among `files` is left out.
    """
    roots: list[str] = []
    for path, text in files.items():
        if path.rsplit("/", 1)[-1] != MANIFEST:
            continue
        try:
            manifest = tomllib.loads(text)
        except tomllib.TOMLDecodeError as err:
            raise Unscannable(f"{path}: cannot read it: {err}") from err
        package = manifest.get("package")
        if not isinstance(package, dict):
            continue
        base = path[: -len(MANIFEST)]
        named = [manifest.get("lib", {}).get("path", "src/lib.rs")]
        build = package.get("build")
        named.append(build if isinstance(build, str) else "build.rs")
        for section in ("bin", "test", "example", "bench"):
            named.extend(t["path"] for t in manifest.get(section, []) if "path" in t)
        found = [n[len(base) :] for n in files if n.startswith(base) and AUTO_ROOT.fullmatch(n[len(base) :])]
        for rel in named + found:
            root = os.path.normpath(base + rel)
            if root in files and root not in roots:
                roots.append(root)
    return roots


def declarations(text: str) -> list[tuple[str, str | None, bool]]:
    """Each out-of-line `mod name;` in a file: its name, its `#[path]`, and
    whether `#[cfg(any())]` compiles it out.

    The attributes read are those on the declaration's own line and on the
    attribute lines directly above it, up to a line holding a declaration of
    its own, whose attributes are its own. Comment lines among them are passed
    over and not read.
    """
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        decl = MOD_DECL.match(line)
        if not decl:
            continue
        attrs = [decl.group(1)]
        j = i - 1
        while j >= 0 and lines[j].lstrip().startswith(("#[", "//")) and not MOD_DECL.match(lines[j]):
            if lines[j].lstrip().startswith("#["):
                attrs.append(lines[j])
            j -= 1
        explicit = None
        for attr in attrs:
            found = PATH_ATTR.search(attr)
            if found:
                explicit = found.group(1)
        out.append((decl.group(2), explicit, any(DEAD_ATTR.search(a) for a in attrs)))
    return out


def module_tree(files: dict[str, str]) -> tuple[set[str], set[str]]:
    """The `.rs` files a build reaches from the crate roots, and those only a
    module under `#[cfg(any())]` reaches.

    A declaration resolves as rustc resolves it. `#[path]` is relative to the
    declaring file's directory. Without it, `mod name;` is `name.rs` or
    `name/mod.rs` in the declaring file's directory when that file is a crate
    root, a `mod.rs` or loaded by `#[path]`, and in the directory named for
    the file's stem otherwise. A declaration whose file is not among `files`
    is skipped: either it is compiled out for this platform, or the build
    fails on it.
    """
    roots = crate_roots(files)
    if not roots:
        raise Unscannable(f"no crate root found: no {MANIFEST} with a [package] names a file that is here")

    def walk(start: list[str], follow_dead: bool) -> set[str]:
        seen: set[str] = set()
        stack = [(path, True) for path in start]
        while stack:
            path, owned = stack.pop()
            if path in seen:
                continue
            seen.add(path)
            folder = path.rsplit("/", 1)[0] if "/" in path else ""
            stem = path.rsplit("/", 1)[-1][: -len(".rs")]
            for name, explicit, dead in declarations(files[path]):
                if dead and not follow_dead:
                    continue
                if explicit:
                    target = os.path.normpath(f"{folder}/{explicit}" if folder else explicit)
                    if target in files:
                        stack.append((target, True))
                    continue
                base = folder if owned else f"{folder}/{stem}" if folder else stem
                plain = f"{base}/{name}.rs" if base else f"{name}.rs"
                if plain in files:
                    stack.append((plain, False))
                elif f"{plain[: -len('.rs')]}/mod.rs" in files:
                    stack.append((f"{plain[: -len('.rs')]}/mod.rs", True))
        return seen

    live = walk(roots, follow_dead=False)
    declared = walk(roots, follow_dead=True)
    return live, declared - live


def test_names(files: dict[str, str]) -> dict[str, set[str]]:
    """Every test function's bare name, with the files that hold it.

    Only files a build reaches from the crate roots are read.
    """
    live, _ = module_tree(files)
    out: dict[str, set[str]] = {}
    for path in sorted(live):
        for name in file_tests(files[path]):
            out.setdefault(name, set()).add(path)
    return out


def file_tests(text: str) -> list[str]:
    """The test functions of one file not compiled out on their own."""
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        if not TEST_ATTR.match(line):
            continue
        stack = attribute_stack(lines, i)
        if any(DEAD_ATTR.search(attr) for attr in stack):
            continue
        for later in lines[i + 1 : i + 12]:
            found = FN.match(later)
            if found:
                out.append(found.group(1))
                break
    return out


def unreached(files: dict[str, str]) -> list[str]:
    """Each `.rs` file holding a test that no declaration reaches, live or
    compiled out: a file a merge dropped from the module tree and left in
    place, or one this check fails to resolve. Either way its tests are not
    counted, so it is a problem rather than a pass."""
    live, dead = module_tree(files)
    return sorted(
        path
        for path, text in files.items()
        if path.endswith(".rs") and path not in live and path not in dead and file_tests(text)
    )


def attribute_stack(lines: list[str], at: int) -> list[str]:
    """The attribute lines contiguous with line `at`, above and below it."""
    stack = [lines[at]]
    for step in (-1, 1):
        j = at + step
        while 0 <= j < len(lines) and lines[j].lstrip().startswith(("#[", "///", "//")):
            stack.append(lines[j])
            j += step
    return stack


def switches(files: dict[str, str]) -> dict[str, set[str]]:
    """Every variant of the `faults!` list, with its file."""
    text = files.get(FAULTS)
    if text is None:
        return {}
    out: dict[str, set[str]] = {}
    inside = False
    for line in text.splitlines():
        if FAULTS_OPEN.match(line):
            inside = True
        elif inside and line.startswith("}"):
            return out
        elif inside:
            found = VARIANT.match(line)
            if found:
                out[found.group(1)] = {FAULTS}
            elif not FAULTS_FILLER.match(line):
                raise Unscannable(f"{FAULTS}: cannot read {line.strip()!r} in the `faults!` list")
    raise Unscannable(f"{FAULTS}: no closed `faults! {{ ... }}` list to read")


def known_defects(files: dict[str, str]) -> dict[str, set[str]]:
    """Every known-defect entry's test path, with the file it names."""
    out: dict[str, set[str]] = {}
    for line in files.get(IGNORED, "").splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) == 4 and fields[0] == "known-defect":
            out.setdefault(fields[2], set()).add(fields[3])
    return out


def populations(files: dict[str, str]) -> dict[str, dict[str, set[str]]]:
    """The three populations, by kind."""
    return {
        "test": test_names(files),
        "switch": switches(files),
        "known-defect": known_defects(files),
    }


def inventory(text: str) -> tuple[list[tuple[int, list[str]]], list[str]]:
    """Parse the inventory into numbered rows, and the problems of its shape."""
    rows = []
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        fields = line.split("#", 1)[0].split()
        if not fields:
            continue
        where = f"{INVENTORY}:{number}"
        if len(fields) not in (4, 5):
            problems.append(f"{where}: expected kind, class, name, file and an optional target")
            continue
        kind, klass = fields[0], fields[1]
        if kind not in KINDS:
            problems.append(f"{where}: unknown kind {kind!r}")
            continue
        if klass not in CLASSES:
            problems.append(f"{where}: unknown class {klass!r}")
            continue
        if (klass == "replaced") != (len(fields) == 5):
            problems.append(f"{where}: a target goes with class replaced, and only with it")
            continue
        rows.append((number, fields))
    return rows, problems


def compare(
    master: dict[str, dict[str, set[str]]],
    head: dict[str, dict[str, set[str]]],
    listing: str,
) -> list[str]:
    """Every problem between the merged master, HEAD and the inventory."""
    rows, problems = inventory(listing)
    listed: dict[tuple[str, str, str], int] = {}
    entries: dict[tuple[str, str], int] = {}
    for number, fields in rows:
        kind, klass, name, path = fields[:4]
        where = f"{INVENTORY}:{number}"
        key = (kind, name, path)
        if key in listed:
            problems.append(f"{where}: {kind} {name} is already listed at line {listed[key]}")
            continue
        listed[key] = number
        entries[(kind, name)] = entries.get((kind, name), 0) + 1
        held_here = head[kind].get(name, set())
        if name in master[kind] and len(master[kind][name]) > len(held_here) and path in held_here:
            problems.append(f"{where}: {kind} {name} is in {path} on HEAD; that copy is carried")
        if name not in master[kind]:
            problems.append(f"{where}: {kind} {name} is gone from the merged master; remove its entry")
        elif path not in master[kind][name]:
            held = ", ".join(sorted(master[kind][name]))
            problems.append(f"{where}: {kind} {name} is in {held} on the merged master, not {path}")
        if klass == "replaced":
            target = fields[4]
            pool = head["test"] if kind != "switch" else head["switch"]
            if target.split("::")[-1] not in pool:
                problems.append(f"{where}: {kind} {name} is replaced by {target}, which HEAD does not hold")
    for kind, name in sorted(entries):
        if name not in master[kind]:
            continue
        left = len(master[kind][name]) - len(head[kind].get(name, set()))
        if entries[(kind, name)] > max(left, 0):
            if left <= 0:
                problems.append(f"{kind} {name} is on HEAD now; remove its entry")
            else:
                problems.append(
                    f"{kind} {name} has {entries[(kind, name)]} entries, but only {left} "
                    f"of its copies on the merged master are left off"
                )
    for kind in KINDS:
        for name in sorted(master[kind]):
            held_here = head[kind].get(name, set())
            left = len(master[kind][name]) - len(held_here) - entries.get((kind, name), 0)
            if left <= 0:
                continue
            held = ", ".join(sorted(master[kind][name]))
            if not held_here:
                problems.append(
                    f"{kind} {name} ({held}) is on the merged master, not on HEAD, "
                    f"and not in {INVENTORY}"
                )
            else:
                here = ", ".join(sorted(held_here))
                problems.append(
                    f"{kind} {name} is in {held} on the merged master and only in {here} on HEAD; "
                    f"{left} copy or copies are neither carried nor in {INVENTORY}"
                )
    return problems


def open_entries(root: Path) -> list[str]:
    """The kind and name of every entry of class `open`."""
    rows, _ = inventory((root / INVENTORY).read_text(encoding="utf-8"))
    return [f"{fields[0]} {fields[2]}" for _, fields in rows if fields[1] == "open"]


def verdict(root: Path) -> tuple[str, str, list[str], dict[str, int]]:
    """The merged commit, its merge's subject, the problems, and counts."""
    merged, subject = merged_commit(root)
    master = populations(committed_files(root, merged))
    tree = work_files(root)
    head = populations(tree)
    if not head["test"]:
        raise Unscannable("no test functions found in the work tree")
    try:
        listing = (root / INVENTORY).read_text(encoding="utf-8")
    except OSError as err:
        raise Unscannable(f"cannot read {INVENTORY}: {err}") from err
    counts = {kind: len(master[kind]) for kind in KINDS}
    orphans = [
        f"{path} holds tests that no mod declaration from a crate root reaches, "
        f"so none of them is built or counted"
        for path in unreached(tree)
    ]
    return merged, subject, compare(master, head, listing) + orphans, counts


# ── self-test ───────────────────────────────────────────────────────────────


def planted_test(name: str) -> str:
    """A Rust source holding one test function called `name`."""
    return f"#[test]\nfn {name}() {{\n    assert!(true);\n}}\n"


def planted_faults(names: list[str]) -> str:
    """A faults.rs whose `faults!` list holds `names`."""
    body = "".join(f"    /// Doc.\n    {n},\n" for n in names)
    return f"macro_rules! faults {{ () => {{}} }}\n\nfaults! {{\n{body}}}\n"


PLANTED_MANIFEST = '[package]\nname = "planted"\nversion = "0.0.0"\n'


def planted_lib(files: list[str], skip: tuple[str, ...] = (), extra: str = "") -> str:
    """A src/lib.rs declaring each of `files` directly under src/ but those
    in `skip`, then `extra`."""
    stems = sorted(
        p[len("src/") : -len(".rs")]
        for p in files
        if p.startswith("src/") and p.count("/") == 1 and p.endswith(".rs") and p != "src/lib.rs" and p not in skip
    )
    return "".join(f"mod {stem};\n" for stem in stems) + extra


def planted_ignored(paths: list[str]) -> str:
    """An ignored-tests inventory with a known-defect entry per test path."""
    return "".join(f"known-defect  fips-mesh  {p}  src/kd.rs\n" for p in paths)


class Planted:
    """A throwaway repository with master merged into next."""

    def __init__(self, base: Path, merge: bool = True) -> None:
        """Build master and next, and merge master into next unless told not to."""
        self.root = base
        base.mkdir(parents=True)
        self.run("init", "-q", "-b", "next")
        self.write(
            {
                MANIFEST: PLANTED_MANIFEST,
                "src/kept.rs": planted_test("kept_on_both"),
                "src/twin_a.rs": planted_test("twin_on_master"),
                FAULTS: planted_faults(["KeptSwitch"]),
                IGNORED: planted_ignored(["kd::kept_defect"]),
                INVENTORY: "",
            }
        )
        self.commit("root")
        self.root_commit = self.rev("HEAD")
        self.run("switch", "-q", "-c", "master")
        self.write(
            {
                "src/dropped.rs": planted_test("dropped_on_next"),
                "src/twin_b.rs": planted_test("twin_on_master"),
                "src/explore.rs": planted_test("explored_on_master"),
                "src/kd.rs": planted_test("kept_defect") + planted_test("master_defect"),
                FAULTS: planted_faults(["KeptSwitch", "MasterSwitch"]),
                IGNORED: planted_ignored(["kd::kept_defect", "kd::master_defect"]),
            }
        )
        self.commit("master work")
        self.master_commit = self.rev("HEAD")
        self.run("switch", "-q", "next")
        if merge:
            self.run("merge", "-q", "--no-ff", "-s", "ours", "-m", "Merge master into next", "master")

    def run(self, *args: str) -> bytes:
        """Run git in the planted repository, isolated from host config."""
        return git(self.root, "-c", "user.name=planted", "-c", "user.email=planted@example", *args)

    def rev(self, ref: str) -> str:
        """The commit `ref` names."""
        return self.run("rev-parse", ref).decode().strip()

    def write(self, files: dict[str, str]) -> None:
        """Write `files` into the work tree, removing those given as None."""
        for path, text in files.items():
            target = self.root / path
            if text is None:
                target.unlink(missing_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")

    def declare(self, skip: tuple[str, ...] = (), extra: str = "") -> None:
        """Write src/lib.rs to declare each file directly under src/ but
        those in `skip`, then `extra`."""
        present = [p.relative_to(self.root).as_posix() for p in (self.root / "src").glob("*.rs")]
        self.write({"src/lib.rs": planted_lib(present, skip, extra)})

    def commit(self, message: str) -> None:
        """Declare the modules and commit everything in the work tree."""
        self.declare()
        self.run("add", "-A")
        self.run("commit", "-q", "-m", message)


HEALTHY_LISTING = (
    "test          no-site    dropped_on_next      src/dropped.rs\n"
    "test          next-rule  explored_on_master   src/explore.rs\n"
    "test          no-site    master_defect        src/kd.rs\n"
    "switch        no-site    MasterSwitch         core/src/faults.rs\n"
    "known-defect  next-rule  kd::master_defect    src/kd.rs\n"
    "test          no-site    twin_on_master       src/twin_b.rs\n"
)
TWIN_ENTRY = "test          no-site    twin_on_master       src/twin_b.rs\n"
OPEN_LISTING = HEALTHY_LISTING.replace("no-site    dropped_on_next", "open       dropped_on_next")


def selftest() -> list[str]:
    """Run every planted case; return the wrong verdicts."""
    errors: list[str] = []
    saved = {k: os.environ.get(k) for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM")}
    os.environ["GIT_CONFIG_GLOBAL"] = os.devnull
    os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
    try:
        with tempfile.TemporaryDirectory(prefix=f"{NAME}-") as scratch:
            run_cases(Path(scratch), errors)
    except Unscannable as err:
        errors.append(f"planting failed: {err}")
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    return errors


def expect(errors: list[str], case: str, problems: list[str], wanted: list[str]) -> None:
    """Record a wrong verdict unless `problems` is exactly one per `wanted` fragment."""
    unmatched = [w for w in wanted if not any(w in p for p in problems)]
    if unmatched or len(problems) != len(wanted):
        errors.append(f"{case}: expected {wanted}, got {problems}")


def run_cases(scratch: Path, errors: list[str]) -> None:
    """The planted cases, each against a fresh or adjusted repository."""
    repo = Planted(scratch / "merged")
    head_rs = {"src/kept.rs": planted_test("kept_on_both"), "src/kd.rs": planted_test("kept_defect")}
    repo.write(head_rs)

    def check(listing: str, *untracked: str, skip: tuple[str, ...] = (), extra: str = "") -> list[str]:
        repo.declare(skip, extra)
        repo.write({INVENTORY: listing})
        repo.run("add", "-A", "--", ".", *(f":!{path}" for path in untracked))
        merged, subject, problems, _ = verdict(repo.root)
        if merged != repo.master_commit or subject != "Merge master into next":
            errors.append(f"merged commit read as {merged} {subject!r}, not {repo.master_commit}")
        return problems

    expect(errors, "healthy", check(HEALTHY_LISTING), [])
    expect(
        errors,
        "a test absent and unlisted",
        check(HEALTHY_LISTING.replace("test          no-site    dropped_on_next      src/dropped.rs\n", "")),
        ["test dropped_on_next (src/dropped.rs) is on the merged master, not on HEAD"],
    )
    repo.write({"src/dropped.rs": planted_test("dropped_on_next")})
    expect(errors, "a listed test now on HEAD", check(HEALTHY_LISTING), ["test dropped_on_next is on HEAD now"])
    repo.write({"src/dropped.rs": None})
    expect(
        errors,
        "a listed test gone from the merged master",
        check(HEALTHY_LISTING + "test no-site never_on_master src/dropped.rs\n"),
        ["test never_on_master is gone from the merged master"],
    )
    expect(
        errors,
        "an entry naming the wrong file",
        check(HEALTHY_LISTING.replace("src/dropped.rs", "src/elsewhere.rs")),
        ["is in src/dropped.rs on the merged master, not src/elsewhere.rs"],
    )
    expect(
        errors,
        "a switch absent and unlisted",
        check(HEALTHY_LISTING.replace("switch        no-site    MasterSwitch         core/src/faults.rs\n", "")),
        ["switch MasterSwitch (core/src/faults.rs) is on the merged master"],
    )
    repo.write({FAULTS: planted_faults(["KeptSwitch", "MasterSwitch"])})
    expect(errors, "a listed switch now on HEAD", check(HEALTHY_LISTING), ["switch MasterSwitch is on HEAD now"])
    repo.write({FAULTS: planted_faults(["KeptSwitch"])})
    expect(
        errors,
        "a known-defect entry absent and unlisted",
        check(HEALTHY_LISTING.replace("known-defect  next-rule  kd::master_defect    src/kd.rs\n", "")),
        ["known-defect kd::master_defect (src/kd.rs) is on the merged master"],
    )
    repo.write({IGNORED: planted_ignored(["kd::kept_defect", "kd::master_defect"])})
    expect(
        errors,
        "a listed known-defect entry now on HEAD",
        check(HEALTHY_LISTING),
        ["known-defect kd::master_defect is on HEAD now"],
    )
    repo.write({IGNORED: planted_ignored(["kd::kept_defect"])})
    expect(
        errors,
        "a replaced entry whose target is on HEAD",
        check(HEALTHY_LISTING.replace("no-site    dropped_on_next      src/dropped.rs", "replaced dropped_on_next src/dropped.rs kept_on_both")),
        [],
    )
    expect(
        errors,
        "a replaced entry whose target is not on HEAD",
        check(HEALTHY_LISTING.replace("no-site    dropped_on_next      src/dropped.rs", "replaced dropped_on_next src/dropped.rs no_such_test")),
        ["replaced by no_such_test, which HEAD does not hold"],
    )
    expect(
        errors,
        "a second copy of a name left off and unlisted",
        check(HEALTHY_LISTING.replace(TWIN_ENTRY, "")),
        ["test twin_on_master is in src/twin_a.rs, src/twin_b.rs on the merged master and only in src/twin_a.rs on HEAD"],
    )
    expect(
        errors,
        "a second copy listed by the file HEAD holds it in",
        check(HEALTHY_LISTING.replace(TWIN_ENTRY, TWIN_ENTRY.replace("twin_b", "twin_a"))),
        ["is in src/twin_a.rs on HEAD; that copy is carried"],
    )
    repo.write({"src/moved/twin.rs": planted_test("twin_on_master")})
    moved = '#[path = "moved/twin.rs"]\nmod moved_twin;\n'
    expect(
        errors,
        "a second copy carried to another file, unlisted",
        check(HEALTHY_LISTING.replace(TWIN_ENTRY, ""), extra=moved),
        [],
    )
    expect(
        errors,
        "a second copy carried to another file, listed",
        check(HEALTHY_LISTING, extra=moved),
        ["test twin_on_master is on HEAD now"],
    )
    repo.write({"src/moved/twin.rs": None})
    repo.write({"src/dropped.rs": planted_test("dropped_on_next")})
    expect(errors, "an untracked file holding a listed name", check(HEALTHY_LISTING, "src/dropped.rs"), [])
    repo.write({"src/dropped.rs": None})
    expect(errors, "an open entry", check(OPEN_LISTING), [])
    if open_entries(repo.root) != ["test dropped_on_next"]:
        errors.append(f"open entries read as {open_entries(repo.root)}")
    expect(
        errors,
        "an unknown class and an unknown kind",
        check(HEALTHY_LISTING + "test maybe x src/x.rs\nbench no-site x src/x.rs\n"),
        ["unknown class 'maybe'", "unknown kind 'bench'"],
    )

    # A module compiled out reads as absent: listed truly, it passes; with
    # its entry dropped, the test reads as missing rather than as carried.
    repo.write({"src/explore.rs": planted_test("explored_on_master")})
    gone = ("src/explore.rs",)
    dead = "#[cfg(any())]\nmod explore;\n"
    expect(errors, "a test in a compiled-out module, listed", check(HEALTHY_LISTING, skip=gone, extra=dead), [])
    expect(
        errors,
        "a test in a compiled-out module, unlisted",
        check(
            HEALTHY_LISTING.replace("test          next-rule  explored_on_master   src/explore.rs\n", ""),
            skip=gone,
            extra=dead,
        ),
        ["test explored_on_master (src/explore.rs) is on the merged master, not on HEAD"],
    )
    expect(
        errors,
        "a compiled-out module with a comment before its declaration",
        check(HEALTHY_LISTING, skip=gone, extra="#[cfg(any())]\n// Kept for later merges.\nmod explore;\n"),
        [],
    )
    expect(
        errors,
        "a compiled-out module with its attributes on the declaration's line",
        check(HEALTHY_LISTING, skip=gone, extra="#[cfg(any())] #[path = \"explore.rs\"] mod explore;\n"),
        [],
    )

    # A one-line attributed declaration lends its attributes to no other, and
    # a comment line lends none: the declaration below each is resolved and
    # built as written.
    unlisted = HEALTHY_LISTING.replace(TWIN_ENTRY, "")
    repo.write({"src/live.rs": planted_test("twin_on_master")})
    expect(
        errors,
        "a live declaration below a compiled-out one-line declaration",
        check(unlisted, skip=gone + ("src/live.rs",), extra="#[cfg(any())] mod explore;\nmod live;\n"),
        [],
    )
    repo.write({"src/explore.rs": None})
    expect(
        errors,
        "a live declaration below a comment naming attributes",
        check(unlisted, skip=("src/live.rs",), extra='// Once #[cfg(any())] and #[path = "explore.rs"].\nmod live;\n'),
        [],
    )
    repo.write({"src/live.rs": None})
    repo.write({"src/pathed.rs": planted_test("next_only"), "src/plain.rs": planted_test("twin_on_master")})
    expect(
        errors,
        "a plain declaration below a one-line #[path] declaration",
        check(
            unlisted,
            skip=("src/pathed.rs", "src/plain.rs"),
            extra='#[path = "pathed.rs"] mod renamed;\nmod plain;\n',
        ),
        [],
    )
    repo.write({"src/pathed.rs": None, "src/plain.rs": None})
    repo.write({"src/moved/a.rs": planted_test("next_only"), "src/moved/b.rs": planted_test("twin_on_master")})
    expect(
        errors,
        "two one-line #[path] declarations",
        check(unlisted, extra='#[path = "moved/a.rs"] mod a_tests;\n#[path = "moved/b.rs"] mod b_tests;\n'),
        [],
    )
    repo.write({"src/moved/a.rs": None, "src/moved/b.rs": None})

    # Only files the module tree reaches are read. A carried test whose
    # file is left in place with its `mod` line dropped is not built, so it
    # reads as missing, and the file is named.
    expect(
        errors,
        "a carried test whose mod line is dropped",
        check(HEALTHY_LISTING, skip=("src/kept.rs",)),
        [
            "test kept_on_both (src/kept.rs) is on the merged master, not on HEAD",
            "src/kept.rs holds tests that no mod declaration from a crate root reaches",
        ],
    )
    # Declarations resolve as rustc resolves them: a non-mod-rs file's
    # children sit in the directory named for its stem, `#[path]` is relative
    # to the declaring file's directory, a file loaded by `#[path]` keeps its
    # children beside it, and `mod name;` also finds `name/mod.rs`.
    deep = {
        "src/nest.rs": "mod inner;\n",
        "src/nest/inner.rs": '#[path = "../far/away.rs"]\nmod away;\n',
        "src/far/away.rs": "mod pkg;\n",
        "src/far/pkg/mod.rs": "mod near;\n",
        "src/far/pkg/near.rs": planted_test("twin_on_master"),
    }
    repo.write(deep)
    expect(errors, "a second copy carried deep in the module tree", check(HEALTHY_LISTING.replace(TWIN_ENTRY, "")), [])
    repo.write({path: None for path in deep})
    repo.write({"src/nest.rs": "mod inner;\n", "src/inner.rs": planted_test("twin_on_master")})
    expect(
        errors,
        "a stem directory's child placed beside the declaring file instead",
        check(HEALTHY_LISTING.replace(TWIN_ENTRY, ""), skip=("src/inner.rs",)),
        [
            "test twin_on_master is in src/twin_a.rs, src/twin_b.rs on the merged master and only in src/twin_a.rs on HEAD",
            "src/inner.rs holds tests that no mod declaration from a crate root reaches",
        ],
    )
    repo.write({"src/nest.rs": None, "src/inner.rs": None})
    repo.write(
        {
            MANIFEST: PLANTED_MANIFEST + '\n[[bin]]\nname = "tool"\npath = "tools/run.rs"\n',
            "tools/run.rs": planted_test("twin_on_master"),
        }
    )
    expect(errors, "a second copy carried in a named binary's root", check(HEALTHY_LISTING.replace(TWIN_ENTRY, "")), [])
    repo.write({MANIFEST: PLANTED_MANIFEST, "tools/run.rs": None})
    repo.write({MANIFEST: "[workspace]\n"})
    repo.write({INVENTORY: HEALTHY_LISTING})
    repo.run("add", "-A")
    try:
        verdict(repo.root)
        errors.append("no package naming a root: a verdict, not exit 2")
    except Unscannable:
        pass
    repo.write({MANIFEST: PLANTED_MANIFEST})
    repo.write({"src/inline.rs": "#[cfg(any())]\n#[test]\nfn explored_on_master() {}\n"})
    expect(errors, "a compiled-out test function, listed", check(HEALTHY_LISTING), [])
    repo.write({"src/inline.rs": None})

    # The local master and origin/master lag the merge, as on the builder:
    # the verdict is the one read with them current.
    current = check(HEALTHY_LISTING.replace("switch        no-site    MasterSwitch         core/src/faults.rs\n", ""))
    repo.run("branch", "-f", "master", repo.root_commit)
    repo.run("update-ref", "refs/remotes/origin/master", repo.root_commit)
    stale = check(HEALTHY_LISTING.replace("switch        no-site    MasterSwitch         core/src/faults.rs\n", ""))
    if stale != current:
        errors.append(f"with master and origin/master behind the merge: {stale}, not {current}")

    repo.write({FAULTS: planted_faults(["KeptSwitch"]).replace("KeptSwitch,", "KeptSwitch, // note")})
    repo.write({INVENTORY: HEALTHY_LISTING})
    repo.run("add", "-A")
    try:
        verdict(repo.root)
        errors.append("an unreadable line in the faults! list: a verdict, not exit 2")
    except Unscannable:
        pass
    repo.write({FAULTS: planted_faults(["KeptSwitch"])})

    def crash(*_: object) -> dict[str, str]:
        raise ValueError("planted crash")

    reader = globals()["committed_files"]
    globals()["committed_files"] = crash
    try:
        with open(os.devnull, "w", encoding="utf-8") as sink:
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                code = report(repo.root)
    finally:
        globals()["committed_files"] = reader
    if code != 2:
        errors.append(f"a crash while reading: exit {code}, not 2")

    bare = Planted(scratch / "unmerged", merge=False)
    bare.write({INVENTORY: ""})
    try:
        verdict(bare.root)
        errors.append("no merge on the first-parent line: a verdict, not exit 2")
    except Unscannable:
        pass


def main(argv: list[str]) -> int:
    """Self-test, then compare the merged master with HEAD."""
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    try:
        errors = selftest()
    except Exception as err:  # a crash in the self-test has shown nothing
        errors = [f"crashed: {err!r}"]
    if errors:
        for err in errors:
            print(f"{NAME}: self-test: {err}", file=sys.stderr)
        return 2
    if argv and argv[0] == "--self-test":
        print(f"{NAME}: self-test passed")
        return 0
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        print(f"{NAME}: not inside a git work tree", file=sys.stderr)
        return 2
    return report(Path(top))


def report(root: Path) -> int:
    """Compare the merged master with HEAD at `root`, print the verdict, return the exit code."""
    try:
        merged, subject, problems, counts = verdict(root)
        opened = open_entries(root)
    except Unscannable as err:
        print(f"{NAME}: {err}", file=sys.stderr)
        return 2
    except Exception as err:  # a crash has looked at nothing, so it is never a verdict
        print(f"{NAME}: crashed: {err!r}", file=sys.stderr)
        return 2
    print(f"{NAME}: merged master {merged[:12]}, from \"{subject}\"")
    for item in opened:
        print(f"{NAME}: open, not yet classed: {item}")
    for problem in problems:
        print(problem)
    if problems:
        print(f"{NAME}: {len(problems)} problem(s)")
        return 1
    print(
        f"{NAME}: {counts['test']} test names, {counts['switch']} switches and "
        f"{counts['known-defect']} known-defect entries on the merged master, each carried or listed"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
