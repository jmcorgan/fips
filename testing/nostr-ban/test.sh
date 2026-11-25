#!/bin/bash
# ── Break test for the nostr ban in the root clippy.toml ────────────────────
# The root clippy.toml bans the nostr items that read the clock or the OS
# random source. An entry clippy cannot resolve (a misspelt path, or an item
# a nostr release moved) draws only a warning, which `-D warnings` does not
# turn into an error, so a broken entry bans nothing and clippy stays green.
# This lints the fixture beside this script, which uses every banned item
# once in banned.rs and again in allowed.rs under a file-level allow, and
# requires:
#   - clippy to fail;
#   - the set of paths its "use of a disallowed" errors name to equal the set
#     of entries in the clippy.toml;
#   - exactly one such error per entry;
#   - every such error to be in banned.rs, and none in allowed.rs.
#
# The fixture, the clippy.toml, the root Cargo.lock and the root
# rust-toolchain.toml are copied into a temporary directory, so cargo there
# runs the pinned toolchain and resolves the root's nostr version. It builds
# offline when the local registry holds every crate, and fetches otherwise.
#
# The checks read clippy's plain-text output line by line, so cargo runs with
# colour off whatever the caller sets: under CARGO_TERM_COLOR=always (GitHub
# CI sets it) the lines open with ANSI escapes and match no pattern. Output
# that still carries an escape stops the check with exit 2.
#
# Usage: test.sh [<clippy.toml>]
#   With no argument, checks the root clippy.toml. Naming another file checks
#   that one instead, which is how a mutation of the list is run.
#
# Exit 0 = the ban holds. Exit 1 = it does not. Exit 2 = the check could not
# run (a file missing, cargo failed to fetch or resolve, output unreadable);
# never a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG="${1:-$ROOT/clippy.toml}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for f in "$CONFIG" "$ROOT/Cargo.lock" "$ROOT/rust-toolchain.toml"; do
    if [[ ! -f "$f" ]]; then
        echo "nostr-ban: $f is missing; nothing was checked" >&2
        exit 2
    fi
done

cp "$SCRIPT_DIR"/Cargo.toml "$SCRIPT_DIR"/lib.rs "$SCRIPT_DIR"/banned.rs \
    "$SCRIPT_DIR"/allowed.rs "$WORK"/ || exit 2
cp "$CONFIG" "$WORK/clippy.toml" || exit 2
cp "$ROOT/Cargo.lock" "$ROOT/rust-toolchain.toml" "$WORK"/ || exit 2

cd "$WORK" || exit 2
export CARGO_TARGET_DIR="$WORK/target"
export CARGO_TERM_COLOR=never
echo "nostr-ban: $(cargo -V)"

offline=--offline
if ! cargo fetch --offline >/dev/null 2>&1; then
    echo "nostr-ban: the local registry lacks a crate; fetching"
    if ! cargo fetch; then
        echo "nostr-ban: cargo could not fetch the fixture's crates; nothing was checked" >&2
        exit 2
    fi
    offline=
fi

cargo clippy $offline -- -D warnings > "$WORK/clippy.out" 2>&1
clippy_rc=$?
cat "$WORK/clippy.out"

python3 - "$WORK/clippy.toml" "$WORK/clippy.out" "$clippy_rc" <<'PY'
import collections
import re
import sys
import tomllib

config, output, rc = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(config, "rb") as f:
    table = tomllib.load(f)
entries = set(table.get("disallowed-types", [])) | set(table.get("disallowed-methods", []))
if not entries:
    print("nostr-ban: the clippy.toml names no entry; nothing was checked")
    sys.exit(2)

lines = open(output).read().splitlines()
if any("\x1b" in line for line in lines):
    print("nostr-ban: clippy's output carries colour codes; nothing was checked")
    sys.exit(2)
if any(re.match(r"^error\[E\d+\]", line) for line in lines):
    print("nostr-ban: the fixture did not compile; nothing was checked")
    sys.exit(2)

found = []
error = re.compile(r"^error: use of a disallowed (?:type|method) `([^`]+)`")
where = re.compile(r"^\s*--> ([^:]+):(\d+)")
pending = None
for line in lines:
    m = error.match(line)
    if m:
        pending = m.group(1)
        continue
    m = where.match(line)
    if m and pending is not None:
        found.append((pending, m.group(1)))
        pending = None

failures = []
if rc == 0:
    failures.append("clippy exited 0: the ban drew no error")
counts = collections.Counter(path for path, _ in found)
named = set(counts)
for path in sorted(entries - named):
    failures.append(f"no error names `{path}`: the entry bans nothing")
for path in sorted(named - entries):
    failures.append(f"an error names `{path}`, which is not an entry")
for path, n in sorted(counts.items()):
    if n != 1:
        failures.append(f"`{path}` drew {n} errors, not 1")
for path, file in found:
    if file != "banned.rs":
        failures.append(f"`{path}` drew an error in {file}, outside banned.rs")

print(f"nostr-ban: {len(entries)} entries, {len(found)} errors, clippy exit {rc}")
for failure in failures:
    print(f"  FAIL {failure}")
if failures:
    print("nostr-ban FAIL")
    sys.exit(1)
print("nostr-ban PASS")
PY
