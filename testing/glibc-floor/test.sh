#!/bin/bash
# ── Cases for check-glibc-floor.sh ──────────────────────────────────────────
# The floor check runs at release time, on artifacts nobody re-reads, so how it
# reports matters as much as what it finds. An input it cannot examine (a
# missing path, a file that is not an ELF object such as an unextracted
# tarball, a corrupt or binary-less .deb) must come out as "could not check"
# with exit 2, never as a binary above the floor: that advice sends the reader
# to rebuild a package that was never examined. A binary that really is above
# the floor must still exit 1 with the advice, even beside unchecked inputs. A
# floor that is missing or empty means the check cannot run at all, which is
# exit 2 as well.
#
# Inputs are built at run time from the host's own true executable (the first
# one on PATH). Every case either sets FIPS_GLIBC_FLOOR or runs a scratch copy
# of the check beside a build-floor.env of its own, so nothing depends on the
# host's glibc or on the repository's packaging/build-floor.env.
#
# Exit 0 = every case behaved. Exit 1 = a case did not. Exit 2 = the cases
# could not run (no readelf, no dpkg-deb, no dynamic true); never a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECK="$SCRIPT_DIR/../check-glibc-floor.sh"
WORK="$(mktemp -d)"
trap 'chmod -R u+rwx "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

cannot() { echo "glibc-floor cases: $*; cannot run." >&2; exit 2; }

# missing <tool>: like cannot, then names the package that provides the tool.
# The helper is sourced only here, and only if it is there.
missing() {
    echo "glibc-floor cases: $1 is not installed; cannot run." >&2
    if [ -r "$SCRIPT_DIR/../lib/tool-hint.sh" ]; then
        # shellcheck source=/dev/null
        . "$SCRIPT_DIR/../lib/tool-hint.sh"
        local hint
        hint="$(tool_hint "$1")" && echo "glibc-floor cases: $hint" >&2
    fi
    exit 2
}

for tool in readelf dpkg dpkg-deb tar; do
    command -v "$tool" >/dev/null 2>&1 || missing "$tool"
done
# `true` is a shell builtin, so `command -v` would print the bare word.
HOSTELF="$(type -P true)" || cannot "no true executable on PATH"
readelf -hW "$HOSTELF" >/dev/null 2>&1 || cannot "$HOSTELF is not an ELF object"
NEED="$(readelf -VW "$HOSTELF" 2>/dev/null | awk '/Version needs section/,0' \
    | grep -oE 'GLIBC_[0-9.]+' | sed 's/GLIBC_//' | sort -V | tail -1)"
[ -n "$NEED" ] || cannot "$HOSTELF has no glibc version requirement"
dpkg --compare-versions "$NEED" gt 2.0 || cannot "$HOSTELF needs glibc $NEED, not above 2.0"

FAILED=0
ok()  { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAILED=$((FAILED + 1)); }

ADVICE='installs cleanly and then fails to start'

# run_script <script> <name> <floor> <arg...>: runs the given copy of the
# check, leaving combined output in $WORK/out and the status in RC.
run_script() {
    local script="$1"
    CASE="$2"
    local floor="$3"
    shift 3
    FIPS_GLIBC_FLOOR="$floor" bash "$script" "$@" > "$WORK/out" 2>&1
    RC=$?
    return 0
}

# run_case <name> <floor> <arg...>: runs the check under test.
run_case() { run_script "$CHECK" "$@"; }

# floor_tree <name> [env contents]: a scratch copy of the check at
# $WORK/<name>/testing, so it reads its floor from $WORK/<name>/packaging. With
# no contents there is no packaging/build-floor.env at all. Prints the copy.
floor_tree() {
    local root="$WORK/$1"
    mkdir -p "$root/testing"
    cp "$CHECK" "$root/testing/check-glibc-floor.sh"
    if [ $# -gt 1 ]; then
        mkdir -p "$root/packaging"
        printf '%s\n' "$2" > "$root/packaging/build-floor.env"
    fi
    printf '%s\n' "$root/testing/check-glibc-floor.sh"
}

# Assertions on the last run.
exit_is() {
    if [ "$RC" -eq "$1" ]; then ok "$CASE: exit $1"
    else bad "$CASE: exit $RC, expected $1"; sed 's/^/        | /' "$WORK/out"; fi
}
has() {
    if grep -qF -- "$1" "$WORK/out"; then ok "$CASE: says '$1'"
    else bad "$CASE: does not say '$1'"; fi
}
lacks() {
    if grep -qF -- "$1" "$WORK/out"; then bad "$CASE: says '$1'"
    else ok "$CASE: does not say '$1'"; fi
}
# unchecked_lists <name>: the name appears on an UNCHECKED line where it was
# met, and again in the "Not checked:" list at the end of the run, which is the
# part a reader of a long run sees.
unchecked_lists() {
    if grep -E '^\s*UNCHECKED ' "$WORK/out" | grep -qF -- "$1"; then
        ok "$CASE: reports $1 as not checked"
    else
        bad "$CASE: does not report $1 as not checked"
    fi
    if sed -n '/^  Not checked:$/,$p' "$WORK/out" | grep -qF -- "$1"; then
        ok "$CASE: lists $1 at the end of the run"
    else
        bad "$CASE: does not list $1 at the end of the run"
    fi
}
# no_advice: the above-the-floor advice is absent.
no_advice() { lacks "$ADVICE"; }

# build_deb <name> <file to place in usr/bin>
build_deb() {
    local name="$1" payload="$2" root="$WORK/pkg-$1"
    mkdir -p "$root/DEBIAN" "$root/usr/bin"
    cp "$payload" "$root/usr/bin/"
    chmod 755 "$root/usr/bin/"*
    printf 'Package: %s\nVersion: 1.0\nArchitecture: all\nMaintainer: t <t@t>\nDescription: t\n' \
        "$name" > "$root/DEBIAN/control"
    dpkg-deb --root-owner-group -b "$root" "$WORK/$name.deb" >/dev/null 2>&1 \
        || cannot "dpkg-deb could not build a test package"
}

echo "check-glibc-floor cases ($HOSTELF needs glibc $NEED)"

printf 'not an ELF object\n' > "$WORK/notes.txt"
mkdir -p "$WORK/tarsrc" && cp "$HOSTELF" "$WORK/tarsrc/true"
tar -czf "$WORK/fips.tar.gz" -C "$WORK/tarsrc" true
printf 'not a package\n' > "$WORK/x.deb"
printf '#!/bin/sh\nexit 0\n' > "$WORK/setup-script"
build_deb scripts-only "$WORK/setup-script"
build_deb with-elf "$HOSTELF"

run_case "text file" "$NEED" "$WORK/notes.txt"
exit_is 2; has "could not check"; unchecked_lists notes.txt; no_advice

run_case "tarball" "$NEED" "$WORK/fips.tar.gz"
exit_is 2; has "unpack it"; unchecked_lists fips.tar.gz; no_advice

run_case "nonexistent path" "$NEED" "$WORK/missing-binary"
exit_is 2; has "does not exist"; unchecked_lists missing-binary; no_advice

if [ "$(id -u)" -eq 0 ]; then
    echo "  SKIP unreadable file: running as root, so permissions do not stop a read"
else
    cp "$HOSTELF" "$WORK/locked" && chmod 000 "$WORK/locked"
    run_case "unreadable file" "$NEED" "$WORK/locked"
    exit_is 2; unchecked_lists locked; no_advice
fi

run_case "corrupt .deb then a good binary" "$NEED" "$WORK/x.deb" "$HOSTELF"
exit_is 2; has "could not check"; unchecked_lists x.deb; no_advice
has "ok    $(basename "$HOSTELF") needs glibc $NEED"

run_case ".deb with only a script" "$NEED" "$WORK/scripts-only.deb"
exit_is 2; has "no ELF executables"; unchecked_lists scripts-only.deb; no_advice

run_case "binary at the floor" "$NEED" "$HOSTELF"
exit_is 0; has "glibc floor check passed"; lacks "could not check"; no_advice

run_case ".deb with a binary at the floor" "$NEED" "$WORK/with-elf.deb"
exit_is 0; has "glibc floor check passed"; no_advice

run_case "binary above the floor" 2.0 "$HOSTELF"
exit_is 1; has "above the declared floor 2.0"; has "$ADVICE"

run_case "binary above the floor beside a text file" 2.0 "$HOSTELF" "$WORK/notes.txt"
exit_is 1; has "$ADVICE"; unchecked_lists notes.txt

run_case "binary at the floor beside a text file" "$NEED" "$HOSTELF" "$WORK/notes.txt"
exit_is 2; has "ok    $(basename "$HOSTELF") needs glibc $NEED"; unchecked_lists notes.txt
no_advice

# With FIPS_GLIBC_FLOOR empty the floor comes from packaging/build-floor.env.
# When that cannot supply one, there is nothing to check against: that is
# "could not run" (exit 2), never a pass and never a binary above the floor.
NOENV="$(floor_tree no-env)"
run_script "$NOENV" "no build-floor.env and no floor set" "" "$HOSTELF"
exit_is 2; has "no floor to check against"; lacks "glibc floor check passed"
no_advice

EMPTYENV="$(floor_tree empty-env 'FIPS_GLIBC_FLOOR=""')"
run_script "$EMPTYENV" "build-floor.env with an empty floor" "" "$HOSTELF"
exit_is 2; has "no floor to check against"; lacks "glibc floor check passed"
no_advice

NOFLOOR="$(floor_tree no-floor 'FIPS_BUILD_IMAGE="ubuntu:22.04"')"
run_script "$NOFLOOR" "build-floor.env declaring no floor" "" "$HOSTELF"
exit_is 2; has "no floor to check against"; lacks "glibc floor check passed"
no_advice

GOODENV="$(floor_tree good-env "FIPS_GLIBC_FLOOR=\"$NEED\"")"
run_script "$GOODENV" "floor read from build-floor.env" "" "$HOSTELF"
exit_is 0; has "declared floor: $NEED"; has "glibc floor check passed"

if [ "$FAILED" -ne 0 ]; then
    echo "check-glibc-floor cases: $FAILED assertion(s) failed"
    exit 1
fi
echo "check-glibc-floor cases: all passed"
