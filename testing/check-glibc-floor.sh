#!/bin/bash
# Fail when a shipped binary needs a newer glibc than the declared floor.
#
# The defect this exists to catch installs cleanly and then cannot run. Rust's
# standard library references pidfd_spawnp and pidfd_getpid as weak undefined
# symbols guarded by a runtime check, so a binary is meant to fall back where
# the C library lacks them. Linking against a glibc that HAS them records a
# version dependency instead, and the loader refuses the whole image on that
# entry alone regardless of the symbols being weak. Every Linux artifact from
# v0.3.0 to v0.5.0 shipped that way and could not start on Debian 12 or Ubuntu
# 22.04, while apt reported success and fipsctl -- which never spawns a process
# and so never referenced those symbols -- ran perfectly.
#
# Usage: check-glibc-floor.sh <artifact|binary>...
#   A .deb is unpacked and every executable under usr/bin is checked.
#   Anything else is treated as a single ELF binary.
#
# Reads the floor from packaging/build-floor.env unless FIPS_GLIBC_FLOOR is set.
#
# Exit 0 = every input was examined and none is above the floor. Exit 1 = a
# binary needs a newer glibc than the floor. Exit 2 = an input could not be
# examined (missing, not an ELF object, a .deb that would not unpack or holds
# no binaries), or the check could not run at all; never treated as a pass,
# and never reported as a binary above the floor.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# A missing or empty floor means the check cannot run, so it exits 2 here
# rather than letting `set -e` or a `:?` expansion end the run with status 1,
# which callers would read as a binary above the floor.
FLOOR_ENV="$REPO_ROOT/packaging/build-floor.env"
if [ -z "${FIPS_GLIBC_FLOOR:-}" ]; then
    [ -r "$FLOOR_ENV" ] || {
        echo "check-glibc-floor: cannot read $FLOOR_ENV and FIPS_GLIBC_FLOOR is not set;" >&2
        echo "                   there is no floor to check against." >&2
        exit 2
    }
    # shellcheck source=/dev/null
    . "$FLOOR_ENV"
fi
if [ -z "${FIPS_GLIBC_FLOOR:-}" ]; then
    echo "check-glibc-floor: $FLOOR_ENV declares no FIPS_GLIBC_FLOOR;" >&2
    echo "                   there is no floor to check against." >&2
    exit 2
fi
FLOOR="$FIPS_GLIBC_FLOOR"

# The package hint is sourced only when a tool is missing, and only if the
# helper is there: glibc-floor/test.sh runs copies of this script with no lib/
# beside them.
for tool in readelf dpkg dpkg-deb; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "check-glibc-floor: $tool is not installed; cannot check anything." >&2
        echo "                   Refusing to report a pass I did not establish." >&2
        if [ -r "$SCRIPT_DIR/lib/tool-hint.sh" ]; then
            # shellcheck source=/dev/null
            . "$SCRIPT_DIR/lib/tool-hint.sh"
            hint="$(tool_hint "$tool")" && echo "                   $hint" >&2
        fi
        exit 2
    }
done

# The maximum glibc version a binary requires.
#
# Reads the `Version needs` section, which is the table the dynamic loader
# enforces and the one that carries the fatal entry. Do NOT compute this from
# `objdump -T | grep GLIBC_ | sort -V | tail -1`: that sorts whole lines, the
# version is not the leading field, and a data symbol at GLIBC_2.2.5 therefore
# sorts last. Measured against the shipped v0.5.0 fips binary, that pipeline
# reports 2.2.5 for a binary whose real floor is 2.39 -- it would have passed
# every affected release.
#
# Prints nothing and returns 1 when it finds no GLIBC requirement at all, so an
# unreadable or non-dynamic input cannot be scored as a pass.
max_glibc_need() {
    local bin="$1" found
    found=$(readelf -VW "$bin" 2>/dev/null \
        | awk '/Version needs section/,0' \
        | grep -oE 'GLIBC_[0-9.]+' \
        | sed 's/GLIBC_//' \
        | sort -V \
        | tail -1) || true
    [ -n "$found" ] || return 1
    printf '%s\n' "$found"
    # Explicit: the caller tests this status to tell "no requirement" from a
    # value, so it must not be whatever printf happened to return.
    return 0
}

FAILED=0
CHECKED=0
UNCHECKED=0
UNCHECKED_LIST=()

# unchecked <label> <reason>: records an input this run could not examine. It
# is kept apart from FAILED because the remedy differs: an input that was never
# read says nothing about the floor, and the above-the-floor advice would send
# the reader to rebuild a package that may be fine.
unchecked() {
    echo "  UNCHECKED $1: could not check ($2)" >&2
    UNCHECKED_LIST+=("$1: $2")
    UNCHECKED=$((UNCHECKED + 1))
}

is_elf() { readelf -hW "$1" >/dev/null 2>&1; }

check_binary() {
    local bin="$1" label="$2" need
    if ! need=$(max_glibc_need "$bin"); then
        # A static binary is a legitimate no-requirement case, so distinguish
        # it from a file that could not be read rather than passing both.
        if readelf -hW "$bin" >/dev/null 2>&1; then
            echo "  ok    $label (no glibc version requirement)"
            CHECKED=$((CHECKED + 1))
            return
        fi
        case "$label" in
            *.tar.gz|*.tgz|*.tar|*.tar.*)
                unchecked "$label" "not a readable ELF object; unpack it and pass its binaries" ;;
            *)
                unchecked "$label" "not a readable ELF object" ;;
        esac
        return
    fi
    CHECKED=$((CHECKED + 1))
    if dpkg --compare-versions "$need" gt "$FLOOR"; then
        echo "  FAIL  $label needs glibc $need, above the declared floor $FLOOR" >&2
        FAILED=$((FAILED + 1))
    else
        echo "  ok    $label needs glibc $need"
    fi
}

check_deb() {
    local deb="$1" tmp
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN
    if ! dpkg-deb -x "$deb" "$tmp"; then
        unchecked "$(basename "$deb")" "dpkg-deb could not unpack it"
        return
    fi
    # A package legitimately ships executable shell scripts alongside its
    # binaries -- fips-dns-setup and its teardown are two -- so filter to ELF
    # objects rather than treating a script as an unreadable binary. A .deb
    # with no ELF object at all is still not a pass: it means the glob or the
    # layout moved and this check examined nothing.
    local found=0 f
    while IFS= read -r -d '' f; do
        is_elf "$f" || continue
        found=1
        check_binary "$f" "$(basename "$deb"):$(basename "$f")"
    done < <(find "$tmp" -type f -perm -u+x -print0)
    if [ "$found" -eq 0 ]; then
        unchecked "$(basename "$deb")" "contains no ELF executables"
    fi
}

[ $# -gt 0 ] || {
    echo "usage: check-glibc-floor.sh <artifact|binary>..." >&2
    exit 2
}

echo "=== glibc floor check (declared floor: $FLOOR) ==="
for arg in "$@"; do
    [ -e "$arg" ] || { unchecked "$arg" "does not exist"; continue; }
    case "$arg" in
        *.deb) check_deb "$arg" ;;
        *)     check_binary "$arg" "$(basename "$arg")" ;;
    esac
done

# print_unchecked: lists the inputs this run could not examine, if any.
print_unchecked() {
    [ "$UNCHECKED" -gt 0 ] || return 0
    echo "  Not checked:" >&2
    local entry
    for entry in "${UNCHECKED_LIST[@]}"; do
        echo "    $entry" >&2
    done
}

# A real floor failure is the stronger signal, so it decides the status even
# when other inputs went unchecked; those are still listed.
if [ "$FAILED" -ne 0 ]; then
    echo "check-glibc-floor: $FAILED binary(ies) above the floor across $CHECKED checked, $UNCHECKED input(s) not checked." >&2
    echo "  A binary above the floor installs cleanly and then fails to start." >&2
    echo "  Build through packaging/debian/build-deb-container.sh, which pins" >&2
    echo "  the build image to the oldest supported distribution." >&2
    print_unchecked
    exit 1
fi

# An input that could not be examined is not a pass. This is also where a
# stale caller glob lands: an unexpanded pattern such as "$UNPACK"/*/fips
# arrives as a path that does not exist, and reporting that as green is how a
# guard quietly stops guarding.
if [ "$UNCHECKED" -ne 0 ]; then
    if [ "$CHECKED" -eq 0 ]; then
        echo "check-glibc-floor: could not check $UNCHECKED input(s) and examined no binaries." >&2
    else
        echo "check-glibc-floor: could not check $UNCHECKED input(s); nothing was found above the floor in the $CHECKED binaries checked." >&2
    fi
    print_unchecked
    exit 2
fi

# Backstop: every argument raises CHECKED, FAILED or UNCHECKED, and an empty
# argument list is refused above, so this is not expected to be reached.
if [ "$CHECKED" -eq 0 ]; then
    echo "check-glibc-floor: examined no binaries; refusing to report a pass." >&2
    exit 2
fi

echo "=== glibc floor check passed ($CHECKED binaries, all at or below $FLOOR) ==="
