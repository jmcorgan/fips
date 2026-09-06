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

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -z "${FIPS_GLIBC_FLOOR:-}" ]; then
    # shellcheck source=../packaging/build-floor.env
    . "$REPO_ROOT/packaging/build-floor.env"
fi
FLOOR="${FIPS_GLIBC_FLOOR:?no floor declared}"

for tool in readelf dpkg dpkg-deb; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "check-glibc-floor: $tool is not installed; cannot check anything." >&2
        echo "                   Refusing to report a pass I did not establish." >&2
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
        echo "  ERROR $label is not a readable ELF object" >&2
        FAILED=$((FAILED + 1))
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
    dpkg-deb -x "$deb" "$tmp"
    # A package legitimately ships executable shell scripts alongside its
    # binaries -- fips-dns-setup and its teardown are two -- so filter to ELF
    # objects rather than treating a script as an unreadable binary. A .deb
    # with no ELF object at all is still an error: it means the glob or the
    # layout moved and this check examined nothing.
    local found=0 f
    while IFS= read -r -d '' f; do
        is_elf "$f" || continue
        found=1
        check_binary "$f" "$(basename "$deb"):$(basename "$f")"
    done < <(find "$tmp" -type f -perm -u+x -print0)
    if [ "$found" -eq 0 ]; then
        echo "  ERROR $(basename "$deb") contains no ELF executables" >&2
        FAILED=$((FAILED + 1))
    fi
}

[ $# -gt 0 ] || {
    echo "usage: check-glibc-floor.sh <artifact|binary>..." >&2
    exit 2
}

echo "=== glibc floor check (declared floor: $FLOOR) ==="
for arg in "$@"; do
    [ -e "$arg" ] || { echo "  ERROR $arg does not exist" >&2; FAILED=$((FAILED + 1)); continue; }
    case "$arg" in
        *.deb) check_deb "$arg" ;;
        *)     check_binary "$arg" "$(basename "$arg")" ;;
    esac
done

# Nothing examined is a failure, not a pass. An argument list that matched no
# binary means the caller's glob went stale, and reporting that as green is how
# a guard quietly stops guarding.
if [ "$CHECKED" -eq 0 ] && [ "$FAILED" -eq 0 ]; then
    echo "check-glibc-floor: examined no binaries; refusing to report a pass." >&2
    exit 2
fi

if [ "$FAILED" -ne 0 ]; then
    echo "check-glibc-floor: $FAILED problem(s) across $CHECKED binaries." >&2
    echo "  A binary above the floor installs cleanly and then fails to start." >&2
    echo "  Build through packaging/debian/build-deb-container.sh, which pins" >&2
    echo "  the build image to the oldest supported distribution." >&2
    exit 1
fi

echo "=== glibc floor check passed ($CHECKED binaries, all at or below $FLOOR) ==="
