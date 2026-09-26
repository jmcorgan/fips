#!/bin/bash
# Fail when an RPM records a glibc requirement above the declared floor.
#
# The counterpart of check-deb-depends.sh, for the other package format and for
# a different failure. On the Debian side the package's Depends are written by
# hand and can disagree with what the binaries need, so that check compares the
# two. rpm derives the requirement from the ELF files and cannot disagree with
# them -- which moves the risk one step back: the binaries themselves may have
# been built somewhere above the floor, and the package that results installs
# nowhere older, silently, until someone tries.
#
# This reads the requirement out of the finished package, which is the artifact
# that ships and the same table dnf enforces at install time.
#
# Usage: check-rpm-floor.sh <package.rpm>...
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

command -v rpm >/dev/null 2>&1 || {
    echo "check-rpm-floor: rpm is not installed; cannot check anything." >&2
    echo "                 Refusing to report a pass I did not establish." >&2
    exit 2
}

[ $# -gt 0 ] || {
    echo "usage: check-rpm-floor.sh <package.rpm>..." >&2
    exit 2
}

# Sorts versions the way rpm does, so 2.10 is above 2.9 rather than below it.
version_gt() {
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ] && [ "$1" != "$2" ]
}

FAILED=0
CHECKED=0

for pkg in "$@"; do
    if [ ! -f "$pkg" ]; then
        echo "  ERROR $pkg does not exist" >&2
        FAILED=$((FAILED + 1))
        continue
    fi

    # Every libc.so.6(GLIBC_x.y) entry rpm derived from the packaged binaries.
    # The highest one is the floor the package will be held to.
    need=$(rpm -qp --requires "$pkg" 2>/dev/null \
        | grep -oE 'GLIBC_[0-9.]+' \
        | sed 's/GLIBC_//' \
        | sort -V \
        | tail -1) || true

    if [ -z "$need" ]; then
        # No requirement at all means the package holds no dynamically linked
        # binary, which for this package means the file list moved. Not a pass.
        echo "  ERROR $(basename "$pkg") records no glibc requirement" >&2
        FAILED=$((FAILED + 1))
        continue
    fi

    CHECKED=$((CHECKED + 1))
    if version_gt "$need" "$FLOOR"; then
        echo "  FAIL  $(basename "$pkg") requires glibc $need, above the declared floor $FLOOR" >&2
        FAILED=$((FAILED + 1))
    else
        echo "  ok    $(basename "$pkg") requires glibc $need"
    fi
done

if [ "$FAILED" -ne 0 ]; then
    echo "check-rpm-floor: $FAILED check(s) failed against floor $FLOOR." >&2
    echo "  The package was built from binaries compiled above the floor. Build" >&2
    echo "  them in the pinned container: packaging/rpm/build-rpm-container.sh." >&2
    exit 1
fi

if [ "$CHECKED" -eq 0 ]; then
    echo "check-rpm-floor: nothing was checked; refusing to report a pass." >&2
    exit 2
fi

echo "=== RPM glibc floor check passed ($CHECKED package(s)) ==="
