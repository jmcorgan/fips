#!/bin/bash
# Build and package fips inside the pinned build container. Run by
# build-deb-container.sh with the source at /src (read-only) and the cargo
# target directory in a named volume at /target; not meant to be run directly.
#
# Usage: build-in-container.sh --version V --output-dir DIR --name-file PATH
#                              [--features LIST]
#
# The target volume is shared by every checkout on the host. Cargo decides
# whether a workspace crate is up to date from file modification times, and a
# crate's artifacts carry no trace of which tree they came from, because every
# tree is mounted at the same /src. So a build of one tree whose files are
# older than another tree's last build links that tree's crates: it either
# fails to compile, when the root crate is rebuilt against another tree's
# member crate, or it packages the other tree's binary and says nothing. Four
# things here stop that:
#
#   1. A lock on the volume, held for the whole build and packaging, so two
#      package builds never interleave in it. It also covers the registry
#      volume: cargo keeps its own lock for the registry in CARGO_HOME, outside
#      that volume, so without this two containers can unpack the same crate at
#      once. Only builds that run this script take the lock.
#   2. The workspace crates are cleaned before every build, so they are always
#      compiled from this tree. Dependencies from the registry are keyed by
#      version, checksum, features and toolchain, so they stay cached and are
#      safe to share. This is what a repeat build pays for: the workspace
#      crates are compiled every time, about a minute, even when nothing
#      changed.
#   3. The build's own report is checked: a crate built from a path, rather
#      than downloaded, that cargo reports as fresh was not compiled here.
#   4. The binaries cargo left in the target volume are hashed after the build
#      and again after packaging, so a binary replaced in between, by a build
#      that does not take the lock, fails the build rather than shipping.
#
# After packaging, testing/check-deb-revision.sh checks that every binary in
# the package carries the revision and dirty flag of this tree, as git reads it
# here. That needs git here to read the tree's repository, which
# build-deb-container.sh arranges with its git mounts; HEAD is compared with the
# host's on entry so a gap in those mounts fails at once. A commit made in the
# tree while this build runs, including while it waits for the lock, fails the
# build: the package's version names one commit and its binaries may name
# another. Build again once the tree has settled.

set -euo pipefail

VERSION=""
DEST_DIR=""
NAME_FILE=""
FEATURES=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)    VERSION="${2:?missing value for --version}"; shift 2 ;;
        --output-dir) DEST_DIR="${2:?missing value for --output-dir}"; shift 2 ;;
        --name-file)  NAME_FILE="${2:?missing value for --name-file}"; shift 2 ;;
        --features)   FEATURES="${2:?missing value for --features}"; shift 2 ;;
        *)            echo "build-in-container: unknown option: $1" >&2; exit 2 ;;
    esac
done
if [ -z "$VERSION" ] || [ -z "$DEST_DIR" ] || [ -z "$NAME_FILE" ]; then
    echo "build-in-container: --version, --output-dir and --name-file are required" >&2
    exit 2
fi
: "${CARGO_TARGET_DIR:?build-in-container: CARGO_TARGET_DIR is not set}"

say() {
    echo "build-in-container: $*" >&2
}

# The binaries cargo-deb packages from the target directory.
BINARIES=(fips fipsctl fips-gateway fipstop)

# ── The tree's git metadata ─────────────────────────────────────────────────
# Read before the lock wait, which can be minutes, so the comparison with the
# host's HEAD tests the mounts and not a commit made during the wait.
HOST_HEAD=${FIPS_HOST_HEAD:-}
ENTRY_HEAD=""
if ENTRY_HEAD=$(git rev-parse --verify --quiet HEAD 2>/dev/null); then
    if [ -n "$HOST_HEAD" ] && [ "$ENTRY_HEAD" != "$HOST_HEAD" ]; then
        say "git here reads HEAD $ENTRY_HEAD, but the host read $HOST_HEAD as the build"
        say "started. Either the git metadata mounted here is not this tree's, or a"
        say "commit was made in the tree just then."
        exit 1
    fi
else
    ENTRY_HEAD=""
    if [ -n "$HOST_HEAD" ]; then
        say "the host reads HEAD $HOST_HEAD, but git here cannot read the tree, so"
        say "the git metadata mounts are incomplete and the binaries would carry no"
        say "revision."
        exit 1
    fi
fi

# none: no git checkout; unreadable: git reads HEAD but not the tree's state.
tree_state() {
    git rev-parse --verify --quiet HEAD >/dev/null 2>&1 || { echo none; return 0; }
    local s
    s=$(git status --porcelain 2>/dev/null) || { echo unreadable; return 0; }
    if [ -n "$s" ]; then echo dirty; else echo clean; fi
    return 0
}

# ── The lock ────────────────────────────────────────────────────────────────
# The lock file lives in the target volume because the volume is the shared
# resource; a lock file on the host would not reach a build running under a
# private /tmp, as the builder's CI worker does. A waiting build names the one
# holding the lock. The wait is not bounded here: each caller bounds its own
# build, and a killed caller's container still runs to completion.
LOCK="$CARGO_TARGET_DIR/.fips-package-build.lock"
HOLDER="$CARGO_TARGET_DIR/.fips-package-build.holder"
exec 9>>"$LOCK"
if ! flock -n 9; then
    echo "=== Waiting for the package build already using this target volume: $(cat "$HOLDER" 2>/dev/null || echo unknown) ===" >&2
    flock 9
fi
printf '%s, since %s\n' "${FIPS_BUILD_ORIGIN:-unknown}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$HOLDER"

# The state build.rs is about to read, sampled again after packaging.
STATE_BEFORE=$(tree_state)

# ── Clean ───────────────────────────────────────────────────────────────────
# --workspace is required, not a style choice. With it, cargo resolves the
# workspace and waits on the target directory's own lock while another cargo
# process is running there; without it, `cargo clean --release` deletes files
# under a running build and fails that build.
echo "=== Cleaning the workspace crates in the target volume ===" >&2
cargo clean --release --workspace >&2

# ── Build, and check the build's report ─────────────────────────────────────
cargo_args=(build --release --locked --message-format=json-render-diagnostics)
[ -n "$FEATURES" ] && cargo_args+=(--features "$FEATURES")
MESSAGES=$(mktemp) # mount-tmpdir: inside the container, never mounted
# A package that fails a check after packaging is removed from the output
# directory, so nothing later picks it up as a good one.
PACKAGE=""
cleanup() {
    local rc=$?
    rm -f "$MESSAGES"
    if [ "$rc" -ne 0 ] && [ -n "$PACKAGE" ] && rm -f "$PACKAGE"; then
        say "removed $(basename "$PACKAGE") from the output directory, which failed a check"
    fi
}
trap cleanup EXIT
# The status is kept rather than left to set -e, so the report is checked even
# when the build fails: a root crate compiled against another tree's member
# crate fails to compile, and the check below is what names the cause.
build_rc=0
cargo "${cargo_args[@]}" >"$MESSAGES" || build_rc=$?

# Every crate built from a path must have been compiled in this build. A path
# crate is one of ours: a workspace member, or any path dependency. One that
# cargo reports as fresh came from an earlier build, of this tree or another.
path_units=$(grep -F '"reason":"compiler-artifact"' "$MESSAGES" \
    | grep -F '"package_id":"path+file://' || true)
reused=()
if [ -n "$path_units" ]; then
    mapfile -t reused < <(printf '%s\n' "$path_units" | grep -F '"fresh":true' \
        | sed -E 's/.*"package_id":"([^"]*)".*/\1/' | sort -u)
fi
if [ "${#reused[@]}" -gt 0 ]; then
    say "these crates were taken from an earlier build instead of being compiled"
    say "from this tree, so the package could hold another tree's code:"
    printf '  %s\n' "${reused[@]}" >&2
    say "the clean above removes them, so a package build that does not take the"
    say "lock on this target volume has probably run alongside this one."
    [ "$build_rc" -ne 0 ] && exit "$build_rc"
    exit 1
fi
if [ -z "$path_units" ]; then
    if [ "$build_rc" -ne 0 ]; then
        say "cargo failed before it built any crate from a path; the check for"
        say "reused crates had nothing to check."
        exit "$build_rc"
    fi
    say "cargo's build report names no crate built from a path, so whether the"
    say "workspace was compiled here cannot be told."
    exit 1
fi
[ "$build_rc" -eq 0 ] || exit "$build_rc"

uplift_hashes() {
    (cd "$CARGO_TARGET_DIR/release" && sha256sum "${BINARIES[@]}")
}
BUILT_HASHES=$(uplift_hashes) || {
    say "the build did not leave every binary the package needs in $CARGO_TARGET_DIR/release"
    exit 1
}

# ── Package ─────────────────────────────────────────────────────────────────
# Packaging runs no cargo build: the binaries checked above are the ones
# packaged. A feature build passes --built-with so build-deb.sh marks the
# version. Letting cargo-deb build again could recompile the root crate, and a
# dirty flag that changed in between would then fail the check below for the
# wrong reason.
deb_args=(--version "$VERSION" --output-dir "$DEST_DIR" --name-file "$NAME_FILE")
if [ -n "$FEATURES" ]; then
    deb_args+=(--built-with "$FEATURES")
else
    deb_args+=(--no-build)
fi
packaging/debian/build-deb.sh "${deb_args[@]}" >&2
PACKAGE="$DEST_DIR/$(head -n 1 "$NAME_FILE")"

PACKAGED_HASHES=$(uplift_hashes) || {
    say "a binary the package needs was removed from $CARGO_TARGET_DIR/release during packaging"
    exit 1
}
if [ "$PACKAGED_HASHES" != "$BUILT_HASHES" ]; then
    say "the binaries in the target volume changed between the build and packaging,"
    say "so the package may hold another build's binaries. After the build:"
    printf '  %s\n' "${BUILT_HASHES//$'\n'/$'\n'  }" >&2
    say "after packaging:"
    printf '  %s\n' "${PACKAGED_HASHES//$'\n'/$'\n'  }" >&2
    say "a package build that does not take the lock on this target volume has"
    say "probably run alongside this one."
    exit 1
fi

# ── The package's revision ──────────────────────────────────────────────────
# The dirty flag is checked only when the tree's state held for the whole
# build; ci-local writes into the tree while its suites run.
STATE_AFTER=$(tree_state)
if [ "$STATE_BEFORE" = "$STATE_AFTER" ]; then
    revision_state=$STATE_BEFORE
else
    say "the tree went from $STATE_BEFORE to $STATE_AFTER during the build, so only"
    say "the commit is checked, not the dirty flag."
    revision_state=changed
fi
bash testing/check-deb-revision.sh "$DEST_DIR/$(head -n 1 "$NAME_FILE")" \
    "$ENTRY_HEAD" "$revision_state"
