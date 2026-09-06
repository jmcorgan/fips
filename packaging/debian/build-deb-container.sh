#!/bin/bash
# Build the Debian package in the pinned build container, then check its floor.
#
# This is the one place the Linux artifacts are produced. The release workflow,
# the CI integration job and a local run all call it, so all three build the
# same way and a package that passes locally is the package that ships. That was
# not true before: the test suite built its own package inside a Debian 12 image
# while the release built on the newest GitHub runner, so the suite could not
# exhibit a defect that only the release environment produced -- and for five
# releases it did not.
#
# Usage: build-deb-container.sh [--output-dir DIR] [--version V] [--features LIST]
#                               [--rebuild-image]
#
# Requires docker. The image is cached between runs and rebuilt only when the
# Dockerfile or the floor changes; the source is mounted rather than copied, so
# editing code does not invalidate it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=../build-floor.env
. "$REPO_ROOT/packaging/build-floor.env"

DEST_DIR="$REPO_ROOT/deploy"
VERSION=""
FEATURES=""
REBUILD_IMAGE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)    DEST_DIR="${2:?missing value for --output-dir}"; shift 2 ;;
        --version)       VERSION="${2:?missing value for --version}"; shift 2 ;;
        --features)      FEATURES="${2:?missing value for --features}"; shift 2 ;;
        --rebuild-image) REBUILD_IMAGE=1; shift ;;
        -h|--help)       sed -n '2,17p' "$0"; exit 0 ;;
        *)               echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

command -v docker >/dev/null 2>&1 || {
    echo "build-deb-container: docker is required and was not found." >&2
    exit 2
}

# Read the toolchain from the pin rather than choosing one here, and put it in
# the tag so a bump rebuilds the image instead of silently reusing a stale one.
RUST_TOOLCHAIN=$(awk -F'"' '/^channel *=/{print $2; exit}' "$REPO_ROOT/rust-toolchain.toml")
[ -n "$RUST_TOOLCHAIN" ] || {
    echo "build-deb-container: could not read channel from rust-toolchain.toml" >&2
    exit 2
}

IMAGE_TAG="fips-deb-builder:${FIPS_BUILD_IMAGE//[:\/]/-}-rust${RUST_TOOLCHAIN}"

if [ "$REBUILD_IMAGE" -eq 1 ] || ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
    echo "=== Building $IMAGE_TAG from $FIPS_BUILD_IMAGE with Rust $RUST_TOOLCHAIN ===" >&2
    docker build \
        --build-arg "BASE=$FIPS_BUILD_IMAGE" \
        --build-arg "RUST_TOOLCHAIN=$RUST_TOOLCHAIN" \
        -t "$IMAGE_TAG" \
        -f "$SCRIPT_DIR/Dockerfile.build" \
        "$SCRIPT_DIR"
else
    echo "=== Using cached $IMAGE_TAG ===" >&2
fi

# Derive the version and the timestamp on the host, where git works, and pass
# both in. The container then never runs git, which matters for two reasons: a
# worktree's .git is a file pointing outside the mount and would not resolve,
# and a bind-mounted repository trips git's dubious-ownership check.
if [ -z "$VERSION" ]; then
    CRATE_VERSION=$(awk -F'"' '/^version = /{print $2; exit}' "$REPO_ROOT/Cargo.toml")
    if [[ "$CRATE_VERSION" == *-dev ]]; then
        GIT_DATE=$(git -C "$REPO_ROOT" log -1 --format=%cs | tr -d '-')
        GIT_SHA=$(git -C "$REPO_ROOT" rev-parse --short HEAD)
        DIRTY=""
        [ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ] && DIRTY=".dirty"
        VERSION="${CRATE_VERSION%-dev}~dev+git${GIT_DATE}.${GIT_SHA}${DIRTY}-1"
    else
        VERSION="$CRATE_VERSION"
    fi
fi
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" log -1 --format=%ct)}"

mkdir -p "$DEST_DIR"
DEST_ABS="$(cd "$DEST_DIR" && pwd)"

echo "=== Building fips $VERSION in $IMAGE_TAG ===" >&2

# A feature build hands the whole job to build-deb.sh rather than pre-building:
# --features has to reach cargo, and build-deb.sh is also what marks the version
# so a feature package is distinguishable from the default build of the same
# commit. It refuses --features with --no-build for exactly that reason, so the
# two cases cannot share one command.
if [ -n "$FEATURES" ]; then
    # build-deb.sh does the whole job here: --features has to reach cargo, and
    # it is also what marks the version so a feature package is distinguishable
    # from the default build of the same commit. It refuses --features with
    # --no-build for that reason, so the two cases cannot share one command.
    # The version still comes from the host, because the image has no git.
    BUILD_CMD="packaging/debian/build-deb.sh --features '$FEATURES' --version '$VERSION' --output-dir /out"
else
    BUILD_CMD="cargo build --release --locked
        packaging/debian/build-deb.sh --no-build --version '$VERSION' --output-dir /out"
fi

# The source is mounted read-only so a build cannot leave artifacts in the tree.
# CARGO_TARGET_DIR and the registry live in named volumes, which is what makes a
# second run fast; they are per-base-image so a floor change does not reuse
# objects linked against the wrong C library.
VOL_SUFFIX="${FIPS_BUILD_IMAGE//[:\/]/-}"
docker run --rm \
    -v "$REPO_ROOT":/src:ro \
    -v "$DEST_ABS":/out \
    -v "fips-deb-target-${VOL_SUFFIX}":/target \
    -v "fips-deb-registry-${VOL_SUFFIX}":/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR=/target \
    -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    -w /src \
    "$IMAGE_TAG" \
    bash -euo pipefail -c "$BUILD_CMD" >&2

DEB=$(find "$DEST_ABS" -maxdepth 1 -name "fips_*_*.deb" -newermt '-10 minutes' -print | sort | tail -1)
[ -n "$DEB" ] || { echo "build-deb-container: no .deb was produced." >&2; exit 1; }

# Check the artifact here rather than in one workflow, so every producer is
# gated: the release, the CI job, a local run and packaging/Makefile all reach
# the check through this script.
"$REPO_ROOT/testing/check-glibc-floor.sh" "$DEB" >&2

echo "=== Built $DEB ===" >&2
printf '%s\n' "$DEB"
