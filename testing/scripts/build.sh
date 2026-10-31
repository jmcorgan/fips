#!/bin/bash
# Build FIPS binaries and the unified test Docker image.
#
# The binaries are the integration build: the release settings under the
# `integration` cargo profile, with the `test-overrides` feature that honours
# test-only configuration keys, built in target/integration rather than
# target/release so that no package script can pick one up.
#
# Supports cross-compilation from macOS to Linux using cargo-zigbuild.
#
# Usage: ./build.sh [--no-docker]
#   --no-docker  Skip Docker image build (just compile and copy binaries)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTING_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKER_DIR="$TESTING_DIR/docker"

# Find project root (directory containing Cargo.toml)
PROJECT_ROOT="$(cd "$TESTING_DIR/.." && pwd)"
if [ ! -f "$PROJECT_ROOT/Cargo.toml" ]; then
    echo "Error: Cannot find Cargo.toml at $PROJECT_ROOT" >&2
    exit 1
fi

BUILD_DOCKER=true
# Extra flags for the container-image cargo build. Empty by default: every
# subsystem is governed by platform cfg gates, and the profile and the
# `test-overrides` feature are fixed on the cargo command lines below, so
# FIPS_CARGO_BUILD_ARGS adds to them rather than replacing them.
DEFAULT_CARGO_BUILD_ARGS=()
if [ -n "${FIPS_CARGO_BUILD_ARGS:-}" ]; then
    # shellcheck disable=SC2206
    CARGO_BUILD_ARGS=($FIPS_CARGO_BUILD_ARGS)
else
    CARGO_BUILD_ARGS=("${DEFAULT_CARGO_BUILD_ARGS[@]}")
fi
while [ $# -gt 0 ]; do
    case "$1" in
        --no-docker) BUILD_DOCKER=false; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Detect host OS
UNAME_S=$(uname -s)
CARGO_TARGET="x86_64-unknown-linux-musl"

TARGET_ROOT="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"

# A target directory outside this checkout may be shared with another checkout.
# Cargo fingerprints a workspace crate relative to the workspace root and judges
# it by file modification times, so a checkout whose files are older than
# another checkout's last build in that directory compiles nothing, and the
# binaries copied below are the other checkout's. A directory outside the tree
# that only this checkout uses is fine, and nothing here can tell the two
# apart, so this warns rather than refuses. A path that names a place inside
# the checkout is accepted even when a symlink there leads outside it: that
# link is the checkout's own, as iperf-compare-refs.sh makes one per ref.
warn_shared_target() {
    local dir="$1" abs root head="$1" tail=""
    case "$dir" in
        /*) abs="$dir" ;;
        *) abs="$PWD/$dir" ;;
    esac
    case "$abs/" in
        */../*|*/./*) ;;
        "$PROJECT_ROOT"/*) return 0 ;;
    esac
    root="$(cd "$PROJECT_ROOT" && pwd -P)"
    # Resolve the deepest part of the path that exists, since cargo creates
    # the rest.
    while [ ! -d "$head" ] && [ "$head" != "$(dirname "$head")" ]; do
        tail="/$(basename "$head")$tail"
        head="$(dirname "$head")"
    done
    abs="$(cd "$head" && pwd -P)$tail"
    case "$abs/" in
        "$root"/*) return 0 ;;
    esac
    echo "Warning: CARGO_TARGET_DIR ($dir) is outside this checkout. If another" >&2
    echo "checkout also builds there, this build can reuse that checkout's crates" >&2
    echo "and put its binaries in the test image. Unset it, or give each checkout" >&2
    echo "its own directory." >&2
    return 0
}
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    warn_shared_target "$CARGO_TARGET_DIR"
fi

if [ "$UNAME_S" = "Darwin" ]; then
    echo "Detected macOS host — using cross-compilation for Linux..."

    if ! command -v cargo-zigbuild &> /dev/null; then
        echo "Error: cargo-zigbuild not found." >&2
        echo "Please install it: cargo install cargo-zigbuild" >&2
        exit 1
    fi

    if ! rustup target list --installed | grep -q "$CARGO_TARGET"; then
        echo "Installing Rust target $CARGO_TARGET..."
        rustup target add "$CARGO_TARGET"
    fi

    echo "Building FIPS for Linux (integration build) using cargo-zigbuild..."
    cargo zigbuild --profile integration --features test-overrides --bins --examples --target "$CARGO_TARGET" --manifest-path="$PROJECT_ROOT/Cargo.toml" "${CARGO_BUILD_ARGS[@]}"

    TARGET_DIR="$TARGET_ROOT/$CARGO_TARGET/integration"
else
    echo "Building FIPS (integration build)..."
    cargo build --profile integration --features test-overrides --bins --examples --manifest-path="$PROJECT_ROOT/Cargo.toml" "${CARGO_BUILD_ARGS[@]}"

    TARGET_DIR="$TARGET_ROOT/integration"
fi

# --bins --examples above rather than the bare default: the native datagram
# API's example programs are cargo examples, and the shared image carries them.
# Naming --bins keeps the daemon and its tools, which --examples alone would drop.
echo "Copying binaries to $DOCKER_DIR/"
cp "$TARGET_DIR/fips" "$DOCKER_DIR/fips"
cp "$TARGET_DIR/fipsctl" "$DOCKER_DIR/fipsctl"
cp "$TARGET_DIR/fips-gateway" "$DOCKER_DIR/fips-gateway"
[ -f "$TARGET_DIR/fipstop" ] && cp "$TARGET_DIR/fipstop" "$DOCKER_DIR/fipstop" || true
# Not optional: the Dockerfile COPYs both native API examples unconditionally,
# so a missing one must fail here, where the cause is legible, rather than
# inside docker build.
cp "$TARGET_DIR/examples/native-echo" "$DOCKER_DIR/native-echo"
cp "$TARGET_DIR/examples/native-surface" "$DOCKER_DIR/native-surface"
chmod +x "$DOCKER_DIR/fips" "$DOCKER_DIR/fipsctl" "$DOCKER_DIR/fips-gateway" \
    "$DOCKER_DIR/native-echo" "$DOCKER_DIR/native-surface"
[ -f "$DOCKER_DIR/fipstop" ] && chmod +x "$DOCKER_DIR/fipstop" || true

echo "Done. Binaries at $DOCKER_DIR/{fips,fipsctl,fipstop,fips-gateway,native-echo,native-surface}"

if [ "$BUILD_DOCKER" = true ]; then
    echo ""
    echo "Building Docker images..."
    docker build -t fips-test:latest "$DOCKER_DIR"
    docker build -t fips-test-app:latest -f "$DOCKER_DIR/Dockerfile.app" "$DOCKER_DIR"
    echo "Done. Images: fips-test:latest, fips-test-app:latest"
fi
