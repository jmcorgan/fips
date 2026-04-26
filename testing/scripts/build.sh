#!/bin/bash
# Build FIPS binaries and the unified test Docker image.
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
while [ $# -gt 0 ]; do
    case "$1" in
        --no-docker) BUILD_DOCKER=false; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Detect host OS
UNAME_S=$(uname -s)
CARGO_TARGET="x86_64-unknown-linux-musl"

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

    echo "Building FIPS for Linux (release) using cargo-zigbuild..."
    cargo zigbuild --release --target "$CARGO_TARGET" --manifest-path="$PROJECT_ROOT/Cargo.toml"

    TARGET_DIR="$PROJECT_ROOT/target/$CARGO_TARGET/release"
else
    echo "Building FIPS (release)..."
    cargo build --release --manifest-path="$PROJECT_ROOT/Cargo.toml"

    TARGET_DIR="$PROJECT_ROOT/target/release"
fi

echo "Copying binaries to $DOCKER_DIR/"
cp "$TARGET_DIR/fips" "$DOCKER_DIR/fips"
cp "$TARGET_DIR/fipsctl" "$DOCKER_DIR/fipsctl"
cp "$TARGET_DIR/fips-gateway" "$DOCKER_DIR/fips-gateway"
[ -f "$TARGET_DIR/fipstop" ] && cp "$TARGET_DIR/fipstop" "$DOCKER_DIR/fipstop" || true
chmod +x "$DOCKER_DIR/fips" "$DOCKER_DIR/fipsctl" "$DOCKER_DIR/fips-gateway"
[ -f "$DOCKER_DIR/fipstop" ] && chmod +x "$DOCKER_DIR/fipstop" || true

echo "Done. Binaries at $DOCKER_DIR/{fips,fipsctl,fipstop,fips-gateway}"

if [ "$BUILD_DOCKER" = true ]; then
    echo ""
    echo "Building Docker images..."
    docker build -t fips-test:latest "$DOCKER_DIR"
    docker build -t fips-test-app:latest -f "$DOCKER_DIR/Dockerfile.app" "$DOCKER_DIR"
    echo "Done. Images: fips-test:latest, fips-test-app:latest"
fi
