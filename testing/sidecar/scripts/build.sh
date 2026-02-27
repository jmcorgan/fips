#!/bin/bash
# Build the FIPS binary and Docker sidecar image.
# Usage: ./build.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Find project root (directory containing Cargo.toml)
PROJECT_ROOT="$(cd "$DOCKER_DIR/../.." && pwd)"
if [ ! -f "$PROJECT_ROOT/Cargo.toml" ]; then
    echo "Error: Cannot find Cargo.toml at $PROJECT_ROOT" >&2
    echo "Expected layout: <project-root>/testing/sidecar/scripts/build.sh" >&2
    exit 1
fi

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

    echo "Copying binaries to docker context..."
    cp "$PROJECT_ROOT/target/$CARGO_TARGET/release/fips" "$DOCKER_DIR/fips"
    cp "$PROJECT_ROOT/target/$CARGO_TARGET/release/fipsctl" "$DOCKER_DIR/fipsctl"
else
    echo "Building FIPS (release)..."
    cargo build --release --manifest-path="$PROJECT_ROOT/Cargo.toml"

    echo "Copying binaries to docker context..."
    cp "$PROJECT_ROOT/target/release/fips" "$DOCKER_DIR/fips"
    cp "$PROJECT_ROOT/target/release/fipsctl" "$DOCKER_DIR/fipsctl"
fi

echo "Done. Binaries at $DOCKER_DIR/{fips,fipsctl}"
echo ""
echo "Building Docker image..."
docker compose -f "$DOCKER_DIR/docker-compose.yml" build
echo ""
echo "Ready: cd testing/sidecar && docker compose up -d"
