#!/bin/bash
# Build the FIPS binary and copy it to the docker build context.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Find project root (directory containing Cargo.toml)
PROJECT_ROOT="$(cd "$DOCKER_DIR/../.." && pwd)"
if [ ! -f "$PROJECT_ROOT/Cargo.toml" ]; then
    echo "Error: Cannot find Cargo.toml at $PROJECT_ROOT" >&2
    echo "Expected layout: <project-root>/examples/docker-network/scripts/build.sh" >&2
    exit 1
fi

echo "Building FIPS (release)..."
cargo build --release --manifest-path="$PROJECT_ROOT/Cargo.toml"

echo "Copying binary to docker context..."
cp "$PROJECT_ROOT/target/release/fips" "$DOCKER_DIR/fips"

echo "Done. Binary at $DOCKER_DIR/fips"
echo ""
echo "Next: cd $DOCKER_DIR && docker compose --profile mesh build"
