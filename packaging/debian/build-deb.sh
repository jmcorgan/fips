#!/usr/bin/env bash
# Build a .deb package for FIPS using cargo-deb.
#
# Usage: ./build-deb.sh
#
# Prerequisites: cargo-deb (install with: cargo install cargo-deb)
# Output: deploy/fips_<version>_<arch>.deb

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/../.."

cd "${PROJECT_ROOT}"

# Ensure cargo-deb is available
if ! command -v cargo-deb &>/dev/null; then
    echo "cargo-deb not found. Install with: cargo install cargo-deb" >&2
    exit 1
fi

# Derive SOURCE_DATE_EPOCH from git if not already set (reproducible builds)
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
fi

# Build the .deb package
echo "Building .deb package..."
cargo deb

# Move output to deploy/
mkdir -p deploy
DEB_FILE=$(find target/debian -name '*.deb' -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2)

if [ -z "${DEB_FILE}" ]; then
    echo "Error: No .deb file found in target/debian/" >&2
    exit 1
fi

cp "${DEB_FILE}" deploy/
BASENAME=$(basename "${DEB_FILE}")
echo "Package built: deploy/${BASENAME}"
echo ""
echo "Install with: sudo dpkg -i deploy/${BASENAME}"
echo "Remove with:  sudo dpkg -r fips"
echo "Purge with:   sudo dpkg -P fips  (removes config and identity keys)"
