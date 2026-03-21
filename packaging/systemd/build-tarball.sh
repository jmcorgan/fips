#!/usr/bin/env bash
# Build FIPS release binaries and create an install tarball.
#
# Usage: ./packaging/build-tarball.sh
# Output: deploy/fips-<version>-linux-<arch>.tar.gz

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PACKAGING_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROJECT_ROOT="$(cd "${PACKAGING_DIR}/.." && pwd)"

# Extract version from Cargo.toml
VERSION=$(grep '^version' "${PROJECT_ROOT}/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')
ARCH=$(uname -m)
TARBALL_NAME="fips-${VERSION}-linux-${ARCH}"
DEPLOY_DIR="${PROJECT_ROOT}/deploy"
STAGING_DIR="${DEPLOY_DIR}/${TARBALL_NAME}"

echo "Building FIPS v${VERSION} for ${ARCH}..."

# Build release binaries (tui is a default feature, includes fipstop)
cargo build --release --manifest-path="${PROJECT_ROOT}/Cargo.toml"

# Create staging directory
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}"

# Copy binaries
cp "${PROJECT_ROOT}/target/release/fips" "${STAGING_DIR}/"
cp "${PROJECT_ROOT}/target/release/fipsctl" "${STAGING_DIR}/"
cp "${PROJECT_ROOT}/target/release/fipstop" "${STAGING_DIR}/"

# Strip binaries to reduce size
strip "${STAGING_DIR}/fips" "${STAGING_DIR}/fipsctl" "${STAGING_DIR}/fipstop"

# Copy packaging files
cp "${SCRIPT_DIR}/install.sh" "${STAGING_DIR}/"
cp "${SCRIPT_DIR}/uninstall.sh" "${STAGING_DIR}/"
cp "${SCRIPT_DIR}/fips.service" "${STAGING_DIR}/"
cp "${SCRIPT_DIR}/fips-dns.service" "${STAGING_DIR}/"
cp "${PACKAGING_DIR}/common/fips.yaml" "${STAGING_DIR}/"
cp "${PACKAGING_DIR}/common/hosts" "${STAGING_DIR}/"
cp "${SCRIPT_DIR}/README.install.md" "${STAGING_DIR}/"

chmod +x "${STAGING_DIR}/install.sh" "${STAGING_DIR}/uninstall.sh"

# Create tarball (reproducible: normalize timestamps and ownership)
cd "${DEPLOY_DIR}"
TAR_REPRO_FLAGS=""
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    TAR_REPRO_FLAGS="--mtime=@${SOURCE_DATE_EPOCH}"
fi
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
    TAR_REPRO_FLAGS="${TAR_REPRO_FLAGS} --numeric-owner --owner=0 --group=0"
fi
COPYFILE_DISABLE=1 tar ${TAR_REPRO_FLAGS} -czf "${TARBALL_NAME}.tar.gz" "${TARBALL_NAME}/"
rm -rf "${STAGING_DIR}"

echo ""
echo "Tarball created: deploy/${TARBALL_NAME}.tar.gz"
ls -lh "${TARBALL_NAME}.tar.gz"
