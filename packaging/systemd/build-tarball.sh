#!/usr/bin/env bash
# Build FIPS release binaries and create an install tarball.
#
# Usage: ./packaging/build-tarball.sh [--target <triple>] [--version <version>] [--arch <arch>] [--no-build]
# Output: deploy/fips-<version>-linux-<arch>.tar.gz

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PACKAGING_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROJECT_ROOT="$(cd "${PACKAGING_DIR}/.." && pwd)"

usage() {
    cat <<'EOF'
Usage: packaging/systemd/build-tarball.sh [options]

Options:
  --target <triple>   Rust target triple to build/package
  --version <version> Override artifact version
  --arch <arch>       Override artifact architecture name
  --no-build          Package existing binaries without running cargo build
  -h, --help          Show this help
EOF
}

target_to_arch() {
    local target="$1"
    printf '%s\n' "${target%%-*}"
}

VERSION_OVERRIDE=""
TARGET_TRIPLE=""
ARCH_OVERRIDE=""
NO_BUILD=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET_TRIPLE="${2:?missing value for --target}"
            shift 2
            ;;
        --version)
            VERSION_OVERRIDE="${2:?missing value for --version}"
            shift 2
            ;;
        --arch)
            ARCH_OVERRIDE="${2:?missing value for --arch}"
            shift 2
            ;;
        --no-build)
            NO_BUILD=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

VERSION="${VERSION_OVERRIDE:-$(grep '^version' "${PROJECT_ROOT}/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')}"
if [[ -n "${ARCH_OVERRIDE}" ]]; then
    ARCH="${ARCH_OVERRIDE}"
elif [[ -n "${TARGET_TRIPLE}" ]]; then
    ARCH="$(target_to_arch "${TARGET_TRIPLE}")"
else
    ARCH="$(uname -m)"
fi
TARBALL_NAME="fips-${VERSION}-linux-${ARCH}"
DEPLOY_DIR="${PROJECT_ROOT}/deploy"
STAGING_DIR="${DEPLOY_DIR}/${TARBALL_NAME}"
STRIP_BIN="${STRIP:-strip}"

if [[ -n "${TARGET_TRIPLE}" ]]; then
    BINARY_DIR="${PROJECT_ROOT}/target/${TARGET_TRIPLE}/release"
else
    BINARY_DIR="${PROJECT_ROOT}/target/release"
fi

echo "Building FIPS v${VERSION} for ${ARCH}..."

# Build release binaries (tui is a default feature, includes fipstop)
if [[ "${NO_BUILD}" -eq 0 ]]; then
    cargo_args=(build --release --manifest-path="${PROJECT_ROOT}/Cargo.toml")
    if [[ -n "${TARGET_TRIPLE}" ]]; then
        cargo_args+=(--target "${TARGET_TRIPLE}")
    fi
    cargo "${cargo_args[@]}"
fi

# Create staging directory
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}"

# Copy binaries
for bin in fips fipsctl fipstop; do
    if [[ ! -f "${BINARY_DIR}/${bin}" ]]; then
        echo "Missing binary: ${BINARY_DIR}/${bin}" >&2
        exit 1
    fi
    cp "${BINARY_DIR}/${bin}" "${STAGING_DIR}/"
done

# Strip binaries to reduce size
if ! command -v "${STRIP_BIN}" &>/dev/null; then
    echo "Strip tool not found: ${STRIP_BIN}" >&2
    exit 1
fi
"${STRIP_BIN}" "${STAGING_DIR}/fips" "${STAGING_DIR}/fipsctl" "${STAGING_DIR}/fipstop"

# Copy packaging files
cp "${SCRIPT_DIR}/install.sh" "${STAGING_DIR}/"
cp "${SCRIPT_DIR}/uninstall.sh" "${STAGING_DIR}/"
cp "${SCRIPT_DIR}/fips.service" "${STAGING_DIR}/"
cp "${SCRIPT_DIR}/fips-dns.service" "${STAGING_DIR}/"
cp "${PACKAGING_DIR}/common/fips.yaml" "${STAGING_DIR}/"
cp "${PACKAGING_DIR}/common/hosts" "${STAGING_DIR}/"
cp "${SCRIPT_DIR}/README.install.md" "${STAGING_DIR}/"

chmod +x "${STAGING_DIR}/install.sh" "${STAGING_DIR}/uninstall.sh"

# Create tarball (reproducible: normalize timestamps, ownership, and sort order)
cd "${DEPLOY_DIR}"

# Default SOURCE_DATE_EPOCH to git commit timestamp if not set
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git -C "${PROJECT_ROOT}" log -1 --format=%ct)
    export SOURCE_DATE_EPOCH
fi

TAR_REPRO_FLAGS="--mtime=@${SOURCE_DATE_EPOCH} --sort=name"
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
    TAR_REPRO_FLAGS="${TAR_REPRO_FLAGS} --numeric-owner --owner=0 --group=0"
fi
COPYFILE_DISABLE=1 tar ${TAR_REPRO_FLAGS} -czf "${TARBALL_NAME}.tar.gz" "${TARBALL_NAME}/"
rm -rf "${STAGING_DIR}"

echo ""
echo "Tarball created: deploy/${TARBALL_NAME}.tar.gz"
ls -lh "${TARBALL_NAME}.tar.gz"
