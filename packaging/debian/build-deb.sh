#!/usr/bin/env bash
# Build a .deb package for FIPS using cargo-deb.
#
# Usage: ./build-deb.sh [--target <triple>] [--version <version>] [--no-build]
#
# Prerequisites: cargo-deb (install with: cargo install cargo-deb)
# Output: deploy/fips_<version>_<arch>.deb

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/../.."

usage() {
    cat <<'EOF'
Usage: packaging/debian/build-deb.sh [options]

Options:
  --target <triple>   Rust target triple to build/package
  --version <version> Override Debian package version
  --no-build          Package existing binaries without running cargo build
  -h, --help          Show this help
EOF
}

TARGET_TRIPLE=""
VERSION_OVERRIDE=""
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

# Auto-derive a per-commit Debian Version for dev builds so apt-based
# upgrade detection (`ansible.builtin.apt: deb:`, `apt install ./*.deb`)
# does not silently no-op when one dev .deb is installed on top of another.
# Tagged release builds (Cargo.toml version without "-dev") keep the
# clean upstream version. Operator override via --version still wins.
if [[ -z "${VERSION_OVERRIDE}" ]]; then
    CRATE_VERSION=$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)
    if [[ "${CRATE_VERSION}" == *-dev ]]; then
        BASE_VERSION="${CRATE_VERSION%-dev}"
        GIT_DATE=$(git log -1 --format=%cs | tr -d '-')
        GIT_SHA=$(git rev-parse --short HEAD)
        DIRTY_SUFFIX=""
        if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
            DIRTY_SUFFIX=".dirty"
        fi
        # Debian Version: <upstream>~dev+git<YYYYMMDD>.<sha>[.dirty]-1
        # The "~" makes every dev build sort BEFORE the eventual tagged
        # release; the date+sha makes consecutive dev builds compare as
        # different versions; the trailing "-1" is the Debian revision.
        VERSION_OVERRIDE="${BASE_VERSION}~dev+git${GIT_DATE}.${GIT_SHA}${DIRTY_SUFFIX}-1"
        echo "Auto-derived dev Version: ${VERSION_OVERRIDE}"
    fi
fi

# Build the .deb package
echo "Building .deb package..."
OUTPUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUTPUT_DIR}"' EXIT

cargo_args=(deb --output "${OUTPUT_DIR}")
if [[ -n "${TARGET_TRIPLE}" ]]; then
    cargo_args+=(--target "${TARGET_TRIPLE}")
fi
if [[ -n "${VERSION_OVERRIDE}" ]]; then
    cargo_args+=(--deb-version "${VERSION_OVERRIDE}")
fi
if [[ "${NO_BUILD}" -eq 1 ]]; then
    cargo_args+=(--no-build)
fi
cargo "${cargo_args[@]}"

# Move output to deploy/
mkdir -p deploy
DEB_FILE=$(find "${OUTPUT_DIR}" -maxdepth 1 -name '*.deb' -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2)

if [ -z "${DEB_FILE}" ]; then
    echo "Error: No .deb file found in ${OUTPUT_DIR}" >&2
    exit 1
fi

cp "${DEB_FILE}" deploy/
BASENAME=$(basename "${DEB_FILE}")
echo "Package built: deploy/${BASENAME}"
echo ""
echo "Install with: sudo dpkg -i deploy/${BASENAME}"
echo "Remove with:  sudo dpkg -r fips"
echo "Purge with:   sudo dpkg -P fips  (removes config and identity keys)"
