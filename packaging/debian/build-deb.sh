#!/usr/bin/env bash
# Build a .deb package for FIPS using cargo-deb.
#
# Usage: ./build-deb.sh [--target <triple>] [--version <version>] [--no-build]
#                       [--features <list>]
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
  --features <list>   Cargo features to build with (comma-separated). Marks the
                      auto-derived Version so the package is distinguishable
                      from a default build of the same commit.
  -h, --help          Show this help
EOF
}

TARGET_TRIPLE=""
VERSION_OVERRIDE=""
NO_BUILD=0
FEATURES=""

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
        --features)
            FEATURES="${2:?missing value for --features}"
            shift 2
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

# A feature build that skips the build step would stamp a feature-marked Version
# onto whatever binaries already sit in target/, which is the one outcome the
# marking exists to prevent. Refuse rather than emit a package that misdescribes
# itself.
if [[ -n "${FEATURES}" && "${NO_BUILD}" -eq 1 ]]; then
    echo "--features cannot be combined with --no-build: the features would not" >&2
    echo "reach the binaries, but the Version would claim they had." >&2
    exit 1
fi

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
        # A feature build of a given commit is a different package from the
        # default build of that same commit, but nothing else in this version
        # says so: the crate version, the date and the sha are all identical.
        # Without a marker the two are byte-identical versions, so installing
        # one over the other is an apt no-op (the very failure the per-commit
        # version above exists to prevent) and the node offers no way to tell
        # which one it is running. Underscores and commas are not legal in a
        # Debian version, so the feature list is folded to dots.
        FEATURE_SUFFIX=""
        if [[ -n "${FEATURES}" ]]; then
            FEATURE_SUFFIX="+$(printf '%s' "${FEATURES}" | tr -c 'a-zA-Z0-9.' '.')"
        fi
        # Debian Version: <upstream>~dev+git<YYYYMMDD>.<sha>[.dirty][+<features>]-1
        # The "~" makes every dev build sort BEFORE the eventual tagged
        # release; the date+sha makes consecutive dev builds compare as
        # different versions; the trailing "-1" is the Debian revision.
        # The feature suffix sorts ABOVE the unsuffixed build, so installing a
        # feature build is an upgrade and reverting to the default build is a
        # downgrade — which apt refuses without being told to, and `dpkg -i`
        # performs. Revert with `dpkg -i`, not `apt install`.
        VERSION_OVERRIDE="${BASE_VERSION}~dev+git${GIT_DATE}.${GIT_SHA}${DIRTY_SUFFIX}${FEATURE_SUFFIX}-1"
        echo "Auto-derived dev Version: ${VERSION_OVERRIDE}"
    fi
elif [[ -n "${FEATURES}" ]]; then
    echo "Warning: --version was given with --features, so the Version carries no" >&2
    echo "feature marker and this package is indistinguishable from a default" >&2
    echo "build of the same commit. Mark it yourself if that matters." >&2
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
if [[ -n "${FEATURES}" ]]; then
    cargo_args+=(--features "${FEATURES}")
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
