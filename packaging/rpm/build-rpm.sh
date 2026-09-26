#!/usr/bin/env bash
# Build an .rpm package for FIPS.
#
# The counterpart of packaging/debian/build-deb.sh, and deliberately the same
# shape: the same options, the same dev-version derivation, the same output in
# deploy/. cargo-deb builds the binaries itself; here cargo builds them and
# rpmbuild packages what it produced, so one cargo invocation stays the only
# thing that compiles FIPS.
#
# Usage: ./build-rpm.sh [--target <triple>] [--version <version>] [--no-build]
#                       [--features <list>] [--output-dir <dir>]
#                       [--name-file <path>] [--bin-dir <dir>]
#
# Prerequisites: rpm-build and systemd-rpm-macros.
# Output: deploy/fips-mesh-<version>-<release>.<arch>.rpm
#
# "fips-mesh", not "fips": Fedora's namespace has a `fips` package already (an
# unrelated FITS image viewer), and ours would look like an old version of it.
# See the header of fips.spec.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SPEC="${SCRIPT_DIR}/fips.spec"

usage() {
    cat <<'EOF'
Usage: packaging/rpm/build-rpm.sh [options]

Options:
  --target <triple>   Rust target triple to build/package
  --version <version> Override the RPM Version-Release. Accepts either
                      "<version>" or "<version>-<release>".
  --no-build          Package existing binaries without running cargo build
  --features <list>   Cargo features to build with (comma-separated). Marks the
                      auto-derived Release so the package is distinguishable
                      from a default build of the same commit.
  --output-dir <dir>  Where to put the finished .rpm. Defaults to deploy/ under
                      the project root.

Environment:
  HOST_UID, HOST_GID  Give the finished package to this owner. Set by a
                      container build, whose root would otherwise leave a file
                      on the mounted tree that its owner cannot remove.
  --name-file <path>  Also write the finished package's file name (basename
                      only) to <path>.
  --bin-dir <dir>     Package the binaries in <dir> rather than the ones under
                      target/. Implies --no-build. This is how the container
                      build packages binaries compiled somewhere else.
  -h, --help          Show this help
EOF
}

TARGET_TRIPLE=""
VERSION_OVERRIDE=""
BIN_DIR_OVERRIDE=""
NO_BUILD=0
FEATURES=""
DEST_DIR=""
NAME_FILE=""

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
        --output-dir)
            DEST_DIR="${2:?missing value for --output-dir}"
            shift 2
            ;;
        --name-file)
            NAME_FILE="${2:?missing value for --name-file}"
            shift 2
            ;;
        --bin-dir)
            BIN_DIR_OVERRIDE="${2:?missing value for --bin-dir}"
            NO_BUILD=1
            shift 2
            ;;
        -h | --help)
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

# Same refusal as the Debian build, for the same reason: a feature build that
# skips the build step would stamp a feature-marked Release onto whatever
# binaries already sit in target/, which is the one outcome the marking exists
# to prevent.
if [[ -n "${FEATURES}" && "${NO_BUILD}" -eq 1 ]]; then
    echo "--features cannot be combined with --no-build: the features would not" >&2
    echo "reach the binaries, but the Release would claim they had." >&2
    exit 1
fi

cd "${PROJECT_ROOT}"

if ! command -v rpmbuild &>/dev/null; then
    echo "rpmbuild not found. Install the rpm-build package." >&2
    exit 1
fi

# Reproducible builds, as on the Debian side.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
    export SOURCE_DATE_EPOCH
fi

CRATE_VERSION=$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)

if [[ -n "${VERSION_OVERRIDE}" ]]; then
    # Accept "<version>" or "<version>-<release>".
    RPM_VERSION="${VERSION_OVERRIDE%%-*}"
    if [[ "${VERSION_OVERRIDE}" == *-* ]]; then
        RPM_RELEASE="${VERSION_OVERRIDE#*-}"
    else
        RPM_RELEASE="1"
    fi
elif [[ "${CRATE_VERSION}" == *-dev ]]; then
    # A dev build gets a Release that sorts BELOW the eventual tagged release
    # and differs between commits, so `dnf upgrade` on one dev package
    # installed over another is not a silent no-op. rpm has understood "~"
    # since 4.10 and the Debian version uses it; a Release beginning with 0. is
    # the convention for pre-release packages here and is what this picks.
    RPM_VERSION="${CRATE_VERSION%-dev}"
    GIT_DATE=$(git log -1 --format=%cs | tr -d '-')
    GIT_SHA=$(git rev-parse --short HEAD)
    RPM_RELEASE="0.dev.git${GIT_DATE}.${GIT_SHA}"
    if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
        RPM_RELEASE="${RPM_RELEASE}.dirty"
    fi
    # A feature build of a commit is a different package from the default
    # build of the same commit, and nothing else in the version says so. The
    # suffix sorts above the unsuffixed build, so installing a feature build
    # is an upgrade and going back is a downgrade — which dnf refuses unless
    # told; use `dnf downgrade` or `rpm -U --oldpackage`.
    if [[ -n "${FEATURES}" ]]; then
        RPM_RELEASE="${RPM_RELEASE}.features.$(printf '%s' "${FEATURES}" | tr -c 'a-zA-Z0-9.' '.')"
    fi
    echo "Auto-derived dev Version-Release: ${RPM_VERSION}-${RPM_RELEASE}"
else
    RPM_VERSION="${CRATE_VERSION}"
    RPM_RELEASE="1"
fi

# Build the binaries, unless we were told they are already there.
if [[ "${NO_BUILD}" -eq 0 ]]; then
    cargo_args=(build --release)
    [[ -n "${TARGET_TRIPLE}" ]] && cargo_args+=(--target "${TARGET_TRIPLE}")
    [[ -n "${FEATURES}" ]] && cargo_args+=(--features "${FEATURES}")
    echo "Building binaries..."
    cargo "${cargo_args[@]}"
fi

if [[ -n "${BIN_DIR_OVERRIDE}" ]]; then
    BIN_DIR="$(cd "${BIN_DIR_OVERRIDE}" && pwd)"
    RPM_ARCH="$(rpm --eval '%{_target_cpu}')"
elif [[ -n "${TARGET_TRIPLE}" ]]; then
    BIN_DIR="${PROJECT_ROOT}/target/${TARGET_TRIPLE}/release"
    # rpm names architectures its own way; map the ones we cross-build for.
    case "${TARGET_TRIPLE}" in
        x86_64-*) RPM_ARCH="x86_64" ;;
        aarch64-*) RPM_ARCH="aarch64" ;;
        armv7-*) RPM_ARCH="armv7hl" ;;
        riscv64-*) RPM_ARCH="riscv64" ;;
        *)
            echo "Unknown target triple for rpm: ${TARGET_TRIPLE}" >&2
            echo "Add it to the case in $(basename "$0")." >&2
            exit 1
            ;;
    esac
else
    BIN_DIR="${PROJECT_ROOT}/target/release"
    RPM_ARCH="$(rpm --eval '%{_target_cpu}')"
fi

for binary in fips fipsctl fipstop fips-gateway; do
    if [[ ! -x "${BIN_DIR}/${binary}" ]]; then
        echo "Missing ${BIN_DIR}/${binary}." >&2
        [[ "${NO_BUILD}" -eq 1 ]] && echo "Drop --no-build, or build first." >&2
        exit 1
    fi
done

TOP_DIR="$(mktemp -d)"
trap 'rm -rf "${TOP_DIR}"' EXIT
mkdir -p "${TOP_DIR}"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

echo "Building .rpm package..."
# The Release carries no %{dist} tag. A dist tag says which distribution's
# build of a package this is, and there is one build: the same glibc binaries
# the .deb and the tarball ship, packaged. Leaving it in would name whichever
# image or host happened to run rpmbuild (.el9 from the release build, .fc44
# from a developer's) in an artifact that installs on all of them.
rpmbuild -bb "${SPEC}" \
    --target "${RPM_ARCH}" \
    --define "dist %{nil}" \
    --define "_topdir ${TOP_DIR}" \
    --define "_sourcedir ${PROJECT_ROOT}" \
    --define "fips_srcdir ${PROJECT_ROOT}" \
    --define "fips_bindir ${BIN_DIR}" \
    --define "fips_version ${RPM_VERSION}" \
    --define "fips_release ${RPM_RELEASE}" \
    --quiet

: "${DEST_DIR:=deploy}"
mkdir -p "${DEST_DIR}"
RPM_FILE=$(find "${TOP_DIR}/RPMS" -name '*.rpm' -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2)

if [ -z "${RPM_FILE}" ]; then
    echo "Error: No .rpm file found under ${TOP_DIR}/RPMS" >&2
    exit 1
fi

cp "${RPM_FILE}" "${DEST_DIR}/"
BASENAME=$(basename "${RPM_FILE}")

# A container build runs as root on a mounted source tree, which would leave a
# package its owner cannot delete without sudo. HOST_UID/HOST_GID say who asked
# for it; unset (the ordinary case, building as yourself) changes nothing.
if [[ -n "${HOST_UID:-}" && -n "${HOST_GID:-}" ]]; then
    chown "${HOST_UID}:${HOST_GID}" "${DEST_DIR}/${BASENAME}"
fi
if [[ -n "${NAME_FILE}" ]]; then
    printf '%s\n' "${BASENAME}" > "${NAME_FILE}"
fi

# dnf needs a path it can tell from a package name, so a relative one gets a
# "./" and an absolute one is already unambiguous.
OUT_PATH="${DEST_DIR}/${BASENAME}"
case "${OUT_PATH}" in
    /*) INSTALL_PATH="${OUT_PATH}" ;;
    *) INSTALL_PATH="./${OUT_PATH}" ;;
esac

echo "Package built: ${OUT_PATH}"
echo ""
echo "Install with: sudo dnf install ${INSTALL_PATH}"
echo "Remove with:  sudo dnf remove fips-mesh  (keeps /etc/fips and its identity keys)"

# The last line of stdout is the package path, and nothing may follow it: the
# release workflow reads it to learn which package this run produced, exactly
# as it does with build-deb-container.sh.
echo "${OUT_PATH}"
