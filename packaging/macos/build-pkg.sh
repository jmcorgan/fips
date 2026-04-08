#!/usr/bin/env bash
# Build a macOS .pkg installer for FIPS.
#
# Usage: ./packaging/macos/build-pkg.sh [--version <version>] [--no-build]
# Output: deploy/fips-<version>-macos-<arch>.pkg
#
# Prerequisites: Xcode command-line tools (pkgbuild is included)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PACKAGING_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROJECT_ROOT="$(cd "${PACKAGING_DIR}/.." && pwd)"

usage() {
    cat <<'EOF'
Usage: packaging/macos/build-pkg.sh [options]

Options:
  --version <version> Override package version
  --target <triple>   Rust target triple (e.g. x86_64-apple-darwin)
  --no-build          Package existing binaries without running cargo build
  -h, --help          Show this help
EOF
}

VERSION_OVERRIDE=""
TARGET_TRIPLE=""
NO_BUILD=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            VERSION_OVERRIDE="${2:?missing value for --version}"
            shift 2
            ;;
        --target)
            TARGET_TRIPLE="${2:?missing value for --target}"
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
ARCH="$(uname -m)"
PKG_NAME="fips-${VERSION}-macos-${ARCH}"
DEPLOY_DIR="${PROJECT_ROOT}/deploy"
STAGING_DIR="$(mktemp -d)"
SCRIPTS_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGING_DIR}" "${SCRIPTS_DIR}"' EXIT

if [[ -n "${TARGET_TRIPLE}" ]]; then
    BINARY_DIR="${PROJECT_ROOT}/target/${TARGET_TRIPLE}/release"
else
    BINARY_DIR="${PROJECT_ROOT}/target/release"
fi

echo "Building FIPS v${VERSION} for macOS ${ARCH}..."

# Build release binaries
if [[ "${NO_BUILD}" -eq 0 ]]; then
    cargo_args=(build --release --manifest-path="${PROJECT_ROOT}/Cargo.toml" --no-default-features --features tui,ble-macos)
    [[ -n "${TARGET_TRIPLE}" ]] && cargo_args+=(--target "${TARGET_TRIPLE}")
    cargo "${cargo_args[@]}"
fi

# Verify binaries exist
for bin in fips fipsctl fipstop; do
    if [[ ! -f "${BINARY_DIR}/${bin}" ]]; then
        echo "Missing binary: ${BINARY_DIR}/${bin}" >&2
        exit 1
    fi
done

# Stage the payload (mirrors installed filesystem layout)
mkdir -p "${STAGING_DIR}/usr/local/bin"
mkdir -p "${STAGING_DIR}/usr/local/etc/fips"
mkdir -p "${STAGING_DIR}/usr/local/var/log/fips"
mkdir -p "${STAGING_DIR}/Library/LaunchDaemons"
mkdir -p "${STAGING_DIR}/etc/resolver"

# Binaries
for bin in fips fipsctl fipstop; do
    cp "${BINARY_DIR}/${bin}" "${STAGING_DIR}/usr/local/bin/"
    strip "${STAGING_DIR}/usr/local/bin/${bin}"
done

# Config (marked as conf file via postinstall logic — won't overwrite on upgrade)
cp "${PACKAGING_DIR}/common/fips.yaml" "${STAGING_DIR}/usr/local/etc/fips/fips.yaml.default"
cp "${PACKAGING_DIR}/common/hosts" "${STAGING_DIR}/usr/local/etc/fips/hosts.default"

# LaunchDaemon plist
cp "${SCRIPT_DIR}/com.fips.daemon.plist" "${STAGING_DIR}/Library/LaunchDaemons/"

# DNS resolver
cat > "${STAGING_DIR}/etc/resolver/fips" <<EOF
nameserver 127.0.0.1
port 5354
EOF

# Create postinstall script
cat > "${SCRIPTS_DIR}/postinstall" <<'POSTINSTALL'
#!/bin/sh
set -e

LOG="/var/log/fips-install.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG"; logger -t fips-install "$*"; }

log "postinstall started"

CONFDIR="/usr/local/etc/fips"

# Install default config only if none exists (preserve on upgrade)
if [ ! -f "$CONFDIR/fips.yaml" ]; then
    cp "$CONFDIR/fips.yaml.default" "$CONFDIR/fips.yaml"
    chmod 600 "$CONFDIR/fips.yaml"
    log "installed default config"
fi
if [ ! -f "$CONFDIR/hosts" ]; then
    cp "$CONFDIR/hosts.default" "$CONFDIR/hosts"
fi

# Flush DNS cache so macOS picks up the new /etc/resolver/fips file
dscacheutil -flushcache
killall -HUP mDNSResponder 2>/dev/null || true
log "flushed DNS cache"

# Create fips group if it doesn't exist
if ! dscl . -read /Groups/fips > /dev/null 2>&1; then
    dscl . -create /Groups/fips RecordName fips
    dscl . -create /Groups/fips PrimaryGroupID 999
    log "created group fips"
fi

# stat /dev/console gives the user logged into the GUI session —
# logname/SUDO_USER are not set in pkg postinstall context
REAL_USER="$(stat -f '%Su' /dev/console 2>/dev/null || true)"
log "console user: ${REAL_USER:-unknown}"
if [ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ]; then
    if ! dscl . -read /Groups/fips GroupMembership 2>/dev/null | grep -qw "$REAL_USER"; then
        dscl . -append /Groups/fips GroupMembership "$REAL_USER"
        log "added $REAL_USER to group fips"
    else
        log "$REAL_USER already in group fips"
    fi
fi

# Load the launchd service
launchctl bootout system /Library/LaunchDaemons/com.fips.daemon.plist 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.fips.daemon.plist 2>/dev/null || true
log "launchd service loaded"

log "postinstall complete"
exit 0
POSTINSTALL
chmod +x "${SCRIPTS_DIR}/postinstall"

# Create preinstall script (stop service before upgrade)
cat > "${SCRIPTS_DIR}/preinstall" <<'PREINSTALL'
#!/bin/sh
# Stop service before upgrade
launchctl bootout system /Library/LaunchDaemons/com.fips.daemon.plist 2>/dev/null || true
exit 0
PREINSTALL
chmod +x "${SCRIPTS_DIR}/preinstall"

# Build the .pkg
mkdir -p "${DEPLOY_DIR}"
pkgbuild \
    --root "${STAGING_DIR}" \
    --scripts "${SCRIPTS_DIR}" \
    --identifier com.fips.pkg \
    --version "${VERSION}" \
    --ownership recommended \
    "${DEPLOY_DIR}/${PKG_NAME}.pkg"

echo ""
echo "Package built: deploy/${PKG_NAME}.pkg"
ls -lh "${DEPLOY_DIR}/${PKG_NAME}.pkg"
echo ""
echo "Install with: sudo installer -pkg deploy/${PKG_NAME}.pkg -target /"
echo "Remove with:  sudo packaging/macos/uninstall.sh"
