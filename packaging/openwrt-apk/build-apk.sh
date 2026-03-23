#!/bin/bash
# Build a FIPS .apk package for OpenWrt 25+ (apk-tools v3).
#
# OpenWrt 25 replaced opkg/ipk with Alpine Package Keeper (apk-tools).
# An .apk is two concatenated gzip-compressed tar streams: control (containing
# .PKGINFO and optional hook scripts) followed by data (the filesystem tree).
#
# Usage:
#   ./packaging/openwrt-apk/build-apk.sh [--arch <name>]
#
# Architectures (--arch):
#   aarch64   GL.iNet MT3000/MT6000, RPi 3/4/5, most modern routers  [default]
#   mipsel    Older MIPS routers (TP-Link, Netgear, GL.iNet AR750)
#   mips      MIPS big-endian routers (ath79)
#   arm       32-bit ARM routers (Cortex-A7)
#   x86_64    x86 routers / VMs
#
# Output: dist/fips_<apk-version>_<openwrt-arch>.apk
#
# Prerequisites:
#   cargo install cargo-zigbuild
#   rustup target add <rust-triple>   (added automatically if missing)

set -euo pipefail

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

ARCH="aarch64"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch) ARCH="$2"; shift 2 ;;
        --arch=*) ARCH="${1#*=}"; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Architecture mapping
#
# RUST_TARGET   — passed to cargo --target
# OPENWRT_ARCH  — goes in the .PKGINFO arch field and filename
# ---------------------------------------------------------------------------

case "$ARCH" in
    aarch64)
        RUST_TARGET="aarch64-unknown-linux-musl"
        OPENWRT_ARCH="aarch64_cortex-a53"
        ;;
    mipsel)
        RUST_TARGET="mipsel-unknown-linux-musl"
        OPENWRT_ARCH="mipsel_24kc"
        ;;
    mips)
        RUST_TARGET="mips-unknown-linux-musl"
        OPENWRT_ARCH="mips_24kc"
        ;;
    arm)
        RUST_TARGET="arm-unknown-linux-musleabihf"
        OPENWRT_ARCH="arm_cortex-a7"
        ;;
    x86_64)
        RUST_TARGET="x86_64-unknown-linux-musl"
        OPENWRT_ARCH="x86_64"
        ;;
    *)
        echo "Unknown arch: $ARCH" >&2
        echo "Valid: aarch64, mipsel, mips, arm, x86_64" >&2
        exit 1
        ;;
esac

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FILES_DIR="$(dirname "$SCRIPT_DIR")/openwrt-ipk/files"
DIST_DIR="$PROJECT_ROOT/dist"

PKG_NAME="fips"
PKG_VERSION="${PKG_VERSION:-$(cd "$PROJECT_ROOT" && git describe --tags --always --dirty 2>/dev/null || echo "0.1.0")}"

# ---------------------------------------------------------------------------
# Version conversion
#
# APK requires <version>-r<release> format. Convert git describe output:
#   v0.1.0              → 0.1.0-r0
#   v0.1.0-16-ga5130b3  → 0.1.0_git16-r0
#   v0.1.0-16-ga5130b3-dirty → 0.1.0_git16-r0
# ---------------------------------------------------------------------------

apk_version() {
    local ver="${1#v}"          # strip leading 'v'
    ver="${ver%-dirty}"         # strip -dirty suffix
    if [[ "$ver" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)-g[a-f0-9]+$ ]]; then
        echo "${BASH_REMATCH[1]}_git${BASH_REMATCH[2]}-r0"
    else
        echo "${ver}-r0"
    fi
}

APK_VERSION="$(apk_version "$PKG_VERSION")"

echo "==> Building $PKG_NAME $APK_VERSION for $OPENWRT_ARCH ($RUST_TARGET)"

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

if ! command -v cargo-zigbuild &>/dev/null; then
    echo "Error: cargo-zigbuild not found." >&2
    echo "  Install: cargo install cargo-zigbuild" >&2
    exit 1
fi

if ! rustup target list --installed | grep -q "^$RUST_TARGET$"; then
    echo "==> Adding Rust target $RUST_TARGET..."
    rustup target add "$RUST_TARGET"
fi

# ---------------------------------------------------------------------------
# 1. Build
# ---------------------------------------------------------------------------

echo "==> Compiling..."
cd "$PROJECT_ROOT"
cargo zigbuild \
    --release \
    --target "$RUST_TARGET" \
    --bin fips \
    --bin fipsctl \
    --bin fipstop

RELEASE_DIR="$PROJECT_ROOT/target/$RUST_TARGET/release"

echo "==> Stripping binaries..."
if [ -n "${LLVM_STRIP:-}" ]; then
    STRIP="$LLVM_STRIP"
elif command -v llvm-strip &>/dev/null; then
    STRIP="llvm-strip"
elif [ -x "/opt/homebrew/opt/llvm/bin/llvm-strip" ]; then
    STRIP="/opt/homebrew/opt/llvm/bin/llvm-strip"
else
    echo "Warning: llvm-strip not found; using system strip (may not work for cross-compiled ELF)" >&2
    STRIP="strip"
fi
for bin in fips fipsctl fipstop; do
    "$STRIP" "$RELEASE_DIR/$bin" 2>/dev/null || true
done

SIZE=$(du -sh "$RELEASE_DIR/fips" | cut -f1)
echo "    fips: $SIZE after strip"

# ---------------------------------------------------------------------------
# 2. Assemble .apk
# ---------------------------------------------------------------------------
# APK v2 format is two gzip-compressed tar streams concatenated into one file:
#
#   [control.tar.gz]  — .PKGINFO + install/remove hook scripts
#   [data.tar.gz]     — the actual filesystem tree
#
# apk-tools identifies the format by reading the two independent gzip members.
# Putting everything in a single tar.gz produces a "v2 package format error".

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

CONTROL_DIR="$WORK_DIR/control"
DATA_DIR="$WORK_DIR/data"
mkdir -p "$CONTROL_DIR" "$DATA_DIR"

# ---- data tree ----

install -d "$DATA_DIR/usr/bin"
install -m 0755 "$RELEASE_DIR/fips"    "$DATA_DIR/usr/bin/fips"
install -m 0755 "$RELEASE_DIR/fipsctl" "$DATA_DIR/usr/bin/fipsctl"
install -m 0755 "$RELEASE_DIR/fipstop" "$DATA_DIR/usr/bin/fipstop"

install -d "$DATA_DIR/etc/init.d"
install -m 0755 "$FILES_DIR/etc/init.d/fips" "$DATA_DIR/etc/init.d/fips"

install -d "$DATA_DIR/etc/fips"
install -m 0600 "$FILES_DIR/etc/fips/fips.yaml"   "$DATA_DIR/etc/fips/fips.yaml"
install -m 0755 "$FILES_DIR/etc/fips/firewall.sh" "$DATA_DIR/etc/fips/firewall.sh"

install -d "$DATA_DIR/etc/dnsmasq.d"
install -m 0644 "$FILES_DIR/etc/dnsmasq.d/fips.conf" "$DATA_DIR/etc/dnsmasq.d/fips.conf"

install -d "$DATA_DIR/etc/sysctl.d"
install -m 0644 "$FILES_DIR/etc/sysctl.d/fips-bridge.conf" "$DATA_DIR/etc/sysctl.d/fips-bridge.conf"

install -d "$DATA_DIR/etc/hotplug.d/net"
install -m 0755 "$FILES_DIR/etc/hotplug.d/net/99-fips" "$DATA_DIR/etc/hotplug.d/net/99-fips"

install -d "$DATA_DIR/etc/uci-defaults"
install -m 0755 "$FILES_DIR/etc/uci-defaults/90-fips-setup" "$DATA_DIR/etc/uci-defaults/90-fips-setup"

install -d "$DATA_DIR/lib/upgrade/keep.d"
install -m 0644 "$FILES_DIR/lib/upgrade/keep.d/fips" "$DATA_DIR/lib/upgrade/keep.d/fips"

# ---- control files ----
# size is installed size in bytes; builddate is a Unix timestamp.

PKG_SIZE=$(du -sk "$DATA_DIR" | awk '{print $1 * 1024}')
BUILDDATE=${SOURCE_DATE_EPOCH:-$(date +%s)}

cat > "$CONTROL_DIR/.PKGINFO" <<EOF
pkgname = $PKG_NAME
pkgver = $APK_VERSION
arch = $OPENWRT_ARCH
size = $PKG_SIZE
pkgdesc = FIPS Mesh Network Daemon
url = https://github.com/jmcorgan/fips
builddate = $BUILDDATE
packager = FIPS Network
depend = kmod-tun
depend = kmod-br-netfilter
EOF

cat > "$CONTROL_DIR/.post-install" <<'SCRIPT'
#!/bin/sh
# Run first-boot UCI setup (the script deletes itself when done).
if [ -x /etc/uci-defaults/90-fips-setup ]; then
    /etc/uci-defaults/90-fips-setup && rm -f /etc/uci-defaults/90-fips-setup
fi

/etc/init.d/fips enable
/etc/init.d/fips start
exit 0
SCRIPT
chmod 0755 "$CONTROL_DIR/.post-install"

cat > "$CONTROL_DIR/.pre-deinstall" <<'SCRIPT'
#!/bin/sh
/etc/init.d/fips stop    2>/dev/null || true
/etc/init.d/fips disable 2>/dev/null || true
exit 0
SCRIPT
chmod 0755 "$CONTROL_DIR/.pre-deinstall"

# ---- pack ----

PKG_FILENAME="${PKG_NAME}_${APK_VERSION}_${OPENWRT_ARCH}.apk"

# Detect GNU tar (available as gtar on macOS via Homebrew).
# Always use ustar format — apk-tools and busybox both handle it; GNU extensions
# and PAX headers can confuse the apk extraction layer.
# COPYFILE_DISABLE=1 suppresses macOS resource-fork (._*) files; no-op on Linux.
if command -v gtar &>/dev/null; then
    TAR_CMD="gtar"
else
    TAR_CMD="tar"
fi
TAR_EXTRA_FLAGS="--format=ustar --numeric-owner"

apk_tar() {
    local out="$1" src="$2"; shift 2
    COPYFILE_DISABLE=1 "$TAR_CMD" $TAR_EXTRA_FLAGS -czf "$out" -C "$src" "$@"
}

# Data stream first — we need its SHA256 for the datahash field in .PKGINFO.
apk_tar "$WORK_DIR/data.tar.gz" "$DATA_DIR" .

# Compute SHA256 of the data stream.
# apk-tools checks this hash even with --allow-untrusted.
if command -v sha256sum &>/dev/null; then
    DATAHASH=$(sha256sum "$WORK_DIR/data.tar.gz" | cut -d' ' -f1)
else
    # macOS
    DATAHASH=$(shasum -a 256 "$WORK_DIR/data.tar.gz" | cut -d' ' -f1)
fi
echo "datahash = $DATAHASH" >> "$CONTROL_DIR/.PKGINFO"

# Control stream: .PKGINFO must be the first entry, then hook scripts.
apk_tar "$WORK_DIR/control.tar.gz" "$CONTROL_DIR" .PKGINFO .post-install .pre-deinstall

# APK v2 wire format: two concatenated gzip streams.
#
#   [control.tar.gz]  — .PKGINFO + hook scripts (stream 1)
#   [data.tar.gz]     — filesystem tree (stream 2)
#
# Unsigned packages omit the signature stream entirely. apk-tools identifies
# the first stream as control by the presence of .PKGINFO as the first tar
# entry. --allow-untrusted skips signature verification; --no-network skips
# repository index refresh.

mkdir -p "$DIST_DIR"
cat "$WORK_DIR/control.tar.gz" "$WORK_DIR/data.tar.gz" > "$DIST_DIR/$PKG_FILENAME"

echo ""
echo "==> Done: dist/$PKG_FILENAME"
echo "    $(du -sh "$DIST_DIR/$PKG_FILENAME" | cut -f1)"
echo ""
echo "Install on router (OpenWrt 25+):"
echo "    scp -O dist/$PKG_FILENAME root@192.168.1.1:/tmp/"
echo "    ssh root@192.168.1.1 apk add --allow-untrusted --no-network /tmp/$PKG_FILENAME"
