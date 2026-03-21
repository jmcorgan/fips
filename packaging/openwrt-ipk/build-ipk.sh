#!/bin/bash
# Build a FIPS .ipk package for OpenWrt without the OpenWrt SDK.
#
# Uses cargo-zigbuild for cross-compilation and assembles the .ipk directly.
# An .ipk is just an ar archive containing two tarballs — no SDK required.
#
# Usage:
#   ./packaging/openwrt/build-ipk.sh [--arch <name>]
#
# Architectures (--arch):
#   aarch64   GL.iNet MT3000/MT6000, RPi 3/4/5, most modern routers  [default]
#   mipsel    Older MIPS routers (TP-Link, Netgear, GL.iNet AR750)
#   mips      MIPS big-endian routers (ath79)
#   arm       32-bit ARM routers (Cortex-A7)
#   x86_64    x86 routers / VMs
#
# Output: dist/fips_<version>_<openwrt-arch>.ipk
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
# OPENWRT_ARCH  — goes in the .ipk control file and filename
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
FILES_DIR="$SCRIPT_DIR/files"
DIST_DIR="$PROJECT_ROOT/dist"

PKG_NAME="fips"
PKG_VERSION="${PKG_VERSION:-$(cd "$PROJECT_ROOT" && git describe --tags --always --dirty 2>/dev/null || echo "0.1.0")}"

echo "==> Building $PKG_NAME $PKG_VERSION for $OPENWRT_ARCH ($RUST_TARGET)"

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
STRIP="${LLVM_STRIP:-strip}"
for bin in fips fipsctl fipstop; do
    "$STRIP" "$RELEASE_DIR/$bin" 2>/dev/null || true
done

SIZE=$(du -sh "$RELEASE_DIR/fips" | cut -f1)
echo "    fips: $SIZE after strip"

# ---------------------------------------------------------------------------
# 2. Assemble .ipk
# ---------------------------------------------------------------------------
# An .ipk is an ar archive with three members:
#   debian-binary   — format version ("2.0\n")
#   control.tar.gz  — package metadata, conffiles, pre/post scripts
#   data.tar.gz     — the actual filesystem tree

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

PKG_SIZE=$(du -sk "$DATA_DIR" | cut -f1)

cat > "$CONTROL_DIR/control" <<EOF
Package: $PKG_NAME
Version: $PKG_VERSION
Architecture: $OPENWRT_ARCH
Maintainer: FIPS Network
Section: net
Priority: optional
Depends: kmod-tun, kmod-br-netfilter
Description: FIPS Mesh Network Daemon
 Distributed, decentralized mesh networking over UDP, TCP, and raw Ethernet.
 Provides a TUN interface (fips0) with ULA IPv6 addressing and a DNS
 responder for .fips name resolution.
Installed-Size: $PKG_SIZE
EOF

# Mark fips.yaml as a conffile so opkg won't overwrite user edits on upgrade.
cat > "$CONTROL_DIR/conffiles" <<EOF
/etc/fips/fips.yaml
EOF

cat > "$CONTROL_DIR/postinst" <<'EOF'
#!/bin/sh
# Run first-boot UCI setup (the script deletes itself when done).
if [ -x /etc/uci-defaults/90-fips-setup ]; then
    /etc/uci-defaults/90-fips-setup && rm -f /etc/uci-defaults/90-fips-setup
fi

/etc/init.d/fips enable
/etc/init.d/fips start
exit 0
EOF
chmod 0755 "$CONTROL_DIR/postinst"

cat > "$CONTROL_DIR/prerm" <<'EOF'
#!/bin/sh
/etc/init.d/fips stop    2>/dev/null || true
/etc/init.d/fips disable 2>/dev/null || true
exit 0
EOF
chmod 0755 "$CONTROL_DIR/prerm"

# ---- pack ----

PKG_FILENAME="${PKG_NAME}_${PKG_VERSION}_${OPENWRT_ARCH}.ipk"
IPK_WORK="$WORK_DIR/ipk"
mkdir -p "$IPK_WORK"

echo "2.0" > "$IPK_WORK/debian-binary"

# Detect a tar that supports --format=gnu.
# On macOS, Homebrew's GNU tar is installed as 'gtar'; the system tar is BSD.
# Our filenames are short so BSD tar (ustar) works too, but gnu is preferred
# to match ipkg-build exactly and to embed numeric UID/GID.
# COPYFILE_DISABLE=1 suppresses macOS resource-fork (._*) files; no-op on Linux.
if command -v gtar &>/dev/null; then
    # Homebrew GNU tar on macOS
    TAR_CMD="gtar"
    TAR_EXTRA_FLAGS="--format=gnu --numeric-owner"
elif tar --version 2>/dev/null | grep -q 'GNU tar'; then
    # System tar is GNU tar (Linux)
    TAR_CMD="tar"
    TAR_EXTRA_FLAGS="--format=gnu --numeric-owner"
else
    # macOS BSD tar (libarchive). Its default format is PAX (typeflag 0x78),
    # which OpenWrt's busybox tar cannot handle. Force ustar explicitly.
    TAR_CMD="tar"
    TAR_EXTRA_FLAGS="--format=ustar"
fi

ipk_tar() {
    # ipk_tar <output.tar.gz> <source-dir> [paths...]
    local out="$1" src="$2"; shift 2
    local mtime_flags=""
    if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
        mtime_flags="--mtime=@$SOURCE_DATE_EPOCH"
    fi
    COPYFILE_DISABLE=1 "$TAR_CMD" $TAR_EXTRA_FLAGS $mtime_flags -czf "$out" -C "$src" "$@"
}

ipk_tar "$IPK_WORK/control.tar.gz" "$CONTROL_DIR" .
ipk_tar "$IPK_WORK/data.tar.gz"    "$DATA_DIR"    .

# The outer .ipk container is a gzip-compressed tar — NOT an ar archive.
# (Debian .deb uses ar; OpenWrt .ipk uses tar.gz.)
# Entries must be named with ./ prefix, as ipkg-build produces.
mkdir -p "$DIST_DIR"
ipk_tar "$DIST_DIR/$PKG_FILENAME" "$IPK_WORK" ./debian-binary ./control.tar.gz ./data.tar.gz

echo ""
echo "==> Done: dist/$PKG_FILENAME"
echo "    $(du -sh "$DIST_DIR/$PKG_FILENAME" | cut -f1)"
echo ""
echo "Install on router:"
echo "    scp -O dist/$PKG_FILENAME root@192.168.1.1:/tmp/"
echo "    ssh root@192.168.1.1 opkg install /tmp/$PKG_FILENAME"
