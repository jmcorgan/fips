#!/bin/bash
# Build a FIPS .apk package for OpenWrt without the OpenWrt SDK.
#
# apk-tools (.apk) is the mandatory package manager from OpenWrt 25 onward; it
# is also available opt-in on 24.10, where opkg (.ipk) remains the default. The
# .ipk package in ../openwrt-ipk/ still covers OpenWrt 24.x and earlier; this
# .apk package is what you need on 25+. Unlike the .ipk format (a plain tar.gz
# of tarballs that we
# assemble by hand in ../openwrt-ipk/build-ipk.sh), the .apk container is the
# apk-tools v3 ADB format, which is impractical to hand-roll. Instead we drive
# the official `apk mkpkg` applet — the same tool OpenWrt's build system calls
# in include/package-pack.mk — so no SDK is required, only the `apk` binary.
#
# Usage:
#   ./packaging/openwrt-apk/build-apk.sh [--arch <name>]
#
# Architectures (--arch): aarch64 [default], x86_64, mipsel, mips, arm
#   (the apk CI matrix ships aarch64 + x86_64; the rest are buildable locally).
#
# Output: dist/fips_<version>_<openwrt-arch>.apk
#
# Prerequisites:
#   cargo install cargo-zigbuild           (Rust musl cross-compilation)
#   apk-tools v3 `apk` binary on PATH, or pointed at via APK_BIN=/path/to/apk
#     (build from source — see README.md; CI builds apk-tools 3.0.5).
#   fakeroot (optional but recommended; makes packaged files root-owned).
#
# Install on a router (packages are unsigned, like our .ipk):
#   scp -O dist/fips_<version>_<arch>.apk root@192.168.1.1:/tmp/
#   ssh root@192.168.1.1 apk add --allow-untrusted /tmp/fips_<version>_<arch>.apk

set -euo pipefail

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

ARCH="aarch64"
BIN_DIR=""   # if set, use prebuilt binaries from here instead of compiling

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch) ARCH="$2"; shift 2 ;;
        --arch=*) ARCH="${1#*=}"; shift ;;
        --bin-dir) BIN_DIR="$2"; shift 2 ;;
        --bin-dir=*) BIN_DIR="${1#*=}"; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Architecture mapping
#
# RUST_TARGET   — passed to cargo --target
# OPENWRT_ARCH  — apk "arch:" field and the package filename
#
# Kept in sync with ../openwrt-ipk/build-ipk.sh (same target table).
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
# The installed-filesystem payload (init scripts, config, sysctl, etc.) is
# shared with the .ipk package; there is one canonical copy in openwrt-ipk/.
FILES_DIR="$PROJECT_ROOT/packaging/openwrt-ipk/files"
DIST_DIR="$PROJECT_ROOT/dist"

PKG_NAME="fips"
# Human-readable version for the filename (e.g. v0.4.0 or master.123.abcdef0),
# mirroring the .ipk artifacts and the CI/NIP-94 plumbing.
PKG_VERSION="${PKG_VERSION:-$(cd "$PROJECT_ROOT" && git describe --tags --always --dirty 2>/dev/null || echo "0.1.0")}"
# apk-tools-compatible version embedded inside the package metadata.
APK_VERSION="${APK_VERSION:-$(cd "$PROJECT_ROOT" && sh "$SCRIPT_DIR/apk-version.sh" auto)}"

APK_BIN="${APK_BIN:-apk}"
if ! command -v "$APK_BIN" >/dev/null 2>&1; then
    echo "Error: apk-tools binary not found (looked for '$APK_BIN')." >&2
    echo "  Build apk-tools v3 from source or set APK_BIN=/path/to/apk." >&2
    echo "  See packaging/openwrt-apk/README.md." >&2
    exit 1
fi

echo "==> Building $PKG_NAME $PKG_VERSION (apk version $APK_VERSION) for $OPENWRT_ARCH ($RUST_TARGET)"

# ---------------------------------------------------------------------------
# 1. Obtain binaries
#
# Either use a directory of prebuilt binaries (--bin-dir; CI cross-compiles
# once in a shared job and hands them to both the .ipk and .apk packagers), or
# compile from source here for a self-contained local build.
# ---------------------------------------------------------------------------

if [ -n "$BIN_DIR" ]; then
    RELEASE_DIR="$BIN_DIR"
    echo "==> Using prebuilt binaries from $RELEASE_DIR"
    for bin in fips fipsctl fipstop fips-gateway; do
        [ -f "$RELEASE_DIR/$bin" ] || {
            echo "Error: prebuilt binary not found: $RELEASE_DIR/$bin" >&2
            exit 1
        }
    done
else
    if ! command -v cargo-zigbuild &>/dev/null; then
        echo "Error: cargo-zigbuild not found." >&2
        echo "  Install: cargo install cargo-zigbuild" >&2
        exit 1
    fi

    if ! rustup target list --installed | grep -q "^$RUST_TARGET$"; then
        echo "==> Adding Rust target $RUST_TARGET..."
        rustup target add "$RUST_TARGET"
    fi

    echo "==> Compiling..."
    cd "$PROJECT_ROOT"
    cargo zigbuild \
        --release \
        --target "$RUST_TARGET" \
        --bin fips \
        --bin fipsctl \
        --bin fipstop \
        --bin fips-gateway

    RELEASE_DIR="$PROJECT_ROOT/target/$RUST_TARGET/release"

    echo "==> Stripping binaries..."
    STRIP="${LLVM_STRIP:-strip}"
    for bin in fips fipsctl fipstop fips-gateway; do
        "$STRIP" "$RELEASE_DIR/$bin" 2>/dev/null || true
    done
fi

SIZE=$(du -sh "$RELEASE_DIR/fips" | cut -f1)
echo "    fips: $SIZE"

# ---------------------------------------------------------------------------
# 2. Stage the installed filesystem tree (--files root for apk mkpkg)
# ---------------------------------------------------------------------------
# This block is the same payload as ../openwrt-ipk/build-ipk.sh; keep the two
# in sync. The CI apk structural check asserts every path below is present.

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

STAGE_DIR="$WORK_DIR/root"        # becomes the package's filesystem
SCRIPTS_DIR="$WORK_DIR/scripts"   # maintainer scripts (metadata, not payload)
mkdir -p "$STAGE_DIR" "$SCRIPTS_DIR"

install -d "$STAGE_DIR/usr/bin"
install -m 0755 "$RELEASE_DIR/fips"         "$STAGE_DIR/usr/bin/fips"
install -m 0755 "$RELEASE_DIR/fipsctl"      "$STAGE_DIR/usr/bin/fipsctl"
install -m 0755 "$RELEASE_DIR/fipstop"      "$STAGE_DIR/usr/bin/fipstop"
install -m 0755 "$RELEASE_DIR/fips-gateway" "$STAGE_DIR/usr/bin/fips-gateway"
install -m 0755 "$FILES_DIR/usr/bin/fips-mesh-setup" "$STAGE_DIR/usr/bin/fips-mesh-setup"

install -d "$STAGE_DIR/etc/init.d"
install -m 0755 "$FILES_DIR/etc/init.d/fips"         "$STAGE_DIR/etc/init.d/fips"
install -m 0755 "$FILES_DIR/etc/init.d/fips-gateway" "$STAGE_DIR/etc/init.d/fips-gateway"

install -d "$STAGE_DIR/etc/fips"
install -m 0600 "$FILES_DIR/etc/fips/fips.yaml"   "$STAGE_DIR/etc/fips/fips.yaml"
install -m 0755 "$FILES_DIR/etc/fips/firewall.sh" "$STAGE_DIR/etc/fips/firewall.sh"

# The shared fips.yaml ships ethernet.wan.interface: "eth0", the OpenWrt 24
# default. This .apk package targets OpenWrt 25+ (DSA), where the WAN port is
# named "wan", so ship "wan" as the default. Patching the staged copy keeps the
# as-installed config correct for the platform without maintaining a second copy
# of the file; operators can still edit /etc/fips/fips.yaml for non-standard boards.
sed -i 's|interface: "eth0"|interface: "wan"|' "$STAGE_DIR/etc/fips/fips.yaml"

install -d "$STAGE_DIR/etc/dnsmasq.d"
install -m 0644 "$FILES_DIR/etc/dnsmasq.d/fips.conf" "$STAGE_DIR/etc/dnsmasq.d/fips.conf"

install -d "$STAGE_DIR/etc/sysctl.d"
install -m 0644 "$FILES_DIR/etc/sysctl.d/fips-bridge.conf"  "$STAGE_DIR/etc/sysctl.d/fips-bridge.conf"
install -m 0644 "$FILES_DIR/etc/sysctl.d/fips-gateway.conf" "$STAGE_DIR/etc/sysctl.d/fips-gateway.conf"

install -d "$STAGE_DIR/etc/hotplug.d/net"
install -m 0755 "$FILES_DIR/etc/hotplug.d/net/99-fips" "$STAGE_DIR/etc/hotplug.d/net/99-fips"

install -d "$STAGE_DIR/etc/uci-defaults"
install -m 0755 "$FILES_DIR/etc/uci-defaults/90-fips-setup" "$STAGE_DIR/etc/uci-defaults/90-fips-setup"

install -d "$STAGE_DIR/lib/upgrade/keep.d"
install -m 0644 "$FILES_DIR/lib/upgrade/keep.d/fips" "$STAGE_DIR/lib/upgrade/keep.d/fips"

# ---- conffiles ----
# apk mkpkg discovers config files from /lib/apk/packages/<name>.conffiles
# inside the --files tree (same mechanism OpenWrt's package-pack.mk uses).
# Listing fips.yaml here makes apk preserve user edits across upgrades, the
# apk equivalent of opkg's conffiles handling.
install -d "$STAGE_DIR/lib/apk/packages"
cat > "$STAGE_DIR/lib/apk/packages/${PKG_NAME}.conffiles" <<'EOF'
/etc/fips/fips.yaml
EOF

# ---- maintainer scripts ----
# Map our opkg maintainer scripts onto apk's lifecycle phases:
#   opkg postinst -> apk post-install   (enable + start services)
#   opkg prerm    -> apk pre-deinstall  (stop + disable services)

cat > "$SCRIPTS_DIR/post-install" <<'EOF'
#!/bin/sh
# Run first-boot UCI setup (the script deletes itself when done).
if [ -x /etc/uci-defaults/90-fips-setup ]; then
    /etc/uci-defaults/90-fips-setup && rm -f /etc/uci-defaults/90-fips-setup
fi

/etc/init.d/fips enable
/etc/init.d/fips start
/etc/init.d/fips-gateway enable
/etc/init.d/fips-gateway start
exit 0
EOF

cat > "$SCRIPTS_DIR/pre-deinstall" <<'EOF'
#!/bin/sh
/etc/init.d/fips-gateway stop    2>/dev/null || true
/etc/init.d/fips-gateway disable 2>/dev/null || true
/etc/init.d/fips stop            2>/dev/null || true
/etc/init.d/fips disable         2>/dev/null || true
exit 0
EOF

chmod 0755 "$SCRIPTS_DIR/post-install" "$SCRIPTS_DIR/pre-deinstall"

# ---------------------------------------------------------------------------
# 3. Assemble the .apk via apk mkpkg
# ---------------------------------------------------------------------------
# fakeroot makes the packaged files root-owned even though CI runs unprivileged.

DESCRIPTION="FIPS Mesh Network Daemon. Distributed, decentralized mesh networking over UDP, TCP, and raw Ethernet, with a TUN interface (fips0), ULA IPv6 addressing, and a .fips DNS responder."
DEPENDS="kmod-tun kmod-br-netfilter kmod-nft-nat kmod-nf-conntrack ip-full"

PKG_FILENAME="${PKG_NAME}_${PKG_VERSION}_${OPENWRT_ARCH}.apk"
mkdir -p "$DIST_DIR"

FAKEROOT=""
if command -v fakeroot >/dev/null 2>&1; then
    FAKEROOT="fakeroot"
else
    echo "Warning: fakeroot not found — packaged files will be owned by the build user." >&2
fi

$FAKEROOT "$APK_BIN" mkpkg \
    --info "name:$PKG_NAME" \
    --info "version:$APK_VERSION" \
    --info "description:$DESCRIPTION" \
    --info "arch:$OPENWRT_ARCH" \
    --info "license:MIT" \
    --info "origin:$PKG_NAME" \
    --info "url:https://github.com/jmcorgan/fips" \
    --info "maintainer:FIPS Network" \
    --info "depends:$DEPENDS" \
    --script "post-install:$SCRIPTS_DIR/post-install" \
    --script "pre-deinstall:$SCRIPTS_DIR/pre-deinstall" \
    --files "$STAGE_DIR" \
    --output "$DIST_DIR/$PKG_FILENAME"

echo ""
echo "==> Done: dist/$PKG_FILENAME"
echo "    $(du -sh "$DIST_DIR/$PKG_FILENAME" | cut -f1)"
echo ""
echo "Install on router (OpenWrt 25+, or 24.10 with apk enabled):"
echo "    scp -O dist/$PKG_FILENAME root@192.168.1.1:/tmp/"
echo "    ssh root@192.168.1.1 apk add --allow-untrusted /tmp/$PKG_FILENAME"
