#!/bin/sh
# Build a FreeBSD .pkg package for FIPS using pkg-create(8).
#
# Usage: packaging/freebsd/build-pkg.sh [--version <version>] [--no-build]
#
# Prerequisites: the pinned Rust toolchain, pkg(8).
# Output: deploy/fips-<version>-freebsd-<arch>.pkg
#
# Ships fips, fipsctl, and fipstop. fips-gateway is excluded: its NAT
# backend is nftables (Linux-only) and the binary is a stub elsewhere.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Mechanics shared with the pfSense builder: version derivation, the
# stage layout, the @sample manifest scripts, and pkg create.
. "${PROJECT_ROOT}/packaging/common/pkg-lib.sh"

NO_BUILD=0
VERSION=""
while [ $# -gt 0 ]; do
    case "$1" in
        --no-build) NO_BUILD=1 ;;
        --version) VERSION="${2:?--version requires an argument}"; shift ;;
        *) echo "usage: $0 [--version <version>] [--no-build]" >&2; exit 1 ;;
    esac
    shift
done

# CI passes a derived version that appends +<branch>.<height>.<hash> on
# branch builds; otherwise the version comes from Cargo.toml.
VERSION="$(pkg_resolve_version "$PROJECT_ROOT" "$VERSION")"

ABI="$(pkg_host_abi)"
ARCH="${ABI##*:}"

if [ "$NO_BUILD" -eq 0 ]; then
    pkg_cargo_build "$PROJECT_ROOT"
fi

pkg_require_binaries "${PROJECT_ROOT}/target/release" fips fipsctl fipstop

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/fips-pkg.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

echo "==> staging into ${STAGE}"
pkg_stage_tree "$STAGE"
pkg_stage_binaries "${PROJECT_ROOT}/target/release" "$STAGE" fips fipsctl fipstop

# Config ships sample-style: copied into place on install if absent,
# removed on deinstall only if unmodified (see the manifest scripts).
# fips.yaml may hold a node private key (nsec:), so it is never
# world-readable — 0600 like the Debian and macOS packages.
install -m 0600 "${PROJECT_ROOT}/packaging/common/fips.yaml" \
                "${STAGE}/usr/local/etc/fips/fips.yaml.sample"
install -m 0644 "${PROJECT_ROOT}/packaging/common/hosts" \
                "${STAGE}/usr/local/etc/fips/hosts.sample"

install -m 0755 "${SCRIPT_DIR}/fips.rc" "${STAGE}/usr/local/etc/rc.d/fips"
install -m 0755 "${SCRIPT_DIR}/fips-dns.rc" "${STAGE}/usr/local/etc/rc.d/fips_dns"

install -m 0755 "${SCRIPT_DIR}/fips-dns-setup" \
                "${SCRIPT_DIR}/fips-dns-teardown" \
                "${STAGE}/usr/local/libexec/fips/"

DESC="$(cat "${SCRIPT_DIR}/pkg-descr")"

# The config files get @sample semantics — copied into place on install
# if absent, removed on deinstall only if unmodified — but spelled out as
# manifest scripts: the @sample plist keyword lives in the ports tree
# (/usr/ports/Keywords/sample.ucl), which a plain pkg-create host (e.g.
# a CI VM) does not have.
cat > "${STAGE}/+MANIFEST" <<EOF
$(pkg_manifest_header "$VERSION" "$ABI" "Self-organizing encrypted mesh network on Nostr identities" "$DESC")
scripts: {
  post-install: <<EOD
# Control-socket access group: the rc script creates /var/run/fips as
# root:fips 0750, so members can use fipsctl/fipstop without root.
$(pkg_group_script)
# Install-if-absent config. fips.yaml may hold a node private key
# (nsec:), so it is 0600; FreeBSD has no "root" group, wheel is gid 0.
$(pkg_sample_seed_script fips.yaml:0600 hosts:0644)
# pkg upgrade runs the old package's pre-deinstall (which stops the
# services); bring them back up on the new binaries if enabled.
if [ "\${PKG_UPGRADE:-}" = "true" ]; then
    if service fips enabled >/dev/null 2>&1; then
        service fips start >/dev/null 2>&1 || true
    fi
    if service fips_dns enabled >/dev/null 2>&1; then
        service fips_dns start >/dev/null 2>&1 || true
    fi
fi
EOD
  pre-deinstall: <<EOD
# Stop the services so the daemon binary is never replaced (upgrade) or
# removed (deinstall) under a running process. fips_dns stop also tears
# down the .fips resolver drop-in; on upgrade the new package's
# post-install re-establishes it.
service fips_dns onestop >/dev/null 2>&1 || true
service fips onestop >/dev/null 2>&1 || true
if [ "\${PKG_UPGRADE:-}" != "true" ]; then
    # Removal: clear the resolver drop-in even if the service was never
    # started through rc.
    /usr/local/libexec/fips/fips-dns-teardown 2>/dev/null || true
$(pkg_sample_purge_script fips.yaml hosts)
fi
EOD
}
EOF

cat > "${STAGE}/pkg-plist" <<'EOF'
bin/fips
bin/fipsctl
bin/fipstop
etc/fips/fips.yaml.sample
etc/fips/hosts.sample
etc/rc.d/fips
etc/rc.d/fips_dns
libexec/fips/fips-dns-setup
libexec/fips/fips-dns-teardown
@dir etc/fips
EOF

# pkg create always names the file <name>-<version>.pkg; add the OS and
# arch so release assets stay distinct from the macOS .pkg files.
OUT="${PROJECT_ROOT}/deploy/fips-${VERSION}-freebsd-${ARCH}.pkg"

pkg_create_package "$STAGE" "${PROJECT_ROOT}/deploy" "$VERSION" "$OUT"
