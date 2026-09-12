#!/bin/sh
# Build a pfSense .pkg package for FIPS using pkg-create(8).
#
# Usage: packaging/pfsense/build-pkg.sh [--version <v>] [--abi <abi>]
#                                      [--target <triple>] [--product <id>] [--dynamic] [--no-build]
#
# Links statically by default; --dynamic opts out. See the "Static
# linking is the default" section of packaging/pfsense/README.md.
#
# Prerequisites: the pinned Rust toolchain, pkg(8). Must run on FreeBSD:
# the binaries are native, and pkg create needs a FreeBSD host.
# Output: deploy/fips-<version>-pfsense-<products>-<arch>.pkg
#
# This is a sibling of packaging/freebsd/build-pkg.sh, not a replacement
# for it. pfSense is FreeBSD underneath, but it diverges in the four
# places a package touches:
#
#   - Boot. pfSense's rc.start_packages globs /usr/local/etc/rc.d/*.sh
#     and runs each as `<script> start`. The FreeBSD package's
#     rc.d/fips has no .sh suffix and gates on an /etc/rc.conf variable,
#     so on pfSense it would never start.
#   - DNS. pfSense generates unbound.conf from config.xml and reads no
#     conf.d directory, so the FreeBSD package's drop-in is inert here.
#     This package integrates through the DNS Resolver custom options.
#   - The responder's bind address, for the reason recorded in
#     fips.yaml.dns.
#   - Lifetime. A pfSense firmware upgrade reinstalls the base image and
#     takes third-party packages with it, so post-install says so.
#
# Ships fips, fipsctl and fipstop. fips-gateway is excluded: its NAT
# backend is nftables (Linux-only), and pfSense has pf for that anyway.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Mechanics shared with the FreeBSD builder: version derivation, the
# stage layout, the @sample manifest scripts, and pkg create.
. "${PROJECT_ROOT}/packaging/common/pkg-lib.sh"

NO_BUILD=0
VERSION=""
ABI_OVERRIDE=""
STATIC=1
PRODUCT=""
TARGET=""
while [ $# -gt 0 ]; do
    case "$1" in
        --no-build) NO_BUILD=1 ;;
        --static) STATIC=1 ;;   # the default, spelled out
        --dynamic) STATIC=0 ;;
        --product) PRODUCT="${2:?--product requires an argument}"; shift ;;
        --version) VERSION="${2:?--version requires an argument}"; shift ;;
        --abi) ABI_OVERRIDE="${2:?--abi requires an argument}"; shift ;;
        --target) TARGET="${2:?--target requires an argument}"; shift ;;
        *)
            echo "usage: $0 [--version <version>] [--abi <abi>] [--target <triple>] [--product <id>] [--dynamic] [--no-build]" >&2
            exit 1
            ;;
    esac
    shift
done

# CI passes a derived version that appends +<branch>.<height>.<hash> on
# branch builds; otherwise the version comes from Cargo.toml.
VERSION="$(pkg_resolve_version "$PROJECT_ROOT" "$VERSION")"

if [ -n "$ABI_OVERRIDE" ]; then
    ABI="$ABI_OVERRIDE"
else
    ABI="$(pkg_host_abi)"
fi
ABI_MAJOR="$(printf '%s' "$ABI" | awk -F: '{print $2}')"
ARCH="${ABI##*:}"

# --- Which pfSense this is for --------------------------------------
#
# The filename names the pfSense product(s), not the FreeBSD ABI, because
# that is what the person choosing a download knows: "I run Plus 26.03 on
# a 4200", not "I need FreeBSD:16:aarch64". pkg still enforces the ABI,
# which the manifest carries; the name is wayfinding.
#
# One ABI can serve more than one product. CE 2.9 and Plus 26.x are both
# FreeBSD 16 on amd64 and the artifact is byte-identical, so the name
# carries every supported product the package installs on. The mapping is
# therefore ABI -> products: the ABI is what gets built, the products are
# what people look for.
#
# Supported releases as of 2026-09, from Netgate's version table:
#
#   CE 2.8.1       FreeBSD 15   amd64
#   CE 2.9.0       FreeBSD 16   amd64
#   Plus 26.03.1   FreeBSD 16   amd64, aarch64
#   Plus 26.07     FreeBSD 16   amd64, aarch64
#
# CE has only ever shipped for amd64, and Netgate has said there are no
# plans for an ARM CE image. Plus 24.x and 25.07 (FreeBSD 15) and 25.11
# (FreeBSD 16) are end-of-life and deliberately absent: a package named
# for an unsupported release is an invitation to install it there.
#
# Verify against https://docs.netgate.com/pfsense/en/latest/releases/versions.html
# when a release moves, and change this table in the same commit.
abi_products() {
    case "$1" in
        FreeBSD:15:amd64)   echo "ce2.8" ;;
        FreeBSD:16:amd64)   echo "ce2.9 plus26" ;;
        FreeBSD:16:aarch64) echo "plus26" ;;
        *)                  echo "" ;;
    esac
}

PRODUCTS="$(abi_products "$ABI")"
if [ -z "$PRODUCTS" ]; then
    echo "error: no supported pfSense release runs on ${ABI}." >&2
    case "$ABI" in
        FreeBSD:15:aarch64)
            echo "error: The ARM releases on FreeBSD 15 (Plus 24.x, 25.07) are end-of-" >&2
            echo "error: life. Plus 26.x on ARM is FreeBSD:16:aarch64." >&2
            ;;
        *)
            echo "error: If Netgate has shipped a release on this base, add it to the" >&2
            echo "error: table in $0 in the same change, so the next build does not" >&2
            echo "error: have to guess." >&2
            ;;
    esac
    exit 1
fi

# --product is an assertion, not a selector. The artifact serves every
# product listed for its ABI whatever is passed, so the name always
# carries them all; --product says "I believe I am building for X", and
# the build refuses when X is not among them — which is how an ABI
# chosen for the wrong release gets caught before anything is packaged.
if [ -n "$PRODUCT" ]; then
    product_ok=0
    for known_product in $PRODUCTS; do
        [ "$known_product" = "$PRODUCT" ] && product_ok=1
    done
    if [ "$product_ok" -eq 0 ]; then
        echo "error: --product ${PRODUCT} does not run on ${ABI}, which serves: ${PRODUCTS}." >&2
        case "$PRODUCT" in
            ce2.8 | ce2.9)
                echo "error: CE ships for amd64 only: CE 2.8 is FreeBSD 15, CE 2.9 is FreeBSD 16." >&2 ;;
            plus26)
                echo "error: Plus 26.x is FreeBSD 16, on amd64 or aarch64." >&2 ;;
            *)
                echo "error: Known products: ce2.8, ce2.9, plus26." >&2 ;;
        esac
        exit 1
    fi
fi

# The filename tag: every product this ABI serves, joined with '-'.
PRODUCT_TAG="$(printf '%s' "$PRODUCTS" | tr ' ' '-')"

# Where cargo leaves the binaries. `--target` puts them one level deeper,
# and is also the flag that says this is not a host build.
if [ -n "$TARGET" ]; then
    BIN_DIR="${PROJECT_ROOT}/target/${TARGET}/release"
else
    BIN_DIR="${PROJECT_ROOT}/target/release"
fi

# --- Static linking -------------------------------------------------
#
# pfSense runs a FreeBSD base you cannot obtain: Netgate builds Plus
# from a 16.0-CURRENT snapshot of their own, and download.freebsd.org
# keeps only the last two CURRENT builds. So the build host's libc is
# almost always *newer* than the appliance's, which is the direction
# that breaks: a binary can reference a versioned libc symbol the
# appliance does not export, install cleanly, and then refuse to start.
#
# Linking statically removes the negotiation entirely — there is no
# libc.so.7 to disagree with. What is left is the kernel syscall ABI,
# which is stable within a FreeBSD major.
#
# Verified viable on this codebase: no dlopen/libloading anywhere, and
# FreeBSD builds files+dns resolution into libc, so a static binary
# still resolves hostnames (the thing that defeats static glibc).
if [ "$STATIC" -eq 1 ]; then
    # RUSTFLAGS must not reach build scripts and proc-macros, which run
    # on the build host; passing --target is what confines it.
    if [ -z "$TARGET" ]; then
        TARGET="$(rustc -vV | sed -n 's/^host: //p')"
        [ -n "$TARGET" ] || { echo "error: could not determine host target triple" >&2; exit 1; }
        BIN_DIR="${PROJECT_ROOT}/target/${TARGET}/release"
        echo "==> static build for host target ${TARGET}"
    fi
    RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static"
    export RUSTFLAGS
fi

# The package's arch has to describe the binaries in it, and nothing
# downstream checks that: pkg believes the ABI string in the manifest, so
# a mislabelled package installs on the appliance and then cannot exec.
# Cross-check the two here, where it is still cheap.
#
# pkg's arch names are not the Rust triple's: amd64 is x86_64, and only
# aarch64 spells itself the same in both.
case "$TARGET" in
    "")             expected_arch="$ARCH" ;;  # host build: nothing to cross-check
    aarch64-*freebsd*) expected_arch="aarch64" ;;
    x86_64-*freebsd*)  expected_arch="amd64" ;;
    i686-*freebsd*)    expected_arch="i386" ;;
    *)
        echo "error: --target ${TARGET} is not a FreeBSD target triple." >&2
        echo "error: This package can only be built for FreeBSD-based systems." >&2
        exit 1
        ;;
esac
if [ "$expected_arch" != "$ARCH" ]; then
    echo "error: --target ${TARGET} produces ${expected_arch} binaries, but the" >&2
    echo "error: ABI says ${ARCH} (${ABI}). Pass a matching --abi, e.g.:" >&2
    echo "error:     --target ${TARGET} --abi FreeBSD:${ABI_MAJOR}:${expected_arch}" >&2
    exit 1
fi

# pkg refuses a package whose ABI does not match the running system, in
# both the FreeBSD major and the architecture, so the build has to be
# aimed at the target's base rather than at the build host's.
#
#   pfSense CE 2.8.1    FreeBSD 15, amd64      -> FreeBSD:15:amd64
#   pfSense CE 2.9.0    FreeBSD 16, amd64      -> FreeBSD:16:amd64
#   pfSense Plus 26.x   FreeBSD 16, amd64      -> FreeBSD:16:amd64
#   pfSense Plus 26.x   FreeBSD 16, ARM        -> FreeBSD:16:aarch64
#
# The mapping moves between releases; check it against the target before
# building, and confirm on the appliance with `pkg config abi`.
HOST_ABI="$(pkg config abi 2>/dev/null || echo "unknown")"
if [ "$ABI" != "$HOST_ABI" ]; then
    echo "warning: building for ${ABI}, but this host is ${HOST_ABI}." >&2
    echo "warning: The binaries must genuinely be ${ARCH} and must link against" >&2
    echo "warning: the target's base libraries — an ABI string alone does not" >&2
    echo "warning: make an amd64 binary run on ARM. Verify with:" >&2
    echo "warning:     file ${BIN_DIR}/fips" >&2
    echo "warning: Target mapping: https://docs.netgate.com/pfsense/en/latest/releases/versions.html" >&2
fi

# --- Toolchain provenance -------------------------------------------
#
# rust-toolchain.toml pins an exact compiler, and rustup honours it
# wherever rustup has binaries. aarch64 FreeBSD is not such a place:
#
#   rustup target add aarch64-unknown-freebsd
#     -> no prebuilt artifacts available for target
#   (and on the platform itself)
#     -> installer for platform 'aarch64-unknown-freebsd' not found
#
# so an ARM build uses the ports Rust, and the ports cargo ignores
# rust-toolchain.toml entirely. The pin is therefore not a property
# every build of this package has. Rather than let that be silent, the
# version actually used is checked here and recorded in the package.
RUST_VERSION="$(rustc --version 2>/dev/null | awk '{print $2}')"
[ -n "$RUST_VERSION" ] \
    || { echo "error: no rustc on PATH" >&2; exit 1; }
PINNED_VERSION="$(sed -n 's/.*channel *= *"\([^"]*\)".*/\1/p' \
    "${PROJECT_ROOT}/rust-toolchain.toml" 2>/dev/null | head -1)"

# True when $1 is strictly older than $2, comparing dotted numerics.
version_lt() {
    [ "$1" != "$2" ] || return 1
    [ "$(printf '%s\n%s\n' "$1" "$2" \
        | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$1" ]
}

# Edition 2024 needs 1.85. Below it the build dies deep inside a
# dependency with a message that never names the real cause, so refuse
# up front where the error can say what is wrong.
if version_lt "$RUST_VERSION" "1.85.0"; then
    echo "error: rustc ${RUST_VERSION} is below the edition-2024 floor (1.85.0)." >&2
    echo "error: This crate cannot be built with it." >&2
    exit 1
fi

PIN_HONOURED="yes"
if [ -n "$PINNED_VERSION" ] && [ "$RUST_VERSION" != "$PINNED_VERSION" ]; then
    PIN_HONOURED="no"
    echo "notice: rustc ${RUST_VERSION} is NOT the pinned ${PINNED_VERSION}." >&2
    echo "notice: rust-toolchain.toml pins ${PINNED_VERSION}; this build does not" >&2
    echo "notice: honour it. Expected on aarch64, where rustup ships no toolchain;" >&2
    echo "notice: unexpected anywhere rustup works, and worth investigating there." >&2
    echo "notice: The package records this — see 'pkg info -A'." >&2
fi

# Where the compiler came from, when it came from ports (ARM). Pinning
# the ports package version is the only reproducibility available on a
# platform rustup does not serve.
RUST_PKG="$(pkg info -q rust 2>/dev/null | head -1)"

# Static linking is unusable on aarch64 FreeBSD, so the default does not
# apply there. A statically linked aarch64 binary faults at addr=0x0
# exactly where posix_spawn should be, killing the process the first time
# it spawns anything:
#
#   openat("/dev/null", O_RDONLY|O_CLOEXEC) = 9
#   pipe2() = 0
#   pipe2() = 0
#   SIGNAL 11 (SIGSEGV) code=SEGV_MAPERR addr=0x0
#
# The same trace on static amd64 reaches rfork(RFSPAWN) and spawns
# normally, so this is specific to the architecture, not to static
# linking. FIPS spawns sysctl in is_ipv6_disabled() at the top of
# TunDevice::create, so the daemon dies during TUN setup and looks like a
# TUN bug; with tun.enabled false it never spawns and appears healthy.
#
# Refused rather than silently downgraded: a package that quietly linked
# differently from what was asked is how the wrong artifact ships.
if [ "$STATIC" -eq 1 ] && [ "$ARCH" = "aarch64" ]; then
    echo "error: --static is not supported on aarch64: a statically linked" >&2
    echo "error: aarch64 FreeBSD binary segfaults at posix_spawn, so the daemon" >&2
    echo "error: dies the first time it shells out (sysctl, during TUN setup)." >&2
    echo "error: Build with --dynamic and check ldd on the target, since that" >&2
    echo "error: reintroduces the base-drift exposure static linking removes." >&2
    exit 1
fi

if [ "$NO_BUILD" -eq 0 ]; then
    pkg_cargo_build "$PROJECT_ROOT" "$TARGET"
fi

pkg_require_binaries "$BIN_DIR" fips fipsctl fipstop

# crt-static is a request, not a guarantee: a target that does not
# respect it still links dynamically and says nothing. Shipping a
# dynamic binary while believing it static would put back exactly the
# drift this flag exists to remove, so check the artifact, not the flag.
if [ "$STATIC" -eq 1 ]; then
    for bin in fips fipsctl fipstop; do
        if ! file -b "${BIN_DIR}/${bin}" | grep -q 'statically linked'; then
            echo "error: --static was requested but ${bin} is not statically linked:" >&2
            echo "error:     $(file -b "${BIN_DIR}/${bin}")" >&2
            exit 1
        fi
    done
    echo "==> verified: all three binaries are statically linked"
fi


# The ABI in the manifest is an assertion about the binaries, and pkg
# believes it without looking. Check it against what is actually in
# BIN_DIR, on every build.
#
# The --target cross-check above cannot cover this: it compares the
# requested triple with the requested ABI, so a host build that names a
# foreign ABI (`--abi FreeBSD:15:aarch64` with no --target) passes it and
# then packages the host's binaries under a foreign arch. That produces
# a package which installs on the appliance and cannot exec — the exact
# failure the naming rules exist to prevent. check-pfsense-pkg.sh catches
# it, but only if someone runs it; the build should not emit it at all.
case "$ARCH" in
    amd64)   arch_signature="x86-64" ;;
    aarch64) arch_signature="aarch64" ;;
    i386)    arch_signature="Intel 80386" ;;
    *)       arch_signature="" ;;
esac
if [ -n "$arch_signature" ]; then
    binary_description="$(file -b "${BIN_DIR}/fips" 2>/dev/null)"
    case "$binary_description" in
        *"$arch_signature"*) ;;
        *)
            echo "error: the ABI says ${ARCH} (${ABI}), but ${BIN_DIR}/fips is not:" >&2
            echo "error:     ${binary_description}" >&2
            echo "error: pkg trusts the manifest, so this package would install on" >&2
            echo "error: the appliance and then fail to exec. Build for ${ARCH}, or" >&2
            echo "error: correct --abi." >&2
            exit 1
            ;;
    esac
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/fips-pfsense-pkg.XXXXXX")"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/fips-pfsense-work.XXXXXX")"
trap 'rm -rf "$STAGE" "$WORK"' EXIT

echo "==> staging into ${STAGE}"
pkg_stage_tree "$STAGE"
pkg_stage_binaries "$BIN_DIR" "$STAGE" fips fipsctl fipstop

# --- Configuration sample -------------------------------------------
#
# The shipped config is the common default with its `dns:` block
# replaced by the pfSense one in fips.yaml.dns (which records why the
# responder binds IPv4 loopback here). Everything else — identity,
# transports, peers — is tracked from packaging/common/fips.yaml like
# every other platform's package, so it does not drift.
#
# Owning one block silently would hide a new dns option added upstream,
# so the key set of the common block is checked first: anything beyond
# what fips.yaml.dns already accounts for fails the build.
COMMON_CONFIG="${PROJECT_ROOT}/packaging/common/fips.yaml"
DNS_BLOCK="${SCRIPT_DIR}/fips.yaml.dns"
STAGED_CONFIG="${STAGE}/usr/local/etc/fips/fips.yaml.sample"

# Active (uncommented) keys in the common config's dns block. bind_addr
# is commented out there, so it is deliberately not in this list.
EXPECTED_DNS_KEYS="enabled port"

actual_dns_keys="$(awk '
    /^[^[:space:]#]/ { section = $1; sub(/:.*/, "", section); next }
    section != "dns" { next }
    /^[[:space:]]*#/ { next }
    /^[[:space:]]+[a-z_]+:/ {
        key = $1; sub(/:.*/, "", key); print key
    }
' "$COMMON_CONFIG" | tr '\n' ' ' | sed 's/ *$//')"

if [ "$actual_dns_keys" != "$EXPECTED_DNS_KEYS" ]; then
    echo "error: the dns: block in ${COMMON_CONFIG} has changed." >&2
    echo "error:   expected keys: ${EXPECTED_DNS_KEYS}" >&2
    echo "error:   found keys:    ${actual_dns_keys}" >&2
    echo "error: This package substitutes its own dns: block, so a new or" >&2
    echo "error: renamed option there would be dropped silently. Fold the" >&2
    echo "error: change into ${DNS_BLOCK} and update EXPECTED_DNS_KEYS." >&2
    exit 1
fi

# Splice: copy the common config, replacing the top-level dns: block.
# Skipping runs until the next top-level key, so the blank and indented
# lines inside the block go with it.
awk -v blockfile="$DNS_BLOCK" '
    BEGIN {
        while ((getline line < blockfile) > 0) { block = block line "\n" }
        if (block == "") { print "error: dns block file is empty" > "/dev/stderr"; exit 1 }
    }
    /^dns:[[:space:]]*$/ { replaced++; printf "%s", block; skipping = 1; next }
    skipping && /^[^[:space:]#]/ { skipping = 0 }
    skipping { next }
    { print }
    END {
        if (replaced != 1) {
            printf "error: replaced %d dns: blocks, expected exactly 1\n", replaced > "/dev/stderr"
            exit 1
        }
    }
' "$COMMON_CONFIG" > "${WORK}/fips.yaml"

# Belt and braces: the staged config must actually carry the pfSense
# bind address, and must not still carry the ::1 default.
grep -Fqx '  bind_addr: "127.0.0.1"' "${WORK}/fips.yaml" || {
    echo "error: staged config is missing the pfSense dns.bind_addr line" >&2
    exit 1
}

# fips.yaml may hold a node private key (nsec:), so it is never
# world-readable — 0600, like the Debian, macOS and FreeBSD packages.
install -m 0600 "${WORK}/fips.yaml" "$STAGED_CONFIG"

install -m 0644 "${PROJECT_ROOT}/packaging/common/hosts" \
                "${STAGE}/usr/local/etc/fips/hosts.sample"
install -m 0644 "${SCRIPT_DIR}/fips.conf" \
                "${STAGE}/usr/local/etc/fips/fips.conf.sample"
# Not a .sample: it is the source fips.sh copies into
# /var/etc/newsyslog.conf.d at every start, never edited in place.
install -m 0644 "${SCRIPT_DIR}/fips.newsyslog" \
                "${STAGE}/usr/local/etc/fips/fips.newsyslog"

install -m 0755 "${SCRIPT_DIR}/fips.sh" "${STAGE}/usr/local/etc/rc.d/fips.sh"

install -m 0755 "${SCRIPT_DIR}/fips-dns-setup" \
                "${SCRIPT_DIR}/fips-dns-teardown" \
                "${STAGE}/usr/local/libexec/fips/"
install -m 0644 "${SCRIPT_DIR}/fips-unbound-custom.php" \
                "${STAGE}/usr/local/libexec/fips/"

# Record what produced this package, in the package. "Which compiler
# built this, and is it statically linked?" should be answerable from
# the artifact via `pkg info -A fips`, not from the memory of whoever
# ran the build — especially on aarch64, where the answer is not the
# pinned toolchain.
LINKAGE="dynamic"
[ "$STATIC" -eq 1 ] && LINKAGE="static"
ANNOTATIONS="  pfsense_products: \"${PRODUCTS}\"
  built_with: \"rustc ${RUST_VERSION}\"
  toolchain_pin: \"${PINNED_VERSION:-unset}\"
  pin_honoured: \"${PIN_HONOURED}\"
  linkage: \"${LINKAGE}\""
if [ -n "$RUST_PKG" ]; then
    ANNOTATIONS="${ANNOTATIONS}
  rust_pkg: \"${RUST_PKG}\""
fi

DESC="$(cat "${SCRIPT_DIR}/pkg-descr")"

# The config files get @sample semantics — copied into place on install
# if absent, removed on deinstall only if unmodified — but spelled out as
# manifest scripts: the @sample plist keyword lives in the ports tree
# (/usr/ports/Keywords/sample.ucl), which neither a plain pkg-create
# host nor pfSense itself has.
cat > "${STAGE}/+MANIFEST" <<EOF
$(pkg_manifest_header "$VERSION" "$ABI" "Self-organizing encrypted mesh network on Nostr identities (pfSense build)" "$DESC")
annotations: {
${ANNOTATIONS}
}
scripts: {
  post-install: <<EOD
# Control-socket access group: fips.sh creates /var/run/fips as
# root:fips 0750, so members can use fipsctl/fipstop without root.
$(pkg_group_script)
# Install-if-absent config. fips.yaml may hold a node private key
# (nsec:), so it is 0600; FreeBSD has no "root" group, wheel is gid 0.
$(pkg_sample_seed_script fips.yaml:0600 hosts:0644 fips.conf:0644)
# pkg upgrade runs the old package's pre-deinstall, which stops the
# daemon and leaves this marker if it had been running. Bring it back up
# on the new binaries, and only then.
if [ -f /var/run/fips/upgrade-restart ]; then
    rm -f /var/run/fips/upgrade-restart
    /usr/local/etc/rc.d/fips.sh onestart >/dev/null 2>&1 || true
fi
if [ "\${PKG_UPGRADE:-}" != "true" ]; then
    echo ""
    echo "FIPS installed. To finish:"
    echo "  1. vi /usr/local/etc/fips/fips.yaml       # identity and peers"
    echo "  2. /usr/local/etc/rc.d/fips.sh start"
    echo "  3. /usr/local/libexec/fips/fips-dns-setup # .fips in the DNS Resolver"
    echo ""
    echo "Step 3 edits config.xml, so it is not run for you. It is"
    echo "revertable from Diagnostics > Backup & Restore > Config History."
    echo ""
    echo "The mesh needs 'Allow IPv6' (System > Advanced > Networking),"
    echo "which is on by default. If it has been turned off, pfSense blocks"
    echo "all IPv6 and the fd00::/8 mesh cannot pass traffic even though"
    echo ".fips still resolves — see the README."
    echo ""
    echo "Not a Netgate-supported package. A firmware upgrade keeps it"
    echo "(it is not a pfSense-pkg-*); after a major upgrade, reinstall the"
    echo "package built for the new base. To upgrade the package itself use"
    echo "'pkg install ./<file>.pkg', then 'fips.sh restart'."
fi
EOD
  pre-deinstall: <<EOD
# Stop the daemon so its binary is never replaced (upgrade) or removed
# (deinstall) underneath a running process, and remember whether it was
# running so post-install can restore that state on upgrade.
if /usr/local/etc/rc.d/fips.sh status >/dev/null 2>&1; then
    if [ "\${PKG_UPGRADE:-}" = "true" ]; then
        mkdir -p /var/run/fips && touch /var/run/fips/upgrade-restart
    fi
fi
/usr/local/etc/rc.d/fips.sh stop >/dev/null 2>&1 || true
if [ "\${PKG_UPGRADE:-}" != "true" ]; then
    # Removal: take the .fips block back out of config.xml. Left behind,
    # it would forward the fips. zone to a port nothing listens on.
    if ! /usr/local/libexec/fips/fips-dns-teardown; then
        echo "fips: the .fips block is still in the DNS Resolver custom options;"
        echo "fips: remove it by hand under Services > DNS Resolver > Custom options,"
        echo "fips: or the fips. zone stays forwarded to a port nothing listens on."
    fi
$(pkg_sample_purge_script fips.yaml hosts fips.conf)
fi
EOD
}
EOF

cat > "${STAGE}/pkg-plist" <<'EOF'
bin/fips
bin/fipsctl
bin/fipstop
etc/fips/fips.conf.sample
etc/fips/fips.newsyslog
etc/fips/fips.yaml.sample
etc/fips/hosts.sample
etc/rc.d/fips.sh
libexec/fips/fips-dns-setup
libexec/fips/fips-dns-teardown
libexec/fips/fips-unbound-custom.php
@dir etc/fips
EOF

OUT="${PROJECT_ROOT}/deploy/fips-${VERSION}-pfsense-${PRODUCT_TAG}-${ARCH}.pkg"

pkg_create_package "$STAGE" "${PROJECT_ROOT}/deploy" "$VERSION" "$OUT"
