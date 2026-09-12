#!/bin/sh
# Shared helpers for the FreeBSD-family package builders.
#
# packaging/freebsd/build-pkg.sh and packaging/pfsense/build-pkg.sh
# produce different packages for different systems, but the mechanics of
# getting there — deriving a pkg-legal version, locating the binaries,
# laying out the stage, and the manifest scripts that give the config
# files @sample semantics — are the same work, and were duplicated
# verbatim. They live here so a fix lands in both.
#
# What deliberately does NOT live here is anything the two packages
# disagree about: the boot script, the DNS integration, linkage, the ABI
# and product naming. Those differences are the reason there are two
# builders at all, and folding them into a shared file with flags would
# hide them.
#
# POSIX sh, sourced with `.` — no bashisms, no `local`.

# Print the version to stamp on the package, given the project root and
# an optional override (CI passes a derived version on branch builds).
#
# '-' is the pkg name/version separator and neither '-' nor '+' is legal
# inside a pkg version, so both map to '.': 0.6.0-dev -> 0.6.0.dev.
pkg_resolve_version() {
    pkg_rv_root="$1"
    pkg_rv_version="${2:-}"
    [ -n "$pkg_rv_version" ] \
        || pkg_rv_version="$(sed -n 's/^version = "\(.*\)"/\1/p' "${pkg_rv_root}/Cargo.toml" | head -1)"
    if [ -z "$pkg_rv_version" ]; then
        echo "error: could not read version from Cargo.toml" >&2
        return 1
    fi
    printf '%s\n' "$pkg_rv_version" | tr -- '+-' '..'
}

# The build host's pkg ABI, or a sane default where pkg cannot say.
pkg_host_abi() {
    pkg config abi 2>/dev/null || echo "FreeBSD:15:amd64"
}

# Fail unless every named binary is present and executable in $1.
pkg_require_binaries() {
    pkg_rb_dir="$1"
    shift
    for pkg_rb_bin in "$@"; do
        if [ ! -x "${pkg_rb_dir}/${pkg_rb_bin}" ]; then
            echo "error: ${pkg_rb_dir}/${pkg_rb_bin} missing (run without --no-build)" >&2
            return 1
        fi
    done
    return 0
}

# The directory skeleton both packages install into.
pkg_stage_tree() {
    install -d "$1/usr/local/bin" \
               "$1/usr/local/etc/fips" \
               "$1/usr/local/etc/rc.d" \
               "$1/usr/local/libexec/fips"
}

# Copy the named binaries from $1 into the stage at $2.
pkg_stage_binaries() {
    pkg_sb_dir="$1"
    pkg_sb_stage="$2"
    shift 2
    for pkg_sb_bin in "$@"; do
        install -m 0755 "${pkg_sb_dir}/${pkg_sb_bin}" "${pkg_sb_stage}/usr/local/bin/" || return 1
    done
    return 0
}

# Emit the post-install lines that copy a sample into place if the real
# file is absent. Arguments are "<name>:<mode>" pairs, e.g. fips.yaml:0600.
#
# This is the @sample plist keyword spelled out by hand: that keyword
# lives in the ports tree (/usr/ports/Keywords/sample.ucl), which neither
# a plain pkg-create host nor pfSense has.
#
# FreeBSD has no "root" group; wheel is gid 0.
pkg_sample_seed_script() {
    for pkg_ss_entry in "$@"; do
        pkg_ss_name="${pkg_ss_entry%%:*}"
        pkg_ss_mode="${pkg_ss_entry##*:}"
        cat <<EOS
[ -f /usr/local/etc/fips/${pkg_ss_name} ] || install -m ${pkg_ss_mode} -o root -g wheel \\
    /usr/local/etc/fips/${pkg_ss_name}.sample /usr/local/etc/fips/${pkg_ss_name}
EOS
    done
}

# Emit the pre-deinstall lines that remove a seeded config only when it
# is still byte-identical to the sample, so an edited config — and the
# identity it may carry — is never deleted. Arguments are bare names.
pkg_sample_purge_script() {
    printf '    for f in %s; do\n' "$*"
    cat <<'EOS'
        s="/usr/local/etc/fips/${f}.sample"
        t="/usr/local/etc/fips/${f}"
        if [ -f "$t" ] && cmp -s "$t" "$s"; then rm -f "$t"; fi
    done
EOS
}

# Run pkg-create(8) over a staged tree and move the result to $4.
#
# pkg create always names the file <name>-<version>.pkg; every caller
# wants something more specific, so the rename is part of the helper
# rather than repeated after it.
pkg_create_package() {
    pkg_cp_stage="$1"
    pkg_cp_deploy="$2"
    pkg_cp_version="$3"
    pkg_cp_out="$4"

    mkdir -p "$pkg_cp_deploy"
    echo "==> pkg create"
    pkg create -M "${pkg_cp_stage}/+MANIFEST" -p "${pkg_cp_stage}/pkg-plist" \
        -r "$pkg_cp_stage" -o "$pkg_cp_deploy" || return $?
    mv "${pkg_cp_deploy}/fips-${pkg_cp_version}.pkg" "$pkg_cp_out" || return $?

    echo "==> built:"
    ls -l "$pkg_cp_out"
}

# Emit the manifest fields both packages agree on, in the order
# pkg-create(8) expects: $1 version, $2 ABI, $3 comment, $4 description.
#
# Shared because they are shared *policy*, not merely duplicated text —
# origin, maintainer, licence and prefix describe one project, and two
# copies is two things to forget to update. Anything a package decides
# for itself (annotations, the scripts block) is appended by the caller
# after this.
pkg_manifest_header() {
    cat <<EOS
name: "fips"
version: "$1"
origin: "net/fips"
comment: "$3"
desc: <<EOD
$4
EOD
maintainer: "johnathan@corganlabs.com"
www: "https://fips.network"
abi: "$2"
prefix: "/usr/local"
licenselogic: "single"
licenses: ["MIT"]
categories: ["net"]
EOS
}

# The post-install lines creating the control-socket access group. Both
# packages create /var/run/fips as root:fips 0750 from their boot
# script, so members of this group can use fipsctl and fipstop without
# root; the group has to exist before either runs.
pkg_group_script() {
    cat <<'EOS'
pw groupshow fips >/dev/null 2>&1 || pw groupadd fips
EOS
}

# Build the release binaries. $1 project root, $2 optional Rust target
# triple — passing one keeps RUSTFLAGS off build scripts and proc-macros,
# and puts the output under target/<triple>/release.
pkg_cargo_build() {
    if [ -n "${2:-}" ]; then
        echo "==> cargo build --release --target $2"
        (cd "$1" && cargo build --release --target "$2")
    else
        echo "==> cargo build --release"
        (cd "$1" && cargo build --release)
    fi
}
