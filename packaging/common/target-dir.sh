# shellcheck shell=sh
# Where cargo put the binaries a package script is about to stage.
#
# Sourced, not run, by packaging/macos/build-pkg.sh,
# packaging/freebsd/build-pkg.sh and packaging/systemd/build-tarball.sh:
#   . "${PROJECT_ROOT}/packaging/common/target-dir.sh"
#   TARGET_DIR="$(target_dir "${PROJECT_ROOT}" "${BUILT}")" || exit 1
#   BINARY_DIR="${TARGET_DIR}/release"     # or ${TARGET_DIR}/<triple>/release
#
# POSIX sh, so the FreeBSD script can source it. Not installed by any package.
#
# cargo writes under its target directory, which CARGO_TARGET_DIR,
# CARGO_BUILD_TARGET_DIR or build.target-dir in any config.toml can move away
# from target/. A script that copies from a literal target/release after such
# a build stages whatever an older build left there, or fails with a missing
# binary when nothing is there.

# target_dir ROOT BUILT
#
# Prints the target directory for the workspace at ROOT.
#
# BUILT is 1 when the script has just run `cargo build`: the directory is
# then read from `cargo metadata`, which knows every way it can be moved, as
# packaging/openwrt-ipk/build-ipk.sh does. Read with sed, so a build host needs
# no jq or Python. Returns 1, with a message, when it cannot be read.
#
# cargo reads its config files from the directory it is run in, not from the
# manifest's, so a build.target-dir in ROOT/.cargo/config.toml is seen only
# from ROOT. The lookup therefore runs from ROOT, and so must the build that
# precedes it: each script builds with `cd ROOT && cargo build`. A build run
# from the caller's directory would land elsewhere whenever that directory
# sees different config, and the binaries staged would not be the ones built.
#
# BUILT is 0 for --no-build: the directory is ${CARGO_TARGET_DIR:-ROOT/target}
# and cargo is not run. The package workflows run their packaging steps with
# --no-build on hosts that may have no cargo, after placing the binaries under
# target/release themselves. A build.target-dir set in a cargo config file is
# not seen on this path; no config in the tree sets one.
target_dir() {
    _td_root="$1"
    _td_built="$2"
    if [ "$_td_built" -eq 1 ]; then
        _td_dir="$(cd "$_td_root" && cargo metadata --format-version 1 --no-deps \
            --manifest-path="${_td_root}/Cargo.toml" 2>/dev/null \
            | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')" || _td_dir=""
        if [ -z "$_td_dir" ] || [ ! -d "$_td_dir" ]; then
            echo "Error: could not read cargo's target directory from 'cargo metadata'" \
                "(got '$_td_dir')." >&2
            return 1
        fi
    else
        _td_dir="${CARGO_TARGET_DIR:-${_td_root}/target}"
    fi
    printf '%s\n' "$_td_dir"
}
