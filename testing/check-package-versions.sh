#!/bin/bash
# ── Package version derivation check ────────────────────────────────────────
# A release candidate is tagged vX.Y.Z-rcN, because git refuses '~' in a ref
# name. dpkg reads X.Y.Z-rcN as revision rcN of X.Y.Z and sorts it ABOVE the
# release, so a host that installed the candidate is never upgraded by the
# release. package-linux.yml's "Derive Linux package version" step therefore
# maps the tag's pre-release suffix to '~' for the .deb, which dpkg sorts below.
#
# This runs that step's own text, taken from the workflow, rather than a copy,
# so the check and the workflow cannot drift apart.
#
# Debian cases:
#   refs/tags/v0.5.3      both versions 0.5.3
#   refs/tags/v0.5.3-rc1  deb 0.5.3~rc1, tarball and artifact 0.5.3-rc1, and
#                         dpkg orders 0.5.2 < 0.5.3~rc1 < 0.5.3
#   refs/heads/maint      deb equals the tarball version, which is
#                         <Cargo version>+maint.<height>.<hash>
#
# It also checks the wiring the derivation needs to have any effect: the job
# declares the deb_package_version output, the .deb build passes it as
# --version, and that step renames a '~' in the package file name to '-' (a
# GitHub release renames an asset with special characters in its name, which
# would leave checksums-linux.txt naming a file the release does not have).
# Those three are read from the text, not executed.
#
# OpenWrt's opkg compares versions with dpkg's algorithm (libopkg/pkg.c
# verrevcmp in openwrt/opkg-lede, read at 80503d94) and splits a revision at
# the last '-', so the .ipk has the same defect. package-openwrt.yml's "Derive
# package version" step maps the tag for the .ipk control Version, keeping the
# leading 'v' every released .ipk carries: under opkg, 0.5.4 sorts below
# v0.5.3, so dropping it would stop releases upgrading. dpkg stands in for
# opkg as the ordering oracle; it warns about the 'v' and still compares.
#
# ipk cases:
#   refs/tags/v0.5.3      package_version and ipk_version v0.5.3
#   refs/tags/v0.5.3-rc1  ipk_version v0.5.3~rc1, package_version (the file
#                         label) v0.5.3-rc1, and v0.5.2 < v0.5.3~rc1 < v0.5.3
#                         < v0.5.4
#   refs/tags/v0.5.3-beta1  ipk_version v0.5.3~beta1, which sorts between
#                         v0.5.2 and v0.5.3~rc1
#   refs/heads/maint      ipk_version equals package_version
# and the wiring: the job declares ipk_version, and the "Build .ipk" step
# passes it as IPK_VERSION. build-ipk.sh's use of IPK_VERSION is executed by
# testing/openwrt/package-test.sh.
#
# Exit 0 = clean. Exit 1 = a case or a wiring check failed, including a
# derivation that ran but did not write a declared output. Exit 2 = the check
# could not run (no dpkg, no PyYAML, a step not found, the derivation failed,
# or dpkg could not compare); never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKFLOWS="$PROJECT_ROOT/.github/workflows"

cant() {
    echo "check-package-versions: $*; cannot verify the package version derivation" >&2
    exit 2
}

# missing <tool> <message>: like cant, then names the package that provides
# the tool. The helper is sourced only here, and only if it is there.
missing() {
    echo "check-package-versions: $2; cannot verify the package version derivation" >&2
    if [ -r "$SCRIPT_DIR/lib/tool-hint.sh" ]; then
        # shellcheck source=/dev/null
        . "$SCRIPT_DIR/lib/tool-hint.sh"
        local hint
        hint="$(tool_hint "$1")" && echo "check-package-versions: $hint" >&2
    fi
    exit 2
}

command -v dpkg >/dev/null 2>&1 || missing dpkg "dpkg not found"
command -v python3 >/dev/null 2>&1 || missing python3 "python3 not found"
python3 -c "import yaml" >/dev/null 2>&1 || missing yaml "python3 module 'yaml' not found"

WORK=$(mktemp -d) || cant "mktemp failed"
trap 'rm -rf "$WORK"' EXIT

# Pull a derivation step's run text, its job's declared outputs, and a build
# step's env block and run text out of a workflow, into
# $WORK/<prefix>.derive.sh, <prefix>.outputs and <prefix>.build.sh.
# Usage: extract <prefix> <workflow file> <job> <derive step> <build job> <build step>
extract() {
    local prefix="$1" workflow="$WORKFLOWS/$2"
    [ -f "$workflow" ] || cant "missing $workflow"
    python3 - "$workflow" "$WORK" "$prefix" "$3" "$4" "$5" "$6" <<'PY' || exit 2
import sys
from pathlib import Path

import yaml

workflow, work, prefix, job, derive_name, build_job, build_name = sys.argv[1:]
work = Path(work)
doc = yaml.safe_load(Path(workflow).read_text(encoding="utf-8"))
jobs = doc.get("jobs") or {}


def find_step(job, name):
    for step in (jobs.get(job) or {}).get("steps") or []:
        if step.get("name") == name:
            return step
    return None


derive = find_step(job, derive_name)
build = find_step(build_job, build_name)
for label, step in (("derivation", derive), ("build", build)):
    if not step or not step.get("run"):
        print(f"check-package-versions: the {label} step was not found in {workflow}",
              file=sys.stderr)
        sys.exit(2)
(work / f"{prefix}.derive.sh").write_text(derive["run"], encoding="utf-8")
env = build.get("env") or {}
(work / f"{prefix}.build.sh").write_text(
    "".join(f"{k}: {v}\n" for k, v in env.items()) + build["run"],
    encoding="utf-8")
outputs = (jobs.get(job) or {}).get("outputs") or {}
(work / f"{prefix}.outputs").write_text(
    "".join(f"{k}={v}\n" for k, v in outputs.items()), encoding="utf-8")
PY
}

FAILED=0
ok()  { echo "  PASS  $*"; }
bad() { echo "  FAIL  $*"; FAILED=$((FAILED + 1)); }

# Run a derivation step for one ref and load the named outputs into OUT.
# Exits 2 when the step itself fails: no version was established. A step that
# runs but does not write a declared output is a failed check rather than a
# harness failure, so it is recorded and the output is left empty.
# Usage: derive <prefix> <ref> <output name>...
declare -A OUT
derive() {
    local prefix="$1" ref="$2" out="$WORK/github_output" name
    shift 2
    : > "$out"
    if ! (cd "$PROJECT_ROOT" && GITHUB_OUTPUT="$out" GITHUB_REF="$ref" \
            GITHUB_REF_NAME="${ref#refs/*/}" bash -eo pipefail "$WORK/$prefix.derive.sh") >"$WORK/derive.log" 2>&1; then
        echo "check-package-versions: the $prefix derivation failed for $ref:" >&2
        cat "$WORK/derive.log" >&2
        exit 2
    fi
    for name in "$@"; do
        OUT[$name]=$(sed -n "s/^$name=//p" "$out")
        if [ -z "${OUT[$name]}" ]; then
            bad "the $prefix derivation for $ref did not write $name"
        fi
    done
    return 0
}

# Record whether dpkg orders $1 $2 $3 (lt, gt, ...). An empty version is a
# failed case, because dpkg would compare it and sort it below everything.
expect_order() {
    local rc=0
    if [ -z "$1" ] || [ -z "$3" ]; then
        bad "dpkg: no version to compare ('$1' $2 '$3')"
        return 0
    fi
    dpkg --compare-versions "$1" "$2" "$3" 2>"$WORK/dpkg.err" || rc=$?
    case $rc in
        0) ok "dpkg: $1 $2 $3" ;;
        1) bad "dpkg: $1 $2 $3 does not hold" ;;
        *) cat "$WORK/dpkg.err" >&2
           cant "dpkg could not compare $1 $2 $3 (exit $rc)" ;;
    esac
    return 0
}

# Record whether a derived version equals the expected one.
expect_eq() {
    local label="$1" got="$2" want="$3"
    if [ "$got" = "$want" ]; then
        ok "$label: $got"
    else
        bad "$label: '$got' (want $want)"
    fi
    return 0
}

# Record whether extracted workflow text contains a fixed string. With -x the
# string must be a whole line.
# Usage: expect_text [-x] <file> <text> <description>
expect_text() {
    local flags=-qF
    if [ "$1" = -x ]; then flags=-qxF; shift; fi
    if grep "$flags" -- "$2" "$1"; then
        ok "$3"
    else
        bad "not so: $3"
    fi
    return 0
}

CRATE=$(awk -F'"' '/^version = /{print $2; exit}' "$PROJECT_ROOT/Cargo.toml")
HEIGHT=$(git -C "$PROJECT_ROOT" rev-list --count HEAD) || cant "git rev-list failed"
HASH=$(git -C "$PROJECT_ROOT" rev-parse --short HEAD) || cant "git rev-parse failed"
[ -n "$CRATE" ] || cant "no version in Cargo.toml"

# ── Debian .deb, package-linux.yml ──────────────────────────────────────────
extract deb package-linux.yml determine-versioning "Derive Linux package version" \
    build "Build Debian package in the pinned container"

echo "Debian: release tag refs/tags/v0.5.3"
derive deb refs/tags/v0.5.3 linux_package_version deb_package_version
expect_eq "linux_package_version" "${OUT[linux_package_version]}" "0.5.3"
expect_eq "deb_package_version" "${OUT[deb_package_version]}" "0.5.3"

echo "Debian: candidate tag refs/tags/v0.5.3-rc1"
derive deb refs/tags/v0.5.3-rc1 linux_package_version deb_package_version
expect_eq "linux_package_version" "${OUT[linux_package_version]}" "0.5.3-rc1"
expect_eq "deb_package_version" "${OUT[deb_package_version]}" "0.5.3~rc1"
expect_order "${OUT[deb_package_version]}" lt 0.5.3
expect_order "${OUT[deb_package_version]}" gt 0.5.2

echo "Debian: branch refs/heads/maint"
derive deb refs/heads/maint linux_package_version deb_package_version
expect_eq "linux_package_version" "${OUT[linux_package_version]}" "${CRATE}+maint.${HEIGHT}.${HASH}"
expect_eq "deb_package_version" "${OUT[deb_package_version]}" "${OUT[linux_package_version]}"

echo "Debian: wiring"
# shellcheck disable=SC2016  # the ${{ }} expressions are workflow text, not shell
expect_text -x "$WORK/deb.outputs" \
    'deb_package_version=${{ steps.linux_version.outputs.deb_package_version }}' \
    "determine-versioning declares deb_package_version from the derivation step"
# shellcheck disable=SC2016
expect_text "$WORK/deb.build.sh" \
    '--version "${{ needs.determine-versioning.outputs.deb_package_version }}"' \
    "the .deb build passes deb_package_version as --version"
expect_text "$WORK/deb.build.sh" "tr '~' '-'" \
    "the .deb build renames a '~' in the package file name"

# ── OpenWrt .ipk, package-openwrt.yml ─────────────────────────────────────
extract ipk package-openwrt.yml determine-versioning "Derive package version" \
    build "Build .ipk"

echo "ipk: release tag refs/tags/v0.5.3"
derive ipk refs/tags/v0.5.3 package_version ipk_version
expect_eq "package_version" "${OUT[package_version]}" "v0.5.3"
expect_eq "ipk_version" "${OUT[ipk_version]}" "v0.5.3"

echo "ipk: candidate tag refs/tags/v0.5.3-rc1"
derive ipk refs/tags/v0.5.3-rc1 package_version ipk_version
expect_eq "package_version" "${OUT[package_version]}" "v0.5.3-rc1"
expect_eq "ipk_version" "${OUT[ipk_version]}" "v0.5.3~rc1"
expect_order "${OUT[ipk_version]}" lt v0.5.3
expect_order "${OUT[ipk_version]}" gt v0.5.2
expect_order v0.5.4 gt "${OUT[ipk_version]}"
RC1_IPK="${OUT[ipk_version]}"

echo "ipk: candidate tag refs/tags/v0.5.3-beta1"
derive ipk refs/tags/v0.5.3-beta1 package_version ipk_version
expect_eq "package_version" "${OUT[package_version]}" "v0.5.3-beta1"
expect_eq "ipk_version" "${OUT[ipk_version]}" "v0.5.3~beta1"
expect_order "${OUT[ipk_version]}" lt "$RC1_IPK"
expect_order "${OUT[ipk_version]}" gt v0.5.2

echo "ipk: branch refs/heads/maint"
derive ipk refs/heads/maint package_version ipk_version
expect_eq "package_version" "${OUT[package_version]}" "maint.${HEIGHT}.${HASH}"
expect_eq "ipk_version" "${OUT[ipk_version]}" "${OUT[package_version]}"

echo "ipk: wiring"
# shellcheck disable=SC2016  # the ${{ }} expressions are workflow text, not shell
expect_text -x "$WORK/ipk.outputs" \
    'ipk_version=${{ steps.version.outputs.ipk_version }}' \
    "determine-versioning declares ipk_version from the derivation step"
# shellcheck disable=SC2016
expect_text -x "$WORK/ipk.build.sh" \
    'IPK_VERSION: ${{ needs.determine-versioning.outputs.ipk_version }}' \
    "the .ipk build passes ipk_version as IPK_VERSION"

echo
if [ "$FAILED" -eq 0 ]; then
    echo "check-package-versions: all checks passed"
    exit 0
fi
echo "check-package-versions: $FAILED check(s) failed"
exit 1
