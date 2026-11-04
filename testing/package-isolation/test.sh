#!/bin/bash
# Check that a Debian package built in the shared build container is built
# from its own tree, whatever was built before it or beside it.
#
# Usage: testing/package-isolation/test.sh [--script-dir DIR] [--name-prefix P]
#                                          [--log-dir DIR] [--keep]
#
#   --script-dir DIR   take the package build scripts from the checkout at DIR
#                      instead of this one (see "Scripts" below)
#   --name-prefix P    prefix for the Docker volumes this run creates
#                      (default fips-pkgiso-<pid>); also its run label
#   --log-dir DIR      copy every build's output there as <scenario>-tree<N>.out
#   --keep             leave the work directory in place
#
# Two trees at this checkout's HEAD are built in turn and together, sharing a
# target volume the way every checkout on a host shares
# fips-deb-target-<image>. Tree 1 is a `git clone -s` of this checkout and
# tree 2 a `git worktree add` of tree 1. Tree 2 is a worktree on purpose: its
# .git is a file, so build.rs reruns and the root crate is recompiled on every
# build, which is how CI worktrees build, and how a root crate comes to be
# compiled against another tree's copy of a workspace member.
#
# Each tree is marked before anything is built, so its files are older than
# any build: `fips --version` gains a line `isolation: root-N core-N`, where
# core-N is a constant added to the fips-core member (or `-` on a tree with no
# core/ member). A package carrying the other tree's mark was built, in whole
# or in part, from the other tree.
#
# Scenarios, each with a fresh target volume: tree 1 then tree 2; tree 2 then
# tree 1; both at once. The registry volume is the run's own and shared by the
# scenarios; registry content is the same for both trees.
#
# Two verdicts, reported separately for every package:
#   marker    the package's isolation line is its own tree's. This is the only
#             oracle that tells the two trees apart: both are at one commit and
#             both are dirty, so they carry the same revision. Do not drop the
#             marks as redundant with the revision check.
#   revision  the package's revision is its tree's commit and dirty flag.
# The run passes when every build exits 0 and both verdicts pass everywhere.
#
# Scripts: the files listed in PACKAGE_SCRIPTS are copied into both trees from
# --script-dir, or from this checkout's working tree, so uncommitted changes to
# them are what is tested. A build-deb-container.sh that cannot be pointed at
# other volumes (FIPS_DEB_TARGET_VOLUME) is patched to read them, so an older
# script can be shown failing without touching the host's volumes.
#
# Not run by ci-local.sh or on GitHub: it costs about ten minutes of full CPU
# (a cold and a warm build per scenario). Coverage gap, recorded: nothing runs
# it automatically, so a change to the package build that breaks isolation is
# caught only by the checks every package build runs (see
# packaging/debian/build-in-container.sh) until this is run by hand. Run it
# when changing the package build, and on each trunk the change reaches.
#
# Exit 0 = every package came from its own tree. Exit 1 = a build failed or a
# verdict failed. Exit 2 = the test could not run.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=../lib/image-build.sh
. "$REPO_ROOT/testing/lib/image-build.sh"

PACKAGE_SCRIPTS=(
    packaging/debian/build-deb-container.sh
    packaging/debian/build-in-container.sh
    packaging/debian/build-deb.sh
    packaging/debian/Dockerfile.build
    testing/check-deb-revision.sh
    testing/lib/image-build.sh
)
CI_LABEL=com.corganlabs.fips-ci=1
RUN_LABEL_KEY=com.corganlabs.fips-ci.run

SCRIPT_SRC="$REPO_ROOT"
PREFIX="fips-pkgiso-$$"
LOG_DIR=""
KEEP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --script-dir)  SCRIPT_SRC="${2:?missing value for --script-dir}"; shift 2 ;;
        --name-prefix) PREFIX="${2:?missing value for --name-prefix}"; shift 2 ;;
        --log-dir)     LOG_DIR="${2:?missing value for --log-dir}"; shift 2 ;;
        --keep)        KEEP=1; shift ;;
        -h|--help)     sed -n '2,14p' "$0"; exit 0 ;;
        *)             echo "package-isolation: unknown option: $1" >&2; exit 2 ;;
    esac
done

die() {
    echo "package-isolation: $*" >&2
    exit 2
}

command -v docker >/dev/null 2>&1 || die "docker is required"
[ -f "$SCRIPT_SRC/packaging/debian/build-deb-container.sh" ] \
    || die "$SCRIPT_SRC has no packaging/debian/build-deb-container.sh"
SCRIPT_SRC="$(cd "$SCRIPT_SRC" && pwd)"
if [ -n "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR" || die "cannot create $LOG_DIR"
    LOG_DIR="$(cd "$LOG_DIR" && pwd)"
fi
HEAD_SHA=$(git -C "$REPO_ROOT" rev-parse --verify HEAD) || die "$REPO_ROOT is not a git checkout"

# The trees and the packages are bind-mount sources, so the work directory is
# made with shared_tmpdir, under the checkout's target/ (ignored by git). Not
# under testing/: the static checks that sweep testing/ would read the scratch
# trees' copies of the repository's scripts as the repository's own.
WORK=$(shared_tmpdir --sweep "$REPO_ROOT/target" package-isolation) \
    || die "could not create a work directory"
VOLUMES=()
# shellcheck disable=SC2317  # run by the EXIT trap
cleanup() {
    local v
    for v in "${VOLUMES[@]}"; do
        docker volume rm -f "$v" >/dev/null 2>&1 || true
    done
    if [ "$KEEP" -eq 0 ]; then
        rm -rf "$WORK"
    else
        echo "package-isolation: work directory kept: $WORK" >&2
    fi
    return 0
}
trap cleanup EXIT

make_volume() {
    local name=$1
    docker volume create --label "$CI_LABEL" --label "$RUN_LABEL_KEY=$PREFIX" "$name" >/dev/null \
        || die "could not create volume $name"
    VOLUMES+=("$name")
    return 0
}

# ── The trees ───────────────────────────────────────────────────────────────
T1="$WORK/tree1"
T2="$WORK/tree2"
git clone -q -s --no-checkout "$REPO_ROOT" "$T1" || die "could not clone $REPO_ROOT"
git -C "$T1" checkout -q --detach "$HEAD_SHA" || die "could not check out $HEAD_SHA in tree 1"
git -C "$T1" worktree add -q --detach "$T2" "$HEAD_SHA" || die "could not add tree 2"

install_scripts() {
    local tree=$1 f
    for f in "${PACKAGE_SCRIPTS[@]}"; do
        [ -f "$SCRIPT_SRC/$f" ] || continue
        mkdir -p "$(dirname "$tree/$f")"
        cp "$SCRIPT_SRC/$f" "$tree/$f" || die "could not copy $f into $tree"
    done
    local bdc="$tree/packaging/debian/build-deb-container.sh"
    if ! grep -q 'FIPS_DEB_TARGET_VOLUME' "$bdc"; then
        # An older script names the host's volumes outright. Point it at the
        # test's; refuse to run if that does not take, rather than build in the
        # host's shared volumes.
        # shellcheck disable=SC2016  # the ${...} are the script's, not ours
        sed -i \
            -e 's|"fips-deb-target-${VOL_SUFFIX}":/target|"${FIPS_DEB_TARGET_VOLUME:?}":/target|' \
            -e 's|"fips-deb-registry-${VOL_SUFFIX}":/usr/local/cargo/registry|"${FIPS_DEB_REGISTRY_VOLUME:?}":/usr/local/cargo/registry|' \
            "$bdc"
        if grep -q 'fips-deb-target-\|fips-deb-registry-' "$bdc" \
                || [ "$(grep -c 'FIPS_DEB_\(TARGET\|REGISTRY\)_VOLUME:?' "$bdc")" -ne 2 ]; then
            die "could not point $f's volumes at the test's; not running it against the host's"
        fi
    fi
    return 0
}

# mark_tree TREE N: add the isolation line to --version, and the core mark.
mark_tree() {
    local tree=$1 n=$2 slot='"-"'
    if [ -f "$tree/core/src/lib.rs" ]; then
        printf '\n/// Which tree this crate was compiled from (package isolation test).\npub const ISOLATION_PROBE: &str = "core-%s";\n' "$n" \
            >>"$tree/core/src/lib.rs"
        slot='fips_core::ISOLATION_PROBE'
    fi
    # shellcheck disable=SC2016  # Rust source, not shell
    sed -i "s|format!(\"{}\\\\ntarget: {TARGET}\", \\*SHORT_VERSION)|format!(\"{}\\\\ntarget: {TARGET}\\\\nisolation: root-$n {}\", *SHORT_VERSION, $slot)|" \
        "$tree/src/version.rs"
    grep -qF "isolation: root-$n {}" "$tree/src/version.rs" \
        || die "could not mark the tree: $tree/src/version.rs has no LONG_VERSION format line to extend"
    return 0
}

install_scripts "$T1"
install_scripts "$T2"
mark_tree "$T1" 1
mark_tree "$T2" 2
EXPECT_CORE=("" "core-1" "core-2")
[ -f "$T1/core/src/lib.rs" ] || EXPECT_CORE=("" "-" "-")

IMAGE_TAG=$(bash "$T1/packaging/debian/build-deb-container.sh" --print-image-tag) \
    || die "could not read the build image tag"
REGISTRY="$PREFIX-registry"
make_volume "$REGISTRY"

# ── Builds ──────────────────────────────────────────────────────────────────
# build SCENARIO N TARGET: build tree N; writes $WORK/SCENARIO-treeN.{out,rc,deb}.
build() {
    local sc=$1 n=$2 target=$3 tree out rc=0 start
    tree="$WORK/tree$n"
    out="$WORK/$sc-tree$n"
    mkdir -p "$out.pkg"
    start=$SECONDS
    FIPS_DEB_TARGET_VOLUME="$target" FIPS_DEB_REGISTRY_VOLUME="$REGISTRY" \
        bash "$tree/packaging/debian/build-deb-container.sh" --output-dir "$out.pkg" \
        >"$out.stdout" 2>"$out.out" || rc=$?
    echo "$rc" >"$out.rc"
    echo "$((SECONDS - start))" >"$out.secs"
    [ "$rc" -ne 0 ] || tail -n 1 "$out.stdout" >"$out.deb"
    [ -z "$LOG_DIR" ] || cp "$out.out" "$LOG_DIR/$sc-tree$n.out"
    return 0
}

# version_of DEB: print the packaged fips binary's --version output.
version_of() {
    local deb=$1
    docker run --rm --label "$CI_LABEL" --label "$RUN_LABEL_KEY=$PREFIX" \
        -v "$(dirname "$deb")":/pkg:ro "$IMAGE_TAG" bash -c '
            set -e
            u=$(mktemp -d) # mount-tmpdir: inside the container, never mounted
            dpkg-deb -x "/pkg/$1" "$u"
            "$u/usr/bin/fips" --version' version "$(basename "$deb")"
}

FAILED=0
# verdict SCENARIO N: report tree N's package in SCENARIO.
verdict() {
    local sc=$1 n=$2 base rc deb ver iso rev want_iso want_rev short dirty=""
    base="$WORK/$sc-tree$n"
    rc=$(cat "$base.rc")
    if [ "$rc" -ne 0 ]; then
        printf '  %s tree %s: build FAILED (exit %s, %ss); last lines of its output:\n' \
            "$sc" "$n" "$rc" "$(cat "$base.secs")"
        tail -n 25 "$base.out" | sed 's/^/    | /'
        FAILED=1
        return 0
    fi
    deb=$(cat "$base.deb")
    if ! ver=$(version_of "$deb"); then
        printf '  %s tree %s: could not read --version from %s\n' "$sc" "$n" "$deb"
        FAILED=1
        return 0
    fi
    iso=$(printf '%s\n' "$ver" | sed -n 's/^isolation: //p')
    # Line 1 read by sed on a here-string, not through head: under pipefail
    # and set -e, head exiting after line 1 can kill printf with SIGPIPE
    # before it writes line 2, and that ends the script.
    rev=$(sed -nE '1s/.*\(rev ([0-9a-f]+(-dirty)?)\)$/\1/p' <<<"$ver")
    short=$(git -C "$WORK/tree$n" rev-parse --short=10 HEAD)
    [ -z "$(git -C "$WORK/tree$n" status --porcelain)" ] || dirty="-dirty"
    want_iso="root-$n ${EXPECT_CORE[$n]}"
    want_rev="$short$dirty"
    local mv rv
    if [ -z "$iso" ]; then
        mv="FAIL (no marker in the package)"
    elif [ "$iso" = "$want_iso" ]; then
        mv="ok"
    else
        mv="FAIL (STALE: carries $iso, expected $want_iso)"
    fi
    if [ "$rev" = "$want_rev" ]; then
        rv="ok"
    else
        rv="FAIL (carries ${rev:-no revision}, expected $want_rev)"
    fi
    printf '  %s tree %s: exit 0 (%ss); isolation: %s; rev %s\n' \
        "$sc" "$n" "$(cat "$base.secs")" "${iso:--}" "${rev:--}"
    printf '      marker verdict: %s; revision verdict: %s\n' "$mv" "$rv"
    [ "$mv" = ok ] && [ "$rv" = ok ] || FAILED=1
    return 0
}

echo "package-isolation: trees at $(git -C "$T1" rev-parse --short=10 HEAD), scripts from $SCRIPT_SRC" >&2
echo "package-isolation: image $IMAGE_TAG; volumes $PREFIX-*" >&2

for sc in s1 s2 s3; do
    target="$PREFIX-target-$sc"
    make_volume "$target"
    case "$sc" in
        s1) echo "=== s1: tree 1, then tree 2 ===" >&2
            build s1 1 "$target"; build s1 2 "$target" ;;
        s2) echo "=== s2: tree 2, then tree 1 ===" >&2
            build s2 2 "$target"; build s2 1 "$target" ;;
        s3) echo "=== s3: both trees at once ===" >&2
            build s3 1 "$target" & p1=$!
            build s3 2 "$target" & p2=$!
            wait "$p1"; wait "$p2" ;;
    esac
    docker volume rm -f "$target" >/dev/null 2>&1 || true
done

echo
echo "package-isolation results (tree N should carry root-N ${EXPECT_CORE[1]/1/N}):"
for sc in s1 s2 s3; do
    verdict "$sc" 1
    verdict "$sc" 2
done
if [ "$FAILED" -ne 0 ]; then
    echo "package-isolation: FAIL"
    exit 1
fi
echo "package-isolation: PASS (every package came from its own tree)"
exit 0
