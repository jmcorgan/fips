#!/bin/bash
# Build the Debian package in the pinned build container, then check its floor.
#
# This is the one place the Linux artifacts are produced. The release workflow,
# the CI integration job and a local run all call it, so all three build the
# same way and a package that passes locally is the package that ships. That was
# not true before: the test suite built its own package inside a Debian 12 image
# while the release built on the newest GitHub runner, so the suite could not
# exhibit a defect that only the release environment produced -- and for five
# releases it did not.
#
# Usage: build-deb-container.sh [--output-dir DIR] [--version V] [--features LIST]
#                               [--rebuild-image] [--image-archive PATH]
#        build-deb-container.sh --print-image-tag
#
# Requires docker, except for --print-image-tag. The image is cached between
# runs under a tag made of the floor image, the Rust toolchain and a hash of
# Dockerfile.build, so a change to any of the three builds a new image; the
# source is mounted rather than copied, so editing code does not invalidate it.
#
# --print-image-tag prints that tag and exits. --image-archive carries the image
# between hosts that do not share a docker daemon, such as fresh CI runners:
# when the image is absent and PATH exists it is loaded from there, and when
# this run builds the image it is saved there. A bad archive is warned about and
# the image rebuilt; it never fails the build.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=../build-floor.env
. "$REPO_ROOT/packaging/build-floor.env"
# shellcheck source=SCRIPTDIR/../../testing/lib/image-build.sh
. "$REPO_ROOT/testing/lib/image-build.sh"

DEST_DIR="$REPO_ROOT/deploy"
VERSION=""
FEATURES=""
REBUILD_IMAGE=0
PRINT_TAG=0
IMAGE_ARCHIVE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)    DEST_DIR="${2:?missing value for --output-dir}"; shift 2 ;;
        --version)       VERSION="${2:?missing value for --version}"; shift 2 ;;
        --features)      FEATURES="${2:?missing value for --features}"; shift 2 ;;
        --rebuild-image) REBUILD_IMAGE=1; shift ;;
        --print-image-tag) PRINT_TAG=1; shift ;;
        --image-archive) IMAGE_ARCHIVE="${2:?missing value for --image-archive}"; shift 2 ;;
        -h|--help)       sed -n '2,25p' "$0"; exit 0 ;;
        *)               echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

# Read the toolchain from the pin rather than choosing one here, and put it in
# the tag so a bump rebuilds the image instead of silently reusing a stale one.
# The Dockerfile's content goes in the tag for the same reason: without it a
# host that has the image cached keeps using it after the Dockerfile changes.
RUST_TOOLCHAIN=$(awk -F'"' '/^channel *=/{print $2; exit}' "$REPO_ROOT/rust-toolchain.toml")
[ -n "$RUST_TOOLCHAIN" ] || {
    echo "build-deb-container: could not read channel from rust-toolchain.toml" >&2
    exit 2
}

DOCKERFILE_HASH=$(sha256sum "$SCRIPT_DIR/Dockerfile.build" | cut -c1-12) || DOCKERFILE_HASH=""
[[ "$DOCKERFILE_HASH" =~ ^[0-9a-f]{12}$ ]] || {
    echo "build-deb-container: could not hash $SCRIPT_DIR/Dockerfile.build" >&2
    exit 2
}

IMAGE_TAG="fips-deb-builder:${FIPS_BUILD_IMAGE//[:\/]/-}-rust${RUST_TOOLCHAIN}-${DOCKERFILE_HASH}"

# Before the docker check, so a workflow can key a cache on the tag without
# docker being involved.
if [ "$PRINT_TAG" -eq 1 ]; then
    printf '%s\n' "$IMAGE_TAG"
    exit 0
fi

command -v docker >/dev/null 2>&1 || {
    echo "build-deb-container: docker is required and was not found." >&2
    exit 2
}

# FIPS_DEB_TARGET_VOLUME and FIPS_DEB_REGISTRY_VOLUME name other volumes, for a
# test that must not touch the host's. They are set together or not at all:
# the lock in the target volume is what serializes use of the registry volume,
# so a registry shared with other builds must come with their target volume.
# Checked before the image is built, so a wrong setting fails at once.
VOL_SUFFIX="${FIPS_BUILD_IMAGE//[:\/]/-}"
if [ -n "${FIPS_DEB_TARGET_VOLUME:-}" ] && [ -n "${FIPS_DEB_REGISTRY_VOLUME:-}" ]; then
    TARGET_VOLUME=$FIPS_DEB_TARGET_VOLUME
    REGISTRY_VOLUME=$FIPS_DEB_REGISTRY_VOLUME
elif [ -z "${FIPS_DEB_TARGET_VOLUME:-}" ] && [ -z "${FIPS_DEB_REGISTRY_VOLUME:-}" ]; then
    TARGET_VOLUME="fips-deb-target-${VOL_SUFFIX}"
    REGISTRY_VOLUME="fips-deb-registry-${VOL_SUFFIX}"
else
    echo "build-deb-container: set FIPS_DEB_TARGET_VOLUME and FIPS_DEB_REGISTRY_VOLUME together or not at all" >&2
    exit 2
fi

# A problem with the image archive is a warning, not a failure: the archive only
# saves time, and failing a release over a bad cache entry would hold the tag
# until someone removed the entry by hand. The ::warning:: line puts it on the
# GitHub run summary; the plain line is for everywhere else.
archive_warning() {
    echo "::warning::build-deb-container: $*"
    echo "build-deb-container: warning: $*" >&2
}

# Stays unset when the image was found or loaded, so only an image this run
# built is saved: saving a loaded one would only rewrite the archive it came from.
BUILT_IMAGE=0
if [ "$REBUILD_IMAGE" -eq 1 ]; then
    BUILT_IMAGE=1
elif docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
    echo "=== Using cached $IMAGE_TAG ===" >&2
elif [ -n "$IMAGE_ARCHIVE" ] && [ -f "$IMAGE_ARCHIVE" ]; then
    echo "=== Loading $IMAGE_TAG from $IMAGE_ARCHIVE ===" >&2
    if ! docker load -i "$IMAGE_ARCHIVE" >&2; then
        archive_warning "could not load $IMAGE_ARCHIVE; building $IMAGE_TAG instead"
        BUILT_IMAGE=1
    elif ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
        archive_warning "$IMAGE_ARCHIVE does not hold $IMAGE_TAG; building it instead"
        BUILT_IMAGE=1
    else
        echo "=== Using $IMAGE_TAG loaded from $IMAGE_ARCHIVE ===" >&2
    fi
else
    BUILT_IMAGE=1
fi

if [ "$BUILT_IMAGE" -eq 1 ]; then
    echo "=== Building $IMAGE_TAG from $FIPS_BUILD_IMAGE with Rust $RUST_TOOLCHAIN ===" >&2
    # Retried because the build pulls the floor image and fetches apt packages,
    # rustup and crates, any of which can fail for a few seconds at a time.
    retry_build "docker build $IMAGE_TAG" docker build \
        --build-arg "BASE=$FIPS_BUILD_IMAGE" \
        --build-arg "RUST_TOOLCHAIN=$RUST_TOOLCHAIN" \
        -t "$IMAGE_TAG" \
        -f "$SCRIPT_DIR/Dockerfile.build" \
        "$SCRIPT_DIR"

    # Written to a temporary name and renamed, so a failed or interrupted save
    # never leaves a truncated archive where a cache step would pick it up.
    if [ -n "$IMAGE_ARCHIVE" ]; then
        ARCHIVE_TMP="$IMAGE_ARCHIVE.tmp.$$"
        if docker save "$IMAGE_TAG" -o "$ARCHIVE_TMP" >&2 \
                && mv -f "$ARCHIVE_TMP" "$IMAGE_ARCHIVE"; then
            echo "=== Saved $IMAGE_TAG to $IMAGE_ARCHIVE ===" >&2
        else
            rm -f "$ARCHIVE_TMP"
            archive_warning "could not save $IMAGE_TAG to $IMAGE_ARCHIVE; the next run will build it again"
        fi
    fi
fi

# Derive the version and the timestamp on the host and pass both in. Git in the
# container reads the same repository, through the mounts set up below, but it
# is there for build.rs's revision and for the check that the package carries
# it; the version is decided here.
if [ -z "$VERSION" ]; then
    CRATE_VERSION=$(awk -F'"' '/^version = /{print $2; exit}' "$REPO_ROOT/Cargo.toml")
    if [[ "$CRATE_VERSION" == *-dev ]]; then
        GIT_DATE=$(git -C "$REPO_ROOT" log -1 --format=%cs | tr -d '-')
        GIT_SHA=$(git -C "$REPO_ROOT" rev-parse --short HEAD)
        DIRTY=""
        [ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ] && DIRTY=".dirty"
        VERSION="${CRATE_VERSION%-dev}~dev+git${GIT_DATE}.${GIT_SHA}${DIRTY}-1"
    else
        VERSION="$CRATE_VERSION"
    fi
fi
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" log -1 --format=%ct)}"

mkdir -p "$DEST_DIR"
DEST_ABS="$(cd "$DEST_DIR" && pwd)"

echo "=== Building fips $VERSION in $IMAGE_TAG ===" >&2

# The build and packaging run in packaging/debian/build-in-container.sh, which
# is also where the target volume is locked and cleaned and the build checked;
# its header says why. A feature build passes --features through, and that
# script hands it to build-deb.sh, which marks the version so a feature package
# is distinguishable from the default build of the same commit.
build_args=(--version "$VERSION" --output-dir /out --name-file /name/deb)
[ -n "$FEATURES" ] && build_args+=(--features "$FEATURES")

# The build names the package it produced rather than this script picking one
# out of the output directory. The output directory is the caller's and may
# already hold packages from earlier runs; a search there by name or by age
# could return one of those, and a package that sorts higher by name was
# returned in preference to the one just built. The name travels through a
# directory of its own, created fresh for this run, so a name left by an
# earlier run cannot be read.
#
# The directory lives inside the output directory, not under /tmp, because a
# bind-mount source must resolve the same way for the Docker daemon as for this
# script, and under a private /tmp a bare `mktemp -d` path does not (see
# shared_tmpdir in testing/lib/image-build.sh). The output directory is already
# bind-mounted as /out, so it already resolves the same way in both namespaces,
# which makes it the one place the name can travel through unconditionally.
# The trap below clears the directory on any ordinary exit, but not on a
# SIGKILL, and the builder's watch loop group-kills a run that overruns its
# ceiling or is superseded by a newer tip. Nothing else sweeps the output
# directory, so --sweep clears siblings old enough that no live run owns them.
#
# A package that fails a check after it was written is removed, so it is not
# left in the output directory for a later step to pick up; deb-install, run
# without --deb, reuses any package there newer than the sources.
NAME_DIR=$(shared_tmpdir --sweep "$DEST_ABS" .name) || {
    echo "build-deb-container: could not create a name directory in $DEST_ABS" >&2
    exit 1
}
REJECT=""
cleanup() {
    rm -rf "$NAME_DIR"
    if [ -n "$REJECT" ] && rm -f "$REJECT"; then
        echo "build-deb-container: removed $REJECT, which failed a check" >&2
    fi
}
trap cleanup EXIT

# The source is mounted read-only so a build cannot leave artifacts in the tree.
# CARGO_TARGET_DIR and the registry live in named volumes, per base image so a
# floor change does not reuse objects linked against the wrong C library. The
# volumes are shared by every checkout on the host. What a second run reuses
# from them is the registry and the compiled dependencies, which are keyed by
# version and checksum and so are the same for every tree. The workspace's own
# crates are not reused: build-in-container.sh cleans and recompiles them on
# every build, under a lock on the target volume, because cargo judges them by
# file times and would otherwise hand one tree another tree's build. The
# volume names are set above.
REPO_PHYS=$(cd "$REPO_ROOT" && pwd -P)

# build.rs embeds the tree's revision and dirty flag from git, and the check
# after packaging reads them back, so git in the container must reach the whole
# repository. A worktree's .git is a file naming a directory outside the tree,
# and a clone made with --shared borrows objects from another repository, which
# may borrow from a third. Each such directory outside the tree is mounted
# read-only at the path those references name, so git finds it there. Without
# them a worktree build carried no revision and a --shared clone's build could
# not see that its tree was dirty.
#
# Alternates are followed as deep as git follows them: an alternates file is
# read at nesting depths 0 to 5 and ignored beyond. A directory git needs and
# this does not mount shows up as a tree whose state git cannot read, which the
# check after packaging fails on.
#
# An alternate is mounted at the path git in the container will open, which is
# the path as written in the alternates file, made absolute against the
# container's path for the objects directory holding the file, with no symlink
# resolved: inside the container the mount point is a plain directory. The
# mount's source is the directory that path reaches here. The two differ when
# the alternate was named through a symlink, as `git clone -s` does when its
# source was.
#
# --mount refuses a missing source, where -v would create an empty directory.
# Its value is comma-separated, so a path is quoted for docker's CSV parser.
GIT_MOUNTS=()
declare -A GIT_SEEN=()
# Print an absolute path with . and .. removed by text alone, as git does.
# Fails, as git does, on a .. that would climb above /.
lexical_path() {
    local part out=() parts
    IFS=/ read -ra parts <<<"$1"
    for part in "${parts[@]}"; do
        case "$part" in
            ''|.) ;;
            ..) [ "${#out[@]}" -gt 0 ] || return 1; unset 'out[-1]' ;;
            *) out+=("$part") ;;
        esac
    done
    (IFS=/; printf '/%s\n' "${out[*]}")
}
# Mount host directory $1 at container path $2, unless the source mount at
# /src already shows it there.
mount_git_dir() {
    local src=$1 dst=$2
    case "$src/" in
        "$REPO_PHYS"/*) [ "$dst" != "/src${src#"$REPO_PHYS"}" ] || return 0 ;;
    esac
    GIT_MOUNTS+=(--mount "type=bind,\"src=${src//\"/\"\"}\",\"dst=${dst//\"/\"\"}\",readonly")
    return 0
}
# Follow the alternates of the objects directory at host path $1, which the
# container opens at $2.
follow_alternates() {
    local src=$1 dst=$2 depth=$3 alt asrc adst
    [ "$depth" -le 5 ] && [ -f "$src/info/alternates" ] || return 0
    while IFS= read -r alt; do
        case "$alt" in ''|'#'*) continue ;; esac
        asrc=$(cd "$src" && cd -P "$alt" 2>/dev/null && pwd -P) || continue
        case "$alt" in
            /*) adst=$alt ;;
            *)  adst=$dst/$alt ;;
        esac
        # A relative entry is read from where the container sees its objects
        # directory, which for the tree's own is /src/.git/objects; one that
        # climbs further than that cannot be followed there.
        adst=$(lexical_path "$adst") || {
            echo "build-deb-container: $src/info/alternates names $alt, which git in the" >&2
            echo "build-deb-container: container would read from $dst and cannot follow above /." >&2
            echo "build-deb-container: Write the entry as an absolute path." >&2
            exit 1
        }
        [ -z "${GIT_SEEN[$adst]+x}" ] || continue
        GIT_SEEN[$adst]=1
        mount_git_dir "$asrc" "$adst"
        follow_alternates "$asrc" "$adst" $((depth + 1))
    done <"$src/info/alternates"
    return 0
}
# The tree is a checkout only when it is the top of a work tree. A tree inside
# another repository, such as a release tarball unpacked in a packaging
# repository, is built as no checkout and its binaries carry no revision: git
# in the container cannot reach that outer repository from /src, and the outer
# HEAD is not this tree's revision anyway.
HOST_HEAD=""
HOST_TOP=$(git -C "$REPO_ROOT" rev-parse --show-toplevel 2>/dev/null) || HOST_TOP=""
if [ -n "$HOST_TOP" ] && [ "$(cd "$HOST_TOP" && pwd -P)" = "$REPO_PHYS" ] \
        && HOST_HEAD=$(git -C "$REPO_ROOT" rev-parse --verify --quiet HEAD 2>/dev/null); then
    GIT_COMMON=$(cd "$REPO_ROOT" && cd "$(git rev-parse --git-common-dir)" && pwd -P)
    case "$GIT_COMMON/" in
        "$REPO_PHYS"/*) GIT_COMMON_DST="/src${GIT_COMMON#"$REPO_PHYS"}" ;;
        *)              GIT_COMMON_DST=$GIT_COMMON ;;
    esac
    GIT_SEEN[$GIT_COMMON_DST/objects]=1
    mount_git_dir "$GIT_COMMON" "$GIT_COMMON_DST"
    follow_alternates "$GIT_COMMON/objects" "$GIT_COMMON_DST/objects" 0
else
    HOST_HEAD=""
fi

docker run --rm "${CI_LABELS[@]}" \
    -v "$REPO_ROOT":/src:ro \
    "${GIT_MOUNTS[@]}" \
    -v "$DEST_ABS":/out \
    -v "$NAME_DIR":/name \
    -v "$TARGET_VOLUME":/target \
    -v "$REGISTRY_VOLUME":/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR=/target \
    -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    -e FIPS_BUILD_ORIGIN="$(hostname):$REPO_PHYS" \
    -e FIPS_HOST_HEAD="$HOST_HEAD" \
    -w /src \
    "$IMAGE_TAG" \
    bash packaging/debian/build-in-container.sh "${build_args[@]}" >&2

DEB_NAME=""
[ -f "$NAME_DIR/deb" ] && DEB_NAME=$(head -n 1 "$NAME_DIR/deb")
[ -n "$DEB_NAME" ] || {
    echo "build-deb-container: the build did not name its package" >&2
    echo "build-deb-container: the name travels through $NAME_DIR, bind-mounted as /name." >&2
    echo "build-deb-container: if that path is not visible to the Docker daemon -- a private" >&2
    echo "build-deb-container: /tmp is the usual cause -- the container wrote the name elsewhere." >&2
    exit 1
}
if [[ "$DEB_NAME" == */* || "$DEB_NAME" != fips_*_*.deb ]]; then
    echo "build-deb-container: the build named '$DEB_NAME', which is not a package file name" >&2
    exit 1
fi
DEB="$DEST_ABS/$DEB_NAME"
[ -f "$DEB" ] || {
    echo "build-deb-container: the build named $DEB_NAME but $DEB does not exist" >&2
    exit 1
}
REJECT=$DEB

# Check the artifact here rather than in one workflow, so every producer is
# gated: the release, the CI job, a local run and packaging/Makefile all reach
# both checks through this script. The glibc floor is read from the binaries
# and runs on the host. The Depends check runs in the build image, because it
# compares against dpkg-shlibdeps and has to read the same symbols files and C
# library that cargo-deb's "$auto" read; a host of another distribution could
# produce a difference of its own.
"$REPO_ROOT/testing/check-glibc-floor.sh" "$DEB" >&2
docker run --rm "${CI_LABELS[@]}" \
    -v "$REPO_ROOT":/src:ro \
    -v "$DEST_ABS":/out:ro \
    -w /src \
    "$IMAGE_TAG" \
    testing/check-deb-depends.sh "/out/$DEB_NAME" >&2
REJECT=""

echo "=== Built $DEB ===" >&2
printf '%s\n' "$DEB"
