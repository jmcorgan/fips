#!/bin/bash
# Build the RPM from binaries compiled in the pinned container, then check the
# floor of the package it produced.
#
# This is the supported path, and the counterpart of
# packaging/debian/build-deb-container.sh. Both exist for the same reason: a
# package built against the host's C library carries that library's version
# floor, and the host is almost never the oldest system the package has to
# install on. The Debian package answered that with a pinned build image; this
# reuses that image rather than pinning a second one, so the RPM ships the same
# objects the .deb and the tarball do.
#
# rpmbuild itself runs in FIPS_RPM_BUILD_IMAGE, which compiles nothing. It is
# there because the build host may have no rpmbuild at all, and -- the part
# that would fail quietly -- may have no systemd-rpm-macros, without which the
# spec's %systemd_post does not expand and the package ships scriptlets that do
# nothing.
#
# Usage: build-rpm-container.sh [--output-dir DIR] [--version V] [--features L]
#                               [--no-build] [--bin-dir DIR]
#
# --no-build packages the binaries already under target/release instead of
# building any, for a caller that has them: the release workflow recovers them
# from the .deb it just built, and building them twice would only be slower.
# --bin-dir says where those binaries are, if not target/release.
#
# --features reaches cargo through the Debian container build and then marks
# the Release, so a feature build of a commit is a different package from the
# default build of the same commit.
#
# Requires docker. Nothing else: no rust toolchain, no rpmbuild, no dpkg.

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
NO_BUILD=0
BIN_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir) DEST_DIR="${2:?missing value for --output-dir}"; shift 2 ;;
        --version)    VERSION="${2:?missing value for --version}"; shift 2 ;;
        --features)   FEATURES="${2:?missing value for --features}"; shift 2 ;;
        --no-build)   NO_BUILD=1; shift ;;
        --bin-dir)    BIN_DIR="${2:?missing value for --bin-dir}"; NO_BUILD=1; shift 2 ;;
        -h | --help)  sed -n '2,28p' "$0"; exit 0 ;;
        *)            echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

command -v docker >/dev/null 2>&1 || {
    echo "build-rpm-container: docker is required and was not found." >&2
    exit 2
}

# The same refusal build-rpm.sh makes, and for the same reason: with no build
# of our own the features cannot reach cargo, so the Release marking below
# would claim binaries that were compiled by somebody else, with who knows
# what. Refused here rather than after the container build that --no-build was
# asked to skip.
if [ -n "$FEATURES" ] && [ "$NO_BUILD" -eq 1 ]; then
    echo "build-rpm-container: --features cannot be combined with --no-build or" >&2
    echo "--bin-dir: the features would not reach the binaries, but the Release" >&2
    echo "would claim they had." >&2
    exit 2
fi

mkdir -p "$DEST_DIR"
DEST_ABS="$(cd "$DEST_DIR" && pwd)"

# Both scratch directories live inside the output directory rather than under
# /tmp, which is the shape build-deb-container.sh takes and for the same
# reason: a bind-mount source is resolved by the Docker daemon in the host's
# mount namespace, so under a private /tmp -- systemd's PrivateTmp=, which the
# CI worker sets -- a path from a bare `mktemp -d` exists only in this
# process's namespace. The daemon would create its own directory at that path
# in the host's /tmp, the container would write there, and this script would
# read an empty one. The output directory is already bind-mounted as /out and
# so resolves the same way in both namespaces.
#
# The traps clear them on any ordinary exit but not on a SIGKILL, and the
# builder's watch loop group-kills a run that overruns or is superseded, so
# sweep siblings old enough that no live run can own them.
find "$DEST_ABS" -maxdepth 1 -type d \( -name '.name.*' -o -name '.stage.*' \) \
    -mmin +120 -exec rm -rf {} + 2>/dev/null || :

STAGE=""
# The body is last, not the test: written as `[ -n "$STAGE" ] && rm -rf ...`,
# an unset STAGE makes the test the handler's final command, the handler
# returns 1, and from an EXIT trap under `set -e` that becomes the script's
# exit status.
cleanup() {
    if [ -n "$STAGE" ]; then
        rm -rf "$STAGE"
    fi
}
trap cleanup EXIT

if [ "$NO_BUILD" -eq 0 ]; then
    # Build the .deb in the pinned container and package the binaries out of
    # it. That is one build rather than two, and it is the build that
    # build-deb-container.sh has already run the glibc floor and Depends checks
    # on, so the RPM cannot carry objects those checks never saw.
    STAGE=$(mktemp -d "$DEST_ABS/.stage.XXXXXX") || {
        echo "build-rpm-container: could not create a staging directory in $DEST_ABS" >&2
        exit 1
    }
    DEB_DIR="$STAGE/deb"
    BIN_DIR="$STAGE/bin"
    mkdir -p "$DEB_DIR" "$BIN_DIR"

    deb_args=(--output-dir "$DEB_DIR")
    [ -n "$VERSION" ] && deb_args+=(--version "$VERSION")
    [ -n "$FEATURES" ] && deb_args+=(--features "$FEATURES")

    echo "=== Building the binaries in the pinned container ===" >&2
    DEB=$("$REPO_ROOT/packaging/debian/build-deb-container.sh" "${deb_args[@]}" | tail -n 1)
    [ -f "$DEB" ] || {
        echo "build-rpm-container: the Debian build did not produce a package" >&2
        exit 1
    }

    # dpkg-deb lives in the build image, not necessarily on a host that wants
    # an RPM -- a Fedora workstation has no dpkg at all.
    BUILD_IMAGE=$("$REPO_ROOT/packaging/debian/build-deb-container.sh" --print-image-tag)
    docker run --rm \
        -v "$DEB_DIR":/deb:ro \
        -v "$BIN_DIR":/bin-out \
        -e "HOST_UID=$(id -u)" -e "HOST_GID=$(id -g)" \
        "$BUILD_IMAGE" \
        bash -euo pipefail -c '
            unpack=$(mktemp -d)
            dpkg-deb -x /deb/*.deb "$unpack"
            for binary in fips fipsctl fipstop fips-gateway; do
                install -m 0755 "$unpack/usr/bin/$binary" "/bin-out/$binary"
            done
            chown "$HOST_UID:$HOST_GID" /bin-out/*
        ' >&2
fi

: "${BIN_DIR:=$REPO_ROOT/target/release}"
BIN_DIR="$(cd "$BIN_DIR" && pwd)"

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" log -1 --format=%ct)}"

# The version is derived on the host and passed in, because a worktree's .git
# is a file pointing outside the mount and git in the container cannot read it.
# Same reasoning as the Debian container build.
if [ -z "$VERSION" ]; then
    CRATE_VERSION=$(awk -F'"' '/^version = /{print $2; exit}' "$REPO_ROOT/Cargo.toml")
    if [[ "$CRATE_VERSION" == *-dev ]]; then
        GIT_DATE=$(git -C "$REPO_ROOT" log -1 --format=%cs | tr -d '-')
        GIT_SHA=$(git -C "$REPO_ROOT" rev-parse --short HEAD)
        DIRTY=""
        [ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ] && DIRTY=".dirty"
        VERSION="${CRATE_VERSION%-dev}-0.dev.git${GIT_DATE}.${GIT_SHA}${DIRTY}"
    else
        VERSION="$CRATE_VERSION"
    fi
fi

# `docker run` pulls the image implicitly on a miss, and that pull is not
# retried by anything. It reaches a registry on every runner that has not seen
# the digest before, which is every fresh one. retry_build is what the Debian
# builder image uses, so a pull that fails and then succeeds leaves a warning
# on the run rather than passing silently.
if ! docker image inspect "$FIPS_RPM_BUILD_IMAGE" >/dev/null 2>&1; then
    retry_build "docker pull $FIPS_RPM_BUILD_IMAGE" \
        docker pull --quiet "$FIPS_RPM_BUILD_IMAGE" >&2
fi

echo "=== Packaging fips $VERSION in $FIPS_RPM_BUILD_IMAGE ===" >&2

NAME_DIR=$(mktemp -d "$DEST_ABS/.name.XXXXXX") || {
    echo "build-rpm-container: could not create a name directory in $DEST_ABS" >&2
    exit 1
}
trap 'cleanup; rm -rf "$NAME_DIR"' EXIT

# The features reached cargo in the build above, so the binaries already have
# them; what is left is to say so in the Release. build-rpm.sh refuses
# --features with --no-build for exactly that reason -- the flag would promise
# a build it is not doing -- so the marker is folded into the version here
# instead of passed inward.
if [ -n "$FEATURES" ]; then
    MARKER="features.$(printf '%s' "$FEATURES" | tr -c 'a-zA-Z0-9.' '.')"
    case "$VERSION" in
        *-*) VERSION="${VERSION}.${MARKER}" ;;
        *) VERSION="${VERSION}-1.${MARKER}" ;;
    esac
fi

rpm_args=(--no-build --bin-dir /bins --version "$VERSION" --output-dir /out --name-file /name/rpm)

docker run --rm \
    -v "$REPO_ROOT":/src:ro \
    -v "$BIN_DIR":/bins:ro \
    -v "$DEST_ABS":/out \
    -v "$NAME_DIR":/name \
    -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    -e "HOST_UID=$(id -u)" -e "HOST_GID=$(id -g)" \
    -w /src \
    "$FIPS_RPM_BUILD_IMAGE" \
    bash -euo pipefail -c "
        # Retried: this reaches a mirror, and a transient failure here would
        # fail a release build that has nothing wrong with it. The Debian
        # builder image gets the same treatment one layer up, in
        # testing/lib/image-build.sh.
        for attempt in 1 2 3; do
            if dnf install -y --setopt=install_weak_deps=False rpm-build systemd-rpm-macros >/dev/null; then
                break
            fi
            if [ \"\$attempt\" -eq 3 ]; then
                echo 'could not install rpm-build and systemd-rpm-macros' >&2
                exit 1
            fi
            sleep \$((attempt * 5))
        done
        packaging/rpm/build-rpm.sh ${rpm_args[*]}
        chown \"\$HOST_UID:\$HOST_GID\" /name/rpm
    " >&2

RPM_NAME=""
[ -f "$NAME_DIR/rpm" ] && RPM_NAME=$(head -n 1 "$NAME_DIR/rpm")
[ -n "$RPM_NAME" ] || {
    echo "build-rpm-container: the build did not name its package" >&2
    echo "build-rpm-container: the name travels through $NAME_DIR, bind-mounted as /name." >&2
    echo "build-rpm-container: if that path is not visible to the Docker daemon -- a private" >&2
    echo "build-rpm-container: /tmp is the usual cause -- the container wrote the name elsewhere." >&2
    exit 1
}
if [[ "$RPM_NAME" == */* || "$RPM_NAME" != fips-mesh-*.rpm ]]; then
    echo "build-rpm-container: the build named '$RPM_NAME', which is not a package file name" >&2
    exit 1
fi

RPM="$DEST_ABS/$RPM_NAME"
[ -f "$RPM" ] || {
    echo "build-rpm-container: the build named $RPM_NAME but $RPM does not exist" >&2
    exit 1
}

# Check the artifact, not its inputs. rpm records the requirement it derived
# from the binaries, which is the table dnf enforces at install time, so this
# reads what a user's package manager will read. It runs in the rpm image
# because the host may have no rpm.
docker run --rm \
    -v "$REPO_ROOT":/src:ro \
    -v "$DEST_ABS":/out:ro \
    -w /src \
    "$FIPS_RPM_BUILD_IMAGE" \
    testing/check-rpm-floor.sh "/out/$RPM_NAME" >&2

echo "=== Built $RPM ===" >&2
printf '%s\n' "$RPM"
