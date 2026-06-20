#!/bin/sh
# Emit an apk-tools-compatible version string for FIPS.
#
# apk-tools enforces a strict version grammar:
#   <digit>(.<digit>)*(_<suffix><digit>*)*(-r<N>)
# where <suffix> is a recognised pre-release/post-release token
# (alpha, beta, pre, rc, cvs, svn, git, hg, p).
#
# Unlike a regex rewrite of an already-flattened version string, this
# helper builds the apk version directly from the *structured* inputs the
# caller already has (a release tag, or a commit height). There is no
# parsing-back-out of a "branch.height.hash" blob, so there is no fragile
# reparse step to get wrong.
#
# Usage:
#   apk-version.sh tag  <git-tag>     # e.g. v1.2.3, v1.2.3-rc1
#   apk-version.sh dev  <height>      # e.g. 1234  (git rev-list --count HEAD)
#   apk-version.sh auto               # derive from the current git checkout
#
# Examples:
#   apk-version.sh tag v1.2.3       -> 1.2.3-r0
#   apk-version.sh tag v1.2.3-rc1   -> 1.2.3_rc1-r0
#   apk-version.sh dev 1234         -> 0.0.0_git1234-r0
set -eu

mode="${1:-auto}"

case "$mode" in
    tag) raw_tag="${2:?tag mode requires a tag argument}"; height="" ;;
    dev) raw_tag=""; height="${2:?dev mode requires a height argument}" ;;
    auto)
        if raw_tag="$(git describe --exact-match --tags 2>/dev/null)"; then
            height=""
        else
            raw_tag=""
            height="$(git rev-list --count HEAD 2>/dev/null || echo 0)"
        fi
        ;;
    *)
        echo "usage: $0 [auto | tag <git-tag> | dev <height>]" >&2
        exit 2
        ;;
esac

if [ -n "$raw_tag" ]; then
    # Release tag: vX.Y.Z or vX.Y.Z-<pre>. Strip the leading 'v', split the
    # core (X.Y.Z) from the pre-release token, and map our hyphen separator
    # to apk's '_' pre-release marker.
    body="${raw_tag#v}"
    core="${body%%-*}"
    case "$body" in
        *-*) pre="${body#*-}" ;;
        *)   pre="" ;;
    esac

    case "$pre" in
        "")                    suffix="" ;;
        alpha*|beta*|pre*|rc*) suffix="_${pre}" ;;
        *)
            # Unknown pre-release token: apk would reject or misorder it, so
            # drop it rather than emit an invalid version. The human-readable
            # PACKAGE_VERSION (the raw tag) is still used for the filename.
            suffix=""
            ;;
    esac

    printf '%s%s-r0\n' "$core" "$suffix"
else
    # Untagged build: no meaningful semver, so anchor at 0.0.0 and encode the
    # monotonic commit height as a _git pre-release component. This keeps apk's
    # ordering sane across dev builds without smuggling the hash/branch into a
    # field that cannot represent them.
    printf '0.0.0_git%s-r0\n' "${height:-0}"
fi
