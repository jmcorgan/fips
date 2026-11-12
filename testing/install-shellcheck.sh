#!/bin/bash
# ── Install the pinned shellcheck, checksum-verified ────────────────────────
# Every CI run of testing/check-shellcheck.sh uses the shellcheck version
# pinned here: ci.yml's CI parity job, package-openwrt.yml's .ipk build and
# ci-local.sh's shellcheck stage. Without the pin each GitHub job used the
# runner image's shellcheck and local CI used the host's package, so a runner
# image update could turn the lint red with no change in the tree: 0.11.0
# reports a trap-only function under a code 0.9.0 did not have.
#
# Usage: install-shellcheck.sh <dir>
#   Leaves the pinned binary at <dir>/shellcheck and prints its version. The
#   verified release tarball stays in <dir>, and a later run reuses it once it
#   passes the checksum again, so a host needs the network only the first time.
#
# The hashes are GitHub's SHA-256 digests of koalaman/shellcheck's release
# assets, read on 2026-11-12 from
#   gh api repos/koalaman/shellcheck/releases/tags/v0.11.0 \
#     --jq '.assets[] | [.name, .digest] | @tsv'
# and matched against a download made that day. Upstream publishes no
# checksum file of its own. Bumping SHELLCHECK_VERSION means replacing every
# hash below, and adding an arch means adding its hash here too.
#
# Exit 0 = <dir>/shellcheck is the pinned version, from a verified tarball.
# Exit 1 = it could not be installed (download, checksum or version failed).
# Exit 2 = bad usage.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SHELLCHECK_VERSION="0.11.0"

if [[ $# -ne 1 || -z "$1" ]]; then
    echo "usage: $0 <dir>" >&2
    exit 2
fi
DEST="$1"

case "$(uname -m)" in
    x86_64|amd64)
        ARCH="x86_64"
        SHA256="8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198"
        ;;
    aarch64|arm64)
        ARCH="aarch64"
        SHA256="12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588"
        ;;
    *)
        echo "install-shellcheck: no shellcheck ${SHELLCHECK_VERSION} pinned for $(uname -m)" >&2
        exit 1
        ;;
esac

NAME="shellcheck-v${SHELLCHECK_VERSION}.linux.${ARCH}.tar.xz"
URL="https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/${NAME}"
TARBALL="${DEST}/${NAME}"

mkdir -p "$DEST"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# matches <file>: the file is non-empty and has the pinned SHA-256.
matches() {
    [[ -s "$1" ]] && [[ "$(sha256sum < "$1" | cut -d' ' -f1)" == "$SHA256" ]]
}

if matches "$TARBALL"; then
    echo "install-shellcheck: reusing ${TARBALL}, which matches its pinned SHA-256"
else
    # A download is checked in the staging directory and only then moved into
    # <dir>, so a bad or partial file never becomes the reused copy. curl's
    # --retry does not cover a short read, and a checksum mismatch needs a fresh
    # download anyway, so the retry is an explicit bounded loop.
    part="${STAGE}/${NAME}"
    verified=""
    previous=""
    for attempt in 1 2 3; do
        rm -f "$part"
        if curl -fsSL -o "$part" "$URL" && [[ -s "$part" ]]; then
            actual="$(sha256sum < "$part" | cut -d' ' -f1)"
            if [[ "$actual" == "$SHA256" ]]; then
                verified=yes
                break
            fi
            echo "install-shellcheck: ${NAME} failed its checksum on attempt ${attempt}:"
            echo "  expected ${SHA256}"
            echo "  actual   ${actual}"
            if [[ "$actual" == "$previous" ]]; then
                echo "  Two attempts fetched the same bytes, so retrying will not help."
                break
            fi
            previous="$actual"
        else
            echo "install-shellcheck: ${NAME} download failed on attempt ${attempt}"
        fi
        if [[ "$attempt" -lt 3 ]]; then
            sleep $((attempt * 10))
        fi
    done
    if [[ -z "$verified" ]]; then
        echo "install-shellcheck: no copy of ${NAME} matched its pinned SHA-256;" \
            "nothing installed" >&2
        exit 1
    fi
    mv -f "$part" "$TARBALL"
    echo "install-shellcheck: downloaded ${NAME}, which matches its pinned SHA-256"
fi

tar -xJf "$TARBALL" -C "$STAGE"
# Installed under a temporary name and renamed, so a concurrent run never
# executes a half-written binary.
install -m 0755 "${STAGE}/shellcheck-v${SHELLCHECK_VERSION}/shellcheck" "${DEST}/.shellcheck.$$"
mv -f "${DEST}/.shellcheck.$$" "${DEST}/shellcheck"

got="$("${DEST}/shellcheck" --version | sed -n 's/^version: //p')"
if [[ "$got" != "$SHELLCHECK_VERSION" ]]; then
    echo "install-shellcheck: ${DEST}/shellcheck reports version '${got}'," \
        "not ${SHELLCHECK_VERSION}" >&2
    exit 1
fi
echo "install-shellcheck: shellcheck ${got} at ${DEST}/shellcheck"
