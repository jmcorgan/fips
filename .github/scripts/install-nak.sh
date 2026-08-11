#!/bin/bash
# ── Install nak, checksum-verified ──────────────────────────────────────────
# nak signs the release announcement events, and the jobs that call this script
# hand it the publishing nsec on argv. An unverified download therefore runs
# with the signing key in reach, so the binary is staged, checked against a
# pinned SHA-256, and only then installed.
#
# Called from .github/workflows/package-openwrt.yml by both the .ipk (`build`)
# and .apk (`build-apk`) jobs, which is why it lives here rather than under
# packaging/openwrt-ipk/ — that directory is the .ipk payload tree.
#
# Exit 0 = installed and verified. Any non-zero exit means nothing was
# installed.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

NAK_VERSION="0.16.2"
INSTALL_PATH="/usr/local/bin/nak"

ARCH=$(uname -m)
# Each arch carries the expected SHA-256 of its upstream release asset.
#
# Unlike the zig hashes in the same workflow, which come from ziglang.org's own
# https://ziglang.org/download/index.json, these are NOT upstream-attested:
# fiatjaf/nak publishes no checksum document, sidecar or SHA256SUMS alongside
# its release assets, so the only way to obtain a hash is to download the asset
# and compute it. These were derived that way on 2026-08-11 from
#   https://github.com/fiatjaf/nak/releases/download/v0.16.2/nak-v0.16.2-linux-<arch>
# What the pin buys is therefore continuity, not authenticity: it detects the
# asset changing under a fixed tag, a corrupted or truncated transfer, and a
# substituted download, but it cannot attest that the bytes captured on that
# date were the bytes upstream intended. Bumping NAK_VERSION means re-deriving
# every hash below, and adding an arch means adding its hash here too.
case "$ARCH" in
  x86_64|amd64)
    NAK_ARCH="amd64"
    NAK_SHA256="495243c070c4533ce96e98b6f34b7e97fd4be2da3353488b400233ed7ed0d4da"
    ;;
  aarch64|arm64)
    NAK_ARCH="arm64"
    NAK_SHA256="1fb8868c60ebf77dd86f90d6374ebf8557412baa37026d2844af932776085b88"
    ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

if [ -z "${NAK_SHA256:-}" ]; then
  echo "No SHA-256 pinned for nak ${NAK_VERSION} on ${NAK_ARCH}."
  echo "Add one to the case above, derived by downloading the asset:"
  echo "  curl -fsSL <asset-url> | sha256sum"
  exit 1
fi

NAME="nak-v${NAK_VERSION}-linux-${NAK_ARCH}"
URL="https://github.com/fiatjaf/nak/releases/download/v${NAK_VERSION}/${NAME}"
# Stage outside the checkout so a failed attempt cannot leave a stray binary in
# the working tree, and so nothing lands at $INSTALL_PATH before it verifies.
NAK_TMP="$(mktemp -d)"
trap 'rm -rf "$NAK_TMP"' EXIT
TMP="${NAK_TMP}/${NAME}"

# Download to a file and check it before installing. curl's own --retry does
# not cover a short read (exit 18), and a checksum mismatch needs a fresh
# download anyway, so the retry is an explicit bounded loop — the same failure
# mode that forced one on the zig step in this workflow.
verified=""
previous=""
for attempt in 1 2 3; do
  rm -f "$TMP"
  if curl -fsSL -o "$TMP" "$URL" && [ -s "$TMP" ]; then
    actual="$(sha256sum < "$TMP" | cut -d' ' -f1)"
    if [ "$actual" = "$NAK_SHA256" ]; then
      echo "nak binary matches its pinned SHA-256 (${actual})"
      verified=yes
      break
    fi
    echo "nak binary failed its checksum on attempt ${attempt}:"
    echo "  expected ${NAK_SHA256}"
    echo "  actual   ${actual}"
    echo "  size     $(wc -c < "$TMP") bytes"
    if [ "$actual" = "$previous" ]; then
      echo "Two attempts fetched byte-identical content, so retrying is not"
      echo "going to help: the pin is stale, upstream re-published, or the"
      echo "source is serving the same bad file every time."
      break
    fi
    previous="$actual"
  else
    echo "nak binary download failed on attempt ${attempt}"
  fi
  if [ "$attempt" -lt 3 ]; then
    sleep $((attempt * 10))
  fi
done

if [ -z "$verified" ]; then
  echo "nak ${NAK_VERSION} (${NAK_ARCH}) did not download with its pinned"
  echo "SHA-256 ${NAK_SHA256} in 3 attempts. Nothing installed at ${INSTALL_PATH}."
  exit 1
fi

install -m 0755 "$TMP" "$INSTALL_PATH"
echo "Installed nak ${NAK_VERSION} (${NAK_ARCH}) at ${INSTALL_PATH}"
