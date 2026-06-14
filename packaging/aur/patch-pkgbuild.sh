#!/usr/bin/env bash
# Patch packaging/aur/PKGBUILD in place with the release pkgver, pkgrel,
# conflicts, options, and b2sums.
#
# Shared by the AUR publish workflow's real-publish job and its dry-run job
# so the patching logic lives in exactly one place.
#
# Required environment variables:
#   TAG     - release tag (e.g. v0.4.0 or v0.4.0-rc1)
#   VERSION - tag without the leading 'v' (e.g. 0.4.0)
#   PKGREL  - AUR pkgrel (positive integer)
#
# Source of the tarball b2sum:
#   Default: fetch the GitHub source archive for $TAG and hash it.
#   Dry-run: set LOCAL_TARBALL to a path; its b2sum is used instead and the
#            PKGBUILD source= line is rewritten to point at that local file.
#            This lets a dry-run validate an rc tag that has no published
#            GitHub release archive yet (the archive URL would 404).
#
# Uses $GITHUB_REPOSITORY for the source URL (owner/repo).

set -euo pipefail

: "${TAG:?TAG must be set}"
: "${VERSION:?VERSION must be set}"
: "${PKGREL:?PKGREL must be set}"

PKGBUILD="packaging/aur/PKGBUILD"

SYSUSERS_SUM=$(b2sum packaging/aur/fips.sysusers | awk '{print $1}')
TMPFILES_SUM=$(b2sum packaging/aur/fips.tmpfiles | awk '{print $1}')

if [ -n "${LOCAL_TARBALL:-}" ]; then
  # Dry-run path: hash the locally-created tarball of the checkout.
  echo "Using local tarball $LOCAL_TARBALL for b2sum (dry-run)"
  SOURCE_SUM=$(b2sum "$LOCAL_TARBALL" | awk '{print $1}')
else
  URL="https://github.com/${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}/archive/${TAG}.tar.gz"
  echo "Fetching $URL"
  SOURCE_SUM=$(curl -fsSL --retry 3 "$URL" | b2sum | awk '{print $1}')
fi

for v in SOURCE_SUM SYSUSERS_SUM TMPFILES_SUM; do
  eval val=\$$v
  if [ -z "$val" ]; then echo "$v is empty"; exit 1; fi
done

sed -i "s/^pkgver=.*/pkgver=${VERSION}/" "$PKGBUILD"
sed -i "s/^pkgrel=.*/pkgrel=${PKGREL}/" "$PKGBUILD"
sed -i "s/^conflicts=.*/conflicts=('fips-git' 'fips-git-debug')/" "$PKGBUILD"
sed -i "s/^options=.*/options=('!lto' '!debug')/" "$PKGBUILD"

if [ -n "${LOCAL_TARBALL:-}" ]; then
  # Repoint the first source entry at the local tarball so makepkg builds the
  # checked-out tree instead of fetching the (possibly unpublished) GitHub
  # archive. makepkg resolves a bare filename source against $startdir.
  LOCAL_BASE=$(basename "$LOCAL_TARBALL")
  sed -i "s|^source=(\"\$pkgname-\$pkgver.tar.gz::[^\"]*\"|source=(\"\$pkgname-\$pkgver.tar.gz::${LOCAL_BASE}\"|" "$PKGBUILD"
fi

sed -i "s|^b2sums=('SKIP'.*|b2sums=('${SOURCE_SUM}'|" "$PKGBUILD"
awk -v s1="$SYSUSERS_SUM" -v s2="$TMPFILES_SUM" '
  /^b2sums=\(/ { in_block=1; count=0 }
  in_block {
    count++
    if (count == 2) sub(/[a-f0-9]{128}/, s1)
    if (count == 3) sub(/[a-f0-9]{128}/, s2)
    if ($0 ~ /\)/) in_block=0
  }
  { print }
' "$PKGBUILD" > "$PKGBUILD.new"
mv "$PKGBUILD.new" "$PKGBUILD"

echo "Patched PKGBUILD:"
grep -E "^(pkgver|pkgrel|conflicts|options|source)=" "$PKGBUILD"
awk '/^b2sums=\(/,/\)$/' "$PKGBUILD"
