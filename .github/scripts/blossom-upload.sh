#!/bin/bash
# ── Upload one file to a Blossom server ─────────────────────────────────────
# Usage: blossom-upload.sh <server> <file>
#
# Uploads <file> with `nak blossom upload`, signing with the nsec in $NSEC, in
# up to three attempts. On success it writes `url=<server>/<sha256>` and
# `hash=<sha256>` to $GITHUB_OUTPUT, for the NIP-94 publish step that follows,
# and exits 0. On failure it exits 1.
#
# nak sends a Content-Type it looks up from the file's extension in the host's
# MIME table, which maps .apk to Android's package type, and
# blossom.primal.net refuses that type with HTTP 415. So the file is uploaded
# from a copy with no extension, which nak sends as application/octet-stream,
# the type the accepted .ipk uploads carry. The Blossom address is the
# content's hash, so the name uploaded is not visible anywhere; the NIP-94
# event carries the real filename.
#
# A failed upload is not fatal to the release, which already carries the
# package, but it is made visible: a ::warning:: annotation and a line in the
# run summary ($GITHUB_STEP_SUMMARY), since the NIP-94 event for the file is
# then not published.
#
# Called from .github/workflows/package-openwrt.yml by both the .ipk (`build`)
# and .apk (`build-apk`) jobs' "Upload to Blossom" steps, which run on release
# tags only. .github/scripts/test-blossom-upload.sh tests it against a stub
# server.
#
# BLOSSOM_RETRY_DELAY scales the pause between attempts (attempt N waits N
# times this many seconds); the default is 10. The test sets it to 0.
# ─────────────────────────────────────────────────────────────────────────────
set -eo pipefail

SERVER="${1:?usage: blossom-upload.sh <server> <file>}"
FILE="${2:?usage: blossom-upload.sh <server> <file>}"
DELAY="${BLOSSOM_RETRY_DELAY:-10}"
: "${GITHUB_OUTPUT:=/tmp/github_output}"

STAGE=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/blossom.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
UPLOAD="$STAGE/blossom-$(sha256sum "$FILE" | cut -d' ' -f1)"
cp "$FILE" "$UPLOAD"

FILE_HASH=""
for attempt in 1 2 3; do
  if UPLOAD_RESPONSE=$(nak blossom upload \
    --server "$SERVER" \
    --sec "$NSEC" \
    "$UPLOAD" < /dev/null); then
    echo "Upload response (attempt $attempt):"
    echo "$UPLOAD_RESPONSE"
    FILE_HASH=$(echo "$UPLOAD_RESPONSE" | jq -r '.sha256')
    if [ -n "$FILE_HASH" ] && [ "$FILE_HASH" != "null" ]; then
      break
    fi
    echo "Upload response had no sha256 (attempt $attempt)"
  else
    echo "Blossom upload timed out or failed (attempt $attempt)"
  fi
  FILE_HASH=""
  [ "$attempt" -lt 3 ] && sleep $((attempt * DELAY))
done

if [ -z "$FILE_HASH" ] || [ "$FILE_HASH" = "null" ]; then
  echo "Blossom upload did not succeed after 3 attempts; non-fatal."
  echo "The package still ships as a GitHub release artifact; only the"
  echo "supplementary Blossom/nostr distribution is skipped this run."
  echo "::warning::Blossom upload of $(basename "$FILE") to $SERVER failed after 3 attempts; no NIP-94 event is published for it"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "- Blossom upload of \`$(basename "$FILE")\` to $SERVER failed after 3 attempts; no NIP-94 event was published for it." >> "$GITHUB_STEP_SUMMARY"
  fi
  exit 1
fi

BLOSSOM_URL="${SERVER}/${FILE_HASH}"
echo "url=$BLOSSOM_URL" >> "$GITHUB_OUTPUT"
echo "hash=$FILE_HASH" >> "$GITHUB_OUTPUT"
echo "Uploaded to Blossom: $BLOSSOM_URL"
