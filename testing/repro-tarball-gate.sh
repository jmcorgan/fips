#!/usr/bin/env bash
# Gate 11: build the systemd install tarball twice and compare the two byte for byte.
#
# packaging/systemd/build-tarball.sh already carries the tar-level determinism work
# (SOURCE_DATE_EPOCH, --mtime, --sort=name, --numeric-owner --owner=0 --group=0).
# What has never existed at any FIPS release is a wrapper that actually builds twice
# and compares, so this supplies only that.
#
# Builds run in throwaway worktrees, never in a working checkout, so no existing
# target/ cache is destroyed and no checkout is left dirty.
#
#   A and B  same path, built twice  -- this is the gate
#   C        a different path        -- probe only, never gating: there is no
#            [profile.release], no .cargo/config.toml and no --remap-path-prefix,
#            so an absolute build path can reach the binaries
#
# Usage: testing/repro-tarball-gate.sh <ref> [src-repo] [out-dir]
# Exit:  0 if A and B are identical, 1 if they differ, 2 on a setup failure.

set -euo pipefail

REF="${1:?usage: repro-tarball-gate.sh <ref> [src-repo] [out-dir]}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_REPO="${2:-${REPO_ROOT}}"
# Under target/, which is gitignored, so a gate run never dirties the checkout
# it was launched from.
OUT_DIR="${3:-${REPO_ROOT}/target/repro-tarball}"

# `--git-dir` rather than a test for a .git directory: a linked worktree carries
# a .git file, and the release runs this out of whatever checkout is to hand.
git -C "${SRC_REPO}" rev-parse --git-dir >/dev/null 2>&1 \
    || { echo "no source checkout at ${SRC_REPO}" >&2; exit 2; }

SHA="$(git -C "${SRC_REPO}" rev-parse "${REF}")"
# Pin explicitly rather than letting build-tarball.sh derive it, so all three
# builds share one value even if they are cut from different worktrees.
SOURCE_DATE_EPOCH="$(git -C "${SRC_REPO}" log -1 --format=%ct "${SHA}")"
export SOURCE_DATE_EPOCH

WORK="$(mktemp -d -t repro-gate-XXXXXX)"
mkdir -p "${OUT_DIR}"
trap 'for w in "${WORK}"/*; do [ -d "$w" ] && git -C "${SRC_REPO}" worktree remove --force "$w" 2>/dev/null || true; done; rm -rf "${WORK}"' EXIT

echo "ref              ${REF} (${SHA})"
echo "SOURCE_DATE_EPOCH ${SOURCE_DATE_EPOCH}"
echo "work             ${WORK}"
echo

# Build one tarball in a fresh worktree at $1, leaving it at $2.
build() {
    local dir="$1" dest="$2" label="$3"
    echo "=== ${label}: ${dir}"
    git -C "${SRC_REPO}" worktree add --detach --quiet "${dir}" "${SHA}"
    ( cd "${dir}" && ./packaging/systemd/build-tarball.sh ) >"${OUT_DIR}/${label}.log" 2>&1 || {
        echo "${label}: build failed, see ${OUT_DIR}/${label}.log" >&2
        tail -20 "${OUT_DIR}/${label}.log" >&2
        exit 2
    }
    local tb
    tb="$(ls "${dir}"/deploy/*.tar.gz)"
    cp "${tb}" "${dest}"
    echo "${label}: $(sha256sum "${dest}" | cut -d' ' -f1)  $(basename "${tb}")"
    git -C "${SRC_REPO}" worktree remove --force "${dir}"
}

# A and B share one path, so the second reuses nothing: the worktree is removed
# and recreated between them, which is what makes this a real rebuild.
build "${WORK}/same"  "${OUT_DIR}/A.tar.gz" A
build "${WORK}/same"  "${OUT_DIR}/B.tar.gz" B
build "${WORK}/other-path-for-the-probe" "${OUT_DIR}/C.tar.gz" C

echo
rc=0
if cmp -s "${OUT_DIR}/A.tar.gz" "${OUT_DIR}/B.tar.gz"; then
    echo "GATE PASS: A and B are byte-identical"
else
    echo "GATE FAIL: A and B differ"
    rc=1
fi

if cmp -s "${OUT_DIR}/A.tar.gz" "${OUT_DIR}/C.tar.gz"; then
    echo "PROBE: a different build path changes nothing"
else
    echo "PROBE: a different build path changes the tarball (not gating)"
fi

# Localize any difference to the file level, for both the gate and the probe.
for pair in A:B A:C; do
    l="${pair%%:*}"; r="${pair##*:}"
    cmp -s "${OUT_DIR}/${l}.tar.gz" "${OUT_DIR}/${r}.tar.gz" && continue
    echo
    echo "--- per-member digests, ${l} vs ${r}"
    for s in "${l}" "${r}"; do
        rm -rf "${WORK}/x-${s}"; mkdir -p "${WORK}/x-${s}"
        tar -xzf "${OUT_DIR}/${s}.tar.gz" -C "${WORK}/x-${s}"
        ( cd "${WORK}/x-${s}" && find . -type f | sort | xargs sha256sum ) >"${WORK}/d-${s}.txt"
    done
    diff "${WORK}/d-${l}.txt" "${WORK}/d-${r}.txt" || true
done

exit "${rc}"
