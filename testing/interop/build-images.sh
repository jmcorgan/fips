#!/bin/bash
# Mixed-version interop harness: build three Docker images, one per git ref.
#
# Given three git refs, this script builds the FIPS daemon from each ref and
# produces three distinct Docker images:
#
#   fips-interop:a   <- ref A  ("version under test")
#   fips-interop:b   <- ref B  ("parent")
#   fips-interop:c   <- ref C  ("release")
#
# It deliberately does NOT reuse the fips-test:latest tag — that tag is owned
# by the flake-lab and the static suite, which bake a single binary set for
# all nodes. This harness needs a different binary set per node, so each ref
# gets its own tag.
#
# Mechanism:
#   1. For each ref, `git worktree add --detach` a temp checkout of this repo.
#   2. `cargo build --release` the four binaries in that worktree.
#   3. Copy fips/fipsctl/fipstop/fips-gateway into a per-ref build context.
#   4. `docker build` that context with the testing/docker Dockerfile, tagging
#      fips-interop:<slot>.
#   5. Remove the temp worktree.
#
# The harness reuses the testing/docker/Dockerfile (and its entrypoint.sh,
# resolv.conf), so the runtime environment is identical to the static and
# rekey suites — only the daemon binaries differ between the three images.
#
# Idempotent and safe to re-run: each invocation rebuilds all three images
# from scratch and cleans up its worktrees, including stale worktrees from a
# previous interrupted run.
#
# Usage:
#   ./build-images.sh <ref-a> <ref-b> <ref-c>
#
# Example (the motivating run):
#   ./build-images.sh fix/fsp-rekey-overlapping-epoch 79975d72 v0.3.0
#
# Environment:
#   FIPS_INTEROP_KEEP_WORKTREES=1   Keep temp worktrees after build (debug).
#   CARGO_BUILD_JOBS=N              Passed through to cargo if set.
#   FIPS_INTEROP_RUNS_DIR=DIR       Root for harness scratch dirs (.build/,
#                                   .stress-runs/, generated-configs/). When
#                                   unset, falls back to in-tree paths under
#                                   testing/interop/ and prints a warning to
#                                   stderr; set it to a path outside the
#                                   source tree to keep generated artefacts
#                                   out of the checkout.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOCKER_CTX_SRC="$REPO_ROOT/testing/docker"

# ── Scratch-dir root ─────────────────────────────────────────────────
#
# FIPS_INTEROP_RUNS_DIR controls where the harness writes its scratch
# directories (.build/, .stress-runs/, generated-configs/). When unset
# we fall back to in-tree paths under testing/interop/ and warn the
# operator, so the warning fires exactly once per invocation. When a
# parent script has already warned it exports _FIPS_INTEROP_WARNED=1
# to suppress duplicate warnings in child scripts.
if [[ -n "${FIPS_INTEROP_RUNS_DIR:-}" ]]; then
    RUNS_BASE="$FIPS_INTEROP_RUNS_DIR"
    mkdir -p "$RUNS_BASE"
else
    RUNS_BASE="$SCRIPT_DIR"
    if [[ -z "${_FIPS_INTEROP_WARNED:-}" ]]; then
        echo >&2 "WARNING: FIPS_INTEROP_RUNS_DIR not set; harness output will be written under the source tree at $RUNS_BASE. Set FIPS_INTEROP_RUNS_DIR to a path outside the source tree to avoid this."
        export _FIPS_INTEROP_WARNED=1
    fi
fi

# Per-ref tag slots. Order matters: slot[i] <- ref[i].
SLOTS=(a b c)

# ── Args ─────────────────────────────────────────────────────────────

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <ref-a> <ref-b> <ref-c>" >&2
    echo "" >&2
    echo "  ref-a  version under test       -> fips-interop:a" >&2
    echo "  ref-b  parent / comparison      -> fips-interop:b" >&2
    echo "  ref-c  release baseline         -> fips-interop:c" >&2
    exit 1
fi

REFS=("$1" "$2" "$3")

# ── Preflight ────────────────────────────────────────────────────────

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker daemon is not reachable" >&2
    exit 2
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: cargo not found on PATH" >&2
    exit 2
fi

for ref in "${REFS[@]}"; do
    if ! git -C "$REPO_ROOT" rev-parse --verify --quiet "${ref}^{commit}" >/dev/null; then
        echo "ERROR: git ref '$ref' does not resolve to a commit" >&2
        exit 2
    fi
done

# ── Worktree + build-context scratch space ───────────────────────────

WORK_BASE="$RUNS_BASE/.build"
mkdir -p "$WORK_BASE"

# Track worktree paths for cleanup.
CREATED_WORKTREES=()

cleanup() {
    if [ "${FIPS_INTEROP_KEEP_WORKTREES:-}" = "1" ]; then
        echo ""
        echo "FIPS_INTEROP_KEEP_WORKTREES=1 — leaving worktrees in place:"
        for wt in "${CREATED_WORKTREES[@]:-}"; do
            [ -n "$wt" ] && echo "  $wt"
        done
        return
    fi
    for wt in "${CREATED_WORKTREES[@]:-}"; do
        [ -n "$wt" ] || continue
        if [ -d "$wt" ]; then
            git -C "$REPO_ROOT" worktree remove --force "$wt" 2>/dev/null \
                || rm -rf "$wt"
        fi
    done
    git -C "$REPO_ROOT" worktree prune 2>/dev/null || true
}
trap cleanup EXIT

# Prune any stale interop worktrees from a prior interrupted run before we
# start, so re-running the script is clean.
git -C "$REPO_ROOT" worktree prune 2>/dev/null || true

# ── Per-ref build ────────────────────────────────────────────────────

build_one() {
    local slot="$1"
    local ref="$2"
    local sha
    sha="$(git -C "$REPO_ROOT" rev-parse --short "$ref")"

    echo ""
    echo "=== Building slot '$slot'  ref='$ref'  sha=$sha ==="

    local wt="$WORK_BASE/worktree-$slot"
    local ctx="$WORK_BASE/ctx-$slot"

    # Fresh worktree per build (remove a stale one first).
    if [ -d "$wt" ]; then
        git -C "$REPO_ROOT" worktree remove --force "$wt" 2>/dev/null \
            || rm -rf "$wt"
    fi
    git -C "$REPO_ROOT" worktree add --detach "$wt" "$ref"
    CREATED_WORKTREES+=("$wt")

    # Build the four binaries from this ref.
    local cargo_jobs_arg=()
    if [ -n "${CARGO_BUILD_JOBS:-}" ]; then
        cargo_jobs_arg=(--jobs "$CARGO_BUILD_JOBS")
    fi
    (
        cd "$wt"
        cargo build --release "${cargo_jobs_arg[@]}" \
            --bin fips --bin fipsctl --bin fipstop --bin fips-gateway
    )

    # Assemble a build context: the testing/docker Dockerfile + support
    # files from the MAIN checkout, with the per-ref binaries layered in.
    rm -rf "$ctx"
    mkdir -p "$ctx"
    cp "$DOCKER_CTX_SRC/Dockerfile"    "$ctx/Dockerfile"
    cp "$DOCKER_CTX_SRC/entrypoint.sh" "$ctx/entrypoint.sh"
    cp "$DOCKER_CTX_SRC/resolv.conf"   "$ctx/resolv.conf"
    for bin in fips fipsctl fipstop fips-gateway; do
        cp "$wt/target/release/$bin" "$ctx/$bin"
        chmod +x "$ctx/$bin"
    done

    docker build \
        --label "fips.interop.slot=$slot" \
        --label "fips.interop.ref=$ref" \
        --label "fips.interop.sha=$sha" \
        -t "fips-interop:$slot" \
        "$ctx"

    # The worktree is large (target/ dir); remove it now rather than at
    # exit so peak disk use stays at one worktree, not three.
    if [ "${FIPS_INTEROP_KEEP_WORKTREES:-}" != "1" ]; then
        git -C "$REPO_ROOT" worktree remove --force "$wt" 2>/dev/null \
            || rm -rf "$wt"
        rm -rf "$ctx"
    fi

    echo "=== Built fips-interop:$slot  ($ref @ $sha) ==="
}

# Record the ref->sha mapping so the driver and README can report what
# actually ran. Written before the builds so a partial failure still
# leaves a breadcrumb.
MANIFEST="$WORK_BASE/refs.env"
{
    echo "# Generated by build-images.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    for i in 0 1 2; do
        slot="${SLOTS[$i]}"
        ref="${REFS[$i]}"
        sha="$(git -C "$REPO_ROOT" rev-parse --short "$ref")"
        upper="$(echo "$slot" | tr '[:lower:]' '[:upper:]')"
        echo "INTEROP_REF_${upper}=$ref"
        echo "INTEROP_SHA_${upper}=$sha"
    done
} > "$MANIFEST"

for i in 0 1 2; do
    build_one "${SLOTS[$i]}" "${REFS[$i]}"
done

echo ""
echo "=== All three interop images built ==="
docker image ls --filter 'reference=fips-interop' \
    --format 'table {{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.CreatedSince}}'
echo ""
echo "Ref manifest: $MANIFEST"
cat "$MANIFEST"
echo ""
echo "Next: bash testing/interop/interop-test.sh"
