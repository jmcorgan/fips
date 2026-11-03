#!/bin/bash
# ── Mutation lane ───────────────────────────────────────────────────────────
# Each patch in this directory puts back the shape a real defect took, or
# makes the smallest change that fixes a known defect. manifest.txt names, for
# each patch, the tests it must turn red and the tests it must let pass. This
# script applies each patch, builds both library test binaries once, runs each
# named test as its own process, classifies the run with
# testing/lib/test-verdict.sh, and reverts the patch.
#
# A `red` line holds when the test fails at the behaviour the patch breaks:
#   - with no anchor, the class must be `defect` (the test's own `defect:`
#     assertion);
#   - with an anchor, the class must be `defect` or `unmarked`, and the anchor
#     must be a substring of the panic's first message line, or the panic
#     location must be at the anchor's `file:line`. An existing test that
#     predates the `defect:` marker is checked this way.
# A `pass` line holds when the test passes. `precondition`, `timeout` and
# `norun` never hold: a test that broke in setup or hung has not shown the
# patch's effect.
#
# A patch that no longer applies reds the lane; it is never skipped. Every
# test name must resolve in its binary before any patch is applied.
#
# Environment:
#   FIPS_MUTATION_TIMEOUT  seconds per test run (default 120)
#   FIPS_MUTATION_ONLY     run only the patch of this name (for trying one)
#
# Exit 0 = every manifest line held. Exit 1 = a line missed, a patch did not
# apply, a test name did not resolve, or the tree was not clean afterwards.
# Exit 2 = the lane could not run (dirty tree before, build failed, manifest
# unreadable).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MANIFEST="$SCRIPT_DIR/manifest.txt"
LIMIT="${FIPS_MUTATION_TIMEOUT:-120}"
ONLY="${FIPS_MUTATION_ONLY:-}"

cd "$PROJECT_ROOT" || exit 2
[[ -r "$MANIFEST" ]] || { echo "mutation-lane: cannot read $MANIFEST" >&2; exit 2; }
if [[ -n "$(git status --porcelain)" ]]; then
    echo "mutation-lane: the tree has uncommitted changes; commit or stash them first" >&2
    exit 2
fi

# shellcheck source-path=SCRIPTDIR source=../lib/test-verdict.sh disable=SC1091
source "$SCRIPT_DIR/../lib/test-verdict.sh"

# The manifest's lines: patch, expectation, crate, test, anchor.
declare -a M_PATCH=() M_WANT=() M_CRATE=() M_TEST=() M_ANCHOR=()
while IFS=$'\t' read -r patch want crate test anchor; do
    [[ -z "$patch" || "$patch" == \#* ]] && continue
    M_PATCH+=("$patch"); M_WANT+=("$want"); M_CRATE+=("$crate")
    M_TEST+=("$test"); M_ANCHOR+=("${anchor:-}")
done <"$MANIFEST"
[[ ${#M_PATCH[@]} -gt 0 ]] || { echo "mutation-lane: the manifest names no test" >&2; exit 2; }

misses=0
miss() {
    echo "mutation-lane: MISS $*"
    misses=$((misses + 1))
    return 0
}

start_all=$(date +%s)
echo "mutation-lane: building the healthy tree"
test_bins || exit 2

# Every name resolves, and every expectation and patch is well formed. Each
# binary is listed once, into a variable: a `grep -q` reading the listing
# through a pipe would stop it early, and pipefail would count that as a
# missing name.
declare -A LISTED=()
for pkg in fips-mesh fips-core; do
    LISTED[$pkg]=$("${BIN[$pkg]}" --list --format terse 2>/dev/null) || {
        echo "mutation-lane: listing $pkg's tests failed" >&2
        exit 2
    }
done
for i in "${!M_PATCH[@]}"; do
    case "${M_WANT[$i]}" in red | pass) ;; *) miss "line $((i + 1)): expectation ${M_WANT[$i]}" ;; esac
    [[ -r "$SCRIPT_DIR/${M_PATCH[$i]}.patch" ]] || miss "line $((i + 1)): no patch ${M_PATCH[$i]}.patch"
    if ! grep -qxF "${M_TEST[$i]}: test" <<<"${LISTED[${M_CRATE[$i]}]:-}"; then
        miss "line $((i + 1)): ${M_CRATE[$i]} has no test ${M_TEST[$i]}"
    fi
done
if [[ $misses -gt 0 ]]; then
    echo "mutation-lane: $misses problem(s) in the manifest; no patch was applied"
    exit 1
fi

applied=""
revert() {
    if [[ -n "$applied" ]]; then
        git apply -R "$SCRIPT_DIR/$applied.patch" || echo "mutation-lane: could not revert $applied" >&2
        applied=""
    fi
    return 0
}
trap revert EXIT INT TERM

# The patches, in manifest order, each once.
declare -a PATCHES=()
for p in "${M_PATCH[@]}"; do
    [[ " ${PATCHES[*]} " == *" $p "* ]] || PATCHES+=("$p")
done

for patch in "${PATCHES[@]}"; do
    [[ -n "$ONLY" && "$patch" != "$ONLY" ]] && continue
    t0=$(date +%s)
    echo "== $patch"
    if ! git apply --check "$SCRIPT_DIR/$patch.patch" 2>&1; then
        miss "$patch: the patch does not apply"
        continue
    fi
    git apply "$SCRIPT_DIR/$patch.patch" || { miss "$patch: git apply failed"; continue; }
    applied="$patch"
    if ! test_bins; then
        miss "$patch: the patched tree does not build"
        revert
        continue
    fi
    for i in "${!M_PATCH[@]}"; do
        [[ "${M_PATCH[$i]}" == "$patch" ]] || continue
        name="${M_TEST[$i]}" want="${M_WANT[$i]}" anchor="${M_ANCHOR[$i]}"
        ts=$(date +%s%N)
        out=$(timeout -k 5 "$LIMIT" "${BIN[${M_CRATE[$i]}]}" --include-ignored --exact "$name" 2>&1)
        rc=$?
        IFS=$'\t' read -r class loc msg < <(verdict "$out" "$rc" "$name")
        tenths=$(( ($(date +%s%N) - ts) / 100000000 ))
        held=no
        if [[ "$want" == pass ]]; then
            [[ "$class" == passed ]] && held=yes
        elif [[ -z "$anchor" ]]; then
            [[ "$class" == defect ]] && held=yes
        elif [[ "$class" == defect || "$class" == unmarked ]]; then
            if [[ "$msg" == *"$anchor"* || "$loc" == "$anchor":* ]]; then
                held=yes
            fi
        fi
        line="$want $name ($((tenths / 10)).$((tenths % 10)) s): $class${loc:+ at $loc}${msg:+: $msg}"
        if [[ $held == yes ]]; then
            echo "   held  $line"
        else
            miss "$patch: $line${anchor:+ (anchor: $anchor)}"
        fi
    done
    revert
    echo "   $patch: $(($(date +%s) - t0)) s"
done
trap - EXIT INT TERM

if [[ -n "$(git status --porcelain)" ]]; then
    miss "the tree is not clean after the patches were reverted"
    git status --short
fi
echo "mutation-lane: total $(($(date +%s) - start_all)) s"
if [[ $misses -gt 0 ]]; then
    echo "mutation-lane: $misses miss(es)"
    exit 1
fi
echo "mutation-lane: every line of $(basename "$MANIFEST") held"
exit 0
