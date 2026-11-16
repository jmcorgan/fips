#!/bin/bash
# Tests for testing/check-ci-parity.sh: each case copies the files the check
# reads (ci.yml, ci-local.sh, the install suites' scenario lists and the
# cross-check target list) into a scratch tree, plants one divergence, and
# runs the check there. The healthy copy must pass; a unit-test step or a
# suite added to ci.yml only, a stage dropped from or added to ci-local.sh's
# tier 2 only, and an exception removed from the check's lists must each
# fail it, naming what diverged.
#
# Hermetic: nothing is built or started, and the tree under test is never
# written. Each case runs the check once, which runs ci-local.sh --tier 2
# --plan; a few seconds in all.
#
# Run:
#   ./ci-parity-test.sh
# Exits 0 only if every case passes; non-zero if any case fails.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
FAILURES=0

# Record a single assertion result.
check() {
    local name="$1" ok="$2" detail="${3:-}"
    if [ "$ok" -eq 0 ]; then
        echo "PASS  $name${detail:+  ($detail)}"
    else
        echo "FAIL  $name${detail:+  ($detail)}"
        FAILURES=$((FAILURES + 1))
    fi
    return 0
}

# A fresh copy of what the check reads, at $SCRATCH/tree.
fresh() {
    local f
    rm -rf "$SCRATCH/tree"
    for f in Cargo.toml .github/workflows/ci.yml testing/ci-local.sh \
            testing/check-ci-parity.sh testing/deb-install/test.sh \
            testing/rpm-install/test.sh testing/cross-check/check.sh; do
        mkdir -p "$SCRATCH/tree/$(dirname "$f")"
        cp "$ROOT/$f" "$SCRATCH/tree/$f" || return 1
    done
    return 0
}

# Replace the first occurrence of $2 with $3 in the copy of file $1; fail the
# case's setup, loudly, if $2 is not there, since the plant would be a no-op.
plant() {
    python3 - "$SCRATCH/tree/$1" "$2" "$3" <<'PY'
import sys
path, old, new = sys.argv[1:4]
text = open(path).read()
if old not in text:
    sys.exit(f"ci-parity-test: plant target not found in {path}: {old[:60]!r}")
open(path, "w").write(text.replace(old, new, 1))
PY
}

# Run the check on the copy; sets RC and OUT.
run_check() {
    RC=0
    OUT="$(bash "$SCRATCH/tree/testing/check-ci-parity.sh" 2>&1)" || RC=$?
    return 0
}

# Assert the check fails (exit 1) and names the divergence.
expect_red() {
    local name="$1" text="$2"
    run_check
    check "$name: fails" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)" "rc=$RC"
    check "$name: names it" "$(grep -qF -- "$text" <<<"$OUT" && echo 0 || echo 1)" \
        "want '$text'"
    return 0
}

fresh || { echo "ci-parity-test: could not copy the tree" >&2; exit 2; }
run_check
check "the healthy tree passes" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)" "rc=$RC"

fresh && plant .github/workflows/ci.yml \
    "      - name: Run the known-defect lane" \
    "      - name: Run a check only GitHub has
        run: true

      - name: Run the known-defect lane"
expect_red "a unit-test step in ci.yml only" \
    "test-core: step 'Run a check only GitHub has' maps to no ci-local.sh result"

fresh && plant .github/workflows/ci.yml \
    "          - suite: gateway" \
    "          - suite: github-only-suite
          - suite: gateway"
expect_red "a suite in ci.yml only" "github-only-suite"

fresh && plant testing/ci-local.sh \
    "        MUTATIONS=true
        MUSL=true" \
    "        MUSL=true"
expect_red "the mutation lane dropped from tier 2 only" \
    "GitHub runs the work of mutations, which ci-local.sh --tier 2 does not"

fresh && plant testing/ci-local.sh \
    '    "run_veth_host veth-host"' \
    '    "run_veth_host veth-host"
    "run_local_guard local-guard"'
expect_red "a guard added to tier 2 only" \
    "tier 2 stage local-guard has no GitHub step mapped to it"

fresh && plant .github/workflows/ci.yml \
    "      - name: Run the mutation lane" \
    "      - name: Run the mutation lane, renamed"
expect_red "a mapped step renamed in ci.yml" \
    "test-mutations: mapped step 'Run the mutation lane' is no longer in ci.yml"

fresh && plant testing/check-ci-parity.sh \
    'LOCAL_ONLY = {"cross-check-*": "zig compiles of targets GitHub builds natively"}' \
    'LOCAL_ONLY = {}'
expect_red "the cross-check exception removed" \
    "tier 2 stage cross-check-x86_64-apple-darwin has no GitHub step mapped to it"

fresh && plant testing/check-ci-parity.sh \
    '    ("test", "Report tests that passed only on retry"):
        "nextest'"'"'s ci profile retries; the internal builder has no nextest yet",' \
    ''
expect_red "the retry-flake report exception removed" \
    "test: step 'Report tests that passed only on retry' maps to no ci-local.sh result"

fresh && plant testing/check-ci-parity.sh \
    '    "test-macos": "native macOS unit tests",' \
    ''
expect_red "the macOS job exception removed" \
    "job test-macos is in no list of this check"

fresh && plant .github/workflows/ci.yml \
    "      - name: Build
        if: matrix.os != 'ubuntu-latest'" \
    "      - name: Build"
expect_red "the build job's release build run on ubuntu-latest" \
    "build: step 'Build' runs on ubuntu-latest, where deb-build is the release build"

fresh && plant testing/ci-local.sh \
    "    deb_early && echo deb-build" \
    ""
expect_red "the .deb build dropped from tier 2 only" \
    "GitHub runs the work of deb-build, which ci-local.sh --tier 2 does not"

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "All check-ci-parity.sh cases passed"
    exit 0
fi
echo "$FAILURES check-ci-parity.sh case(s) failed"
exit 1
