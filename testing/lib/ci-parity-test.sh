#!/bin/bash
# Tests for testing/check-ci-parity.sh: each case copies the files the check
# reads (ci.yml, ci-local.sh, the install suites' scenario lists and the
# cross-check target list) into a scratch tree, plants one divergence, and
# runs the check there. The healthy copy must pass; a unit-test step or a
# suite added to ci.yml only, a stage dropped from or added to ci-local.sh's
# tier 2 only, an exception removed from the check's lists, a mapped step
# or a suite leg's step that keeps its name but runs something else,
# nothing, or the explorers, or cannot fail, the explorers in a package
# workflow, and a nightly-only chaos scenario without its reason, back in
# tier 2 or on GitHub, or out of tier 3's batch must each fail it, naming
# what diverged.
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
    '    "run_fwtable fw-table"' \
    '    "run_fwtable fw-table"
    "run_local_guard local-guard"'
expect_red "a guard added to tier 2 only" \
    "tier 2 stage local-guard has no GitHub step mapped to it"

fresh && plant .github/workflows/ci.yml \
    "      - name: Run the mutation lane" \
    "      - name: Run the mutation lane, renamed"
expect_red "a mapped step renamed in ci.yml" \
    "test-mutations: mapped step 'Run the mutation lane' is no longer in ci.yml"

fresh && plant testing/check-ci-parity.sh \
    '    "cross-check-*": "zig compiles of targets GitHub builds natively",' \
    ''
expect_red "the cross-check exception removed" \
    "tier 2 stage cross-check-x86_64-apple-darwin has no GitHub step mapped to it"

fresh && plant testing/check-ci-parity.sh \
    '    "root-explorers": "the real-node walks run at incus tier 2 only (operator, 2026-11-24)",' \
    ''
expect_red "the root walks' exception removed" \
    "tier 2 stage root-explorers has no GitHub step mapped to it"

fresh && plant testing/check-ci-parity.sh \
    '    "mutations-explorers": "the real-node walks run at incus tier 2 only (operator, 2026-11-24)",' \
    ''
expect_red "the explorer mutation lines' exception removed" \
    "tier 2 stage mutations-explorers has no GitHub step mapped to it"

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

# What a mapped step runs, not only its name: each of these keeps the step's
# name and changes or empties its command.
fresh && plant .github/workflows/ci.yml \
    "          bash testing/known-defect-lane.sh" \
    "          true"
expect_red "the known-defect lane's run line replaced by true" \
    "test-core: mapped step 'Run the known-defect lane' does not run 'testing/known-defect-lane.sh'"

fresh && plant .github/workflows/ci.yml \
    "          cargo test -p fips-core --features slow-tests" \
    "          cargo test -p fips-core --features slow-explorers"
expect_red "the core's slow suites changed to the explorers" \
    "test-core: step 'Run the no_std core's tests on their own, with its slow suites' runs fips-core's slow-explorers feature"

fresh && plant .github/workflows/ci.yml \
    "          cargo test -p fips-mesh --lib --features profiling,test-overrides" \
    "          cargo test -p fips-mesh --lib --features profiling,test-overrides,explorers"
expect_red "the root crate's explorers feature added to a test run" \
    "runs the root crate's explorers feature"

fresh && plant .github/workflows/ci.yml \
    "          bash testing/mutations/run.sh" \
    "          FIPS_MUTATION_EXPLORERS=1 bash testing/mutations/run.sh"
expect_red "the mutation lane's explorer lines turned on" \
    "test-mutations: step 'Run the mutation lane' runs the mutation lane's explorer lines"

fresh && plant testing/check-ci-parity.sh \
    '    ("test-core", "Run the known-defect lane"): ["testing/known-defect-lane.sh"],' \
    ''
expect_red "a mapped step with no fragment entry" \
    "test-core: mapped step 'Run the known-defect lane' has no entry in CMDS"

fresh && plant .github/workflows/ci.yml \
    "          bash testing/known-defect-lane.sh" \
    "          true  # bash testing/known-defect-lane.sh"
expect_red "the known-defect lane only in a comment" \
    "test-core: mapped step 'Run the known-defect lane' does not run 'testing/known-defect-lane.sh'"

fresh && plant .github/workflows/ci.yml \
    "          bash testing/known-defect-lane.sh" \
    "          echo bash testing/known-defect-lane.sh"
expect_red "the known-defect lane only in an echo" \
    "test-core: mapped step 'Run the known-defect lane' does not run 'testing/known-defect-lane.sh'"

fresh && plant .github/workflows/ci.yml \
    "          bash testing/known-defect-lane.sh" \
    "          bash testing/known-defect-lane.sh || true"
expect_red "the known-defect lane neutralised by || true" \
    "test-core: mapped step 'Run the known-defect lane' cannot fail: 'bash testing/known-defect-lane.sh || true'"

fresh && plant .github/workflows/ci.yml \
    "          bash testing/known-defect-lane.sh" \
    "          bash testing/known-defect-lane.sh || echo skipped"
expect_red "the known-defect lane neutralised by || echo" \
    "test-core: mapped step 'Run the known-defect lane' cannot fail: 'bash testing/known-defect-lane.sh || echo skipped'"

fresh && plant .github/workflows/ci.yml \
    "          bash testing/known-defect-lane.sh" \
    "          exit 0
          bash testing/known-defect-lane.sh"
expect_red "an exit 0 before the known-defect lane" \
    "test-core: mapped step 'Run the known-defect lane' skips its command: 'exit 0'"

fresh && plant .github/workflows/ci.yml \
    "          bash testing/known-defect-lane.sh" \
    "          : bash testing/known-defect-lane.sh"
expect_red "the known-defect lane handed to :" \
    "test-core: mapped step 'Run the known-defect lane' skips its command: ': bash testing/known-defect-lane.sh'"

fresh && plant .github/workflows/ci.yml \
    "          bash testing/known-defect-lane.sh" \
    "          if false; then bash testing/known-defect-lane.sh; fi"
expect_red "the known-defect lane behind if false" \
    "test-core: mapped step 'Run the known-defect lane' skips its command"

fresh && plant .github/workflows/ci.yml \
    "          bash testing/known-defect-lane.sh" \
    "          bash testing/known-defect-lane.sh | tee kd.log"
expect_red "the known-defect lane piped in a shell without pipefail" \
    "test-core: mapped step 'Run the known-defect lane' hides the exit status of 'testing/known-defect-lane.sh' behind a pipe"

fresh && plant .github/workflows/ci.yml \
    "      - name: Run the known-defect lane
        run: |" \
    "      - name: Run the known-defect lane
        env:
          LANE: testing/known-defect-lane.sh
        run: |" \
    && plant .github/workflows/ci.yml \
    "          bash testing/known-defect-lane.sh" \
    "          true"
expect_red "the known-defect lane only in the step's env" \
    "test-core: mapped step 'Run the known-defect lane' does not run 'testing/known-defect-lane.sh'"

fresh && plant .github/workflows/ci.yml \
    "      - name: Run the known-defect lane" \
    "      - name: Run the known-defect lane
        if: \${{ false && github.ref }}"
expect_red "the known-defect lane under a false conjunction" \
    "test-core: mapped step 'Run the known-defect lane' never runs"

fresh && plant .github/workflows/ci.yml \
    "          cargo test -p fips-core --features slow-tests" \
    "          cargo test -p fips-core --features slow-tests --no-run"
expect_red "the core's slow suites built but not run" \
    "test-core: mapped step 'Run the no_std core's tests on their own, with its slow suites' builds its tests but runs none"

fresh && plant .github/workflows/ci.yml \
    "          cargo test -p fips-mesh --lib --features profiling,test-overrides" \
    "          cargo test -p fips-mesh --lib --features profiling,test-overrides --features \"test-overrides explorers\""
expect_red "the root crate's explorers in a quoted, space-separated feature list" \
    "test-features: step 'Run library tests with the optional root features enabled' runs the root crate's explorers feature"

fresh && plant .github/workflows/ci.yml \
    "          cargo test -p fips-core --features slow-tests" \
    "          cargo test -p fips-core --features slow-tests,\${{ matrix.extra }}" \
    && plant .github/workflows/ci.yml \
    "  test-core:
    name:" \
    "  test-core:
    strategy:
      matrix:
        extra: [slow-explorers]
    name:"
expect_red "the core's explorers supplied by a matrix value" \
    "test-core: step 'Run the no_std core's tests on their own, with its slow suites' runs fips-core's slow-explorers feature"

cp "$ROOT/.github/workflows/package-freebsd.yml" "$SCRATCH/freebsd.yml"
fresh && cp "$SCRATCH/freebsd.yml" "$SCRATCH/tree/.github/workflows/package-freebsd.yml" \
    && run_check \
    && check "the healthy tree with the FreeBSD package workflow passes" \
        "$([ "$RC" -eq 0 ] && echo 0 || echo 1)" "rc=$RC" \
    && plant .github/workflows/package-freebsd.yml \
    "            cargo test --no-run" \
    "            cargo test --no-run --features explorers"
expect_red "the root crate's explorers in a push-started package workflow" \
    "package-freebsd.yml: build: step"

# The suite jobs: each kind of leg needs the step that runs its suite, under
# the if: that selects it, able to fail.
fresh && plant .github/workflows/ci.yml \
    "        run: bash testing/nat/scripts/nat-test.sh \${{ matrix.scenario }}" \
    "        run: true"
expect_red "the NAT legs' run line replaced by true" \
    "integration: suite step 'Run NAT lab scenario' does not run 'bash testing/nat/scripts/nat-test.sh \${{ matrix.scenario }}'"

fresh && plant .github/workflows/ci.yml \
    "        run: bash testing/chaos/scripts/chaos.sh \${{ matrix.scenario }} \${{ matrix.chaos_flags }}" \
    "        run: bash testing/chaos/scripts/chaos.sh \${{ matrix.scenario }} \${{ matrix.chaos_flags }} || true"
expect_red "the chaos legs neutralised by || true" \
    "integration: suite step 'Run chaos scenario' cannot fail"

fresh && plant .github/workflows/ci.yml \
    "      - name: Run chaos scenario
        if: matrix.type == 'chaos'" \
    "      - name: Run chaos scenario
        if: matrix.type == 'chaos-off'"
expect_red "the chaos step selected by a type no leg has" \
    "integration: suite step 'Run chaos scenario' runs under if: \"matrix.type == 'chaos-off'\""

fresh && plant .github/workflows/ci.yml \
    "          - suite: mdns
            type: mdns" \
    "          - suite: mdns
            type: mdns-lan"
expect_red "an integration leg whose type no suite step selects" \
    "integration: legs of type mdns-lan have no step in SUITE_CMDS"

fresh && plant .github/workflows/ci.yml \
    "      - name: Run the known-defect lane" \
    "      - name: Run the known-defect lane
        if: false"
expect_red "the known-defect lane under if: false" \
    "test-core: mapped step 'Run the known-defect lane' never runs"

fresh && plant .github/workflows/ci.yml \
    "      - name: Run the known-defect lane" \
    "      - name: Run the known-defect lane
        continue-on-error: true"
expect_red "the known-defect lane under continue-on-error" \
    "test-core: mapped step 'Run the known-defect lane' cannot fail its run"

# The nightly-only chaos scenarios: each needs its reason in the check, and
# must stay out of tier 2 and GitHub and in tier 3's batch.
fresh && plant testing/check-ci-parity.sh \
    '    "congestion-stress": "176 recorded runs met none of its criteria, cause "
        "unknown",' \
    ''
expect_red "a nightly-only scenario's exception removed" \
    "congestion-stress is in ci-local.sh's NIGHTLY_CHAOS but has no entry in NIGHTLY_ONLY"

fresh && plant .github/workflows/ci.yml \
    "          - suite: tcp-mesh" \
    "          - suite: dual-udp-flap
            type: chaos
            scenario: dual-udp-flap
          - suite: tcp-mesh"
expect_red "a nightly-only scenario back on GitHub" \
    "dual-udp-flap is nightly-only but a GitHub leg runs scenario dual-udp-flap on every push"

fresh && plant testing/ci-local.sh \
    '    "tcp-mesh tcp-mesh"' \
    '    "tcp-mesh tcp-mesh"
    "dual-udp-flap dual-udp-flap"'
expect_red "a nightly-only scenario back in tier 2" \
    "dual-udp-flap is in both NIGHTLY_CHAOS and CHAOS_SUITES"

# shellcheck disable=SC2016  # the plant is ci-local.sh's text, not this shell's
fresh && plant testing/ci-local.sh \
    '    for entry in "${CHAOS_SUITES[@]}" "${NIGHTLY_CHAOS[@]}"; do
        read -ra parts <<< "$entry"
        for (( i = 1;' \
    '    for entry in "${CHAOS_SUITES[@]}"; do
        read -ra parts <<< "$entry"
        for (( i = 1;'
expect_red "the nightly-only scenarios dropped from tier 3's batch" \
    "two-bound-udp-bulk is nightly-only but tier 3's chaos part does not batch it"

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "All check-ci-parity.sh cases passed"
    exit 0
fi
echo "$FAILURES check-ci-parity.sh case(s) failed"
exit 1
