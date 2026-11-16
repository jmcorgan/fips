#!/bin/bash
# Tests for ci-local.sh's plan check: a green tier run must record exactly
# the results --plan lists for its tier, less the stages it skipped for want
# of something on the host (check_plan). Each case loads ci-local.sh's
# configuration, stage lists and plan functions, plants a set of recorded
# results, and runs check_plan on them: the plan itself passes, a missing or
# an extra result fails and is named, and a skipped stage is not counted as
# missing.
#
# Nothing is built or started: the functions are read out of ci-local.sh and
# run in this shell, and record() is a stand-in that only stores the result.
# About a second.
#
# Run:
#   ./ci-plan-test.sh
# Exits 0 only if every case passes; non-zero if any case fails.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CI_LOCAL="$SCRIPT_DIR/ci-local.sh"

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

# The part of ci-local.sh that defines the switches, the suite arrays, the
# helpers and the plan, then check_plan and skip_stage. If any is missing the
# test cannot run, which is not a pass.
defs="$(sed -n '/^# ── Configuration/,/^# ── Parse arguments/p' "$CI_LOCAL")
$(awk '/^(check_plan|skip_stage)\(\) \{/,/^}/' "$CI_LOCAL")"
for fn in print_plan apply_tier nightly_chaos check_plan skip_stage; do
    if ! grep -q "^$fn() {" <<<"$defs"; then
        echo "ci-plan-test: $fn() not found in $CI_LOCAL; nothing was tested" >&2
        exit 2
    fi
done

# Load the definitions for tier $1 with no results yet, in this shell.
load() {
    eval "$defs"
    # shellcheck disable=SC2034  # read by the functions loaded from ci-local.sh
    TIER="$1"
    apply_tier 2>/dev/null
    declare -gA RESULTS=()
    record() { RESULTS["$1"]=$2; return 0; }
    return 0
}

# Record every result the plan lists for the loaded tier, except those named.
record_plan() {
    local name
    while read -r name; do
        [[ " $* " == *" $name "* ]] || record "$name" 0
    done < <(print_plan | grep -v '^#')
    return 0
}

# Run check_plan; sets OUT and whether it recorded plan-match.
run_check() {
    OUT="$(check_plan 2>&1; echo "plan-match=${RESULTS[plan-match]:-none}")"
    return 0
}

for tier in 1 2 3; do
    load "$tier"
    record_plan
    run_check
    check "tier $tier: the plan itself passes" \
        "$(grep -qx 'plan-match=none' <<<"$OUT" && echo 0 || echo 1)"
done

load 1
record_plan unit-tests
run_check
check "tier 1: a missing result fails" \
    "$(grep -qx 'plan-match=1' <<<"$OUT" && echo 0 || echo 1)"
check "tier 1: the missing result is named" \
    "$(grep -qF 'planned, not recorded: unit-tests' <<<"$OUT" && echo 0 || echo 1)"

load 1
record_plan
record mutations 0
run_check
check "tier 1: an extra result fails" \
    "$(grep -qx 'plan-match=1' <<<"$OUT" && echo 0 || echo 1)"
check "tier 1: the extra result is named" \
    "$(grep -qF 'recorded, not planned: mutations' <<<"$OUT" && echo 0 || echo 1)"

load 2
record_plan musl-tests
skip_stage musl-tests "no musl target on this host" >/dev/null
run_check
check "tier 2: a skipped stage is not missing" \
    "$(grep -qx 'plan-match=none' <<<"$OUT" && echo 0 || echo 1)"

load 2
record_plan musl-tests
run_check
check "tier 2: an unrecorded stage that was not skipped fails" \
    "$(grep -qx 'plan-match=1' <<<"$OUT" && echo 0 || echo 1)"

load 3
record_plan root-explorers
run_check
check "tier 3: a missing explorer half fails" \
    "$(grep -qF 'planned, not recorded: root-explorers' <<<"$OUT" && echo 0 || echo 1)"

load 3
record_plan mutations-explorers
run_check
check "tier 3: a missing mutations-explorers fails" \
    "$(grep -qF 'planned, not recorded: mutations-explorers' <<<"$OUT" && echo 0 || echo 1)"

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "All ci-local.sh plan cases passed"
    exit 0
fi
echo "$FAILURES ci-local.sh plan check(s) failed"
exit 1
