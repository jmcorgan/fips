#!/bin/bash
# Tests for ci-local.sh's plan check: a green tier run must record exactly
# the results --plan lists for its tier, less the stages it skipped for want
# of something on the host (check_plan). Each case loads ci-local.sh's
# configuration, stage lists and plan functions, plants a set of recorded
# results, and runs check_plan on them: the plan itself passes, a missing or
# an extra result fails and is named, and a skipped stage is not counted as
# missing. The same holds for the part of tier 3 (--part). The chaos part,
# with tier 2, must list exactly what tier 3 lists, each only results tier 3
# lists, and the two no result in common but the integration build; each
# failure names the result at fault. Tier 2 runs the root crate's explorers
# and its mutation lines, so a run of it that records either one short
# fails. A part whose plan has nothing
# of its own is refused, and the chaos part with no scenario fails before it
# builds anything.
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
$(awk '/^(check_plan|skip_stage|run_part)\(\) \{/,/^}/' "$CI_LOCAL")"
for fn in print_plan apply_tier nightly_chaos print_part_plan apply_part part_has_work \
        check_plan skip_stage run_part; do
    if ! grep -q "^$fn() {" <<<"$defs"; then
        echo "ci-plan-test: $fn() not found in $CI_LOCAL; nothing was tested" >&2
        exit 2
    fi
done

# Load the definitions for tier $1, and part $2 if given, with no results
# yet, in this shell.
load() {
    eval "$defs"
    # shellcheck disable=SC2034  # read by the functions loaded from ci-local.sh
    TIER="$1"
    # shellcheck disable=SC2034
    PART="${2:-}"
    apply_tier 2>/dev/null
    [[ -n "$PART" ]] && apply_part
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

load 2
record_plan root-explorers
run_check
check "tier 2: a missing root explorer run fails" \
    "$(grep -qF 'planned, not recorded: root-explorers' <<<"$OUT" && echo 0 || echo 1)"

load 2
record_plan mutations-explorers
run_check
check "tier 2: a missing mutations-explorers fails" \
    "$(grep -qF 'planned, not recorded: mutations-explorers' <<<"$OUT" && echo 0 || echo 1)"

load 3
record_plan mutations-explorers
run_check
check "tier 3: a missing mutations-explorers fails" \
    "$(grep -qF 'planned, not recorded: mutations-explorers' <<<"$OUT" && echo 0 || echo 1)"

PARTS=(chaos)
for part in "${PARTS[@]}"; do
    load 3 "$part"
    record_plan
    run_check
    check "part $part: the plan itself passes" \
        "$(grep -qx 'plan-match=none' <<<"$OUT" && echo 0 || echo 1)"
    first=$(print_part_plan | grep -v '^#' | grep -vx build-integration | head -n 1)
    load 3 "$part"
    record_plan "$first"
    run_check
    check "part $part: a missing result fails and is named" \
        "$(grep -qF "planned, not recorded: $first" <<<"$OUT" && grep -qx 'plan-match=1' <<<"$OUT" && echo 0 || echo 1)"
    load 3 "$part"
    record_plan
    record unit-tests 0
    run_check
    check "part $part: an extra result fails and is named" \
        "$(grep -qF 'recorded, not planned: unit-tests' <<<"$OUT" && grep -qx 'plan-match=1' <<<"$OUT" && echo 0 || echo 1)"
    load 3 "$part"
    run_check
    check "part $part: a run that recorded nothing fails" \
        "$(grep -qx 'plan-match=1' <<<"$OUT" && echo 0 || echo 1)"
done

# The plan of tier $1, part $2 (or none), with WITH_TOR $3, sorted, without
# notes. Run in a subshell, so nothing it loads stays.
plan_of() {
    (
        load "$1" "$2"
        # shellcheck disable=SC2034  # read by print_plan
        WITH_TOR="$3"
        print_plan | grep -v '^#' | sort
    )
    return 0
}

# Hold the parts to tier 3, without and with the Tor suites: tier 2 is the
# nightly's first part and never takes them.
for tor in false true; do
    t3=$(plan_of 3 "" "$tor")
    t2=$(plan_of 2 "" false)
    declare -A PLANS=([tier2]="$t2")
    for part in "${PARTS[@]}"; do
        PLANS[$part]=$(plan_of 3 "$part" "$tor")
    done
    union=$(printf '%s\n' "${PLANS[@]}" | grep -v '^$' | sort -u)
    problems=()
    while read -r r; do
        [[ -n "$r" ]] && problems+=("tier 3 lists $r that no part lists")
    done < <(comm -23 <(echo "$t3") <(echo "$union"))
    for part in tier2 "${PARTS[@]}"; do
        while read -r r; do
            [[ -n "$r" ]] && problems+=("part $part lists $r, which tier 3 does not")
        done < <(comm -13 <(echo "$t3") <(echo "${PLANS[$part]}"))
    done
    names=(tier2 "${PARTS[@]}")
    for (( i = 0; i < ${#names[@]}; i++ )); do
        for (( j = i + 1; j < ${#names[@]}; j++ )); do
            while read -r r; do
                [[ -n "$r" && "$r" != build-integration ]] \
                    && problems+=("parts ${names[$i]} and ${names[$j]} both list $r")
            done < <(comm -12 <(echo "${PLANS[${names[$i]}]}") <(echo "${PLANS[${names[$j]}]}"))
        done
    done
    for p in "${problems[@]}"; do echo "  $p"; done
    check "tier 3 with WITH_TOR=$tor: the parts and tier 2 list exactly tier 3, each only its own" \
        "${#problems[@]}" "${problems[*]:0:3}"
    unset PLANS
done

# A part with nothing of its own to run is refused at --plan and at the
# start of a run: the chaos part with no scenario lists only the shared
# build.
load 3 chaos
# shellcheck disable=SC2034  # read by the functions loaded from ci-local.sh
CHAOS_SUITES=()
# shellcheck disable=SC2034
NIGHTLY_CHAOS=()
# shellcheck disable=SC2034
NIGHTLY_LONG=()
check "part chaos with no scenario lists nothing of its own" \
    "$(part_has_work && echo 1 || echo 0)"
load 3 chaos
check "part chaos as it stands lists something of its own" \
    "$(part_has_work && echo 0 || echo 1)"

# The chaos part with no scenario fails before it builds anything.
load 3 chaos
# shellcheck disable=SC2034  # read by the functions loaded from ci-local.sh
CHAOS_SUITES=()
# shellcheck disable=SC2034
NIGHTLY_CHAOS=()
# shellcheck disable=SC2034
NIGHTLY_LONG=()
stage() { return 0; }
fail() { echo "FAIL $*"; return 0; }
prepare_images() { echo "prepare_images called"; return 0; }
run_nightly() { echo "run_nightly called"; return 0; }
out=$(run_part; echo "rc=$?")
check "part chaos with no scenario fails before building" \
    "$(grep -qx 'rc=1' <<<"$out" && grep -qF 'part chaos has no scenario to run' <<<"$out" \
        && ! grep -q 'called' <<<"$out" && echo 0 || echo 1)" "$(tr '\n' ' ' <<<"$out")"

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "All ci-local.sh plan cases passed"
    exit 0
fi
echo "$FAILURES ci-local.sh plan check(s) failed"
exit 1
