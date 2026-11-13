#!/bin/bash
# Unit tests for run_container() in docker-run.sh.
#
# `docker` and `sleep` are replaced with shell functions. The docker stand-in
# answers each `docker run` with the next exit status from a per-case plan,
# printing the daemon refusal seen in local CI when the status is non-zero, and
# records every call's arguments; `docker rm` is counted. The sleep stand-in
# counts instead of waiting. No containers are involved, so the suite is
# hermetic and takes well under a second.
#
# Run:
#   ./docker-run-test.sh
# Exits 0 only if every case passes; non-zero if any case fails.

# The stand-ins below are called only through the library, which shellcheck
# cannot follow.
# shellcheck disable=SC2317

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=image-build.sh
source "$SCRIPT_DIR/image-build.sh"
# shellcheck source-path=SCRIPTDIR source=docker-run.sh
source "$SCRIPT_DIR/docker-run.sh"

RESULTS=()
FAILURES=0

# Record a single assertion result.
check() {
    local name="$1"
    local ok="$2"      # 0 = pass, anything else = fail
    local detail="${3:-}"
    if [ "$ok" -eq 0 ]; then
        RESULTS+=("PASS  $name")
        echo "PASS  $name${detail:+  ($detail)}"
    else
        RESULTS+=("FAIL  $name")
        echo "FAIL  $name${detail:+  ($detail)}"
        FAILURES=$((FAILURES + 1))
    fi
    return 0
}

# --- The stand-ins ------------------------------------------------------

REFUSAL="docker: Error response from daemon: failed to create task for container: Unavailable: error reading from server: EOF"
PLAN=()       # exit status of each successive `docker run`, 0 once exhausted
RUNS=0
REMOVES=0
SLEEPS=0
CALLS=()      # the arguments of each `docker run`, one string per call

docker() {
    case "$1" in
        run)
            local rc="${PLAN[$RUNS]:-0}"
            CALLS+=("$*")
            RUNS=$((RUNS + 1))
            if [ "$rc" -ne 0 ]; then
                echo "$REFUSAL" >&2
                return "$rc"
            fi
            echo "0123456789abcdef"
            return 0
            ;;
        rm) REMOVES=$((REMOVES + 1)); return 0 ;;
    esac
    return 0
}

sleep() {
    SLEEPS=$((SLEEPS + 1))
    return 0
}

reset() {
    PLAN=("$@")
    RUNS=0; REMOVES=0; SLEEPS=0; CALLS=()
    return 0
}

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

# expect <case> <want rc> <got rc> <want runs> <want sleeps>
expect() {
    local c="$1" want_rc="$2" got_rc="$3" want_runs="$4" want_sleeps="$5" ok=1
    [ "$got_rc" -eq "$want_rc" ] && [ "$RUNS" -eq "$want_runs" ] \
        && [ "$SLEEPS" -eq "$want_sleeps" ] && ok=0
    check "$c: exit $want_rc after $want_runs run(s) and $want_sleeps wait(s)" "$ok" \
        "rc=$got_rc runs=$RUNS sleeps=$SLEEPS"
    return 0
}

# expect_has <case> <text>: the captured stderr holds TEXT.
expect_has() {
    local ok=1
    grep -qF -- "$2" "$OUT" && ok=0
    check "$1: output has '$2'" "$ok"
    return 0
}

# expect_lacks <case> <text>: the captured stderr does not hold TEXT.
expect_lacks() {
    local ok=1
    grep -qF -- "$2" "$OUT" || ok=0
    check "$1: output lacks '$2'" "$ok"
    return 0
}

# --- Cases --------------------------------------------------------------

echo "== Case 1: the second node's start is refused once, then succeeds =="
reset 0 125
rc_a=0; rc_b=0
run_container node-a img 2>"$OUT" || rc_a=$?
run_container node-b img 2>>"$OUT" || rc_b=$?
ok=1; [ "$rc_a" -eq 0 ] && ok=0
check "case1: the first node starts" "$ok" "rc=$rc_a"
expect case1 0 "$rc_b" 3 1
ok=1; [ "$REMOVES" -eq 1 ] && ok=0
check "case1: the refused attempt's name is removed before the retry" "$ok" "removes=$REMOVES"
expect_has case1 "node-b started on attempt 2 of 3"
expect_lacks case1 "INFRASTRUCTURE"

echo
echo "== Case 2: every attempt is refused =="
reset 125 125 125
rc=0
run_container node-b img 2>"$OUT" || rc=$?
expect case2 125 "$rc" 3 2
expect_has case2 "INFRASTRUCTURE: docker run for node-b failed: $REFUSAL"

echo
echo "== Case 3: the first attempt succeeds =="
reset 0
rc=0
run_container node-a img 2>"$OUT" || rc=$?
expect case3 0 "$rc" 1 0
ok=1; [ ! -s "$OUT" ] && [ "$REMOVES" -eq 0 ] && ok=0
check "case3: a clean start prints nothing and removes nothing" "$ok"

echo
echo "== Case 4: every attempt carries the name and both run labels =="
reset 125 0
run_container node-c --network n img --config x 2>"$OUT"
for i in "${!CALLS[@]}"; do
    call="${CALLS[$i]}"
    ok=1
    [[ "$call" == "run -d --name node-c "* ]] \
        && [[ " $call " == *" com.corganlabs.fips-ci=1 "* ]] \
        && [[ " $call " == *" com.corganlabs.fips-ci.run="* ]] \
        && [[ "$call" == *" --network n img --config x" ]] && ok=0
    check "case4: attempt $((i + 1)) has the name, both labels and the caller's arguments" "$ok" "$call"
done
ok=1; [ "${#CALLS[@]}" -eq 2 ] && ok=0
check "case4: two attempts were made" "$ok" "calls=${#CALLS[@]}"

echo
echo "== Case 5: CI_LABELS is not set =="
saved=("${CI_LABELS[@]}")
unset CI_LABELS
reset 0
rc=0
run_container node-a img 2>"$OUT" || rc=$?
expect case5 2 "$rc" 0 0
expect_has case5 "CI_LABELS is not set"
CI_LABELS=("${saved[@]}")

# --- Summary ----------------------------------------------------------
echo
echo "=============================================="
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo "=============================================="
if [ "$FAILURES" -ne 0 ]; then
    echo "RESULT: $FAILURES assertion(s) FAILED"
    exit 1
fi
echo "RESULT: all assertions passed"
exit 0
