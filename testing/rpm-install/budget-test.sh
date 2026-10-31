#!/bin/bash
# Unit tests for the RPM install suite's network budget: the --deadline and
# --label handling in packaging/rpm/dnf-bounded.sh, and retry_build's refusal
# of a late retry in testing/lib/image-build.sh.
#
# dnf is a stand-in script on PATH that writes the librepo log lines the
# report reads (DNF_BOUNDED_LOG points the script at it) and then sleeps and
# exits as each case scripts it. retry_build runs a counting stand-in command,
# and its sleep is a stand-in that only records the pause. Deadlines are a few
# seconds out, so the cases run in about ten seconds with no containers and no
# network.
#
# What it does not assert: the per-attempt report line's wording beyond the
# budget's own phrases, so a change to that line elsewhere does not break it.
#
# Run:
#   ./budget-test.sh
# Exits 0 only if every case passes; non-zero if any case fails.

# The stand-ins below are called only through the library, which shellcheck
# cannot follow.
# shellcheck disable=SC2317

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DNF_BOUNDED="$REPO_ROOT/packaging/rpm/dnf-bounded.sh"
# shellcheck source=../lib/image-build.sh
source "$REPO_ROOT/testing/lib/image-build.sh"

WORK=$(mktemp -d) || exit 2
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"
export DNF_BOUNDED_LOG="$WORK/librepo.log"
export STUB_COUNT="$WORK/count"
export STUB_PLAN=""

# The dnf stand-in. STUB_PLAN holds one "SECONDS:STATUS:MIRROR" step per
# attempt; each call takes the next, logs one download from MIRROR, sleeps,
# and exits with STATUS.
cat >"$WORK/bin/dnf" <<'STUB'
#!/bin/bash
if [ "${1:-}" = "--version" ]; then
    echo "4.14.0"
    exit 0
fi
n=$(($(cat "$STUB_COUNT" 2>/dev/null || echo 0) + 1))
echo "$n" >"$STUB_COUNT"
read -ra steps <<<"$STUB_PLAN"
IFS=: read -r secs status mirror <<<"${steps[$((n - 1))]:-0:0:http://none.example}"
echo "Downloading: $mirror/repodata/repomd.xml" >>"$DNF_BOUNDED_LOG"
sleep "$secs"
exit "$status"
STUB
chmod +x "$WORK/bin/dnf"
export PATH="$WORK/bin:$PATH"

RESULTS=()
FAILURES=0

# Record a single assertion result.
check() {
    local name="$1" ok="$2" detail="${3:-}"
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

OUT=""
RC=0
CALLS=0
TOOK=0

# Run dnf-bounded with the given plan and arguments; leave its stderr in OUT,
# its status in RC, the stand-in's call count in CALLS, its time in TOOK.
run_bounded() {
    STUB_PLAN="$1"
    shift
    rm -f "$STUB_COUNT" "$DNF_BOUNDED_LOG"
    local start=$SECONDS
    RC=0
    OUT=$(bash "$DNF_BOUNDED" "$@" 2>&1 >/dev/null) || RC=$?
    TOOK=$((SECONDS - start))
    CALLS=$(cat "$STUB_COUNT" 2>/dev/null || echo 0)
    return 0
}

expect_rc() {
    local name="$1" want="$2"
    [ "$RC" -eq "$want" ]
    check "$name: exits $want" $? "exit $RC"
}

expect_calls() {
    local name="$1" want="$2" what="${3:-dnf ran}"
    [ "$CALLS" -eq "$want" ]
    check "$name: $what $want time(s)" $? "$CALLS"
}

expect_has() {
    local name="$1" text="$2"
    [[ "$OUT" == *"$text"* ]]
    check "$name: says '$text'" $? "$(tail -n 3 <<<"$OUT" | tr '\n' '|')"
}

expect_lacks() {
    local name="$1" text="$2"
    [[ "$OUT" != *"$text"* ]]
    check "$name: does not say '$text'" $?
}

now() { date +%s; }

echo "== Case 1: an attempt its own bound would allow ends at the deadline =="
run_bounded "20:0:http://m1.example" --bound 60 --attempts 3 --label "packaging tools" \
    --deadline $(($(now) + 3)) -- install x
expect_rc clamp 124
expect_calls clamp 1
[ "$TOOK" -le 8 ]
check "clamp: ended near the deadline, not at the 60 s bound" $? "${TOOK}s"
expect_has clamp "killed at the run's budget (deadline "
expect_has clamp "dnf-bounded: packaging tools: the run's network budget is spent after attempt 1 of 3; mirrors tried: http://m1.example (1)"
expect_lacks clamp "killed at the 60s bound"

echo
echo "== Case 2: no retry starts with under 30 s left =="
run_bounded "0:1:http://m1.example" --bound 60 --attempts 3 --deadline $(($(now) + 20)) -- install x
expect_rc floor 124
expect_calls floor 1
expect_has floor "dnf-bounded: dnf install: the run's network budget is spent after attempt 1 of 3"

echo
echo "== Case 3: a first attempt still starts with 5 s left =="
run_bounded "0:0:http://m1.example" --bound 60 --attempts 3 --deadline $(($(now) + 5)) -- makecache
expect_rc first 0
expect_calls first 1

echo
echo "== Case 4: a deadline already reached runs nothing =="
for offset in 0 -60; do
    run_bounded "0:0:http://m1.example" --bound 60 --attempts 2 --label "runtime image almalinux:9" \
        --deadline $(($(now) + offset)) -- install x
    expect_rc "spent ($offset)" 124
    expect_calls "spent ($offset)" 0
    expect_has "spent ($offset)" "dnf-bounded: runtime image almalinux:9: the run's network budget was spent before attempt 1 of 2"
done

echo
echo "== Case 5: the budget's last line names every attempt's mirrors =="
run_bounded "0:1:http://m1.example 0:1:http://m2.example 0:0:http://m3.example" \
    --bound 60 --attempts 3 --deadline $(($(now) + 40)) -- install x
expect_rc union 124
expect_calls union 2
expect_has union "spent after attempt 2 of 3; mirrors tried: http://m1.example (1), http://m2.example (1)"

echo
echo "== Case 6: a deadline file that cannot be read is a usage error =="
printf '' >"$WORK/empty"
printf 'abc\n' >"$WORK/abc"
for c in "missing:$WORK/missing" "empty:$WORK/empty" "not an integer:$WORK/abc"; do
    why="${c%%:*}" file="${c#*:}"
    run_bounded "0:0:http://m1.example" --bound 60 --deadline "@$file" -- install x
    expect_rc "@FILE $why" 2
    expect_calls "@FILE $why" 0
    expect_has "@FILE $why" "dnf-bounded: --deadline @FILE: $file is $why"
done
echo "$(($(now) + 60))" >"$WORK/good"
run_bounded "0:0:http://m1.example" --bound 60 --deadline "@$WORK/good" -- install x
expect_rc "@FILE good" 0
expect_calls "@FILE good" 1

echo
echo "== Case 7: with no deadline, the status is the attempt's own =="
run_bounded "0:3:http://m1.example" --bound 60 -- install x
expect_rc "no deadline" 3
expect_lacks "no deadline" "budget"
run_bounded "5:0:http://m1.example" --bound 1 -- install x
expect_rc "no deadline, bound" 124
expect_has "no deadline, bound" "killed at the 1s bound"
expect_lacks "no deadline, bound" "budget"

# --- retry_build --------------------------------------------------------

BUILDS=0
BUILD_RCS=()
PAUSES=()
# The build stand-in exits with the next status in BUILD_RCS.
fake_build() {
    BUILDS=$((BUILDS + 1))
    return "${BUILD_RCS[$((BUILDS - 1))]:-0}"
}
sleep() {
    PAUSES+=("$1")
    return 0
}

# Run retry_build over fake_build; leave its stderr in OUT and status in RC.
run_retry() {
    BUILDS=0
    PAUSES=()
    BUILD_RCS=("$@")
    RC=0
    OUT=$(retry_build "docker build -t x" fake_build 2>&1; echo "rc=$? builds=$BUILDS")
    RC=$(sed -n 's/.*rc=\([0-9]*\) builds=.*/\1/p' <<<"$OUT" | tail -n 1)
    CALLS=$(sed -n 's/.*builds=\([0-9]*\)$/\1/p' <<<"$OUT" | tail -n 1)
    return 0
}

echo
echo "== Case 8: retry_build does not start a retry the budget cannot hold =="
export FIPS_CI_DEADLINE=$(($(now) + 25))
run_retry 1 0
expect_rc "late retry" 1
expect_calls "late retry" 1 "the build ran"
expect_has "late retry" "image-build: docker build -t x not retried: the run's budget ends in "
FIPS_CI_DEADLINE=$(($(now) + 600))
run_retry 1 0
expect_rc "early retry" 0
expect_calls "early retry" 2 "the build ran"
expect_has "early retry" "image-build: docker build -t x recovered on attempt 2 of 3"
FIPS_CI_DEADLINE="soon"
run_retry 1 0
expect_rc "bad deadline" 1
expect_calls "bad deadline" 1 "the build ran"
expect_has "bad deadline" "not retried: FIPS_CI_DEADLINE is not an integer"
unset FIPS_CI_DEADLINE

echo
echo "== Case 9: with no deadline, retry_build says what it always said =="
run_retry 1 0
expect_rc "unset, recovered" 0
expect_has "unset, recovered" "image-build: docker build -t x failed on attempt 1 of 3 (exit 1); retrying in 10s
image-build: docker build -t x recovered on attempt 2 of 3
rc=0 builds=2"
run_retry 1 1 1
expect_rc "unset, all failed" 1
expect_has "unset, all failed" "image-build: docker build -t x failed on attempt 1 of 3 (exit 1); retrying in 10s
image-build: docker build -t x failed on attempt 2 of 3 (exit 1); retrying in 20s
image-build: docker build -t x failed on all 3 attempts (last exit 1)
rc=1 builds=3"

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
