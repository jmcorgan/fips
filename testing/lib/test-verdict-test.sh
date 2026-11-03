#!/bin/bash
# Fixture tests for verdict() and lane_decision() in test-verdict.sh,
# including lane_decision's pinned form.
#
# Each case is a captured single-test libtest run, written inline, with the
# exit status the run had and the class, location and message verdict must
# print. The outputs are the shapes rustc 1.94.1's libtest prints, the
# thread-id panic line included. No build is involved, so the suite takes
# well under a second. testing/known-defect-lane.sh runs it as part of its
# self-check before any inventory entry, so a classifier change that breaks a
# case reds that lane wherever it runs.
#
# Run:
#   ./test-verdict-test.sh
# Exits 0 only if every case passes; 1 if any case fails.

# The captured outputs hold libtest's literal backticks.
# shellcheck disable=SC2016

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The library is linted as its own target in testing/check-shellcheck.sh,
# which runs without --external-sources.
# shellcheck source-path=SCRIPTDIR source=test-verdict.sh disable=SC1091
source "$SCRIPT_DIR/test-verdict.sh"

FAILURES=0
CASES=0
T="node::tests::settle::lane::a_test"

# expect <case name> <rc> <class> <loc> <msg>, with the run's output on stdin.
expect() {
    local name="$1" rc="$2" want got
    want=$(printf '%s\t%s\t%s' "$3" "$4" "$5")
    got=$(verdict "$(cat)" "$rc" "$T")
    CASES=$((CASES + 1))
    if [[ "$got" == "$want" ]]; then
        echo "PASS  $name"
    else
        echo "FAIL  $name"
        echo "      want: $(printf '%q' "$want")"
        echo "      got:  $(printf '%q' "$got")"
        FAILURES=$((FAILURES + 1))
    fi
    return 0
}

# decide <class> <decision> [<location> <pin>]
decide() {
    local got
    got=$(lane_decision "$1" "${3:-}" "${4:-}")
    CASES=$((CASES + 1))
    if [[ "$got" == "$2" ]]; then
        echo "PASS  lane_decision $1${4:+ at ${3:-(none)} pinned to $4} = $2"
    else
        echo "FAIL  lane_decision $1${4:+ at ${3:-(none)} pinned to $4}: want $2, got $got"
        FAILURES=$((FAILURES + 1))
    fi
    return 0
}

# failed <panic line> <message lines...>: a captured one-test failure.
failed() {
    local panic="$1"
    shift
    printf '\nrunning 1 test\ntest %s ... FAILED\n\nfailures:\n\n---- %s stdout ----\n\n' "$T" "$T"
    printf '%s\n' "$panic" "$@"
    printf 'note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n\n\n'
    printf 'failures:\n    %s\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3330 filtered out; finished in 0.41s\n\n' "$T"
    return 0
}

ID="thread '$T' (3592801) panicked at"
OLD="thread '$T' panicked at"

# --- passed, timeout, norun -------------------------------------------------

expect "a single passing run is passed" 0 passed "" "" <<EOF

running 1 test
test $T ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3330 filtered out; finished in 0.20s

EOF

expect "rc 124 from timeout is timeout" 124 timeout "" "" <<EOF

running 1 test
EOF

expect "rc 137 from timeout -k is timeout" 137 timeout "" "" </dev/null

expect "a run of no test is norun" 0 norun "" "" <<EOF

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3331 filtered out; finished in 0.00s

EOF

expect "two passing tests in one run are norun" 0 norun "" "" <<EOF

running 2 tests
test $T ... ok
test ${T}_too ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 3329 filtered out; finished in 0.00s

EOF

expect "two failing tests in one run are norun" 101 norun "" "" <<EOF
test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 3329 filtered out; finished in 0.00s
EOF

expect "a crash with no summary is norun" 134 norun "" "" <<EOF

running 1 test
free(): invalid pointer
EOF

# --- defect -----------------------------------------------------------------

OUT=$(failed "$ID src/node/tests/settle/lane.rs:40:5:" \
    "defect: the planted behaviour is wrong")
expect "a defect: message after the thread-id panic line is defect" 101 defect \
    "src/node/tests/settle/lane.rs:40:5" "defect: the planted behaviour is wrong" <<<"$OUT"

OUT=$(failed "$OLD src/node/tests/settle/lane.rs:40:5:" \
    "defect: the planted behaviour is wrong")
expect "a defect: message after the older panic line is defect" 101 defect \
    "src/node/tests/settle/lane.rs:40:5" "defect: the planted behaviour is wrong" <<<"$OUT"

OUT=$(failed "$ID src/node/tests/settle/crossing.rs:310:9:" \
    'assertion `left == right` failed: defect: the record is Inbound' \
    "  left: Inbound" " right: Outbound")
expect "a defect: message behind an assert_eq! prefix is defect" 101 defect \
    "src/node/tests/settle/crossing.rs:310:9" "defect: the record is Inbound" <<<"$OUT"

OUT=$(failed "$ID src/node/tests/settle/audit.rs:88:5:" \
    "defect: incoherent at the end: [" "    RightLink {" "        node: 1," "    }," "]")
expect "an aggregated defect: [ list is defect" 101 defect \
    "src/node/tests/settle/audit.rs:88:5" "defect: incoherent at the end: [" <<<"$OUT"

OUT=$(failed "$ID src/node/tests/settle/fsp.rs:200:5:" \
    "defect: no data within one exchange;" "recovered at Some(31) s")
expect "a multi-line defect: message gives its first line" 101 defect \
    "src/node/tests/settle/fsp.rs:200:5" "defect: no data within one exchange;" <<<"$OUT"

OUT=$(
    printf '\nrunning 1 test\ntest %s ... FAILED\n\nfailures:\n\n---- %s stdout ----\n\n' "$T" "$T"
    echo "thread 'tokio-runtime-worker' (3592900) panicked at src/node/mod.rs:10:5:"
    echo "precondition: a spawned task's own panic"
    echo "$ID src/node/tests/settle/lane.rs:40:5:"
    echo "defect: the planted behaviour is wrong"
    printf '\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s\n'
)
expect "another thread's panic before the test's own is not read" 101 defect \
    "src/node/tests/settle/lane.rs:40:5" "defect: the planted behaviour is wrong" <<<"$OUT"

# --- precondition -----------------------------------------------------------

OUT=$(failed "$ID src/node/tests/settle/lane.rs:30:10:" \
    "precondition: the planted setup did not hold")
expect "a precondition: message is precondition" 101 precondition \
    "src/node/tests/settle/lane.rs:30:10" "precondition: the planted setup did not hold" <<<"$OUT"

OUT=$(failed "$ID src/node/tests/settle/crossing.rs:120:5:" \
    'assertion `left == right` failed: precondition: both ends promoted' \
    "  left: 1" " right: 2")
expect "a precondition: message behind an assert_eq! prefix is precondition" 101 precondition \
    "src/node/tests/settle/crossing.rs:120:5" "precondition: both ends promoted" <<<"$OUT"

# --- unmarked ---------------------------------------------------------------

OUT=$(failed "$ID src/node/tests/settle/lane.rs:20:30:" \
    'called `Option::unwrap()` on a `None` value')
expect "a bare unwrap() is unmarked" 101 unmarked \
    "src/node/tests/settle/lane.rs:20:30" 'called `Option::unwrap()` on a `None` value' <<<"$OUT"

OUT=$(failed "$ID src/node/tests/spanning_tree.rs:72:10:" \
    "existing loopback address must be registered")
expect "a shared helper's plain expect is unmarked" 101 unmarked \
    "src/node/tests/spanning_tree.rs:72:10" "existing loopback address must be registered" <<<"$OUT"

OUT=$(failed "$ID src/node/tests/settle/lane.rs:14:34:" \
    "attempt to subtract with overflow")
expect "an arithmetic overflow in setup is unmarked" 101 unmarked \
    "src/node/tests/settle/lane.rs:14:34" "attempt to subtract with overflow" <<<"$OUT"

OUT=$(failed "$ID src/node/tests/settle/lane.rs:50:5:" \
    "assertion failed: bad.is_empty()")
expect "an unmarked assert! is unmarked" 101 unmarked \
    "src/node/tests/settle/lane.rs:50:5" "assertion failed: bad.is_empty()" <<<"$OUT"

OUT=$(failed "$ID src/node/tests/settle/lane.rs:50:5:" \
    "[" "    Breach," "]")
expect "an aggregated list without the marker is unmarked" 101 unmarked \
    "src/node/tests/settle/lane.rs:50:5" "[" <<<"$OUT"

OUT=$(failed "$ID src/node/tests/settle/lane.rs:50:5:" \
    "the message mentions defect: only later")
expect "a marker not at the start of the line is unmarked" 101 unmarked \
    "src/node/tests/settle/lane.rs:50:5" "the message mentions defect: only later" <<<"$OUT"

OUT=$(
    printf '\nrunning 1 test\ntest %s ... FAILED\n\nfailures:\n\n---- %s stdout ----\n\n' "$T" "$T"
    echo "thread 'tokio-runtime-worker' (3592900) panicked at src/node/mod.rs:10:5:"
    echo "defect: a spawned task's panic, not the test's"
    printf '\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s\n'
)
expect "a failure with no panic of the test's own thread is unmarked" 101 unmarked "" "" <<<"$OUT"

OUT=$(
    printf '\nrunning 1 test\ntest %s_longer ... FAILED\n\n' "$T"
    echo "thread '${T}_longer' (3592801) panicked at src/node/tests/settle/lane.rs:40:5:"
    echo "defect: another test's panic, whose name extends this one's"
    printf '\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s\n'
)
expect "a panic of a test whose name extends this one's is not read" 101 unmarked "" "" <<<"$OUT"

# --- the known-defect lane's decision ---------------------------------------

decide defect still-fails
# A timeout is a problem: a test killed before it reached any assertion has
# not shown its defect.
decide timeout problem
decide passed now-passes
decide precondition problem
decide unmarked problem
decide norun problem
decide "" problem

# A pinned entry: an existing test that cannot carry the marker, pinned to
# the file:line of its own defect assertion.
PIN=src/transport/ethernet/io.rs:662
decide unmarked still-fails src/transport/ethernet/io.rs:662:14 "$PIN"
decide unmarked problem src/transport/ethernet/io.rs:651:28 "$PIN"
decide unmarked problem src/transport/ethernet/io.rs:6620:14 "$PIN"
decide unmarked problem src/transport/ethernet/io.rs:66:14 "$PIN"
decide unmarked problem src/transport/ethernet/other.rs:662:14 "$PIN"
decide unmarked problem "" "$PIN"
decide precondition problem src/transport/ethernet/io.rs:662:14 "$PIN"
decide norun problem "" "$PIN"
decide timeout problem "" "$PIN"
decide defect still-fails src/transport/ethernet/io.rs:700:9 "$PIN"
decide passed now-passes "" "$PIN"
decide unmarked problem src/transport/ethernet/io.rs:662:14 ""

if [[ $CASES -lt 20 ]]; then
    echo "test-verdict-test: only $CASES case(s) ran"
    exit 1
fi
if [[ $FAILURES -ne 0 ]]; then
    echo "test-verdict-test: $FAILURES of $CASES case(s) failed"
    exit 1
fi
echo "test-verdict-test: all $CASES cases passed"
exit 0
