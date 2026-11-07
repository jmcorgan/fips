#!/bin/bash
# ── Known-defect lane ───────────────────────────────────────────────────────
# A test that asserts the correct behaviour and fails today is kept, ignored,
# as the record of a defect not yet fixed. Ignored, it runs nowhere, so the
# day the defect is fixed nothing notices and the test never starts gating.
# This lane runs every known-defect entry of testing/ignored-tests.txt and
# expects it to fail. A known-defect test that passes reds the lane: remove
# its ignore and its inventory line in the change that fixed it, so it gates
# from then on.
#
# It also lists the ignored tests of each library test binary and reds on
# one the inventory does not name by its full test path. That is the half of
# the inventory check testing/check-ignored-tests.py cannot do statically:
# the module path of a test depends on `#[path]` attributes, so only the
# build knows it. Tests the host does not compile (the macOS hardware tests
# on Linux) are not listed and are checked statically only.
#
# Each test runs its binary directly, under `timeout` with
# FIPS_KNOWN_DEFECT_TIMEOUT seconds (default 120), so a hang is killed with
# the process, and testing/lib/test-verdict.sh classifies the run. A
# known-defect test still fails only when it fails at its own assertion of
# the defect, the one whose message starts `defect:`. One that fails at a
# `precondition:` check, at an unmarked panic (a bare unwrap(), a shared
# helper's plain expect, an overflow), that is killed by the timeout, or that
# does not run as one test, is a problem: it has stopped showing its defect,
# and a fix landing elsewhere would go unseen. A timeout is a problem because
# the run never reached an assertion, so a test that hangs in its setup is
# not taken for one failing at its defect. No current entry is a hang.
#
# A known-defect test outside the settlement tests may predate the marker and
# sit in a file a change cannot edit. Such an entry is pinned in PINNED below
# to the file:line of its own defect assertion, and an unmarked failure at
# that line counts as still failing; an unmarked failure anywhere else is
# still a problem. A pin that names no known-defect entry is a problem too.
#
# Before the inventory, a self-check runs testing/lib/test-verdict-test.sh
# (the classifier over captured outputs) and the planted tests of
# node::tests::settle::lane, each of which must be classified as its name
# says. A miss there exits 1 with `lane self-check:`, so the rule above is
# shown to fire wherever the lane runs.
#
# FIPS_KNOWN_DEFECT_INVENTORY names another inventory file, for trying the
# lane against an edited copy; it defaults to testing/ignored-tests.txt.
#
# Exit 0 = every known-defect test still fails at its defect assertion (or
# its pinned line), the self-check held, and every listed ignored test is
# inventoried. Exit 1 = one passed, failed anywhere else, timed out, ran
# nothing, a listed ignored test is missing from the inventory, or the
# self-check missed; every problem is printed.
# Exit 2 = the lane could not run (build failed, binaries not found,
# inventory unreadable); never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INVENTORY="${FIPS_KNOWN_DEFECT_INVENTORY:-$SCRIPT_DIR/ignored-tests.txt}"
LIMIT="${FIPS_KNOWN_DEFECT_TIMEOUT:-120}"

cd "$PROJECT_ROOT" || exit 2
[[ -r "$INVENTORY" ]] || { echo "known-defect-lane: cannot read $INVENTORY" >&2; exit 2; }

# The library is linted as its own target in testing/check-shellcheck.sh,
# which runs without --external-sources.
# shellcheck source-path=SCRIPTDIR source=lib/test-verdict.sh disable=SC1091
source "$SCRIPT_DIR/lib/test-verdict.sh"
test_bins || exit 2

problems=0
problem() {
    echo "known-defect-lane: $*"
    problems=$((problems + 1))
    return 0
}

# Every ignored test the host compiles must be inventoried under its path.
for pkg in fips-mesh fips-core; do
    listed=$("${BIN[$pkg]}" --list --ignored --format terse) || {
        echo "known-defect-lane: listing $pkg's ignored tests failed" >&2
        exit 2
    }
    while read -r name; do
        [[ -z "$name" ]] && continue
        if ! awk -v c="$pkg" -v t="$name" \
            '!/^[[:space:]]*#/ && $2 == c && $3 == t { found = 1 } END { exit !found }' \
            "$INVENTORY"; then
            problem "$pkg: ignored test $name is not in the inventory under that path"
        fi
    done < <(sed -n 's/: test$//p' <<<"$listed")
done

# Known-defect entries that cannot carry the `defect:` marker, each pinned to
# the file:line of its defect assertion: <test path> <file:line>. Each has a
# comment saying why it is unmarked and what removes the pin.
declare -A PIN=()
while read -r name pin; do
    [[ -z "$name" || "$name" == \#* ]] && continue
    PIN[$name]=$pin
done <<'PINNED'
# Its expect message has no marker, and the test sits in a production
# source file (inline tests). It fails in 5 s at the expect when
# blocking_send does not return; it does not hang. Removed when that
# message starts `defect:`.
transport::ethernet::io::tests::blocking_send_parks_past_a_shutdown_request_when_the_channel_is_full src/transport/ethernet/io.rs:662
PINNED
for name in "${!PIN[@]}"; do
    if ! awk -v t="$name" '!/^[[:space:]]*#/ && $1 == "known-defect" && $3 == t { found = 1 } END { exit !found }' \
        "$INVENTORY"; then
        problem "pinned entry $name is not a known-defect entry of the inventory"
    fi
done

# The self-check: the classifier's fixtures, then the planted tests, each
# classified as its name says. A planted test missing from the binary is a
# miss, not a skip.
SELF="node::tests::settle::lane"
self_misses=0
if ! fixture_out=$(bash "$SCRIPT_DIR/lib/test-verdict-test.sh" 2>&1); then
    echo "$fixture_out"
    echo "known-defect-lane: lane self-check: testing/lib/test-verdict-test.sh failed"
    self_misses=$((self_misses + 1))
fi
while read -r want name; do
    out=$(timeout -k 5 "$LIMIT" "${BIN[fips-mesh]}" --ignored --exact "$SELF::$name" 2>&1)
    rc=$?
    IFS=$'\t' read -r class loc msg < <(verdict "$out" "$rc" "$SELF::$name")
    if [[ "$class" != "$want" ]]; then
        echo "known-defect-lane: lane self-check: $SELF::$name is $class, expected $want${loc:+ (at $loc: $msg)}"
        self_misses=$((self_misses + 1))
    fi
done <<'PLANTED'
precondition a_planted_failure_at_its_precondition
unmarked     a_planted_failure_at_a_bare_unwrap
unmarked     a_planted_failure_at_a_plain_expect_in_a_setup_helper
defect       a_planted_failure_at_its_defect_assertion
passed       a_planted_test_that_passes
PLANTED
# The pin, through a real run: the planted plain-expect failure, pinned to
# the line of its own expect, still fails; pinned to another line of the
# same file, it is a problem.
HELPER="$SELF::a_planted_failure_at_a_plain_expect_in_a_setup_helper"
out=$(timeout -k 5 "$LIMIT" "${BIN[fips-mesh]}" --ignored --exact "$HELPER" 2>&1)
rc=$?
IFS=$'\t' read -r class loc msg < <(verdict "$out" "$rc" "$HELPER")
while read -r want pin; do
    got=$(lane_decision "$class" "$loc" "$pin")
    if [[ "$got" != "$want" ]]; then
        echo "known-defect-lane: lane self-check: $HELPER ($class at ${loc:-no location}) pinned to $pin is $got, expected $want"
        self_misses=$((self_misses + 1))
    fi
done <<'PINCHECK'
still-fails src/node/tests/settle/lane.rs:18
problem     src/node/tests/settle/lane.rs:17
problem     src/node/tests/settle/lane.rs:46
PINCHECK
if [[ $self_misses -gt 0 ]]; then
    echo "known-defect-lane: lane self-check: $self_misses miss(es); the lane cannot tell a defect from a setup failure"
    exit 1
fi
echo "known-defect-lane: lane self-check passed (classifier fixtures, five planted tests, the pinned form)"

# Every known-defect test must still fail, at its defect assertion.
ran=0
while read -r pkg name; do
    ran=$((ran + 1))
    out=$(timeout -k 5 "$LIMIT" "${BIN[$pkg]}" --ignored --exact "$name" 2>&1)
    rc=$?
    IFS=$'\t' read -r class loc msg < <(verdict "$out" "$rc" "$name")
    case "$(lane_decision "$class" "$loc" "${PIN[$name]:-}")" in
        still-fails)
            if [[ "$class" == unmarked ]]; then
                echo "known-defect-lane: $name still fails at its pinned line $loc: $msg"
            else
                echo "known-defect-lane: $name still fails at $loc: $msg"
            fi
            ;;
        now-passes)
            problem "$name now passes: remove its ignore and its inventory line"
            ;;
        *)
            case "$class" in
                precondition | unmarked)
                    problem "$name fails at $class ${loc:-(no panic of its own thread)}${msg:+: $msg}, not at its defect: assertion${PIN[$name]:+ or its pinned line ${PIN[$name]}}"
                    ;;
                timeout)
                    problem "$name timed out after ${LIMIT}s before failing at its defect: assertion${PIN[$name]:+ or its pinned line ${PIN[$name]}}"
                    ;;
                *)
                    problem "$name did not run as one test (rc $rc); check its path in the inventory"
                    ;;
            esac
            ;;
    esac
done < <(awk '!/^[[:space:]]*#/ && $1 == "known-defect" { print $2, $3 }' "$INVENTORY")

if [[ $problems -gt 0 ]]; then
    echo "known-defect-lane: $problems problem(s)"
    exit 1
fi
echo "known-defect-lane: $ran known-defect test(s) still fail at their defect assertions or pinned lines; every listed ignored test is inventoried"
exit 0
