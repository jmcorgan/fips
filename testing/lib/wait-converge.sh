#!/bin/bash
# Shared convergence wait helpers for FIPS integration tests.
#
# Source this file to get wait_for_peers() and wait_until_connected().
#
# Usage:
#   source "$(dirname "$0")/../../lib/wait-converge.sh"
#   wait_for_peers <container> <min_peers> [timeout_secs]
#   wait_until_connected <ping_fn> <max_secs> <stall_secs> [poll_secs] \
#       [near_converged_slack]
#
# wait_until_connected also sets CONVERGE_OUTCOME / CONVERGE_REACHED /
# CONVERGE_PENDING; see the block above it.
#
# There was a wait_for_links() here. It was removed rather than kept for
# symmetry: it had no caller anywhere in the tree on any branch, and its
# reader carried the same failure-to-zero fallback wait_for_peers does. An
# uncalled helper cannot be wrong today, so the risk was that the first
# caller to appear would inherit the hazard below without the reasoning
# that goes with it. `git log` has the implementation if one is needed.

# Wait until a container has at least min_peers connected peers.
# Returns 0 on success, 1 on timeout.
#
# The read below falls back to 0 when the container does not answer, which
# is safe ONLY because this is a floor: a fallback of 0 reads as "not
# converged yet", the loop keeps polling, and a container that never answers
# times out and returns 1. That safety is a property of the comparison, not
# of the reader.
#
# A minimum of 0 inverts it. `[ 0 -ge 0 ]` is true, so the first read from a
# dead container would satisfy the wait immediately and the caller would
# proceed as though convergence had been observed. No caller passes 0, and
# rejecting it here means none can start to — which is cheaper than auditing
# every future caller, and is why this is a hard error rather than a warning.
# A caller that genuinely wants to assert "exactly zero peers" needs a reader
# that distinguishes no-answer from zero, not this floor.
wait_for_peers() {
    local container="$1"
    local min_peers="$2"
    local timeout="${3:-30}"

    if [ "$min_peers" -lt 1 ]; then
        echo "  wait_for_peers: refusing a minimum of $min_peers for $container — a floor of 0 is satisfied by a container that never answered" >&2
        return 2
    fi

    for i in $(seq 1 "$timeout"); do
        local count
        count=$(docker exec "$container" fipsctl show peers 2>/dev/null \
            | python3 -c "import sys,json; print(sum(1 for p in json.load(sys.stdin).get('peers',[]) if p.get('connectivity')=='connected'))" 2>/dev/null || echo 0)
        if [ "$count" -ge "$min_peers" ]; then
            echo "  $container: $count peer(s) after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "  $container: TIMEOUT waiting for $min_peers peer(s) after ${timeout}s"
    return 1
}

# Verdict of the most recent wait_until_connected() call, so a caller can
# report WHICH condition failed rather than only that one did:
#   CONVERGE_OUTCOME  converged | stalled | timeout
#   CONVERGE_REACHED  reachable pairs at the moment of the verdict
#   CONVERGE_PENDING  unreachable pairs at that moment
#
# These exist because the gate's own probe is strictly harsher than the
# assertion it guards, so a run can fail the gate at 18/20 and then pass
# the strict all-pairs assertion 20/20. Without them the caller's summary
# line reads "20 passed, 0 failed" on a non-convergence exit, which a
# reader cannot tell from a connectivity failure.
CONVERGE_OUTCOME=""
CONVERGE_REACHED=0
CONVERGE_PENDING=0

# Record the verdict of a wait_until_connected() return.
#
# shellcheck disable=SC2034  # read by sourcing suites, not within this file
_converge_verdict() {
    CONVERGE_OUTCOME="$1"
    CONVERGE_REACHED="$PASSED"
    CONVERGE_PENDING="$FAILED"
}

# Wait until a connectivity check reports every pair reachable, using a
# progress-aware deadline instead of a fixed one.
#
#   wait_until_connected <ping_fn> <max_secs> <stall_secs> [poll_secs] \
#       [near_converged_slack]
#
# <ping_fn> is the name of a function that runs the suite's own
# connectivity check and sets two globals each call:
#   PASSED  number of reachable pairs this round
#   FAILED  number of unreachable pairs this round
#
# The convergence signal is the suite's real pings (the same signal it
# asserts on), not a structural proxy. Behaviour:
#   - converged: FAILED == 0  -> return 0.
#   - progressing: PASSED climbed past the best seen -> reset the stall
#     clock and keep waiting (slow-but-improving is not a failure, so it
#     does not false-time-out under CI load).
#   - stuck: PASSED has not improved for stall_secs -> return 1 (fail
#     fast rather than burn the whole budget on a genuinely wedged pair),
#     BUT only when FAILED > near_converged_slack (default 2). A mesh
#     that is genuinely far from convergence still bails fast on stall.
#   - near-converged hold: when FAILED <= near_converged_slack and the
#     stall window has elapsed, do NOT bail. A handful of straggling
#     pairs (e.g. a deep node whose last pair clears only after stacked
#     discovery backoff + late bloom propagation) is a rare timing event,
#     not a routing defect, so the gate keeps polling toward max_secs
#     rather than emitting a false RED with budget still unspent. A
#     genuinely never-converging single pair still hits the hard cap.
#   - hard cap: max_secs elapsed -> return 1 (never runs unbounded).
#
# Returns 0 once fully connected, 1 on stall or timeout.
wait_until_connected() {
    local ping_fn="$1"
    local max_secs="$2"
    local stall_secs="$3"
    local poll_secs="${4:-1}"
    local near_converged_slack="${5:-2}"

    local start_secs=$SECONDS
    local best=-1
    local last_progress=$SECONDS
    local held_for_budget=0

    while (( SECONDS - start_secs < max_secs )); do
        "$ping_fn"
        if (( FAILED == 0 )); then
            _converge_verdict converged
            echo "  converge: all $PASSED pair(s) reachable after $((SECONDS - start_secs))s"
            return 0
        fi
        if (( PASSED > best )); then
            best=$PASSED
            last_progress=$SECONDS
            echo "  converge: $PASSED reachable, $FAILED pending (progressing) after $((SECONDS - start_secs))s"
        elif (( SECONDS - last_progress >= stall_secs )); then
            if (( FAILED > near_converged_slack )); then
                _converge_verdict stalled
                echo "  converge: STUCK — tree did not converge: $PASSED reachable / $FAILED pending, no progress for ${stall_secs}s (after $((SECONDS - start_secs))s)"
                return 1
            fi
            if (( held_for_budget == 0 )); then
                held_for_budget=1
                echo "  converge: near-converged ($PASSED reachable / $FAILED pending <= slack=$near_converged_slack) — holding for full budget, not bailing (after $((SECONDS - start_secs))s)"
            fi
        fi
        sleep "$poll_secs"
    done

    _converge_verdict timeout
    echo "  converge: TIMEOUT — tree did not converge: $PASSED reachable / $FAILED pending after ${max_secs}s"
    return 1
}
