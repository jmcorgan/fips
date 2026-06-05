#!/bin/bash
# Shared convergence wait helpers for FIPS integration tests.
#
# Source this file to get wait_for_links(), wait_for_peers(), and
# wait_until_connected().
#
# Usage:
#   source "$(dirname "$0")/../../lib/wait-converge.sh"
#   wait_for_links <container> <min_links> [timeout_secs]
#   wait_for_peers <container> <min_peers> [timeout_secs]
#   wait_until_connected <ping_fn> <max_secs> <stall_secs> [poll_secs]

# Wait until a container has at least min_links active links.
# Returns 0 on success, 1 on timeout.
wait_for_links() {
    local container="$1"
    local min_links="$2"
    local timeout="${3:-30}"

    for i in $(seq 1 "$timeout"); do
        local count
        count=$(docker exec "$container" fipsctl show links 2>/dev/null \
            | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('links',[])))" 2>/dev/null || echo 0)
        if [ "$count" -ge "$min_links" ]; then
            echo "  $container: $count link(s) after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "  $container: TIMEOUT waiting for $min_links link(s) after ${timeout}s"
    return 1
}

# Wait until a container has at least min_peers connected peers.
# Returns 0 on success, 1 on timeout.
wait_for_peers() {
    local container="$1"
    local min_peers="$2"
    local timeout="${3:-30}"

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

# Wait until a connectivity check reports every pair reachable, using a
# progress-aware deadline instead of a fixed one.
#
#   wait_until_connected <ping_fn> <max_secs> <stall_secs> [poll_secs]
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
#     fast rather than burn the whole budget on a genuinely wedged pair).
#   - hard cap: max_secs elapsed -> return 1 (never runs unbounded).
#
# Returns 0 once fully connected, 1 on stall or timeout.
wait_until_connected() {
    local ping_fn="$1"
    local max_secs="$2"
    local stall_secs="$3"
    local poll_secs="${4:-1}"

    local start_secs=$SECONDS
    local best=-1
    local last_progress=$SECONDS

    while (( SECONDS - start_secs < max_secs )); do
        "$ping_fn"
        if (( FAILED == 0 )); then
            echo "  converge: all $PASSED pair(s) reachable after $((SECONDS - start_secs))s"
            return 0
        fi
        if (( PASSED > best )); then
            best=$PASSED
            last_progress=$SECONDS
            echo "  converge: $PASSED reachable, $FAILED pending (progressing) after $((SECONDS - start_secs))s"
        elif (( SECONDS - last_progress >= stall_secs )); then
            echo "  converge: STUCK at $PASSED reachable / $FAILED pending — no progress for ${stall_secs}s (after $((SECONDS - start_secs))s)"
            return 1
        fi
        sleep "$poll_secs"
    done

    echo "  converge: TIMEOUT at $PASSED reachable / $FAILED pending after ${max_secs}s"
    return 1
}
