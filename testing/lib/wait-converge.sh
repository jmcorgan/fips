#!/bin/bash
# Shared convergence wait helpers for FIPS integration tests.
#
# Source this file to get wait_for_links() and wait_for_peers().
#
# Usage:
#   source "$(dirname "$0")/../../lib/wait-converge.sh"
#   wait_for_links <container> <min_links> [timeout_secs]
#   wait_for_peers <container> <min_peers> [timeout_secs]

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
