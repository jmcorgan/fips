#!/bin/bash
# End-to-end ping test between FIPS nodes via DNS resolution.
# Usage: ./ping-test.sh [mesh|chain]
#
# Requires containers to be running:
#   docker compose --profile mesh up -d
#   ./scripts/ping-test.sh mesh
set -e

# Exit entire script on Ctrl+C
trap 'echo ""; echo "Test interrupted"; exit 130' INT

PROFILE="${1:-mesh}"
COUNT=1
TIMEOUT=5
PASSED=0
FAILED=0

# Node identities (from generated env file)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../lib/wait-converge.sh"
ENV_FILE="$SCRIPT_DIR/../generated-configs/npubs.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found. Run generate-configs.sh first." >&2
    exit 1
fi
# shellcheck source=../generated-configs/npubs.env
source "$ENV_FILE"

NPUBS=("$NPUB_A" "$NPUB_B" "$NPUB_C" "$NPUB_D" "$NPUB_E")
LABELS=(A B C D E)

ping_test() {
    local from="$1"
    local to_npub="$2"
    local label="$3"

    echo -n "  $label ... "
    local output
    if output=$(docker exec "fips-$from" ping6 -c "$COUNT" -W "$TIMEOUT" "${to_npub}.fips" 2>&1); then
        # Extract round-trip time from ping output
        local rtt
        rtt=$(echo "$output" | grep -oE 'time=[0-9.]+' | cut -d= -f2)
        if [ -n "$rtt" ]; then
            echo "OK (${rtt}ms)"
        else
            echo "OK"
        fi
        PASSED=$((PASSED + 1))
    else
        echo "FAIL"
        FAILED=$((FAILED + 1))
    fi
}

# Quietly ping all pairs to check FSP-level convergence.
ping_all_quiet() {
    PASSED=0
    FAILED=0
    local n=${#LABELS[@]}
    for ((i=0; i<n; i++)); do
        for ((j=0; j<n; j++)); do
            [ "$i" -eq "$j" ] && continue
            if docker exec "fips-node-${LABELS[$i],,}" \
                ping6 -c 1 -W 1 "${NPUBS[$j]}.fips" >/dev/null 2>&1; then
                PASSED=$((PASSED + 1))
            else
                FAILED=$((FAILED + 1))
            fi
        done
    done
}

# Wait until all ping pairs succeed or timeout.
wait_for_full_connectivity() {
    local timeout="${1:-30}"
    local start_secs=$SECONDS

    while (( SECONDS - start_secs < timeout )); do
        ping_all_quiet
        if [ "$FAILED" -eq 0 ]; then
            echo "  All $PASSED pairs reachable after $((SECONDS - start_secs))s"
            return 0
        fi
        sleep 1
    done
    echo "  TIMEOUT: $PASSED passed, $FAILED failed after ${timeout}s"
    return 1
}

echo "=== FIPS Ping Test ($PROFILE topology) ==="
echo ""

# Wait for nodes to converge — all nodes must reach expected peer counts.
echo "Waiting for mesh convergence..."
if [ "$PROFILE" = "chain" ]; then
    # Chain: A-B-C-D-E, each interior node has 2 peers, endpoints have 1
    wait_for_peers fips-node-a 1 20 || true
    wait_for_peers fips-node-b 2 20 || true
    wait_for_peers fips-node-c 2 20 || true
    wait_for_peers fips-node-d 2 20 || true
    wait_for_peers fips-node-e 1 20 || true
elif [ "$PROFILE" = "mesh" ] || [ "$PROFILE" = "mesh-public" ]; then
    # Mesh: check all nodes reach their configured peer counts
    wait_for_peers fips-node-a 2 20 || true
    wait_for_peers fips-node-b 1 20 || true
    wait_for_peers fips-node-c 3 20 || true
    wait_for_peers fips-node-d 3 20 || true
    wait_for_peers fips-node-e 3 20 || true
fi
# Wait for FSP-level connectivity (discovery + session establishment)
wait_for_full_connectivity 45 || true

# Reset counters for the actual test
PASSED=0
FAILED=0

if [ "$PROFILE" = "mesh" ] || [ "$PROFILE" = "mesh-public" ]; then
    # Sparse mesh topology: A-B, B-C, C-D, D-E, E-A, A-D
    # Test all 20 directed pairs (5 nodes × 4 targets each)
    echo ""
    echo "From node-a:"
    ping_test node-a "$NPUB_B" "A → B"
    ping_test node-a "$NPUB_C" "A → C"
    ping_test node-a "$NPUB_D" "A → D"
    ping_test node-a "$NPUB_E" "A → E"

    echo ""
    echo "From node-b:"
    ping_test node-b "$NPUB_A" "B → A"
    ping_test node-b "$NPUB_C" "B → C"
    ping_test node-b "$NPUB_D" "B → D"
    ping_test node-b "$NPUB_E" "B → E"

    echo ""
    echo "From node-c:"
    ping_test node-c "$NPUB_A" "C → A"
    ping_test node-c "$NPUB_B" "C → B"
    ping_test node-c "$NPUB_D" "C → D"
    ping_test node-c "$NPUB_E" "C → E"

    echo ""
    echo "From node-d:"
    ping_test node-d "$NPUB_A" "D → A"
    ping_test node-d "$NPUB_B" "D → B"
    ping_test node-d "$NPUB_C" "D → C"
    ping_test node-d "$NPUB_E" "D → E"

    echo ""
    echo "From node-e:"
    ping_test node-e "$NPUB_A" "E → A"
    ping_test node-e "$NPUB_B" "E → B"
    ping_test node-e "$NPUB_C" "E → C"
    ping_test node-e "$NPUB_D" "E → D"

elif [ "$PROFILE" = "chain" ]; then
    echo ""
    echo "Adjacent peer tests:"
    ping_test node-a "$NPUB_B" "A → B (1 hop)"
    ping_test node-b "$NPUB_C" "B → C (1 hop)"

    echo ""
    echo "Multi-hop tests:"
    ping_test node-a "$NPUB_C" "A → C (2 hops)"
    ping_test node-a "$NPUB_D" "A → D (3 hops)"
    ping_test node-a "$NPUB_E" "A → E (4 hops)"

    echo ""
    echo "Reverse multi-hop:"
    ping_test node-e "$NPUB_A" "E → A (4 hops)"
fi

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
