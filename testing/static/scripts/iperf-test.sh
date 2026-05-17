#!/bin/bash
# End-to-end iperf3 bandwidth test between FIPS nodes via DNS resolution.
# Usage: ./iperf-test.sh [mesh|chain] [--live]
#
# Requires containers to be running:
#   docker compose --profile mesh up -d
#   ./scripts/iperf-test.sh mesh
#   ./scripts/iperf-test.sh mesh --live  # Show live iperf3 output
set -e

# Exit entire script on Ctrl+C
trap 'echo ""; echo "Test interrupted"; exit 130' INT

PROFILE="${1:-mesh}"
LIVE_OUTPUT=false
if [ "$2" = "--live" ] || [ "$1" = "--live" ]; then
    LIVE_OUTPUT=true
    [ "$1" = "--live" ] && PROFILE="mesh"
fi

DURATION="${DURATION:-10}"
PARALLEL="${PARALLEL:-8}"
SETTLE_SECONDS="${SETTLE_SECONDS:-3}"
IPERF_TIMEOUT="${IPERF_TIMEOUT:-$((DURATION + 30))}"
PASSED=0
FAILED=0

# Node identities (from generated env file)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/../generated-configs/npubs.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found. Run generate-configs.sh first." >&2
    exit 1
fi
# shellcheck source=../generated-configs/npubs.env
source "$ENV_FILE"

iperf_test() {
    local server_node="$1"
    local client_node="$2"
    local dest_npub="$3"
    local label="$4"

    echo ""
    echo "=== $label ==="
    
    # iperf3 server is already running in daemon mode in each container
    
    if [ "$LIVE_OUTPUT" = true ]; then
        # Show live output
        echo "Running iperf3 test (live output):"
        if docker exec "fips-$client_node" timeout "$IPERF_TIMEOUT" iperf3 -c "${dest_npub}.fips" -t "$DURATION" -P "$PARALLEL"; then
            PASSED=$((PASSED + 1))
        else
            echo "FAIL"
            FAILED=$((FAILED + 1))
        fi
    else
        # Capture and summarize output
        echo -n "Running iperf3 test... "
        local output
        if output=$(docker exec "fips-$client_node" timeout "$IPERF_TIMEOUT" iperf3 -c "${dest_npub}.fips" -t "$DURATION" -P "$PARALLEL" 2>&1); then
            # Check if we got valid results
            if echo "$output" | grep -q "sender"; then
                # Extract and display results (get SUM line for aggregate bandwidth)
                local bandwidth=$(echo "$output" | grep "\[SUM\].*sender" | tail -1 | awk '{for(i=1;i<=NF;i++) if($i ~ /bits\/sec/) {print $(i-1), $i; exit}}')
                echo "OK"
                echo "Bandwidth: $bandwidth"
                PASSED=$((PASSED + 1))
            else
                echo "FAIL (no bandwidth data)"
                echo "Output: $output"
                FAILED=$((FAILED + 1))
            fi
        else
            echo "FAIL"
            echo "Error output:"
            echo "$output" | head -10
            FAILED=$((FAILED + 1))
        fi
    fi
}

echo "=== FIPS iperf3 Bandwidth Test ($PROFILE topology) ==="
echo ""

# Wait for nodes to converge
echo "Waiting ${SETTLE_SECONDS}s for mesh convergence..."
sleep "$SETTLE_SECONDS"

if [ "$PROFILE" = "mesh" ] || [ "$PROFILE" = "mesh-public" ]; then
    # Test key paths in mesh topology
    echo ""
    echo "Testing mesh topology paths:"
    
    # Direct peer links (client on A, server on D/E)
    iperf_test node-d node-a "$NPUB_D" "A → D (direct peer)"
    iperf_test node-e node-a "$NPUB_E" "A → E (direct peer)"

    # Multi-hop paths (client on A, server on B/C)
    iperf_test node-b node-a "$NPUB_B" "A → B (multi-hop)"
    iperf_test node-c node-a "$NPUB_C" "A → C (multi-hop)"

    # Reverse test (client on E, server on A)
    iperf_test node-a node-e "$NPUB_A" "E → A (direct peer)"

elif [ "$PROFILE" = "chain" ]; then
    echo ""
    echo "Testing chain topology paths:"
    
    # Adjacent hop (client on A, server on B)
    iperf_test node-b node-a "$NPUB_B" "A → B (1 hop)"

    # Multi-hop tests (client on A, server on C/D/E)
    iperf_test node-c node-a "$NPUB_C" "A → C (2 hops)"
    iperf_test node-d node-a "$NPUB_D" "A → D (3 hops)"
    iperf_test node-e node-a "$NPUB_E" "A → E (4 hops)"

    # Reverse multi-hop (client on E, server on A)
    iperf_test node-a node-e "$NPUB_A" "E → A (4 hops)"
fi

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
