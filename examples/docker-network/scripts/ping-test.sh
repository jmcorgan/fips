#!/bin/bash
# End-to-end ping test between FIPS nodes via DNS resolution.
# Usage: ./ping-test.sh [mesh|chain]
#
# Requires containers to be running:
#   docker compose --profile mesh up -d
#   ./scripts/ping-test.sh mesh
set -e

PROFILE="${1:-mesh}"
COUNT=3
TIMEOUT=10
PASSED=0
FAILED=0

# Node identities
NPUB_A="npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"
NPUB_B="npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le"
NPUB_C="npub1cld9yay0u24davpu6c35l4vldrhzvaq66pcqtg9a0j2cnjrn9rtsxx2pe6"
NPUB_D="npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl"
NPUB_E="npub1wf8akf8lu2zdkjkmwhl75pqvven654mpv4sz2x2tprl5265mgrzq8nhak4"

ping_test() {
    local from="$1"
    local to_npub="$2"
    local label="$3"

    echo -n "  $label ... "
    if docker exec "fips-$from" ping6 -c "$COUNT" -W "$TIMEOUT" "${to_npub}.fips" > /dev/null 2>&1; then
        echo "OK"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL"
        FAILED=$((FAILED + 1))
    fi
}

echo "=== FIPS Ping Test ($PROFILE topology) ==="
echo ""

# Wait for nodes to converge
echo "Waiting 5s for mesh convergence..."
sleep 5

if [ "$PROFILE" = "mesh" ]; then
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
