#!/bin/bash
# Tor directory-mode integration test.
#
# Validates end-to-end connectivity through a Tor onion service managed
# by HiddenServiceDir (directory mode) with Sandbox 1:
#   fips-a creates onion service via Tor-managed HiddenServiceDir
#   fips-b connects outbound to fips-a's .onion address via SOCKS5
#
# Both containers run Tor + FIPS co-located. This is the recommended
# production deployment mode.
#
# Requires internet — the Tor daemon must bootstrap to the network
# and publish the onion service descriptor for .onion routing.
#
# Usage: ./directory-test.sh

set -e
trap 'echo ""; echo "Test interrupted — cleaning up..."; docker compose down 2>/dev/null; exit 130' INT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/.."
DERIVE_KEYS="$SCRIPT_DIR/../../../lib/derive_keys.py"
cd "$TEST_DIR"

PASSED=0
FAILED=0
TIMEOUT_PING=15
MAX_WAIT_ONION=120
MAX_WAIT_PEER=180

# Count connected peers for a node using fipsctl show peers JSON output
count_connected_peers() {
    local container="$1"
    docker exec "$container" fipsctl show peers 2>/dev/null \
        | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(sum(1 for p in data.get('peers', []) if p.get('connectivity') == 'connected'))
except:
    print(0)
" 2>/dev/null || echo 0
}

echo "=== FIPS Tor Directory-Mode Integration Test ==="
echo ""

# ── Phase 0: Setup ───────────────────────────────────────────────
echo "Phase 0: Setup..."

# Copy binaries from common (built externally)
if [ ! -f fips ] || [ ! -f fipsctl ]; then
    if [ -f ../common/fips ] && [ -f ../common/fipsctl ]; then
        cp ../common/fips ../common/fipsctl .
        echo "  Copied binaries from ../common/"
    else
        echo "  ERROR: fips and fipsctl binaries not found."
        echo "  Build them first: cargo build --release"
        echo "  Then copy to testing/tor/common/ or testing/tor/directory-mode/"
        exit 1
    fi
fi

# Generate ephemeral identities
MESH_NAME="dir-test-$(date +%s)-$$"
echo "  Mesh name: $MESH_NAME"

KEYS_A=$(python3 "$DERIVE_KEYS" "$MESH_NAME" "a")
NSEC_A=$(echo "$KEYS_A" | grep "^nsec=" | cut -d= -f2)
NPUB_A=$(echo "$KEYS_A" | grep "^npub=" | cut -d= -f2)

KEYS_B=$(python3 "$DERIVE_KEYS" "$MESH_NAME" "b")
NSEC_B=$(echo "$KEYS_B" | grep "^nsec=" | cut -d= -f2)
NPUB_B=$(echo "$KEYS_B" | grep "^npub=" | cut -d= -f2)

echo "  Node A: $NPUB_A"
echo "  Node B: $NPUB_B"

# Generate node-a config
sed "s/{{NSEC_A}}/$NSEC_A/" configs/node-a.yaml.tmpl > configs/node-a.yaml
echo "  Node A config generated"
echo ""

# ── Phase 1: Start node A (Tor + FIPS co-located) ────────────────
echo "Phase 1: Starting node A (Tor+FIPS, directory-mode onion service)..."
docker compose down 2>/dev/null || true
docker compose up -d fips-a
echo ""

# ── Phase 2: Wait for onion service creation ─────────────────────
echo "Phase 2: Waiting for node A's onion service (up to ${MAX_WAIT_ONION}s)..."
echo "  (Tor bootstrap + HiddenServiceDir publication)"
ONION_ADDR=""
elapsed=0
while [ "$elapsed" -lt "$MAX_WAIT_ONION" ]; do
    # Extract .onion address from structured log: onion_address=<addr>.onion
    # Strip ANSI color codes before matching (tracing emits them by default)
    ONION_ADDR=$(docker logs fips-dir-a 2>&1 \
        | sed 's/\x1b\[[0-9;]*m//g' \
        | grep -oE 'onion_address=[a-z2-7]{56}\.onion' \
        | head -1 \
        | cut -d= -f2)

    if [ -n "$ONION_ADDR" ]; then
        echo "  Onion service active after ${elapsed}s"
        echo "  Address: $ONION_ADDR"
        break
    fi
    sleep 5
    elapsed=$((elapsed + 5))
    echo "  ${elapsed}s..."
done

if [ -z "$ONION_ADDR" ]; then
    echo "  FAIL: Onion service not created within ${MAX_WAIT_ONION}s"
    echo ""
    echo "Node A logs (last 30 lines):"
    docker logs fips-dir-a 2>&1 | tail -30
    docker compose down
    exit 1
fi
echo ""

# ── Phase 3: Start node B with .onion address ────────────────────
echo "Phase 3: Starting node B (Tor+FIPS, socks5-only)..."

# Generate node-b config with discovered .onion address + virtual port
ONION_CONNECT="${ONION_ADDR}:8443"
sed -e "s/{{NSEC_B}}/$NSEC_B/" \
    -e "s/{{NPUB_A}}/$NPUB_A/" \
    -e "s/{{ONION_ADDR_A}}/$ONION_CONNECT/" \
    configs/node-b.yaml.tmpl > configs/node-b.yaml

echo "  Node B config generated (target: $ONION_CONNECT)"
docker compose up -d fips-b
echo ""

# ── Phase 4: Wait for peer connection ────────────────────────────
echo "Phase 4: Waiting for peer connection (up to ${MAX_WAIT_PEER}s)..."
echo "  (SOCKS5 circuit setup + .onion routing may take a while)"

peers_a=0
peers_b=0
elapsed=0
while [ "$elapsed" -lt "$MAX_WAIT_PEER" ]; do
    peers_a=$(count_connected_peers fips-dir-a)
    peers_b=$(count_connected_peers fips-dir-b)

    if [ "$peers_a" -ge 1 ] && [ "$peers_b" -ge 1 ]; then
        echo "  Both nodes connected after ${elapsed}s (A: ${peers_a}, B: ${peers_b})"
        break
    fi
    sleep 10
    elapsed=$((elapsed + 10))
    echo "  ${elapsed}s... (A peers: ${peers_a}, B peers: ${peers_b})"
done

if [ "$peers_a" -lt 1 ] || [ "$peers_b" -lt 1 ]; then
    echo "  FAIL: Peers not established within ${MAX_WAIT_PEER}s"
    echo ""
    echo "Node A logs (last 30 lines):"
    docker logs fips-dir-a 2>&1 | tail -30
    echo ""
    echo "Node B logs (last 30 lines):"
    docker logs fips-dir-b 2>&1 | tail -30
    docker compose down
    exit 1
fi

# Extra convergence time for routing
echo "  Waiting 10s for routing convergence..."
sleep 10
echo ""

# ── Phase 5: Connectivity tests ──────────────────────────────────
echo "Phase 5: Connectivity tests"

PING_COUNT=11

ping_series() {
    local from="$1"
    local to_npub="$2"
    local label="$3"

    echo "  $label ($PING_COUNT pings, dropping first):"
    local rtts=()
    local fails=0
    for i in $(seq 1 "$PING_COUNT"); do
        local output
        if output=$(docker exec "$from" ping6 -c 1 -W "$TIMEOUT_PING" "${to_npub}.fips" 2>&1); then
            local rtt
            rtt=$(echo "$output" | grep -oE 'time=[0-9.]+' | cut -d= -f2)
            if [ -n "$rtt" ]; then
                printf "    %2d: %s ms\n" "$i" "$rtt"
                rtts+=("$rtt")
            else
                printf "    %2d: OK (no rtt)\n" "$i"
            fi
        else
            printf "    %2d: FAIL\n" "$i"
            fails=$((fails + 1))
        fi
    done

    if [ "$fails" -gt 0 ]; then
        FAILED=$((FAILED + fails))
    fi

    # Drop first ping, compute average of remaining
    if [ "${#rtts[@]}" -ge 2 ]; then
        local avg
        local csv
        csv=$(IFS=,; echo "${rtts[*]}")
        avg=$(python3 -c "
rtts = [$csv]
trimmed = rtts[1:]
print(f'{sum(trimmed)/len(trimmed):.1f}')
")
        echo "    Avg (excluding first): ${avg} ms"
        PASSED=$((PASSED + ${#rtts[@]}))
    elif [ "${#rtts[@]}" -eq 1 ]; then
        echo "    Only 1 successful ping, no average"
        PASSED=$((PASSED + 1))
    else
        echo "    No successful pings"
    fi
    echo ""
}

echo ""
echo "  Ping via Tor onion service (directory mode, Sandbox 1):"
ping_series fips-dir-a "$NPUB_B" "A → B"
ping_series fips-dir-b "$NPUB_A" "B → A"

echo ""

# ── Phase 6: Log analysis ────────────────────────────────────────
echo "Phase 6: Log analysis"

for node in fips-dir-a fips-dir-b; do
    panics=$(docker logs "$node" 2>&1 | grep -ci "panic" || true)
    errors=$(docker logs "$node" 2>&1 | grep -ci "error" || true)
    onion=$(docker logs "$node" 2>&1 | grep -ci "onion" || true)
    directory=$(docker logs "$node" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -ci "directory.mode" || true)
    echo "  $node: panics=$panics errors=$errors onion_mentions=$onion directory_mentions=$directory"
    if [ "$panics" -gt 0 ]; then
        echo "    WARNING: panics detected in $node logs"
    fi
done

echo ""

# ── Cleanup ──────────────────────────────────────────────────────
echo "Cleaning up..."
docker compose down
rm -f configs/node-a.yaml configs/node-b.yaml

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
