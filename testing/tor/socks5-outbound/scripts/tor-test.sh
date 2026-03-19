#!/bin/bash
# Tor transport integration test.
#
# Validates end-to-end connectivity through a real Tor network:
#   fips-a --tor/socks5--> vps-chi <--tor/socks5-- fips-b
#
# Both local FIPS nodes connect outbound through a local Tor daemon
# to vps-chi's TCP listener (217.77.8.91:443). Once both are peered
# with vps-chi, traffic between fips-a and fips-b is routed through it.
#
# Each run generates ephemeral identities to avoid mesh clashes when
# multiple instances of this test run concurrently.
#
# Usage: ./tor-test.sh
#
# Timings (approximate):
#   Tor bootstrap:          10-30s
#   First SOCKS5 attempt:   may timeout at 60s (circuits not ready)
#   Retry + circuit setup:  10-30s
#   FIPS handshake:         ~1s per peer
#   Routing convergence:    ~5s
#   Total:                  ~90-180s
#
# This test requires internet access for the Tor daemon.

set -e
trap 'echo ""; echo "Test interrupted — cleaning up..."; docker compose down 2>/dev/null; exit 130' INT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOR_DIR="$SCRIPT_DIR/.."
DERIVE_KEYS="$SCRIPT_DIR/../../../lib/derive_keys.py"
cd "$TOR_DIR"

PASSED=0
FAILED=0
TIMEOUT_PING=15
MAX_WAIT_TOR=90
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

echo "=== FIPS Tor Transport Integration Test ==="
echo ""

# ── Phase 0: Generate ephemeral identities ───────────────────────
echo "Phase 0: Generating ephemeral identities..."

MESH_NAME="tor-test-$(date +%s)-$$"
echo "  Mesh name: $MESH_NAME"

KEYS_A=$(python3 "$DERIVE_KEYS" "$MESH_NAME" "a")
NSEC_A=$(echo "$KEYS_A" | grep "^nsec=" | cut -d= -f2)
NPUB_A=$(echo "$KEYS_A" | grep "^npub=" | cut -d= -f2)

KEYS_B=$(python3 "$DERIVE_KEYS" "$MESH_NAME" "b")
NSEC_B=$(echo "$KEYS_B" | grep "^nsec=" | cut -d= -f2)
NPUB_B=$(echo "$KEYS_B" | grep "^npub=" | cut -d= -f2)

echo "  Node A: $NPUB_A"
echo "  Node B: $NPUB_B"

# Generate configs from templates
sed "s/{{NSEC_A}}/$NSEC_A/" configs/node-a.yaml.tmpl > configs/node-a.yaml
sed "s/{{NSEC_B}}/$NSEC_B/" configs/node-b.yaml.tmpl > configs/node-b.yaml
echo "  Configs generated"
echo ""

# ── Phase 1: Build and start ─────────────────────────────────────
echo "Phase 1: Starting Tor daemon and FIPS nodes..."
docker compose down 2>/dev/null || true
docker compose up -d
echo ""

# ── Phase 2: Wait for Tor bootstrap ─────────────────────────────
echo "Phase 2: Waiting for Tor daemon to bootstrap (up to ${MAX_WAIT_TOR}s)..."
elapsed=0
while [ "$elapsed" -lt "$MAX_WAIT_TOR" ]; do
    if docker logs tor-daemon 2>&1 | grep -q "Bootstrapped 100%"; then
        echo "  Tor bootstrapped after ${elapsed}s"
        break
    fi
    sleep 5
    elapsed=$((elapsed + 5))
    echo "  ${elapsed}s..."
done

if [ "$elapsed" -ge "$MAX_WAIT_TOR" ]; then
    echo "  FAIL: Tor daemon did not bootstrap within ${MAX_WAIT_TOR}s"
    echo ""
    echo "Tor daemon logs:"
    docker logs tor-daemon 2>&1 | tail -20
    docker compose down
    exit 1
fi
echo ""

# ── Phase 3: Wait for FIPS peers via Tor ─────────────────────────
echo "Phase 3: Waiting for FIPS nodes to peer with vps-chi via Tor (up to ${MAX_WAIT_PEER}s)..."
echo "  (First SOCKS5 attempt may timeout while Tor builds circuits)"

peers_a=0
peers_b=0
elapsed=0
while [ "$elapsed" -lt "$MAX_WAIT_PEER" ]; do
    peers_a=$(count_connected_peers fips-tor-a)
    peers_b=$(count_connected_peers fips-tor-b)

    if [ "$peers_a" -ge 1 ] && [ "$peers_b" -ge 1 ]; then
        echo "  Both nodes have connected peers after ${elapsed}s (A: ${peers_a}, B: ${peers_b})"
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
    docker logs fips-tor-a 2>&1 | tail -30
    echo ""
    echo "Node B logs (last 30 lines):"
    docker logs fips-tor-b 2>&1 | tail -30
    docker compose down
    exit 1
fi

# Extra convergence time for routing
echo "  Waiting 10s for routing convergence..."
sleep 10
echo ""

# ── Phase 4: Connectivity tests ──────────────────────────────────
echo "Phase 4: Connectivity tests"

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
echo "  Ping via Tor (routed through vps-chi):"
ping_series fips-tor-a "$NPUB_B" "A → B"
ping_series fips-tor-b "$NPUB_A" "B → A"

echo ""

# ── Phase 5: Log analysis ────────────────────────────────────────
echo "Phase 5: Log analysis"

for node in fips-tor-a fips-tor-b; do
    panics=$(docker logs "$node" 2>&1 | grep -ci "panic" || true)
    errors=$(docker logs "$node" 2>&1 | grep -ci "error" || true)
    socks5=$(docker logs "$node" 2>&1 | grep -ci "socks5\|socks" || true)
    echo "  $node: panics=$panics errors=$errors socks5_mentions=$socks5"
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
