#!/bin/bash
# Integration test for the FIPS sidecar deployment.
#
# Starts a 3-node chain (A—B—C) using standalone sidecar instances,
# verifies link establishment, multi-hop connectivity, and network
# isolation on each app container.
#
# Usage: ./test-sidecar.sh [--skip-build]
#
# Exit codes:
#   0 — all tests passed
#   1 — test failure
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIDECAR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Deterministic keys derived from: derive-keys.py sidecar-test node-{a,b,c}
NODE_A_NSEC="9e688d0879fa9cd025fea0487ac23495080e3de626070fdb9b78dc1f619dd453"
NODE_A_NPUB="npub1jvren5hnege54lu3p2nzqacctmulqvkgp68yvfuj5jme5dtgnhxsdh6788"
NODE_B_NSEC="3e4e10614c0490575fa5e994524ff3f4deaac2f20db189cc9c9a79da0d90f17a"
NODE_B_NPUB="npub15h7z0ljzudqe9pgwx99cjsz2c0ennuyvkcc8zvtk3lg97xwzex9ska6g4y"
NODE_C_NSEC="15148ed0131f7da43fd13e369dfedede14fb64698f3756636b569c3a3e87438f"
NODE_C_NPUB="npub1zhezcykd0e34z4fxtranl45jaasgnlxv0kjqwlq2v56ggssn0w4qelcrvr"

NETWORK_NAME="fips-sidecar-test"
SUBNET="172.20.2.0/24"
NODE_A_IP="172.20.2.10"
NODE_B_IP="172.20.2.11"
NODE_C_IP="172.20.2.12"

CONVERGE_TIMEOUT=30
PASSED=0
FAILED=0

# Compose file paths
COMPOSE_BASE="-f $SIDECAR_DIR/docker-compose.yml"
COMPOSE_EXT="$COMPOSE_BASE -f $SIDECAR_DIR/docker-compose.external-net.yml"

# ── Helpers ────────────────────────────────────────────────────────────────

log()   { echo "=== $*"; }
pass()  { echo "  PASS: $*"; PASSED=$((PASSED + 1)); }
fail()  { echo "  FAIL: $*"; FAILED=$((FAILED + 1)); }

cleanup() {
    log "Cleaning up..."
    # Tear down B and C first (they reference A's network as external)
    docker compose $COMPOSE_EXT -p sidecar-c down --volumes --remove-orphans 2>/dev/null || true
    docker compose $COMPOSE_EXT -p sidecar-b down --volumes --remove-orphans 2>/dev/null || true
    # Tear down A last (it owns the network)
    docker compose $COMPOSE_BASE -p sidecar-a down --volumes --remove-orphans 2>/dev/null || true
}

# Always clean up on exit
trap cleanup EXIT

# ── Build ──────────────────────────────────────────────────────────────────

if [[ "${1:-}" != "--skip-build" ]]; then
    log "Building sidecar images..."
    docker compose $COMPOSE_BASE build
fi

# ── Start nodes ────────────────────────────────────────────────────────────
#
# Chain topology: A — B — C
#   node-a: no outbound peers (accepts inbound from B)
#   node-b: peers with A (middle node, transit router)
#   node-c: peers with B (end node)

log "Starting node-a (no peers, creates network)..."
FIPS_NSEC="$NODE_A_NSEC" \
FIPS_NETWORK="$NETWORK_NAME" \
FIPS_SUBNET="$SUBNET" \
FIPS_IPV4="$NODE_A_IP" \
docker compose $COMPOSE_BASE -p sidecar-a up -d

log "Starting node-b (peers with node-a, joins external network)..."
FIPS_NSEC="$NODE_B_NSEC" \
FIPS_PEER_NPUB="$NODE_A_NPUB" \
FIPS_PEER_ADDR="${NODE_A_IP}:2121" \
FIPS_PEER_ALIAS="node-a" \
FIPS_NETWORK="$NETWORK_NAME" \
FIPS_SUBNET="$SUBNET" \
FIPS_IPV4="$NODE_B_IP" \
docker compose $COMPOSE_EXT -p sidecar-b up -d

log "Starting node-c (peers with node-b, joins external network)..."
FIPS_NSEC="$NODE_C_NSEC" \
FIPS_PEER_NPUB="$NODE_B_NPUB" \
FIPS_PEER_ADDR="${NODE_B_IP}:2121" \
FIPS_PEER_ALIAS="node-b" \
FIPS_NETWORK="$NETWORK_NAME" \
FIPS_SUBNET="$SUBNET" \
FIPS_IPV4="$NODE_C_IP" \
docker compose $COMPOSE_EXT -p sidecar-c up -d

# ── Wait for convergence ──────────────────────────────────────────────────

log "Waiting for link establishment (up to ${CONVERGE_TIMEOUT}s)..."

converged=false
for i in $(seq 1 "$CONVERGE_TIMEOUT"); do
    # node-b should have 2 links (A and C)
    link_count=$(docker exec sidecar-b-fips-1 fipsctl show links 2>/dev/null \
        | grep -c '"state": "connected"' || true)
    if [ "$link_count" -ge 2 ]; then
        converged=true
        break
    fi
    sleep 1
done

if [ "$converged" = true ]; then
    log "Links established after ${i}s"
else
    log "TIMEOUT: links did not converge in ${CONVERGE_TIMEOUT}s"
    log "node-a links:"
    docker exec sidecar-a-fips-1 fipsctl show links 2>&1 || true
    log "node-b links:"
    docker exec sidecar-b-fips-1 fipsctl show links 2>&1 || true
    log "node-c links:"
    docker exec sidecar-c-fips-1 fipsctl show links 2>&1 || true
    exit 1
fi

# Allow a few more seconds for tree convergence and coordinate propagation
sleep 3

# ── Link verification ─────────────────────────────────────────────────────

log "Verifying link counts..."

a_links=$(docker exec sidecar-a-fips-1 fipsctl show links 2>/dev/null \
    | grep -c '"state": "connected"' || true)
b_links=$(docker exec sidecar-b-fips-1 fipsctl show links 2>/dev/null \
    | grep -c '"state": "connected"' || true)
c_links=$(docker exec sidecar-c-fips-1 fipsctl show links 2>/dev/null \
    | grep -c '"state": "connected"' || true)

[ "$a_links" -ge 1 ] && pass "node-a has $a_links link(s)" || fail "node-a has $a_links links (expected >= 1)"
[ "$b_links" -ge 2 ] && pass "node-b has $b_links link(s)" || fail "node-b has $b_links links (expected >= 2)"
[ "$c_links" -ge 1 ] && pass "node-c has $c_links link(s)" || fail "node-c has $c_links links (expected >= 1)"

# ── Direct connectivity (adjacent nodes) ──────────────────────────────────

log "Testing direct connectivity (B app → A via fips0)..."

if docker exec sidecar-b-app-1 ping6 -c2 -W5 "${NODE_A_NPUB}.fips" >/dev/null 2>&1; then
    pass "node-b app can ping node-a via fips0"
else
    fail "node-b app cannot ping node-a via fips0"
fi

# ── Multi-hop connectivity (C → A through B) ─────────────────────────────

log "Testing multi-hop connectivity (C app → A via fips0, through B)..."

if docker exec sidecar-c-app-1 ping6 -c2 -W10 "${NODE_A_NPUB}.fips" >/dev/null 2>&1; then
    pass "node-c app can ping node-a via fips0 (multi-hop through B)"
else
    fail "node-c app cannot ping node-a via fips0 (multi-hop through B)"
fi

# ── Reverse direction (A → C through B) ──────────────────────────────────

log "Testing reverse multi-hop (A app → C via fips0, through B)..."

if docker exec sidecar-a-app-1 ping6 -c2 -W10 "${NODE_C_NPUB}.fips" >/dev/null 2>&1; then
    pass "node-a app can ping node-c via fips0 (multi-hop through B)"
else
    fail "node-a app cannot ping node-c via fips0 (multi-hop through B)"
fi

# ── Network isolation verification ────────────────────────────────────────
#
# This is the critical security assertion: app containers must NOT be able
# to reach anything outside the FIPS mesh.

log "Verifying network isolation on app containers..."

for node in a b c; do
    container="sidecar-${node}-app-1"
    # Pick a peer IP that isn't this node's own address
    case $node in
        a) peer_ip="$NODE_B_IP" ;;
        b) peer_ip="$NODE_C_IP" ;;
        c) peer_ip="$NODE_A_IP" ;;
    esac
    log "  Checking $container..."

    # IPv4 gateway should be unreachable (iptables DROP on eth0)
    if docker exec "$container" ping -c1 -W2 172.20.2.1 >/dev/null 2>&1; then
        fail "$container can reach IPv4 gateway (isolation broken!)"
    else
        pass "$container cannot reach IPv4 gateway (IPv4 blocked)"
    fi

    # IPv4 peer should be unreachable (iptables DROP on eth0)
    if docker exec "$container" ping -c1 -W2 "$peer_ip" >/dev/null 2>&1; then
        fail "$container can reach peer IPv4 (isolation broken!)"
    else
        pass "$container cannot reach peer IPv4 (IPv4 blocked)"
    fi

    # Loopback should work
    if docker exec "$container" ping -c1 -W2 127.0.0.1 >/dev/null 2>&1; then
        pass "$container can reach loopback (expected)"
    else
        fail "$container cannot reach loopback"
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────

echo ""
log "Results: $PASSED passed, $FAILED failed"

if [ "$FAILED" -gt 0 ]; then
    log "Dumping logs for failed run..."
    for node in a b c; do
        echo "--- sidecar-${node} logs ---"
        docker logs "sidecar-${node}-fips-1" 2>&1 | tail -30
        echo ""
    done
    exit 1
fi

log "All tests passed."
