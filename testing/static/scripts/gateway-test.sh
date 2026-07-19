#!/bin/bash
# Gateway integration test: non-FIPS LAN client reaches mesh HTTP server.
#
# Topology:
#   gw-client (non-FIPS) → gw-gateway (fips + fips-gateway) → gw-server (fips + http)
#
# Usage:
#   ./scripts/gateway-test.sh [inject-config]
#
# Subcommands:
#   inject-config  — post-process generated configs to add gateway section
#   (no args)      — run the test (containers must be running)
set -e

trap 'echo ""; echo "Test interrupted"; exit 130' INT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../lib/wait-converge.sh"

GENERATED_DIR="$SCRIPT_DIR/../generated-configs"
ENV_FILE="$GENERATED_DIR/npubs.env"

GATEWAY="fips-gw-gateway${FIPS_CI_NAME_SUFFIX:-}"
SERVER="fips-gw-server${FIPS_CI_NAME_SUFFIX:-}"
SERVER2="fips-gw-server-2${FIPS_CI_NAME_SUFFIX:-}"
CLIENT="fips-gw-client${FIPS_CI_NAME_SUFFIX:-}"
CLIENT2="fips-gw-client-2${FIPS_CI_NAME_SUFFIX:-}"

# ── inject-config subcommand ─────────────────────────────────────────────

inject_gateway_config() {
    local config_file="$GENERATED_DIR/gateway/node-a.yaml"

    if [ ! -f "$config_file" ]; then
        echo "Error: $config_file not found. Run generate-configs.sh gateway first." >&2
        exit 1
    fi

    echo "Injecting gateway config into $config_file"
    python3 -c "
import yaml

with open('$config_file') as f:
    cfg = yaml.safe_load(f)

cfg['gateway'] = {
    'enabled': True,
    'pool': 'fd01::/112',
    # Docker assigns gateway-lan to eth1 (fips-net is eth0). The
    # LAN-side masquerade for inbound port forwards gates on this.
    'lan_interface': 'eth1',
    'dns': {
        'listen': '[::]:53',
        'ttl': 5,
    },
    'pool_grace_period': 5,
    'port_forwards': [
        {
            'listen_port': 18080,
            'proto': 'tcp',
            'target': '[fd02::20]:8080',
        },
        # 6B: second TCP forward — exercises multiple simultaneous TCP
        # rules sharing the same LAN backend on a different listen port.
        {
            'listen_port': 18082,
            'proto': 'tcp',
            'target': '[fd02::20]:8081',
        },
        # 6A: UDP forward — exercises the runtime UDP DNAT path (rule
        # shape + conntrack handling) end-to-end.
        {
            'listen_port': 18081,
            'proto': 'udp',
            'target': '[fd02::20]:8081',
        },
    ],
}

with open('$config_file', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
"
    echo "  ✓ Gateway config injected"
}

if [ "${1:-}" = "inject-config" ]; then
    inject_gateway_config
    exit 0
fi

# ── Main test ────────────────────────────────────────────────────────────

if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found. Run generate-configs.sh gateway first." >&2
    exit 1
fi

# shellcheck source=../generated-configs/npubs.env
source "$ENV_FILE"

PASSED=0
FAILED=0

check() {
    local label="$1"
    local result="$2"
    if [ "$result" -eq 0 ]; then
        echo "  $label ... OK"
        PASSED=$((PASSED + 1))
    else
        echo "  $label ... FAIL"
        FAILED=$((FAILED + 1))
    fi
}

echo "=== FIPS Gateway Integration Test ==="
echo ""

# Phase 1: Wait for mesh convergence (gateway ↔ server, gateway ↔ server-2)
echo "Phase 1: Mesh convergence"
wait_for_peers "$GATEWAY" 2 30 || true
wait_for_peers "$SERVER" 1 30 || true
wait_for_peers "$SERVER2" 1 30 || true

# Phase 2: Wait for gateway DNS to respond
echo ""
echo "Phase 2: Gateway DNS readiness"
DNS_READY=false
for i in $(seq 1 30); do
    # Try resolving the server's npub via the gateway DNS from the client.
    # Match fd01:: specifically (the pool prefix) to avoid false-positive
    # matches on error messages containing fd02::10.
    local_result=$(docker exec "$CLIENT" dig +short AAAA "${NPUB_B}.fips" @fd02::10 2>/dev/null || true)
    if echo "$local_result" | grep -q "^fd01::"; then
        echo "  Gateway DNS responding after ${i}s"
        DNS_READY=true
        break
    fi
    sleep 1
done

if [ "$DNS_READY" != true ]; then
    echo "  WARNING: Gateway DNS did not respond within 30s, continuing anyway"
fi

# Phase 3: Client network setup — route virtual IP pool via gateway
echo ""
echo "Phase 3: Client network setup"
docker exec "$CLIENT" ip -6 route add fd01::/112 via fd02::10 2>/dev/null || true
echo "  Added route fd01::/112 via fd02::10 on $CLIENT"
docker exec "$CLIENT2" ip -6 route add fd01::/112 via fd02::10 2>/dev/null || true
echo "  Added route fd01::/112 via fd02::10 on $CLIENT2"

# Phase 4: DNS resolution test — resolve server npub from both clients,
# exercising concurrent multi-client mappings.
echo ""
echo "Phase 4: DNS resolution"
VIRTUAL_IP=$(docker exec "$CLIENT" dig +short AAAA "${NPUB_B}.fips" @fd02::10 2>/dev/null | head -1)
if [ -n "$VIRTUAL_IP" ] && echo "$VIRTUAL_IP" | grep -q "fd01"; then
    check "Resolve ${NPUB_B:0:20}...fips on $CLIENT → $VIRTUAL_IP" 0
else
    check "Resolve ${NPUB_B:0:20}...fips on $CLIENT (got: '$VIRTUAL_IP')" 1
fi

VIRTUAL_IP_2=$(docker exec "$CLIENT2" dig +short AAAA "${NPUB_C}.fips" @fd02::10 2>/dev/null | head -1)
if [ -n "$VIRTUAL_IP_2" ] && echo "$VIRTUAL_IP_2" | grep -q "fd01"; then
    check "Resolve ${NPUB_C:0:20}...fips on $CLIENT2 → $VIRTUAL_IP_2" 0
else
    check "Resolve ${NPUB_C:0:20}...fips on $CLIENT2 (got: '$VIRTUAL_IP_2')" 1
fi

# Both clients must receive distinct virtual-IP mappings — this is the
# core multi-client invariant: each LAN client gets its own pool entry.
if [ -n "$VIRTUAL_IP" ] && [ -n "$VIRTUAL_IP_2" ] && [ "$VIRTUAL_IP" != "$VIRTUAL_IP_2" ]; then
    check "Distinct virtual IPs per client ($VIRTUAL_IP vs $VIRTUAL_IP_2)" 0
else
    check "Distinct virtual IPs per client (got: '$VIRTUAL_IP' vs '$VIRTUAL_IP_2')" 1
fi

# Verify gateway show_mappings reports both client mappings. Mapping
# allocation happens in the DNS response path, but the gateway control
# socket serves a snapshot that is refreshed on a 10s tick (see
# src/bin/fips-gateway.rs tick interval). Poll up to 15s so at least
# one post-allocation snapshot tick is guaranteed to land.
ACTIVE_COUNT="error"
# Control socket protocol is line-delimited JSON ({"command": "..."});
# bare "show_mappings" returns an "invalid request" error response with
# no data field and the parse below counts that as 0 mappings.
for _ in $(seq 1 15); do
    GW_MAPPINGS=$(docker exec "$GATEWAY" bash -c \
        'echo "{\"command\":\"show_mappings\"}" | nc -U -w1 /run/fips/gateway.sock 2>/dev/null' || echo "")
    ACTIVE_COUNT=$(echo "$GW_MAPPINGS" \
        | python3 -c "import sys,json; r=json.load(sys.stdin); print(len(r.get('data',{}).get('mappings',[])))" 2>/dev/null || echo "error")
    if [ "$ACTIVE_COUNT" = "2" ]; then
        break
    fi
    sleep 1
done
if [ "$ACTIVE_COUNT" = "2" ]; then
    check "Gateway reports 2 active mappings (multi-client)" 0
else
    check "Gateway active mapping count (got: $ACTIVE_COUNT)" 1
fi

# Phase 5: End-to-end HTTP test from both clients in parallel
echo ""
echo "Phase 5: HTTP through gateway"

# Use --resolve to bind the .fips hostname to the virtual IP for curl.
# Run both client requests concurrently to exercise simultaneous flows
# through distinct NAT mappings.
RESP_FILE=$(mktemp)
RESP_FILE_2=$(mktemp)
trap 'rm -f "$RESP_FILE" "$RESP_FILE_2"' EXIT

if [ -n "$VIRTUAL_IP" ]; then
    docker exec "$CLIENT" curl -6 -s --max-time 10 \
        --resolve "${NPUB_B}.fips:8000:[$VIRTUAL_IP]" \
        "http://${NPUB_B}.fips:8000/" >"$RESP_FILE" 2>&1 &
    PID1=$!
else
    PID1=""
fi

if [ -n "$VIRTUAL_IP_2" ]; then
    docker exec "$CLIENT2" curl -6 -s --max-time 10 \
        --resolve "${NPUB_C}.fips:8000:[$VIRTUAL_IP_2]" \
        "http://${NPUB_C}.fips:8000/" >"$RESP_FILE_2" 2>&1 &
    PID2=$!
else
    PID2=""
fi

[ -n "$PID1" ] && wait "$PID1" || true
[ -n "$PID2" ] && wait "$PID2" || true

RESPONSE=$(cat "$RESP_FILE")
RESPONSE_2=$(cat "$RESP_FILE_2")

if [ -n "$VIRTUAL_IP" ]; then
    if echo "$RESPONSE" | grep -q "Fuck IPs"; then
        check "HTTP GET from $CLIENT" 0
    else
        check "HTTP GET from $CLIENT (response: '${RESPONSE:0:80}')" 1
    fi
else
    check "HTTP GET from $CLIENT (skipped — no virtual IP)" 1
fi

if [ -n "$VIRTUAL_IP_2" ]; then
    if echo "$RESPONSE_2" | grep -q "Fuck IPs"; then
        check "HTTP GET from $CLIENT2" 0
    else
        check "HTTP GET from $CLIENT2 (response: '${RESPONSE_2:0:80}')" 1
    fi
else
    check "HTTP GET from $CLIENT2 (skipped — no virtual IP)" 1
fi

# Phase 6: Verify NAT state on gateway
echo ""
echo "Phase 6: Gateway NAT state"
# Check that nftables rules were created
NFT_RULES=$(docker exec "$GATEWAY" nft list table inet fips_gateway 2>/dev/null || echo "")
if echo "$NFT_RULES" | grep -q "dnat"; then
    check "nftables DNAT rules present" 0
else
    check "nftables DNAT rules" 1
fi

# Phase 7: Inbound port forwarding — UDP and a second simultaneous TCP forward.
#
# Three forwards exercised:
#   tcp 18080 → [fd02::20]:8080  (original — single TCP rule)
#   tcp 18082 → [fd02::20]:8081  (6B — second TCP rule, multiple forwards)
#   udp 18081 → [fd02::20]:8081  (6A — UDP DNAT runtime path)
#
# Mesh peer (gw-server) hits each gw-gateway fips0:<port> rule, which
# DNATs into the LAN-side gw-client. Exercises the DNAT rules + LAN-side
# masquerade installed by set_port_forwards().
echo ""
echo "Phase 7: Inbound port forwards"

# Confirm all three port-forward DNAT rules are present on the gateway.
# The distinctive listen ports identify our rules regardless of how nft
# renders the l4proto/dport predicates.
if echo "$NFT_RULES" | grep -q "18080"; then
    check "nftables port-forward DNAT rule (tcp 18080)" 0
else
    check "nftables port-forward DNAT rule (tcp 18080)" 1
fi
if echo "$NFT_RULES" | grep -q "18082"; then
    check "nftables port-forward DNAT rule (tcp 18082)" 0
else
    check "nftables port-forward DNAT rule (tcp 18082)" 1
fi
if echo "$NFT_RULES" | grep -q "18081"; then
    check "nftables port-forward DNAT rule (udp 18081)" 0
else
    check "nftables port-forward DNAT rule (udp 18081)" 1
fi

# Start marker HTTP servers on the LAN-side client.
#   :8080 → "inbound-forward-ok"   (target of tcp 18080)
#   :8081 → "inbound-forward-ok-2" (target of tcp 18082)
# `docker exec -d` is required; `docker exec bash -c 'cmd &'` doesn't
# keep the child alive past the exec session, even with nohup.
docker exec "$CLIENT" sh -c '
    mkdir -p /tmp/inbound /tmp/inbound2
    echo "inbound-forward-ok"   > /tmp/inbound/index.html
    echo "inbound-forward-ok-2" > /tmp/inbound2/index.html
    pkill -f "http.server 8080" 2>/dev/null || true
    pkill -f "http.server 8081" 2>/dev/null || true
    pkill -f "udp_echo.py" 2>/dev/null || true
' >/dev/null 2>&1 || true
docker exec -d "$CLIENT" python3 -m http.server 8080 --bind :: --directory /tmp/inbound \
    >/dev/null 2>&1 || true
docker exec -d "$CLIENT" python3 -m http.server 8081 --bind :: --directory /tmp/inbound2 \
    >/dev/null 2>&1 || true

# Start a UDP echo server on the LAN-side client at [::]:8081/udp.
# This is the target of the udp 18081 forward. Stash the script as a
# named file (`udp_echo.py`) so the cleanup pkill above can find it.
docker exec "$CLIENT" sh -c 'cat > /tmp/udp_echo.py <<'\''PYEOF'\''
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("::", 8081))
while True:
    data, addr = s.recvfrom(2048)
    s.sendto(b"udp-forward-ok:" + data, addr)
PYEOF' >/dev/null 2>&1 || true
docker exec -d "$CLIENT" python3 /tmp/udp_echo.py >/dev/null 2>&1 || true

# Give the servers a moment to bind.
for _ in 1 2 3 4 5; do
    TCP_READY=$(docker exec "$CLIENT" ss -6lnt 2>/dev/null | grep -cE ':8080|:8081' || true)
    UDP_READY=$(docker exec "$CLIENT" ss -6lnu 2>/dev/null | grep -c ':8081' || true)
    if [ "$TCP_READY" -ge 2 ] && [ "$UDP_READY" -ge 1 ]; then
        break
    fi
    sleep 1
done

# Derive the gateway's mesh IPv6 (fd00::/8 address assigned to fips0).
GW_MESH_IP=$(docker exec "$GATEWAY" bash -c \
    "ip -6 -o addr show fips0 | awk '/inet6 fd/ {print \$4}' | cut -d/ -f1 | head -1" \
    2>/dev/null || echo "")

if [ -z "$GW_MESH_IP" ]; then
    check "Gateway fips0 IPv6 address" 1
else
    echo "  Gateway mesh IPv6: $GW_MESH_IP"

    # From the mesh side (gw-server), fetch through each TCP forward.
    FWD_RESPONSE=$(docker exec "$SERVER" curl -6 -s --max-time 10 \
        "http://[${GW_MESH_IP}]:18080/" 2>&1) || true
    # 8080 backend serves "inbound-forward-ok" (no -2 suffix) — distinct
    # from the 8081 backend so a misrouted response would be detectable.
    if echo "$FWD_RESPONSE" | grep -qE '^inbound-forward-ok$'; then
        check "Inbound HTTP via TCP forward 18080 → [fd02::20]:8080" 0
    else
        check "Inbound HTTP via TCP forward 18080 (response: '${FWD_RESPONSE:0:80}')" 1
    fi

    FWD_RESPONSE_2=$(docker exec "$SERVER" curl -6 -s --max-time 10 \
        "http://[${GW_MESH_IP}]:18082/" 2>&1) || true
    if echo "$FWD_RESPONSE_2" | grep -q "inbound-forward-ok-2"; then
        check "Inbound HTTP via TCP forward 18082 → [fd02::20]:8081 (6B)" 0
    else
        check "Inbound HTTP via TCP forward 18082 (response: '${FWD_RESPONSE_2:0:80}')" 1
    fi

    # 6A: UDP forward. Send a probe via a one-shot Python client on
    # gw-server; the LAN-side echo server prepends "udp-forward-ok:".
    UDP_RESPONSE=$(docker exec "$SERVER" python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(b'ping-via-udp-fwd', ('${GW_MESH_IP}', 18081))
try:
    data, _ = s.recvfrom(2048)
    sys.stdout.write(data.decode('utf-8', 'replace'))
except Exception as e:
    sys.stdout.write('ERR: ' + str(e))
" 2>&1) || true
    if echo "$UDP_RESPONSE" | grep -q "udp-forward-ok:ping-via-udp-fwd"; then
        check "Inbound UDP via forward 18081 → [fd02::20]:8081 (6A)" 0
    else
        check "Inbound UDP via forward 18081 (response: '${UDP_RESPONSE:0:80}')" 1
    fi
fi

# Cleanup: stop the LAN-side responders so Phase 8's pool-reclamation
# wait isn't interfered with by lingering sessions.
docker exec "$CLIENT" sh -c '
    pkill -f "http.server 8080" 2>/dev/null || true
    pkill -f "http.server 8081" 2>/dev/null || true
    pkill -f "udp_echo.py" 2>/dev/null || true
' >/dev/null 2>&1 || true

# Phase 8: TTL expiration and pool reclamation
echo ""
echo "Phase 8: TTL expiration and pool reclamation"
# Flush conntrack so stale sessions from Phase 5 don't keep the mapping alive.
docker exec "$GATEWAY" conntrack -F 2>/dev/null || true
# Config uses ttl=5, pool_grace_period=5. Pool tick interval is 10s, so:
#   tick 1 (~10s): TTL expired → Draining (sessions=0 after flush)
#   tick 2 (~20s): grace expired → freed
# Wait 25s to ensure two full tick cycles have passed.
echo "  Waiting 25s for TTL + grace period to expire (two tick cycles)..."
sleep 25

# Query gateway control socket for mapping count
MAPPING_COUNT=$(docker exec "$GATEWAY" bash -c \
    'echo "{\"command\":\"show_mappings\"}" | nc -U -w1 /run/fips/gateway.sock 2>/dev/null' \
    | python3 -c "import sys,json; r=json.load(sys.stdin); print(len(r.get('data',{}).get('mappings',[])))" 2>/dev/null || echo "error")
if [ "$MAPPING_COUNT" = "0" ]; then
    check "Mapping reclaimed after TTL+grace" 0
else
    check "Mapping reclaimed (count: $MAPPING_COUNT)" 1
fi

# Phase 9: SERVFAIL when daemon DNS is down
echo ""
echo "Phase 9: SERVFAIL when daemon DNS is down"
# Kill the fips daemon inside the gateway container (gateway stays running)
docker exec "$GATEWAY" pkill -f "^fips --config" 2>/dev/null || true
sleep 2

# Gateway upstream timeout is 5s, so dig must wait longer than that.
SERVFAIL_RESULT=$(docker exec "$CLIENT" dig +short +tries=1 +time=8 AAAA "test-servfail.fips" @fd02::10 2>&1 || true)
SERVFAIL_STATUS=$(docker exec "$CLIENT" dig +tries=1 +time=8 AAAA "test-servfail.fips" @fd02::10 2>&1 | grep -c "SERVFAIL" || true)
if [ "$SERVFAIL_STATUS" -ge 1 ]; then
    check "SERVFAIL when daemon DNS is down" 0
else
    check "SERVFAIL when daemon DNS down (got: '${SERVFAIL_RESULT:0:80}')" 1
fi

# Phase 10: Cleanup verification (nftables removed on shutdown)
echo ""
echo "Phase 10: Cleanup on shutdown"
# fips-gateway is PID 1 (exec in entrypoint), so SIGTERM stops the container.
# Verify cleanup by checking container logs for the shutdown sequence.
docker stop --time=10 "$GATEWAY" >/dev/null 2>&1 || true
sleep 1

LOGS=$(docker logs --tail=20 "$GATEWAY" 2>&1)
if echo "$LOGS" | grep -q "shutdown complete"; then
    check "Gateway shutdown completed cleanly" 0
else
    check "Gateway shutdown (no completion message in logs)" 1
fi

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
