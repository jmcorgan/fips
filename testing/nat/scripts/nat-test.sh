#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$NAT_DIR/../.." && pwd)"
BUILD_SCRIPT="$ROOT_DIR/testing/scripts/build.sh"
GENERATE_SCRIPT="$SCRIPT_DIR/generate-configs.sh"
TOPOLOGY_SCRIPT="$SCRIPT_DIR/setup-topology.sh"
WAIT_LIB="$ROOT_DIR/testing/lib/wait-converge.sh"

SCENARIO="${1:-all}"
COMPOSE=(docker compose -f "$NAT_DIR/docker-compose.yml")

source "$WAIT_LIB"

cleanup() {
    "${COMPOSE[@]}" --profile cone --profile symmetric --profile lan \
        down -v --remove-orphans >/dev/null 2>&1 || true
}

helper_tcpdump_image() {
    docker inspect -f '{{.Config.Image}}' fips-nat-router-a 2>/dev/null || echo nat-nat-a
}

dump_container_state() {
    local container="$1"
    echo ""
    echo "--- $container: logs (last 80) ---"
    docker logs "$container" 2>&1 | tail -80 || true
}

send_stun_probe() {
    local container="$1"
    local stun_host="$2"
    local stun_port="$3"

    docker exec "$container" python3 - "$stun_host" "$stun_port" <<'PY' 2>&1 || true
import os
import socket
import struct
import sys

host = sys.argv[1]
port = int(sys.argv[2])
txn_id = os.urandom(12)
request = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txn_id

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2.0)
sock.sendto(request, (host, port))

try:
    data, remote = sock.recvfrom(2048)
except socket.timeout:
    print(f"stun timeout waiting for {host}:{port}")
    raise SystemExit(1)

if len(data) < 20:
    print(f"short stun response from {remote}: {len(data)} bytes")
    raise SystemExit(1)

msg_type, msg_len, cookie = struct.unpack("!HHI", data[:8])
if msg_type != 0x0101 or cookie != 0x2112A442 or data[8:20] != txn_id:
    print(f"unexpected stun response from {remote}: type=0x{msg_type:04x} len={msg_len} cookie=0x{cookie:08x}")
    raise SystemExit(1)

print(f"stun binding success from {remote[0]}:{remote[1]}")
PY
}

dump_fips_state() {
    local container="$1"
    local relay_host="${2:-172.31.254.30}"
    local relay_port="${3:-7777}"
    local stun_host="${4:-172.31.254.40}"
    local stun_port="${5:-3478}"
    dump_container_state "$container"
    echo ""
    echo "--- $container: UDP sockets ---"
    docker exec "$container" sh -lc 'ss -H -uanp 2>/dev/null || ss -H -uan 2>/dev/null || netstat -anu 2>/dev/null' 2>&1 || true
    echo ""
    echo "--- $container: fipsctl show status ---"
    docker exec "$container" fipsctl show status 2>&1 || true
    echo ""
    echo "--- $container: fipsctl show peers ---"
    docker exec "$container" fipsctl show peers 2>&1 || true
    echo ""
    echo "--- $container: fipsctl show links ---"
    docker exec "$container" fipsctl show links 2>&1 || true
    echo ""
    echo "--- $container: relay reachability ---"
    docker exec "$container" sh -lc "nc -vz -w5 ${relay_host} ${relay_port}" 2>&1 || true
    echo ""
    echo "--- $container: stun reachability ---"
    send_stun_probe "$container" "$stun_host" "$stun_port"
}

dump_node_udp_probe() {
    local node="$1"
    local stun_host="${2:-172.31.254.40}"
    local stun_port="${3:-3478}"

    echo ""
    echo "--- $node: UDP sockets (pre-capture) ---"
    docker exec "$node" sh -lc 'ss -H -uanp 2>/dev/null || ss -H -uan 2>/dev/null || netstat -anu 2>/dev/null' 2>&1 || true
    echo ""
    echo "--- $node: UDP routes to STUN and peer WANs ---"
    docker exec "$node" sh -lc 'for ip in 172.31.254.40 172.31.254.10 172.31.254.11; do ip route get "$ip"; done' 2>&1 || true

    local capture_file
    capture_file="$(mktemp)"
    docker exec "$node" sh -lc "timeout 8 tcpdump -ni eth0 'udp and not port 53' -c 80" \
        >"$capture_file" 2>&1 &
    local tcpdump_pid=$!
    sleep 1

    echo ""
    echo "--- $node: UDP active probe ---"
    echo "probe: ${node} -> ${stun_host}:${stun_port}/udp (STUN binding request)"
    send_stun_probe "$node" "$stun_host" "$stun_port"

    wait "$tcpdump_pid" || true

    echo ""
    echo "--- $node: UDP tcpdump during active probe ---"
    cat "$capture_file"
    rm -f "$capture_file"

    echo ""
    echo "--- $node: UDP sockets (post-capture) ---"
    docker exec "$node" sh -lc 'ss -H -uanp 2>/dev/null || ss -H -uan 2>/dev/null || netstat -anu 2>/dev/null' 2>&1 || true
}

dump_router_udp_probe() {
    local router="$1"
    local source_node="$2"
    local stun_host="${3:-172.31.254.40}"
    local stun_port="${4:-3478}"

    echo ""
    echo "--- $router: UDP conntrack/state (before probe) ---"
    docker exec "$router" sh -lc 'conntrack -L -p udp 2>/dev/null || echo "conntrack unavailable"' 2>&1 || true

    echo ""
    echo "--- $router: UDP counters (before probe) ---"
    docker exec "$router" sh -lc 'iptables -vnL FORWARD; echo; iptables -t nat -vnL POSTROUTING' 2>&1 || true
    echo ""
    echo "--- $router: UDP routes to STUN and peer WANs ---"
    docker exec "$router" sh -lc 'for ip in 172.31.254.40 172.31.254.10 172.31.254.11; do ip route get "$ip"; done' 2>&1 || true

    local capture_file
    capture_file="$(mktemp)"
    docker exec "$router" sh -lc "timeout 8 tcpdump -ni any 'udp and not port 53' -c 80" \
        >"$capture_file" 2>&1 &
    local tcpdump_pid=$!
    sleep 1

    echo ""
    echo "--- $router: UDP active probe ---"
    echo "probe: ${source_node} -> ${stun_host}:${stun_port}/udp (STUN binding request)"
    send_stun_probe "$source_node" "$stun_host" "$stun_port"

    wait "$tcpdump_pid" || true

    echo ""
    echo "--- $router: UDP tcpdump during active probe ---"
    cat "$capture_file"
    rm -f "$capture_file"

    echo ""
    echo "--- $router: UDP counters (after probe) ---"
    docker exec "$router" sh -lc 'iptables -vnL FORWARD; echo; iptables -t nat -vnL POSTROUTING' 2>&1 || true

    echo ""
    echo "--- $router: UDP conntrack/state (after probe) ---"
    docker exec "$router" sh -lc 'conntrack -L -p udp 2>/dev/null || echo "conntrack unavailable"' 2>&1 || true
}

dump_stun_udp_probe() {
    local source_node="$1"
    local stun_host="${2:-172.31.254.40}"
    local stun_port="${3:-3478}"
    local helper_image
    helper_image="$(helper_tcpdump_image)"

    local capture_file
    capture_file="$(mktemp)"
    docker run --rm --net=container:fips-nat-stun --cap-add NET_ADMIN --cap-add NET_RAW \
        --entrypoint sh "$helper_image" \
        -lc "timeout 8 tcpdump -ni any 'udp and not port 53' -c 80" \
        >"$capture_file" 2>&1 &
    local tcpdump_pid=$!
    sleep 1

    echo ""
    echo "--- fips-nat-stun: UDP active probe ---"
    echo "probe: ${source_node} -> ${stun_host}:${stun_port}/udp (STUN binding request)"
    send_stun_probe "$source_node" "$stun_host" "$stun_port"

    wait "$tcpdump_pid" || true

    echo ""
    echo "--- fips-nat-stun: UDP tcpdump during active probe ---"
    cat "$capture_file"
    rm -f "$capture_file"
}

dump_cone_diagnostics() {
    echo ""
    echo "=== cone diagnostics ==="
    dump_fips_state fips-nat-cone-a 172.31.254.30 7777 172.31.254.40 3478
    dump_node_udp_probe fips-nat-cone-a
    dump_fips_state fips-nat-cone-b 172.31.254.30 7777 172.31.254.40 3478
    dump_node_udp_probe fips-nat-cone-b
    dump_container_state fips-nat-router-a
    dump_router_udp_probe fips-nat-router-a fips-nat-cone-a
    dump_container_state fips-nat-router-b
    dump_router_udp_probe fips-nat-router-b fips-nat-cone-b
    dump_container_state fips-nat-relay
    dump_stun_udp_probe fips-nat-cone-a
    dump_stun_udp_probe fips-nat-cone-b
    dump_container_state fips-nat-stun
}

dump_symmetric_diagnostics() {
    echo ""
    echo "=== symmetric diagnostics ==="
    dump_fips_state fips-nat-symmetric-a 172.31.254.30 7777 172.31.254.40 3478
    dump_fips_state fips-nat-symmetric-b 172.31.254.30 7777 172.31.254.40 3478
    dump_container_state fips-nat-router-a
    dump_container_state fips-nat-router-b
    dump_container_state fips-nat-relay
    dump_container_state fips-nat-stun
}

dump_lan_diagnostics() {
    echo ""
    echo "=== lan diagnostics ==="
    dump_fips_state fips-nat-lan-a 172.31.10.30 7777 172.31.10.40 3478
    dump_fips_state fips-nat-lan-b 172.31.10.30 7777 172.31.10.40 3478
    dump_container_state fips-nat-relay
    dump_container_state fips-nat-stun
}

trap 'echo ""; echo "NAT test interrupted"; cleanup; exit 130' INT TERM

require_test_image() {
    if ! docker image inspect fips-test:latest >/dev/null 2>&1; then
        echo "fips-test:latest not found; building test image"
        "$BUILD_SCRIPT"
    fi
}

require_docker_daemon() {
    if ! docker info >/dev/null 2>&1; then
        echo "Docker daemon is not reachable; cannot run NAT lab harness" >&2
        exit 1
    fi
}

assert_peer_path() {
    local container="$1"
    local expected_transport="$2"
    local expected_prefix="$3"
    docker exec "$container" fipsctl show peers \
        | python3 -c "
import json, sys
data = json.load(sys.stdin)
peers = [p for p in data.get('peers', []) if p.get('connectivity') == 'connected']
if not peers:
    raise SystemExit(1)
peer = peers[0]
transport = peer.get('transport_type', '')
addr = peer.get('transport_addr', '')
if transport != sys.argv[1]:
    raise SystemExit(f'transport mismatch: expected {sys.argv[1]!r}, got {transport!r}')
if not addr.startswith(sys.argv[2]):
    raise SystemExit(f'addr mismatch: expected prefix {sys.argv[2]!r}, got {addr!r}')
" "$expected_transport" "$expected_prefix"
}

assert_link_path() {
    local container="$1"
    local expected_prefix="$2"
    docker exec "$container" fipsctl show links \
        | python3 -c "
import json, sys
data = json.load(sys.stdin)
links = data.get('links', [])
if not links:
    raise SystemExit(1)
addr = links[0].get('remote_addr', '')
if not addr.startswith(sys.argv[1]):
    raise SystemExit(f'link addr mismatch: expected prefix {sys.argv[1]!r}, got {addr!r}')
" "$expected_prefix"
}

require_bootstrap_activity() {
    local container="$1"
    local logs
    logs="$(docker logs "$container" 2>&1 || true)"
    if ! grep -Eq "bootstrap failed|Started Nostr( UDP)? NAT traversal attempt" <<<"$logs"; then
        echo "Expected bootstrap activity in ${container} logs" >&2
        return 1
    fi
}

ping_peer() {
    local container="$1"
    local npub="$2"
    docker exec "$container" ping6 -c 3 -W 5 "${npub}.fips" >/dev/null
}

run_cone() {
    echo "=== NAT lab: cone ==="
    cleanup
    "$GENERATE_SCRIPT" cone
    "${COMPOSE[@]}" --profile cone up -d --build --force-recreate
    "$TOPOLOGY_SCRIPT" cone
    wait_for_peers fips-nat-cone-a 1 45 || {
        dump_cone_diagnostics
        return 1
    }
    wait_for_peers fips-nat-cone-b 1 45 || {
        dump_cone_diagnostics
        return 1
    }
    assert_peer_path fips-nat-cone-a udp 172.31.254.
    assert_peer_path fips-nat-cone-b udp 172.31.254.
    assert_link_path fips-nat-cone-a 172.31.254.
    assert_link_path fips-nat-cone-b 172.31.254.
    # shellcheck disable=SC1090
    source "$NAT_DIR/generated-configs/cone/npubs.env"
    ping_peer fips-nat-cone-a "$NPUB_B"
    ping_peer fips-nat-cone-b "$NPUB_A"
    cleanup
}

run_symmetric() {
    echo "=== NAT lab: symmetric fallback ==="
    cleanup
    NAT_MODE_A=symmetric NAT_MODE_B=symmetric "$GENERATE_SCRIPT" symmetric
    NAT_MODE_A=symmetric NAT_MODE_B=symmetric "${COMPOSE[@]}" --profile symmetric up -d --build --force-recreate
    "$TOPOLOGY_SCRIPT" symmetric
    wait_for_peers fips-nat-symmetric-a 1 60 || {
        dump_symmetric_diagnostics
        return 1
    }
    wait_for_peers fips-nat-symmetric-b 1 60 || {
        dump_symmetric_diagnostics
        return 1
    }
    assert_peer_path fips-nat-symmetric-a tcp 172.31.254.11:
    assert_peer_path fips-nat-symmetric-b tcp 172.31.254.10:
    assert_link_path fips-nat-symmetric-a 172.31.254.11:
    assert_link_path fips-nat-symmetric-b 172.31.254.10:
    require_bootstrap_activity fips-nat-symmetric-a
    require_bootstrap_activity fips-nat-symmetric-b
    # shellcheck disable=SC1090
    source "$NAT_DIR/generated-configs/symmetric/npubs.env"
    ping_peer fips-nat-symmetric-a "$NPUB_B"
    ping_peer fips-nat-symmetric-b "$NPUB_A"
    cleanup
}

run_lan() {
    echo "=== NAT lab: lan preference ==="
    cleanup
    "$GENERATE_SCRIPT" lan
    "${COMPOSE[@]}" --profile lan up -d --build --force-recreate
    wait_for_peers fips-nat-lan-a 1 45 || {
        dump_lan_diagnostics
        return 1
    }
    wait_for_peers fips-nat-lan-b 1 45 || {
        dump_lan_diagnostics
        return 1
    }
    assert_peer_path fips-nat-lan-a udp 172.31.10.
    assert_peer_path fips-nat-lan-b udp 172.31.10.
    assert_link_path fips-nat-lan-a 172.31.10.
    assert_link_path fips-nat-lan-b 172.31.10.
    # shellcheck disable=SC1090
    source "$NAT_DIR/generated-configs/lan/npubs.env"
    ping_peer fips-nat-lan-a "$NPUB_B"
    ping_peer fips-nat-lan-b "$NPUB_A"
    cleanup
}

main() {
    require_docker_daemon
    require_test_image
    case "$SCENARIO" in
        all)
            run_cone
            run_symmetric
            run_lan
            ;;
        cone)
            run_cone
            ;;
        symmetric)
            run_symmetric
            ;;
        lan)
            run_lan
            ;;
        *)
            echo "Usage: $0 [all|cone|symmetric|lan]" >&2
            exit 1
            ;;
    esac
    echo "NAT lab scenarios passed"
}

main "$@"
