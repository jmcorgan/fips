#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$NAT_DIR/../.." && pwd)"
BUILD_SCRIPT="$ROOT_DIR/testing/scripts/build.sh"
GENERATE_SCRIPT="$SCRIPT_DIR/generate-configs.sh"
TOPOLOGY_SCRIPT="$SCRIPT_DIR/setup-topology.sh"
WAIT_LIB="$ROOT_DIR/testing/lib/wait-converge.sh"
# Must track generate-configs.sh's OUTPUT_DIR and the compose bind-mounts: the
# npubs are read back here after the containers are up, so reading a different
# directory than the one the generator wrote pings an npub no node owns.
CONFIG_DIR="$NAT_DIR/generated-configs${FIPS_CI_NAME_SUFFIX:-}"

# The two lab bridges. ci-local.sh claims a free /24 for each per run and
# exports these; unset renders the addresses the lab has always used, so the
# GitHub matrix, mesh-lab/run-loop.sh and a bare run are unaffected. The
# router-side LANs (172.31.1.x / 172.31.2.x) are deliberately NOT parameterized:
# they live inside per-container network namespaces, never become docker
# networks, and so cannot collide across runs.
NAT_WAN="${NAT_WAN_PREFIX:-172.31.254}"
NAT_LAN="${NAT_LAN_PREFIX:-172.31.10}"

SCENARIO="${1:-all}"
COMPOSE=(docker compose -f "$NAT_DIR/docker-compose.yml")

# Optional extra compose-file overlay chain (colon-separated paths), e.g.
# trace-RUST_LOG overrides supplied by the mesh-lab harness when
# FIPS_MESH_LAB_TRACE=1. Paths are interpreted relative to the repo root
# (ROOT_DIR) unless absolute. The mesh-lab harness sets this env var to
# `testing/mesh-lab/compose-trace-nat.yml` for nat-lan trace runs.
if [ -n "${FIPS_NAT_EXTRA_COMPOSE:-}" ]; then
    IFS=':' read -ra _NAT_EXTRA <<< "${FIPS_NAT_EXTRA_COMPOSE}"
    for _f in "${_NAT_EXTRA[@]}"; do
        case "$_f" in
            /*) COMPOSE+=(-f "$_f") ;;
            *)  COMPOSE+=(-f "$ROOT_DIR/$_f") ;;
        esac
    done
fi

source "$WAIT_LIB"

cleanup() {
    "${COMPOSE[@]}" --profile cone --profile symmetric --profile lan \
        down -v --remove-orphans >/dev/null 2>&1 || true
}

helper_tcpdump_image() {
    docker inspect -f '{{.Config.Image}}' fips-nat-router-a${FIPS_CI_NAME_SUFFIX:-} 2>/dev/null || echo nat-nat-a
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
    local relay_host="${2:-${NAT_WAN}.30}"
    local relay_port="${3:-7777}"
    local stun_host="${4:-${NAT_WAN}.40}"
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
    local stun_host="${2:-${NAT_WAN}.40}"
    local stun_port="${3:-3478}"

    echo ""
    echo "--- $node: UDP sockets (pre-capture) ---"
    docker exec "$node" sh -lc 'ss -H -uanp 2>/dev/null || ss -H -uan 2>/dev/null || netstat -anu 2>/dev/null' 2>&1 || true
    echo ""
    echo "--- $node: UDP routes to STUN and peer WANs ---"
    # Double-quoted so THIS shell expands NAT_WAN; the loop variable is escaped
    # so the container's shell still expands that one. Left single-quoted, the
    # literal string ${NAT_WAN}.40 would reach `ip route get` and the probe
    # would stop probing without anything going red — these are diagnostic
    # paths, so the loss would only surface during a failure investigation.
    docker exec "$node" sh -lc "for ip in ${NAT_WAN}.40 ${NAT_WAN}.10 ${NAT_WAN}.11; do ip route get \"\$ip\"; done" 2>&1 || true

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
    local stun_host="${3:-${NAT_WAN}.40}"
    local stun_port="${4:-3478}"

    echo ""
    echo "--- $router: UDP conntrack/state (before probe) ---"
    docker exec "$router" sh -lc 'conntrack -L -p udp 2>/dev/null || echo "conntrack unavailable"' 2>&1 || true

    echo ""
    echo "--- $router: UDP counters (before probe) ---"
    docker exec "$router" sh -lc 'iptables -vnL FORWARD; echo; iptables -t nat -vnL POSTROUTING' 2>&1 || true
    echo ""
    echo "--- $router: UDP routes to STUN and peer WANs ---"
    # See the note in dump_node_udp_probe: outer shell expands NAT_WAN, inner
    # shell expands the loop variable.
    docker exec "$router" sh -lc "for ip in ${NAT_WAN}.40 ${NAT_WAN}.10 ${NAT_WAN}.11; do ip route get \"\$ip\"; done" 2>&1 || true

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
    local stun_host="${2:-${NAT_WAN}.40}"
    local stun_port="${3:-3478}"
    local helper_image
    helper_image="$(helper_tcpdump_image)"

    local capture_file
    capture_file="$(mktemp)"
    docker run --rm --label com.corganlabs.fips-ci=1 --label "com.corganlabs.fips-ci.run=${FIPS_CI_RUN_ID:-manual}" --net=container:fips-nat-stun${FIPS_CI_NAME_SUFFIX:-} --cap-add NET_ADMIN --cap-add NET_RAW \
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
    dump_fips_state fips-nat-cone-a${FIPS_CI_NAME_SUFFIX:-} ${NAT_WAN}.30 7777 ${NAT_WAN}.40 3478
    dump_node_udp_probe fips-nat-cone-a${FIPS_CI_NAME_SUFFIX:-}
    dump_fips_state fips-nat-cone-b${FIPS_CI_NAME_SUFFIX:-} ${NAT_WAN}.30 7777 ${NAT_WAN}.40 3478
    dump_node_udp_probe fips-nat-cone-b${FIPS_CI_NAME_SUFFIX:-}
    dump_container_state fips-nat-router-a${FIPS_CI_NAME_SUFFIX:-}
    dump_router_udp_probe fips-nat-router-a${FIPS_CI_NAME_SUFFIX:-} fips-nat-cone-a${FIPS_CI_NAME_SUFFIX:-}
    dump_container_state fips-nat-router-b${FIPS_CI_NAME_SUFFIX:-}
    dump_router_udp_probe fips-nat-router-b${FIPS_CI_NAME_SUFFIX:-} fips-nat-cone-b${FIPS_CI_NAME_SUFFIX:-}
    dump_container_state fips-nat-relay${FIPS_CI_NAME_SUFFIX:-}
    dump_stun_udp_probe fips-nat-cone-a${FIPS_CI_NAME_SUFFIX:-}
    dump_stun_udp_probe fips-nat-cone-b${FIPS_CI_NAME_SUFFIX:-}
    dump_container_state fips-nat-stun${FIPS_CI_NAME_SUFFIX:-}
}

dump_symmetric_diagnostics() {
    echo ""
    echo "=== symmetric diagnostics ==="
    dump_fips_state fips-nat-symmetric-a${FIPS_CI_NAME_SUFFIX:-} ${NAT_WAN}.30 7777 ${NAT_WAN}.40 3478
    dump_fips_state fips-nat-symmetric-b${FIPS_CI_NAME_SUFFIX:-} ${NAT_WAN}.30 7777 ${NAT_WAN}.40 3478
    dump_container_state fips-nat-router-a${FIPS_CI_NAME_SUFFIX:-}
    dump_container_state fips-nat-router-b${FIPS_CI_NAME_SUFFIX:-}
    dump_container_state fips-nat-relay${FIPS_CI_NAME_SUFFIX:-}
    dump_container_state fips-nat-stun${FIPS_CI_NAME_SUFFIX:-}
}

dump_lan_diagnostics() {
    echo ""
    echo "=== lan diagnostics ==="
    dump_fips_state fips-nat-lan-a${FIPS_CI_NAME_SUFFIX:-} ${NAT_LAN}.30 7777 ${NAT_LAN}.40 3478
    dump_fips_state fips-nat-lan-b${FIPS_CI_NAME_SUFFIX:-} ${NAT_LAN}.30 7777 ${NAT_LAN}.40 3478
    dump_container_state fips-nat-relay${FIPS_CI_NAME_SUFFIX:-}
    dump_container_state fips-nat-stun${FIPS_CI_NAME_SUFFIX:-}
}

trap 'echo ""; echo "NAT test interrupted"; cleanup; exit 130' INT TERM

require_test_image() {
    local img="${FIPS_TEST_IMAGE:-fips-test:latest}"
    if docker image inspect "$img" >/dev/null 2>&1; then
        return 0
    fi
    # Building here is right for a hand run and wrong under a harness. When
    # FIPS_TEST_IMAGE is set the caller has already built the image it named, so
    # a miss means something upstream is broken; building a substitute would
    # hide that and run binaries nobody asked for.
    if [ -n "${FIPS_TEST_IMAGE:-}" ]; then
        echo "ERROR: $img not present, and FIPS_TEST_IMAGE names the caller's own image" >&2
        echo "The harness that set it is expected to have built it." >&2
        exit 1
    fi
    echo "$img not found; building test image"
    "$BUILD_SCRIPT"
}

require_docker_daemon() {
    if ! docker info >/dev/null 2>&1; then
        echo "Docker daemon is not reachable; cannot run NAT lab harness" >&2
        exit 1
    fi
}

# The two path assertions below decide whether a converged mesh took the path
# the scenario expects. Every failure branch names the container, what was
# expected and what was read instead, and callers wrap them in the same
# `|| { dump_*_diagnostics; return 1; }` shape the convergence waits use, so the
# container state behind a mismatch is captured with it. Both stay silent on
# success: this suite passes most of the time.
assert_peer_path() {
    local container="$1"
    local expected_transport="$2"
    local expected_prefix="$3"
    local peers errfile rc=0
    # stdout and stderr are kept apart deliberately: any warning fipsctl writes
    # to stderr would otherwise be spliced into the JSON and turn a healthy read
    # into a parse failure.
    errfile="$(mktemp)"
    peers="$(docker exec "$container" fipsctl show peers 2>"$errfile")" || rc=$?
    if [ "$rc" != 0 ]; then
        echo "ASSERT FAIL: peer path $container: expected transport ${expected_transport} to a peer at ${expected_prefix}*, but 'fipsctl show peers' exited ${rc}:" >&2
        cat "$errfile" >&2
        rm -f "$errfile"
        return 1
    fi
    rm -f "$errfile"
    if ! python3 -c "
import json, sys
container, want_transport, want_prefix = sys.argv[1], sys.argv[2], sys.argv[3]
raw = sys.stdin.read()
want = f'transport {want_transport!r} to a peer at {want_prefix}*'
head = f'ASSERT FAIL: peer path {container}: expected {want}, '
try:
    data = json.loads(raw)
except ValueError as exc:
    raise SystemExit(head + f'but the peer JSON did not parse: {exc}; read: {raw!r}')
reported = data.get('peers', [])
seen = [
    {k: p.get(k) for k in
     ('npub', 'connectivity', 'transport_type', 'transport_addr', 'direction', 'last_seen_ms')}
    for p in reported
]
peers = [p for p in reported if p.get('connectivity') == 'connected']
if not peers:
    raise SystemExit(head + f'observed no connected peer; {len(reported)} peer(s) reported: {seen}')
peer = peers[0]
transport = peer.get('transport_type', '')
addr = peer.get('transport_addr', '')
if transport != want_transport:
    raise SystemExit(head + f'observed transport {transport!r} at {addr!r}; peers: {seen}')
if not addr.startswith(want_prefix):
    raise SystemExit(head + f'observed addr {addr!r} on transport {transport!r}; peers: {seen}')
" "$container" "$expected_transport" "$expected_prefix" <<<"$peers"; then
        return 1
    fi
}

assert_link_path() {
    local container="$1"
    local expected_prefix="$2"
    local links errfile rc=0
    # See assert_peer_path: stderr is kept out of the JSON on purpose.
    errfile="$(mktemp)"
    links="$(docker exec "$container" fipsctl show links 2>"$errfile")" || rc=$?
    if [ "$rc" != 0 ]; then
        echo "ASSERT FAIL: link path $container: expected a link to ${expected_prefix}*, but 'fipsctl show links' exited ${rc}:" >&2
        cat "$errfile" >&2
        rm -f "$errfile"
        return 1
    fi
    rm -f "$errfile"
    if ! python3 -c "
import json, sys
container, want_prefix = sys.argv[1], sys.argv[2]
raw = sys.stdin.read()
want = f'a link to {want_prefix}*'
head = f'ASSERT FAIL: link path {container}: expected {want}, '
try:
    data = json.loads(raw)
except ValueError as exc:
    raise SystemExit(head + f'but the link JSON did not parse: {exc}; read: {raw!r}')
links = data.get('links', [])
seen = [
    {k: link.get(k) for k in ('link_id', 'remote_addr', 'direction', 'state')}
    for link in links
]
if not links:
    raise SystemExit(head + 'observed no links at all')
addr = links[0].get('remote_addr', '')
if not addr.startswith(want_prefix):
    raise SystemExit(head + f'observed {addr!r}; links: {seen}')
" "$container" "$expected_prefix" <<<"$links"; then
        return 1
    fi
}

require_bootstrap_activity() {
    local container="$1"
    local logs
    logs="$(docker logs "$container" 2>&1 || true)"
    if ! grep -Eq "Started Nostr( UDP)? NAT traversal attempt" <<<"$logs"; then
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
    wait_for_peers fips-nat-cone-a${FIPS_CI_NAME_SUFFIX:-} 1 45 || {
        dump_cone_diagnostics
        return 1
    }
    wait_for_peers fips-nat-cone-b${FIPS_CI_NAME_SUFFIX:-} 1 45 || {
        dump_cone_diagnostics
        return 1
    }
    assert_peer_path fips-nat-cone-a${FIPS_CI_NAME_SUFFIX:-} udp ${NAT_WAN}. || {
        dump_cone_diagnostics
        return 1
    }
    assert_peer_path fips-nat-cone-b${FIPS_CI_NAME_SUFFIX:-} udp ${NAT_WAN}. || {
        dump_cone_diagnostics
        return 1
    }
    assert_link_path fips-nat-cone-a${FIPS_CI_NAME_SUFFIX:-} ${NAT_WAN}. || {
        dump_cone_diagnostics
        return 1
    }
    assert_link_path fips-nat-cone-b${FIPS_CI_NAME_SUFFIX:-} ${NAT_WAN}. || {
        dump_cone_diagnostics
        return 1
    }
    # shellcheck disable=SC1090
    source "$CONFIG_DIR/cone/npubs.env"
    ping_peer fips-nat-cone-a${FIPS_CI_NAME_SUFFIX:-} "$NPUB_B"
    ping_peer fips-nat-cone-b${FIPS_CI_NAME_SUFFIX:-} "$NPUB_A"
    cleanup
}

run_symmetric() {
    echo "=== NAT lab: symmetric fallback ==="
    cleanup
    NAT_MODE_A=symmetric NAT_MODE_B=symmetric "$GENERATE_SCRIPT" symmetric
    NAT_MODE_A=symmetric NAT_MODE_B=symmetric "${COMPOSE[@]}" --profile symmetric up -d --build --force-recreate
    "$TOPOLOGY_SCRIPT" symmetric
    wait_for_peers fips-nat-symmetric-a${FIPS_CI_NAME_SUFFIX:-} 1 60 || {
        dump_symmetric_diagnostics
        return 1
    }
    wait_for_peers fips-nat-symmetric-b${FIPS_CI_NAME_SUFFIX:-} 1 60 || {
        dump_symmetric_diagnostics
        return 1
    }
    assert_peer_path fips-nat-symmetric-a${FIPS_CI_NAME_SUFFIX:-} tcp ${NAT_WAN}.11: || {
        dump_symmetric_diagnostics
        return 1
    }
    assert_peer_path fips-nat-symmetric-b${FIPS_CI_NAME_SUFFIX:-} tcp ${NAT_WAN}.10: || {
        dump_symmetric_diagnostics
        return 1
    }
    assert_link_path fips-nat-symmetric-a${FIPS_CI_NAME_SUFFIX:-} ${NAT_WAN}.11: || {
        dump_symmetric_diagnostics
        return 1
    }
    assert_link_path fips-nat-symmetric-b${FIPS_CI_NAME_SUFFIX:-} ${NAT_WAN}.10: || {
        dump_symmetric_diagnostics
        return 1
    }
    require_bootstrap_activity fips-nat-symmetric-a${FIPS_CI_NAME_SUFFIX:-}
    require_bootstrap_activity fips-nat-symmetric-b${FIPS_CI_NAME_SUFFIX:-}
    # shellcheck disable=SC1090
    source "$CONFIG_DIR/symmetric/npubs.env"
    ping_peer fips-nat-symmetric-a${FIPS_CI_NAME_SUFFIX:-} "$NPUB_B"
    ping_peer fips-nat-symmetric-b${FIPS_CI_NAME_SUFFIX:-} "$NPUB_A"
    cleanup
}

run_lan() {
    echo "=== NAT lab: lan preference ==="
    cleanup
    "$GENERATE_SCRIPT" lan
    "${COMPOSE[@]}" --profile lan up -d --build --force-recreate
    wait_for_peers fips-nat-lan-a${FIPS_CI_NAME_SUFFIX:-} 1 45 || {
        dump_lan_diagnostics
        return 1
    }
    wait_for_peers fips-nat-lan-b${FIPS_CI_NAME_SUFFIX:-} 1 45 || {
        dump_lan_diagnostics
        return 1
    }
    assert_peer_path fips-nat-lan-a${FIPS_CI_NAME_SUFFIX:-} udp ${NAT_LAN}. || {
        dump_lan_diagnostics
        return 1
    }
    assert_peer_path fips-nat-lan-b${FIPS_CI_NAME_SUFFIX:-} udp ${NAT_LAN}. || {
        dump_lan_diagnostics
        return 1
    }
    assert_link_path fips-nat-lan-a${FIPS_CI_NAME_SUFFIX:-} ${NAT_LAN}. || {
        dump_lan_diagnostics
        return 1
    }
    assert_link_path fips-nat-lan-b${FIPS_CI_NAME_SUFFIX:-} ${NAT_LAN}. || {
        dump_lan_diagnostics
        return 1
    }
    # shellcheck disable=SC1090
    source "$CONFIG_DIR/lan/npubs.env"
    ping_peer fips-nat-lan-a${FIPS_CI_NAME_SUFFIX:-} "$NPUB_B"
    ping_peer fips-nat-lan-b${FIPS_CI_NAME_SUFFIX:-} "$NPUB_A"
    # Skip the final teardown when the mesh-lab harness wraps this
    # script: it needs to docker-logs the containers before teardown,
    # and will run its own cleanup after capture. Failure paths above
    # already leave containers up via the bare `return 1` so the
    # harness can capture stall-state evidence.
    if [ -z "${FIPS_NAT_SKIP_FINAL_CLEANUP:-}" ]; then
        cleanup
    fi
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
