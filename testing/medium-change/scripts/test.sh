#!/bin/bash
# Transport-medium change suite.
#
# Moves node-a's default route between two live access paths while mesh
# traffic is in flight, and asserts the peering survives it intact.
#
# What makes the assertions meaningful rather than "the mesh still works":
#
#   link_id / authenticated_at_ms  unchanged  → no re-handshake happened
#   node-b's transport_addr        changed    → the far side re-pinned
#   ping gap                       bounded    → the data plane really carried
#
# The first two are what separate "the fix worked" from "the liveness reaper
# tore it down and a re-dial rebuilt it", which look identical if you only
# check that traffic eventually returns.
#
# Phase 3 runs the same move with detection disabled and requires the outage,
# so the suite demonstrates the regression rather than asserting it from a
# changelog entry.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$MC_DIR/../.." && pwd)"
BUILD_SCRIPT="$ROOT_DIR/testing/scripts/build.sh"
GENERATE_SCRIPT="$SCRIPT_DIR/generate-configs.sh"
WAIT_LIB="$ROOT_DIR/testing/lib/wait-converge.sh"
CONFIG_DIR="$MC_DIR/generated-configs${FIPS_CI_NAME_SUFFIX:-}"

PRIMARY="${MC_PRIMARY_PREFIX:-172.31.60}"
SECONDARY="${MC_SECONDARY_PREFIX:-172.31.61}"
ROUTER_OCTET=254

NODE_A="fips-mc-node-a${FIPS_CI_NAME_SUFFIX:-}"
NODE_B="fips-mc-node-b${FIPS_CI_NAME_SUFFIX:-}"

COMPOSE=(docker compose -f "$MC_DIR/docker-compose.yml")

# Ping cadence during a move. 5/s is fast enough to resolve a sub-second gap
# without the send loop itself becoming the thing under test.
PING_INTERVAL=0.2
# The move must cost less than this. Generous next to the ~82s the unpatched
# daemon took, and still far below the 30s liveness timeout, so a pass here
# cannot be the reaper doing the work.
MAX_GAP_SECS="${MC_MAX_GAP_SECS:-5}"
# How long the negative control must stay dark before the outage is believed.
CONTROL_DARK_SECS="${MC_CONTROL_DARK_SECS:-12}"

source "$WAIT_LIB"

PASS=0
FAIL=0

# Build the test image only when nobody has handed us one.
#
# Building here is right for a hand run and wrong under a harness: when
# FIPS_TEST_IMAGE is set the caller has already built the image it named, so a
# miss means something upstream is broken and building a substitute would hide
# that behind a green run of binaries nobody asked for.
require_test_image() {
    local img="${FIPS_TEST_IMAGE:-fips-test:latest}"
    if docker image inspect "$img" >/dev/null 2>&1; then
        echo "Using test image $img"
        return 0
    fi
    if [ -n "${FIPS_TEST_IMAGE:-}" ]; then
        echo "ERROR: $img not present, and FIPS_TEST_IMAGE names the caller's own image" >&2
        echo "The harness that set it is expected to have built it." >&2
        exit 1
    fi
    echo "$img not found; building test image"
    "$BUILD_SCRIPT"
}


cleanup() {
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}

trap 'echo ""; echo "medium-change interrupted"; cleanup; exit 130' INT TERM

ok()   { echo "  ✓ $1"; PASS=$((PASS + 1)); }
bad()  { echo "  ✗ $1"; FAIL=$((FAIL + 1)); }

dump_state() {
    echo ""
    echo "--- $NODE_A routes ---"
    docker exec "$NODE_A" ip -4 route 2>&1 | sed 's/^/  /' || true
    for c in "$NODE_A" "$NODE_B"; do
        echo "--- $c: last 60 log lines ---"
        docker logs "$c" 2>&1 | tail -60 | sed 's/^/  /' || true
    done
}

# One field out of `fipsctl show peers`, for the single peer that is present.
# Prints nothing when the container does not answer, which every caller
# treats as a failed read rather than as a value.
peer_field() {
    local container="$1" field="$2"
    docker exec "$container" fipsctl show peers 2>/dev/null \
        | python3 -c "
import sys, json
try:
    peers = json.load(sys.stdin).get('peers', [])
except Exception:
    sys.exit(0)
if peers:
    v = peers[0].get('$field')
    if v is not None:
        print(v)
" 2>/dev/null || true
}

# Move node-a's default route to the named path, leaving both interfaces up.
#
# Interfaces are resolved by subnet for the same reason the entrypoint does
# it: docker's eth0/eth1 ordering is not the compose ordering.
move_default_route() {
    local prefix="$1"
    docker exec "$NODE_A" sh -c "
        set -e
        dev=\$(ip -4 -oneline addr show | awk -v p='${prefix}.' '\$4 ~ \"^\"p {print \$2; exit}')
        test -n \"\$dev\"
        ip route replace default via ${prefix}.${ROUTER_OCTET} dev \$dev
    "
}

# Start a timestamped ping in the background inside node-a, writing to a file
# in the container. Returns immediately.
ping_start() {
    local target="$1"
    docker exec "$NODE_A" sh -c "rm -f /tmp/mc-ping.log"
    docker exec -d "$NODE_A" sh -c \
        "ping -D -i $PING_INTERVAL '$target' > /tmp/mc-ping.log 2>&1"
}

# Stop the ping and remember when. The stop time is what closes an outage
# that never ended — see ping_max_gap.
ping_stop() {
    docker exec "$NODE_A" sh -c "pkill -f 'ping -D' || true" >/dev/null 2>&1 || true
    PING_STOPPED_AT="$(date +%s.%N)"
}

# Longest interval without a successful reply, in seconds.
#
# Measured from `ping -D` timestamps rather than from the loss count, because
# loss alone cannot distinguish twenty scattered drops from one twenty-packet
# blackout — and only the second is the failure this suite is about.
#
# The observation window's end counts as a boundary. Without it an outage that
# never recovers scores *zero*: `ping -D` writes a line only for a reply, so a
# permanent blackout simply stops producing lines and the largest interval
# between two surviving replies stays one ping apart. That reads as perfect
# continuity and passes — the exact failure this suite exists to catch. The
# containers share the host's clock, so the two timebases are comparable.
ping_max_gap() {
    docker exec "$NODE_A" cat /tmp/mc-ping.log 2>/dev/null \
        | python3 -c "
import re, sys
end = float(sys.argv[1])
stamps = []
for line in sys.stdin:
    m = re.match(r'\[(\d+\.\d+)\].*bytes from', line)
    if m:
        stamps.append(float(m.group(1)))
if not stamps:
    print('-1')
else:
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    gaps.append(end - stamps[-1])
    print('%.2f' % max(gaps))
" "${PING_STOPPED_AT:-$(date +%s.%N)}"
}

ping_reply_count() {
    docker exec "$NODE_A" sh -c "grep -c 'bytes from' /tmp/mc-ping.log 2>/dev/null || echo 0"
}

wait_for_mesh() {
    wait_for_peers "$NODE_A" 1 60 || return 1
    wait_for_peers "$NODE_B" 1 60 || return 1
}

# ── One move, fully asserted ────────────────────────────────────────────────
#
# Records the peering identity on both sides, moves the route under live
# traffic, and checks continuity against what was recorded.
assert_move_survives() {
    local label="$1" to_prefix="$2" expect_src="$3"

    echo ""
    echo "── $label ──"

    local link_before auth_before addr_before
    link_before="$(peer_field "$NODE_A" link_id)"
    auth_before="$(peer_field "$NODE_A" authenticated_at_ms)"
    addr_before="$(peer_field "$NODE_B" transport_addr)"

    if [ -z "$link_before" ] || [ -z "$auth_before" ]; then
        bad "$label: could not read the peering before the move"
        return
    fi
    echo "  before: link_id=$link_before authenticated_at_ms=$auth_before"
    echo "  before: node-b sees node-a at $addr_before"

    ping_start "${NPUB_B}.fips"
    sleep 3

    local baseline
    baseline="$(ping_reply_count)"
    if [ "$baseline" -lt 5 ]; then
        bad "$label: traffic was not flowing before the move ($baseline replies)"
        ping_stop
        return
    fi

    echo "  moving default route to ${to_prefix}.${ROUTER_OCTET} ..."
    move_default_route "$to_prefix"

    # Long enough for detection, the socket drop and the heartbeat to land,
    # and for the far side to re-pin — but well short of the liveness timeout,
    # so a pass cannot be the reaper's doing.
    sleep 10
    ping_stop

    local gap replies
    gap="$(ping_max_gap)"
    replies="$(ping_reply_count)"

    local link_after auth_after addr_after
    link_after="$(peer_field "$NODE_A" link_id)"
    auth_after="$(peer_field "$NODE_A" authenticated_at_ms)"
    addr_after="$(peer_field "$NODE_B" transport_addr)"

    echo "  after:  link_id=$link_after authenticated_at_ms=$auth_after"
    echo "  after:  node-b sees node-a at $addr_after"
    echo "  traffic: $replies replies, longest gap ${gap}s"

    # 1. The data plane carried through the move.
    if [ "$gap" = "-1" ]; then
        bad "$label: no replies at all — the mesh never carried traffic"
    elif awk "BEGIN{exit !($gap <= $MAX_GAP_SECS)}"; then
        ok "$label: traffic continuous, longest gap ${gap}s (limit ${MAX_GAP_SECS}s)"
    else
        bad "$label: ${gap}s outage exceeds the ${MAX_GAP_SECS}s limit"
    fi

    # 2. No re-handshake. This is the assertion that distinguishes the fix
    #    from a reconnect that merely happened fast enough.
    if [ "$link_after" = "$link_before" ] && [ "$auth_after" = "$auth_before" ]; then
        ok "$label: peering survived intact (same link_id, same authenticated_at_ms)"
    else
        bad "$label: peering was rebuilt — link_id $link_before→$link_after, authenticated_at_ms $auth_before→$auth_after"
    fi

    # 3. The far side actually re-pinned to the new source address. Without
    #    this the first two could pass on a topology where nothing moved.
    if [ "$addr_after" = "${expect_src}.10:2121" ]; then
        ok "$label: node-b re-pinned to ${expect_src}.10:2121"
    else
        bad "$label: node-b still sees node-a at ${addr_after:-<none>}, expected ${expect_src}.10:2121"
    fi
}

# ── Negative control ────────────────────────────────────────────────────────
#
# The same move with detection off. The point is not to characterise the bug
# precisely, only to prove this suite can see it: if traffic survives here,
# the topology is not exercising the code path and every pass above is
# vacuous.
assert_control_fails() {
    echo ""
    echo "── Phase 3: negative control (netmon disabled) ──"

    "$GENERATE_SCRIPT" "$MESH_NAME" false >/dev/null
    "${COMPOSE[@]}" restart node-a >/dev/null 2>&1

    if ! wait_for_mesh; then
        bad "control: mesh did not re-form after restarting node-a with detection off"
        return
    fi
    # Start from the primary path again, whatever the previous phase left.
    move_default_route "$PRIMARY"
    sleep 5

    ping_start "${NPUB_B}.fips"
    sleep 3
    local baseline
    baseline="$(ping_reply_count)"
    if [ "$baseline" -lt 5 ]; then
        bad "control: traffic was not flowing before the move ($baseline replies)"
        ping_stop
        return
    fi

    echo "  moving default route to ${SECONDARY}.${ROUTER_OCTET} with detection off ..."
    move_default_route "$SECONDARY"
    sleep "$CONTROL_DARK_SECS"
    ping_stop

    local gap
    gap="$(ping_max_gap)"
    echo "  traffic: longest gap ${gap}s over a ${CONTROL_DARK_SECS}s observation"

    if [ "$gap" = "-1" ]; then
        bad "control: no replies at all, so nothing was demonstrated"
    elif awk "BEGIN{exit !($gap > $MAX_GAP_SECS)}"; then
        ok "control: the move black-holed traffic for ${gap}s with detection off — the suite can see the regression"
    else
        bad "control: traffic survived a ${gap}s gap without detection; this topology does not exercise the bug, so the passes above prove nothing"
    fi
}

main() {
    echo "=============================================="
    echo " FIPS transport-medium change suite"
    echo "=============================================="

    trap cleanup EXIT
    cleanup

    MESH_NAME="medium-change-$(date +%s)-$$"

    echo ""
    require_test_image

    echo "Generating configs ..."
    "$GENERATE_SCRIPT" "$MESH_NAME" true
    # shellcheck disable=SC1090
    source "$CONFIG_DIR/npubs.env"

    echo "Starting topology ..."
    "${COMPOSE[@]}" up -d

    if ! wait_for_mesh; then
        bad "mesh never converged"
        dump_state
        echo ""
        echo "Result: $PASS passed, $FAIL failed"
        exit 1
    fi
    ok "mesh converged with node-a on the primary path"

    assert_move_survives "Phase 1: primary → secondary" "$SECONDARY" "$SECONDARY"
    sleep 5
    assert_move_survives "Phase 2: secondary → primary" "$PRIMARY" "$PRIMARY"
    assert_control_fails

    echo ""
    echo "=============================================="
    echo " Result: $PASS passed, $FAIL failed"
    echo "=============================================="

    if [ "$FAIL" -ne 0 ]; then
        dump_state
        exit 1
    fi
}

main "$@"
