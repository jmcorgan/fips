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
#
# No phase moves the route until the move can mean something: node-a's
# connected socket to node-b is pinned to the path the phase starts from, and
# a ping has collected enough replies to show the data plane is carrying
# traffic. Both are waited for with a deadline rather than assumed after a
# fixed sleep, and each wait prints how long it took.
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
FAR="${MC_FAR_PREFIX:-172.31.62}"
ROUTER_OCTET=254

NODE_A="fips-mc-node-a${FIPS_CI_NAME_SUFFIX:-}"
NODE_B="fips-mc-node-b${FIPS_CI_NAME_SUFFIX:-}"

COMPOSE=(docker compose -f "$MC_DIR/docker-compose.yml")

# Extra compose overlays, colon-separated, appended in order. ci-local.sh sets
# this to docker-compose.external-net.yml so the lab attaches to the /24s it
# claimed rather than the base file's fixed pins; nothing else sets it, so the
# GitHub matrix and a bare `docker compose up` keep today's addresses. Applied
# to the whole COMPOSE array, so teardown matches bring-up — a `down` that
# omitted the overlay would not know the networks are external and would try to
# delete networks it does not own.
if [ -n "${MC_EXTRA_COMPOSE:-}" ]; then
    IFS=':' read -ra _MC_EXTRA <<< "${MC_EXTRA_COMPOSE}"
    for _f in "${_MC_EXTRA[@]}"; do
        case "$_f" in
            /*) COMPOSE+=(-f "$_f") ;;
            *)  COMPOSE+=(-f "$ROOT_DIR/$_f") ;;
        esac
    done
fi

# Ping cadence during a move. 5/s is fast enough to resolve a sub-second gap
# without the send loop itself becoming the thing under test.
PING_INTERVAL=0.2
# The move must cost less than this. Generous next to the ~82s the unpatched
# daemon took, and still far below the 30s liveness timeout, so a pass here
# cannot be the reaper doing the work.
MAX_GAP_SECS="${MC_MAX_GAP_SECS:-5}"
# How long the negative control must stay dark before the outage is believed.
CONTROL_DARK_SECS="${MC_CONTROL_DARK_SECS:-12}"
# Replies the ping must have collected before a move. A move only tests the
# data plane if the data plane was carrying traffic when it happened.
BASELINE_REPLIES=5
# How long to wait for them. The wait ends when they arrive, so this bounds a
# start that never comes; nothing is measured over it.
BASELINE_DEADLINE_SECS="${MC_BASELINE_DEADLINE_SECS:-15}"
# The fixed window the baseline used to be. A start slower than this is
# printed as a slow start, so a run that window would have failed is still
# visible in a green log rather than absorbed by the longer wait.
SLOW_START_SECS=3
# How long node-a's connected socket to node-b may take to appear on the path
# a phase starts from.
PIN_DEADLINE_SECS="${MC_PIN_DEADLINE_SECS:-15}"
# How many times Phase 3 runs. More than one is a diagnosis loop for the
# control's baseline; see the README.
CONTROL_RUNS="${MC_CONTROL_RUNS:-1}"
# Where every phase's ping log and both nodes' logs are kept, pass or fail.
# Unset, they go to a temporary directory that is printed from on failure and
# removed at exit.
KEEP_DIR="${MC_KEEP_DIR:-}"
LOG_DIR=""

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
    if [ -z "$KEEP_DIR" ] && [ -n "$LOG_DIR" ]; then
        rm -rf "$LOG_DIR"
    fi
}

trap 'echo ""; echo "medium-change interrupted"; cleanup; exit 130' INT TERM

ok()   { echo "  ✓ $1"; PASS=$((PASS + 1)); }
bad()  { echo "  ✗ $1"; FAIL=$((FAIL + 1)); }

now_ms() { date +%s%3N; }

# Seconds since a now_ms reading, to a tenth.
secs_since() {
    awk -v s="$1" -v n="$(now_ms)" 'BEGIN { printf "%.1f", (n - s) / 1000 }'
}

# Everything needed to read a failure after the containers are gone: the
# routes, the socket table the pin is read from, every phase's ping log (the
# order and timing of replies, which a count cannot show) and both nodes'
# whole logs.
dump_state() {
    echo ""
    echo "--- $NODE_A routes ---"
    docker exec "$NODE_A" ip -4 route 2>&1 | sed 's/^/  /' || true
    echo "--- $NODE_A UDP sockets (/proc/net/udp) ---"
    docker exec "$NODE_A" cat /proc/net/udp 2>&1 | sed 's/^/  /' || true
    local f
    for f in "$LOG_DIR"/*.ping.log; do
        [ -e "$f" ] || continue
        echo "--- ping log: $(basename "$f" .ping.log) ---"
        sed 's/^/  /' "$f"
    done
    local c
    for c in "$NODE_A" "$NODE_B"; do
        echo "--- $c: full log ---"
        docker logs "$c" 2>&1 | sed 's/^/  /' || true
    done
}

# Copy both nodes' logs into KEEP_DIR, when one was asked for.
keep_logs() {
    [ -n "$KEEP_DIR" ] || return 0
    local c
    for c in "$NODE_A" "$NODE_B"; do
        docker logs "$c" > "$KEEP_DIR/$c.log" 2>&1 || true
    done
    echo "Kept ping and node logs in $KEEP_DIR"
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

# The local addresses of node-a's connected UDP sockets to node-b, one per
# line, read from the kernel's socket table.
#
# This is the socket the suite is about: once a link is up, a tick-driven
# pass gives the peer its own socket connected to the peer's address, and
# connect(2) fixes its source address to whichever path the route pointed at
# then. A move made before that socket exists tests the wildcard socket
# instead, which follows the route by itself, so the netmon phases would pass
# without exercising detection and the control would see no outage.
pinned_sources() {
    docker exec "$NODE_A" cat /proc/net/udp 2>/dev/null \
        | python3 -c "
import socket, struct, sys

def addr(field):
    host, port = field.split(':')
    return '%s:%d' % (socket.inet_ntoa(struct.pack('=I', int(host, 16))), int(port, 16))

want = sys.argv[1]
for line in list(sys.stdin)[1:]:
    fields = line.split()
    try:
        local, remote = addr(fields[1]), addr(fields[2])
    except (IndexError, ValueError):
        continue
    if remote == want:
        print(local.rsplit(':', 1)[0])
" "${FAR}.20:2121" 2>/dev/null || true
}

# Wait until node-a's connected socket to node-b, and no other, is sourced
# from the given path. Prints how long that took.
wait_for_pin() {
    local label="$1" prefix="$2" start sources s pinned
    start="$(now_ms)"
    while :; do
        sources="$(pinned_sources)"
        pinned=1
        while read -r s; do
            case "$s" in
                "$prefix".*) ;;
                *) pinned=0 ;;
            esac
        done <<< "$sources"
        if [ "$pinned" -eq 1 ]; then
            echo "  node-a's socket to node-b is pinned to ${sources//$'\n'/, } after $(secs_since "$start")s"
            return 0
        fi
        if [ "$(( $(now_ms) - start ))" -ge "$(( PIN_DEADLINE_SECS * 1000 ))" ]; then
            bad "$label: node-a's socket to node-b was not pinned to ${prefix}.0/24 within ${PIN_DEADLINE_SECS}s (sources: ${sources:-none})"
            return 1
        fi
        sleep 0.2
    done
}

# Start a timestamped ping in the background inside node-a, writing to a file
# in the container. Returns immediately. The tag names the phase's copy of the
# log that ping_stop keeps.
ping_start() {
    local target="$1"
    PING_TAG="$2"
    docker exec "$NODE_A" sh -c "rm -f /tmp/mc-ping.log"
    PING_STARTED_MS="$(now_ms)"
    docker exec -d "$NODE_A" sh -c \
        "ping -D -i $PING_INTERVAL '$target' > /tmp/mc-ping.log 2>&1"
}

# Stop the ping, remember when, and keep a copy of its log. The stop time is
# what closes an outage that never ended — see ping_max_gap.
ping_stop() {
    docker exec "$NODE_A" sh -c "pkill -f 'ping -D' || true" >/dev/null 2>&1 || true
    PING_STOPPED_MS="$(now_ms)"
    docker exec "$NODE_A" cat /tmp/mc-ping.log \
        > "$LOG_DIR/${PING_TAG}.ping.log" 2>/dev/null || true
}

# Longest interval without a successful reply across and after the move, in
# seconds.
#
# Measured from `ping -D` timestamps rather than from the loss count, because
# loss alone cannot distinguish twenty scattered drops from one twenty-packet
# blackout — and only the second is the failure this suite is about.
#
# It starts at the last reply before the move (or the move itself, if there
# was none), so a gap before the move is not counted. The move is what is
# under test. Counting a slow or lossy start as well would let the control
# pass on an outage the move did not cause, and fail a netmon phase for one.
#
# The observation window's end counts as a boundary. Without it an outage that
# never recovers scores *zero*: `ping -D` writes a line only for a reply, so a
# permanent blackout simply stops producing lines and the largest interval
# between two surviving replies stays one ping apart. That reads as perfect
# continuity and passes — the exact failure this suite exists to catch. The
# containers share the host's clock, so the two timebases are comparable.
ping_max_gap() {
    local moved_ms="$1"
    docker exec "$NODE_A" cat /tmp/mc-ping.log 2>/dev/null \
        | python3 -c "
import re, sys
end = float(sys.argv[1]) / 1000
moved = float(sys.argv[2]) / 1000
stamps = []
for line in sys.stdin:
    m = re.match(r'\[(\d+\.\d+)\].*bytes from', line)
    if m:
        stamps.append(float(m.group(1)))
if not stamps:
    print('-1')
else:
    before = [s for s in stamps if s <= moved]
    window = [before[-1] if before else moved] + [s for s in stamps if s > moved]
    gaps = [b - a for a, b in zip(window, window[1:])]
    gaps.append(end - window[-1])
    print('%.2f' % max(gaps))
" "${PING_STOPPED_MS:-$(now_ms)}" "$moved_ms"
}

# Replies so far, always a single integer: 0 when the log is missing or the
# container does not answer.
ping_reply_count() {
    local n
    n="$(docker exec "$NODE_A" sh -c "grep -c 'bytes from' /tmp/mc-ping.log 2>/dev/null" 2>/dev/null)" || true
    case "$n" in
        ''|*[!0-9]*) n=0 ;;
    esac
    echo "$n"
}

# When the baseline's replies came, from the ping's own timestamps: the first
# reply, the last one the baseline needed, and that reply's sequence number,
# which shows how many requests went unanswered before it.
baseline_timing() {
    docker exec "$NODE_A" cat /tmp/mc-ping.log 2>/dev/null \
        | python3 -c "
import re, sys
start = float(sys.argv[1]) / 1000
n = int(sys.argv[2])
replies = []
for line in sys.stdin:
    m = re.match(r'\[(\d+\.\d+)\].*bytes from.*icmp_seq=(\d+)', line)
    if m:
        replies.append((float(m.group(1)) - start, int(m.group(2))))
if len(replies) >= n:
    print('%.2f %.2f %d' % (replies[0][0], replies[n - 1][0], replies[n - 1][1]))
" "$PING_STARTED_MS" "$BASELINE_REPLIES" 2>/dev/null || true
}

# Wait for the running ping to collect BASELINE_REPLIES replies, at most
# BASELINE_DEADLINE_SECS. Prints the count and how long it took either way.
wait_for_baseline() {
    local label="$1" count
    while :; do
        count="$(ping_reply_count)"
        if [ "$count" -ge "$BASELINE_REPLIES" ]; then
            break
        fi
        if [ "$(( $(now_ms) - PING_STARTED_MS ))" -ge "$(( BASELINE_DEADLINE_SECS * 1000 ))" ]; then
            bad "$label: traffic was not flowing before the move ($count replies in ${BASELINE_DEADLINE_SECS}s)"
            return 1
        fi
        sleep 0.2
    done

    local waited timing first nth seq
    waited="$(secs_since "$PING_STARTED_MS")"
    timing="$(baseline_timing)"
    if [ -z "$timing" ]; then
        echo "  baseline: $count replies after ${waited}s"
        return 0
    fi
    read -r first nth seq <<< "$timing"
    echo "  baseline: $count replies after ${waited}s (first reply at ${first}s, reply $BASELINE_REPLIES at ${nth}s, icmp_seq $seq)"
    if awk "BEGIN{exit !($nth > $SLOW_START_SECS)}"; then
        echo "  note: slow start, reply $BASELINE_REPLIES came ${nth}s after the ping started, past the ${SLOW_START_SECS}s window this baseline used to be"
    fi
}

# Bring a phase to where its move is measured from: node-a's socket to node-b
# pinned to the path the phase starts on, then a ping running with enough
# replies back to show the data plane carrying traffic.
start_traffic() {
    local label="$1" from_prefix="$2" tag="$3"
    wait_for_pin "$label" "$from_prefix" || return 1
    ping_start "${NPUB_B}.fips" "$tag"
    if ! wait_for_baseline "$label"; then
        ping_stop
        return 1
    fi
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
    local label="$1" from_prefix="$2" to_prefix="$3" expect_src="$4" tag="$5"

    echo ""
    echo "── $label ──"

    if ! wait_for_pin "$label" "$from_prefix"; then
        return
    fi

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

    ping_start "${NPUB_B}.fips" "$tag"
    if ! wait_for_baseline "$label"; then
        ping_stop
        return
    fi

    echo "  moving default route to ${to_prefix}.${ROUTER_OCTET} ..."
    local moved_ms
    moved_ms="$(now_ms)"
    move_default_route "$to_prefix"

    # Long enough for detection, the socket drop and the heartbeat to land,
    # and for the far side to re-pin — but well short of the liveness timeout,
    # so a pass cannot be the reaper's doing.
    sleep 10
    ping_stop

    local gap replies
    gap="$(ping_max_gap "$moved_ms")"
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
    local run="$1" tag="phase3"
    echo ""
    if [ "$CONTROL_RUNS" -gt 1 ]; then
        echo "── Phase 3: negative control (netmon disabled), run $run of $CONTROL_RUNS ──"
        tag="phase3-run$run"
    else
        echo "── Phase 3: negative control (netmon disabled) ──"
    fi

    "$GENERATE_SCRIPT" "$MESH_NAME" false >/dev/null
    "${COMPOSE[@]}" restart node-a >/dev/null 2>&1

    if ! wait_for_mesh; then
        bad "control: mesh did not re-form after restarting node-a with detection off"
        return
    fi
    # Start from the primary path again, whatever the previous phase left.
    move_default_route "$PRIMARY"
    if ! start_traffic "control" "$PRIMARY" "$tag"; then
        return
    fi

    echo "  moving default route to ${SECONDARY}.${ROUTER_OCTET} with detection off ..."
    local moved_ms
    moved_ms="$(now_ms)"
    move_default_route "$SECONDARY"
    sleep "$CONTROL_DARK_SECS"
    ping_stop

    local gap
    gap="$(ping_max_gap "$moved_ms")"
    echo "  traffic: longest gap ${gap}s from the move, over a ${CONTROL_DARK_SECS}s observation"

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

    case "$CONTROL_RUNS" in
        ''|*[!0-9]*|0)
            echo "ERROR: MC_CONTROL_RUNS must be a positive integer, got '$CONTROL_RUNS'" >&2
            exit 2
            ;;
    esac

    trap cleanup EXIT
    cleanup

    if [ -n "$KEEP_DIR" ]; then
        mkdir -p "$KEEP_DIR"
        LOG_DIR="$KEEP_DIR"
    else
        LOG_DIR="$(mktemp -d)"
    fi

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
        keep_logs
        echo ""
        echo "Result: $PASS passed, $FAIL failed"
        exit 1
    fi
    ok "mesh converged with node-a on the primary path"

    assert_move_survives "Phase 1: primary → secondary" "$PRIMARY" "$SECONDARY" "$SECONDARY" phase1
    assert_move_survives "Phase 2: secondary → primary" "$SECONDARY" "$PRIMARY" "$PRIMARY" phase2
    local run
    for ((run = 1; run <= CONTROL_RUNS; run++)); do
        assert_control_fails "$run"
    done

    echo ""
    echo "=============================================="
    echo " Result: $PASS passed, $FAIL failed"
    echo "=============================================="

    if [ "$FAIL" -ne 0 ]; then
        dump_state
        keep_logs
        exit 1
    fi
    keep_logs
}

main "$@"
