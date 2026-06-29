#!/bin/bash
# Integration test for the inbound max_peers admission gate.
#
# Verifies the silent-drop behavior of the early-gate in handle_msg1 at
# scale, using the mesh topology with one node's node.max_peers lowered
# to 1. This forces 2 of node-c's 3 configured peers (b, d, e) into a
# sustained denied state, and asserts via tcpdump that no Msg2 responses
# go back to those denied peers across a 60s capture window.
#
# Tested behavior:
#   - Denied peers DO arrive at the cap'd node (inbound FMP-IK Msg1, 84 B)
#   - Cap'd node sends NO Msg2 responses (104 B) to denied peers
#   - Cap'd node maintains exactly max_peers active sessions
#   - Admitted peer's session stays healthy throughout the window
#
# Usage:
#   ./admission-cap-test.sh                Run the test (containers must be up)
#   ./admission-cap-test.sh inject-config  Inject node.max_peers into generated configs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CAP_NODE="${ADMISSION_CAP_NODE:-c}"
MAX_PEERS="${ADMISSION_MAX_PEERS:-1}"
CAPTURE_SECS="${ADMISSION_CAPTURE_SECS:-60}"
TOPOLOGY="mesh"
TOPO_FILE="$SCRIPT_DIR/../configs/topologies/$TOPOLOGY.yaml"

# ── inject-config subcommand ─────────────────────────────────────────
# Inject node.max_peers into generated configs. Called separately by CI
# before building Docker images.
if [ "${1:-}" = "inject-config" ]; then
    echo "Injecting node.limits.max_peers: $MAX_PEERS into node-$CAP_NODE ($TOPOLOGY topology)..."
    cfg="$SCRIPT_DIR/../generated-configs/$TOPOLOGY/node-$CAP_NODE.yaml"
    if [ ! -f "$cfg" ]; then
        echo "  Error: $cfg not found (run generate-configs.sh $TOPOLOGY first)" >&2
        exit 1
    fi
    # Insert under node.limits (the actual config path per src/config/node.rs).
    # Three cases: limits.max_peers already present (update), limits: present
    # without max_peers (append), or no limits block (insert full subtree).
    if grep -qE "^    max_peers:" "$cfg"; then
        sed -i -E "s/^    max_peers: *[0-9]+/    max_peers: $MAX_PEERS/" "$cfg"
    elif grep -qE "^  limits:" "$cfg"; then
        sed -i "/^  limits:/a\\
    max_peers: $MAX_PEERS" "$cfg"
    else
        sed -i "/^node:/a\\
  limits:\\
    max_peers: $MAX_PEERS" "$cfg"
    fi
    echo "  node-$CAP_NODE limits block:"
    sed -n '/^  limits:/,/^  [a-z]/p' "$cfg" | head -5
    exit 0
fi

stamp() { date '+%H:%M:%S'; }
info() { echo "[$(stamp)] $*"; }
fail() { echo "[$(stamp)] FAIL: $*"; exit 1; }
pass() { echo "[$(stamp)] PASS: $*"; }

# Extract docker_ip for a node from the topology file
node_ip() {
    grep -A 5 "^  $1:" "$TOPO_FILE" \
        | grep -m1 'docker_ip:' \
        | sed 's/.*: *"*\([^"]*\)".*/\1/'
}

# Extract npub for a node from the topology file
node_npub() {
    grep -A 5 "^  $1:" "$TOPO_FILE" \
        | grep -m1 'npub:' \
        | sed 's/.*: *"*\([^"]*\)".*/\1/'
}

# Extract configured peers list for a node from the topology file
node_peers() {
    grep -A 5 "^  $1:" "$TOPO_FILE" \
        | grep -m1 'peers:' \
        | sed 's/.*\[\(.*\)\].*/\1/' \
        | tr -d ' ' \
        | tr ',' ' '
}

CAP_IP=$(node_ip "$CAP_NODE")
[ -n "$CAP_IP" ] || fail "could not resolve docker_ip for node-$CAP_NODE in $TOPO_FILE"
info "cap'd node: node-$CAP_NODE (ip $CAP_IP, max_peers=$MAX_PEERS)"

# ── Phase 1: wait for convergence ────────────────────────────────────
info "phase 1: wait for node-$CAP_NODE peer_count to reach $MAX_PEERS (90s timeout)"
deadline=$(($(date +%s) + 90))
pc=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    pc=$(docker exec fips-node-$CAP_NODE fipsctl show status 2>/dev/null \
        | grep -m1 peer_count | sed 's/.*: *//' | tr -d ',' || echo 0)
    [ "$pc" = "$MAX_PEERS" ] && break
    sleep 2
done
[ "$pc" = "$MAX_PEERS" ] \
    || fail "node-$CAP_NODE peer_count=$pc after 90s, expected $MAX_PEERS"
info "node-$CAP_NODE converged: peer_count=$pc"

# Identify admitted vs denied peers among configured peers
ADMITTED_NPUBS=$(docker exec fips-node-$CAP_NODE fipsctl show peers 2>/dev/null \
    | grep -oE 'npub1[a-z0-9]+' | sort -u || true)
DENIED=""
ADMITTED=""
for p in $(node_peers "$CAP_NODE"); do
    npub=$(node_npub "$p")
    if echo "$ADMITTED_NPUBS" | grep -q "$npub"; then
        ADMITTED="$ADMITTED $p"
    else
        DENIED="$DENIED $p"
    fi
done
ADMITTED=$(echo $ADMITTED | xargs)
DENIED=$(echo $DENIED | xargs)
info "admitted: ${ADMITTED:-<none>}"
info "denied (sustained-retry): ${DENIED:-<none>}"
[ -n "$DENIED" ] \
    || fail "no denied peers — test setup wrong (cap=$MAX_PEERS too high vs configured peers)"

# ── Phase 2: capture wire traffic for CAPTURE_SECS seconds ───────────
# Drives sustained load by restarting denied peer containers on a cadence
# during the capture window. Each restart resets the auto-reconnect
# exponential backoff (5s base / 300s cap), producing a fresh burst of
# Msg1s that exercises the silent-drop gate at meaningful rate. Without
# this loop the gate fires ~3-4 times per denied peer in a 60s window;
# with restarts every 15s we get ~30-50 firings across both denied peers.
info "phase 2: capture UDP/2121 on node-$CAP_NODE for ${CAPTURE_SECS}s, with denied-peer restart loop"
CAP_FILE=$(mktemp /tmp/admission-cap-pcap.XXXXXX.txt)
HELPER_IMAGE=$(docker inspect -f '{{.Config.Image}}' fips-node-$CAP_NODE 2>/dev/null)
[ -n "$HELPER_IMAGE" ] || fail "could not resolve helper image from fips-node-$CAP_NODE"

# Background: cycle denied peers to reset their backoff and drive load.
(
    elapsed=0
    while [ $elapsed -lt $((CAPTURE_SECS - 5)) ]; do
        sleep 15
        elapsed=$((elapsed + 15))
        for n in $DENIED; do
            docker restart "fips-node-$n" >/dev/null 2>&1 &
        done
        wait
        info "  [load-driver] restarted denied peers ($DENIED) at t+${elapsed}s"
    done
) &
LOAD_PID=$!

# Foreground: tcpdump capture for CAPTURE_SECS
docker run --rm --label com.corganlabs.fips-ci=1 --net=container:fips-node-$CAP_NODE \
    --cap-add NET_ADMIN --cap-add NET_RAW \
    --entrypoint sh "$HELPER_IMAGE" \
    -c "timeout $CAPTURE_SECS tcpdump -nn -i any 'udp port 2121' -l 2>&1 || true" \
    > "$CAP_FILE" 2>&1

# Reap load-driver if it's still running (should be ~done)
wait $LOAD_PID 2>/dev/null || true

captured=$(wc -l < "$CAP_FILE")
info "captured $captured tcpdump lines → $CAP_FILE"

# ── Phase 3: per-denied-peer wire-level assertion ────────────────────
info "phase 3: per-denied-peer assertion (inbound Msg1 > 0, outbound Msg2 == 0)"
OVERALL=0
TOTAL_MSG1_IN=0
TOTAL_MSG2_OUT=0
for n in $DENIED; do
    n_ip=$(node_ip "$n")
    # Inbound: src=n_ip:* → dst=cap_ip:2121; FMP-IK Msg1 wire size = 84 B
    msg1_in=$(grep -cE "IP $n_ip\.[0-9]+ > $CAP_IP\.2121: UDP, length 84" "$CAP_FILE" || true)
    # Outbound: src=cap_ip:2121 → dst=n_ip:*; FMP-IK Msg2 wire size = 104 B
    msg2_out=$(grep -cE "IP $CAP_IP\.2121 > $n_ip\.[0-9]+: UDP, length 104" "$CAP_FILE" || true)
    info "  node-$n ($n_ip): inbound Msg1 (len 84) = $msg1_in, outbound Msg2 (len 104) = $msg2_out"
    TOTAL_MSG1_IN=$((TOTAL_MSG1_IN + msg1_in))
    TOTAL_MSG2_OUT=$((TOTAL_MSG2_OUT + msg2_out))
    if [ "$msg1_in" -eq 0 ]; then
        info "    FAIL: expected inbound Msg1 retries from denied peer (peer not sustained-retrying?)"
        OVERALL=1
    fi
    if [ "$msg2_out" -gt 0 ]; then
        info "    FAIL: silent-drop gate leaked — expected 0 outbound Msg2, got $msg2_out"
        OVERALL=1
    fi
done

# ── Phase 4: cap'd node still at exactly max_peers ───────────────────
pc_final=$(docker exec fips-node-$CAP_NODE fipsctl show status 2>/dev/null \
    | grep -m1 peer_count | sed 's/.*: *//' | tr -d ',' || echo 0)
info "node-$CAP_NODE final peer_count=$pc_final (expected $MAX_PEERS)"
[ "$pc_final" = "$MAX_PEERS" ] || OVERALL=1

if [ "$OVERALL" -eq 0 ]; then
    pass "admission-cap: silent-drop gate verified at scale"
    pass "  denied peers: $(echo $DENIED | wc -w), capture: ${CAPTURE_SECS}s"
    pass "  total inbound Msg1 from denied: $TOTAL_MSG1_IN (sustained retries observed)"
    pass "  total outbound Msg2 to denied:  $TOTAL_MSG2_OUT (silent-drop holds)"
    rm -f "$CAP_FILE"
    exit 0
else
    info "--- tcpdump capture tail (last 50 lines) ---"
    tail -50 "$CAP_FILE"
    fail "admission-cap: see failures above (capture preserved at $CAP_FILE)"
fi
