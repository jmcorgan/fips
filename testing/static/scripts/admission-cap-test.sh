#!/bin/bash
# Integration test for the inbound max_peers admission cap (Noise XX / next).
#
# Verifies the cap holds under sustained denied-peer load, using the mesh
# topology with one node's node.limits.max_peers lowered to 1. This forces
# 2 of node-c's 3 configured peers (b, d, e) into a sustained denied state.
#
# Unlike the IK version on maint/master — which gates at handle_msg1 before
# Msg2 and asserts "no Msg2 to denied peers" — on Noise XX the identity is
# not known until Msg3, so Msg1/Msg2/Msg3 all cross the wire before the cap
# can act. Moreover, because the cap'd node also dials its configured peers
# (auto_connect), denied peers match the early handle_msg3 gate's
# is_pending_outbound bypass and the cap is enforced by the late
# promote_connection check. The test therefore asserts a path-agnostic
# cap-holds invariant rather than a wire-size discriminator:
#
# Tested behavior:
#   - Denied peers keep re-initiating handshakes (sustained inbound UDP)
#   - No denied peer is ever promoted to an active session
#   - The daemon actively refuses over-cap promotions (enforcement events)
#   - Cap'd node maintains exactly max_peers active sessions
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

# ── Phase 3: per-denied-peer cap-holds assertion ─────────────────────
# Size-agnostic: the XX handshake message sizes differ from IK and may
# change, so we only need evidence that each denied peer keeps trying and
# is never promoted.
info "phase 3: per-denied-peer assertion (sustained inbound retries > 0, not promoted)"
OVERALL=0
TOTAL_IN=0
FINAL_PEERS=$(docker exec fips-node-$CAP_NODE fipsctl show peers 2>/dev/null \
    | grep -oE 'npub1[a-z0-9]+' | sort -u || true)
for n in $DENIED; do
    n_ip=$(node_ip "$n")
    n_npub=$(node_npub "$n")
    # Sustained retry: any inbound UDP from the denied peer to the cap'd
    # node, regardless of handshake message size.
    in_count=$(grep -cE "IP $n_ip\.[0-9]+ > $CAP_IP\.2121:" "$CAP_FILE" || true)
    promoted="no"
    if echo "$FINAL_PEERS" | grep -q "$n_npub"; then promoted="yes"; fi
    info "  node-$n ($n_ip): inbound packets = $in_count, promoted = $promoted"
    TOTAL_IN=$((TOTAL_IN + in_count))
    if [ "$in_count" -eq 0 ]; then
        info "    FAIL: no inbound from denied peer (peer not sustained-retrying?)"
        OVERALL=1
    fi
    if [ "$promoted" = "yes" ]; then
        info "    FAIL: denied peer was promoted to an active session — cap leaked"
        OVERALL=1
    fi
done

# ── Phase 4: cap'd node still at exactly max_peers ───────────────────
pc_final=$(docker exec fips-node-$CAP_NODE fipsctl show status 2>/dev/null \
    | grep -m1 peer_count | sed 's/.*: *//' | tr -d ',' || echo 0)
info "node-$CAP_NODE final peer_count=$pc_final (expected $MAX_PEERS)"
[ "$pc_final" = "$MAX_PEERS" ] || { info "    FAIL: peer_count drifted from cap"; OVERALL=1; }

# ── Phase 5: daemon actively refused over-cap promotions ─────────────
# Enforcement evidence. The inbound max_peers cap is enforced by the late
# promote_connection check, which logs "Rejecting inbound connection at
# max_peers cap" at debug (node-$CAP_NODE runs
# fips::node::handlers::handshake at debug in the mesh profile). In the
# mesh topology denied peers are also dialed by the cap'd node, so the
# cross-connection path handles them and the late check is the active
# enforcer.
clogs=$(docker logs fips-node-$CAP_NODE 2>&1 || true)
late_rejects=$(echo "$clogs" | grep -c "Rejecting inbound connection at max_peers cap" || true)
enforcement=$late_rejects
info "enforcement events on node-$CAP_NODE: late-check=$late_rejects (total $enforcement)"
[ "$enforcement" -gt 0 ] || { info "    FAIL: no cap-enforcement events observed in node-$CAP_NODE logs"; OVERALL=1; }

if [ "$OVERALL" -eq 0 ]; then
    pass "admission-cap: cap holds under sustained denied-peer load"
    pass "  denied peers: $(echo $DENIED | wc -w), capture: ${CAPTURE_SECS}s"
    pass "  total inbound from denied: $TOTAL_IN (sustained retries observed)"
    pass "  cap enforcement events: $enforcement (late-check $late_rejects)"
    pass "  cap'd node held peer_count=$pc_final (max=$MAX_PEERS)"
    rm -f "$CAP_FILE"
    exit 0
else
    info "--- tcpdump capture tail (last 50 lines) ---"
    tail -50 "$CAP_FILE"
    info "--- node-$CAP_NODE log tail (last 30 lines) ---"
    echo "$clogs" | tail -30
    fail "admission-cap: see failures above (capture preserved at $CAP_FILE)"
fi
