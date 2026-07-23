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
    cfg="$SCRIPT_DIR/../generated-configs${FIPS_CI_NAME_SUFFIX:-}/$TOPOLOGY/node-$CAP_NODE.yaml"
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

# A node's docker address, read from the running container.
#
# NOT from the topology file's docker_ip: fips-net requests no subnet, so that
# two concurrent CI runs cannot collide on one fixed range, and docker assigns
# the addresses at `up`. A topology literal would no longer match anything on
# the wire, and the phase-3 tcpdump assertions are built from these addresses
# — a stale one turns "no Msg2 leaked" into a check that cannot fail.
# Takes the first attachment only: these nodes have one, and concatenating two
# would yield a string that is not an address at all. The `|| true` keeps a
# missing container from killing the script under `set -e` before the caller
# can say which container it was.
node_ip() {
    docker inspect \
        -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' \
        "fips-node-${1}${FIPS_CI_NAME_SUFFIX:-}" 2>/dev/null \
        | awk '{print $1}' || true
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
[ -n "$CAP_IP" ] || fail "could not read the docker address of container fips-node-${CAP_NODE}${FIPS_CI_NAME_SUFFIX:-}"
info "cap'd node: node-$CAP_NODE (ip $CAP_IP, max_peers=$MAX_PEERS)"

# Read the cap'd node's peer_count, or the empty string if it did not answer.
#
# Empty is deliberately distinct from a real 0. An `|| echo 0` fallback cannot
# do that job here: `||` binds to the last stage of the pipeline, which succeeds
# on empty input, so the fallback never fires and an unreachable container would
# be reported as a legitimate zero.
read_peer_count() {
    docker exec "fips-node-${CAP_NODE}${FIPS_CI_NAME_SUFFIX:-}" fipsctl show status 2>/dev/null \
        | grep -m1 peer_count | sed 's/.*: *//' | tr -d ','
}

# ── Phase 1: wait for convergence ────────────────────────────────────
info "phase 1: wait for node-$CAP_NODE peer_count to reach $MAX_PEERS (90s timeout)"
deadline=$(($(date +%s) + 90))
pc=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    pc=$(read_peer_count)
    [ "$pc" = "$MAX_PEERS" ] && break
    sleep 2
done
[ "$pc" = "$MAX_PEERS" ] \
    || fail "node-$CAP_NODE peer_count=$pc after 90s, expected $MAX_PEERS"
info "node-$CAP_NODE converged: peer_count=$pc"

# Identify admitted vs denied peers among configured peers
ADMITTED_NPUBS=$(docker exec "fips-node-${CAP_NODE}${FIPS_CI_NAME_SUFFIX:-}" fipsctl show peers 2>/dev/null \
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

# Every address a denied peer holds during the capture, one "node ip" line per
# observation.
#
# It is not one address per node. `fips-net` requests no subnet so that
# concurrent CI runs cannot collide on one, and the load driver below restarts
# these containers repeatedly — docker frees the address on stop and may hand
# back a different one, which was impossible while the compose pinned
# ipv4_address. Observed live: node-d went 10.128.2.4 → 10.128.2.6 mid-window.
# Phase 3 matches against the union, because an address that held for only part
# of the window under-counts Msg1 and, worse, satisfies the expect-zero Msg2
# assertion for the wrong reason.
ADDR_FILE=$(mktemp /tmp/admission-cap-addrs.XXXXXX)
record_denied_addrs() {
    local n n_ip
    for n in $DENIED; do
        n_ip=$(node_ip "$n")
        [ -n "$n_ip" ] || continue
        grep -qxF "$n $n_ip" "$ADDR_FILE" 2>/dev/null || echo "$n $n_ip" >> "$ADDR_FILE"
    done
}
record_denied_addrs
for n in $DENIED; do
    grep -q "^$n " "$ADDR_FILE" \
        || fail "could not read the docker address of denied peer node-$n"
done

# ── Phase 2: capture wire traffic for CAPTURE_SECS seconds ───────────
# Drives sustained load by restarting denied peer containers on a cadence
# during the capture window. Each restart resets the auto-reconnect
# exponential backoff (5s base / 300s cap), producing a fresh burst of
# Msg1s that exercises the silent-drop gate at meaningful rate. Without
# this loop the gate fires ~3-4 times per denied peer in a 60s window;
# with restarts every 15s we get ~30-50 firings across both denied peers.
info "phase 2: capture UDP/2121 on node-$CAP_NODE for ${CAPTURE_SECS}s, with denied-peer restart loop"
CAP_FILE=$(mktemp /tmp/admission-cap-pcap.XXXXXX.txt)
HELPER_IMAGE=$(docker inspect -f '{{.Config.Image}}' "fips-node-${CAP_NODE}${FIPS_CI_NAME_SUFFIX:-}" 2>/dev/null)
[ -n "$HELPER_IMAGE" ] || fail "could not resolve helper image from fips-node-${CAP_NODE}${FIPS_CI_NAME_SUFFIX:-}"

# Background: cycle denied peers to reset their backoff and drive load.
(
    elapsed=0
    while [ $elapsed -lt $((CAPTURE_SECS - 5)) ]; do
        sleep 15
        elapsed=$((elapsed + 15))
        # ONE AT A TIME, deliberately. Restarting them together frees both
        # addresses at once and docker reallocates in completion order, so the
        # two peers SWAP — observed live, and it destroys per-peer attribution
        # because both then match the same address set. Restarted singly, a
        # container frees its address and immediately reclaims it as the
        # lowest free one, so each keeps its own.
        for n in $DENIED; do
            docker restart "fips-node-${n}${FIPS_CI_NAME_SUFFIX:-}" >/dev/null 2>&1 || true
        done
        # Belt and braces: a restart may still move an address, so re-read
        # rather than assuming the pre-capture snapshot still holds.
        record_denied_addrs
        info "  [load-driver] restarted denied peers ($DENIED) at t+${elapsed}s"
    done
) &
LOAD_PID=$!

# Foreground: tcpdump capture for CAPTURE_SECS
docker run --rm --label com.corganlabs.fips-ci=1 --label "com.corganlabs.fips-ci.run=${FIPS_CI_RUN_ID:-manual}" --net=container:"fips-node-${CAP_NODE}${FIPS_CI_NAME_SUFFIX:-}" \
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
# One last observation: the final restart round may have moved an address after
# the driver's own record.
record_denied_addrs

# The cap'd node is never restarted, so its address must not have moved. If it
# did, every pattern below covers only part of the window and the counts mean
# nothing — that is a harness failure, not a cap regression.
cap_ip_now=$(node_ip "$CAP_NODE")
[ "$cap_ip_now" = "$CAP_IP" ] \
    || fail "cap'd node address moved during the capture ($CAP_IP → ${cap_ip_now:-<unreadable>}) though it was never restarted"
cap_re=$(printf '%s' "$CAP_IP" | sed 's/\./\\./g')

# Two denied peers must never have held the same address, or the per-peer
# counts below are not per-peer: each would match the other's traffic and the
# "this peer is sustained-retrying" assertion could be satisfied entirely by
# its neighbour. Serialized restarts above are what prevent it; this is the
# check that says so out loud if they ever stop working.
dup=$(awk '{ if (seen[$2] != "" && seen[$2] != $1) print $2; seen[$2] = $1 }' "$ADDR_FILE" | sort -u)
[ -z "$dup" ] \
    || fail "denied peers shared an address during the capture ($(echo "$dup" | paste -sd, -)); per-peer attribution is not possible"

for n in $DENIED; do
    # Match every address this peer held during the window, not just its last:
    # a restart can move it, and grepping for one of several under-counts Msg1
    # and leaves the expect-zero Msg2 assertion unable to see a leak sent to
    # the addresses it no longer holds.
    n_re=$(awk -v n="$n" '$1 == n { gsub(/\./, "\\.", $2); printf "%s%s", (c++ ? "|" : ""), $2 }' "$ADDR_FILE")
    [ -n "$n_re" ] \
        || fail "no docker address was ever recorded for denied peer node-$n"
    n_seen=$(awk -v n="$n" '$1 == n {print $2}' "$ADDR_FILE" | paste -sd, -)
    # Inbound: src=n_ip:* → dst=cap_ip:2121; FMP-IK Msg1 wire size = 84 B
    msg1_in=$(grep -cE "IP ($n_re)\.[0-9]+ > $cap_re\.2121: UDP, length 84" "$CAP_FILE" || true)
    # Outbound: src=cap_ip:2121 → dst=n_ip:*; FMP-IK Msg2 wire size = 104 B
    msg2_out=$(grep -cE "IP $cap_re\.2121 > ($n_re)\.[0-9]+: UDP, length 104" "$CAP_FILE" || true)
    info "  node-$n ($n_seen): inbound Msg1 (len 84) = $msg1_in, outbound Msg2 (len 104) = $msg2_out"
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
#
# Polled rather than sampled once. The load driver above restarts the denied
# peers every 15s and its final restart lands in the same second this runs, so a
# single read can hit a daemon busy with those restarts and come back empty --
# which is a harness race, not a cap regression. Retry briefly before believing
# the answer. A genuine regression still fails, just after the retry window,
# because the loop exits early only on the expected value.
pc_final=""
deadline=$(($(date +%s) + 30))
while [ "$(date +%s)" -lt "$deadline" ]; do
    pc_final=$(read_peer_count)
    [ "$pc_final" = "$MAX_PEERS" ] && break
    sleep 2
done
info "node-$CAP_NODE final peer_count=${pc_final:-<no answer>} (expected $MAX_PEERS)"
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
