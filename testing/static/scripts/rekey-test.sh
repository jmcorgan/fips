#!/bin/bash
# Integration test for Noise rekey (periodic key rotation).
#
# Verifies that FMP link rekey and FSP session rekey complete without
# disrupting connectivity. Uses aggressive rekey timers (35s) so that
# multiple rekey cycles complete within CI time budgets.
#
# Tested failure modes:
#   - Cross-connection msg1 misidentified as rekey (session age guard)
#   - K-bit cutover and drain window (old session cleanup)
#   - FMP + FSP coordinated rekeying
#   - Multi-hop session survival across rekey
#   - Back-to-back rekey cycles (consecutive rekeys)
#   - Link stability through rekey (no spurious link teardowns)
#
# Usage:
#   ./rekey-test.sh                 Run the full test (containers must be up)
#   ./rekey-test.sh inject-config   Inject rekey config into generated configs
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../lib/wait-converge.sh"
# Selectable topology — defaults to "rekey" but the rekey-accept-off
# variant exercises the auto_connect-initiator-with-accept-off
# regression class (udp.accept_connections=false on a peer that
# also auto-connects).
TOPOLOGY="${REKEY_TOPOLOGY:-rekey}"
NODES="a b c d e"
# Comma-separated list of node IDs to set udp.accept_connections=false
# on during inject-config. Empty (default) leaves all nodes accepting.
# When set, also asserted by the test that no sustained "Dual rekey
# initiation" log lines appear on the affected node.
REKEY_ACCEPT_OFF_NODES="${REKEY_ACCEPT_OFF_NODES:-}"

# Comma-separated list of node IDs to set udp.outbound_only=true on
# during inject-config. For each such node, peer addresses are also
# rewritten from numeric docker IPs to docker hostnames (e.g.
# 172.20.0.12:2121 → node-c:2121). This reproduces the production
# scenario where peer configs carry hostnames so the `addr_to_link`
# key is hostname-form while inbound packet source addrs are numeric,
# making the should_admit_msg1 carve-out's `addr_to_link.contains_key`
# check miss.
REKEY_OUTBOUND_ONLY_NODES="${REKEY_OUTBOUND_ONLY_NODES:-}"

# Rekey timing configuration
REKEY_AFTER_SECS=35

# ── inject-config subcommand ──────────────────────────────────────────
# Inject rekey config into generated node configs. Called separately
# by CI before building Docker images.
if [ "${1:-}" = "inject-config" ]; then
    echo "Injecting rekey config (after_secs=$REKEY_AFTER_SECS) into node configs (topology=$TOPOLOGY)..."
    if [ -n "$REKEY_ACCEPT_OFF_NODES" ]; then
        echo "  Setting udp.accept_connections=false on nodes: $REKEY_ACCEPT_OFF_NODES"
    fi
    if [ -n "$REKEY_OUTBOUND_ONLY_NODES" ]; then
        echo "  Setting udp.outbound_only=true + rewriting peer addrs to docker hostnames on nodes: $REKEY_OUTBOUND_ONLY_NODES"
    fi
    for node in $NODES; do
        cfg="$SCRIPT_DIR/../generated-configs/$TOPOLOGY/node-$node.yaml"
        if [ ! -f "$cfg" ]; then
            echo "  Error: $cfg not found" >&2
            exit 1
        fi
        accept_off="false"
        if [ -n "$REKEY_ACCEPT_OFF_NODES" ]; then
            for off_node in ${REKEY_ACCEPT_OFF_NODES//,/ }; do
                if [ "$off_node" = "$node" ]; then
                    accept_off="true"
                fi
            done
        fi
        outbound_only="false"
        if [ -n "$REKEY_OUTBOUND_ONLY_NODES" ]; then
            for oo_node in ${REKEY_OUTBOUND_ONLY_NODES//,/ }; do
                if [ "$oo_node" = "$node" ]; then
                    outbound_only="true"
                fi
            done
        fi
        python3 -c "
import yaml
with open('$cfg') as f:
    cfg = yaml.safe_load(f)
cfg.setdefault('node', {})['rekey'] = {
    'enabled': True,
    'after_secs': $REKEY_AFTER_SECS,
    'after_messages': 65536,
}
if '$accept_off' == 'true':
    transports = cfg.setdefault('transports', {})
    udp = transports.get('udp')
    if udp is None:
        udp = {'bind_addr': '0.0.0.0:2121'}
        transports['udp'] = udp
    if isinstance(udp, dict):
        udp['accept_connections'] = False
if '$outbound_only' == 'true':
    transports = cfg.setdefault('transports', {})
    udp = transports.get('udp')
    if udp is None:
        udp = {}
        transports['udp'] = udp
    if isinstance(udp, dict):
        udp['outbound_only'] = True
    # Rewrite peer addrs to docker hostnames so the addr_to_link key
    # is hostname-form (mirroring production peer configs that carry
    # hostnames). Without this, peer addrs are numeric and the
    # carve-out's addr_to_link lookup matches inbound numeric source
    # addrs, masking the bug.
    ip_to_host = {
        '172.20.0.10': 'node-a',
        '172.20.0.11': 'node-b',
        '172.20.0.12': 'node-c',
        '172.20.0.13': 'node-d',
        '172.20.0.14': 'node-e',
    }
    for peer in cfg.get('peers', []) or []:
        for addr in peer.get('addresses', []) or []:
            t = addr.get('transport')
            if t is not None and t != 'udp':
                continue
            a = addr.get('addr', '')
            for ip, host in ip_to_host.items():
                if a.startswith(ip + ':'):
                    port = a.split(':', 1)[1]
                    addr['addr'] = f'{host}:{port}'
                    break
with open('$cfg', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
"
        suffix=""
        if [ "$accept_off" = "true" ]; then
            suffix=" (accept_connections=false)"
        fi
        if [ "$outbound_only" = "true" ]; then
            suffix=" (outbound_only=true, hostname peer addrs)"
        fi
        echo "  ✓ node-$node$suffix"
    done
    echo "✓ Config injection complete"
    exit 0
fi

# ── Full test ─────────────────────────────────────────────────────────
trap 'echo ""; echo "Test interrupted"; exit 130' INT

# Wait times derived from rekey timer.
# BASELINE_CONVERGENCE_TIMEOUT must cover one full daemon
# node.tree.reeval_interval_secs (default 60) plus a small margin
# so any partition that only heals via the periodic TreeAnnounce
# re-broadcast lands inside the convergence window. The Phase-1 baseline
# wait early-exits on PASS, so successful reps are unaffected by the
# extra headroom.
BASELINE_CONVERGENCE_TIMEOUT=65
REKEY_SETTLE=12        # > DRAIN_WINDOW_SECS (10) so post-rekey samples are off the old session
# First FMP rekey should follow shortly after the 35s interval once the mesh is
# fully converged. Keep this bounded to preserve a meaningful scheduling check
# while still allowing for log visibility at the timeout edge.
FIRST_REKEY_TIMEOUT=$((REKEY_AFTER_SECS + 15))
SECOND_REKEY_WAIT=40   # upper bound for observing the second rekey cutover
LOG_EVENT_POLL_INTERVAL=1

# Post-rekey data-plane reconvergence is polled, not fixed-slept.
# wait_until_connected drives the same all-pairs ping sweep the strict
# per-phase assert depends on: it fails fast when reachability stops
# improving (no new reachable pair for RECONVERGE_STALL seconds while
# more than the near-converged slack of pairs is still down) and extends
# its deadline up to RECONVERGE_TIMEOUT only while pairs keep coming up,
# so a slow-but-converging post-rekey mesh under CI load passes instead
# of false-failing on a fixed settle window.
RECONVERGE_TIMEOUT=45
RECONVERGE_STALL=10

TIMEOUT=5
CONVERGENCE_PING_TIMEOUT=1
# Strict-ping retry policy for the per-phase ping_all asserts. Under 1%
# i.i.d. packet loss (the lab condition surfaced by ISSUE-2026-0028) a
# single-shot ping fails at roughly 2% per directed pair, so a 20-pair
# strict assert misses with probability ~1 - (0.98)^20 ≈ 33%, which is
# below the per-pair loss-math floor but well above the routing-state
# signal we want to measure. Retrying each failing pair up to
# MAX_PING_ATTEMPTS-1 additional times with ~PING_RETRY_DELAY between
# attempts drops the loss-math floor to ~(0.02)^MAX_PING_ATTEMPTS per
# pair, making any residual failure attributable to a non-loss
# mechanism rather than ICMP noise. Applied to Phase 1 (final strict
# ping_all after the Phase-1 baseline wait converges) and Phase 3 / Phase
# 5 (post-rekey strict asserts). The Phase-1 baseline wait's convergence
# loop itself stays single-shot — its job is to detect when the mesh
# first sees a fully clean 20-pair batch, and retries inside the loop
# would conflate "transient ping loss" with "still converging."
MAX_PING_ATTEMPTS=4
PING_RETRY_DELAY=1
PASSED=0
FAILED=0
TOTAL_PASSED=0
TOTAL_FAILED=0

# Node identities
ENV_FILE="$SCRIPT_DIR/../generated-configs/npubs.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found. Run generate-configs.sh first." >&2
    exit 1
fi
source "$ENV_FILE"

NPUBS=("$NPUB_A" "$NPUB_B" "$NPUB_C" "$NPUB_D" "$NPUB_E")
LABELS=(A B C D E)

# ── Helpers ────────────────────────────────────────────────────────────

ping_one() {
    local from="$1"
    local to_npub="$2"
    local label="$3"
    local quiet="${4:-}"
    local ping_timeout="${5:-$TIMEOUT}"
    local max_attempts="${6:-1}"

    local attempt=1
    local output rtt
    while (( attempt <= max_attempts )); do
        if (( attempt > 1 )); then
            sleep "$PING_RETRY_DELAY"
        fi
        if output=$(docker exec "fips-$from" ping6 -c 1 -W "$ping_timeout" "${to_npub}.fips" 2>&1); then
            rtt=$(echo "$output" | grep -oE 'time=[0-9.]+' | cut -d= -f2)
            if [ -z "$quiet" ]; then
                if (( attempt == 1 )); then
                    echo "  $label ... OK (${rtt:-?}ms)"
                else
                    echo "  $label ... OK (${rtt:-?}ms, attempt $attempt)"
                fi
            fi
            PASSED=$((PASSED + 1))
            return
        fi
        attempt=$((attempt + 1))
    done
    if [ -z "$quiet" ]; then
        if (( max_attempts > 1 )); then
            echo "  $label ... FAIL (after $max_attempts attempts)"
        else
            echo "  $label ... FAIL"
        fi
    fi
    FAILED=$((FAILED + 1))
}

# Run all 20 directed pairs
ping_all() {
    local quiet="${1:-}"
    local ping_timeout="${2:-$TIMEOUT}"
    local max_attempts="${3:-1}"
    PASSED=0
    FAILED=0
    for i in 0 1 2 3 4; do
        if [ -z "$quiet" ]; then
            echo "  From node-${LABELS[$i],,}:"
        fi
        for j in 0 1 2 3 4; do
            [ "$i" -eq "$j" ] && continue
            ping_one "node-${LABELS[$i],,}" "${NPUBS[$j]}" \
                "${LABELS[$i]} → ${LABELS[$j]}" "$quiet" "$ping_timeout" "$max_attempts"
        done
    done
}

# Connectivity probe for the progress-aware baseline wait: one full
# all-pairs ping sweep, setting PASSED/FAILED (consumed by
# wait_until_connected).
_baseline_ping() {
    ping_all quiet "$CONVERGENCE_PING_TIMEOUT"
}

phase_result() {
    local phase="$1"
    TOTAL_PASSED=$((TOTAL_PASSED + PASSED))
    TOTAL_FAILED=$((TOTAL_FAILED + FAILED))
    if [ "$FAILED" -eq 0 ]; then
        echo "  ✓ $phase: $PASSED/$((PASSED + FAILED)) passed"
    else
        echo "  ✗ $phase: $PASSED passed, $FAILED FAILED"
    fi
}

# Count occurrences of a pattern across all node logs
count_log_pattern() {
    local pattern="$1"
    local total=0
    for node in $NODES; do
        local count=$(docker logs "fips-node-$node" 2>&1 | grep -c "$pattern" || true)
        total=$((total + count))
    done
    echo "$total"
}

wait_for_log_pattern_count() {
    local pattern="$1"
    local min_count="$2"
    local timeout="$3"
    local start_secs=$SECONDS

    while (( SECONDS - start_secs < timeout )); do
        local count
        count=$(count_log_pattern "$pattern")
        if [ "$count" -ge "$min_count" ]; then
            return 0
        fi
        sleep "$LOG_EVENT_POLL_INTERVAL"
    done

    local count
    count=$(count_log_pattern "$pattern")
    if [ "$count" -ge "$min_count" ]; then
        return 0
    fi

    return 1
}

# Check that a pattern appears at least N times across all logs
assert_min_count() {
    local pattern="$1"
    local min_count="$2"
    local description="$3"
    local count=$(count_log_pattern "$pattern")
    if [ "$count" -ge "$min_count" ]; then
        echo "  ✓ $description: $count (>= $min_count)"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ $description: $count (expected >= $min_count)"
        FAILED=$((FAILED + 1))
    fi
}

# Check that a pattern appears zero times across all logs
assert_zero_count() {
    local pattern="$1"
    local description="$2"
    local count=$(count_log_pattern "$pattern")
    if [ "$count" -eq 0 ]; then
        echo "  ✓ $description: 0"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ $description: $count (expected 0)"
        FAILED=$((FAILED + 1))
    fi
}

dump_peer_connectivity() {
    echo "=== Peer connectivity snapshot ==="
    for node in $NODES; do
        echo "--- node-$node ---"
        docker exec "fips-node-$node" fipsctl show peers 2>/dev/null || true
        echo ""
    done
}

# ── Main ───────────────────────────────────────────────────────────────

echo "=== FIPS Rekey Integration Test ==="
echo ""
echo "Config: rekey.after_secs=$REKEY_AFTER_SECS"
echo ""

# ── Phase 1: Pre-rekey baseline ───────────────────────────────────────
# Wait for full pre-rekey connectivity with a progress-aware deadline:
# the all-pairs ping sweep is the convergence signal, the window extends
# while more pairs come up, and it gives up only if progress stalls — so
# it no longer false-times-out under concurrent CI load. The strict
# ping_all below is the actual assertion, run only after convergence.
echo "Phase 1: Pre-rekey connectivity (waiting for convergence)"
if wait_until_connected _baseline_ping "$BASELINE_CONVERGENCE_TIMEOUT" 20; then
    ping_all "" "$TIMEOUT" "$MAX_PING_ATTEMPTS"
    phase_result "Pre-rekey baseline (all 20 pairs)"
    if [ "$FAILED" -ne 0 ]; then
        echo ""
        dump_peer_connectivity
        echo "=== Results: $TOTAL_PASSED passed, $TOTAL_FAILED failed ==="
        exit 1
    fi
else
    echo "  Mesh did not reach a converged tree before timeout"
    ping_all quiet "$CONVERGENCE_PING_TIMEOUT"
    phase_result "Pre-rekey baseline (all 20 pairs)"
    echo ""
    dump_peer_connectivity
    echo "=== Results: $TOTAL_PASSED passed, $TOTAL_FAILED failed ==="
    exit 1
fi
echo ""

# ── Phase 2: Wait for first FMP rekey cycle ───────────────────────────
echo "Phase 2: First rekey cycle (waiting up to ${FIRST_REKEY_TIMEOUT}s for rekey)"
PASSED=0
FAILED=0
echo "  Checking FMP rekey events..."
wait_for_log_pattern_count \
    "Rekey cutover complete (initiator), K-bit flipped" 1 "$FIRST_REKEY_TIMEOUT" || true
assert_min_count "Rekey cutover complete (initiator), K-bit flipped" 1 \
    "FMP rekey initiator cutovers"
phase_result "FMP rekey events"
echo ""

# Verify connectivity after first rekey (strict — no failures allowed).
# Wait for the data plane to reconverge with a progress-aware deadline
# (the same all-pairs ping sweep the strict assert below depends on)
# instead of a fixed settle: fail fast on a genuinely stuck pair, extend
# only while reachability is still climbing. The strict ping_all is the
# actual assertion, run only after the reconverge poll.
echo "Phase 3: Post-rekey connectivity (reconverging up to ${RECONVERGE_TIMEOUT}s)"
wait_until_connected _baseline_ping "$RECONVERGE_TIMEOUT" "$RECONVERGE_STALL" || true
ping_all "" "$TIMEOUT" "$MAX_PING_ATTEMPTS"
phase_result "Post-first-rekey (all 20 pairs)"
echo ""

# ── Phase 4: Wait for further rekey cutovers ──────────────────────────
# Poll for the FMP rekey cutovers instead of blind-sleeping: capture the
# cutover count reached so far, then wait until two more land AND the
# Phase 6 absolute threshold (>= 4) is covered. The relative "+2" alone
# is not enough: it inherits whatever count Phase 4 starts from, and on
# an unloaded host the ping phases can outrun the jittered first rekey
# cycle, entering here with a single cutover on the books — then "+2"
# releases at three, the remaining first-cycle cutovers land moments
# after the Phase 6 snapshot, and the >= 4 assertion fails even though
# every cutover completed on schedule. Flooring the wait target at the
# Phase 6 threshold makes this wait's guarantee cover that assertion:
# the log count is monotone over a container's lifetime, so a released
# wait means the later count cannot lose the timing race.
#
# What the count measures: the counted line is emitted by the cadence
# path on whichever side(s) flip first, so a completed link rekey yields
# one or two lines (a side promoted by receiving a flipped-K frame logs
# only a DEBUG on a target the test's log filter suppresses). With rekey
# timers resetting at each cutover, the events landing inside this
# test's window are first-cycle cutovers spread across the topology's
# links, not a second cycle on one link.
# Bounded by SECOND_REKEY_WAIT so a stalled rekey still falls through to
# the strict Phase 5/6 assertions rather than hanging.
echo "Phase 4: Further rekey cutovers (waiting up to ${SECOND_REKEY_WAIT}s)"
fmp_cutovers_before=$(count_log_pattern "Rekey cutover complete (initiator), K-bit flipped")
fmp_cutover_target=$((fmp_cutovers_before + 2))
if [ "$fmp_cutover_target" -lt 4 ]; then
    fmp_cutover_target=4
fi
wait_for_log_pattern_count \
    "Rekey cutover complete (initiator), K-bit flipped" \
    "$fmp_cutover_target" "$SECOND_REKEY_WAIT" || true

# Verify connectivity after second rekey (back-to-back). This is the
# site of the recurring post-second-rekey straggler-pair flake: wait for
# the data plane to reconverge with a progress-aware deadline (the same
# all-pairs ping sweep the strict assert below depends on) rather than a
# fixed settle window — fail fast if reachability stops improving, extend
# only while pairs are still coming up.
echo "Phase 5: Post-second-rekey connectivity (reconverging up to ${RECONVERGE_TIMEOUT}s)"
wait_until_connected _baseline_ping "$RECONVERGE_TIMEOUT" "$RECONVERGE_STALL" || true
ping_all "" "$TIMEOUT" "$MAX_PING_ATTEMPTS"
phase_result "Post-second-rekey (all 20 pairs)"
echo ""

# ── Phase 6: Log analysis ─────────────────────────────────────────────
echo "Phase 6: Log analysis"
PASSED=0
FAILED=0

# FSP session rekey trails link-layer rekey in practice. Wait boundedly for
# at least one initiator and responder cutover before the final assertions.
#
# The responder-side cutover is driven by the overlapping-epoch
# trial-decrypt cascade: a frame that authenticates against the pending
# session is itself the cutover signal, logged as "Peer FSP new-epoch
# frame authenticated". The header K-bit is only an ordering hint now,
# so there is no longer a standalone "K-bit flip detected" event.
wait_for_log_pattern_count "FSP rekey cutover complete (initiator)" 1 "$FIRST_REKEY_TIMEOUT" || true
wait_for_log_pattern_count "Peer FSP new-epoch frame authenticated" 1 "$REKEY_SETTLE" || true

# Positive checks: rekey machinery worked
assert_min_count "Rekey cutover complete (initiator), K-bit flipped" 4 \
    "FMP rekey initiator cutovers"

# FSP rekey checks (sessions between non-adjacent nodes)
assert_min_count "FSP rekey cutover complete (initiator)" 1 \
    "FSP session rekey initiator cutovers"
assert_min_count "Peer FSP new-epoch frame authenticated" 1 \
    "FSP session rekey responder cutovers"

# Negative checks: no bad things happened
assert_zero_count "PANIC\|panicked" "Panics"
assert_zero_count "ERROR" "Errors"
assert_zero_count "MMP link teardown" "Spurious link teardowns"
assert_zero_count "Excessive decrypt failures" \
    "Excessive decrypt failure removals"
assert_zero_count "Rekey msg2 processing failed" "Rekey msg2 failures"
assert_zero_count "Session AEAD decryption failed" \
    "FSP decryption failures during rekey"

# Variant-specific: when one or more nodes have udp.accept_connections=false,
# verify the dual-init carve-out keeps the "we win, dropping their msg1"
# log line below the bug threshold. Pre-fix, a 1Hz dual-init loop produced
# ~120 occurrences over the 2-minute test; with the carve-out, the line
# fires at most a handful of times from genuine simultaneous rekeys.
if [ -n "$REKEY_ACCEPT_OFF_NODES" ]; then
    DUAL_INIT_THRESHOLD=10
    for off_node in ${REKEY_ACCEPT_OFF_NODES//,/ }; do
        count=$(docker logs "fips-node-$off_node" 2>&1 \
            | grep -cE "Dual rekey initiation: we win" || true)
        if [ "${count:-0}" -le "$DUAL_INIT_THRESHOLD" ]; then
            echo "  PASS: node-$off_node dual-init drops below threshold ($count <= $DUAL_INIT_THRESHOLD)"
            PASSED=$((PASSED + 1))
        else
            echo "  FAIL: node-$off_node sustained dual-init drops ($count > $DUAL_INIT_THRESHOLD)"
            FAILED=$((FAILED + 1))
        fi
    done
fi

# Variant-specific: udp.outbound_only=true. The pre-fix bug fired the
# dual-init loop on the OTHER side (the peer of the outbound-only node)
# because the outbound-only side rejects the inbound rekey msg1 due to
# the addr_to_link hostname-vs-numeric mismatch, leaving the peer's
# rekey state in a 1Hz retry loop that the outbound-only side keeps
# dropping. The exact node that emits "we win" depends on which side
# has the smaller NodeAddr, so check all five nodes for the sustained-
# loop signature.
if [ -n "$REKEY_OUTBOUND_ONLY_NODES" ]; then
    DUAL_INIT_THRESHOLD=10
    for n in $NODES; do
        count=$(docker logs "fips-node-$n" 2>&1 \
            | grep -cE "Dual rekey initiation: we win" || true)
        if [ "${count:-0}" -le "$DUAL_INIT_THRESHOLD" ]; then
            echo "  PASS: node-$n dual-init drops below threshold ($count <= $DUAL_INIT_THRESHOLD)"
            PASSED=$((PASSED + 1))
        else
            echo "  FAIL: node-$n sustained dual-init drops ($count > $DUAL_INIT_THRESHOLD)"
            FAILED=$((FAILED + 1))
        fi
    done
fi

phase_result "Log analysis"
echo ""

# ── Summary ────────────────────────────────────────────────────────────
echo "=== Results: $TOTAL_PASSED passed, $TOTAL_FAILED failed ==="

if [ "$TOTAL_FAILED" -eq 0 ]; then
    exit 0
else
    # Dump logs on failure for diagnostics.
    #
    # Wider pattern + larger line cap than the original head -30 (which
    # truncated before the actual ping-failure timestamp on Phase 5
    # fires, making the post-cutover convergence window invisible to
    # offline triage). Two passes per node:
    #   1) rekey-related events across the whole run (cap 200 lines).
    #   2) Last 80 lines unfiltered, to surface forwarding decisions,
    #      route lookups, congestion warnings, decrypt errors, and any
    #      other surrounding context near the failure point.
    echo ""
    echo "=== Node logs (rekey-related, head -200) ==="
    for node in $NODES; do
        echo "--- node-$node ---"
        docker logs "fips-node-$node" 2>&1 | \
            grep -E "(rekey|Rekey|cross|Cross|teardown|ERROR|PANIC|K-bit|no route|next hop|TTL exhausted|MTU exceeded|Congestion|decrypt|Decrypt|AEAD|Notify|drain|Drain|promot)" | \
            head -200
        echo ""
    done

    echo "=== Node logs (last 80 lines, unfiltered) ==="
    for node in $NODES; do
        echo "--- node-$node ---"
        docker logs "fips-node-$node" 2>&1 | tail -80
        echo ""
    done
    exit 1
fi
