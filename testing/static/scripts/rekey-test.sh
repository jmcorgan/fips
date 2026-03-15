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
TOPOLOGY="rekey"
NODES="a b c d e"

# Rekey timing configuration
REKEY_AFTER_SECS=35

# ── inject-config subcommand ──────────────────────────────────────────
# Inject rekey config into generated node configs. Called separately
# by CI before building Docker images.
if [ "${1:-}" = "inject-config" ]; then
    echo "Injecting rekey config (after_secs=$REKEY_AFTER_SECS) into node configs..."
    for node in $NODES; do
        cfg="$SCRIPT_DIR/../generated-configs/$TOPOLOGY/node-$node.yaml"
        if [ ! -f "$cfg" ]; then
            echo "  Error: $cfg not found" >&2
            exit 1
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
with open('$cfg', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
"
        echo "  ✓ node-$node"
    done
    echo "✓ Config injection complete"
    exit 0
fi

# ── Full test ─────────────────────────────────────────────────────────
trap 'echo ""; echo "Test interrupted"; exit 130' INT

# Wait times derived from rekey timer
CONVERGE_WAIT=5
FIRST_REKEY_WAIT=40    # > REKEY_AFTER_SECS, allow margin
REKEY_SETTLE=5         # settle time after rekey for cutover to complete
SECOND_REKEY_WAIT=40   # wait for second cycle

TIMEOUT=5
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

    if output=$(docker exec "fips-$from" ping6 -c 1 -W "$TIMEOUT" "${to_npub}.fips" 2>&1); then
        local rtt=$(echo "$output" | grep -oE 'time=[0-9.]+' | cut -d= -f2)
        if [ -z "$quiet" ]; then
            echo "  $label ... OK (${rtt:-?}ms)"
        fi
        PASSED=$((PASSED + 1))
    else
        if [ -z "$quiet" ]; then
            echo "  $label ... FAIL"
        fi
        FAILED=$((FAILED + 1))
    fi
}

# Run all 20 directed pairs
ping_all() {
    local quiet="${1:-}"
    PASSED=0
    FAILED=0
    for i in 0 1 2 3 4; do
        if [ -z "$quiet" ]; then
            echo "  From node-${LABELS[$i],,}:"
        fi
        for j in 0 1 2 3 4; do
            [ "$i" -eq "$j" ] && continue
            ping_one "node-${LABELS[$i],,}" "${NPUBS[$j]}" \
                "${LABELS[$i]} → ${LABELS[$j]}" "$quiet"
        done
    done
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

# ── Main ───────────────────────────────────────────────────────────────

echo "=== FIPS Rekey Integration Test ==="
echo ""
echo "Config: rekey.after_secs=$REKEY_AFTER_SECS"
echo ""

# ── Phase 1: Pre-rekey baseline ───────────────────────────────────────
echo "Phase 1: Pre-rekey connectivity (waiting ${CONVERGE_WAIT}s for convergence)"
sleep "$CONVERGE_WAIT"
ping_all
phase_result "Pre-rekey baseline (all 20 pairs)"
echo ""

# ── Phase 2: Wait for first FMP rekey cycle ───────────────────────────
echo "Phase 2: First rekey cycle (waiting ${FIRST_REKEY_WAIT}s for rekey)"
sleep "$FIRST_REKEY_WAIT"

# Verify rekey events fired
PASSED=0
FAILED=0
echo "  Checking FMP rekey events..."
assert_min_count "Rekey cutover complete (initiator), K-bit flipped" 1 "FMP rekey initiator cutovers"
phase_result "FMP rekey events"
echo ""

# Verify connectivity after first rekey (strict — no failures allowed)
echo "Phase 3: Post-rekey connectivity (settling ${REKEY_SETTLE}s)"
sleep "$REKEY_SETTLE"
ping_all
phase_result "Post-first-rekey (all 20 pairs)"
echo ""

# ── Phase 4: Wait for second rekey cycle ──────────────────────────────
echo "Phase 4: Second rekey cycle (waiting ${SECOND_REKEY_WAIT}s)"
sleep "$SECOND_REKEY_WAIT"

# Verify connectivity after second rekey (back-to-back)
echo "Phase 5: Post-second-rekey connectivity"
ping_all
phase_result "Post-second-rekey (all 20 pairs)"
echo ""

# ── Phase 6: Log analysis ─────────────────────────────────────────────
echo "Phase 6: Log analysis"
PASSED=0
FAILED=0

# Positive checks: rekey machinery worked
assert_min_count "Rekey cutover complete (initiator), K-bit flipped" 4 \
    "FMP rekey initiator cutovers (>= 2 cycles)"

# FSP rekey checks (sessions between non-adjacent nodes)
assert_min_count "FSP rekey cutover complete" 1 \
    "FSP session rekey initiator cutovers"
assert_min_count "Peer FSP K-bit flip detected" 1 \
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

phase_result "Log analysis"
echo ""

# ── Summary ────────────────────────────────────────────────────────────
echo "=== Results: $TOTAL_PASSED passed, $TOTAL_FAILED failed ==="

if [ "$TOTAL_FAILED" -eq 0 ]; then
    exit 0
else
    # Dump logs on failure for diagnostics
    echo ""
    echo "=== Node logs (rekey-related) ==="
    for node in $NODES; do
        echo "--- node-$node ---"
        docker logs "fips-node-$node" 2>&1 | \
            grep -E "(rekey|Rekey|cross|Cross|teardown|ERROR|PANIC|K-bit)" | \
            head -30
        echo ""
    done
    exit 1
fi
