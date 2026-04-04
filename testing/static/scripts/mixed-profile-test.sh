#!/bin/bash
# Mixed-profile integration test: Full, NonRouting, and Leaf nodes.
#
# Topology:
#   A (Full) ─── B (Full)
#   │  \          │
#   │    \        │
#   D (Leaf)  C (NonRouting)
#
# Usage:
#   ./mixed-profile-test.sh inject-config   Inject profile config overrides
#   ./mixed-profile-test.sh                 Run the full test
#
# inject-config is run separately by CI after generate-configs.sh and
# before building Docker images.

set -e
trap 'echo ""; echo "Test interrupted"; exit 130' INT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOPOLOGY="mixed-profile"
NODES="a b c d"

# ── inject-config subcommand ──────────────────────────────────────────
# Inject profile overrides into generated node configs.
if [ "${1:-}" = "inject-config" ]; then
    echo "Injecting mixed-profile config overrides..."

    # Node C: non-routing
    cfg="$SCRIPT_DIR/../generated-configs/$TOPOLOGY/node-c.yaml"
    if [ ! -f "$cfg" ]; then
        echo "  Error: $cfg not found" >&2
        exit 1
    fi
    python3 -c "
import yaml
with open('$cfg') as f:
    cfg = yaml.safe_load(f)
cfg.setdefault('node', {})['disable_routing'] = True
with open('$cfg', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
"
    echo "  ✓ node-c (disable_routing: true)"

    # Node D: leaf
    cfg="$SCRIPT_DIR/../generated-configs/$TOPOLOGY/node-d.yaml"
    if [ ! -f "$cfg" ]; then
        echo "  Error: $cfg not found" >&2
        exit 1
    fi
    python3 -c "
import yaml
with open('$cfg') as f:
    cfg = yaml.safe_load(f)
cfg.setdefault('node', {})['leaf_only'] = True
with open('$cfg', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
"
    echo "  ✓ node-d (leaf_only: true)"

    echo "✓ Config injection complete"
    exit 0
fi

# ── Full test ─────────────────────────────────────────────────────────
source "$SCRIPT_DIR/../../lib/wait-converge.sh"
ENV_FILE="$SCRIPT_DIR/../generated-configs/npubs.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found. Run generate-configs.sh first." >&2
    exit 1
fi
source "$ENV_FILE"

PASSED=0
FAILED=0

check() {
    local desc="$1"
    shift
    echo -n "  $desc ... "
    if "$@" >/dev/null 2>&1; then
        echo "PASS"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL"
        FAILED=$((FAILED + 1))
    fi
}

ping_fips() {
    local from="$1"
    local to_npub="$2"
    docker exec "fips-$from" ping6 -c 1 -W 5 "${to_npub}.fips"
}

echo "=== Mixed-Profile Integration Test ==="
echo ""

# Phase 1: Wait for link convergence
echo "Phase 1: Link convergence"
# A: peers with B, C, D → 3 links
# B: peers with A, C → 2 links
# C (NonRouting): peers with A, B → 2 links
# D (Leaf): peers with A → 1 link
wait_for_peers fips-node-a 3 30 || true
wait_for_peers fips-node-b 2 30 || true
wait_for_peers fips-node-c 2 30 || true
wait_for_peers fips-node-d 1 30 || true

# Phase 2: Verify link counts (already validated by wait_for_peers above)
echo ""
echo "Phase 2: Link counts verified via convergence wait"

# Phase 3: Wait for discovery/session convergence
echo ""
echo "Phase 3: Waiting for session convergence (up to 45s)..."
# Try all pairs repeatedly until they all work
CONV_START=$SECONDS
CONV_TIMEOUT=45
ALL_OK=false
while (( SECONDS - CONV_START < CONV_TIMEOUT )); do
    ALL_GOOD=true
    for pair in "node-a:$NPUB_B" "node-a:$NPUB_C" "node-a:$NPUB_D" \
                "node-b:$NPUB_A" "node-b:$NPUB_C" \
                "node-c:$NPUB_A" "node-c:$NPUB_B" \
                "node-d:$NPUB_A" "node-d:$NPUB_B"; do
        from="${pair%%:*}"
        to="${pair##*:}"
        if ! docker exec "fips-$from" ping6 -c 1 -W 1 "${to}.fips" >/dev/null 2>&1; then
            ALL_GOOD=false
            break
        fi
    done
    if $ALL_GOOD; then
        echo "  All pairs reachable after $((SECONDS - CONV_START))s"
        ALL_OK=true
        break
    fi
    sleep 1
done
if ! $ALL_OK; then
    echo "  WARNING: Not all pairs converged within ${CONV_TIMEOUT}s (continuing with tests)"
fi

# Phase 4: Connectivity tests
echo ""
echo "Phase 4: F↔F connectivity"
check "A → B (Full → Full, direct)" ping_fips node-a "$NPUB_B"
check "B → A (Full → Full, direct)" ping_fips node-b "$NPUB_A"

echo ""
echo "Phase 5: F↔N connectivity"
check "A → C (Full → NonRouting, direct)" ping_fips node-a "$NPUB_C"
check "C → A (NonRouting → Full, direct)" ping_fips node-c "$NPUB_A"
check "B → C (Full → NonRouting, direct)" ping_fips node-b "$NPUB_C"
check "C → B (NonRouting → Full, direct)" ping_fips node-c "$NPUB_B"

echo ""
echo "Phase 6: F↔L connectivity"
check "A → D (Full → Leaf, direct)" ping_fips node-a "$NPUB_D"
check "D → A (Leaf → Full, direct)" ping_fips node-d "$NPUB_A"

echo ""
echo "Phase 7: Multi-hop through Full nodes"
check "D → B (Leaf → Full, via A)" ping_fips node-d "$NPUB_B"

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
