#!/bin/bash
# Mixed-version interop harness: generate the per-node configs for a
# node-spec.
#
# A NODE-SPEC is a multiset of image slots (`a`, `b`, `c`), of size >= 2.
# Each spec entry is one node; the same slot may appear more than once.
# The slots resolve to the three Docker images built by build-images.sh:
#
#   a -> fips-interop:a   ("version under test")
#   b -> fips-interop:b   ("parent / comparison")
#   c -> fips-interop:c   ("release baseline")
#
# Node identity vs image slot are SEPARATE:
#   - A spec entry is a slot letter.
#   - Node id = <slot><ordinal>, ordinal counting occurrences of that
#     slot, 1-based. Spec `a a b c` -> node ids `a1 a2 b1 c1`.
#   - Container name = fips-interop-<nodeid>.
#   - IPv4 = 172.30.0.1<index>, index = 0-based position in the spec
#     (10, 11, 12, 13, ...).
#
# Topology is a FULL MESH: every node auto-connects to every other node.
# Node identities are derived deterministically via the shared
# derive_keys.py helper, keyed by a unique per-node string so that two
# nodes of the same slot (a1, a2) still get DISTINCT identities.
#
# Output goes to <runs-base>/generated-configs/ (see FIPS_INTEROP_RUNS_DIR
# under Environment, below):
#   <nodeid>.yaml                  per-node daemon config (one per node)
#   docker-compose.generated.yml   generated compose, one service per node
#   nodes.env                      manifest for the driver to source
#   npubs.env                      NPUB_<NODEID> map (per-node npubs)
#
# Generation is deterministic and idempotent: same node-spec in -> same
# files out.
#
# Usage:
#   ./generate-configs.sh [node-spec...]
#
#   node-spec   space-separated slot letters, default `a b c`.
#
# Environment:
#   REKEY_AFTER_SECS       FSP/FMP rekey interval (default 35, matching
#                          the static rekey suite).
#   FIPS_INTEROP_RUNS_DIR  Root for harness scratch dirs (.build/,
#                          .stress-runs/, generated-configs/). When
#                          unset, falls back to in-tree paths under
#                          testing/interop/ and prints a warning to
#                          stderr; set it to a path outside the source
#                          tree to keep generated artefacts out of the
#                          checkout.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DERIVE_KEYS="$SCRIPT_DIR/../lib/derive_keys.py"

# ── Scratch-dir root ─────────────────────────────────────────────────
#
# FIPS_INTEROP_RUNS_DIR controls where the harness writes its scratch
# directories (.build/, .stress-runs/, generated-configs/). When unset
# we fall back to in-tree paths under testing/interop/ and warn the
# operator, so the warning fires exactly once per invocation. When a
# parent script has already warned it exports _FIPS_INTEROP_WARNED=1
# to suppress duplicate warnings in child scripts.
if [[ -n "${FIPS_INTEROP_RUNS_DIR:-}" ]]; then
    RUNS_BASE="$FIPS_INTEROP_RUNS_DIR"
    mkdir -p "$RUNS_BASE"
else
    RUNS_BASE="$SCRIPT_DIR"
    if [[ -z "${_FIPS_INTEROP_WARNED:-}" ]]; then
        echo >&2 "WARNING: FIPS_INTEROP_RUNS_DIR not set; harness output will be written under the source tree at $RUNS_BASE. Set FIPS_INTEROP_RUNS_DIR to a path outside the source tree to avoid this."
        export _FIPS_INTEROP_WARNED=1
    fi
fi

OUT_DIR="$RUNS_BASE/generated-configs"

REKEY_AFTER_SECS="${REKEY_AFTER_SECS:-35}"
MESH_NAME="fips-interop-mesh"
UDP_PORT=2121
SUBNET_PREFIX="172.30.0.1"     # node N gets ${SUBNET_PREFIX}<index>

# ── Args: the node-spec ──────────────────────────────────────────────

SPEC=("$@")
if [ "${#SPEC[@]}" -eq 0 ]; then
    SPEC=(a b c)
fi

if [ "${#SPEC[@]}" -lt 2 ]; then
    echo "ERROR: node-spec must have at least 2 nodes (got ${#SPEC[@]})" >&2
    echo "Usage: $0 [node-spec...]   e.g. $0 a a b c" >&2
    exit 1
fi

for slot in "${SPEC[@]}"; do
    case "$slot" in
        a|b|c) ;;
        *)
            echo "ERROR: invalid slot '$slot' — must be one of a, b, c" >&2
            exit 1
            ;;
    esac
done

# ── Derive node ids, slots, containers, IPs from the spec ────────────
#
# NODE_IDS preserves spec order. NODE_SLOT/NODE_IP/NODE_CTR are keyed by
# node id.

NODE_IDS=()
declare -A NODE_SLOT NODE_IP NODE_CTR
declare -A SLOT_COUNT=([a]=0 [b]=0 [c]=0)

index=0
for slot in "${SPEC[@]}"; do
    SLOT_COUNT[$slot]=$(( SLOT_COUNT[$slot] + 1 ))
    nid="${slot}${SLOT_COUNT[$slot]}"
    NODE_IDS+=("$nid")
    NODE_SLOT[$nid]="$slot"
    NODE_CTR[$nid]="fips-interop-$nid"
    NODE_IP[$nid]="${SUBNET_PREFIX}${index}"
    index=$(( index + 1 ))
done

mkdir -p "$OUT_DIR"

# Clear stale per-node configs from a previous (differently-shaped) spec
# so generation is idempotent — a smaller spec must not leave orphans.
rm -f "$OUT_DIR"/*.yaml

# ── Phase 1: derive identities ───────────────────────────────────────
#
# Key the derivation by node id (a1, a2, ...) so two same-slot nodes get
# distinct identities.

declare -A NSEC NPUB
for nid in "${NODE_IDS[@]}"; do
    keys="$(python3 "$DERIVE_KEYS" "$MESH_NAME" "$nid")"
    NSEC[$nid]="$(echo "$keys" | sed -n 's/^nsec=//p')"
    NPUB[$nid]="$(echo "$keys" | sed -n 's/^npub=//p')"
done

# ── Phase 2: emit per-node configs ───────────────────────────────────

emit_peer_block() {
    # Args: peer node-id
    local pid="$1"
    cat <<EOF
  - npub: "${NPUB[$pid]}"
    alias: "$pid"
    addresses:
      - transport: udp
        addr: "${NODE_IP[$pid]}:$UDP_PORT"
    connect_policy: auto_connect
EOF
}

for nid in "${NODE_IDS[@]}"; do
    cfg="$OUT_DIR/$nid.yaml"
    {
        echo "# FIPS interop mesh — node $nid (slot ${NODE_SLOT[$nid]})"
        echo "# Identity: ${NPUB[$nid]}"
        echo "# Generated by testing/interop/generate-configs.sh"
        echo ""
        echo "node:"
        echo "  identity:"
        echo "    nsec: \"${NSEC[$nid]}\""
        echo "  rekey:"
        echo "    enabled: true"
        echo "    after_secs: $REKEY_AFTER_SECS"
        echo "    after_messages: 65536"
        echo ""
        echo "tun:"
        echo "  enabled: true"
        echo "  name: fips0"
        echo "  mtu: 1280"
        echo ""
        echo "dns:"
        echo "  enabled: true"
        echo ""
        echo "transports:"
        echo "  udp:"
        echo "    bind_addr: \"0.0.0.0:$UDP_PORT\""
        echo "    mtu: 1472"
        echo ""
        echo "peers:"
        for pid in "${NODE_IDS[@]}"; do
            [ "$pid" = "$nid" ] && continue
            emit_peer_block "$pid"
        done
    } > "$cfg"
    echo "  generated $cfg"
done

# ── Phase 3: emit the generated docker-compose file ──────────────────
#
# One service per node, image pinned to the node's slot. This supersedes
# the static docker-compose.yml.

COMPOSE_FILE="$OUT_DIR/docker-compose.generated.yml"
{
    echo "# Mixed-version interop harness: generated compose, one service per node."
    echo "#"
    echo "# Generated by testing/interop/generate-configs.sh — DO NOT EDIT."
    echo "# Node-spec: ${SPEC[*]}"
    echo "#"
    echo "# Each service is pinned to its node's image slot, so two nodes of the"
    echo "# same slot (e.g. a1, a2) run the SAME daemon build. Netem is applied"
    echo "# by the driver via 'docker exec ... tc qdisc' on each container eth0."
    echo ""
    echo "networks:"
    echo "  fips-interop-net:"
    echo "    driver: bridge"
    echo "    ipam:"
    echo "      config:"
    echo "        - subnet: 172.30.0.0/24"
    echo ""
    echo "x-fips-interop-common: &fips-interop-common"
    echo "  cap_add:"
    echo "    - NET_ADMIN"
    echo "  devices:"
    echo "    - /dev/net/tun:/dev/net/tun"
    echo "  sysctls:"
    echo "    - net.ipv6.conf.all.disable_ipv6=0"
    echo "  restart: \"no\""
    echo "  environment:"
    echo "    - RUST_LOG=info,fips::node::handlers::rekey=debug,fips::node::handlers::handshake=debug"
    echo ""
    echo "services:"
    for nid in "${NODE_IDS[@]}"; do
        slot="${NODE_SLOT[$nid]}"
        echo "  $nid:"
        echo "    <<: *fips-interop-common"
        echo "    image: fips-interop:$slot"
        echo "    container_name: ${NODE_CTR[$nid]}"
        echo "    hostname: $nid"
        echo "    volumes:"
        echo "      - $REPO_ROOT/testing/docker/resolv.conf:/etc/resolv.conf:ro"
        echo "      - ./$nid.yaml:/etc/fips/fips.yaml:ro"
        echo "    networks:"
        echo "      fips-interop-net:"
        echo "        ipv4_address: ${NODE_IP[$nid]}"
    done
} > "$COMPOSE_FILE"
echo "  generated $COMPOSE_FILE"

# ── Phase 4: nodes.env manifest ──────────────────────────────────────
#
# The driver sources this. NODE_IDS is the canonical ordered node list;
# the per-node maps are emitted as space-separated key:value pairs so the
# driver can rebuild associative arrays without re-deriving anything.

MANIFEST="$OUT_DIR/nodes.env"
{
    echo "# Generated by testing/interop/generate-configs.sh"
    echo "# Mesh name: $MESH_NAME"
    echo "# Node-spec: ${SPEC[*]}"
    echo "INTEROP_SPEC=\"${SPEC[*]}\""
    echo "INTEROP_NODE_IDS=\"${NODE_IDS[*]}\""
    # Per-node maps, one var each, space-separated 'nodeid:value' tokens.
    {
        printf 'INTEROP_NODE_SLOTS="'
        for nid in "${NODE_IDS[@]}"; do printf '%s:%s ' "$nid" "${NODE_SLOT[$nid]}"; done
        printf '"\n'
    }
    {
        printf 'INTEROP_NODE_CONTAINERS="'
        for nid in "${NODE_IDS[@]}"; do printf '%s:%s ' "$nid" "${NODE_CTR[$nid]}"; done
        printf '"\n'
    }
    {
        printf 'INTEROP_NODE_IPS="'
        for nid in "${NODE_IDS[@]}"; do printf '%s:%s ' "$nid" "${NODE_IP[$nid]}"; done
        printf '"\n'
    }
    {
        printf 'INTEROP_NODE_NPUBS="'
        for nid in "${NODE_IDS[@]}"; do printf '%s:%s ' "$nid" "${NPUB[$nid]}"; done
        printf '"\n'
    }
} > "$MANIFEST"
echo "  generated $MANIFEST"

# ── Phase 5: npubs.env — per-node npub map ───────────────────────────

ENV_FILE="$OUT_DIR/npubs.env"
{
    echo "# Generated by testing/interop/generate-configs.sh"
    echo "# Mesh name: $MESH_NAME"
    for nid in "${NODE_IDS[@]}"; do
        upper="$(echo "$nid" | tr '[:lower:]' '[:upper:]')"
        echo "NPUB_${upper}=${NPUB[$nid]}"
    done
} > "$ENV_FILE"
echo "  generated $ENV_FILE"

echo ""
echo "Mesh configs ready (spec='${SPEC[*]}', rekey.after_secs=$REKEY_AFTER_SECS):"
for nid in "${NODE_IDS[@]}"; do
    echo "  $nid  slot ${NODE_SLOT[$nid]}  ${NODE_IP[$nid]}  ${NPUB[$nid]}"
done
