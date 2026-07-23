#!/bin/bash
# Generate FIPS node configuration files from template and topology definition.
#
# Usage: ./generate-configs.sh <topology> [mesh-name]
#   topology:  mesh, mesh-public, chain, etc.
#   mesh-name: optional; when given, docker node identities are derived
#              deterministically via sha256(mesh-name|node-id)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/../configs"
# Scoped by the CI run suffix so two concurrent runs cannot overwrite each
# other's generated configs or npubs.env. Unset (a bare invocation) renders
# the historical unscoped path.
GENERATED_DIR="$SCRIPT_DIR/../generated-configs${FIPS_CI_NAME_SUFFIX:-}"
TEMPLATE_FILE="$CONFIG_DIR/node.template.yaml"
DERIVE_KEYS="$SCRIPT_DIR/../../lib/derive_keys.py"

# Every line belonging to one node, from its key to the next node key.
#
# Bounded by the block rather than by a fixed number of lines: a node that
# omits an attribute would otherwise read the NEXT node's value for it, which
# is silent and wrong in both directions — an external node followed by an
# internal one would be classified as internal, and a node without docker_host
# would dial the following node's container.
node_block() {
    local topology_file="$1"
    local node_id="$2"
    awk -v id="$node_id" '
        $0 ~ "^  " id ":" { inblock = 1; next }
        inblock && /^  [a-zA-Z]/ { exit }
        inblock { print }
    ' "$topology_file"
}

# Parse topology YAML to extract node attributes
# Usage: get_node_attr <topology_file> <node_id> <attr_name>
get_node_attr() {
    local topology_file="$1"
    local node_id="$2"
    local attr="$3"
    local block
    block=$(node_block "$topology_file" "$node_id")
    # Handle both docker_ip and external_ip as "address"
    if [ "$attr" = "address" ]; then
        local ip=$(echo "$block" | grep "docker_ip:" | head -1 | sed 's/.*: *"*\([^"]*\)".*/\1/')
        if [ -z "$ip" ]; then
            ip=$(echo "$block" | grep "external_ip:" | head -1 | sed 's/.*: *"*\([^"]*\)".*/\1/')
        fi
        echo "$ip"
    else
        echo "$block" | grep "${attr}:" | head -1 | sed 's/.*: *"*\([^"]*\)".*/\1/'
    fi
}

# Check if a node is external (has external_ip instead of docker_ip)
is_external_node() {
    local topology_file="$1"
    local node_id="$2"
    local docker_ip
    docker_ip=$(node_block "$topology_file" "$node_id" | grep "docker_ip:" | head -1)
    [ -z "$docker_ip" ]
}

# Docker hostname of an internal node. Peers address each other by name so the
# compose network can be auto-assigned, which is what makes two concurrent runs
# safe: with no fixed subnet requested there is nothing for them to contend
# for. Defaults to node-<id>, the compose `hostname:` every static profile
# uses; a topology whose services are named otherwise declares docker_host.
docker_host_name() {
    local topology_file="$1"
    local node_id="$2"
    local host
    host=$(get_node_attr "$topology_file" "$node_id" "docker_host")
    echo "${host:-node-$node_id}"
}

# Get peers list from topology
get_peers() {
    local topology_file="$1"
    local node_id="$2"
    grep -A 10 "^  $node_id:" "$topology_file" | grep "peers:" | head -1 | \
        sed 's/.*: *\[\(.*\)\].*/\1/' | \
        sed 's/,/ /g' | \
        tr -s ' ' | \
        sed 's/^ *//;s/ *$//'
}

# Get all node IDs from topology file
get_node_ids() {
    local topology_file="$1"
    grep "^  [a-z][a-z0-9_-]*:" "$topology_file" | sed 's/^  \([a-z][a-z0-9_-]*\):.*/\1/'
}

# Resolve nsec and npub for a node.
# If MESH_NAME is set and node is not external, derive from mesh-name.
# Otherwise use the value from the topology YAML.
# Output: two lines: nsec=<hex>\nnpub=<bech32>
resolve_keys() {
    local topology_file="$1"
    local node_id="$2"

    if [ -n "$MESH_NAME" ] && ! is_external_node "$topology_file" "$node_id"; then
        python3 "$DERIVE_KEYS" "$MESH_NAME" "$node_id"
    else
        local nsec
        local npub
        nsec=$(get_node_attr "$topology_file" "$node_id" "nsec")
        npub=$(get_node_attr "$topology_file" "$node_id" "npub")
        echo "nsec=$nsec"
        echo "npub=$npub"
    fi
}

# Get the default transport from topology file (defaults to "udp")
get_default_transport() {
    local topology_file="$1"
    local transport=$(grep "^default_transport:" "$topology_file" | head -1 | sed 's/.*: *\([a-z]*\).*/\1/')
    echo "${transport:-udp}"
}

# Get the port for a given transport type
transport_port() {
    local transport="$1"
    case "$transport" in
        tcp) echo "443" ;;
        *)   echo "2121" ;;
    esac
}

generate_peer_block() {
    local topology_file="$1"
    local peer_id="$2"

    local peer_npub="$(get_key RESOLVED_NPUB "$peer_id")"
    local peer_addr
    if is_external_node "$topology_file" "$peer_id"; then
        # An external peer is not ours to name — use the address the
        # topology gives it.
        peer_addr=$(get_node_attr "$topology_file" "$peer_id" "address")
    else
        peer_addr=$(docker_host_name "$topology_file" "$peer_id")
    fi
    local transport=$(get_default_transport "$topology_file")
    local port=$(transport_port "$transport")

    cat <<EOF
  - npub: "$peer_npub"
    alias: "node-$peer_id"
    addresses:
      - transport: $transport
        addr: "$peer_addr:$port"
    connect_policy: auto_connect
EOF
}

generate_config() {
    local node_id="$1"
    local topology_file="$2"
    local output_file="$3"

    local node_npub
    node_npub="$(get_key RESOLVED_NPUB "$node_id")"
    local node_nsec
    node_nsec="$(get_key RESOLVED_NSEC "$node_id")"
    local peers
    peers=$(get_peers "$topology_file" "$node_id")

    # Generate peers section
    local peers_config=""
    if [ -n "$peers" ]; then
        for peer_id in $peers; do
            if [ -n "$peers_config" ]; then
                peers_config="$peers_config"$'\n'
            fi
            peers_config="$peers_config$(generate_peer_block "$topology_file" "$peer_id")"
        done
    else
        peers_config="  []"
    fi

    # Read and process template
    local template=$(cat "$TEMPLATE_FILE")
    local config="$template"

    config="${config//\{\{NODE_NAME\}\}/$(echo "$node_id" | tr '[:lower:]' '[:upper:]')}"
    config="${config//\{\{TOPOLOGY\}\}/$(basename "$topology_file" .yaml)}"
    config="${config//\{\{NPUB\}\}/$node_npub}"
    config="${config//\{\{NSEC\}\}/$node_nsec}"
    config="${config//\{\{PEERS\}\}/$peers_config}"

    echo "$config" > "$output_file"

    # Post-process: inject TCP transport config for TCP topologies
    local transport
    transport=$(get_default_transport "$topology_file")
    if [ "$transport" = "tcp" ]; then
        # Add TCP transport section and remove UDP transport
        python3 -c "
import yaml, sys
with open('$output_file') as f:
    cfg = yaml.safe_load(f)
cfg.setdefault('transports', {})['tcp'] = {'bind_addr': '0.0.0.0:443'}
cfg.get('transports', {}).pop('udp', None)
with open('$output_file', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
"
    fi
}

# Key storage for bash 3.2 compatibility (using prefixed variables instead of associative arrays)
# Usage: set_key NSEC a "value" / get_key NSEC a
set_key() {
    local prefix="$1"
    local key="$2"
    local value="$3"
    eval "${prefix}_${key}=\"${value}\""
}

get_key() {
    local prefix="$1"
    local key="$2"
    eval "echo \"\$${prefix}_${key}\""
}

generate_topology() {
    local topology_name="$1"
    local topology_file="$CONFIG_DIR/topologies/$topology_name.yaml"
    local output_dir="$GENERATED_DIR/$topology_name"

    if [ ! -f "$topology_file" ]; then
        echo "Error: Topology file not found: $topology_file"
        exit 1
    fi

    echo "Generating $topology_name topology configs..."
    if [ -n "$MESH_NAME" ]; then
        echo "  Mesh name: $MESH_NAME (deriving docker node identities)"
    fi
    mkdir -p "$output_dir"

    # Phase 1: resolve keys for all nodes
    for node_id in $(get_node_ids "$topology_file"); do
        local keys=""
        keys=$(resolve_keys "$topology_file" "$node_id")
        set_key RESOLVED_NSEC "$node_id" "$(echo "$keys" | grep "^nsec=" | cut -d= -f2)"
        set_key RESOLVED_NPUB "$node_id" "$(echo "$keys" | grep "^npub=" | cut -d= -f2)"
    done

    # Phase 2: generate config files for docker nodes
    for node_id in $(get_node_ids "$topology_file"); do
        # Skip external nodes (they don't need Docker config files)
        if is_external_node "$topology_file" "$node_id"; then
            echo "  ⚠ Skipping $node_id (external node)"
            continue
        fi

        local output_file="$output_dir/node-$node_id.yaml"
        generate_config "$node_id" "$topology_file" "$output_file"
        echo "  ✓ Generated $output_file"
    done

    # Phase 3: write npubs.env
    local env_file="$GENERATED_DIR/npubs.env"
    echo "# Generated by generate-configs.sh (topology: $topology_name)" > "$env_file"
    if [ -n "$MESH_NAME" ]; then
        echo "# Mesh name: $MESH_NAME" >> "$env_file"
    fi
    for node_id in $(get_node_ids "$topology_file"); do
        local var_name="NPUB_$(echo "$node_id" | tr '[:lower:]' '[:upper:]')"
        echo "${var_name}=$(get_key RESOLVED_NPUB "$node_id")" >> "$env_file"
    done
    echo "  ✓ Generated $env_file"
}

main() {
    local requested="${1:-mesh}"

    # Support any topology file in the topologies directory
    if [ -f "$CONFIG_DIR/topologies/$requested.yaml" ]; then
        generate_topology "$requested"
    else
        echo "Error: Unknown topology '$requested'"
        echo "Usage: $0 <topology> [mesh-name]"
        echo ""
        echo "Available topologies:"
        ls -1 "$CONFIG_DIR/topologies/" | sed 's/\.yaml$//' | sed 's/^/  - /'
        exit 1
    fi

    echo ""
    echo "✓ All configurations generated successfully!"
}

MESH_NAME="${2:-}"
main "$@"
