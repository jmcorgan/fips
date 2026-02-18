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
GENERATED_DIR="$SCRIPT_DIR/../generated-configs"
TEMPLATE_FILE="$CONFIG_DIR/node.template.yaml"
DERIVE_KEYS="$SCRIPT_DIR/derive-keys.py"

# Parse topology YAML to extract node attributes
# Usage: get_node_attr <topology_file> <node_id> <attr_name>
get_node_attr() {
    local topology_file="$1"
    local node_id="$2"
    local attr="$3"
    # Handle both docker_ip and external_ip as "address"
    if [ "$attr" = "address" ]; then
        local ip=$(grep -A 10 "^  $node_id:" "$topology_file" | grep "docker_ip:" | head -1 | sed 's/.*: *"*\([^"]*\)".*/\1/')
        if [ -z "$ip" ]; then
            ip=$(grep -A 10 "^  $node_id:" "$topology_file" | grep "external_ip:" | head -1 | sed 's/.*: *"*\([^"]*\)".*/\1/')
        fi
        echo "$ip"
    else
        grep -A 10 "^  $node_id:" "$topology_file" | grep "${attr}:" | head -1 | sed 's/.*: *"*\([^"]*\)".*/\1/'
    fi
}

# Check if a node is external (has external_ip instead of docker_ip)
is_external_node() {
    local topology_file="$1"
    local node_id="$2"
    local docker_ip=$(grep -A 10 "^  $node_id:" "$topology_file" | grep "docker_ip:" | head -1)
    [ -z "$docker_ip" ]
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

generate_peer_block() {
    local topology_file="$1"
    local peer_id="$2"

    local peer_npub="$(get_key RESOLVED_NPUB "$peer_id")"
    local peer_ip=$(get_node_attr "$topology_file" "$peer_id" "address")

    cat <<EOF
  - npub: "$peer_npub"
    alias: "node-$peer_id"
    addresses:
      - transport: udp
        addr: "$peer_ip:4000"
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
    local peers=$(get_peers "$topology_file" "$node_id")

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
