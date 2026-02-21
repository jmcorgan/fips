"""FIPS node config generation from template + topology."""

from __future__ import annotations

import os

from .topology import SimTopology

# Path to the shared node config template
_TEMPLATE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "configs", "node.template.yaml"
)


def _load_template() -> str:
    with open(_TEMPLATE_PATH) as f:
        return f.read()


def generate_peers_block(
    topology: SimTopology, node_id: str, outbound_peers: list[str]
) -> str:
    """Generate the YAML peers block for a node.

    Only includes peers that this node is responsible for connecting to
    (outbound direction). The link is still bidirectional once established.
    """
    if not outbound_peers:
        return "  []"

    lines = []
    for peer_id in sorted(outbound_peers):
        peer = topology.nodes[peer_id]
        lines.append(f'  - npub: "{peer.npub}"')
        lines.append(f'    alias: "{peer_id}"')
        lines.append(f"    addresses:")
        lines.append(f"      - transport: udp")
        lines.append(f'        addr: "{peer.docker_ip}:4000"')
        lines.append(f"    connect_policy: auto_connect")
    return "\n".join(lines)


def generate_node_config(
    topology: SimTopology, node_id: str, outbound_peers: list[str]
) -> str:
    """Generate a complete FIPS config YAML for one node."""
    template = _load_template()
    node = topology.nodes[node_id]
    peers_yaml = generate_peers_block(topology, node_id, outbound_peers)

    config = template
    config = config.replace("{{NODE_NAME}}", node_id.upper())
    config = config.replace("{{TOPOLOGY}}", "sim")
    config = config.replace("{{NPUB}}", node.npub)
    config = config.replace("{{NSEC}}", node.nsec)
    config = config.replace("{{PEERS}}", peers_yaml)
    return config


def generate_npubs_env(topology: SimTopology) -> str:
    """Generate npubs.env content mapping NPUB_<ID>=<npub> for all nodes."""
    lines = []
    for node_id in sorted(topology.nodes):
        node = topology.nodes[node_id]
        env_name = f"NPUB_{node_id.upper()}"
        lines.append(f"{env_name}={node.npub}")
    return "\n".join(lines) + "\n"


def write_configs(topology: SimTopology, output_dir: str):
    """Write all node configs and npubs.env to the output directory."""
    os.makedirs(output_dir, exist_ok=True)

    outbound = topology.directed_outbound()
    for node_id in topology.nodes:
        config = generate_node_config(topology, node_id, outbound[node_id])
        path = os.path.join(output_dir, f"{node_id}.yaml")
        with open(path, "w") as f:
            f.write(config)

    env_path = os.path.join(output_dir, "npubs.env")
    with open(env_path, "w") as f:
        f.write(generate_npubs_env(topology))
