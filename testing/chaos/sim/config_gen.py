"""FIPS node config generation from template + topology."""

from __future__ import annotations

import os
from copy import deepcopy

import yaml

from .topology import SimTopology


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base (override wins on conflicts)."""
    result = deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result

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


def _build_ethernet_config(iface: str) -> dict:
    """Build an Ethernet transport config dict for a single interface."""
    return {
        "interface": iface,
        "discovery": True,
        "announce": True,
        "auto_connect": True,
        "accept_connections": True,
        "beacon_interval_secs": 10,
    }


def _inject_ethernet_transports(parsed: dict, eth_ifaces: list[str]):
    """Inject Ethernet transport config into a parsed FIPS config.

    For a single interface, uses the single-instance format.
    For multiple interfaces, uses the named-instances format.
    Pure-Ethernet nodes (no UDP peers) have their UDP transport removed.
    """
    if not eth_ifaces:
        return

    transports = parsed.setdefault("transports", {})
    if len(eth_ifaces) == 1:
        transports["ethernet"] = _build_ethernet_config(eth_ifaces[0])
    else:
        transports["ethernet"] = {
            iface: _build_ethernet_config(iface) for iface in eth_ifaces
        }


def generate_node_config(
    topology: SimTopology,
    node_id: str,
    outbound_peers: list[str],
    fips_overrides: dict | None = None,
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

    # Inject Ethernet transport config if this node has Ethernet edges
    eth_ifaces = topology.ethernet_interfaces(node_id)
    has_udp_peers = bool(outbound_peers) or _has_inbound_udp_peers(topology, node_id)

    if eth_ifaces or not has_udp_peers:
        parsed = yaml.safe_load(config)
        if fips_overrides:
            parsed = _deep_merge(parsed, fips_overrides)
        if eth_ifaces:
            _inject_ethernet_transports(parsed, eth_ifaces)
        if not has_udp_peers and eth_ifaces:
            # Pure-Ethernet node: remove UDP transport
            transports = parsed.get("transports", {})
            transports.pop("udp", None)
        config = yaml.dump(parsed, default_flow_style=False, sort_keys=False)
    elif fips_overrides:
        parsed = yaml.safe_load(config)
        merged = _deep_merge(parsed, fips_overrides)
        config = yaml.dump(merged, default_flow_style=False, sort_keys=False)

    return config


def _has_inbound_udp_peers(topology: SimTopology, node_id: str) -> bool:
    """Check if any other node has a UDP outbound edge to this node."""
    for peer_id in topology.nodes[node_id].peers:
        edge = (min(node_id, peer_id), max(node_id, peer_id))
        if topology.edge_transport.get(edge, "udp") == "udp":
            return True
    return False


def generate_npubs_env(topology: SimTopology) -> str:
    """Generate npubs.env content mapping NPUB_<ID>=<npub> for all nodes."""
    lines = []
    for node_id in sorted(topology.nodes):
        node = topology.nodes[node_id]
        env_name = f"NPUB_{node_id.upper()}"
        lines.append(f"{env_name}={node.npub}")
    return "\n".join(lines) + "\n"


def write_configs(
    topology: SimTopology,
    output_dir: str,
    fips_overrides: dict | None = None,
):
    """Write all node configs and npubs.env to the output directory."""
    os.makedirs(output_dir, exist_ok=True)

    outbound = topology.directed_outbound()
    for node_id in topology.nodes:
        config = generate_node_config(
            topology, node_id, outbound[node_id], fips_overrides
        )
        path = os.path.join(output_dir, f"{node_id}.yaml")
        with open(path, "w") as f:
            f.write(config)

    env_path = os.path.join(output_dir, "npubs.env")
    with open(env_path, "w") as f:
        f.write(generate_npubs_env(topology))
