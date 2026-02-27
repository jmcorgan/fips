"""Topology generation: random graphs with connectivity guarantees."""

from __future__ import annotations

import math
import random
from collections import deque
from dataclasses import dataclass, field

from .keys import derive
from .scenario import TopologyConfig


@dataclass
class SimNode:
    node_id: str  # "n01", "n02", ...
    docker_ip: str  # "172.20.0.10", ...
    nsec: str  # 64-char hex
    npub: str  # bech32 npub1...
    peers: list[str] = field(default_factory=list)
    # MAC addresses for Ethernet veth interfaces, keyed by peer_id
    ethernet_macs: dict[str, str] = field(default_factory=dict)


@dataclass
class SimTopology:
    nodes: dict[str, SimNode] = field(default_factory=dict)
    edges: set[tuple[str, str]] = field(default_factory=set)
    # Per-edge transport type; edges not in this dict default to "udp"
    edge_transport: dict[tuple[str, str], str] = field(default_factory=dict)

    def transport_for_edge(self, a: str, b: str) -> str:
        """Get the transport type for an edge (defaults to 'udp')."""
        edge = _make_edge(a, b)
        return self.edge_transport.get(edge, "udp")

    def ethernet_edges(self) -> list[tuple[str, str]]:
        """Return all edges using Ethernet transport."""
        return [e for e, t in self.edge_transport.items() if t == "ethernet"]

    def has_ethernet(self) -> bool:
        """Check if any edges use Ethernet transport."""
        return any(t == "ethernet" for t in self.edge_transport.values())

    def tcp_edges(self) -> list[tuple[str, str]]:
        """Return all edges using TCP transport."""
        return [e for e, t in self.edge_transport.items() if t == "tcp"]

    def has_tcp(self) -> bool:
        """Check if any edges use TCP transport."""
        return any(t == "tcp" for t in self.edge_transport.values())

    def tcp_peers(self, node_id: str) -> list[str]:
        """Return peer IDs connected to this node via TCP."""
        peers = []
        for (a, b), transport in self.edge_transport.items():
            if transport != "tcp":
                continue
            if a == node_id:
                peers.append(b)
            elif b == node_id:
                peers.append(a)
        return sorted(peers)

    def ethernet_interfaces(self, node_id: str) -> list[str]:
        """Return the veth interface names for a node's Ethernet edges."""
        ifaces = []
        for (a, b), transport in self.edge_transport.items():
            if transport != "ethernet":
                continue
            if a == node_id:
                ifaces.append(veth_interface_name(a, b))
            elif b == node_id:
                ifaces.append(veth_interface_name(b, a))
        return sorted(ifaces)

    def is_connected(self) -> bool:
        """BFS connectivity check."""
        if len(self.nodes) <= 1:
            return True
        start = next(iter(self.nodes))
        visited = set()
        queue = deque([start])
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            for peer in self.nodes[node].peers:
                if peer not in visited:
                    queue.append(peer)
        return len(visited) == len(self.nodes)

    def neighbors(self, node_id: str) -> list[str]:
        return self.nodes[node_id].peers

    def would_disconnect(self, edge: tuple[str, str]) -> bool:
        """Check if removing this edge would disconnect the graph."""
        a, b = edge
        # Temporarily remove edge
        self.nodes[a].peers.remove(b)
        self.nodes[b].peers.remove(a)
        connected = self.is_connected()
        # Restore
        self.nodes[a].peers.append(b)
        self.nodes[b].peers.append(a)
        return not connected

    def container_name(self, node_id: str) -> str:
        return f"fips-node-{node_id}"

    def directed_outbound(self) -> dict[str, list[str]]:
        """Assign each static-config edge to exactly one node for outbound connection.

        Returns a mapping from node_id to the list of peers that node
        should connect to (outbound only). Every edge appears in exactly
        one direction, ensuring auto-reconnect is testable — if B goes
        down, only A (the outbound owner) will attempt to reconnect.

        Ethernet edges are excluded — they use beacon discovery instead
        of static peer configuration. UDP and TCP edges use static config.

        Strategy: BFS spanning tree edges go parent→child. Non-tree
        edges go from the lower node ID to the higher. This guarantees
        every node is reachable via at least one inbound connection.
        """
        # Consider all edges that use static peer config (not Ethernet/discovery)
        static_edges = {
            e for e in self.edges
            if self.edge_transport.get(e, "udp") != "ethernet"
        }

        outbound: dict[str, list[str]] = {nid: [] for nid in self.nodes}

        # Build static-config adjacency for BFS
        static_adj: dict[str, list[str]] = {nid: [] for nid in self.nodes}
        for a, b in static_edges:
            static_adj[a].append(b)
            static_adj[b].append(a)

        # BFS spanning tree from first node (over static-config edges only)
        root = min(self.nodes)
        visited: set[str] = set()
        tree_edges: set[tuple[str, str]] = set()
        queue = deque([root])
        visited.add(root)
        while queue:
            node = queue.popleft()
            for peer in static_adj[node]:
                if peer not in visited:
                    visited.add(peer)
                    queue.append(peer)
                    tree_edges.add((node, peer))  # parent → child
                    outbound[node].append(peer)

        # Non-tree static-config edges: lower ID → higher ID
        for a, b in static_edges:
            if (a, b) not in tree_edges and (b, a) not in tree_edges:
                outbound[a].append(b)  # a < b by _make_edge convention

        return outbound


def generate_topology(
    config: TopologyConfig,
    rng: random.Random,
    mesh_name: str,
) -> SimTopology:
    """Generate a topology according to the config."""
    n = config.num_nodes
    subnet_base = config.subnet.rsplit(".", 1)[0]  # "172.20.0"

    # Create nodes with IPs and keys
    nodes: dict[str, SimNode] = {}
    for i in range(n):
        node_id = f"n{i + 1:02d}"
        docker_ip = f"{subnet_base}.{config.ip_start + i}"
        nsec, npub = derive(mesh_name, node_id)
        nodes[node_id] = SimNode(
            node_id=node_id,
            docker_ip=docker_ip,
            nsec=nsec,
            npub=npub,
        )

    node_ids = sorted(nodes.keys())

    # Generate edges
    if config.algorithm == "chain":
        edges = _generate_chain(node_ids)
    elif config.algorithm == "random_geometric":
        radius = config.params.get("radius", 0.5)
        edges = _generate_random_geometric(node_ids, radius, rng)
    elif config.algorithm == "erdos_renyi":
        p = config.params.get("p", 0.3)
        edges = _generate_erdos_renyi(node_ids, p, rng)
    elif config.algorithm == "explicit":
        adjacency = config.params.get("adjacency")
        if not adjacency:
            raise ValueError("explicit topology requires params.adjacency")
        edges, edge_transport = _generate_explicit(
            adjacency, config.default_transport
        )
        # Validate all referenced nodes exist
        for a, b in edges:
            if a not in nodes:
                raise ValueError(f"explicit adjacency references unknown node {a}")
            if b not in nodes:
                raise ValueError(f"explicit adjacency references unknown node {b}")
    else:
        raise ValueError(f"Unknown algorithm: {config.algorithm}")

    # For non-explicit topologies, all edges use the default transport
    if config.algorithm != "explicit":
        edge_transport = {e: config.default_transport for e in edges}

    # Build peer lists from edges
    for a, b in edges:
        nodes[a].peers.append(b)
        nodes[b].peers.append(a)

    topo = SimTopology(nodes=nodes, edges=edges, edge_transport=edge_transport)

    # Connectivity check with retry
    if config.ensure_connected:
        max_retries = 50
        attempt = 0
        while not topo.is_connected() and attempt < max_retries:
            attempt += 1
            # Clear and regenerate
            for node in nodes.values():
                node.peers.clear()

            if config.algorithm == "random_geometric":
                edges = _generate_random_geometric(node_ids, radius, rng)
            elif config.algorithm == "erdos_renyi":
                edges = _generate_erdos_renyi(node_ids, p, rng)
            else:
                break  # chain is always connected

            for a, b in edges:
                nodes[a].peers.append(b)
                nodes[b].peers.append(a)

            topo.edges = edges

        if not topo.is_connected():
            raise RuntimeError(
                f"Failed to generate connected topology after {max_retries} attempts"
            )

    return topo


def _generate_chain(node_ids: list[str]) -> set[tuple[str, str]]:
    """Linear topology: n01-n02-n03-..."""
    edges = set()
    for i in range(len(node_ids) - 1):
        edge = _make_edge(node_ids[i], node_ids[i + 1])
        edges.add(edge)
    return edges


def _generate_random_geometric(
    node_ids: list[str],
    radius: float,
    rng: random.Random,
) -> set[tuple[str, str]]:
    """Place nodes randomly in [0,1]^2, connect if distance < radius."""
    positions = {nid: (rng.random(), rng.random()) for nid in node_ids}
    edges = set()
    for i, a in enumerate(node_ids):
        for b in node_ids[i + 1 :]:
            ax, ay = positions[a]
            bx, by = positions[b]
            dist = math.sqrt((ax - bx) ** 2 + (ay - by) ** 2)
            if dist < radius:
                edges.add(_make_edge(a, b))
    return edges


def _generate_erdos_renyi(
    node_ids: list[str],
    p: float,
    rng: random.Random,
) -> set[tuple[str, str]]:
    """Include each edge with probability p."""
    edges = set()
    for i, a in enumerate(node_ids):
        for b in node_ids[i + 1 :]:
            if rng.random() < p:
                edges.add(_make_edge(a, b))
    return edges


def _generate_explicit(
    adjacency: list, default_transport: str = "udp"
) -> tuple[set[tuple[str, str]], dict[tuple[str, str], str]]:
    """Build edges from an explicit adjacency list.

    Each entry is a 2-element list ``[nodeA, nodeB]`` (uses default
    transport) or a 3-element list ``[nodeA, nodeB, transport]``.

    Returns ``(edges, edge_transport)`` where ``edge_transport`` maps
    each edge to its transport type.
    """
    edges = set()
    edge_transport: dict[tuple[str, str], str] = {}
    for i, entry in enumerate(adjacency):
        if not isinstance(entry, (list, tuple)) or len(entry) not in (2, 3):
            raise ValueError(
                f"explicit adjacency[{i}]: expected [nodeA, nodeB] or "
                f"[nodeA, nodeB, transport], got {entry}"
            )
        edge = _make_edge(str(entry[0]), str(entry[1]))
        edges.add(edge)
        transport = str(entry[2]) if len(entry) == 3 else default_transport
        edge_transport[edge] = transport
    return edges, edge_transport


def veth_interface_name(local: str, peer: str) -> str:
    """Generate the veth interface name inside a container.

    Format: ``ve-{local}-{peer}`` (max 15 chars for IFNAMSIZ).
    For typical node IDs like "n01", this yields "ve-n01-n02" (10 chars).
    """
    name = f"ve-{local}-{peer}"
    if len(name) > 15:
        raise ValueError(f"veth interface name too long: {name!r} ({len(name)} > 15)")
    return name


def _make_edge(a: str, b: str) -> tuple[str, str]:
    """Canonical edge representation (sorted)."""
    return (min(a, b), max(a, b))
