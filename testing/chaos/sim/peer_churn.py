"""Peer-level topology churn via connect/disconnect commands.

Unlike NodeManager (which stops/starts containers), this uses the
fipsctl connect/disconnect API to dynamically add and remove individual
peer connections while nodes stay running. The topology graph evolves
over time: random links are disconnected and new random pairs connected.

Supports ephemeral identity nodes — half the nodes (configurable) get
new keypairs on each container restart, requiring the simulator to
track current npubs via show_status queries.
"""

from __future__ import annotations

import logging
import random
import time

from .control import query_status, send_command
from .scenario import PeerChurnConfig
from .topology import SimTopology

log = logging.getLogger(__name__)


class PeerChurnManager:
    """Manages peer-level topology churn using connect/disconnect commands."""

    def __init__(
        self,
        topology: SimTopology,
        config: PeerChurnConfig,
        rng: random.Random,
        down_nodes: set[str],
        ephemeral_nodes: set[str] | None = None,
    ):
        self.topology = topology
        self.config = config
        self.rng = rng
        self.down_nodes = down_nodes
        self.ephemeral_nodes = ephemeral_nodes or set()

        # Current npub for each node (populated during init)
        self.npub_cache: dict[str, str] = {}

        # Currently active edges (start with topology edges)
        self.active_edges: set[tuple[str, str]] = set()
        for a, b in topology.edges:
            self.active_edges.add(self._canonical(a, b))

        # Edges disconnected by peer churn (not yet reconnected)
        self.churned_count = 0

    @staticmethod
    def _canonical(a: str, b: str) -> tuple[str, str]:
        """Canonical edge ordering (sorted)."""
        return (min(a, b), max(a, b))

    @property
    def churn_count(self) -> int:
        return self.churned_count

    def refresh_npub(self, node_id: str) -> str | None:
        """Query a node's current npub and update the cache.

        Returns the npub or None if the query failed.
        """
        container = self.topology.container_name(node_id)
        status = query_status(container)
        if status and "npub" in status:
            npub = status["npub"]
            self.npub_cache[node_id] = npub
            return npub
        return None

    def refresh_all_npubs(self):
        """Populate npub cache for all nodes."""
        for node_id in self.topology.nodes:
            if node_id not in self.down_nodes:
                self.refresh_npub(node_id)
        log.info(
            "Cached npubs for %d/%d nodes",
            len(self.npub_cache),
            len(self.topology.nodes),
        )

    def maybe_churn(self):
        """Disconnect a random active link, then connect a random new pair."""
        # Skip if too many nodes are down
        up_nodes = [n for n in self.topology.nodes if n not in self.down_nodes]
        if len(up_nodes) < 3:
            return

        # Phase 1: Disconnect a random active link between up nodes
        candidates = [
            (a, b)
            for a, b in self.active_edges
            if a not in self.down_nodes and b not in self.down_nodes
        ]
        if candidates:
            edge = self.rng.choice(candidates)
            if self._disconnect_edge(edge[0], edge[1]):
                self.active_edges.discard(self._canonical(edge[0], edge[1]))
                self.churned_count += 1

        # Phase 2: Connect a random pair that isn't currently connected
        non_edges = []
        for i, a in enumerate(up_nodes):
            for b in up_nodes[i + 1 :]:
                if self._canonical(a, b) not in self.active_edges:
                    non_edges.append((a, b))

        if non_edges:
            a, b = self.rng.choice(non_edges)
            if self._connect_edge(a, b):
                self.active_edges.add(self._canonical(a, b))

    def _disconnect_edge(self, a: str, b: str) -> bool:
        """Disconnect both sides of a link."""
        npub_a = self.npub_cache.get(a)
        npub_b = self.npub_cache.get(b)
        if not npub_a or not npub_b:
            log.debug("Missing npub for %s or %s, skipping disconnect", a, b)
            return False

        container_a = self.topology.container_name(a)
        container_b = self.topology.container_name(b)

        ok_a = send_command(container_a, "disconnect", {"npub": npub_b})
        ok_b = send_command(container_b, "disconnect", {"npub": npub_a})

        if ok_a is not None or ok_b is not None:
            log.info("Peer DISCONNECT: %s -- %s", a, b)
            return True

        log.debug("Disconnect failed for %s -- %s", a, b)
        return False

    def _connect_edge(self, a: str, b: str) -> bool:
        """Connect both sides of a new link (mutual outbound)."""
        npub_a = self.npub_cache.get(a)
        npub_b = self.npub_cache.get(b)
        if not npub_a or not npub_b:
            log.debug("Missing npub for %s or %s, skipping connect", a, b)
            return False

        # Use UDP transport with the node's Docker IP
        ip_a = self.topology.nodes[a].docker_ip
        ip_b = self.topology.nodes[b].docker_ip
        port = 2121  # Default UDP port

        container_a = self.topology.container_name(a)
        container_b = self.topology.container_name(b)

        # Node A connects to B
        ok_a = send_command(
            container_a,
            "connect",
            {"npub": npub_b, "address": f"{ip_b}:{port}", "transport": "udp"},
        )

        # Node B connects to A
        ok_b = send_command(
            container_b,
            "connect",
            {"npub": npub_a, "address": f"{ip_a}:{port}", "transport": "udp"},
        )

        if ok_a is not None or ok_b is not None:
            log.info("Peer CONNECT: %s -- %s (udp)", a, b)
            return True

        log.debug("Connect failed for %s -- %s", a, b)
        return False

    def restore_all(self):
        """No-op for teardown — peer connections are ephemeral."""
        pass
