"""Node churn simulation via docker stop/start.

Simulates node loss and recovery by stopping and restarting containers.
When a node restarts, its FIPS process starts fresh — all peer
connections, sessions, and routing state are lost. Peers detect the
loss via handshake/link timeouts and reconverge the spanning tree.

After restart, netem rules must be re-applied since tc state is lost
when the container stops.
"""

from __future__ import annotations

import logging
import random
import time
from collections import deque
from dataclasses import dataclass, field

from .docker_exec import docker_exec_quiet, is_container_running
from .scenario import NodeChurnConfig
from .topology import SimTopology

log = logging.getLogger(__name__)


@dataclass
class NodeState:
    node_id: str
    is_down: bool = False
    down_since: float | None = None
    restore_at: float | None = None


class NodeManager:
    """Manages node stop/start lifecycle."""

    def __init__(
        self,
        topology: SimTopology,
        config: NodeChurnConfig,
        rng: random.Random,
        netem_mgr=None,
        down_nodes: set[str] | None = None,
        veth_mgr=None,
    ):
        self.topology = topology
        self.config = config
        self.rng = rng
        self.netem_mgr = netem_mgr
        self.veth_mgr = veth_mgr
        self.down_nodes = down_nodes or set()
        self.node_states: dict[str, NodeState] = {
            nid: NodeState(node_id=nid) for nid in topology.nodes
        }

    @property
    def down_count(self) -> int:
        return sum(1 for ns in self.node_states.values() if ns.is_down)

    def maybe_kill(self):
        """Attempt to stop a random node."""
        if self.down_count >= self.config.max_down_nodes:
            log.debug(
                "At max_down_nodes (%d), skipping churn",
                self.config.max_down_nodes,
            )
            return

        # Candidate: any node that's currently up
        up_nodes = [nid for nid, ns in self.node_states.items() if not ns.is_down]
        if not up_nodes:
            return

        self.rng.shuffle(up_nodes)

        for node_id in up_nodes:
            if self.config.protect_connectivity and self._would_disconnect(node_id):
                log.debug("Skipping %s (would disconnect graph)", node_id)
                continue

            down_duration = self.rng.uniform(
                self.config.down_duration_secs.min,
                self.config.down_duration_secs.max,
            )
            self._stop_node(node_id, down_duration)
            return

        log.debug("No safe node to kill (all would disconnect)")

    def restore_expired(self):
        """Restart nodes whose down duration has expired."""
        now = time.time()
        for nid, state in self.node_states.items():
            if state.is_down and state.restore_at and now >= state.restore_at:
                self._start_node(nid)

    def restore_all(self):
        """Restart all stopped nodes (for teardown — needed for log collection)."""
        for nid, state in list(self.node_states.items()):
            if state.is_down:
                self._start_node(nid)

    def _stop_node(self, node_id: str, duration: float):
        """Stop a container."""
        container = self.topology.container_name(node_id)
        docker_exec_quiet(container, "kill 1", timeout=5)  # SIGTERM to PID 1
        # Use docker stop with a short grace period
        import subprocess

        subprocess.run(
            ["docker", "stop", "-t", "2", container],
            capture_output=True,
            timeout=15,
        )

        now = time.time()
        state = self.node_states[node_id]
        state.is_down = True
        state.down_since = now
        state.restore_at = now + duration

        # Tell other managers to skip this node
        self.down_nodes.add(node_id)

        log.info("Node STOPPED: %s (restore in %.0fs)", node_id, duration)

    def _start_node(self, node_id: str):
        """Start a stopped container and re-apply netem."""
        container = self.topology.container_name(node_id)
        import subprocess

        result = subprocess.run(
            ["docker", "start", container],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            log.warning("Failed to start %s: %s", container, result.stderr)
            return

        state = self.node_states[node_id]
        down_for = time.time() - state.down_since if state.down_since else 0
        state.is_down = False
        state.down_since = None
        state.restore_at = None

        # Clear the down-node flag before re-applying netem
        self.down_nodes.discard(node_id)

        log.info("Node STARTED: %s (was down %.0fs)", node_id, down_for)

        # Re-create veth pairs (container restart destroys netns)
        if self.veth_mgr:
            time.sleep(1)
            self.veth_mgr.setup_node(node_id)

        # Re-apply netem after a brief delay for the container to initialize
        if self.netem_mgr:
            if not self.veth_mgr:
                time.sleep(1)
            self.netem_mgr.setup_node(node_id)

    def _would_disconnect(self, node_id: str) -> bool:
        """Check if removing this node (plus currently-down nodes) disconnects the graph.

        Builds the subgraph of currently-up nodes (excluding the candidate)
        and checks connectivity via BFS.
        """
        # Active nodes: up and not the candidate
        active_nodes = set()
        for nid, state in self.node_states.items():
            if not state.is_down and nid != node_id:
                active_nodes.add(nid)

        if len(active_nodes) <= 1:
            return True  # Can't remove from a 1-node graph

        # Build adjacency for active nodes only
        adj: dict[str, list[str]] = {nid: [] for nid in active_nodes}
        for a, b in self.topology.edges:
            if a in active_nodes and b in active_nodes:
                adj[a].append(b)
                adj[b].append(a)

        # BFS
        start = next(iter(active_nodes))
        visited = set()
        queue = deque([start])
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            for neighbor in adj[node]:
                if neighbor not in visited:
                    queue.append(neighbor)

        return len(visited) < len(active_nodes)
