"""Link up/down simulation via netem 100% loss.

Simulates link failures by setting netem to 100% packet loss on the
specific tc class for that peer. Requires the NetemManager to have
already set up per-link classful qdiscs. Includes connectivity
protection to prevent graph partitioning.

The flap is recorded in the NetemManager's per-direction state
(``held_down``) rather than here, so every path that re-installs a
qdisc (a node restart's re-apply, a mutation) keeps the link down for
the flap's declared length.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field

from .docker_exec import docker_exec_quiet, is_container_running
from .scenario import LinkFlapsConfig
from .topology import SimTopology, veth_interface_name

log = logging.getLogger(__name__)

IFACE = "eth0"


@dataclass
class LinkState:
    edge: tuple[str, str]  # (node_a, node_b) — canonical sorted order
    is_down: bool = False
    down_since: float | None = None
    restore_at: float | None = None


class LinkManager:
    """Manages link up/down state using tc netem 100% loss."""

    def __init__(
        self,
        topology: SimTopology,
        config: LinkFlapsConfig,
        rng: random.Random,
        netem_mgr=None,
    ):
        self.topology = topology
        self.config = config
        self.rng = rng
        self.netem_mgr = netem_mgr  # Optional: for coordinated tc manipulation
        self.link_states: dict[tuple[str, str], LinkState] = {
            edge: LinkState(edge=edge) for edge in topology.edges
        }
        # Every edge taken down or restored, as (epoch seconds, "down" |
        # "up", a, b). The switch-latency assertion reads the down edges
        # against the nodes' own log timestamps, so this is wall-clock time
        # (the containers share the host clock).
        self.flap_events: list[tuple[float, str, str, str]] = []

    @property
    def down_count(self) -> int:
        return sum(1 for ls in self.link_states.values() if ls.is_down)

    def maybe_flap(self):
        """Attempt to bring down a random link."""
        if self.down_count >= self.config.max_down_links:
            log.debug("At max_down_links (%d), skipping flap", self.config.max_down_links)
            return

        # Pick a random up link whose endpoints are both running
        down = self.netem_mgr.down_nodes if self.netem_mgr else set()
        up_links = [
            e for e, ls in self.link_states.items()
            if not ls.is_down and e[0] not in down and e[1] not in down
            and (
                self.config.only_transport is None
                or self.topology.transport_for_edge(*e) == self.config.only_transport
            )
        ]
        if not up_links:
            return

        self.rng.shuffle(up_links)

        for edge in up_links:
            # Connectivity protection
            if self.config.protect_connectivity and self._would_disconnect(edge):
                log.debug("Skipping %s-%s (would disconnect graph)", edge[0], edge[1])
                continue

            # Bring it down
            down_duration = self.rng.uniform(
                self.config.down_duration_secs.min,
                self.config.down_duration_secs.max,
            )
            self._link_down(edge, down_duration)
            return

        log.debug("No safe link to flap (all would disconnect)")

    def restore_expired(self):
        """Restore links whose down duration has expired."""
        now = time.time()
        for edge, state in self.link_states.items():
            if state.is_down and state.restore_at and now >= state.restore_at:
                self._link_up(edge)

    def restore_all(self):
        """Restore all downed links (for teardown)."""
        for edge, state in list(self.link_states.items()):
            if state.is_down:
                self._link_up(edge)

    def _link_down(self, edge: tuple[str, str], duration: float):
        """Simulate link failure by setting netem to 100% loss on both directions."""
        a, b = edge
        state = self.link_states[edge]

        self._set_held(a, b, True)
        self._set_held(b, a, True)

        now = time.time()
        state.is_down = True
        state.down_since = now
        state.restore_at = now + duration
        self.flap_events.append((now, "down", a, b))

        log.info("Link DOWN: %s -- %s (restore in %.0fs)", a, b, duration)

    def _link_up(self, edge: tuple[str, str]):
        """Restore link by re-installing each direction's current netem params.

        The current params include any mutation recorded during the flap.
        """
        a, b = edge
        state = self.link_states[edge]

        self._set_held(a, b, False)
        self._set_held(b, a, False)

        down_for = time.time() - state.down_since if state.down_since else 0
        self.flap_events.append((time.time(), "up", a, b))
        state.is_down = False
        state.down_since = None
        state.restore_at = None

        log.info("Link UP: %s -- %s (was down %.0fs)", a, b, down_for)

    def _set_held(self, src_node: str, dst_node: str, held: bool):
        """Mark the src->dst direction held down (or not) and install it.

        The flag is set whether or not the container is running, so a node
        that restarts during or after the flap re-installs the right params.
        Whether to issue tc now is decided by the live running check alone:
        the NetemManager's down_nodes set is not a reliable liveness signal
        (its only writers are the safety nets here and in _update_link, and
        nothing clears it when a node restarts).

        Transport-aware: UDP links use tc class on eth0, Ethernet links
        use tc qdisc replace on the dedicated veth interface.
        """
        if not self.netem_mgr:
            return

        container = self.topology.container_name(src_node)
        transport = self.topology.transport_for_edge(src_node, dst_node)

        if self.topology.is_veth_transport(transport):
            iface = veth_interface_name(src_node, dst_node)
            state = self.netem_mgr.veth_states.get(container, {}).get(iface)
            if state is None:
                log.warning("No veth netem state for %s -> %s (%s)", src_node, dst_node, iface)
                return
            cmd = f"tc qdisc replace dev {iface} root netem "
        else:
            dest_ip = self.topology.nodes[dst_node].docker_ip
            state = self.netem_mgr.states.get(container, {}).get(dest_ip)
            if state is None:
                log.warning("No netem state for %s -> %s", src_node, dst_node)
                return
            cmd = (
                f"tc qdisc replace dev {IFACE} parent {state.class_id} "
                f"handle {state.netem_handle} netem "
            )

        state.held_down = held

        # Safety net: detect containers that crashed outside of NodeManager.
        # The restart's setup_node installs state.tc_args() instead.
        if not is_container_running(container):
            log.debug(
                "Container %s not running (unexpected), marking %s as down",
                container,
                src_node,
            )
            self.netem_mgr.down_nodes.add(src_node)
            return

        docker_exec_quiet(container, cmd + state.tc_args())

    def _would_disconnect(self, edge: tuple[str, str]) -> bool:
        """Check if removing this edge (plus currently-down edges) disconnects the graph."""
        # Build set of active edges (excluding already-down links and the candidate)
        active_edges = set()
        for e, state in self.link_states.items():
            if not state.is_down and e != edge:
                active_edges.add(e)

        # BFS on active edges
        if not self.topology.nodes:
            return True

        adj: dict[str, list[str]] = {nid: [] for nid in self.topology.nodes}
        for a, b in active_edges:
            adj[a].append(b)
            adj[b].append(a)

        start = next(iter(self.topology.nodes))
        visited = set()
        queue = [start]
        while queue:
            node = queue.pop()
            if node in visited:
                continue
            visited.add(node)
            for neighbor in adj[node]:
                if neighbor not in visited:
                    queue.append(neighbor)

        return len(visited) < len(self.topology.nodes)
