"""Per-link network impairment via tc HTB + netem + u32 filters.

Each container gets an HTB root qdisc on eth0 with one class per peer.
Each class has a netem leaf qdisc for that specific link's impairment.
u32 filters match destination IP to direct traffic to the right class.

    eth0 root (HTB 1:)
    ├── class 1:1  → netem 11: (peer 1) ← u32 filter: dst=<peer1_ip>
    ├── class 1:2  → netem 12: (peer 2) ← u32 filter: dst=<peer2_ip>
    └── class 1:99 → pfifo (default, no impairment)
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field

from .docker_exec import docker_exec_quiet, is_container_running
from .scenario import BandwidthConfig, LinkPolicyOverride, NetemConfig, NetemPolicy
from .topology import SimTopology, veth_interface_name

log = logging.getLogger(__name__)

IFACE = "eth0"


@dataclass
class NetemParams:
    """Concrete netem parameters for one link direction."""

    delay_ms: int = 0
    jitter_ms: int = 0
    loss_pct: float = 0.0
    duplicate_pct: float = 0.0
    reorder_pct: float = 0.0
    corrupt_pct: float = 0.0

    def to_tc_args(self) -> str:
        """Build the netem arguments string for tc."""
        parts = []
        if self.delay_ms > 0:
            if self.jitter_ms > 0:
                parts.append(f"delay {self.delay_ms}ms {self.jitter_ms}ms")
            else:
                parts.append(f"delay {self.delay_ms}ms")
        if self.loss_pct > 0:
            parts.append(f"loss {self.loss_pct:.1f}%")
        if self.duplicate_pct > 0:
            parts.append(f"duplicate {self.duplicate_pct:.1f}%")
        if self.reorder_pct > 0 and self.delay_ms > 0:
            parts.append(f"reorder {self.reorder_pct:.1f}%")
        if self.corrupt_pct > 0:
            parts.append(f"corrupt {self.corrupt_pct:.1f}%")
        return " ".join(parts) if parts else "delay 0ms"


@dataclass
class LinkNetemState:
    """Tracks the netem state for a single link direction (one container's view)."""

    container: str
    dest_ip: str
    class_id: str  # e.g., "1:1"
    netem_handle: str  # e.g., "11:"
    params: NetemParams = field(default_factory=NetemParams)
    rate_mbit: int = 0  # 0 = unlimited (1gbit default)


@dataclass
class VethNetemState:
    """Tracks the netem state for a veth interface (Ethernet link direction)."""

    container: str
    iface: str  # e.g., "ve-n01-n02"
    params: NetemParams = field(default_factory=NetemParams)


class NetemManager:
    """Manages per-link netem impairment across all containers."""

    def __init__(
        self,
        topology: SimTopology,
        config: NetemConfig,
        rng: random.Random,
        bandwidth: BandwidthConfig | None = None,
    ):
        self.topology = topology
        self.config = config
        self.rng = rng
        # Per-container, per-dest-ip netem state (UDP links on eth0)
        self.states: dict[str, dict[str, LinkNetemState]] = {}
        # Per-container, per-veth netem state (Ethernet links)
        self.veth_states: dict[str, dict[str, VethNetemState]] = {}
        # Nodes currently down (updated by NodeManager) — skip tc ops on these
        self.down_nodes: set[str] = set()
        # Per-edge bandwidth: (node_a, node_b) -> rate in mbit
        self._edge_rates: dict[tuple[str, str], int] = {}
        if bandwidth and bandwidth.enabled:
            for a, b in topology.edges:
                rate = rng.choice(bandwidth.tiers_mbps)
                self._edge_rates[(a, b)] = rate
                self._edge_rates[(b, a)] = rate
        # Per-edge policy overrides: canonical "nXX-nYY" -> NetemPolicy
        # Build a set of canonical edge strings for validation
        topo_edge_strs = {"-".join(sorted([a, b])) for a, b in topology.edges}
        self._edge_overrides: dict[str, NetemPolicy] = {}
        for override in config.link_policies:
            policy = override.policy
            if policy is None and override.policy_name:
                policy = config.mutation.policies.get(override.policy_name)
            if policy is None:
                continue
            for edge_str in override.edges:
                if edge_str not in topo_edge_strs:
                    log.warning(
                        "link_policy edge %s not in topology — override ignored",
                        edge_str,
                    )
                self._edge_overrides[edge_str] = policy
        if self._edge_overrides:
            log.info(
                "Per-link policy overrides: %d edges",
                len(self._edge_overrides),
            )

    def _htb_rate(self, node_id: str, peer_id: str) -> str:
        """Return the HTB rate string for a link direction."""
        rate = self._edge_rates.get((node_id, peer_id), 0)
        return f"{rate}mbit" if rate > 0 else "1gbit"

    def _policy_for_edge(self, node_a: str, node_b: str) -> NetemPolicy:
        """Return the netem policy for an edge, checking overrides first."""
        canonical = "-".join(sorted([node_a, node_b]))
        if canonical in self._edge_overrides:
            return self._edge_overrides[canonical]
        return self.config.default_policy

    def setup_initial(self):
        """Set up HTB qdiscs and initial netem on all containers.

        UDP peers use HTB + u32 filters on eth0. Ethernet peers use a
        simple root netem qdisc on their dedicated veth interface.
        """
        if self._edge_rates:
            log.info("Bandwidth pacing enabled (%d edges with rate limits)",
                     len(self._edge_rates) // 2)

        for node_id in sorted(self.topology.nodes):
            node = self.topology.nodes[node_id]
            container = self.topology.container_name(node_id)

            # Split peers by transport type: IP-based (UDP/TCP) vs Ethernet (veth)
            ip_peers = {}
            eth_peers = []
            for peer_id in sorted(node.peers):
                transport = self.topology.transport_for_edge(node_id, peer_id)
                if transport == "ethernet":
                    eth_peers.append(peer_id)
                else:
                    ip_peers[peer_id] = self.topology.nodes[peer_id].docker_ip

            # --- IP-based peers (UDP/TCP): HTB + u32 on eth0 ---
            if ip_peers:
                cmds = [f"tc qdisc del dev {IFACE} root 2>/dev/null || true"]
                cmds.append(
                    f"tc qdisc add dev {IFACE} root handle 1: htb default 99"
                )
                cmds.append(
                    f"tc class add dev {IFACE} parent 1: classid 1:99 htb rate 1gbit"
                )

                container_states = {}

                for idx, (peer_id, dest_ip) in enumerate(ip_peers.items(), start=1):
                    class_id = f"1:{idx}"
                    netem_handle = f"{idx + 10}:"

                    policy = self._policy_for_edge(node_id, peer_id)
                    params = self._sample_policy(policy)

                    rate = self._htb_rate(node_id, peer_id)
                    rate_mbit = self._edge_rates.get((node_id, peer_id), 0)
                    cmds.append(
                        f"tc class add dev {IFACE} parent 1: classid {class_id} htb rate {rate}"
                    )
                    cmds.append(
                        f"tc qdisc add dev {IFACE} parent {class_id} "
                        f"handle {netem_handle} netem {params.to_tc_args()}"
                    )
                    cmds.append(
                        f"tc filter add dev {IFACE} parent 1: protocol ip "
                        f"prio {idx} u32 match ip dst {dest_ip}/32 flowid {class_id}"
                    )

                    state = LinkNetemState(
                        container=container,
                        dest_ip=dest_ip,
                        class_id=class_id,
                        netem_handle=netem_handle,
                        params=params,
                        rate_mbit=rate_mbit,
                    )
                    container_states[dest_ip] = state

                full_cmd = " && ".join(cmds)
                result = docker_exec_quiet(container, full_cmd, timeout=30)
                if result is not None:
                    log.info(
                        "Configured per-link netem on %s (%d IP peers)",
                        container,
                        len(ip_peers),
                    )
                else:
                    log.warning("Failed to configure netem on %s", container)

                self.states[container] = container_states

            # --- Ethernet peers: simple netem on veth ---
            if eth_peers:
                container_veth_states = {}
                for peer_id in eth_peers:
                    iface = veth_interface_name(node_id, peer_id)
                    policy = self._policy_for_edge(node_id, peer_id)
                    params = self._sample_policy(policy)

                    cmd = (
                        f"tc qdisc del dev {iface} root 2>/dev/null || true && "
                        f"tc qdisc add dev {iface} root netem {params.to_tc_args()}"
                    )
                    result = docker_exec_quiet(container, cmd, timeout=10)
                    if result is not None:
                        log.debug("Veth netem on %s:%s -> %s", container, iface, params.to_tc_args())
                    else:
                        log.warning("Failed to configure veth netem on %s:%s", container, iface)

                    container_veth_states[iface] = VethNetemState(
                        container=container,
                        iface=iface,
                        params=params,
                    )

                self.veth_states[container] = container_veth_states
                log.info(
                    "Configured veth netem on %s (%d Ethernet peers)",
                    container,
                    len(eth_peers),
                )

    def setup_node(self, node_id: str):
        """Re-apply HTB/netem/filters for a single node (after container restart).

        Uses the saved state from the initial setup so the node gets the same
        class IDs and current netem params it had before going down.
        """
        container = self.topology.container_name(node_id)

        # Re-apply IP-based netem (eth0 HTB + u32) for UDP/TCP peers
        container_states = self.states.get(container)
        if container_states:
            cmds = [f"tc qdisc del dev {IFACE} root 2>/dev/null || true"]
            cmds.append(
                f"tc qdisc add dev {IFACE} root handle 1: htb default 99"
            )
            cmds.append(
                f"tc class add dev {IFACE} parent 1: classid 1:99 htb rate 1gbit"
            )

            for dest_ip, state in container_states.items():
                rate = f"{state.rate_mbit}mbit" if state.rate_mbit > 0 else "1gbit"
                cmds.append(
                    f"tc class add dev {IFACE} parent 1: classid {state.class_id} htb rate {rate}"
                )
                cmds.append(
                    f"tc qdisc add dev {IFACE} parent {state.class_id} "
                    f"handle {state.netem_handle} netem {state.params.to_tc_args()}"
                )
                prio = state.class_id.split(":")[1]
                cmds.append(
                    f"tc filter add dev {IFACE} parent 1: protocol ip "
                    f"prio {prio} u32 match ip dst {dest_ip}/32 flowid {state.class_id}"
                )

            full_cmd = " && ".join(cmds)
            result = docker_exec_quiet(container, full_cmd, timeout=30)
            if result is not None:
                log.info(
                    "Re-applied IP netem on %s (%d peers)",
                    container,
                    len(container_states),
                )
            else:
                log.warning("Failed to re-apply IP netem on %s", container)

        # Re-apply Ethernet veth netem
        veth_states = self.veth_states.get(container)
        if veth_states:
            for iface, state in veth_states.items():
                cmd = (
                    f"tc qdisc del dev {iface} root 2>/dev/null || true && "
                    f"tc qdisc add dev {iface} root netem {state.params.to_tc_args()}"
                )
                result = docker_exec_quiet(container, cmd, timeout=10)
                if result is not None:
                    log.debug("Re-applied veth netem on %s:%s", container, iface)
                else:
                    log.warning("Failed to re-apply veth netem on %s:%s", container, iface)
            log.info(
                "Re-applied veth netem on %s (%d Ethernet peers)",
                container,
                len(veth_states),
            )

    def mutate(self):
        """Randomly mutate netem params on a fraction of links."""
        if not self.config.mutation.policies:
            return

        # Only consider edges where both endpoints are up
        live_edges = [
            (a, b) for a, b in self.topology.edges
            if a not in self.down_nodes and b not in self.down_nodes
        ]
        if not live_edges:
            return

        num_to_mutate = max(1, int(len(live_edges) * self.config.mutation.fraction))
        edges_to_mutate = self.rng.sample(
            live_edges, min(num_to_mutate, len(live_edges))
        )

        # Pick a random policy for this mutation round
        policy_name = self.rng.choice(list(self.config.mutation.policies.keys()))
        policy = self.config.mutation.policies[policy_name]

        log.info(
            "Netem mutation: %d links -> '%s' policy",
            len(edges_to_mutate),
            policy_name,
        )

        for a, b in edges_to_mutate:
            params = self._sample_policy(policy)
            self._update_link(a, b, params)

    def _update_link(self, node_a: str, node_b: str, params: NetemParams):
        """Update netem on both directions of a link."""
        transport = self.topology.transport_for_edge(node_a, node_b)

        for src, dst in [(node_a, node_b), (node_b, node_a)]:
            if src in self.down_nodes:
                continue
            container = self.topology.container_name(src)

            # Safety net: detect containers that crashed outside of NodeManager
            if not is_container_running(container):
                log.debug(
                    "Container %s not running (unexpected), marking %s as down",
                    container,
                    src,
                )
                self.down_nodes.add(src)
                continue

            if transport == "ethernet":
                # Ethernet: simple netem replace on veth
                iface = veth_interface_name(src, dst)
                veth_states = self.veth_states.get(container, {})
                state = veth_states.get(iface)
                if state is None:
                    continue
                cmd = f"tc qdisc replace dev {iface} root netem {params.to_tc_args()}"
                result = docker_exec_quiet(container, cmd)
                if result is not None:
                    state.params = params
                    log.debug("Updated veth netem %s:%s -> %s", src, iface, params.to_tc_args())
            else:
                # IP-based (UDP/TCP): HTB class-based netem on eth0
                dest_ip = self.topology.nodes[dst].docker_ip
                states = self.states.get(container, {})
                state = states.get(dest_ip)
                if state is None:
                    continue
                cmd = (
                    f"tc qdisc replace dev {IFACE} parent {state.class_id} "
                    f"handle {state.netem_handle} netem {params.to_tc_args()}"
                )
                result = docker_exec_quiet(container, cmd)
                if result is not None:
                    state.params = params
                    log.debug(
                        "Updated netem %s -> %s: %s",
                        src,
                        dst,
                        params.to_tc_args(),
                    )

    def _sample_policy(self, policy: NetemPolicy) -> NetemParams:
        """Sample concrete params from a policy's ranges."""
        return NetemParams(
            delay_ms=int(self.rng.uniform(policy.delay_ms[0], policy.delay_ms[1])),
            jitter_ms=int(self.rng.uniform(policy.jitter_ms[0], policy.jitter_ms[1])),
            loss_pct=round(
                self.rng.uniform(policy.loss_pct[0], policy.loss_pct[1]), 1
            ),
            duplicate_pct=round(
                self.rng.uniform(policy.duplicate_pct[0], policy.duplicate_pct[1]), 1
            ),
            reorder_pct=round(
                self.rng.uniform(policy.reorder_pct[0], policy.reorder_pct[1]), 1
            ),
            corrupt_pct=round(
                self.rng.uniform(policy.corrupt_pct[0], policy.corrupt_pct[1]), 1
            ),
        )
