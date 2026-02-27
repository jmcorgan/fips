"""Scenario YAML loading and validation."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import yaml


@dataclass
class Range:
    """A min/max range for stochastic parameters."""

    min: float
    max: float

    def validate(self, name: str):
        if self.min > self.max:
            raise ValueError(f"{name}: min ({self.min}) > max ({self.max})")
        if self.min < 0:
            raise ValueError(f"{name}: min ({self.min}) must be >= 0")


VALID_TRANSPORTS = ("udp", "ethernet", "tcp")


@dataclass
class TopologyConfig:
    num_nodes: int = 10
    algorithm: str = "random_geometric"
    params: dict = field(default_factory=dict)
    ensure_connected: bool = True
    subnet: str = "172.20.0.0/24"
    ip_start: int = 10
    default_transport: str = "udp"
    # Optional transport mix for random topologies: {transport: weight}.
    # When set, each edge is randomly assigned a transport based on weights.
    # Only valid for non-explicit algorithms (explicit uses per-edge syntax).
    transport_mix: dict[str, float] | None = None


@dataclass
class NetemPolicy:
    delay_ms: tuple[float, float] = (0, 0)
    jitter_ms: tuple[float, float] = (0, 0)
    loss_pct: tuple[float, float] = (0, 0)
    duplicate_pct: tuple[float, float] = (0, 0)
    reorder_pct: tuple[float, float] = (0, 0)
    corrupt_pct: tuple[float, float] = (0, 0)


@dataclass
class NetemMutationConfig:
    interval_secs: Range = field(default_factory=lambda: Range(15, 30))
    fraction: float = 0.3
    policies: dict[str, NetemPolicy] = field(default_factory=dict)


@dataclass
class LinkPolicyOverride:
    """Per-edge netem policy override.

    Edges are specified as "nXX-nYY" strings in canonical form (sorted
    alphabetically). Either ``policy`` (inline) or ``policy_name``
    (reference to a named mutation policy) must be set, not both.
    """

    edges: list[str] = field(default_factory=list)
    policy: NetemPolicy | None = None
    policy_name: str | None = None


@dataclass
class NetemConfig:
    enabled: bool = False
    default_policy: NetemPolicy = field(default_factory=NetemPolicy)
    link_policies: list[LinkPolicyOverride] = field(default_factory=list)
    mutation: NetemMutationConfig = field(default_factory=NetemMutationConfig)


@dataclass
class LinkFlapsConfig:
    enabled: bool = False
    interval_secs: Range = field(default_factory=lambda: Range(20, 60))
    max_down_links: int = 2
    down_duration_secs: Range = field(default_factory=lambda: Range(10, 30))
    protect_connectivity: bool = True


@dataclass
class TrafficConfig:
    enabled: bool = False
    max_concurrent: int = 3
    interval_secs: Range = field(default_factory=lambda: Range(10, 30))
    duration_secs: Range = field(default_factory=lambda: Range(5, 15))
    parallel_streams: int = 4


@dataclass
class NodeChurnConfig:
    enabled: bool = False
    interval_secs: Range = field(default_factory=lambda: Range(60, 180))
    max_down_nodes: int = 1
    down_duration_secs: Range = field(default_factory=lambda: Range(30, 90))
    protect_connectivity: bool = True


@dataclass
class BandwidthConfig:
    """Per-link bandwidth pacing via HTB rate limiting.

    When enabled, each link is randomly assigned a rate from the tiers list.
    # TODO: Add structured bandwidth assignment (e.g., per-node roles,
    # asymmetric uplink/downlink, tiered by topology distance, or
    # time-varying bandwidth mutations similar to netem mutation).
    """

    enabled: bool = False
    tiers_mbps: list[int] = field(default_factory=lambda: [1, 10, 100, 1000])


@dataclass
class LoggingConfig:
    rust_log: str = "info"
    output_dir: str = "./sim-results"


@dataclass
class Scenario:
    name: str = "unnamed"
    seed: int = 42
    duration_secs: int = 120
    topology: TopologyConfig = field(default_factory=TopologyConfig)
    netem: NetemConfig = field(default_factory=NetemConfig)
    link_flaps: LinkFlapsConfig = field(default_factory=LinkFlapsConfig)
    traffic: TrafficConfig = field(default_factory=TrafficConfig)
    node_churn: NodeChurnConfig = field(default_factory=NodeChurnConfig)
    bandwidth: BandwidthConfig = field(default_factory=BandwidthConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    # Raw YAML dict appended to each generated FIPS node config.
    # Allows scenarios to override any FIPS config parameter
    # (e.g., node.tree.reeval_interval_secs).
    fips_overrides: dict = field(default_factory=dict)


def _parse_range(data, name: str) -> Range:
    """Parse a {min, max} dict into a Range."""
    if isinstance(data, dict):
        return Range(min=float(data["min"]), max=float(data["max"]))
    raise ValueError(f"{name}: expected {{min, max}} dict, got {type(data).__name__}")


def _parse_netem_policy(data: dict) -> NetemPolicy:
    """Parse a netem policy from a dict with [min, max] lists or {min, max} dicts."""
    policy = NetemPolicy()
    for attr in (
        "delay_ms",
        "jitter_ms",
        "loss_pct",
        "duplicate_pct",
        "reorder_pct",
        "corrupt_pct",
    ):
        if attr in data:
            val = data[attr]
            if isinstance(val, list) and len(val) == 2:
                setattr(policy, attr, (float(val[0]), float(val[1])))
            elif isinstance(val, dict):
                setattr(policy, attr, (float(val["min"]), float(val["max"])))
            else:
                raise ValueError(f"netem policy {attr}: expected [min, max] or {{min, max}}")
    return policy


def load_scenario(path: str) -> Scenario:
    """Load and validate a scenario from a YAML file."""
    with open(path) as f:
        raw = yaml.safe_load(f)

    s = Scenario()

    # Scenario section
    sc = raw.get("scenario", {})
    s.name = sc.get("name", os.path.splitext(os.path.basename(path))[0])
    s.seed = int(sc.get("seed", 42))
    s.duration_secs = int(sc.get("duration_secs", 120))

    # Topology section
    tc = raw.get("topology", {})
    s.topology.num_nodes = int(tc.get("num_nodes", 10))
    s.topology.algorithm = tc.get("algorithm", "random_geometric")
    s.topology.params = tc.get("params", {})
    s.topology.ensure_connected = tc.get("ensure_connected", True)
    s.topology.subnet = tc.get("subnet", "172.20.0.0/24")
    s.topology.ip_start = int(tc.get("ip_start", 10))
    s.topology.default_transport = tc.get("default_transport", "udp")
    if "transport_mix" in tc:
        mix = tc["transport_mix"]
        if not isinstance(mix, dict) or not mix:
            raise ValueError("topology.transport_mix must be a non-empty dict")
        s.topology.transport_mix = {str(k): float(v) for k, v in mix.items()}

    # Netem section
    nc = raw.get("netem", {})
    s.netem.enabled = nc.get("enabled", False)
    if "default_policy" in nc:
        s.netem.default_policy = _parse_netem_policy(nc["default_policy"])
    if "link_policies" in nc:
        for lp_data in nc["link_policies"]:
            override = LinkPolicyOverride(
                edges=lp_data.get("edges", []),
            )
            if "policy" in lp_data:
                override.policy = _parse_netem_policy(lp_data["policy"])
            if "policy_name" in lp_data:
                override.policy_name = lp_data["policy_name"]
            s.netem.link_policies.append(override)
    if "mutation" in nc:
        mc = nc["mutation"]
        s.netem.mutation.interval_secs = _parse_range(
            mc.get("interval_secs", {"min": 15, "max": 30}), "netem.mutation.interval_secs"
        )
        s.netem.mutation.fraction = float(mc.get("fraction", 0.3))
        if "policies" in mc:
            s.netem.mutation.policies = {
                name: _parse_netem_policy(pdata)
                for name, pdata in mc["policies"].items()
            }

    # Link flaps section
    lf = raw.get("link_flaps", {})
    s.link_flaps.enabled = lf.get("enabled", False)
    if "interval_secs" in lf:
        s.link_flaps.interval_secs = _parse_range(lf["interval_secs"], "link_flaps.interval_secs")
    s.link_flaps.max_down_links = int(lf.get("max_down_links", 2))
    if "down_duration_secs" in lf:
        s.link_flaps.down_duration_secs = _parse_range(
            lf["down_duration_secs"], "link_flaps.down_duration_secs"
        )
    s.link_flaps.protect_connectivity = lf.get("protect_connectivity", True)

    # Traffic section
    tf = raw.get("traffic", {})
    s.traffic.enabled = tf.get("enabled", False)
    s.traffic.max_concurrent = int(tf.get("max_concurrent", 3))
    if "interval_secs" in tf:
        s.traffic.interval_secs = _parse_range(tf["interval_secs"], "traffic.interval_secs")
    if "duration_secs" in tf:
        s.traffic.duration_secs = _parse_range(tf["duration_secs"], "traffic.duration_secs")
    s.traffic.parallel_streams = int(tf.get("parallel_streams", 4))

    # Node churn section
    nc2 = raw.get("node_churn", {})
    s.node_churn.enabled = nc2.get("enabled", False)
    if "interval_secs" in nc2:
        s.node_churn.interval_secs = _parse_range(nc2["interval_secs"], "node_churn.interval_secs")
    s.node_churn.max_down_nodes = int(nc2.get("max_down_nodes", 1))
    if "down_duration_secs" in nc2:
        s.node_churn.down_duration_secs = _parse_range(
            nc2["down_duration_secs"], "node_churn.down_duration_secs"
        )
    s.node_churn.protect_connectivity = nc2.get("protect_connectivity", True)

    # Bandwidth section
    bw = raw.get("bandwidth", {})
    s.bandwidth.enabled = bw.get("enabled", False)
    if "tiers_mbps" in bw:
        tiers = bw["tiers_mbps"]
        if not isinstance(tiers, list) or not tiers:
            raise ValueError("bandwidth.tiers_mbps must be a non-empty list")
        s.bandwidth.tiers_mbps = [int(t) for t in tiers]

    # Logging section
    lg = raw.get("logging", {})
    s.logging.rust_log = lg.get("rust_log", "info")
    s.logging.output_dir = lg.get("output_dir", "./sim-results")

    # FIPS config overrides (raw YAML dict appended to node configs)
    s.fips_overrides = raw.get("fips_overrides", {})

    # Validation
    _validate(s)

    return s


def _validate(s: Scenario):
    """Validate scenario constraints."""
    if s.topology.num_nodes < 2:
        raise ValueError("topology.num_nodes must be >= 2")
    if s.topology.num_nodes > 250:
        raise ValueError("topology.num_nodes must be <= 250 (subnet limit)")
    if s.topology.algorithm not in ("random_geometric", "erdos_renyi", "chain", "explicit"):
        raise ValueError(f"Unknown topology algorithm: {s.topology.algorithm}")
    if s.topology.default_transport not in VALID_TRANSPORTS:
        raise ValueError(
            f"topology.default_transport: '{s.topology.default_transport}' "
            f"not in {VALID_TRANSPORTS}"
        )
    if s.topology.transport_mix is not None:
        if s.topology.algorithm == "explicit":
            raise ValueError(
                "topology.transport_mix cannot be used with explicit algorithm "
                "(use per-edge transport syntax instead)"
            )
        for transport, weight in s.topology.transport_mix.items():
            if transport not in VALID_TRANSPORTS:
                raise ValueError(
                    f"topology.transport_mix: '{transport}' not in {VALID_TRANSPORTS}"
                )
            if weight <= 0:
                raise ValueError(
                    f"topology.transport_mix: weight for '{transport}' must be > 0"
                )
    if s.topology.algorithm == "explicit":
        adj = s.topology.params.get("adjacency")
        if not adj or not isinstance(adj, list):
            raise ValueError("explicit topology requires params.adjacency list")
        node_ids = set()
        for i, entry in enumerate(adj):
            if not isinstance(entry, (list, tuple)) or len(entry) not in (2, 3):
                raise ValueError(
                    f"explicit adjacency[{i}]: expected [nodeA, nodeB] or "
                    f"[nodeA, nodeB, transport], got {entry}"
                )
            node_ids.update(str(p) for p in entry[:2])
            if len(entry) == 3:
                transport = str(entry[2])
                if transport not in VALID_TRANSPORTS:
                    raise ValueError(
                        f"explicit adjacency[{i}]: transport '{transport}' "
                        f"not in {VALID_TRANSPORTS}"
                    )
        if len(node_ids) != s.topology.num_nodes:
            raise ValueError(
                f"explicit adjacency references {len(node_ids)} nodes "
                f"but num_nodes is {s.topology.num_nodes}"
            )
    if s.duration_secs < 1:
        raise ValueError("duration_secs must be >= 1")

    # Validate link_policies
    for i, lp in enumerate(s.netem.link_policies):
        if not lp.edges:
            raise ValueError(f"netem.link_policies[{i}]: edges list is empty")
        if lp.policy is not None and lp.policy_name is not None:
            raise ValueError(
                f"netem.link_policies[{i}]: specify policy or policy_name, not both"
            )
        if lp.policy is None and lp.policy_name is None:
            raise ValueError(
                f"netem.link_policies[{i}]: must specify policy or policy_name"
            )
        if lp.policy_name and lp.policy_name not in s.netem.mutation.policies:
            raise ValueError(
                f"netem.link_policies[{i}]: policy_name '{lp.policy_name}' "
                f"not found in mutation.policies"
            )

    # Validate ranges
    if s.netem.enabled and s.netem.mutation.policies:
        s.netem.mutation.interval_secs.validate("netem.mutation.interval_secs")
    if s.link_flaps.enabled:
        s.link_flaps.interval_secs.validate("link_flaps.interval_secs")
        s.link_flaps.down_duration_secs.validate("link_flaps.down_duration_secs")
    if s.traffic.enabled:
        s.traffic.interval_secs.validate("traffic.interval_secs")
        s.traffic.duration_secs.validate("traffic.duration_secs")
    if s.node_churn.enabled:
        s.node_churn.interval_secs.validate("node_churn.interval_secs")
        s.node_churn.down_duration_secs.validate("node_churn.down_duration_secs")
        if s.node_churn.max_down_nodes >= s.topology.num_nodes:
            raise ValueError("node_churn.max_down_nodes must be < topology.num_nodes")
    if s.bandwidth.enabled:
        for tier in s.bandwidth.tiers_mbps:
            if tier <= 0:
                raise ValueError(f"bandwidth.tiers_mbps: all values must be > 0, got {tier}")
