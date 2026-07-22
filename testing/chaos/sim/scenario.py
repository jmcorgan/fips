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
class PeerChurnConfig:
    """Peer-level topology churn via connect/disconnect commands.

    When enabled, periodically disconnects a random active link and
    connects a random unconnected node pair, causing the mesh topology
    to evolve over time.
    """

    enabled: bool = False
    interval_secs: Range = field(default_factory=lambda: Range(8, 12))
    ephemeral_fraction: float = 0.0


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
class IngressConfig:
    """Per-link ingress policing via tc ingress qdisc + policer.

    When enabled, each link gets an ingress policer that drops inbound
    packets exceeding the configured rate. Unlike egress HTB (which
    paces packets smoothly), the policer drops excess packets at the
    kernel level, creating bursty arrival patterns that can overflow
    small socket buffers and trigger SO_RXQ_OVFL kernel drops.
    """

    enabled: bool = False
    tiers_kbps: list[int] = field(default_factory=lambda: [1000])
    burst_bytes: int = 32000


@dataclass
class LinkSwapEdge:
    """One edge in a link-swap rotation.

    Edge is a canonical "nXX-nYY" string. ``policy`` names a policy
    in ``LinkSwapConfig.policies``.
    """

    edge: str = ""
    policy: str = ""


@dataclass
class LinkSwapConfig:
    """Deterministic asymmetric link-cost flapping.

    On each ``interval_secs``, the policies on every pair of edges in
    ``edges`` are swapped (cyclically rotated by one position). This
    differs from ``link_flaps`` (random link-down events) and
    ``netem.mutation`` (random per-edge policy mutation) by being a
    deterministic, periodic flip between two named netem policies on
    a fixed set of edges.

    Used to drive a downstream node to repeatedly switch parents on
    a fixed cadence — exercises the spanning-tree rebalance path
    without the noise of a random mutation walk.
    """

    enabled: bool = False
    interval_secs: float = 4.0
    policies: dict[str, NetemPolicy] = field(default_factory=dict)
    edges: list[LinkSwapEdge] = field(default_factory=list)


@dataclass
class BloomSendRateAssertion:
    """Trailing-window ceiling on per-node ``stats.bloom.sent`` delta."""

    window_secs: int = 30
    max_per_node: int = 30


@dataclass
class MinParentSwitchesAssertion:
    """Sanity guard: total parent switches across the run must be at
    least ``min_total``. Used to detect a misconfigured harness where
    the flap inducer is firing but the topology never produces a real
    parent-switch event (e.g., wrong root election).
    """

    min_total: int = 1


@dataclass
class AssertionsConfig:
    """Optional post-run assertions evaluated against control-socket data."""

    bloom_send_rate: BloomSendRateAssertion | None = None
    min_parent_switches: MinParentSwitchesAssertion | None = None


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
    peer_churn: PeerChurnConfig = field(default_factory=PeerChurnConfig)
    bandwidth: BandwidthConfig = field(default_factory=BandwidthConfig)
    ingress: IngressConfig = field(default_factory=IngressConfig)
    link_swap: LinkSwapConfig = field(default_factory=LinkSwapConfig)
    assertions: AssertionsConfig = field(default_factory=AssertionsConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    # Raw YAML dict appended to each generated FIPS node config.
    # Allows scenarios to override any FIPS config parameter
    # (e.g., node.tree.reeval_interval_secs).
    fips_overrides: dict = field(default_factory=dict)


# Keys each fixed-schema section understands. A key absent from these sets is a
# typo, and silently ignoring it leaves the block default-constructed while the
# YAML still looks correct — a mistyped "assertion:" disarms a scenario's only
# assertions, a mistyped "link_flap:" turns off the chaos it was meant to inject.
#
# Three mappings are deliberately NOT listed, because their keys are names the
# scenario author chooses rather than a schema: netem.mutation.policies,
# link_swap.policies and topology.transport_mix. Two sub-trees are passed through
# whole and are likewise not checked: fips_overrides and topology.params.
#
# NOTE: adding a new assertion type means adding it to _ASSERTION_KEYS below and
# giving it an entry here, or scenarios using it will be rejected at load.
_TOP_KEYS = {
    "scenario", "topology", "netem", "link_flaps", "traffic", "node_churn",
    "peer_churn", "bandwidth", "ingress", "link_swap", "assertions", "logging",
    "fips_overrides",
}
_SECTION_KEYS = {
    "scenario": {"name", "seed", "duration_secs"},
    "topology": {
        "num_nodes", "algorithm", "params", "ensure_connected", "subnet",
        "ip_start", "default_transport", "transport_mix",
    },
    "netem": {"enabled", "default_policy", "link_policies", "mutation"},
    "netem.link_policies[]": {"edges", "policy", "policy_name"},
    "netem.mutation": {"interval_secs", "fraction", "policies"},
    "link_flaps": {
        "enabled", "interval_secs", "max_down_links", "down_duration_secs",
        "protect_connectivity",
    },
    "traffic": {
        "enabled", "max_concurrent", "interval_secs", "duration_secs",
        "parallel_streams",
    },
    "node_churn": {
        "enabled", "interval_secs", "max_down_nodes", "down_duration_secs",
        "protect_connectivity",
    },
    "peer_churn": {"enabled", "interval_secs", "ephemeral_fraction"},
    "bandwidth": {"enabled", "tiers_mbps"},
    "ingress": {"enabled", "tiers_kbps", "burst_bytes"},
    "link_swap": {"enabled", "interval_secs", "policies", "edges"},
    "link_swap.edges[]": {"edge", "policy"},
    "assertions": {"bloom_send_rate", "min_parent_switches"},
    "logging": {"rust_log", "output_dir"},
}
_ASSERTION_KEYS = {
    "bloom_send_rate": {"window_secs", "max_per_node"},
    "min_parent_switches": {"min_total"},
}
_NETEM_POLICY_KEYS = {
    "delay_ms", "jitter_ms", "loss_pct", "duplicate_pct", "reorder_pct",
    "corrupt_pct",
}
_RANGE_KEYS = {"min", "max"}


def _reject_unknown(data, known, context: str):
    """Raise unless every key in `data` is one the loader understands."""
    if data is None:
        raise ValueError(
            f"{context}: section is present but empty; give it a body or remove it"
        )
    if not isinstance(data, dict):
        raise ValueError(f"{context}: expected a mapping, got {type(data).__name__}")
    unknown = sorted(str(k) for k in set(data) - set(known))
    if unknown:
        raise ValueError(
            f"{context}: unknown key(s): {', '.join(unknown)} "
            f"(known: {', '.join(sorted(known))})"
        )


def _parse_range(data, name: str) -> Range:
    """Parse a {min, max} dict into a Range."""
    if isinstance(data, dict):
        _reject_unknown(data, _RANGE_KEYS, name)
        return Range(min=float(data["min"]), max=float(data["max"]))
    raise ValueError(f"{name}: expected {{min, max}} dict, got {type(data).__name__}")


def _parse_netem_policy(data: dict, name: str = "netem policy") -> NetemPolicy:
    """Parse a netem policy from a dict with [min, max] lists or {min, max} dicts."""
    _reject_unknown(data, _NETEM_POLICY_KEYS, name)
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

    if raw is None:
        raise ValueError(f"{path}: file is empty")
    _reject_unknown(raw, _TOP_KEYS, "(top level)")

    s = Scenario()

    # Scenario section
    sc = raw.get("scenario", {})
    _reject_unknown(sc, _SECTION_KEYS["scenario"], "scenario")
    s.name = sc.get("name", os.path.splitext(os.path.basename(path))[0])
    s.seed = int(sc.get("seed", 42))
    s.duration_secs = int(sc.get("duration_secs", 120))

    # Topology section
    tc = raw.get("topology", {})
    _reject_unknown(tc, _SECTION_KEYS["topology"], "topology")
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
    _reject_unknown(nc, _SECTION_KEYS["netem"], "netem")
    s.netem.enabled = nc.get("enabled", False)
    if "default_policy" in nc:
        s.netem.default_policy = _parse_netem_policy(
            nc["default_policy"], "netem.default_policy"
        )
    if "link_policies" in nc:
        for lp_data in nc["link_policies"]:
            _reject_unknown(
                lp_data, _SECTION_KEYS["netem.link_policies[]"], "netem.link_policies[]"
            )
            override = LinkPolicyOverride(
                edges=lp_data.get("edges", []),
            )
            if "policy" in lp_data:
                override.policy = _parse_netem_policy(
                    lp_data["policy"], "netem.link_policies[].policy"
                )
            if "policy_name" in lp_data:
                override.policy_name = lp_data["policy_name"]
            s.netem.link_policies.append(override)
    if "mutation" in nc:
        mc = nc["mutation"]
        _reject_unknown(mc, _SECTION_KEYS["netem.mutation"], "netem.mutation")
        s.netem.mutation.interval_secs = _parse_range(
            mc.get("interval_secs", {"min": 15, "max": 30}), "netem.mutation.interval_secs"
        )
        s.netem.mutation.fraction = float(mc.get("fraction", 0.3))
        if "policies" in mc:
            s.netem.mutation.policies = {
                name: _parse_netem_policy(pdata, f"netem.mutation.policies.{name}")
                for name, pdata in mc["policies"].items()
            }

    # Link flaps section
    lf = raw.get("link_flaps", {})
    _reject_unknown(lf, _SECTION_KEYS["link_flaps"], "link_flaps")
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
    _reject_unknown(tf, _SECTION_KEYS["traffic"], "traffic")
    s.traffic.enabled = tf.get("enabled", False)
    s.traffic.max_concurrent = int(tf.get("max_concurrent", 3))
    if "interval_secs" in tf:
        s.traffic.interval_secs = _parse_range(tf["interval_secs"], "traffic.interval_secs")
    if "duration_secs" in tf:
        s.traffic.duration_secs = _parse_range(tf["duration_secs"], "traffic.duration_secs")
    s.traffic.parallel_streams = int(tf.get("parallel_streams", 4))

    # Node churn section
    nc2 = raw.get("node_churn", {})
    _reject_unknown(nc2, _SECTION_KEYS["node_churn"], "node_churn")
    s.node_churn.enabled = nc2.get("enabled", False)
    if "interval_secs" in nc2:
        s.node_churn.interval_secs = _parse_range(nc2["interval_secs"], "node_churn.interval_secs")
    s.node_churn.max_down_nodes = int(nc2.get("max_down_nodes", 1))
    if "down_duration_secs" in nc2:
        s.node_churn.down_duration_secs = _parse_range(
            nc2["down_duration_secs"], "node_churn.down_duration_secs"
        )
    s.node_churn.protect_connectivity = nc2.get("protect_connectivity", True)

    # Peer churn section
    pc = raw.get("peer_churn", {})
    _reject_unknown(pc, _SECTION_KEYS["peer_churn"], "peer_churn")
    s.peer_churn.enabled = pc.get("enabled", False)
    if "interval_secs" in pc:
        s.peer_churn.interval_secs = _parse_range(pc["interval_secs"], "peer_churn.interval_secs")
    s.peer_churn.ephemeral_fraction = float(pc.get("ephemeral_fraction", 0.0))

    # Bandwidth section
    bw = raw.get("bandwidth", {})
    _reject_unknown(bw, _SECTION_KEYS["bandwidth"], "bandwidth")
    s.bandwidth.enabled = bw.get("enabled", False)
    if "tiers_mbps" in bw:
        tiers = bw["tiers_mbps"]
        if not isinstance(tiers, list) or not tiers:
            raise ValueError("bandwidth.tiers_mbps must be a non-empty list")
        s.bandwidth.tiers_mbps = [int(t) for t in tiers]

    # Ingress section
    ig = raw.get("ingress", {})
    _reject_unknown(ig, _SECTION_KEYS["ingress"], "ingress")
    s.ingress.enabled = ig.get("enabled", False)
    if "tiers_kbps" in ig:
        tiers = ig["tiers_kbps"]
        if not isinstance(tiers, list) or not tiers:
            raise ValueError("ingress.tiers_kbps must be a non-empty list")
        s.ingress.tiers_kbps = [int(t) for t in tiers]
    s.ingress.burst_bytes = int(ig.get("burst_bytes", 32000))

    # Link swap section (deterministic asymmetric link-cost flapping).
    ls = raw.get("link_swap", {})
    _reject_unknown(ls, _SECTION_KEYS["link_swap"], "link_swap")
    s.link_swap.enabled = ls.get("enabled", False)
    if "interval_secs" in ls:
        s.link_swap.interval_secs = float(ls["interval_secs"])
    if "policies" in ls:
        s.link_swap.policies = {
            name: _parse_netem_policy(pdata, f"link_swap.policies.{name}")
            for name, pdata in ls["policies"].items()
        }
    if "edges" in ls:
        for edata in ls["edges"]:
            if not isinstance(edata, dict):
                raise ValueError("link_swap.edges entries must be dicts")
            _reject_unknown(
                edata, _SECTION_KEYS["link_swap.edges[]"], "link_swap.edges[]"
            )
            edge = str(edata.get("edge", ""))
            policy = str(edata.get("policy", ""))
            if not edge or not policy:
                raise ValueError("link_swap.edges entries require 'edge' and 'policy'")
            s.link_swap.edges.append(LinkSwapEdge(edge=edge, policy=policy))

    # Assertions section (post-run control-socket-based checks).
    asrt = raw.get("assertions", {})
    _reject_unknown(asrt, _SECTION_KEYS["assertions"], "assertions")
    if "bloom_send_rate" in asrt:
        bsr = asrt["bloom_send_rate"]
        _reject_unknown(
            bsr, _ASSERTION_KEYS["bloom_send_rate"], "assertions.bloom_send_rate"
        )
        s.assertions.bloom_send_rate = BloomSendRateAssertion(
            window_secs=int(bsr.get("window_secs", 30)),
            max_per_node=int(bsr.get("max_per_node", 30)),
        )
    if "min_parent_switches" in asrt:
        mps = asrt["min_parent_switches"]
        _reject_unknown(
            mps, _ASSERTION_KEYS["min_parent_switches"],
            "assertions.min_parent_switches",
        )
        s.assertions.min_parent_switches = MinParentSwitchesAssertion(
            min_total=int(mps.get("min_total", 1)),
        )

    # Logging section
    lg = raw.get("logging", {})
    _reject_unknown(lg, _SECTION_KEYS["logging"], "logging")
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
    if s.peer_churn.enabled:
        s.peer_churn.interval_secs.validate("peer_churn.interval_secs")
        if not 0.0 <= s.peer_churn.ephemeral_fraction <= 1.0:
            raise ValueError("peer_churn.ephemeral_fraction must be between 0.0 and 1.0")
    if s.bandwidth.enabled:
        for tier in s.bandwidth.tiers_mbps:
            if tier <= 0:
                raise ValueError(f"bandwidth.tiers_mbps: all values must be > 0, got {tier}")
    if s.ingress.enabled:
        for tier in s.ingress.tiers_kbps:
            if tier <= 0:
                raise ValueError(f"ingress.tiers_kbps: all values must be > 0, got {tier}")
        if s.ingress.burst_bytes <= 0:
            raise ValueError(f"ingress.burst_bytes must be > 0, got {s.ingress.burst_bytes}")

    # Validate link_swap
    if s.link_swap.enabled:
        if s.link_swap.interval_secs <= 0:
            raise ValueError("link_swap.interval_secs must be > 0")
        if len(s.link_swap.edges) < 2:
            raise ValueError("link_swap.edges must list at least 2 edges to swap")
        if not s.link_swap.policies:
            raise ValueError("link_swap.policies must not be empty when link_swap.enabled")
        for entry in s.link_swap.edges:
            if entry.policy not in s.link_swap.policies:
                raise ValueError(
                    f"link_swap.edges: policy '{entry.policy}' not in link_swap.policies"
                )

    # Validate assertions
    if s.assertions.bloom_send_rate is not None:
        bsr = s.assertions.bloom_send_rate
        if bsr.window_secs < 1:
            raise ValueError("assertions.bloom_send_rate.window_secs must be >= 1")
        if bsr.max_per_node < 0:
            raise ValueError("assertions.bloom_send_rate.max_per_node must be >= 0")
        if bsr.window_secs > s.duration_secs:
            raise ValueError(
                "assertions.bloom_send_rate.window_secs must not exceed scenario duration"
            )
