"""Scenario YAML loading and validation."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

import yaml

from .schedule import MODES, Step

# Node ids are rendered nNN by the topology generator, zero-padded to two
# digits. Matching the shape here keeps a typo such as "no4" or "n4x" from
# reaching an assertion as a node that simply never appears.
_NODE_ID_RE = re.compile(r"n\d+")


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


VALID_TRANSPORTS = ("udp", "ethernet", "tcp", "udp-veth")
# Dual edges: a veth half and a UDP-over-the-bridge half between the same
# two nodes (see topology.py).
DUAL_TRANSPORTS = ("ethernet+udp", "udp-veth+udp")


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
    # Assign derived identities in NodeAddr order so n01 holds the smallest and
    # is therefore the root every scenario diagram draws. Default on: without it
    # the root is whichever node happens to hold the smallest key, which is
    # effectively arbitrary and leaves any scenario that reasons about a
    # specific root (e.g. bloom-storm's diamond, or a baseline max_roots check)
    # describing a tree that does not form. Set false where election from an
    # arbitrary key distribution is itself the subject.
    pin_root: bool = True
    # Set by --subnet to opt out of claiming a free range. Not a scenario-file
    # key: a scenario that hardcoded its range would reintroduce the collision
    # claiming exists to remove.
    pinned_subnet: str | None = None


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
    # Edges the periodic mutation must never touch, "nXX-nYY" strings. Use it
    # to pin the links a tree_parents assertion depends on so a random
    # degradation cannot flip the very comparison being asserted. Validated
    # against the topology in NetemManager — an unknown edge is a hard error.
    exclude_edges: list[str] = field(default_factory=list)


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
    # Policy for the bridge (UDP) half of a dual edge. The veth half takes
    # the edge's ordinary policy. ``None`` means the bridge half gets the
    # default policy too.
    bridge_policy: NetemPolicy | None = None


@dataclass
class LinkFlapsConfig:
    enabled: bool = False
    interval_secs: Range = field(default_factory=lambda: Range(20, 60))
    max_down_links: int = 2
    down_duration_secs: Range = field(default_factory=lambda: Range(10, 30))
    protect_connectivity: bool = True
    # Only flap edges of this transport type (``ethernet``, ``udp``, ...);
    # a dual edge counts as its veth half. ``None`` flaps any edge.
    only_transport: str | None = None


@dataclass
class TrafficConfig:
    enabled: bool = False
    max_concurrent: int = 3
    interval_secs: Range = field(default_factory=lambda: Range(10, 30))
    duration_secs: Range = field(default_factory=lambda: Range(5, 15))
    parallel_streams: int = 4
    # Cap on each stream's rate in Mbit/s (iperf3 -b); None runs uncapped.
    rate_mbps: int | None = None
    # When set, each session also runs a constant-rate UDP stream of this
    # many Mbit/s beside it, same pair and length, whose receiver intervals
    # do not depend on TCP's timers (``max_stall`` with ``stream: udp``).
    udp_mbps: int | None = None


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
class MaxParentSwitchesAssertion:
    """Stability ceiling: fail if parent switches exceed ``max_total``.

    ``node`` scopes the count to a single node id (e.g. ``n04``) instead
    of the mesh-wide total. The distinction is not cosmetic: a criterion
    written about one node's log is a different number from the sum over
    every node, and checking the sum against a per-node threshold
    silently tests something other than what was specified.
    """

    max_total: int = 0
    node: str | None = None


@dataclass
class BaselineAssertion:
    """Floor on the mesh having formed at all.

    Deliberately weak and deliberately universal. It does not describe any
    scenario's subject; it says the nodes came up, agreed on a root, and
    took parents. Its value is that a scenario with no other assertion
    still cannot pass while the mesh is dead, which is the state twelve of
    thirteen scenarios were previously unable to distinguish from success.

    ``max_roots`` is how many distinct root values the snapshot may carry.
    One means the whole mesh agreed; a churn scenario that partitions on
    purpose needs a higher number, and setting it above one is a statement
    that partition is expected rather than an oversight.
    """

    min_nodes_reporting: int | None = None
    max_roots: int | None = None
    min_nodes_parented: int | None = None
    min_sessions: int | None = None


@dataclass
class TreeParentsAssertion:
    """Expected parent per node in the final tree snapshot.

    ``expected`` maps a node id to the node id its parent must be, e.g.
    ``{"n04": "n03"}``. Both sides are node ids rather than node
    addresses: an address is a per-run key derived from the generated
    identity, so a scenario could not name one ahead of time.

    A node absent from the snapshot fails rather than being skipped. That
    case is not hypothetical — more than half the archived runs of these
    scenarios have no entry for the node under test, and a skip would
    have reported those as satisfied.
    """

    expected: dict[str, str] = field(default_factory=dict)


@dataclass
class CongestionSignalsAssertion:
    """Floors on how many nodes observed each congestion signal.

    Each floor is the number of nodes whose final congestion snapshot
    reports a non-zero counter, not the counter's own magnitude: the
    scenario's written criteria are about *whether* a signal reached a
    class of node, and a single node with a huge count would satisfy a
    magnitude test while proving the signal never propagated.

    A floor left unset is not asserted. At least one must be set, since a
    block that asserts nothing is the failure this assertion exists to
    remove.
    """

    min_nodes_detected: int | None = None
    min_nodes_ce_forwarded: int | None = None
    min_nodes_ce_received: int | None = None


@dataclass
class MaxReplayRefusalsAssertion:
    """Ceiling on the replays a node refused, over all its peers.

    Read from the final congestion snapshot's ``replay_suppressed_total``,
    which counts a peer's refusals since it was promoted, on both receive
    paths, so a cutover does not clear what a run should see. An established
    peer's own frames are refused only when they fall behind its replay
    window, so a count here is a frame the node read too late.

    ``min_nodes`` is how many nodes must report a count at all. A node that
    reports none observed nothing, and reading that as zero is how this
    assertion would come to pass on a build that never counted.
    """

    max_total: int = 0
    min_nodes: int = 2


@dataclass
class MaxKernelDropsAssertion:
    """Ceiling on the frames the kernel drops at each Ethernet socket.

    Read from the final congestion snapshot, per node and Ethernet
    transport, as dropped / (received + dropped): ``kernel_drops`` is what
    the kernel turned away because the socket's receive buffer was full,
    ``frames_recv`` what the node read. A lost probe or ack counts against
    the path machine's timeout like any other loss, so a socket that
    overflows under a suite's traffic makes path timeouts and switches the
    suite did not cause.

    ``min_nodes`` is how many nodes must report an Ethernet counter at all.
    A node that reports none, or a build that does not count, observed
    nothing and fails rather than passing as zero.
    """

    max_pct: float = 1.0
    min_nodes: int = 1


@dataclass
class DeliveryAssertion:
    """Datagrams of each size must be delivered between each node pair.

    The probe runs at teardown, after every flapped link and stopped node
    has been restored. For each pair and payload size it repeats a
    one-packet ping6 over the mesh until ``min_replies`` replies have come
    back or ``deadline_secs`` has passed. The verdict is binary per pair
    and size, not a loss ratio, so a busy host slows the probe without
    failing it.

    ``require_transport`` with ``transport_node`` proves the probes
    crossed that transport: the node's peers are read before and after
    the probe, and the assertion fails if the node has no peers or any
    peer on another transport. Choose a node whose only edges use that
    transport and put it in every pair.
    """

    pairs: list[tuple[str, str]] = field(default_factory=list)
    payload_bytes: list[int] = field(default_factory=list)
    min_replies: int = 3
    deadline_secs: int = 60
    require_transport: str | None = None
    transport_node: str | None = None


@dataclass
class MaxErrorsAssertion:
    """Ceiling on ERROR-level lines across every node's log.

    Unlike the other assertions this one is applied to every scenario
    whether or not the YAML asks for it, because it is a floor on what a
    green run means rather than a property of one scenario: without it a
    run in which every node errors on every line still exits 0.

    ``max_total`` defaults to 0, which is what the archived corpus
    supports. Across 2416 archived run directories no node log contains a
    single ERROR-level line, while the sibling WARN counter extracted by
    the same code path ranges from 0 to 1135 — so 0 is an observed value
    and not an aspiration, and the counter is known to discriminate.

    A scenario that legitimately induces errors raises the ceiling in its
    own YAML and must say at that site why the errors are expected.
    """

    max_total: int = 0


@dataclass
class MinTrafficAssertion:
    """Floor on how much iperf3 traffic actually completed.

    Traffic has always been generated and its results saved to
    ``iperf3-results.json``, but nothing read them: a scenario could carry
    ``traffic.enabled: true``, have every single session fail, and still
    exit 0 on a green control plane. That gap matters most for the
    scenarios where traffic is the point — a datagram crossing an Ethernet
    link while its interface rebinds underneath is not observable in the
    tree snapshot at all.

    ``min_sessions_ok`` counts sessions that finished with bytes actually
    received. ``min_bytes_total`` is the aggregate floor across them; 0
    disables it and leaves the session count as the only gate.
    """

    min_sessions_ok: int = 1
    min_bytes_total: int = 0


@dataclass
class PathSwitchesAssertion:
    """Band on path switches: a link's active path moving, under one session.

    Counted from the switch executor's "Path switched" line, one per move
    at the node that moves. ``min_total`` proves the run moved something.
    The ceiling is ``max_total``, or ``per_flap`` times the flaps the run
    actually made plus ``extra``, whichever is lower, so a run that drew
    fewer flaps gets a lower ceiling rather than a fixed one.
    """

    min_total: int | None = None
    max_total: int | None = None
    per_flap: int | None = None
    extra: int = 0


@dataclass
class ActiveTimeoutsAssertion:
    """A report of the active path's timeouts that no down explains.

    A ``Live -> Suspect why=Timeout`` on a node's active path later than
    ``within_ms`` after a down stamped at that node: a path that was up and
    lost its probes under load. ``path_switches`` cannot see one, since a
    pair of extra switches sits inside its ceiling at the lower of a suite's
    two baselines. The default is the K-timeout bound, 3 x 200 + 400 + 50 +
    250 ms. It reports and fails nothing, which is the operator's to change.
    """

    within_ms: int = 1300


@dataclass
class MaxPromotionsAssertion:
    """Per-node ceiling on "Peer promoted to active".

    A promotion is a handshake completing: the first one per peer is how a
    pair meets, every later one is a re-peering (the session was lost and
    rebuilt), which a switchover suite exists to catch. Counted per node,
    because a pair re-peering shows up on both sides and a mesh-wide total
    would hide which one started it.
    """

    per_node: int = 1


@dataclass
class SwitchLatencyAssertion:
    """Ceiling on the time from a link going down to the path switch.

    Read from the stamp each flap took inside the container, immediately
    before the command that made it, against the "Path switched" lines of
    the edge's endpoints. ``max_ms`` bounds the earliest switch at either
    end, or with ``each_end`` the first switch at every end; a down with
    no switch inside the bound fails. ``sender_ms``, when set, replaces
    ``max_ms`` for one end of a ``oneway`` down: the end whose own sends
    are dropped, which still hears its peer and so may switch later; the
    other end, and both ends of a two-way down, keep ``max_ms``.
    ``signalled_ms``, when set, is a tighter ceiling on each end's first
    switch, for a down the node has a signal for rather than only probe
    timeouts.
    """

    max_ms: int = 1000
    each_end: bool = False
    signalled_ms: int | None = None
    sender_ms: int | None = None


@dataclass
class MaxStallAssertion:
    """Ceiling on the longest run of iperf3 intervals that moved no bytes.

    ``min_traffic`` passes on any session that moved any data, and a
    switchover that blackholes traffic for ten seconds still leaves bytes
    on either side of the hole. This reads the receiver's per-interval
    totals from each iperf3 result and fails on the longest run of zeros
    inside any session, and on a session it cannot read.

    ``stream`` names what the ceiling holds: ``tcp`` the traffic sessions
    themselves; ``udp`` the constant-rate UDP stream each session runs
    beside it (``traffic.udp_mbps``). A TCP receiver can stay silent after
    a switch for as long as its sender's retransmission timer runs, which
    is TCP's recovery, not the node's; the UDP stream stops only while no
    path carries it. With ``udp`` the TCP sessions' figure is reported,
    not bounded.
    """

    max_secs: float = 2.0
    stream: str = "tcp"


@dataclass
class MaxDialsAssertion:
    """Ceiling on dials a node starts after first contact.

    Counted from "Connection initiated", one per handshake the node
    starts, after the node's first "Peer promoted to active", and from
    "Anonymous discovery connection initiated" after the first to each
    transport and address. A dial to a peer whose link is live is the
    failure: with two paths the second must come through the link's path
    machine, never a second handshake.
    """

    max_total: int = 0


@dataclass
class PathsLiveAssertion:
    """Floor on the paths a node held Live to a peer: the control that a
    second path existed.

    Per node and peer, the paths, keyed by ``path_id``, that logged their
    creation (a "Path state changed" line from ``None``) and later went
    Live, plus one for the link's original path, which is Live from
    link-up and logs no line. Passes when some node holds at least
    ``min`` to some peer.
    """

    min: int = 2
    # Count only paths Live at a pair the scenario configured (a laned
    # edge's lane pairs at its dialler), each at a distinct pair, by
    # ``within_secs`` after warmup.
    configured: bool = False
    within_secs: int | None = None


@dataclass
class LanesAssertion:
    """A laned edge's controls and verdicts.

    ``cross_arrival``: at the dialler, a frame arrived on a lane addressed
    to another lane's address, so an answer could reach an instance other
    than its probe's (the far end's crossings are reported). ``stable``:
    no lane path Live at a configured pair later went Suspect, and the
    sentinel address no host answers never went Live.
    """

    cross_arrival: bool = True
    stable: bool = True


@dataclass
class PathFloorAssertion:
    """The draft's floor on probes to a path that has stopped answering.

    Inside every stop, probe n at least r(n) after probe n - 1 (probe 0 the
    stop), r(1) = r(2) = 1 s and r(n) = min(2 r(n - 1), 30 s), less the
    log-stamp allowance in paths.py. ``min_stops`` stops with at least two
    probes must be seen, so a run in which nothing stopped cannot pass.
    """

    min_stops: int = 1


@dataclass
class DiscoveryLimitAssertion:
    """At most MAX_DISCOVERY_PROBES (8) probes in any Probing episode."""

    max_probes: int = 8


@dataclass
class ReverseHeardAssertion:
    """The control that a one-direction step stayed one-directional.

    For each ``oneway`` step: the end whose sends were not dropped logged a
    path message to the other's veth address during the step, and the
    capture at the other end holds at least as many frames from it as it
    logged in the step's second half, or from its last message when the
    half holds none; and at the step's end neither end's neighbour entry
    for the other is FAILED or INCOMPLETE.
    """

    window_ms: int = 50


@dataclass
class RescueAssertion:
    """An acked Dead standby is probed at once when the active path fails
    with nothing Live, and carries the link.

    Control first: at both ends the standby is Dead when the active path
    goes (a standby only Suspect does not exercise the rule). Then at each
    end a probe on the standby within ``window_ms`` of the step in which
    the active path left Live or was released, the standby Live at both
    ends within 2 x ``delay_ms`` + 1 s of the down, and no peer removed.
    """

    delay_ms: int = 500
    window_ms: int = 60


@dataclass
class AssertionsConfig:
    """Optional post-run assertions evaluated against control-socket data."""

    bloom_send_rate: BloomSendRateAssertion | None = None
    min_parent_switches: MinParentSwitchesAssertion | None = None
    max_parent_switches: MaxParentSwitchesAssertion | None = None
    path_switches: PathSwitchesAssertion | None = None
    active_timeouts: ActiveTimeoutsAssertion | None = None
    max_promotions: MaxPromotionsAssertion | None = None
    switch_latency: SwitchLatencyAssertion | None = None
    max_stall: MaxStallAssertion | None = None
    max_dials: MaxDialsAssertion | None = None
    paths_live: PathsLiveAssertion | None = None
    path_floor: PathFloorAssertion | None = None
    reverse_heard: ReverseHeardAssertion | None = None
    rescue: RescueAssertion | None = None
    lanes: LanesAssertion | None = None
    discovery_limit: DiscoveryLimitAssertion | None = None
    max_errors: MaxErrorsAssertion | None = None
    congestion_signals: CongestionSignalsAssertion | None = None
    max_kernel_drops: MaxKernelDropsAssertion | None = None
    max_replay_refusals: MaxReplayRefusalsAssertion | None = None
    tree_parents: TreeParentsAssertion | None = None
    baseline: BaselineAssertion | None = None
    min_traffic: MinTrafficAssertion | None = None
    delivery: DeliveryAssertion | None = None


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
    # Timed steps, offsets from the end of warmup (see schedule.py).
    schedule: list[Step] = field(default_factory=list)
    # Merged into each generated transport instance of a kind (``ethernet``,
    # ``udp-veth``, ``udp``) after the harness injects it, so a scenario can
    # set what fips_overrides, merged before, cannot reach.
    transport_overrides: dict = field(default_factory=dict)


# Keys each fixed-schema section understands. A key absent from these sets is a
# typo, and silently ignoring it leaves the block default-constructed while the
# YAML still looks correct — a mistyped "assertion:" disarms a scenario's only
# assertions, a mistyped "link_flap:" turns off the chaos it was meant to inject.
#
# Four mappings are deliberately NOT listed, because their keys are names the
# scenario author chooses rather than a schema: netem.mutation.policies,
# link_swap.policies, topology.transport_mix and assertions.tree_parents (whose
# keys are node ids). Two sub-trees are passed through whole and are likewise
# not checked: fips_overrides and topology.params. tree_parents is not thereby
# unchecked -- both sides of every entry are validated as node ids that exist in
# this scenario's topology, which is the check that matters for it.
#
# NOTE: adding a new assertion type means registering it in TWO places below —
# _SECTION_KEYS["assertions"] (so the block accepts its name) and _ASSERTION_KEYS
# (so its own members are checked) — or scenarios using it are rejected at load.
_TOP_KEYS = {
    "scenario", "topology", "netem", "link_flaps", "traffic", "node_churn",
    "peer_churn", "bandwidth", "ingress", "link_swap", "assertions", "logging",
    "fips_overrides", "schedule", "transport_overrides",
}
_SECTION_KEYS = {
    "scenario": {"name", "seed", "duration_secs"},
    "topology": {
        "num_nodes", "algorithm", "params", "ensure_connected", "subnet",
        "ip_start", "default_transport", "transport_mix", "pin_root",
    },
    "netem": {"enabled", "default_policy", "link_policies", "mutation", "bridge_policy"},
    "netem.link_policies[]": {"edges", "policy", "policy_name"},
    "netem.mutation": {"interval_secs", "fraction", "policies", "exclude_edges"},
    "link_flaps": {
        "enabled", "interval_secs", "max_down_links", "down_duration_secs",
        "protect_connectivity", "only_transport",
    },
    "traffic": {
        "enabled", "max_concurrent", "interval_secs", "duration_secs",
        "parallel_streams", "rate_mbps", "udp_mbps",
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
    "assertions": {
        "bloom_send_rate", "min_parent_switches", "max_parent_switches",
        "path_switches", "active_timeouts", "max_promotions", "switch_latency",
        "max_stall",
        "max_dials", "paths_live", "path_floor", "discovery_limit", "reverse_heard",
        "rescue", "lanes",
        "max_errors", "congestion_signals", "max_kernel_drops",
        "max_replay_refusals", "tree_parents", "baseline", "min_traffic", "delivery",
    },
    "logging": {"rust_log", "output_dir"},
}
_ASSERTION_KEYS = {
    "bloom_send_rate": {"window_secs", "max_per_node"},
    "min_parent_switches": {"min_total"},
    "max_parent_switches": {"max_total", "node"},
    "path_switches": {"min_total", "max_total", "per_flap", "extra"},
    "active_timeouts": {"within_ms"},
    "max_promotions": {"per_node"},
    "switch_latency": {"max_ms", "each_end", "signalled_ms", "sender_ms"},
    "max_stall": {"max_secs", "stream"},
    "paths_live": {"min", "configured", "within_secs"},
    "lanes": {"cross_arrival", "stable"},
    "path_floor": {"min_stops"},
    "discovery_limit": {"max_probes"},
    "reverse_heard": {"window_ms"},
    "rescue": {"delay_ms", "window_ms"},
    "max_errors": {"max_total"},
    "min_traffic": {"min_sessions_ok", "min_bytes_total"},
    "congestion_signals": {
        "min_nodes_detected", "min_nodes_ce_forwarded", "min_nodes_ce_received",
    },
    "max_kernel_drops": {"max_pct", "min_nodes"},
    "max_replay_refusals": {"max_total", "min_nodes"},
    "baseline": {
        "min_nodes_reporting", "max_roots", "min_nodes_parented", "min_sessions",
    },
    "delivery": {
        "pairs", "payload_bytes", "min_replies", "deadline_secs",
        "require_transport", "transport_node",
    },
}
# Largest delivery probe payload: an ICMPv6 echo of this size fits the
# 1280-byte TUN MTU with FIPS overhead to spare.
_DELIVERY_MAX_PAYLOAD = 1400
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


def _parse_max_kernel_drops(data) -> MaxKernelDropsAssertion:
    """Parse and range-check an ``assertions.max_kernel_drops`` block."""
    _reject_unknown(
        data, _ASSERTION_KEYS["max_kernel_drops"], "assertions.max_kernel_drops"
    )
    cfg = MaxKernelDropsAssertion()
    if "max_pct" in data:
        pct = data["max_pct"]
        if isinstance(pct, bool) or not isinstance(pct, (int, float)):
            raise ValueError(
                f"assertions.max_kernel_drops.max_pct: must be a number, "
                f"got {pct!r}"
            )
        if not 0 <= pct < 100:
            raise ValueError(
                f"assertions.max_kernel_drops.max_pct: must be at least 0 and "
                f"below 100, got {pct}"
            )
        cfg.max_pct = float(pct)
    if "min_nodes" in data:
        n = data["min_nodes"]
        if isinstance(n, bool) or not isinstance(n, int) or n < 1:
            raise ValueError(
                f"assertions.max_kernel_drops.min_nodes: must be a positive "
                f"integer, got {n!r}"
            )
        cfg.min_nodes = n
    return cfg


def _parse_max_replay_refusals(data) -> MaxReplayRefusalsAssertion:
    """Parse and range-check an ``assertions.max_replay_refusals`` block."""
    _reject_unknown(
        data, _ASSERTION_KEYS["max_replay_refusals"],
        "assertions.max_replay_refusals",
    )
    cfg = MaxReplayRefusalsAssertion()
    if "max_total" in data:
        total = data["max_total"]
        if isinstance(total, bool) or not isinstance(total, int) or total < 0:
            raise ValueError(
                f"assertions.max_replay_refusals.max_total: must be a "
                f"non-negative integer, got {total!r}"
            )
        cfg.max_total = total
    if "min_nodes" in data:
        n = data["min_nodes"]
        if isinstance(n, bool) or not isinstance(n, int) or n < 1:
            raise ValueError(
                f"assertions.max_replay_refusals.min_nodes: must be a "
                f"positive integer, got {n!r}"
            )
        cfg.min_nodes = n
    return cfg


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
    if "pin_root" in tc:
        pin = tc["pin_root"]
        if not isinstance(pin, bool):
            raise ValueError(
                f"topology.pin_root must be a boolean, got {pin!r}"
            )
        s.topology.pin_root = pin
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
    if "bridge_policy" in nc:
        s.netem.bridge_policy = _parse_netem_policy(
            nc["bridge_policy"], "netem.bridge_policy"
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
        s.netem.mutation.exclude_edges = list(mc.get("exclude_edges", []))
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
    only = lf.get("only_transport")
    if only is not None and str(only) not in VALID_TRANSPORTS:
        raise ValueError(
            f"link_flaps.only_transport: {only!r} not in {VALID_TRANSPORTS}"
        )
    s.link_flaps.only_transport = str(only) if only is not None else None

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
    if "rate_mbps" in tf:
        s.traffic.rate_mbps = _count(tf["rate_mbps"], "traffic.rate_mbps", 1)
    if "udp_mbps" in tf:
        s.traffic.udp_mbps = _count(tf["udp_mbps"], "traffic.udp_mbps", 1)

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
    _parsepaths(asrt, s)
    if "min_parent_switches" in asrt:
        mps = asrt["min_parent_switches"]
        _reject_unknown(
            mps, _ASSERTION_KEYS["min_parent_switches"],
            "assertions.min_parent_switches",
        )
        s.assertions.min_parent_switches = MinParentSwitchesAssertion(
            min_total=int(mps.get("min_total", 1)),
        )
    if "max_parent_switches" in asrt:
        xps = asrt["max_parent_switches"]
        _reject_unknown(
            xps, _ASSERTION_KEYS["max_parent_switches"],
            "assertions.max_parent_switches",
        )
        if "max_total" not in xps:
            raise ValueError(
                "assertions.max_parent_switches: max_total is required "
                "(a defaulted ceiling would assert an arbitrary number)"
            )
        max_total = xps["max_total"]
        # bool is a subclass of int, and `max_total: yes` would coerce to 1
        # -- a ceiling low enough to change the verdict, arrived at by typo.
        if isinstance(max_total, bool) or not isinstance(max_total, int):
            raise ValueError(
                f"assertions.max_parent_switches: max_total must be a "
                f"non-negative integer, got {max_total!r}"
            )
        if max_total < 0:
            raise ValueError(
                f"assertions.max_parent_switches: max_total must be "
                f"non-negative, got {max_total}"
            )
        # Distinguish "key absent" from "key present but empty". Only the
        # first means mesh-wide. YAML renders a bare `node:` as None, and
        # treating that as absent would silently swap a per-node ceiling
        # for a mesh-wide one -- the exact conflation this assertion was
        # added to stop, and a live flake rather than a theoretical one:
        # archived runs of this scenario reach 6 mesh-wide against an n04
        # maximum of 2.
        node = None
        if "node" in xps:
            node = xps["node"]
            if not isinstance(node, str) or not node.strip():
                raise ValueError(
                    f"assertions.max_parent_switches: node must be a node id "
                    f"string such as 'n04', got {node!r}. Omit the key "
                    f"entirely for the mesh-wide total."
                )
            node = node.strip()
        s.assertions.max_parent_switches = MaxParentSwitchesAssertion(
            max_total=max_total,
            node=node,
        )
    if "max_errors" in asrt:
        mev = asrt["max_errors"]
        _reject_unknown(
            mev, _ASSERTION_KEYS["max_errors"], "assertions.max_errors",
        )
        if "max_total" not in mev:
            raise ValueError(
                "assertions.max_errors: max_total is required (the point of "
                "overriding the default ceiling is to name the new number)"
            )
        err_total = mev["max_total"]
        if isinstance(err_total, bool) or not isinstance(err_total, int):
            raise ValueError(
                f"assertions.max_errors: max_total must be a non-negative "
                f"integer, got {err_total!r}"
            )
        if err_total < 0:
            raise ValueError(
                f"assertions.max_errors: max_total must be non-negative, "
                f"got {err_total}"
            )
        s.assertions.max_errors = MaxErrorsAssertion(max_total=err_total)

    if "min_traffic" in asrt:
        mt = asrt["min_traffic"]
        _reject_unknown(
            mt, _ASSERTION_KEYS["min_traffic"], "assertions.min_traffic",
        )
        sessions = mt.get("min_sessions_ok", 1)
        if not isinstance(sessions, int) or isinstance(sessions, bool) or sessions < 1:
            raise ValueError(
                "assertions.min_traffic: min_sessions_ok must be a positive "
                f"integer, got {sessions!r} — a floor of zero asserts nothing"
            )
        min_bytes = mt.get("min_bytes_total", 0)
        if not isinstance(min_bytes, int) or isinstance(min_bytes, bool) or min_bytes < 0:
            raise ValueError(
                "assertions.min_traffic: min_bytes_total must be a "
                f"non-negative integer, got {min_bytes!r}"
            )
        s.assertions.min_traffic = MinTrafficAssertion(
            min_sessions_ok=sessions, min_bytes_total=min_bytes,
        )
    else:
        # Default-on. See MaxErrorsAssertion for why this one assertion is
        # applied without being asked for: it is the floor on what a green
        # run means, and a scenario that has to opt in is a scenario that
        # can forget to.
        s.assertions.max_errors = MaxErrorsAssertion()
    if "congestion_signals" in asrt:
        cs = asrt["congestion_signals"]
        _reject_unknown(
            cs, _ASSERTION_KEYS["congestion_signals"],
            "assertions.congestion_signals",
        )
        floors = {}
        for key in _ASSERTION_KEYS["congestion_signals"]:
            if key not in cs:
                continue
            val = cs[key]
            if isinstance(val, bool) or not isinstance(val, int):
                raise ValueError(
                    f"assertions.congestion_signals.{key}: must be a positive "
                    f"integer number of nodes, got {val!r}"
                )
            if val < 1:
                raise ValueError(
                    f"assertions.congestion_signals.{key}: must be at least 1, "
                    f"got {val}. A floor of 0 is satisfied by a mesh that "
                    f"observed nothing, which is the case this assertion exists "
                    f"to catch; omit the key instead."
                )
            floors[key] = val
        if not floors:
            raise ValueError(
                "assertions.congestion_signals: set at least one floor "
                "(min_nodes_detected, min_nodes_ce_forwarded, "
                "min_nodes_ce_received); a block with none asserts nothing"
            )
        s.assertions.congestion_signals = CongestionSignalsAssertion(**floors)
    if "max_replay_refusals" in asrt:
        s.assertions.max_replay_refusals = _parse_max_replay_refusals(
            asrt["max_replay_refusals"]
        )
    if "max_kernel_drops" in asrt:
        s.assertions.max_kernel_drops = _parse_max_kernel_drops(
            asrt["max_kernel_drops"]
        )
    if "delivery" in asrt:
        s.assertions.delivery = _parse_delivery(
            asrt["delivery"], s.topology.num_nodes
        )
    if "tree_parents" in asrt:
        tp = asrt["tree_parents"]
        if not isinstance(tp, dict) or not tp:
            raise ValueError(
                "assertions.tree_parents: give it at least one "
                "'<node>: <expected parent>' entry; an empty block asserts "
                "nothing"
            )
        expected = {}
        for child, parent in tp.items():
            for role, val in (("node", child), ("parent", parent)):
                if not isinstance(val, str) or not _NODE_ID_RE.fullmatch(val):
                    raise ValueError(
                        f"assertions.tree_parents: {role} {val!r} is not a node "
                        f"id of the form 'n04'"
                    )
                idx = int(val[1:])
                if idx < 1 or idx > s.topology.num_nodes:
                    raise ValueError(
                        f"assertions.tree_parents: {role} '{val}' is outside "
                        f"this scenario's {s.topology.num_nodes} nodes. An "
                        f"assertion about a node that cannot exist would fail "
                        f"for the wrong reason every run."
                    )
            if child == parent:
                raise ValueError(
                    f"assertions.tree_parents: '{child}' is given itself as "
                    f"its parent. A node is its own parent only when it "
                    f"believes it is root, which is what an unconverged tree "
                    f"looks like; assert that some other way."
                )
            expected[child] = parent
        s.assertions.tree_parents = TreeParentsAssertion(expected=expected)
    if "baseline" in asrt:
        bl = asrt["baseline"]
        _reject_unknown(bl, _ASSERTION_KEYS["baseline"], "assertions.baseline")
        vals = {}
        for key in _ASSERTION_KEYS["baseline"]:
            if key not in bl:
                continue
            val = bl[key]
            if isinstance(val, bool) or not isinstance(val, int):
                raise ValueError(
                    f"assertions.baseline.{key}: must be an integer, "
                    f"got {val!r}"
                )
            floor = 1 if key == "max_roots" else 0
            if val < floor:
                raise ValueError(
                    f"assertions.baseline.{key}: must be at least {floor}, "
                    f"got {val}"
                )
            vals[key] = val
        if not vals:
            raise ValueError(
                "assertions.baseline: set at least one of "
                + ", ".join(sorted(_ASSERTION_KEYS["baseline"]))
                + "; a block with none asserts nothing"
            )
        if vals.get("min_nodes_parented", 0) > 0:
            # Every root is its own parent, so a mesh with R roots has at most
            # n - R nodes parented. Checked against the roots ceiling rather
            # than against one root: a floor above n - max_roots reds a run
            # that sits exactly at the ceiling the file itself allows, so the
            # two thresholds contradict each other there.
            n = s.topology.num_nodes
            roots = vals.get("max_roots", 1)
            floor = vals["min_nodes_parented"]
            if floor > n - roots:
                raise ValueError(
                    f"assertions.baseline.min_nodes_parented: {floor} exceeds "
                    f"{n - roots}, the most a {n}-node mesh with {roots} "
                    f"root(s) can reach — each root is its own parent, so a "
                    f"run at the max_roots ceiling could never pass"
                )
        s.assertions.baseline = BaselineAssertion(**vals)

    # Logging section
    lg = raw.get("logging", {})
    _reject_unknown(lg, _SECTION_KEYS["logging"], "logging")
    s.logging.rust_log = lg.get("rust_log", "info")
    s.logging.output_dir = lg.get("output_dir", "./sim-results")

    # FIPS config overrides (raw YAML dict appended to node configs)
    s.fips_overrides = raw.get("fips_overrides", {})

    s.schedule = _parsesteps(raw.get("schedule", []))

    to = raw.get("transport_overrides", {})
    if not isinstance(to, dict) or not set(to) <= {"ethernet", "udp-veth", "udp"} or not all(
        isinstance(v, dict) for v in to.values()
    ):
        raise ValueError(
            f"transport_overrides: a mapping of ethernet, udp-veth or udp to a "
            f"mapping of settings, got {to!r}"
        )
    s.transport_overrides = to

    # Validation
    _validate(s)

    return s


def _delivery_node(val, num_nodes: int, where: str) -> str:
    """Validate one node id named by the delivery assertion."""
    if not isinstance(val, str) or not _NODE_ID_RE.fullmatch(val):
        raise ValueError(
            f"assertions.delivery.{where}: {val!r} is not a node id of the "
            f"form 'n04'"
        )
    idx = int(val[1:])
    if idx < 1 or idx > num_nodes:
        raise ValueError(
            f"assertions.delivery.{where}: '{val}' is outside this "
            f"scenario's {num_nodes} nodes"
        )
    return val


def _delivery_int(dl: dict, key: str, default: int) -> int:
    """Read a positive integer setting of the delivery assertion."""
    val = dl.get(key, default)
    if isinstance(val, bool) or not isinstance(val, int) or val < 1:
        raise ValueError(
            f"assertions.delivery.{key}: must be a positive integer, got {val!r}"
        )
    return val


def _parse_delivery(dl, num_nodes: int) -> DeliveryAssertion:
    """Parse and validate the delivery assertion block."""
    if not isinstance(dl, dict):
        raise ValueError("assertions.delivery: must be a mapping")
    _reject_unknown(dl, _ASSERTION_KEYS["delivery"], "assertions.delivery")

    raw_pairs = dl.get("pairs")
    if not isinstance(raw_pairs, list) or not raw_pairs:
        raise ValueError(
            "assertions.delivery.pairs: give at least one [src, dst] pair; "
            "an empty list asserts nothing"
        )
    pairs = []
    for pair in raw_pairs:
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValueError(
                f"assertions.delivery.pairs: each entry must be [src, dst], "
                f"got {pair!r}"
            )
        src = _delivery_node(pair[0], num_nodes, "pairs")
        dst = _delivery_node(pair[1], num_nodes, "pairs")
        if src == dst:
            raise ValueError(
                f"assertions.delivery.pairs: [{src}, {dst}] pings a node from "
                f"itself, which crosses no link"
            )
        pairs.append((src, dst))

    sizes = dl.get("payload_bytes")
    if not isinstance(sizes, list) or not sizes:
        raise ValueError(
            "assertions.delivery.payload_bytes: give at least one size; an "
            "empty list asserts nothing"
        )
    for size in sizes:
        if (isinstance(size, bool) or not isinstance(size, int)
                or not 0 <= size <= _DELIVERY_MAX_PAYLOAD):
            raise ValueError(
                f"assertions.delivery.payload_bytes: each size must be an "
                f"integer from 0 to {_DELIVERY_MAX_PAYLOAD}, got {size!r}"
            )

    transport = dl.get("require_transport")
    node = dl.get("transport_node")
    if (transport is None) != (node is None):
        raise ValueError(
            "assertions.delivery: require_transport and transport_node go "
            "together; one without the other proves nothing"
        )
    if transport is not None:
        if transport not in VALID_TRANSPORTS:
            raise ValueError(
                f"assertions.delivery.require_transport: {transport!r} is not "
                f"one of {', '.join(VALID_TRANSPORTS)}"
            )
        node = _delivery_node(node, num_nodes, "transport_node")
        missing = [p for p in pairs if node not in p]
        if missing:
            raise ValueError(
                f"assertions.delivery: pairs {missing} do not include "
                f"transport_node '{node}', so the transport check says "
                f"nothing about them"
            )

    return DeliveryAssertion(
        pairs=pairs,
        payload_bytes=list(sizes),
        min_replies=_delivery_int(dl, "min_replies", 3),
        deadline_secs=_delivery_int(dl, "deadline_secs", 60),
        require_transport=transport,
        transport_node=node,
    )


def _count(value, where: str, least: int = 0) -> int:
    """A non-negative (or at least ``least``) integer, refusing a bool."""
    if isinstance(value, bool) or not isinstance(value, int) or value < least:
        raise ValueError(f"{where}: must be an integer >= {least}, got {value!r}")
    return value


def _parsepaths(asrt: dict, s: Scenario):
    """Parse the assertions a two-path suite declares."""
    if "path_switches" in asrt:
        ps = asrt["path_switches"]
        where = "assertions.path_switches"
        _reject_unknown(ps, _ASSERTION_KEYS["path_switches"], where)
        if not {"min_total", "max_total", "per_flap"} & set(ps):
            raise ValueError(
                f"{where}: give min_total, max_total or per_flap "
                "(an empty band asserts nothing)"
            )
        if "extra" in ps and "per_flap" not in ps:
            raise ValueError(f"{where}: extra goes with per_flap")
        s.assertions.path_switches = PathSwitchesAssertion(
            min_total=_count(ps["min_total"], f"{where}.min_total") if "min_total" in ps else None,
            max_total=_count(ps["max_total"], f"{where}.max_total") if "max_total" in ps else None,
            per_flap=_count(ps["per_flap"], f"{where}.per_flap", 1) if "per_flap" in ps else None,
            extra=_count(ps.get("extra", 0), f"{where}.extra"),
        )
    if "active_timeouts" in asrt:
        at = asrt["active_timeouts"] or {}
        where = "assertions.active_timeouts"
        _reject_unknown(at, _ASSERTION_KEYS["active_timeouts"], where)
        s.assertions.active_timeouts = ActiveTimeoutsAssertion(
            within_ms=_count(
                at.get("within_ms", ActiveTimeoutsAssertion.within_ms),
                f"{where}.within_ms", 1,
            ),
        )
    if "max_promotions" in asrt:
        mp = asrt["max_promotions"]
        where = "assertions.max_promotions"
        if not isinstance(mp, dict):
            raise ValueError(f"{where}: give a mapping {{per_node: n}}, got {mp!r}")
        _reject_unknown(mp, _ASSERTION_KEYS["max_promotions"], where)
        s.assertions.max_promotions = MaxPromotionsAssertion(
            per_node=_count(mp.get("per_node", 1), f"{where}.per_node", 1),
        )
    if "switch_latency" in asrt:
        sl = asrt["switch_latency"]
        where = "assertions.switch_latency"
        _reject_unknown(sl, _ASSERTION_KEYS["switch_latency"], where)
        each = sl.get("each_end", False)
        if not isinstance(each, bool):
            raise ValueError(f"{where}.each_end: must be true or false, got {each!r}")
        signalled = sl.get("signalled_ms")
        sender = sl.get("sender_ms")
        s.assertions.switch_latency = SwitchLatencyAssertion(
            max_ms=_count(sl.get("max_ms", 1000), f"{where}.max_ms", 1),
            each_end=each,
            signalled_ms=(
                _count(signalled, f"{where}.signalled_ms", 1)
                if signalled is not None else None
            ),
            sender_ms=(
                _count(sender, f"{where}.sender_ms", 1) if sender is not None else None
            ),
        )
    if "max_stall" in asrt:
        ms = asrt["max_stall"]
        where = "assertions.max_stall"
        _reject_unknown(ms, _ASSERTION_KEYS["max_stall"], where)
        secs = ms.get("max_secs", 2.0)
        if isinstance(secs, bool) or not isinstance(secs, (int, float)) or secs <= 0:
            raise ValueError(f"{where}.max_secs: must be a positive number, got {secs!r}")
        stream = ms.get("stream", "tcp")
        if stream not in ("tcp", "udp"):
            raise ValueError(f"{where}.stream: must be tcp or udp, got {stream!r}")
        s.assertions.max_stall = MaxStallAssertion(max_secs=float(secs), stream=stream)
    if "max_dials" in asrt:
        s.assertions.max_dials = MaxDialsAssertion(
            max_total=_count(asrt["max_dials"], "assertions.max_dials"),
        )
    for key, cls, field_name, least in (
        ("path_floor", PathFloorAssertion, "min_stops", 1),
        ("discovery_limit", DiscoveryLimitAssertion, "max_probes", 1),
        ("reverse_heard", ReverseHeardAssertion, "window_ms", 0),
    ):
        if key not in asrt:
            continue
        raw = asrt[key]
        if raw is True or raw is None:
            raw = {}
        if not isinstance(raw, dict):
            raise ValueError(f"assertions.{key}: give true or a mapping, got {raw!r}")
        _reject_unknown(raw, _ASSERTION_KEYS[key], f"assertions.{key}")
        value = _count(raw.get(field_name, getattr(cls(), field_name)),
                       f"assertions.{key}.{field_name}", least)
        setattr(s.assertions, key, cls(**{field_name: value}))
    if "rescue" in asrt:
        rc = asrt["rescue"]
        where = "assertions.rescue"
        if not isinstance(rc, dict):
            raise ValueError(f"{where}: give a mapping, got {rc!r}")
        _reject_unknown(rc, _ASSERTION_KEYS["rescue"], where)
        s.assertions.rescue = RescueAssertion(
            delay_ms=_count(rc.get("delay_ms", 500), f"{where}.delay_ms"),
            window_ms=_count(rc.get("window_ms", 60), f"{where}.window_ms", 1),
        )
    if "paths_live" in asrt:
        pl = asrt["paths_live"]
        where = "assertions.paths_live"
        _reject_unknown(pl, _ASSERTION_KEYS["paths_live"], where)
        configured = pl.get("configured", False)
        if not isinstance(configured, bool):
            raise ValueError(f"{where}.configured: must be true or false, got {configured!r}")
        within = pl.get("within_secs")
        s.assertions.paths_live = PathsLiveAssertion(
            min=_count(pl.get("min", 2), f"{where}.min", 1),
            configured=configured,
            within_secs=_count(within, f"{where}.within_secs", 1) if within is not None else None,
        )
    if "lanes" in asrt:
        ln = asrt["lanes"]
        where = "assertions.lanes"
        if not isinstance(ln, dict):
            raise ValueError(f"{where}: give a mapping, got {ln!r}")
        _reject_unknown(ln, _ASSERTION_KEYS["lanes"], where)
        for key in ("cross_arrival", "stable"):
            if not isinstance(ln.get(key, True), bool):
                raise ValueError(f"{where}.{key}: must be true or false")
        s.assertions.lanes = LanesAssertion(
            cross_arrival=ln.get("cross_arrival", True), stable=ln.get("stable", True),
        )


_SUPPRESSING_LOG_LEVELS = ("off", "error", "warn")

_LEVELS = ("off", "error", "warn", "info", "debug", "trace")


def log_enables(rust_log: str, target: str, level: str) -> bool:
    """Whether an ``EnvFilter`` directive string emits ``level`` at ``target``.

    The most specific directive whose target is ``target`` or a module-path
    prefix of it decides; a bare level is the default for every other
    target, and with none the default is ``error``. Span and field filters
    are not read: a directive carrying them is treated as not matching.
    """
    default = "error"
    best: tuple[int, str] | None = None
    for part in rust_log.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            if part.lower() in _LEVELS:
                default = part.lower()
            continue
        name, lvl = part.rsplit("=", 1)
        lvl = lvl.strip().lower()
        if lvl not in _LEVELS or "[" in name or "{" in name:
            continue
        name = name.strip()
        if target == name or target.startswith(name + "::"):
            if best is None or len(name) > best[0]:
                best = (len(name), lvl)
    chosen = best[1] if best else default
    return _LEVELS.index(chosen) >= _LEVELS.index(level)


# Each assertion that reads a debug line, and the target that emits it.
_TARGETS = [
    ("paths_live", "fips::node::handlers::path"),
    ("path_floor", "fips::node::handlers::path"),
    ("discovery_limit", "fips::node::handlers::path"),
    ("reverse_heard", "fips::node::handlers::path"),
    ("rescue", "fips::node::handlers::path"),
    ("lanes", "fips::node::handlers::path"),
    ("active_timeouts", "fips::node::handlers::path"),
    ("active_timeouts", "fips::node::dataplane::wait"),
    ("max_dials", "fips::node::lifecycle"),
]


def _checklevels(s: Scenario):
    """Refuse an assertion whose lines the log level cannot emit.

    The path machine's state lines and the dial line are ``debug``; at
    ``info`` they are never written, and an assertion counting them would
    count zero whatever the node did: a ceiling would pass and a floor fail
    for the wrong reason. "Path switched" is ``info`` and needs only what
    the error guard below already refuses.
    """
    for key, target in _TARGETS:
        if getattr(s.assertions, key) is None:
            continue
        if not log_enables(s.logging.rust_log, target, "debug"):
            raise ValueError(
                f"assertions.{key} reads debug lines of {target}, which "
                f"logging.rust_log '{s.logging.rust_log}' does not emit. Add "
                f"'{target}=debug' (or wider) to rust_log, or drop the assertion."
            )
    if s.assertions.path_switches or s.assertions.switch_latency:
        if not log_enables(s.logging.rust_log, "fips::node::handlers::path", "info"):
            raise ValueError(
                f"logging.rust_log '{s.logging.rust_log}' suppresses the "
                f"info-level 'Path switched' line the path_switches and "
                f"switch_latency assertions read."
            )


def _validate_parent_switch_observability(s: Scenario):
    """Refuse a parent-switch assertion the log level cannot observe.

    The events these assertions count are emitted at ``info``. A scenario
    that declares one while setting ``logging.rust_log`` to ``warn`` or
    below counts zero switches: the minimum assertion then fails for the
    wrong reason, and the maximum assertion passes without observing
    anything, which is the failure mode the whole assertion effort exists
    to remove. Catch it at load rather than after the run.

    Deliberately conservative. It rejects only a default level that is
    demonstrably too coarse, and says nothing about per-target directives
    such as ``info,fips::node=debug``, which raise verbosity rather than
    lower it.
    """
    if (
        s.assertions.min_parent_switches is None
        and s.assertions.max_parent_switches is None
    ):
        return
    default_level = s.logging.rust_log.split(",")[0].strip().lower()
    if default_level in _SUPPRESSING_LOG_LEVELS:
        raise ValueError(
            f"logging.rust_log is '{s.logging.rust_log}', whose default level "
            f"'{default_level}' suppresses the info-level parent-switch events "
            f"that a parent-switch assertion counts. The assertion would see "
            f"zero switches regardless of what the tree did. Use 'info' or "
            f"more verbose, or drop the assertion."
        )


def _validate_error_observability(s: Scenario):
    """Refuse an error ceiling the log level cannot observe.

    Narrower than the parent-switch guard on purpose: ERROR lines survive
    every level except ``off``, so ``off`` is the only setting that turns
    this assertion into one that counts zero whatever the mesh did. Since
    the ceiling is applied by default, a scenario silencing its logs would
    otherwise acquire an assertion that cannot fail.
    """
    if s.assertions.max_errors is None:
        return
    default_level = s.logging.rust_log.split(",")[0].strip().lower()
    if default_level == "off":
        raise ValueError(
            "logging.rust_log is 'off', which suppresses the ERROR-level "
            "lines the max_errors assertion counts. The assertion would see "
            "zero errors regardless of what the mesh did. Raise the level, "
            "or state a deliberate override in assertions.max_errors."
        )


_STEPKEYS = {
    "down": {"at", "down", "mode", "end", "secs", "capture", "counters", "from", "to"},
    "load": {"at", "load", "secs", "streams", "bidir"},
}


def _seconds(value, where: str, positive: bool) -> float:
    """A number of seconds, at least 0 or above 0, refusing a bool."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{where}: must be a number of seconds, got {value!r}")
    if value < 0 or (positive and value == 0):
        raise ValueError(f"{where}: must be {'> 0' if positive else '>= 0'}, got {value!r}")
    return float(value)


def _pair(value, where: str) -> tuple[str, str]:
    """Two distinct node ids."""
    if not isinstance(value, (list, tuple)) or len(value) != 2 or value[0] == value[1]:
        raise ValueError(f"{where}: must be two distinct node ids, got {value!r}")
    return str(value[0]), str(value[1])


def _parsesteps(raw) -> list[Step]:
    """Parse ``schedule:``, a list of timed steps (see schedule.py)."""
    if not isinstance(raw, list):
        raise ValueError(f"schedule: must be a list of steps, got {raw!r}")
    steps = []
    for i, entry in enumerate(raw):
        where = f"schedule[{i}]"
        if not isinstance(entry, dict):
            raise ValueError(f"{where}: must be a mapping, got {entry!r}")
        kinds = [k for k in _STEPKEYS if k in entry]
        if len(kinds) != 1:
            raise ValueError(f"{where}: give exactly one of down or load")
        kind = kinds[0]
        _reject_unknown(entry, _STEPKEYS[kind], where)
        for key in ("at", "secs"):
            if key not in entry:
                raise ValueError(f"{where}: {key} is required")
        at = _seconds(entry["at"], f"{where}.at", positive=False)
        secs = _seconds(entry["secs"], f"{where}.secs", positive=True)
        if kind == "down":
            a, b = _pair(entry["down"], f"{where}.down")
            mode = entry.get("mode", "netem")
            if mode not in MODES:
                raise ValueError(f"{where}.mode: {mode!r} not in {MODES}")
            end = entry.get("end")
            src = entry.get("from")
            if mode == "oneway":
                if end is not None or {src, entry.get("to")} != {a, b}:
                    raise ValueError(
                        f"{where}: oneway names from and to, the edge's two ends, and no end"
                    )
                end = entry["to"]
            elif src is not None or "to" in entry:
                raise ValueError(f"{where}: from and to go with mode oneway")
            if mode == "admin" and end not in (a, b):
                raise ValueError(f"{where}.end: admin needs the end to take down, one of {a}, {b}")
            if mode == "netem" and end is not None:
                raise ValueError(f"{where}.end: a netem down holds both directions; drop end")
            ends = {}
            for key in ("capture", "counters"):
                ends[key] = entry.get(key, [])
                if not isinstance(ends[key], list) or any(n not in (a, b) for n in ends[key]):
                    raise ValueError(f"{where}.{key}: a list of the edge's ends, got {ends[key]!r}")
            steps.append(Step(at=at, kind=kind, secs=secs, edge=(min(a, b), max(a, b)),
                              mode=mode, end=end,
                              capture=tuple(str(n) for n in ends["capture"]),
                              counters=tuple(str(n) for n in ends["counters"]),
                              src=str(src) if src is not None else None))
        else:
            client, server = _pair(entry["load"], f"{where}.load")
            streams = _count(entry.get("streams", 1), f"{where}.streams", 1)
            bidir = entry.get("bidir", False)
            if not isinstance(bidir, bool):
                raise ValueError(f"{where}.bidir: must be true or false, got {bidir!r}")
            steps.append(Step(at=at, kind=kind, secs=secs, pair=(client, server),
                              streams=streams, bidir=bidir))
    return steps


def _checksteps(s: Scenario):
    """Refuse a step the run could not carry out as written.

    A down names an explicit edge; ``netem`` needs netem on; ``admin``
    needs a veth edge and no node churn (a restarted node's veth comes
    back up, ending the down early). ``admin`` is refused on a
    ``udp-veth`` edge: interface-bound UDP reports neither carrier nor
    presence, so the down would test nothing the netem mode does not.
    Every step ends inside the run.
    """
    if not s.schedule:
        return
    adjacency = s.topology.params.get("adjacency") if s.topology.algorithm == "explicit" else None
    edges: dict[tuple[str, str], str] = {}
    for entry in adjacency or []:
        a, b = str(entry[0]), str(entry[1])
        transport = str(entry[2]) if len(entry) >= 3 else s.topology.default_transport
        edges[(min(a, b), max(a, b))] = transport.split("+")[0]
    nodes = {n for e in edges for n in e}
    for i, step in enumerate(s.schedule):
        where = f"schedule[{i}]"
        if step.until > s.duration_secs:
            raise ValueError(
                f"{where}: ends at {step.until:g} s, after the run's {s.duration_secs} s"
            )
        if step.kind == "load":
            missing = [n for n in step.pair if n not in nodes]
            if missing:
                raise ValueError(f"{where}.load: {missing} not in the explicit topology")
            continue
        if step.edge not in edges:
            raise ValueError(f"{where}.down: {step.edge} is not an explicit edge")
        transport = edges[step.edge]
        if step.mode == "netem" and not s.netem.enabled:
            raise ValueError(f"{where}: a netem down needs netem.enabled")
        if step.mode == "oneway":
            if transport not in ("ethernet", "udp-veth"):
                raise ValueError(f"{where}: oneway needs a veth edge, not {transport}")
            if s.node_churn.enabled:
                raise ValueError(
                    f"{where}: oneway cannot run with node_churn, whose restart "
                    f"drops the ingress filter"
                )
        if step.mode == "admin":
            if transport == "udp-veth":
                raise ValueError(
                    f"{where}: admin on a udp-veth edge tests nothing a netem down "
                    f"does not; interface-bound UDP reports neither carrier nor presence"
                )
            if transport != "ethernet":
                raise ValueError(f"{where}: admin needs a veth edge, not {transport}")
            if s.node_churn.enabled:
                raise ValueError(
                    f"{where}: admin cannot run with node_churn, whose restart "
                    f"brings the veth back up"
                )


def _checkreverse(s: Scenario):
    """reverse_heard reads addresses and a capture: its steps must be
    oneway steps on udp-veth edges that capture at the dropped sender."""
    if s.assertions.reverse_heard is None:
        return
    adjacency = s.topology.params.get("adjacency") or []
    veth = {
        (min(str(e[0]), str(e[1])), max(str(e[0]), str(e[1])))
        for e in adjacency if len(e) >= 3 and str(e[2]).split("+")[0] == "udp-veth"
    }
    for i, step in enumerate(s.schedule):
        if step.kind != "down" or step.mode != "oneway":
            continue
        if step.edge not in veth or step.src not in step.capture:
            raise ValueError(
                f"schedule[{i}]: reverse_heard needs each oneway step on a udp-veth "
                f"edge, capturing at its from end ({step.src})"
            )


def _checksender(s: Scenario):
    """switch_latency's sender_ms applies only to a oneway down's dropped
    sender: refuse it in a scenario that schedules no oneway down, where it
    would bound nothing."""
    sl = s.assertions.switch_latency
    if sl is None or sl.sender_ms is None:
        return
    if not any(st.kind == "down" and st.mode == "oneway" for st in s.schedule):
        raise ValueError(
            "assertions.switch_latency.sender_ms: bounds the dropped sender of "
            "a oneway down, and the schedule has none"
        )


def _validate(s: Scenario):
    """Validate scenario constraints."""
    _checkreverse(s)
    _checksender(s)
    _validate_parent_switch_observability(s)
    _validate_error_observability(s)
    _checksteps(s)
    _checklevels(s)
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
        laned: set[str] = set()
        for i, entry in enumerate(adj):
            if not isinstance(entry, (list, tuple)) or len(entry) not in (2, 3, 4):
                raise ValueError(
                    f"explicit adjacency[{i}]: expected [nodeA, nodeB], "
                    f"[nodeA, nodeB, transport] or [nodeA, nodeB, udp-veth, "
                    f"{{lanes: n}}], got {entry}"
                )
            node_ids.update(str(p) for p in entry[:2])
            if len(entry) == 4:
                opts = entry[3]
                lanes = opts.get("lanes") if isinstance(opts, dict) else None
                if (
                    str(entry[2]) != "udp-veth" or set(opts) != {"lanes"}
                    or isinstance(lanes, bool) or not isinstance(lanes, int)
                    or not 1 <= lanes <= 4
                ):
                    raise ValueError(
                        f"explicit adjacency[{i}]: only a udp-veth edge takes "
                        f"{{lanes: n}}, n from 1 to 4, got {entry}"
                    )
                ends = {str(p) for p in entry[:2]}
                if ends & laned:
                    raise ValueError(
                        f"explicit adjacency[{i}]: a node holds at most one laned "
                        f"edge (its lanes are named vl<k>-<node>)"
                    )
                laned |= ends
                if s.node_churn.enabled:
                    raise ValueError(
                        f"explicit adjacency[{i}]: lanes cannot run with node_churn, "
                        f"whose restart does not rebuild them"
                    )
            if len(entry) == 3:
                transport = str(entry[2])
                if transport not in VALID_TRANSPORTS and transport not in DUAL_TRANSPORTS:
                    raise ValueError(
                        f"explicit adjacency[{i}]: transport '{transport}' "
                        f"not in {VALID_TRANSPORTS} or {DUAL_TRANSPORTS}"
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
    ms = s.assertions.max_stall
    if ms is not None and ms.stream == "udp" and not (
        s.traffic.enabled and s.traffic.udp_mbps
    ):
        raise ValueError(
            "assertions.max_stall.stream: udp needs traffic enabled with "
            "traffic.udp_mbps, or no UDP stream runs to measure"
        )
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
