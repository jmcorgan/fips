"""Post-run scenario assertions evaluated via control-socket data.

Assertions are declared in the scenario YAML under ``assertions:`` and
are evaluated near the end of the simulation, before teardown begins.
Each failing assertion is recorded with a clear pass/fail message; the
runner exits non-zero when any assertion fails.

Currently supported assertions:

- ``bloom_send_rate``: per-node trailing-window ceiling on
  ``stats.bloom.sent`` delta. Calibrated for the bloom-storm
  regression scenario but generally usable.
- ``min_parent_switches`` / ``max_parent_switches``: bounds on the
  parent switches counted from the node logs.
- ``max_errors``: ceiling on ERROR-level log lines (applied by default).
- ``baseline``: the mesh formed, agreed on a root and took parents.
- ``tree_parents``: named nodes ended with the named parents.
- ``congestion_signals``: floors on how many nodes saw each congestion
  counter.
- ``max_kernel_drops``: ceiling on the share of frames the kernel dropped
  at each node's Ethernet socket.
- ``max_replay_refusals``: ceiling on the replays the nodes refused.
- ``delivery``: datagrams of each configured size were delivered
  between node pairs, optionally proven to cross one transport.
- ``path_switches``, ``max_promotions``, ``switch_latency``,
  ``max_stall``, ``max_dials`` and ``paths_live``: a pair joined by two
  paths moved its traffic between them under one session, fast enough,
  without a stall, a re-peering or a dial, and the second path existed.
- ``active_timeouts``: a report, failing nothing, of the active path's
  timeouts that no down explains.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from .control import snapshot_all_bloom
from . import paths as P
from .paths import line_epoch, line_fields
from .scenario import (
    ActiveTimeoutsAssertion,
    MinTrafficAssertion,
    BaselineAssertion,
    BloomSendRateAssertion,
    CongestionSignalsAssertion,
    DeliveryAssertion,
    DiscoveryLimitAssertion,
    MaxKernelDropsAssertion,
    MaxReplayRefusalsAssertion,
    LanesAssertion,
    MaxDialsAssertion,
    MaxErrorsAssertion,
    MaxParentSwitchesAssertion,
    MaxPromotionsAssertion,
    MaxStallAssertion,
    MinParentSwitchesAssertion,
    PathFloorAssertion,
    PathsLiveAssertion,
    PathSwitchesAssertion,
    RescueAssertion,
    ReverseHeardAssertion,
    SwitchLatencyAssertion,
    TreeParentsAssertion,
)
from .topology import SimTopology

log = logging.getLogger(__name__)


@dataclass
class AssertionOutcome:
    name: str
    passed: bool
    detail: str


def _bloom_sent_total(node_data: dict) -> int | None:
    """Extract stats.bloom.sent from a show_bloom response."""
    stats = node_data.get("stats") or {}
    sent = stats.get("sent")
    if sent is None:
        return None
    try:
        return int(sent)
    except (TypeError, ValueError):
        return None


class BloomSendRateMonitor:
    """Samples per-node ``stats.bloom.sent`` to evaluate a trailing-window
    ceiling assertion at end-of-run.

    Usage:
        m = BloomSendRateMonitor(topology, cfg)
        m.sample_window_start()   # called window_secs before scenario end
        ...
        m.sample_end()            # called at scenario end
        outcome = m.evaluate()
    """

    def __init__(self, topology: SimTopology, cfg: BloomSendRateAssertion):
        self.topology = topology
        self.cfg = cfg
        self.window_start: dict[str, int] = {}
        self.window_end: dict[str, int] = {}

    def sample_window_start(self) -> None:
        snap = snapshot_all_bloom(self.topology)
        for nid, data in snap.items():
            v = _bloom_sent_total(data)
            if v is not None:
                self.window_start[nid] = v

    def sample_end(self) -> None:
        snap = snapshot_all_bloom(self.topology)
        for nid, data in snap.items():
            v = _bloom_sent_total(data)
            if v is not None:
                self.window_end[nid] = v

    def evaluate(self) -> AssertionOutcome:
        max_per_node = self.cfg.max_per_node
        window_secs = self.cfg.window_secs

        if not self.window_start or not self.window_end:
            return AssertionOutcome(
                name="bloom_send_rate",
                passed=False,
                detail=(
                    f"FAIL bloom_send_rate: failed to sample window endpoints "
                    f"(start={len(self.window_start)} nodes, "
                    f"end={len(self.window_end)} nodes)"
                ),
            )

        per_node_deltas: dict[str, int] = {}
        for nid, end_v in self.window_end.items():
            start_v = self.window_start.get(nid)
            if start_v is None:
                continue
            per_node_deltas[nid] = end_v - start_v

        offenders = {
            nid: d for nid, d in per_node_deltas.items() if d > max_per_node
        }
        max_obs = max(per_node_deltas.values()) if per_node_deltas else 0

        if offenders:
            sorted_off = sorted(offenders.items(), key=lambda kv: -kv[1])
            details = ", ".join(f"{nid}={d}" for nid, d in sorted_off)
            detail = (
                f"FAIL bloom_send_rate: {len(offenders)} node(s) exceeded "
                f"ceiling of {max_per_node} bloom_sent over trailing "
                f"{window_secs}s — offenders: {details} "
                f"(all per-node deltas: "
                f"{', '.join(f'{n}={v}' for n, v in sorted(per_node_deltas.items()))})"
            )
            return AssertionOutcome(
                name="bloom_send_rate",
                passed=False,
                detail=detail,
            )

        detail = (
            f"PASS bloom_send_rate: max per-node delta {max_obs} <= "
            f"ceiling {max_per_node} over trailing {window_secs}s "
            f"(per-node: "
            f"{', '.join(f'{n}={v}' for n, v in sorted(per_node_deltas.items()))})"
        )
        return AssertionOutcome(
            name="bloom_send_rate",
            passed=True,
            detail=detail,
        )


def evaluate_max_parent_switches(
    cfg: MaxParentSwitchesAssertion,
    parent_switch_count: int,
    scope: str,
) -> AssertionOutcome:
    """Stability ceiling on parent switches over the run.

    ``scope`` describes what was counted and appears in the message, so a
    reader can tell a per-node result from a mesh-wide one. Resolving a
    per-node scope to a real node is the caller's job, and so is failing
    loudly when it cannot: an unresolvable node would count zero switches
    and sail under any ceiling without having observed anything.
    """
    if parent_switch_count <= cfg.max_total:
        return AssertionOutcome(
            name="max_parent_switches",
            passed=True,
            detail=(
                f"PASS max_parent_switches: {parent_switch_count} switches "
                f"({scope}) <= ceiling {cfg.max_total}"
            ),
        )
    return AssertionOutcome(
        name="max_parent_switches",
        passed=False,
        detail=(
            f"FAIL max_parent_switches: {parent_switch_count} switches "
            f"({scope}) > ceiling {cfg.max_total} — the tree is reparenting "
            f"more than the hysteresis band should allow. Check whether a "
            f"cost change smaller than the hysteresis margin is still "
            f"triggering a switch."
        ),
    )


def evaluate_baseline(
    cfg: BaselineAssertion,
    snapshot: dict | None,
    sessions: int,
) -> AssertionOutcome:
    """Floor on the mesh having formed: nodes answered, agreed a root, took parents."""
    if not snapshot:
        return AssertionOutcome(
            name="baseline",
            passed=False,
            detail=(
                "FAIL baseline: no final tree snapshot was taken, so nothing "
                "about the mesh was observed. This is a harness failure."
            ),
        )

    reporting = len(snapshot)
    roots = {v.get("root") for v in snapshot.values() if v.get("root")}
    parented = sum(
        1 for v in snapshot.values()
        if v.get("parent") and v.get("parent") != v.get("my_node_addr")
    )

    parts, failures = [], []

    def note(ok, text):
        parts.append(text)
        if not ok:
            failures.append(text)

    if cfg.min_nodes_reporting is not None:
        note(reporting >= cfg.min_nodes_reporting,
             f"{reporting} node(s) answered (need {cfg.min_nodes_reporting})")
    if cfg.max_roots is not None:
        note(len(roots) <= cfg.max_roots and len(roots) >= 1,
             f"{len(roots)} distinct root(s) (allowed {cfg.max_roots})")
    if cfg.min_nodes_parented is not None:
        note(parented >= cfg.min_nodes_parented,
             f"{parented} node(s) have a parent (need {cfg.min_nodes_parented})")
    if cfg.min_sessions is not None:
        note(sessions >= cfg.min_sessions,
             f"{sessions} session(s) established (need {cfg.min_sessions})")

    summary = "; ".join(parts)
    if failures:
        return AssertionOutcome(
            name="baseline",
            passed=False,
            detail=(
                f"FAIL baseline: {'; '.join(failures)}. Full: {summary}"
            ),
        )
    return AssertionOutcome(
        name="baseline", passed=True, detail=f"PASS baseline: {summary}"
    )


def evaluate_tree_parents(
    cfg: TreeParentsAssertion,
    snapshot: dict | None,
) -> AssertionOutcome:
    """Check each node's parent in the final tree snapshot.

    Parents are compared by node address, resolved from the snapshot's own
    ``my_node_addr`` fields, so the check does not depend on the display
    name a node happened to publish.

    Every way of not knowing the answer is a failure: no snapshot, the
    node absent from it, the expected parent absent from it, or the node
    still claiming to be its own root. Each of those produces the same
    "no match" that a genuinely wrong parent does, and only saying so
    separately keeps a harness problem from reading as a routing verdict.
    """
    if not snapshot:
        return AssertionOutcome(
            name="tree_parents",
            passed=False,
            detail=(
                "FAIL tree_parents: no final tree snapshot was taken, so no "
                "node's parent was observed. This is a harness failure, not "
                "a statement about the tree."
            ),
        )

    addr_of = {
        nid: data.get("my_node_addr")
        for nid, data in snapshot.items()
        if data.get("my_node_addr")
    }
    id_of = {addr: nid for nid, addr in addr_of.items()}

    good, bad = [], []
    for child, want_parent in sorted(cfg.expected.items()):
        entry = snapshot.get(child)
        if entry is None:
            bad.append(
                f"{child} is absent from the snapshot ({len(snapshot)} node(s) "
                f"present: {', '.join(sorted(snapshot))})"
            )
            continue
        want_addr = addr_of.get(want_parent)
        if want_addr is None:
            bad.append(
                f"{child}: expected parent {want_parent} is absent from the "
                f"snapshot, so its address cannot be resolved"
            )
            continue
        got_addr = entry.get("parent")
        if got_addr == entry.get("my_node_addr"):
            bad.append(
                f"{child} is its own parent — it still believes it is root, "
                f"so the tree never converged around it (wanted {want_parent})"
            )
            continue
        if got_addr == want_addr:
            good.append(f"{child}->{want_parent}")
            continue
        got_id = id_of.get(got_addr) or entry.get("parent_display_name") or got_addr
        bad.append(f"{child} chose {got_id}, wanted {want_parent}")

    if bad:
        detail = f"FAIL tree_parents: {'; '.join(bad)}"
        if good:
            detail += f". Correct: {', '.join(good)}"
        return AssertionOutcome(name="tree_parents", passed=False, detail=detail)
    return AssertionOutcome(
        name="tree_parents",
        passed=True,
        detail=f"PASS tree_parents: {', '.join(good)}",
    )


_CONGESTION_FLOORS = (
    ("min_nodes_detected", "congestion_detected"),
    ("min_nodes_ce_forwarded", "ce_forwarded"),
    ("min_nodes_ce_received", "ce_received"),
)


def evaluate_congestion_signals(
    cfg: CongestionSignalsAssertion,
    snapshot: dict | None,
) -> AssertionOutcome:
    """Floors on how many nodes observed each congestion counter.

    ``snapshot`` is the final congestion snapshot keyed by node id. None
    means the snapshot never ran, which fails: a missing snapshot and a
    mesh that observed no congestion produce the same zero counts, and
    treating them alike is how an assertion comes to pass on an absence
    of evidence.
    """
    if not snapshot:
        return AssertionOutcome(
            name="congestion_signals",
            passed=False,
            detail=(
                "FAIL congestion_signals: no final congestion snapshot was "
                "taken, so no node was observed at all. This is a harness "
                "failure, not a statement about congestion."
            ),
        )

    parts, failures = [], []
    for attr, counter in _CONGESTION_FLOORS:
        floor = getattr(cfg, attr)
        if floor is None:
            continue
        hits = sorted(
            nid for nid, data in snapshot.items()
            if (data.get("congestion") or {}).get(counter, 0) > 0
        )
        parts.append(f"{counter}: {len(hits)} node(s) >0 (floor {floor})")
        if len(hits) < floor:
            failures.append(
                f"{counter} non-zero on {len(hits)} node(s), need {floor}"
            )
        else:
            parts[-1] += f" [{', '.join(hits)}]"

    summary = "; ".join(parts)
    if failures:
        return AssertionOutcome(
            name="congestion_signals",
            passed=False,
            detail=(
                f"FAIL congestion_signals: {'; '.join(failures)} — across "
                f"{len(snapshot)} node(s) sampled. Full counts: {summary}"
            ),
        )
    return AssertionOutcome(
        name="congestion_signals",
        passed=True,
        detail=f"PASS congestion_signals: {summary}",
    )


_TRANSPORT_LABEL = {"ethernet": "Ethernet", "udp": "UDP", "tcp": "TCP"}


def _transport_failure(transport: dict) -> str | None:
    """Return why the transport proof failed, or None when it holds."""
    node, want = transport["node"], transport["want"]
    for read in transport["reads"]:
        when, peers = read["when"], read["peers"]
        if peers is None:
            return (
                f"traversal unproven: show_peers on {node} failed {when} the "
                f"probe"
            )
        if not peers:
            return (
                f"traversal unproven: {node} reported zero peers {when} the "
                f"probe, after waiting {read['waited_s']:.0f}s"
            )
        other = [
            f"{str(p.get('npub', '?'))[:16]} via "
            f"{p.get('transport_type', 'no transport_type')}"
            for p in peers if p.get("transport_type") != want
        ]
        if other:
            return (
                f"{node} has a non-{_TRANSPORT_LABEL.get(want, want)} peer "
                f"{when} the probe ({'; '.join(other)}), so a probe to or "
                f"from it may not have crossed {want}"
            )
    return None


def evaluate_delivery(
    cfg: DeliveryAssertion,
    probe: dict | None,
) -> AssertionOutcome:
    """Every configured pair and size got ``min_replies`` replies in time.

    ``probe`` is the runner's delivery probe result. None means the probe
    never ran, which fails as a harness failure: no probe and no delivery
    would otherwise look alike.
    """
    if probe is None:
        return AssertionOutcome(
            name="delivery",
            passed=False,
            detail=(
                "FAIL delivery: the delivery probe never ran, so nothing was "
                "observed. This is a harness failure, not a statement about "
                "delivery."
            ),
        )

    failures = []
    transport = probe.get("transport")
    if transport is not None:
        why = _transport_failure(transport)
        if why:
            failures.append(why)

    parts = []
    for r in probe["results"]:
        label = f"{r['src']}->{r['dst']} {r['size']}B"
        if r["replies"] >= cfg.min_replies:
            parts.append(f"{label} {r['replies']}/{r['attempts']} in {r['elapsed_s']:.1f}s")
        else:
            failures.append(
                f"{label} got {r['replies']} of {cfg.min_replies} replies in "
                f"{r['elapsed_s']:.0f}s ({r['attempts']} attempts); last ping: "
                f"{r['last_output']!r}"
            )

    if failures:
        return AssertionOutcome(
            name="delivery",
            passed=False,
            detail=f"FAIL delivery: {'; '.join(failures)}",
        )
    via = f" via {transport['want']} ({transport['node']})" if transport else ""
    return AssertionOutcome(
        name="delivery",
        passed=True,
        detail=f"PASS delivery{via}: {'; '.join(parts)}",
    )


def evaluate_max_errors(
    cfg: MaxErrorsAssertion,
    errors: list[tuple[str, str]],
) -> AssertionOutcome:
    """Ceiling on ERROR-level log lines across the whole mesh.

    ``errors`` is the ``AnalysisResult.errors`` list of ``(source, line)``
    pairs rather than a bare count, so a failure can name the nodes and
    quote the lines. A ceiling breach that only reports a number sends the
    reader back to the logs it was supposed to save them reading.
    """
    count = len(errors)
    if count <= cfg.max_total:
        return AssertionOutcome(
            name="max_errors",
            passed=True,
            detail=(
                f"PASS max_errors: {count} ERROR line(s) mesh-wide <= "
                f"ceiling {cfg.max_total}"
            ),
        )

    per_node: dict[str, int] = {}
    for source, _line in errors:
        per_node[source] = per_node.get(source, 0) + 1
    worst = sorted(per_node.items(), key=lambda kv: -kv[1])
    breakdown = ", ".join(f"{src}={n}" for src, n in worst)
    samples = "\n".join(
        f"    [{src}] {line.strip()}" for src, line in errors[:5]
    )
    return AssertionOutcome(
        name="max_errors",
        passed=False,
        detail=(
            f"FAIL max_errors: {count} ERROR line(s) mesh-wide > ceiling "
            f"{cfg.max_total} — per node: {breakdown}. First "
            f"{min(5, count)}:\n{samples}"
        ),
    )


def evaluate_min_parent_switches(
    cfg: MinParentSwitchesAssertion,
    parent_switch_count: int,
) -> AssertionOutcome:
    """Sanity guard: fail the scenario if the harness-induced flap did
    not produce at least ``cfg.min_total`` parent switches across the
    run. Detects misconfiguration (e.g., wrong root election) where
    the bloom-rate assertion would otherwise trivially pass on any
    binary including the regressed one.
    """
    if parent_switch_count >= cfg.min_total:
        return AssertionOutcome(
            name="min_parent_switches",
            passed=True,
            detail=(
                f"PASS min_parent_switches: {parent_switch_count} switches "
                f"(mesh-wide) >= floor {cfg.min_total}"
            ),
        )
    return AssertionOutcome(
        name="min_parent_switches",
        passed=False,
        detail=(
            f"FAIL min_parent_switches: {parent_switch_count} switches "
            f"(mesh-wide) < floor {cfg.min_total} — harness did not induce "
            f"sufficient "
            f"parent flapping; bloom-rate assertion would be trivially "
            f"true. Check tree-snapshot-warmup.json: did the expected "
            f"node win the root election?"
        ),
    )


def _session_bytes(result: dict) -> int:
    """Bytes actually received in one iperf3 session, or 0 if it failed.

    iperf3 reports a failed run as a top-level ``error`` string with no
    ``end`` block, and a killed-but-partial run still carries whatever it
    managed. Both are handled by reading the received total and treating
    anything missing as zero, so a session only counts when it moved bytes.
    """
    if not isinstance(result, dict) or result.get("error"):
        return 0
    end = result.get("end")
    if not isinstance(end, dict):
        return 0
    summary = end.get("sum_received") or end.get("sum_sent")
    if not isinstance(summary, dict):
        return 0
    value = summary.get("bytes", 0)
    return value if isinstance(value, int) and value > 0 else 0


def evaluate_min_traffic(
    cfg: MinTrafficAssertion,
    results: list[dict],
) -> AssertionOutcome:
    """Floor on iperf3 sessions that actually carried data.

    Without this the traffic generator is decoration: the results were
    written to disk and never read, so a scenario whose every session
    failed still passed on a healthy control plane. A rebind under load is
    exactly the case a tree snapshot cannot see.
    """
    per_session = [_session_bytes(r) for r in results]
    ok = [b for b in per_session if b > 0]
    total = sum(ok)

    if len(ok) >= cfg.min_sessions_ok and total >= cfg.min_bytes_total:
        return AssertionOutcome(
            name="min_traffic",
            passed=True,
            detail=(
                f"PASS min_traffic: {len(ok)}/{len(results)} session(s) moved "
                f"data (need {cfg.min_sessions_ok}); {total} byte(s) total "
                f"(need {cfg.min_bytes_total})"
            ),
        )

    return AssertionOutcome(
        name="min_traffic",
        passed=False,
        detail=(
            f"FAIL min_traffic: {len(ok)}/{len(results)} session(s) moved data "
            f"(need {cfg.min_sessions_ok}); {total} byte(s) total (need "
            f"{cfg.min_bytes_total}). A green control plane with no traffic "
            f"means the data path did not survive what the scenario did to it."
        ),
    )


def _stamp(t: float) -> str:
    """A UTC wall-clock time to the millisecond, for a failure message."""
    return datetime.fromtimestamp(t, timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z"


def evaluate_path_switches(
    cfg: PathSwitchesAssertion,
    switches: list[tuple[str, str]],
    flaps: int,
) -> AssertionOutcome:
    """Band on path switches over the run.

    ``switches`` is ``AnalysisResult.path_switches``. ``min_total`` catches
    a run whose flaps moved nothing: a two-path suite in which no switch
    happened tested nothing. The ceiling is the stability bound: a healthy
    pair switches only when a path goes and comes back, so with
    ``per_flap`` it is that many per flap the run made (``flaps``) plus
    ``extra``, and ``max_total`` caps it outright.
    """
    count = len(switches)
    ceilings = []
    if cfg.max_total is not None:
        ceilings.append((cfg.max_total, f"max_total {cfg.max_total}"))
    if cfg.per_flap is not None:
        ceiling = cfg.per_flap * flaps + cfg.extra
        ceilings.append(
            (ceiling, f"{cfg.per_flap} per flap x {flaps} flap(s) + {cfg.extra} = {ceiling}")
        )
    per_node: dict[str, int] = {}
    for source, _line in switches:
        per_node[source] = per_node.get(source, 0) + 1
    breakdown = ", ".join(f"{src}={n}" for src, n in sorted(per_node.items())) or "none"
    if cfg.min_total is not None and count < cfg.min_total:
        return AssertionOutcome(
            name="path_switches",
            passed=False,
            detail=(
                f"FAIL path_switches: {count} switches < floor {cfg.min_total} "
                f"({breakdown}): the run did not move traffic between paths. "
                f"Check that both paths were Live before the first flap."
            ),
        )
    if ceilings:
        ceiling, why = min(ceilings)
        if count > ceiling:
            return AssertionOutcome(
                name="path_switches",
                passed=False,
                detail=(
                    f"FAIL path_switches: {count} switches > ceiling {ceiling} "
                    f"({why}; {breakdown}): traffic moved between paths more "
                    f"than the flaps account for."
                ),
            )
    return AssertionOutcome(
        name="path_switches",
        passed=True,
        detail=(
            f"PASS path_switches: {count} switches ({breakdown}) within "
            f"[{cfg.min_total if cfg.min_total is not None else 0}, "
            f"{min(ceilings)[0] if ceilings else 'inf'}]"
        ),
    )


# How far either side of a timeout a node's "Task wait" lines are read. The
# line is written once a second, so the one that reports a wait before the
# timeout can come up to a second after it.
WAIT_BEFORE = 2.0
WAIT_AFTER = 1.0

# The smallest wait the node writes a line for.
WAIT_FLOOR = 5


def _waited(waits: list[tuple[str, str]], nodes: list[str], t: float) -> str:
    """Each node's largest task wait around time ``t``: a figure, under the
    line's floor when the node wrote lines but none near ``t``, or "not kept"
    when its log has none, which says nothing either way."""
    shown = []
    for node in nodes:
        mine = [(line_epoch(line), line_fields(line)) for src, line in waits if src == node]
        near = [
            int(f["worst_ms"]) for at, f in mine
            if at is not None and "worst_ms" in f
            and t - WAIT_BEFORE <= at <= t + WAIT_AFTER
        ]
        if near:
            figure = f"{max(near)} ms"
        elif mine:
            figure = f"under {WAIT_FLOOR} ms"
        else:
            figure = "not kept"
        shown.append(f"{_short(node)} {figure}")
    return ", ".join(shown)


def evaluate_active_timeouts(
    cfg: ActiveTimeoutsAssertion,
    path_lines: list[tuple[str, str]],
    downs: list[tuple[float, str, str]],
    waits: list[tuple[str, str]],
    nodes: list[str],
) -> AssertionOutcome:
    """Report the timeouts of a node's active path that no down explains.

    A ``Live -> Suspect why=Timeout`` on the active path counts unless it
    falls within ``cfg.within_ms`` after a down stamped at that node. Each
    one is printed with each node's largest task wait near it. This never
    fails a run: ``downs`` are ``(stamp, a, b)`` as for ``switch_latency``.
    """
    bound = cfg.within_ms / 1000.0
    hits: list[tuple[float, str, str]] = []
    inside = 0
    for source, peers in sorted(P.timelines(path_lines).items()):
        for tl in peers.values():
            for c in tl.changes:
                if not (c.active and c.frm == "Some(Live)" and c.nxt == "Some(Suspect)"
                        and c.why == "Timeout"):
                    continue
                if any(source in (a, b) and 0 <= c.t - t <= bound for t, a, b in downs):
                    inside += 1
                else:
                    hits.append((c.t, source, c.path_id))
    shown = "".join(
        f"; {_short(source)} path {pid} at {_stamp(t)}, task wait: "
        f"{_waited(waits, nodes, t)}"
        for t, source, pid in sorted(hits)
    )
    return AssertionOutcome(
        name="active_timeouts",
        passed=True,
        detail=(
            f"REPORT active_timeouts: {len(hits)} outside a flap, {inside} inside "
            f"the {cfg.within_ms} ms after a down{shown}"
        ),
    )


def evaluate_max_promotions(
    cfg: MaxPromotionsAssertion,
    promotions: list[tuple[str, str]],
) -> AssertionOutcome:
    """Per-node ceiling on "Peer promoted to active" lines.

    ``promotions`` is ``AnalysisResult.peers_promoted``: one per handshake
    that completed on that node. The first per peer is the pair meeting;
    any beyond the ceiling is a re-peering, the session torn down and
    rebuilt, which a switchover suite exists to show does not happen.
    """
    per_node: dict[str, int] = {}
    for source, _line in promotions:
        per_node[source] = per_node.get(source, 0) + 1
    over = {src: n for src, n in per_node.items() if n > cfg.per_node}
    if not over:
        return AssertionOutcome(
            name="max_promotions",
            passed=True,
            detail=(
                f"PASS max_promotions: every node promoted at most "
                f"{cfg.per_node} time(s) ({len(promotions)} total)"
            ),
        )
    breakdown = ", ".join(f"{src}={n}" for src, n in sorted(over.items()))
    samples = "\n".join(
        f"    [{src}] {line.strip()}" for src, line in promotions if src in over
    )
    return AssertionOutcome(
        name="max_promotions",
        passed=False,
        detail=(
            f"FAIL max_promotions: {breakdown} exceed(s) the per-node ceiling "
            f"of {cfg.per_node}. A second promotion is a re-peering: the "
            f"session was lost and rebuilt, so a switchover did not carry.\n"
            f"{samples}"
        ),
    )


def switch_delays(
    downs: list[tuple[float, str, str]],
    switches: list[tuple[str, str]],
) -> list[tuple[float, str, float | None]]:
    """Each down's delay to the first switch at each of its two ends.

    ``downs`` are ``(stamp, a, b)`` with ``a`` and ``b`` named as the log
    sources are; ``switches`` are ``(source, line)``. Returns ``(stamp,
    end, seconds)`` per down and end, ``seconds`` being ``None`` where the
    end logged no switch at or after the stamp.
    """
    timed: dict[str, list[float]] = {}
    for source, line in switches:
        t = line_epoch(line)
        if t is not None:
            timed.setdefault(source, []).append(t)
    for times in timed.values():
        times.sort()
    out = []
    for down_at, a, b in downs:
        for end in (a, b):
            after = [t for t in timed.get(end, []) if t >= down_at]
            out.append((down_at, end, after[0] - down_at if after else None))
    return out


def dropped_senders(records: list[dict], cname) -> dict[float, str]:
    """The end whose own sends each ``oneway`` down dropped, by its stamp.

    ``records`` are the schedule's down records, each carrying its
    ``mode``, its ``src`` (the end whose frames were dropped) and its
    ``down`` stamp, the same stamp the down's flap event carries.
    ``cname`` maps a node id to its container, the name the log sources
    use. A two-way down has no dropped sender and is absent.
    """
    return {
        r["down"]: cname(r["src"])
        for r in records
        if r.get("mode") == "oneway" and r.get("src") and r.get("down") is not None
    }


def _active_at(path_lines: list[tuple[str, str]], source: str, t: float) -> set[str]:
    """The addresses the link to each of ``source``'s peers sent on at ``t``,
    for each peer whose active address the lines give.

    The latest "Path switched" line at or before ``t`` names it (``to``),
    followed through any "Path moved to a new address" of that address
    after it. With no switch by then, the link was on its original path,
    which the first switch after ``t`` names as ``from``, or failing that
    the original's own first state line (paths.timelines). A peer whose
    link logged neither has no address here.
    """
    cur: dict[str, str] = {}
    first_from: dict[str, str] = {}
    for src, line in path_lines:
        if src != source:
            continue
        at = line_epoch(line)
        if at is None:
            continue
        f = line_fields(line)
        peer = f.get("peer", "?")
        if "Path switched" in line:
            if at <= t:
                cur[peer] = f.get("to", "?")
            else:
                first_from.setdefault(peer, f.get("from", "?"))
        elif "Path moved to a new address" in line and at <= t:
            if cur.get(peer) == f.get("from"):
                cur[peer] = f.get("to", "?")
    for peer, tl in P.timelines(path_lines).get(source, {}).items():
        if peer in cur:
            continue
        if peer in first_from:
            cur[peer] = first_from[peer]
            continue
        first = next((c for c in tl.changes if c.path_id == tl.original), None)
        if first is not None:
            cur[peer] = first.addr
    return set(cur.values())


def _at(addr: str, wanted: set[str]) -> bool:
    """Whether a path's remote address is one of ``wanted``: a MAC, or an
    IP whatever the port."""
    return addr.lower() in wanted or addr.rsplit(":", 1)[0] in wanted


def uncarried_downs(
    downs: list[tuple[float, str, str]],
    path_lines: list[tuple[str, str]],
    addrs: dict[tuple[float, str], set[str]],
) -> dict[tuple[float, str], str]:
    """The ends at which a down's path did not carry the link when it went
    down, by ``(stamp, end)``, each with the address the link was on.

    ``addrs`` gives, by ``(stamp, end)``, the remote addresses the down's
    path has at that end: the other end's veth IP or MAC. An end with none
    given, or whose active address the lines do not give, is left out, and
    ``evaluate_switch_latency`` measures it as before.
    """
    out = {}
    for down_at, a, b in downs:
        for end in (a, b):
            wanted = {x.lower() for x in addrs.get((down_at, end), set())}
            if not wanted:
                continue
            active = _active_at(path_lines, end, down_at)
            if active and not any(_at(x, wanted) for x in active):
                out[(down_at, end)] = ", ".join(sorted(active))
    return out


def evaluate_switch_latency(
    cfg: SwitchLatencyAssertion,
    downs: list[tuple[float, str, str]],
    switches: list[tuple[str, str]],
    senders: dict[float, str] | None = None,
    uncarried: dict[tuple[float, str], str] | None = None,
) -> AssertionOutcome:
    """Ceiling on the time from each down to the path switch it caused.

    ``downs`` are ``(stamp, a, b)``: the epoch each down was stamped inside
    the container immediately before the command that made it, and its
    two ends named as the log sources are. Without ``each_end`` a down
    passes when either end switched within its ceiling; with it, every end
    must. The ceiling is ``max_ms``, except that with ``sender_ms`` set the
    end whose own sends a one-way down dropped (``senders``, by the down's
    stamp, from ``dropped_senders``) has ``sender_ms`` instead.
    ``signalled_ms`` bounds each end's first switch on its own. The whole
    distribution is printed, so a pass shows its margin.

    An end at which the down's path did not carry the link when it went
    down (``uncarried``, by the down's stamp and the end, from
    ``uncarried_downs``) has no switch for the down to cause: its first
    switch after the down is some later move, such as the fail-back after
    the restore. Such an end is not measured, and the run fails on the
    unmet precondition, naming the end, the down and where the link was.
    """
    if not downs:
        return AssertionOutcome(
            name="switch_latency",
            passed=False,
            detail="FAIL switch_latency: no link was taken down, nothing measured",
        )
    senders = senders or {}
    uncarried = uncarried or {}
    delays = switch_delays(downs, switches)

    def sender(down_at: float, end: str) -> bool:
        """Whether ``end`` takes the dropped sender's ceiling for this down."""
        return cfg.sender_ms is not None and senders.get(down_at) == end

    def ceiling(down_at: float, end: str) -> int:
        """The ceiling in ms for ``end``'s first switch after this down."""
        return cfg.sender_ms if sender(down_at, end) else cfg.max_ms

    failures = []
    for down_at, a, b in downs:
        ends = {end: d for t, end, d in delays if t == down_at and end in (a, b)}
        for end in sorted(e for e in ends if (down_at, e) in uncarried):
            failures.append(
                f"{end} after {a}--{b} down at {_stamp(down_at)}: precondition not met, "
                f"the down's path did not carry the link at {end} when it went down "
                f"(it was on {uncarried[(down_at, end)]}), so no switch latency is measured"
            )
            del ends[end]
        if not ends:
            continue
        within = {
            end: d for end, d in ends.items()
            if d is not None and d <= ceiling(down_at, end) / 1000.0
        }
        if cfg.each_end:
            for end, d in sorted(ends.items()):
                if end not in within:
                    got = "no switch" if d is None else f"{d * 1000:.0f} ms"
                    role = (
                        f" (dropped sender, ceiling {cfg.sender_ms} ms)"
                        if sender(down_at, end) else ""
                    )
                    failures.append(
                        f"{end}{role} after {a}--{b} down at {_stamp(down_at)}: {got}"
                    )
        elif not within:
            bound = (
                f"{cfg.max_ms} ms" if cfg.sender_ms is None or down_at not in senders
                else "its ceiling"
            )
            failures.append(
                f"{a}--{b} down at {_stamp(down_at)}: no switch at either end "
                f"within {bound}"
            )
        if cfg.signalled_ms is not None:
            for end, d in sorted(ends.items()):
                if d is None or d * 1000 > cfg.signalled_ms:
                    got = "no switch" if d is None else f"{d * 1000:.0f} ms"
                    failures.append(
                        f"{end} after {a}--{b} down at {_stamp(down_at)}: {got} "
                        f"> signalled ceiling {cfg.signalled_ms} ms"
                    )
    shown = ", ".join(
        f"{end}=not measured" if (t, end) in uncarried else
        f"{end}={'none' if d is None else f'{d * 1000:.0f}'}"
        + (" (dropped sender)" if sender(t, end) else "")
        for t, end, d in delays
    )
    scope = "each end" if cfg.each_end else "either end"
    limits = (
        f"ceiling {cfg.max_ms} ms"
        + (f", dropped sender {cfg.sender_ms} ms" if cfg.sender_ms is not None else "")
        + (f", signalled {cfg.signalled_ms} ms" if cfg.signalled_ms else "")
    )
    if failures:
        return AssertionOutcome(
            name="switch_latency",
            passed=False,
            detail=(
                f"FAIL switch_latency ({scope}, {limits}): {'; '.join(failures)}. "
                f"All delays (ms): {shown}"
            ),
        )
    return AssertionOutcome(
        name="switch_latency",
        passed=True,
        detail=(
            f"PASS switch_latency ({scope}, {limits}) over {len(downs)} down(s); "
            f"delays (ms): {shown}"
        ),
    )


# iperf3's error when a session is started against a server still serving
# another: a collision between the harness's own sessions, not a stall.
_BUSY = "the server is busy"


def _stall(result: dict) -> float:
    """Longest run of consecutive zero-byte intervals at the receiver.

    Reads the server's intervals, which the client fetches with
    ``--get-server-output``: they count the bytes that arrived. The client's
    own intervals count what the application wrote into its socket, and a
    sender whose TCP is recovering after a switch writes in bursts, with
    empty seconds between them while data is still being delivered.

    Raises ``ValueError`` for a result that cannot be read: one carrying an
    ``error``, or with no receiver intervals. Such a session measured
    nothing, and reading it as no stall is how a switchover that killed a
    session passed.
    """
    if not isinstance(result, dict):
        raise ValueError(f"not a result object: {result!r:.80}")
    if result.get("error"):
        raise ValueError(f"error: {result['error']}")
    server = result.get("server_output_json")
    if not isinstance(server, dict):
        raise ValueError("no receiver output (server_output_json)")
    if server.get("error"):
        raise ValueError(f"receiver error: {server['error']}")
    intervals = server.get("intervals")
    if not isinstance(intervals, list) or not intervals:
        raise ValueError("no receiver intervals")
    longest = 0.0
    run = 0.0
    for iv in intervals:
        summary = iv.get("sum") if isinstance(iv, dict) else None
        if not isinstance(summary, dict):
            raise ValueError("an interval without a sum")
        seconds = summary.get("seconds", 1.0)
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds < 0:
            seconds = 1.0
        if summary.get("bytes", 0) == 0:
            run += seconds
            longest = max(longest, run)
        else:
            run = 0.0
    return longest


def _session(result, kind: str = "session") -> str:
    """Where and when an iperf3 session (or stream) started, for a message."""
    if not isinstance(result, dict):
        return f"an unreadable {kind}"
    start = result.get("start") if isinstance(result.get("start"), dict) else {}
    when = (start.get("timestamp") or {}).get("time", "?")
    peer = ((start.get("connecting_to") or {}).get("host")) or "?"
    if peer == "?" and isinstance(result.get("_meta"), dict):
        meta = result["_meta"]
        peer = f"{meta.get('server', '?')} from {meta.get('client', '?')}"
    return f"{kind} to {peer} at {when}"


def _measure(results: list[dict], kind: str):
    """Each readable result's stall, the unreadable ones named, and the
    busy-server collisions named."""
    measured: list[tuple[float, dict]] = []
    unreadable: list[str] = []
    busy: list[str] = []
    for r in results:
        try:
            measured.append((_stall(r), r))
        except ValueError as e:
            if _BUSY in str(e):
                busy.append(_session(r, kind))
            else:
                unreadable.append(f"{_session(r, kind)} ({e})")
    return measured, unreadable, busy


def _reported(results: list[dict]) -> str:
    """The TCP sessions' receiver stall, reported beside a UDP bound."""
    measured, unreadable, busy = _measure(results, "session")
    if not measured:
        figure = "none measured"
    else:
        figure = (
            f"longest zero-byte run {max(m for m, _ in measured):.0f} s "
            f"across {len(measured)} session(s)"
        )
    extra = "".join(
        f", {len(group)} {what}" for group, what in (
            (unreadable, "unreadable"), (busy, "collided with a busy server"),
        ) if group
    )
    return f"; TCP (reported, not bounded): {figure}{extra}"


def _restarted(restarts: int) -> str:
    """The run's restarted UDP streams, for the stall check's message."""
    if not restarts:
        return ""
    return (
        f"; {restarts} UDP stream(s) restarted after a start that never ran, "
        f"the seconds before not measured"
    )


def evaluate_max_stall(
    cfg: MaxStallAssertion,
    results: list[dict],
    udp: list[dict] | None = None,
    restarts: int = 0,
) -> AssertionOutcome:
    """Ceiling on the longest zero-byte run inside any iperf3 session.

    ``min_traffic`` cannot see a hole: a session that stalls for ten
    seconds mid-run still moves bytes before and after. This reads the
    receiver's per-interval totals and fails on the longest run of zeros
    across every session. A session that cannot be read (an error, no
    intervals) fails it too, naming the session, except a busy server,
    which is a collision between the harness's own sessions: it is listed,
    not measured, and a run in which every session collided measured
    nothing and fails.

    With ``stream: udp`` the ceiling holds the constant-rate UDP streams
    (``udp``) instead, by the same rules, and the TCP sessions' figure is
    reported beside it. A stream that lost its start and ran on its second
    is held like any other, and every such restart in the run (``restarts``)
    goes in the message, because a lost start is otherwise green and its
    seconds are not measured. The count comes from the run, not from
    ``udp``: a restarted stream the run kills at its end leaves no result.
    """
    if cfg.stream == "udp":
        held, kind = list(udp or []), "UDP stream"
        note = _restarted(restarts) + _reported(results)
    else:
        held, kind, note = results, "session", ""
    if not held:
        return AssertionOutcome(
            name="max_stall",
            passed=False,
            detail=f"FAIL max_stall: no iperf3 {kind} ran, nothing measured{note}",
        )
    measured, unreadable, busy = _measure(held, kind)
    collided = f"; {len(busy)} collided with a busy server, not measured" if busy else ""
    if unreadable:
        return AssertionOutcome(
            name="max_stall",
            passed=False,
            detail=(
                f"FAIL max_stall: {len(unreadable)} of {len(held)} {kind}(s) "
                f"could not be read: {'; '.join(unreadable)}{collided}{note}"
            ),
        )
    if not measured:
        return AssertionOutcome(
            name="max_stall",
            passed=False,
            detail=f"FAIL max_stall: no {kind} was measured{collided}{note}",
        )
    worst_secs, worst = max(measured, key=lambda pair: pair[0])
    if worst_secs <= cfg.max_secs:
        return AssertionOutcome(
            name="max_stall",
            passed=True,
            detail=(
                f"PASS max_stall: longest zero-byte run {worst_secs:.0f} s across "
                f"{len(measured)} {kind}(s), ceiling {cfg.max_secs:g} s{collided}{note}"
            ),
        )
    return AssertionOutcome(
        name="max_stall",
        passed=False,
        detail=(
            f"FAIL max_stall: the {_session(worst, kind)} moved nothing for "
            f"{worst_secs:.0f} s, over the ceiling of {cfg.max_secs:g} s{collided}{note}"
        ),
    )


def evaluate_max_dials(
    cfg: MaxDialsAssertion,
    dials: list[tuple[str, str]],
    promotions: list[tuple[str, str]],
    anon_dials: list[tuple[str, str]] | None = None,
) -> AssertionOutcome:
    """Ceiling on dials a node started after first contact.

    ``dials`` is ``AnalysisResult.dials`` ("Connection initiated"),
    ``promotions`` ``AnalysisResult.peers_promoted`` and ``anon_dials``
    ``AnalysisResult.anon_dials`` ("Anonymous discovery connection
    initiated"). A named dial counts once the node has promoted a peer; a
    node that never promoted has no link to dial past. An anonymous dial
    names no peer, so first contact is the first one to its transport and
    address: every later one to the same pair counts, whether or not the
    node logged a promotion, since only the dialling end writes that line.
    The counts are per node and summed against the ceiling.
    """
    first: dict[str, float] = {}
    for source, line in promotions:
        t = line_epoch(line)
        if t is not None and (source not in first or t < first[source]):
            first[source] = t
    named: dict[str, list[str]] = {}
    for source, line in dials:
        t = line_epoch(line)
        if source in first and t is not None and t > first[source]:
            named.setdefault(source, []).append(line.strip())
    seen: set[tuple[str, str | None, str | None]] = set()
    anon: dict[str, list[str]] = {}
    for source, line in anon_dials or []:
        f = line_fields(line)
        key = (source, f.get("transport_id"), f.get("remote_addr"))
        if key in seen:
            anon.setdefault(source, []).append(line.strip())
        seen.add(key)
    late = {
        src: named.get(src, []) + anon.get(src, [])
        for src in sorted(set(named) | set(anon))
    }
    over = {src: lines for src, lines in late.items() if len(lines) > cfg.max_total}

    def count(per: dict[str, list[str]]) -> str:
        """Per-node counts of ``per``, or "none"."""
        return ", ".join(f"{src}={len(v)}" for src, v in sorted(per.items())) or "none"

    counts = f"named: {count(named)}; anonymous: {count(anon)}"
    if over:
        samples = "\n".join(
            f"    [{src}] {line}" for src, lines in sorted(over.items()) for line in lines[:3]
        )
        return AssertionOutcome(
            name="max_dials",
            passed=False,
            detail=(
                f"FAIL max_dials: dials after first contact ({counts}) "
                f"exceed the per-node ceiling of {cfg.max_total}: a live peer "
                f"was dialled.\n{samples}"
            ),
        )
    return AssertionOutcome(
        name="max_dials",
        passed=True,
        detail=(
            f"PASS max_dials: dials after first contact: {counts} "
            f"(ceiling {cfg.max_total} per node; "
            f"{len(first)} node(s) promoted)"
        ),
    )


def _creates(f: dict[str, str]) -> bool:
    """Whether a "Path state changed" line's fields create a path during
    the run: a path's first line, from ``None``, unless a renewal logged it.

    A renewal (``why=Renewed``) starts the link again, and the ``from=None``
    line it logs begins the new link's original path, which
    ``evaluate_paths_live`` counts as the link's original, as it does the
    first link's, which logs no line.
    """
    return f.get("from") == "None" and f.get("why") != "Renewed"


def live_paths(path_lines: list[tuple[str, str]]) -> dict[str, dict[str, set[str]]]:
    """Per node and peer, the paths created during the run that went Live.

    A path's creation is its first "Path state changed" line, from
    ``None``, unless a renewal logged it (``_creates``); a
    ``next=Some(Live)`` line under a ``path_id`` with no creation line is
    the link's original path changing state, which is not one of these.
    """
    created: dict[tuple[str, str], set[str]] = {}
    live: dict[str, dict[str, set[str]]] = {}
    for source, line in path_lines:
        if "Path state changed" not in line:
            continue
        f = line_fields(line)
        peer, pid = f.get("peer", "?"), f.get("path_id")
        if pid is None:
            continue
        key = (source, peer)
        if f.get("from") == "None":
            if _creates(f):
                created.setdefault(key, set()).add(pid)
        elif f.get("next") == "Some(Live)" and pid in created.get(key, set()):
            live.setdefault(source, {}).setdefault(peer, set()).add(pid)
    return live


def configured_live(
    path_lines: list[tuple[str, str]],
    source: str,
    pairs: set[tuple[str, str]],
    deadline: float | None,
) -> dict[tuple[str, str], str]:
    """At one node, the configured pairs at which a path created during the
    run (``_creates``) went Live by ``deadline``: pair -> the first such
    path_id."""
    created: set[str] = set()
    out: dict[tuple[str, str], str] = {}
    for src, line in path_lines:
        if src != source or "Path state changed" not in line:
            continue
        f = line_fields(line)
        pid = f.get("path_id")
        if f.get("from") == "None":
            if _creates(f):
                created.add(pid)
            continue
        t = line_epoch(line)
        pair = (f.get("transport_id", "?"), f.get("remote_addr", "?"))
        if (
            f.get("next") == "Some(Live)" and pid in created and pair in pairs
            and (deadline is None or (t is not None and t <= deadline))
        ):
            out.setdefault(pair, pid)
    return out


def evaluate_paths_live(
    cfg: PathsLiveAssertion,
    path_lines: list[tuple[str, str]],
    nodes: list[str],
    configured: dict[str, set[tuple[str, str]]] | None = None,
    since: float | None = None,
) -> AssertionOutcome:
    """Floor on the paths each node held Live to one peer: the control that
    a second path existed.

    Each of ``nodes`` (named as the log sources are) counts, for its best
    peer, the paths created during the run that went Live, plus one for
    the link's original path, which is Live from link-up and logs no line
    (or, after a renewal, logs its beginning, which creates nothing).
    Every node must reach ``min``; a run in which no second path formed
    tested a switchover between paths that were never there. With
    ``configured``, only the nodes given pairs in ``configured`` count, and
    only paths Live at those pairs, each pair once, by ``within_secs``
    after ``since``.
    """
    if cfg.configured:
        if not configured:
            return AssertionOutcome(
                name="paths_live", passed=False,
                detail="FAIL paths_live: configured, but no node has configured pairs",
            )
        deadline = since + cfg.within_secs if since is not None and cfg.within_secs else None
        counts, held = {}, {}
        for node, pairs in sorted(configured.items()):
            held[node] = configured_live(path_lines, node, pairs, deadline)
            counts[node] = 1 + len(held[node])
        short = {n: c for n, c in counts.items() if c < cfg.min}
        shown = "; ".join(
            f"{n}={c} ({', '.join(f'{t} {a}' for t, a in sorted(held[n]))})"
            for n, c in sorted(counts.items())
        )
        by = f" by {cfg.within_secs} s after warmup" if deadline else ""
        if short:
            return AssertionOutcome(
                name="paths_live", passed=False,
                detail=(
                    f"FAIL paths_live: fewer than {cfg.min} paths Live at distinct "
                    f"configured pairs{by}, original included: {shown}"
                ),
            )
        return AssertionOutcome(
            name="paths_live", passed=True,
            detail=f"PASS paths_live: Live at distinct configured pairs{by}, original included: {shown}",
        )
    live = live_paths(path_lines)
    counts = {}
    for node in nodes:
        peers = live.get(node, {})
        counts[node] = 1 + max((len(p) for p in peers.values()), default=0)
    short = {n: c for n, c in counts.items() if c < cfg.min}
    shown = ", ".join(f"{n}={c}" for n, c in sorted(counts.items()))
    if short or not counts:
        return AssertionOutcome(
            name="paths_live",
            passed=False,
            detail=(
                f"FAIL paths_live: {', '.join(sorted(short)) or 'no node'} held "
                f"fewer than {cfg.min} Live path(s) to a peer ({shown}), counting "
                f"the link's original path as one: the paths the run moved "
                f"traffic between were never all there."
            ),
        )
    return AssertionOutcome(
        name="paths_live",
        passed=True,
        detail=f"PASS paths_live: Live paths per node, original included: {shown} (floor {cfg.min})",
    )


def _short(source: str) -> str:
    """A node's id from its container name, for a message."""
    return source.removeprefix("fips-node-").split("-")[0]


def evaluate_path_floor(
    cfg: PathFloorAssertion,
    path_lines: list[tuple[str, str]],
) -> AssertionOutcome:
    """The draft's floor on probes to a path that has stopped answering.

    For every stop at every node (paths.stops), each probe's gap from the
    one before, probe 0 being the stop, must be at least the floor's least
    gap less the log-stamp allowance (paths.STAMP_ALLOWANCE). A stop that
    began more than PATH_SILENCE_MAX after the path's first unanswered
    probe began, unlogged, before its Dead entry, so its gaps cannot be
    placed: it is refused rather than checked from the wrong origin. One
    probe per stop sent with an answer to the peer's probe is the early
    probe on the peer clearing ACTIVE, and a probe sent as the link's
    active path fails with nothing Live is the one Section 5.7 requires at
    once; the draft exempts both (paths.EXEMPT_WINDOW). Every other probe
    inside a stop is held to the floor, and a red prints each probe's
    time. A run with fewer than ``min_stops`` stops of two probes or more
    measured nothing and fails.

    A stop of a path that carried the link takes the node's re-check
    (paths.RECHECK_SPAN): its least gap stays 1 s while a probe goes before
    30 s after the path's silence clock started, then doubles as the floor
    does (paths.least_gaps). That holds only for a path that was the active
    path at its Dead entry, or when it last left Live since its previous
    stop (paths._carried), and the probes after the span are still held to
    the doubling, so a re-check that runs past 30 s fails.
    """
    breaks, refused, checked, margins, rechecked = [], [], 0, [], 0
    for source, peers in sorted(P.timelines(path_lines).items()):
        for peer, tl in sorted(peers.items()):
            for st in P.stops(tl):
                where = f"{_short(source)} path {st.path_id} to {st.addr}"
                if st.unanswered is not None and st.start - st.unanswered > P.SILENCE_MAX:
                    refused.append(
                        f"{where}: Dead at {_stamp(st.start)}, "
                        f"{st.start - st.unanswered:.0f} s after its first unanswered "
                        f"probe, so it stopped earlier, unlogged"
                    )
                    continue
                if len(st.probes) >= 2:
                    checked += 1
                    rechecked += st.until is not None
                m = P.margin(st)
                if m is not None:
                    margins.append(m)
                bad = P.floor_breaks(st)
                if bad:
                    probes = ", ".join(_stamp(t) for t in st.probes)
                    if st.exempt:
                        probes += f"; exempt: {', '.join(_stamp(t) for t in st.exempt)}"
                    gaps = "; ".join(
                        f"probe {n} {g:.3f} s after the last, least {least:g} s"
                        for n, g, least in bad
                    )
                    recheck = (
                        f", re-checked as the path that carried the link until "
                        f"{_stamp(st.until)}" if st.until is not None else ", not re-checked"
                    )
                    breaks.append(
                        f"{where}, stopped {_stamp(st.start)}{recheck}: {gaps} "
                        f"(probes: {probes})"
                    )
    tight = f"; smallest margin {min(margins) * 1000:.0f} ms" if margins else ""
    tight += (
        f"; {rechecked} of them re-checked at 1 s for {P.RECHECK_SPAN:g} s after the "
        f"path that carried the link went silent" if rechecked else ""
    )
    if breaks or refused:
        parts = []
        if breaks:
            parts.append(f"{len(breaks)} stop(s) probed under the floor: " + " | ".join(breaks))
        if refused:
            parts.append(f"{len(refused)} stop(s) refused: " + " | ".join(refused))
        return AssertionOutcome(
            name="path_floor",
            passed=False,
            detail=(
                f"FAIL path_floor: {'; '.join(parts)} "
                f"(allowance {P.STAMP_ALLOWANCE * 1000:.0f} ms{tight})"
            ),
        )
    if checked < cfg.min_stops:
        return AssertionOutcome(
            name="path_floor",
            passed=False,
            detail=(
                f"FAIL path_floor: {checked} stop(s) with two probes or more, need "
                f"{cfg.min_stops}: no path stopped long enough to test the floor"
            ),
        )
    return AssertionOutcome(
        name="path_floor",
        passed=True,
        detail=(
            f"PASS path_floor: {checked} stop(s) with two probes or more, every gap "
            f"within the floor (allowance {P.STAMP_ALLOWANCE * 1000:.0f} ms{tight})"
        ),
    )


def evaluate_discovery_limit(
    cfg: DiscoveryLimitAssertion,
    path_lines: list[tuple[str, str]],
) -> AssertionOutcome:
    """At most ``max_probes`` probes in any Probing episode (draft 5.6)."""
    over, count, most = [], 0, 0
    for source, peers in sorted(P.timelines(path_lines).items()):
        for peer, tl in sorted(peers.items()):
            for ep in P.episodes(tl):
                count += 1
                most = max(most, ep.probes)
                if ep.probes > cfg.max_probes:
                    over.append(
                        f"{_short(source)} path {ep.path_id}: {ep.probes} probes in the "
                        f"episode from {_stamp(ep.start)}"
                    )
    if over:
        return AssertionOutcome(
            name="discovery_limit",
            passed=False,
            detail=f"FAIL discovery_limit: over {cfg.max_probes}: " + "; ".join(over),
        )
    if not count:
        return AssertionOutcome(
            name="discovery_limit",
            passed=False,
            detail="FAIL discovery_limit: no Probing episode was logged, nothing measured",
        )
    return AssertionOutcome(
        name="discovery_limit",
        passed=True,
        detail=(
            f"PASS discovery_limit: {count} Probing episode(s), at most {most} probes "
            f"(limit {cfg.max_probes})"
        ),
    )


_BADNEIGH = ("FAILED", "INCOMPLETE")


def _neighstate(text: str, ip: str) -> str | None:
    """The state of ``ip``'s entry in ``ip -4 neigh show`` output, or None."""
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0] == ip:
            return parts[-1]
    return None


def evaluate_reverse_heard(
    cfg: ReverseHeardAssertion,
    records: list[dict],
    path_lines: list[tuple[str, str]],
    cname,
    veth_ip,
    port: int = 2122,
) -> AssertionOutcome:
    """The positive control of a one-direction step.

    ``records`` are the schedule's step records; ``cname`` names a node's
    log source and ``veth_ip(node, peer)`` gives a node's address on its
    veth to the peer. For each ``oneway`` step, with ``from`` the end whose
    frames are dropped and ``to`` the end dropping them: (i) ``to`` logged
    at least one path message to ``from``'s veth address during the step,
    and the capture at ``from``'s veth holds at least as many frames from
    ``to``'s address and port as ``to`` logged in the window counted, so
    the reverse direction delivered to the step's end. The window is the
    step's second half, widened by ``window_ms`` at each side for stamp
    error. When ``to`` logged nothing in that half, it starts instead at
    the last message ``to`` logged during the step: once the Dead
    interval exceeds the half, which an at-once probe can bring about by
    restarting the cadence at its doubled interval, the half may hold no
    probe at all. And (ii) at the
    step's end both ends' entries for each other are present and neither
    FAILED nor INCOMPLETE. A run with no oneway step measured nothing.
    """
    steps = [r for r in records if r.get("mode") == "oneway"]
    if not steps:
        return AssertionOutcome(
            name="reverse_heard", passed=False,
            detail="FAIL reverse_heard: no oneway step ran, nothing measured",
        )
    pad = cfg.window_ms / 1000.0
    failures, shown = [], []
    for r in steps:
        src, dst = r["src"], r["end"]
        down, up = r.get("down"), r.get("up")
        label = f"{src}->{dst} dropped at {_stamp(down) if down else '?'}"
        if down is None or up is None:
            failures.append(f"{label}: the step did not complete")
            continue
        src_ip, dst_ip = veth_ip(src, dst), veth_ip(dst, src)
        during = sorted(
            t for source, line in path_lines
            if source == cname(dst) and "Path message sent" in line
            and line_fields(line).get("remote_addr") == f"{src_ip}:{port}"
            and (t := line_epoch(line)) is not None and down <= t <= up
        )
        # The second half, reaching back to the last message before it when
        # none falls inside: a Dead path's cadence may leave a gap longer
        # than the half (an at-once probe restarts it at the doubled interval).
        start = (down + up) / 2
        if during:
            start = min(start, during[-1])
        sent = [t for t in during if start <= t]
        cap = (r.get("captures") or {}).get(src)
        if cap is None:
            failures.append(f"{label}: no capture at {src}")
            continue
        seen = sum(
            1 for f in cap["frames"]
            if f.get("ip_src") == f"{dst_ip}.{port}" and f.get("ip_dst") == f"{src_ip}.{port}"
            and start - pad <= f["t"] <= up + pad
        )
        neigh = r.get("neigh") or {}
        states = {
            src: _neighstate(neigh.get(src, ""), dst_ip),
            dst: _neighstate(neigh.get(dst, ""), src_ip),
        }
        shown.append(
            f"{label}: from {_stamp(start)} {len(sent)} sent by {dst}, {seen} captured at {src}; "
            f"neighbours {src}:{states[src]} {dst}:{states[dst]}"
        )
        if not sent:
            failures.append(f"{label}: {dst} logged no path message to {src} during the step")
        elif seen < len(sent):
            failures.append(
                f"{label}: {dst} logged {len(sent)} path message(s) to {src} from "
                f"{_stamp(start)}, the capture at {src} saw {seen}"
            )
        for node, st in states.items():
            if st is None or st in _BADNEIGH:
                failures.append(f"{label}: {node}'s neighbour entry for the other is {st}")
    if failures:
        return AssertionOutcome(
            name="reverse_heard", passed=False,
            detail=f"FAIL reverse_heard: {'; '.join(failures)}. Steps: {' | '.join(shown)}",
        )
    return AssertionOutcome(
        name="reverse_heard", passed=True,
        detail=f"PASS reverse_heard: {' | '.join(shown)}",
    )


def _latest(tl, t: float) -> dict[str, str]:
    """Each path's state as its last line before ``t`` left it."""
    out: dict[str, str] = {}
    for c in tl.changes:
        if c.t < t:
            out[c.path_id] = c.nxt
    return out


def evaluate_rescue(
    cfg: RescueAssertion,
    records: list[dict],
    path_lines: list[tuple[str, str]],
    cname,
    drops: list[tuple[str, str]],
    rejects: list[tuple[str, str]],
) -> AssertionOutcome:
    """The at-once probe of an acked Dead standby when the active path fails.

    For each admin down in ``records``, at each end: the control, that a
    path other than the one carrying the link was Dead when the down was
    stamped (otherwise the run did not exercise the at-once probe and fails
    as such);
    then a probe on that standby within ``window_ms`` after the first line
    at or after the down in which another path left Live or was released
    (the step the active path failed in); and the standby Live within
    2 x ``delay_ms`` + 1 s of the down. No peer may be removed after the
    down (``drops``). ``rejects``, the decryption failures logged, are
    reported as the mechanism that killed the standby.
    """
    downs = [r for r in records if r.get("mode") == "admin" and r.get("down") is not None]
    if not downs:
        return AssertionOutcome(
            name="rescue", passed=False,
            detail="FAIL rescue: no admin down ran, nothing measured",
        )
    tls = P.timelines(path_lines)
    window = cfg.window_ms / 1000.0
    within = 2 * cfg.delay_ms / 1000.0 + 1.0
    failures, shown = [], []
    for r in downs:
        t0 = r["down"]
        for node in r["edge"]:
            src = cname(node)
            peers = tls.get(src, {})
            tl = next(iter(peers.values()), None) if len(peers) == 1 else None
            where = f"{node} ({'downed' if node == r['end'] else 'far'} end)"
            if tl is None:
                failures.append(f"{where}: {len(peers)} peer timelines, expected one")
                continue
            dead = [pid for pid, st in _latest(tl, t0).items() if st == "Some(Dead)"]
            if not dead:
                states = ", ".join(f"{p}={v}" for p, v in sorted(_latest(tl, t0).items()))
                failures.append(
                    f"{where}: no path was Dead at the down ({states or 'no lines'}), so "
                    f"the run did not exercise the at-once probe of a Dead standby"
                )
                continue
            fail = next(
                (c for c in tl.changes
                 if c.t >= t0 and c.frm == "Some(Live)" and c.path_id not in dead),
                None,
            )
            if fail is None:
                failures.append(f"{where}: the active path never left Live after the down")
                continue
            probes = [
                m.t for m in tl.messages
                if m.path_id in dead and m.msg_type == P.PROBE
                and -0.005 <= m.t - fail.t <= window
            ]
            live = [
                c.t for c in tl.changes
                if c.path_id in dead and c.nxt == "Some(Live)" and t0 <= c.t <= t0 + within
            ]
            shown.append(
                f"{where}: standby {','.join(dead)} Dead; active left Live "
                f"{(fail.t - t0) * 1000:.0f} ms after the down ({fail.why}); probe "
                + (f"{(probes[0] - fail.t) * 1000:.1f} ms after that" if probes else "none")
                + "; standby Live "
                + (f"{(live[0] - t0):.2f} s after the down" if live else "not in time")
            )
            if not probes:
                failures.append(
                    f"{where}: no probe on the Dead standby within {cfg.window_ms} ms of "
                    f"the active path leaving Live at {_stamp(fail.t)}"
                )
            if not live:
                failures.append(f"{where}: the standby was not Live within {within:.1f} s")
    late = [(s, l) for s, l in drops if (t := line_epoch(l)) is not None
            and any(t >= r["down"] for r in downs)]
    if late:
        failures.append(f"{len(late)} peer removal(s) after the down: {late[0][1].strip()[:160]}")
    counts: dict[str, int] = {}
    for source, _ in rejects:
        counts[_short(source)] = counts.get(_short(source), 0) + 1
    tail = f"; decryption failures logged (first three per peer): {counts or 'none'}"
    if failures:
        return AssertionOutcome(
            name="rescue", passed=False,
            detail=f"FAIL rescue: {'; '.join(failures)}. Seen: {' | '.join(shown)}{tail}",
        )
    return AssertionOutcome(
        name="rescue", passed=True, detail=f"PASS rescue: {' | '.join(shown)}{tail}",
    )


def evaluate_lanes(
    cfg: LanesAssertion,
    path_lines: list[tuple[str, str]],
    lanes: dict[str, dict],
    frames: dict[str, dict[str, list[dict]]],
) -> AssertionOutcome:
    """A laned edge's control and verdicts (scenario.LanesAssertion).

    ``lanes`` is per node (log source): its ``lanes`` as ``(iface, ip)``,
    whether it is the ``dialler``, its ``configured`` pairs and the edge's
    ``sentinel``. ``frames`` are the run-long captures, per node and lane,
    of frames addressed to that node's other lanes.
    """
    failures, shown = [], []
    for node, info in sorted(lanes.items()):
        ips = {ip for _, ip in info["lanes"]}
        crossed = 0
        for iface, ip in info["lanes"]:
            others = ips - {ip}
            crossed += sum(
                1 for f in frames.get(node, {}).get(iface, [])
                if f.get("ip_dst", "").rsplit(".", 1)[0] in others
            )
        role = "dialler" if info["dialler"] else "far end"
        shown.append(f"{_short(node)} ({role}): {crossed} frame(s) crossed lanes")
        if cfg.cross_arrival and info["dialler"] and not crossed:
            failures.append(
                f"{_short(node)}: no frame arrived on a lane addressed to another lane's "
                f"address, so no answer could reach another instance: the run did not "
                f"exercise the rule"
            )
    if cfg.stable:
        for node, info in sorted(lanes.items()):
            if not info["dialler"]:
                continue
            held = set(configured_live(path_lines, node, info["configured"], None).values())
            went: set[str] = set()
            for src, line in path_lines:
                if src != node or "Path state changed" not in line:
                    continue
                f = line_fields(line)
                pid = f.get("path_id")
                if pid in held and f.get("next") == "Some(Live)":
                    went.add(pid)
                if pid in went and f.get("from") == "Some(Live)" and f.get("next") == "Some(Suspect)":
                    failures.append(
                        f"{_short(node)}: path {pid} at {f.get('transport_id')} "
                        f"{f.get('remote_addr')} went Live, then Suspect at "
                        f"{_stamp(line_epoch(line) or 0)}"
                    )
        sentinels = {info["sentinel"] for info in lanes.values()}
        for src, line in path_lines:
            if "Path state changed" not in line:
                continue
            f = line_fields(line)
            if f.get("remote_addr") in sentinels and f.get("next") == "Some(Live)":
                failures.append(
                    f"{_short(src)}: the sentinel {f.get('remote_addr')}, which no host "
                    f"answers, went Live"
                )
    if failures:
        return AssertionOutcome(
            name="lanes", passed=False,
            detail=f"FAIL lanes: {'; '.join(failures)}. {'; '.join(shown)}",
        )
    return AssertionOutcome(
        name="lanes", passed=True,
        detail=f"PASS lanes: {'; '.join(shown)}; no configured lane path went Suspect, "
               f"the sentinel never Live",
    )


def evaluate_max_replay_refusals(
    cfg: MaxReplayRefusalsAssertion,
    snapshot: dict | None,
) -> AssertionOutcome:
    """Ceiling on the replays refused, over every peer of every node.

    ``snapshot`` is the final congestion snapshot keyed by node id, whose
    ``replay_refusals`` holds each peer's total. A missing snapshot, a peer
    with no total, or fewer than ``min_nodes`` nodes with a count fails:
    each of those observed nothing, and reading it as zero refusals is how
    this assertion would come to pass on a build that never counted. It
    cannot tell a counter that was never incremented from a clean run; the
    unit test of the worker's refusal is its partner there.
    """
    name = "max_replay_refusals"
    if not snapshot:
        return AssertionOutcome(
            name=name,
            passed=False,
            detail=(
                "FAIL max_replay_refusals: no final congestion snapshot was "
                "taken, so no count was observed."
            ),
        )

    parts, failures, counted, total = [], [], set(), 0
    for nid in sorted(snapshot):
        for entry in snapshot[nid].get("replay_refusals") or []:
            refused = entry.get("total")
            label = f"{nid}/{entry.get('peer')}"
            if refused is None:
                failures.append(f"{label} reported no count")
                continue
            counted.add(nid)
            total += refused
            parts.append(f"{label} {refused}")
    if len(counted) < cfg.min_nodes:
        failures.append(
            f"{len(counted)} node(s) reported a refusal count, "
            f"need {cfg.min_nodes}"
        )
    if total > cfg.max_total:
        failures.append(f"{total} replays refused")

    summary = "; ".join(parts) or "none"
    if failures:
        return AssertionOutcome(
            name=name,
            passed=False,
            detail=(
                f"FAIL max_replay_refusals: {'; '.join(failures)} (ceiling "
                f"{cfg.max_total}). All: {summary}"
            ),
        )
    return AssertionOutcome(
        name=name,
        passed=True,
        detail=f"PASS max_replay_refusals: ceiling {cfg.max_total}; {summary}",
    )


def evaluate_max_kernel_drops(
    cfg: MaxKernelDropsAssertion,
    snapshot: dict | None,
) -> AssertionOutcome:
    """Ceiling on each Ethernet socket's kernel drops, as a share of frames.

    ``snapshot`` is the final congestion snapshot keyed by node id. Each
    Ethernet transport's share is ``kernel_drops / (frames_recv +
    kernel_drops)``. A missing snapshot, an Ethernet entry with either count
    absent, or fewer than ``min_nodes`` nodes with an Ethernet counter
    fails: each of those observed nothing, and reading it as zero drops is
    how this assertion would come to pass on a build that never counted.
    """
    name = "max_kernel_drops"
    if not snapshot:
        return AssertionOutcome(
            name=name,
            passed=False,
            detail=(
                "FAIL max_kernel_drops: no final congestion snapshot was "
                "taken, so no socket was observed."
            ),
        )

    parts, failures, counted, over = [], [], set(), False
    for nid in sorted(snapshot):
        for t in snapshot[nid].get("kernel_drops") or []:
            if t.get("type") != "ethernet":
                continue
            label = f"{nid}/transport:{t.get('transport_id')}"
            drops, recv = t.get("kernel_drops"), t.get("frames_recv")
            if drops is None or recv is None:
                failures.append(
                    f"{label} reported no count (kernel_drops={drops}, "
                    f"frames_recv={recv})"
                )
                continue
            counted.add(nid)
            total = recv + drops
            pct = 100.0 * drops / total if total else 0.0
            parts.append(f"{label} {drops}/{total} ({pct:.3f}%)")
            if pct > cfg.max_pct:
                over = True
                failures.append(
                    f"{label} dropped {drops} of {total} frames ({pct:.3f}%)"
                )
    if len(counted) < cfg.min_nodes:
        failures.append(
            f"{len(counted)} node(s) reported an Ethernet drop count, "
            f"need {cfg.min_nodes}"
        )

    summary = "; ".join(parts) or "none"
    if failures:
        why = (
            " A socket's receive buffer overflowed, so its node lost frames "
            "before reading them." if over else ""
        )
        return AssertionOutcome(
            name=name,
            passed=False,
            detail=(
                f"FAIL max_kernel_drops: {'; '.join(failures)} (ceiling "
                f"{cfg.max_pct}%).{why} All: {summary}"
            ),
        )
    return AssertionOutcome(
        name=name,
        passed=True,
        detail=f"PASS max_kernel_drops: ceiling {cfg.max_pct}%; {summary}",
    )
