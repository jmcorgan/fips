"""Post-run scenario assertions evaluated via control-socket data.

Assertions are declared in the scenario YAML under ``assertions:`` and
are evaluated near the end of the simulation, before teardown begins.
Each failing assertion is recorded with a clear pass/fail message; the
runner exits non-zero when any assertion fails.

Currently supported assertions:

- ``bloom_send_rate``: per-node trailing-window ceiling on
  ``stats.bloom.sent`` delta. Calibrated for the bloom-storm
  regression scenario but generally usable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .control import snapshot_all_bloom
from .scenario import (
    MinTrafficAssertion,
    BaselineAssertion,
    BloomSendRateAssertion,
    CongestionSignalsAssertion,
    MaxErrorsAssertion,
    MaxParentSwitchesAssertion,
    MaxPromotionsAssertion,
    MaxStallAssertion,
    MinParentSwitchesAssertion,
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


def evaluate_path_switches(cfg, count: int) -> AssertionOutcome:
    """Band on path switches (traffic moving between transports under one
    session) over the run.

    ``min_total`` catches a harness that flapped a link nothing was
    switching over: a dual-path scenario in which no switch happened
    tested nothing. ``max_total`` is the stability ceiling: a healthy
    dual-path pair should switch only when a link goes and comes back,
    never on its own.
    """
    if cfg.min_total is not None and count < cfg.min_total:
        return AssertionOutcome(
            name="path_switches",
            passed=False,
            detail=(
                f"FAIL path_switches: {count} switches < floor {cfg.min_total} "
                f"— the flaps did not move traffic between paths. Check that "
                f"both paths came up (fipsctl path show) before the first flap."
            ),
        )
    if cfg.max_total is not None and count > cfg.max_total:
        return AssertionOutcome(
            name="path_switches",
            passed=False,
            detail=(
                f"FAIL path_switches: {count} switches > ceiling {cfg.max_total} "
                f"— traffic is moving between paths more than the flaps "
                f"account for. Look for discretionary switches on a healthy "
                f"pair: the margin or the dwell is too small."
            ),
        )
    return AssertionOutcome(
        name="path_switches",
        passed=True,
        detail=(
            f"PASS path_switches: {count} switches within "
            f"[{cfg.min_total if cfg.min_total is not None else 0}, "
            f"{cfg.max_total if cfg.max_total is not None else 'inf'}]"
        ),
    )


def evaluate_max_promotions(
    cfg: MaxPromotionsAssertion,
    promotions: list[tuple[str, str]],
) -> AssertionOutcome:
    """Per-node ceiling on "Peer promoted to active" lines.

    ``promotions`` is ``AnalysisResult.peers_promoted``: ``(source, line)``
    pairs, one per handshake that completed on that node. The first per
    peer is the pair meeting; any beyond the ceiling is a re-peering — the
    session was torn down and rebuilt — which a switchover scenario exists
    to prove does not happen. Liveness is no backstop here: standby probes
    keep a peer alive while its data path is blackholed, so this counts
    the one event a blackhole that lasts to the reaper cannot avoid.
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
        f"    [{src}] {line.strip()}"
        for src, line in promotions
        if src in over
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


def _line_epoch(line: str) -> float | None:
    """Epoch seconds of a node log line's leading RFC 3339 timestamp, if any.

    ``tracing`` writes ``2026-09-13T13:39:01.123456Z`` first on every line.
    Anything else (a bare stderr line, a runner line) is not timed.
    """
    from datetime import datetime, timezone

    head = line.strip().split(" ", 1)[0]
    if not head.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(head.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def evaluate_switch_latency(
    cfg: SwitchLatencyAssertion,
    flap_events: list[tuple[float, str, str, str]],
    switches: list[tuple[str, str]],
) -> AssertionOutcome:
    """Ceiling on the time from each link-down to the first switch on
    either endpoint.

    ``flap_events`` is the link manager's record: ``(epoch, "down" | "up",
    a, b)``. ``switches`` is ``AnalysisResult.path_switches``: ``(source,
    line)``, where ``source`` is the node id and the line carries its own
    timestamp. For each down edge, the latency is the earliest switch line
    on ``a`` or ``b`` stamped at or after the down; a down with no switch
    inside ``max_ms`` fails. The worst flap is what is reported.
    """
    downs = [(t, a, b) for t, kind, a, b in flap_events if kind == "down"]
    if not downs:
        return AssertionOutcome(
            name="switch_latency",
            passed=False,
            detail="FAIL switch_latency: no link was taken down, nothing measured",
        )
    timed: list[tuple[str, float]] = []
    for source, line in switches:
        t = _line_epoch(line)
        if t is not None:
            timed.append((source, t))
    limit = cfg.max_ms / 1000.0
    worst: tuple[float, str, str] | None = None
    missing: list[str] = []
    for down_at, a, b in downs:
        after = [
            t - down_at
            for src, t in timed
            if src in (a, b) and t >= down_at and t - down_at <= limit
        ]
        if not after:
            from datetime import datetime, timezone

            when = datetime.fromtimestamp(down_at, timezone.utc).strftime("%H:%M:%S")
            missing.append(f"{a}--{b} down at {when}Z")
            continue
        latency = min(after)
        if worst is None or latency > worst[0]:
            worst = (latency, a, b)
    if missing:
        return AssertionOutcome(
            name="switch_latency",
            passed=False,
            detail=(
                f"FAIL switch_latency: {len(missing)} of {len(downs)} link-down(s) "
                f"had no path switch on either endpoint within {cfg.max_ms} ms: "
                + "; ".join(missing)
            ),
        )
    assert worst is not None
    return AssertionOutcome(
        name="switch_latency",
        passed=True,
        detail=(
            f"PASS switch_latency: worst {worst[0] * 1000:.0f} ms "
            f"({worst[1]}--{worst[2]}) over {len(downs)} link-down(s), "
            f"ceiling {cfg.max_ms} ms"
        ),
    )


def _longest_stall_secs(result: dict) -> float:
    """Longest run of consecutive zero-byte intervals in one iperf3 result,
    in seconds. 0 for a result with no intervals."""
    intervals = result.get("intervals") if isinstance(result, dict) else None
    if not isinstance(intervals, list):
        return 0.0
    longest = 0.0
    run = 0.0
    for iv in intervals:
        summary = iv.get("sum") if isinstance(iv, dict) else None
        if not isinstance(summary, dict):
            continue
        seconds = summary.get("seconds", 1.0)
        if not isinstance(seconds, (int, float)) or seconds <= 0:
            seconds = 1.0
        if summary.get("bytes", 0) == 0:
            run += seconds
            longest = max(longest, run)
        else:
            run = 0.0
    return longest


def evaluate_max_stall(
    cfg: MaxStallAssertion,
    results: list[dict],
) -> AssertionOutcome:
    """Ceiling on the longest zero-byte run inside any iperf3 session.

    ``min_traffic`` cannot see a hole: a session that stalls for ten
    seconds mid-run still moves bytes before and after. This reads the
    per-interval totals iperf3 records and fails on the longest run of
    zeros across every session, which is the stall a switchover leaves
    when it does not carry.
    """
    if not results:
        return AssertionOutcome(
            name="max_stall",
            passed=False,
            detail="FAIL max_stall: no iperf3 session ran, nothing measured",
        )
    stalls = [(_longest_stall_secs(r), r) for r in results]
    worst_secs, worst = max(stalls, key=lambda pair: pair[0])
    if worst_secs <= cfg.max_secs:
        return AssertionOutcome(
            name="max_stall",
            passed=True,
            detail=(
                f"PASS max_stall: longest zero-byte run {worst_secs:.0f} s "
                f"across {len(results)} session(s), ceiling {cfg.max_secs:g} s"
            ),
        )
    start = worst.get("start", {}) if isinstance(worst, dict) else {}
    when = start.get("timestamp", {}).get("time", "?") if isinstance(start, dict) else "?"
    return AssertionOutcome(
        name="max_stall",
        passed=False,
        detail=(
            f"FAIL max_stall: a session starting {when} moved nothing for "
            f"{worst_secs:.0f} s, over the ceiling of {cfg.max_secs:g} s. Bytes "
            f"either side of the hole satisfied min_traffic; the hole is a "
            f"switchover that did not carry."
        ),
    )
