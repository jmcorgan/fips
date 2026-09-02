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
    MinParentSwitchesAssertion,
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
