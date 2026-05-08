"""Deterministic asymmetric link-cost flapping.

Periodically rotates a fixed assignment of netem policies across a
fixed set of edges. Unlike ``LinkManager`` (random link-down events)
or the ``netem.mutation`` block (random per-edge policy mutation),
this is a deterministic, periodic flip between named policies on
named edges — useful for forcing a downstream node to switch parents
on a fixed cadence.

Rotation is a simple one-position cyclic shift: the policy assigned
to edges[0] moves to edges[1], edges[1] -> edges[2], ..., edges[N-1]
-> edges[0]. With two edges this degenerates to a swap, which is the
intended use for the bloom-storm scenario.
"""

from __future__ import annotations

import logging
import random
import time

from .netem import NetemManager, NetemParams
from .scenario import LinkSwapConfig, NetemPolicy
from .topology import SimTopology

log = logging.getLogger(__name__)


def _canonical_edge(edge_str: str) -> tuple[str, str]:
    """Parse "nXX-nYY" into a canonical (a, b) tuple sorted alphabetically."""
    parts = edge_str.split("-")
    if len(parts) != 2:
        raise ValueError(f"link_swap edge '{edge_str}' is not 'nXX-nYY' form")
    a, b = sorted(parts)
    return a, b


class LinkSwapManager:
    """Manages deterministic netem-policy rotation across a fixed edge set."""

    def __init__(
        self,
        topology: SimTopology,
        config: LinkSwapConfig,
        netem_mgr: NetemManager,
        rng: random.Random,
    ):
        self.topology = topology
        self.config = config
        self.netem_mgr = netem_mgr
        self.rng = rng

        # Resolve edges and validate they exist in the topology
        topo_edges = {tuple(sorted([a, b])) for a, b in topology.edges}
        self._edges: list[tuple[str, str]] = []
        for entry in config.edges:
            edge = _canonical_edge(entry.edge)
            if edge not in topo_edges:
                raise ValueError(
                    f"link_swap edge {entry.edge} not present in topology"
                )
            self._edges.append(edge)

        # Current per-position policy name. Index i in this list is
        # the policy currently applied to self._edges[i]. Each rotate()
        # cyclically shifts these by one position.
        self._current_policies: list[str] = [e.policy for e in config.edges]

        self.swap_count = 0
        # Last apply timestamp; the runner uses this together with
        # config.interval_secs to schedule rotations.
        self.last_swap_at: float | None = None

    def policies(self) -> dict[str, NetemPolicy]:
        return self.config.policies

    def setup_initial(self) -> None:
        """Apply the initial policy assignment to each edge.

        Called once after NetemManager.setup_initial() so the link's
        per-direction tc class state already exists. The initial
        assignment is taken straight from the config (no rotation).
        """
        for edge, policy_name in zip(self._edges, self._current_policies):
            policy = self.config.policies[policy_name]
            self._apply(edge, policy)
        self.last_swap_at = time.time()
        log.info(
            "Link swap initialized: %d edges, interval %.1fs, policies=%s",
            len(self._edges),
            self.config.interval_secs,
            list(self.config.policies.keys()),
        )

    def maybe_swap(self, now: float) -> bool:
        """If the swap interval has elapsed, rotate policies. Return whether
        a swap occurred so the runner can reschedule.
        """
        if self.last_swap_at is None:
            self.last_swap_at = now
            return False
        if (now - self.last_swap_at) < self.config.interval_secs:
            return False

        # Cyclic shift by one position
        self._current_policies = (
            [self._current_policies[-1]] + self._current_policies[:-1]
        )
        for edge, policy_name in zip(self._edges, self._current_policies):
            policy = self.config.policies[policy_name]
            self._apply(edge, policy)
        self.swap_count += 1
        self.last_swap_at = now
        log.debug(
            "Link swap #%d: %s",
            self.swap_count,
            ", ".join(
                f"{a}-{b}={p}"
                for (a, b), p in zip(self._edges, self._current_policies)
            ),
        )
        return True

    def _apply(self, edge: tuple[str, str], policy: NetemPolicy) -> None:
        """Apply a policy to both directions of an edge using NetemManager."""
        params = self._sample_policy(policy)
        # Drive both directions through NetemManager's per-link state so
        # the rotation persists across mutate() runs and survives node
        # restarts via setup_node().
        self.netem_mgr._update_link(edge[0], edge[1], params)

    def _sample_policy(self, policy: NetemPolicy) -> NetemParams:
        """Sample concrete params from a policy's ranges (deterministic
        when min == max, which is the bloom-storm scenario's contract).
        """
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
