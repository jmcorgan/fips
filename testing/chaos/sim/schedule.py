"""Timed steps a scenario scripts beside its random managers.

A scenario's ``schedule:`` lists steps at fixed offsets from the end of
warmup. A step draws nothing from any seeded stream, so a schedule needs no
case in testing/check-chaos-schedule.py.

- ``down``: take an edge down for ``secs``, by ``mode``:
  ``netem`` (100% loss both ways, as a random flap does), ``admin``
  (``ip link set dev <veth> down`` at the edge's ``end``, then ``up``) or
  ``oneway`` (the IPv4 frames ``from`` one end dropped at the ingress of
  the veth ``to`` the other; the neighbour entries at both ends are read
  at the step's end, before the drop is lifted).
- ``load``: run ``iperf3`` from the pair's first node to its second for
  ``secs``, with ``streams`` parallel streams, both ways with ``bidir``.

A down may name nodes to ``capture`` on: each runs ``tcpdump`` on its own
veth of the edge from just before the down to just after the restore. It
may also name nodes whose veth ``counters`` (``tx_packets``,
``tx_dropped``) are read just before the down and just after the restore,
a second count of what that end sent. Each down's stamps, captures and
counters are kept in ``records`` for the figures.

A step whose command fails raises ``StepError``, and the runner scores
the run NOT SCORED: a down that did not happen would otherwise be scored as
though it had.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .docker_exec import DockerExecError, docker_exec

if TYPE_CHECKING:  # topology imports scenario, which imports this module
    from .topology import SimTopology

log = logging.getLogger(__name__)

# The modes a scripted down may take.
MODES = ("netem", "admin", "oneway")


class StepError(RuntimeError):
    """A scheduled step's command failed, so the run cannot be scored."""


@dataclass
class Step:
    """One timed step. ``at`` is seconds after warmup; ``secs`` its length.

    A down names its ``edge`` (sorted), ``mode`` and, for ``admin``, the
    ``end`` whose veth goes down. A load names its ``pair`` (client,
    server), ``streams`` and ``bidir``.
    """

    at: float
    kind: str
    secs: float
    edge: tuple[str, str] | None = None
    mode: str = "netem"
    end: str | None = None
    pair: tuple[str, str] | None = None
    streams: int = 1
    bidir: bool = False
    capture: tuple[str, ...] = ()
    counters: tuple[str, ...] = ()
    src: str | None = None

    @property
    def until(self) -> float:
        """The offset at which the step ends."""
        return self.at + self.secs

    def label(self) -> str:
        """A short description for the run log."""
        if self.kind == "down":
            where = f" at {self.end}" if self.end else ""
            if self.src:
                where = f", {self.src} to {self.end} dropped"
            return f"down {self.edge[0]}--{self.edge[1]} ({self.mode}{where}, {self.secs:g} s)"
        flow = "<->" if self.bidir else "->"
        return f"load {self.pair[0]}{flow}{self.pair[1]} ({self.streams} streams, {self.secs:g} s)"


def run_stamped(container: str, cmd: str) -> float:
    """Run ``cmd`` in ``container`` after stamping the time there.

    Returns the epoch ``date +%s.%N`` printed in the same shell,
    immediately before the command. Raises ``StepError`` when the command
    fails or its stamp cannot be read.
    """
    try:
        out = docker_exec(container, f"date +%s.%N; {cmd}")
    except (DockerExecError, OSError) as e:
        raise StepError(f"{container}: {cmd!r} failed: {e}") from e
    except Exception as e:  # subprocess.TimeoutExpired and kin
        raise StepError(f"{container}: {cmd!r} did not finish: {e}") from e
    try:
        return float(out.splitlines()[0].strip())
    except (ValueError, IndexError) as e:
        raise StepError(f"{container}: no stamp before {cmd!r}: {out!r:.80}") from e


class Schedule:
    """Fires a scenario's steps at their offsets and ends them after.

    ``links`` is the LinkManager the downs go through (one of its own, so
    its random flaps never run); ``npub`` gives a node's current npub for a
    load's server. Load results are collected with ``collect``.
    """

    def __init__(self, steps: list[Step], topology: SimTopology, links, npub):
        """Hold ``steps`` pending in order of their offsets; none fires
        until ``tick``."""
        self.pending = sorted(steps, key=lambda s: s.at)
        self.active: list[Step] = []
        self.topology = topology
        self.links = links
        self.npub = npub
        self.loads: list[tuple[Step, str, str]] = []
        self.results: list[dict] = []
        self.records: list[dict] = []
        self._open: dict[int, tuple[dict, list]] = {}

    def tick(self, elapsed: float) -> None:
        """End the steps due to end, then fire the steps due at ``elapsed``."""
        for step in [s for s in self.active if s.until <= elapsed]:
            self._end(step)
            self.active.remove(step)
        while self.pending and self.pending[0].at <= elapsed:
            step = self.pending.pop(0)
            self._start(step)
            self.active.append(step)

    def finish(self) -> None:
        """End every step still active, as teardown does with flaps."""
        for step in list(self.active):
            self._end(step)
        self.active.clear()

    def _start(self, step: Step) -> None:
        """Begin one step: its captures first, then its command."""
        log.info("Schedule: %s", step.label())
        if step.kind != "down":
            self._load(step)
            return
        from .capture import Capture
        from .topology import veth_interface_name

        record = {
            "step": step.label(), "mode": step.mode, "edge": list(step.edge),
            "end": step.end, "at": step.at, "secs": step.secs, "captures": {},
            "counters": {n: {"before": self._counters(step, n)} for n in step.counters},
        }
        caps = []
        for node in step.capture:
            other = step.edge[1] if node == step.edge[0] else step.edge[0]
            iface = veth_interface_name(node, other)
            cap = Capture(self.topology.container_name(node), iface,
                          f"{len(self.records)}-{node}")
            cap.start()
            caps.append((node, iface, cap))
        record["src"] = step.src
        record["down"] = self.links.scripted_down(
            step.edge, step.mode, step.end, step.secs, step.src
        )
        self.records.append(record)
        self._open[id(step)] = (record, caps)

    def _end(self, step: Step) -> None:
        """End one step, then stop its captures; a load ends by itself."""
        if step.kind != "down":
            return
        record, caps = self._open.pop(id(step))
        if step.mode == "oneway":
            record["neigh"] = {n: self._neigh(step, n) for n in step.edge}
        record["up"] = self.links.scripted_up(step.edge, step.mode, step.end)
        for node in step.counters:
            record["counters"][node]["after"] = self._counters(step, node)
        for node, iface, cap in caps:
            record["captures"][node] = {"iface": iface, "frames": cap.stop()}

    def _neigh(self, step: Step, node: str) -> str:
        """``node``'s IPv4 neighbour entries on its veth of the step's edge."""
        from .topology import veth_interface_name

        other = step.edge[1] if node == step.edge[0] else step.edge[0]
        iface = veth_interface_name(node, other)
        try:
            return docker_exec(self.topology.container_name(node), f"ip -4 neigh show dev {iface}")
        except Exception as e:
            raise StepError(f"reading {node}'s neighbours on {iface} failed: {e}") from e

    def _counters(self, step: Step, node: str) -> dict:
        """``node``'s veth of the step's edge: its tx counters, and when
        they were read."""
        from .topology import veth_interface_name

        other = step.edge[1] if node == step.edge[0] else step.edge[0]
        stats = f"/sys/class/net/{veth_interface_name(node, other)}/statistics"
        container = self.topology.container_name(node)
        cmd = f"date +%s.%N; cat {stats}/tx_packets {stats}/tx_dropped"
        try:
            t, packets, dropped = docker_exec(container, cmd).split()
            return {"t": float(t), "tx_packets": int(packets), "tx_dropped": int(dropped)}
        except Exception as e:
            raise StepError(f"{container}: reading {stats} failed: {e}") from e

    def _load(self, step: Step) -> None:
        """Start an iperf3 client for the step's length, writing JSON."""
        client, server = step.pair
        container = self.topology.container_name(client)
        result = f"/tmp/iperf3-step-{client}-{server}-{int(time.time())}.json"
        bidir = " --bidir" if step.bidir else ""
        cmd = (
            f"nohup iperf3 -c {self.npub(server)}.fips -t {step.secs:g} "
            f"-P {step.streams}{bidir} --json > {result} 2>&1 &"
        )
        run_stamped(container, cmd)
        self.loads.append((step, container, result))

    def collect(self) -> list[dict]:
        """Read every load's iperf3 result; an unreadable one is kept as an
        error, so the stall assertion fails on it rather than missing it."""
        for step, container, path in self.loads:
            try:
                out = docker_exec(container, f"cat {path} 2>/dev/null; rm -f {path}")
                data = json.loads(out.strip())
            except Exception as e:
                data = {"error": f"scheduled load result unreadable: {e}"}
            data["_meta"] = {
                "client": step.pair[0],
                "server": step.pair[1],
                "duration_secs": step.secs,
                "scheduled": True,
            }
            self.results.append(data)
        self.loads.clear()
        return self.results
