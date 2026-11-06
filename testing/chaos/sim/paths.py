"""Per-path timelines from the node's path lines, and the draft's bounds on them.

The path machine logs every change of a path's state ("Path state changed":
``path_id``, ``from``, ``next``, ``why``, the pair it is at) and every path
message it sends ("Path message sent": the pair, ``msg_type``, ``len``), a
path that moves to a new address logs "Path moved to a new address", and
each change of the link's active path logs "Path switched" (``to``, the
pair it now sends on). Every path message taken in logs "Path message
received", with the same fields, and "Task wait" (``worst_ms``) gives how long
a spawned task waited for the runtime thread, at most once a second. Those two
are there to be read from a run's logs and beside a timeout (``active_timeouts``
in ``assertions.py``); the timelines do not use them. From the rest, per node
and peer, this module rebuilds:

- each path's **stops** (draft Section 5.6): from its entry to Dead until a
  ``next=Some(Live)`` with ``why=Answered``, a ``from=Some(Dead)
  next=Some(Probing)`` with ``why=Probed`` (the peer's probe revived it), or
  its release (``next=None``). ``Returned`` and ``Found`` do not end one.
- each **Probing episode**: from entering Probing to leaving it.
- the probes (``msg_type=82``) sent on each path, attributed to the path
  that held their pair when they were sent.

The link's original path is Live from link-up and logs nothing until it
changes state, so a message sent on it before then is not attributed, and
until then it is read as Live. It is the first path whose first line is not
from ``None``; it is active until the first switch. A renewal starts the
link again: it ends every path of the old link (``next=None``) and begins
the new link's original path (``from=None``), each for ``why=Renewed``,
and that path is the original from then on, active until the next switch.
Neither the ending nor the beginning is a failure of the active path. The
lines carry no other link-up, so a second link to the same peer in one log
that no renewal began is read as going on from the first.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime


def line_epoch(line: str) -> float | None:
    """Epoch seconds of a node log line's leading RFC 3339 timestamp, if any.

    ``tracing`` writes ``2026-09-13T13:39:01.123456Z`` first on every line.
    Anything else (a bare stderr line, a runner line) is not timed.
    """
    head = line.strip().split(" ", 1)[0]
    if not head.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(head.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


_FIELD = re.compile(r"(\w+)=(\S+)")


def line_fields(line: str) -> dict[str, str]:
    """The ``key=value`` fields of a tracing line, values as written.

    Values are taken up to the next space, which holds for every field the
    path lines carry (``from=Some(Live)``, ``remote_addr=10.222.0.2:2122``,
    ``peer=npub1abc...wxyz``).
    """
    return dict(_FIELD.findall(line))


# The path message types, from their type byte (core/src/proto/path/mod.rs).
PROBE = 82
ACK = 83
CLOSE = 84

# PATH_SILENCE_MAX (draft Appendix A): a path that goes this long without an
# answer has stopped answering even if it is not Dead. That stop is not
# logged, so a stop is placed only where it began at a Dead entry.
SILENCE_MAX = 60.0

# The draft's floor on a stopped path's probes (Section 5.6; Appendix A
# PATH_DEAD_PROBE_INTERVAL_MIN and _MAX): the first two at least 1 s apart,
# each later one at least twice the least gap before it, up to 30 s.
FLOOR_MIN = 1.0
FLOOR_MAX = 30.0

# MAX_DISCOVERY_PROBES (draft Appendix A): probes per Probing episode.
DISCOVERY_MAX = 8

# The draft exempts two probes from the floor (Section 5.6), and the node
# sends each in the step that prompts it, so its line follows the prompt's
# within microseconds; a probe within this of its prompt is that probe.
#
# - The early probe on the peer clearing the ACTIVE flag it sends on the
#   path, sent with the answer (msg_type 83) to the peer's probe on the
#   same pair. At most one per stop, since the flag clears once per
#   setting. It happens where the peer drops a path without a probe from
#   it (an interface going away releases the path at once) while this end
#   still holds the flag set, then probes from its returning interface
#   with the flag clear.
# - The probe Section 5.7 requires at once of an acked Dead path when the
#   active path fails with nothing Live: sent in the step in which the
#   link's active path left Live or Suspect for a worse state (which may be
#   the stopped path itself going Dead), when by the lines no path of the
#   peer is Live after it, the original counted Live until its first line.
#   The machine logs a step's state changes before its switch, so the
#   active path is the one the switch lines named before the change.
EXEMPT_WINDOW = 0.005

# The allowance for comparing log stamps against the floor. A healthy node
# probes a stopped path exactly at the floor in its own clock: the machine
# reads its monotonic clock once per step, on the 50 ms path tick, and a
# probe due one interval after the last goes on the tick at that instant.
# Each line's wall-clock stamp is taken later than that read, by the step's
# own handling and, for a message, the send before the line; a stop's first
# reference is a state line and its probes are message lines, so a gap
# between two stamps can read short of the machine's by up to the earlier
# line's delay. That delay stays inside the tick that took the clock read
# while the node's loop keeps up with its ticks, so one tick (50 ms) bounds
# it. A defective cadence is off by a whole interval (1 s or more), twenty
# times this. Every stop's smallest margin is reported, so a run shows how
# much of the allowance it used.
STAMP_ALLOWANCE = 0.050


def floor_gap(n: int) -> float:
    """The least gap before probe ``n`` of a stop (probe 0 is the stop)."""
    gap = FLOOR_MIN
    for _ in range(3, n + 1):
        gap = min(2 * gap, FLOOR_MAX)
    return gap


@dataclass
class Change:
    """One "Path state changed" line; ``active`` when the path held the
    link's active pair as the line was logged."""

    t: float
    path_id: str
    frm: str
    nxt: str
    why: str
    transport: str
    addr: str
    active: bool = False
    # The link's original path as the line was logged, once it has logged
    # a line; a renewal changes it.
    original: str | None = None


@dataclass
class Message:
    """One "Path message sent" line, with the path that held its pair."""

    t: float
    transport: str
    addr: str
    msg_type: int
    length: int
    path_id: str | None


@dataclass
class Stop:
    """A path's stop: from its Dead entry until it answers, is revived or is
    released; ``end`` is None while it lasts to the end of the log."""

    path_id: str
    transport: str
    addr: str
    start: float
    end: float | None
    ended_by: str
    probes: list[float] = field(default_factory=list)
    bytes: int = 0
    # The early probe on the peer clearing ACTIVE, held to no gap.
    exempt: list[float] = field(default_factory=list)
    # The first probe the path left unanswered before this Dead entry, if
    # one is seen; a stop more than SILENCE_MAX after it began before its
    # Dead entry, unlogged, and cannot be placed.
    unanswered: float | None = None


@dataclass
class Episode:
    """A path's Probing episode, and the probes sent in it."""

    path_id: str
    start: float
    end: float | None
    probes: int = 0


@dataclass
class Timeline:
    """One node's view of one peer's paths, in log order, and the link's
    original path once it has logged a line (the latest link's, after a
    renewal)."""

    changes: list[Change] = field(default_factory=list)
    messages: list[Message] = field(default_factory=list)
    original: str | None = None


def timelines(path_lines: list[tuple[str, str]]) -> dict[str, dict[str, Timeline]]:
    """Per node (log source) and peer, the path changes and the messages
    sent, each message attributed to the path holding its pair then, and
    each change marked active when its path held the link's active pair."""
    out: dict[str, dict[str, Timeline]] = {}
    holder: dict[tuple[str, str, str, str], str] = {}
    # The active pair per node and peer, from the last switch line; absent
    # before the first, while the original path is active.
    active: dict[tuple[str, str], tuple[str, str]] = {}
    seen: dict[tuple[str, str], set[str]] = {}
    for source, line in path_lines:
        t = line_epoch(line)
        if t is None:
            continue
        f = line_fields(line)
        peer = f.get("peer", "?")
        tl = out.setdefault(source, {}).setdefault(peer, Timeline())
        transport = f.get("transport_id", "?")
        link = (source, peer)
        if "Path state changed" in line:
            c = Change(
                t=t, path_id=f.get("path_id", "?"), frm=f.get("from", "?"),
                nxt=f.get("next", "?"), why=f.get("why", "?"),
                transport=transport, addr=f.get("remote_addr", "?"),
            )
            ids = seen.setdefault(link, set())
            if c.frm == "None" and c.why == "Renewed":
                tl.original = c.path_id
                active.pop(link, None)
            elif tl.original is None and c.frm != "None" and c.path_id not in ids:
                tl.original = c.path_id
            ids.add(c.path_id)
            c.original = tl.original
            c.active = (
                active[link] == (transport, c.addr) if link in active
                else c.path_id == tl.original
            )
            tl.changes.append(c)
            key = (source, peer, transport, c.addr)
            if c.nxt == "None":
                if holder.get(key) == c.path_id:
                    del holder[key]
            else:
                holder[key] = c.path_id
        elif "Path switched" in line:
            active[link] = (transport, f.get("to", "?"))
        elif "Path moved to a new address" in line:
            old = (source, peer, transport, f.get("from", "?"))
            new = (source, peer, transport, f.get("to", "?"))
            if old in holder:
                holder[new] = holder.pop(old)
            if active.get(link) == old[2:]:
                active[link] = new[2:]
        elif "Path message sent" in line:
            addr = f.get("remote_addr", "?")
            tl.messages.append(Message(
                t=t, transport=transport, addr=addr,
                msg_type=int(f.get("msg_type", "0")), length=int(f.get("len", "0")),
                path_id=holder.get((source, peer, transport, addr)),
            ))
    return out


def _probes(tl: Timeline, path_id: str) -> list[Message]:
    """The probes sent on one path, in order."""
    return [m for m in tl.messages if m.path_id == path_id and m.msg_type == PROBE]


def _unanswered(tl: Timeline, dead: Change, k: int = 3) -> float | None:
    """The first probe left unanswered before a Dead entry, or None.

    Into Dead straight from Live (a close, a removal, a carrier loss) leaves
    no probe unanswered. From Suspect, the K timeouts that made it Suspect
    are the K probes sent last before the Suspect entry, and the first of
    them is the earliest unanswered. From Probing, every probe of the
    episode went unanswered.
    """
    mine = [c for c in tl.changes if c.path_id == dead.path_id and c.t <= dead.t]
    if dead.frm == "Some(Live)" or len(mine) < 2:
        return None
    probes = _probes(tl, dead.path_id)
    if dead.frm == "Some(Suspect)":
        suspect = next(
            (c for c in reversed(mine[:-1]) if c.nxt == "Some(Suspect)"), None
        )
        if suspect is None:
            return None
        before = [p.t for p in probes if p.t <= suspect.t]
        return before[-k] if len(before) >= k else (before[0] if before else None)
    if dead.frm == "Some(Probing)":
        entered = next(
            (c for c in reversed(mine[:-1]) if c.nxt == "Some(Probing)"), None
        )
        if entered is None:
            return None
        inside = [p.t for p in probes if entered.t <= p.t <= dead.t]
        return inside[0] if inside else None
    return None


def _failures(tl: Timeline) -> list[tuple[float, str]]:
    """Each instant the link's active path left Live or Suspect for a worse
    state leaving no path of the peer Live, by the lines, the original
    counted Live until its first line: ``(time, path_id)`` of that path.
    A renewal ending the old link's paths is not one: the link goes on at
    the new original, Live."""
    latest: dict[str, str] = {}
    out = []
    for c in tl.changes:
        latest[c.path_id] = c.nxt
        if not c.active or c.why == "Renewed" or c.original not in latest:
            continue
        if c.frm in ("Some(Live)", "Some(Suspect)") and c.nxt in (
            "Some(Suspect)", "Some(Dead)", "None",
        ) and c.frm != c.nxt:
            if not any(v == "Some(Live)" for v in latest.values()):
                out.append((c.t, c.path_id))
    return out


def stops(tl: Timeline) -> list[Stop]:
    """Every stop of every path in one timeline, with its probes."""
    out: list[Stop] = []
    open_stop: dict[str, Stop] = {}
    for c in tl.changes:
        s = open_stop.get(c.path_id)
        if s is not None:
            ends = (
                (c.nxt == "Some(Live)" and c.why == "Answered")
                or (c.frm == "Some(Dead)" and c.nxt == "Some(Probing)" and c.why == "Probed")
                or c.nxt == "None"
            )
            if ends:
                s.end = c.t
                s.ended_by = "released" if c.nxt == "None" else c.why
                del open_stop[c.path_id]
        if c.nxt == "Some(Dead)" and c.path_id not in open_stop:
            s = Stop(
                path_id=c.path_id, transport=c.transport, addr=c.addr,
                start=c.t, end=None, ended_by="open",
                unanswered=_unanswered(tl, c),
            )
            open_stop[c.path_id] = s
            out.append(s)
    failed = _failures(tl)
    for s in out:
        inside = [
            p for p in _probes(tl, s.path_id)
            if p.t > s.start and (s.end is None or p.t < s.end)
        ]
        acks = [
            m.t for m in tl.messages
            if m.path_id == s.path_id and m.msg_type == ACK
            and m.t > s.start and (s.end is None or m.t < s.end)
        ]
        flagged = False
        for p in inside:
            if not flagged and any(0 <= p.t - a <= EXEMPT_WINDOW for a in acks):
                s.exempt.append(p.t)
                flagged = True
            elif any(0 <= p.t - t <= EXEMPT_WINDOW for t, _pid in failed):
                s.exempt.append(p.t)
        s.probes = [p.t for p in inside if p.t not in s.exempt]
        s.bytes = sum(p.length for p in inside)
    return out


def episodes(tl: Timeline) -> list[Episode]:
    """Every Probing episode of every path in one timeline."""
    out: list[Episode] = []
    current: dict[str, Episode] = {}
    for c in tl.changes:
        e = current.pop(c.path_id, None)
        if e is not None and c.nxt != "Some(Probing)":
            e.end = c.t
        elif e is not None:
            current[c.path_id] = e
        if c.nxt == "Some(Probing)" and c.path_id not in current:
            e = Episode(path_id=c.path_id, start=c.t, end=None)
            current[c.path_id] = e
            out.append(e)
    for e in out:
        e.probes = sum(
            1 for p in _probes(tl, e.path_id)
            if p.t >= e.start and (e.end is None or p.t < e.end)
        )
    return out


def gaps(stop: Stop) -> list[tuple[int, float, float]]:
    """Each probe's gap from the one before (probe 0 the stop) against the
    floor: ``(n, gap, least gap)``."""
    times = [stop.start] + stop.probes
    return [(n, times[n] - times[n - 1], floor_gap(n)) for n in range(1, len(times))]


def floor_breaks(stop: Stop, allowance: float = STAMP_ALLOWANCE) -> list[tuple[int, float, float]]:
    """The gaps that fall short of the floor by more than the allowance."""
    return [(n, g, least) for n, g, least in gaps(stop) if g < least - allowance]


def margin(stop: Stop) -> float | None:
    """The smallest gap minus its least gap over a stop, or None for a stop
    with no probe."""
    m = [g - least for _, g, least in gaps(stop)]
    return min(m) if m else None


def _node(source: str) -> str:
    """A node's id from its container name."""
    return source.removeprefix("fips-node-").split("-")[0]


def _stepfigures(rec: dict, tls: dict[str, dict[str, Timeline]], cname) -> dict:
    """One scheduled down's figures at each end of its edge."""
    down, up = rec.get("down"), rec.get("up")
    out = {k: rec[k] for k in ("step", "mode", "edge", "end", "at", "secs")}
    out["down"], out["up"] = down, up
    ends = {}
    for node in rec["edge"]:
        src = cname(node)
        row: dict = {"probes": 0, "bytes": 0, "stops": 0, "probes_down": 0, "recovery_s": None}
        for tl in tls.get(src, {}).values():
            for st in stops(tl):
                if down is not None and up is not None and down <= st.start <= up:
                    row["stops"] += 1
                    row["probes"] += len(st.probes) + len(st.exempt)
                    row["bytes"] += st.bytes
                    # The probes sent while the interface was down, to set
                    # against the capture and the veth's tx counter.
                    row["probes_down"] += sum(1 for t in st.probes + st.exempt if t <= up)
            if down is None or up is None:
                continue
            hit = {
                c.transport for c in tl.changes
                if down <= c.t <= up and c.frm in ("Some(Live)", "Some(Suspect)")
            }
            back = [
                c.t for c in tl.changes
                if c.t > up and c.nxt == "Some(Live)" and c.transport in hit
            ]
            if back:
                rec_s = min(back) - up
                row["recovery_s"] = (
                    rec_s if row["recovery_s"] is None else min(row["recovery_s"], rec_s)
                )
        cap = rec.get("captures", {}).get(node)
        if cap is not None:
            # Per source (MAC, or address and port for IPv4): every frame the
            # capture saw, and those between the down's stamp and the up's.
            by_src: dict[str, list[int]] = {}
            for f in cap["frames"]:
                key = f.get("ip_src") or f["src"]
                n = by_src.setdefault(key, [0, 0, 0, 0])
                n[0] += 1
                n[1] += f["len"]
                if down is not None and up is not None and down <= f["t"] <= up:
                    n[2] += 1
                    n[3] += f["len"]
            row["capture"] = {
                "iface": cap["iface"],
                "frames": len(cap["frames"]),
                "by_source": {
                    k: {"frames": v[0], "bytes": v[1], "frames_down": v[2], "bytes_down": v[3]}
                    for k, v in sorted(by_src.items())
                },
            }
        ctr = rec.get("counters", {}).get(node)
        if ctr and "after" in ctr:
            row["counters"] = {
                k: ctr["after"][k] - ctr["before"][k] for k in ("tx_packets", "tx_dropped")
            }
        ends[node] = row
    out["ends"] = ends
    return out


def _reorder(mmp_lines: list[tuple[str, str]], switches: list[tuple[str, str]],
             settle: float = 2.0) -> list[dict]:
    """The peer's reorder count across each switch: the last MMP sample at
    or before the switch, and the first ``settle`` seconds or more after."""
    samples: dict[str, list[tuple[float, str]]] = {}
    for source, line in mmp_lines:
        t = line_epoch(line)
        v = line_fields(line).get("rr_reordered")
        if t is not None and v is not None:
            samples.setdefault(source, []).append((t, v))
    out = []
    for source, line in switches:
        t = line_epoch(line)
        series = samples.get(source, [])
        if t is None or not series:
            continue
        before = [v for st, v in series if st <= t]
        after = [v for st, v in series if st >= t + settle]
        out.append({
            "node": _node(source), "switch": t,
            "before": before[-1] if before else None,
            "after": after[0] if after else None,
        })
    return out


def figures(
    path_lines: list[tuple[str, str]],
    records: list[dict],
    cname,
    latencies: list[tuple[float, str, float | None]],
    mmp_lines: list[tuple[str, str]],
    switches: list[tuple[str, str]],
    resends: list[tuple[str, str]],
    log_interval: float | None,
) -> dict:
    """The run's figures: every stop and Probing episode, each scheduled
    down's probes, captures and recovery at each end, the switch latencies,
    announce resends and the reorder count across each switch."""
    tls = timelines(path_lines)
    all_stops, most = [], {}
    for source, peers in sorted(tls.items()):
        for peer, tl in sorted(peers.items()):
            for st in stops(tl):
                g = gaps(st)
                m = margin(st)
                all_stops.append({
                    "node": _node(source), "peer": peer, "path_id": st.path_id,
                    "transport": st.transport, "addr": st.addr,
                    "start": st.start, "end": st.end, "ended_by": st.ended_by,
                    "probes": len(st.probes) + len(st.exempt), "bytes": st.bytes,
                    "exempt": st.exempt,
                    "gaps_s": [round(x, 4) for _, x, _ in g],
                    "least_s": [least for _, _, least in g],
                    "min_margin_ms": None if m is None else round(m * 1000, 1),
                    "first_unanswered": st.unanswered,
                })
            for ep in episodes(tl):
                most[_node(source)] = max(most.get(_node(source), 0), ep.probes)
    count: dict[str, int] = {}
    for source, _ in resends:
        count[_node(source)] = count.get(_node(source), 0) + 1
    return {
        "stamp_allowance_ms": STAMP_ALLOWANCE * 1000,
        "floor": {"min_s": FLOOR_MIN, "max_s": FLOOR_MAX, "silence_max_s": SILENCE_MAX},
        "stops": all_stops,
        "discovery_most_probes": most,
        "steps": [_stepfigures(r, tls, cname) for r in records],
        "switch_latency_ms": [
            {"down": t, "node": _node(end), "ms": None if d is None else round(d * 1000)}
            for t, end, d in latencies
        ],
        "announce_resends": count,
        "reorder": _reorder(mmp_lines, switches),
        "reorder_resolution": (
            f"the MMP log interval ({log_interval:g} s) or the receiver report "
            f"interval, whichever is longer"
            if log_interval else "the MMP log interval (default 30 s)"
        ),
    }


def summary(fig: dict) -> str:
    """A text section of the figures for analysis.txt."""
    lines = ["", "=== Path figures ===", ""]
    lines.append(f"Stops: {len(fig['stops'])} (allowance {fig['stamp_allowance_ms']:.0f} ms)")
    for st in fig["stops"]:
        lines.append(
            f"  {st['node']} path {st['path_id']} to {st['addr']}: {st['probes']} probes "
            f"({len(st['exempt'])} exempt), "
            f"{st['bytes']} bytes, ended by {st['ended_by']}, gaps {st['gaps_s']}, "
            f"smallest margin {st['min_margin_ms']} ms"
        )
    for step in fig["steps"]:
        lines.append(f"Step {step['step']}:")
        for node, row in step["ends"].items():
            cap = row.get("capture")
            capped = ""
            if cap:
                down = {k: v["frames_down"] for k, v in cap["by_source"].items()}
                capped = f", capture on {cap['iface']} while down: {down}"
            if row.get("counters"):
                capped += f", veth tx over the step: {row['counters']}"
            rec = row["recovery_s"]
            lines.append(
                f"  {node}: {row['probes']} probes ({row['probes_down']} while down), "
                f"{row['bytes']} bytes in {row['stops']} stop(s); recovery "
                f"{'none' if rec is None else f'{rec:.2f} s'}{capped}"
            )
    lat = [x["ms"] for x in fig["switch_latency_ms"] if x["ms"] is not None]
    if lat:
        lines.append(f"Switch latency (ms): min {min(lat)}, max {max(lat)}, all {lat}")
    lines.append(f"Announce resends: {fig['announce_resends'] or 'none'}")
    lines.append(f"Reorder across switches ({fig['reorder_resolution']}):")
    for r in fig["reorder"]:
        lines.append(f"  {r['node']} at {r['switch']:.3f}: {r['before']} -> {r['after']}")
    lines.append("")
    return "\n".join(lines)
