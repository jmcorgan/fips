#!/usr/bin/env python3
"""Hermetic tests of the chaos assertions that read path lines, of the
Ethernet kernel drop ceiling, which reads the final congestion snapshot, and
of the edge agreement, which reads both ends' peer rows and the crossing
lines.

Each case feeds an evaluator planted log lines, flap stamps or iperf3
results and checks its verdict, so every assertion is shown able to fail
and able to pass without a container. The planted lines are copied from the
shape the node writes (`tracing`'s full format: an RFC 3339 stamp, the
level, the target, the message, then `key=value` fields, an `Option` field
as `Some(Live)` or `None`).

Usage: testing/chaos/sim-assert-test.py [-v]
Exit:  0 every case gave its expected verdict, 1 otherwise.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

from lib.log_analysis import analyze_logs  # noqa: E402
from sim import assertions as A  # noqa: E402
from sim import scenario as S  # noqa: E402

# The planted failures log warnings on purpose.
logging.getLogger("sim").addHandler(logging.NullHandler())

T0 = 1793650000.0
N1 = "fips-node-n01"
N2 = "fips-node-n02"
VERBOSE = "-v" in sys.argv[1:]


def stamp(t: float) -> str:
    """The node's own timestamp for epoch ``t``."""
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def switched(t: float, why: str = "mandatory", to: str = "e2:36:d0:87:92:fd",
             transport: str = "transport:1") -> str:
    """A "Path switched" line at ``t``, to ``to`` on ``transport``."""
    return (
        f"{stamp(t)}  INFO fips::node::handlers::path: Path switched "
        f"peer=npub17cx8...wz28 from=10.30.0.11:2121 to={to} "
        f"transport_id={transport} why=\"{why}\""
    )


def state(t: float, pid: int, frm: str, nxt: str, why: str = "Answered",
          peer: str = "npub17cx8...wz28", addr: str = "10.222.0.2:2122",
          transport: str = "transport:2") -> str:
    """A "Path state changed" line at ``t``."""
    return (
        f"{stamp(t)} DEBUG fips::node::handlers::path: Path state changed "
        f"peer={peer} transport_id={transport} remote_addr={addr} "
        f"path_id={pid} from={frm} next={nxt} why={why}"
    )


def promoted(t: float) -> str:
    """A "Peer promoted to active" line at ``t``."""
    return f"{stamp(t)}  INFO fips::node::handlers::handshake: Peer promoted to active peer=n02"


def dialled(t: float) -> str:
    """A "Connection initiated" line at ``t``."""
    return (
        f"{stamp(t)} DEBUG fips::node::lifecycle: Connection initiated peer=n02 "
        f"transport_id=transport:1 remote_addr=10.30.0.12:2121 link_id=3 our_index=7"
    )


def anon_dialled(t: float, addr: str = "e2:36:d0:87:92:fd") -> str:
    """An "Anonymous discovery connection initiated" line at ``t``, to ``addr``."""
    return (
        f"{stamp(t)} DEBUG fips::node::lifecycle: Anonymous discovery connection "
        f"initiated transport_id=transport:2 remote_addr={addr} link_id=4 our_index=9"
    )


def max_dials(r) -> A.AssertionOutcome:
    """``evaluate_max_dials`` at a ceiling of 0 on ``r``'s dial lines.

    The anonymous dials are passed where the analysis has them, so the same
    cases also run against a harness that does not parse them.
    """
    anon = getattr(r, "anon_dials", None)
    if anon is None:
        return A.evaluate_max_dials(S.MaxDialsAssertion(0), r.dials, r.peers_promoted)
    return A.evaluate_max_dials(S.MaxDialsAssertion(0), r.dials, r.peers_promoted, anon)


def logs(**per_node: list[str]):
    """Analyse planted lines, one list per node."""
    return analyze_logs({k: "\n".join(v) for k, v in per_node.items()})


def iperf(*rates: int, sent: tuple[int, ...] | None = None) -> dict:
    """An iperf3 result whose receiver took in these bytes, one per second.

    ``sent`` gives the client's own intervals (what it wrote); by default
    they match what arrived.
    """
    def ivs(values):
        """iperf3 intervals of one second carrying ``values`` bytes."""
        return [{"sum": {"bytes": b, "seconds": 1.0}} for b in values]
    return {
        "start": {"timestamp": {"time": "Mon, 02 Nov 2026 22:00:00 GMT"},
                  "connecting_to": {"host": "npub1x.fips"}},
        "intervals": ivs(rates if sent is None else sent),
        "server_output_json": {"intervals": ivs(rates)},
    }


CASES: list[tuple[str, bool, object]] = []


def case(name: str, expect: bool):
    """Register a case: a function returning an outcome (or a bool)."""
    def wrap(fn):
        """Add ``fn`` to CASES under ``name`` and return it unchanged."""
        CASES.append((name, expect, fn))
        return fn
    return wrap


# --- path_switches -----------------------------------------------------------

@case("a planted Path switched line counts one switch", True)
def _():
    r = logs(**{N1: [switched(T0)]})
    return len(r.path_switches) == 1


@case("a line without Path switched counts no switch", True)
def _():
    r = logs(**{N1: [state(T0, 5, "Some(Live)", "Some(Suspect)", "Timeout")]})
    return len(r.path_switches) == 0


@case("path_switches per_flap 4 extra 2 fails 4F+3 switches over F flaps", False)
def _():
    cfg = S.PathSwitchesAssertion(min_total=4, per_flap=4, extra=2)
    return A.evaluate_path_switches(cfg, [(N1, switched(T0))] * (4 * 3 + 3), 3)


@case("path_switches per_flap 4 extra 2 passes 4F+2 switches over F flaps", True)
def _():
    cfg = S.PathSwitchesAssertion(min_total=4, per_flap=4, extra=2)
    return A.evaluate_path_switches(cfg, [(N1, switched(T0))] * (4 * 3 + 2), 3)


@case("path_switches min_total fails a run with fewer switches", False)
def _():
    cfg = S.PathSwitchesAssertion(min_total=4, per_flap=4, extra=2)
    return A.evaluate_path_switches(cfg, [(N1, switched(T0))] * 3, 3)


@case("path_switches max_total 2 fails three switches", False)
def _():
    cfg = S.PathSwitchesAssertion(max_total=2)
    return A.evaluate_path_switches(cfg, [(N1, switched(T0))] * 3, 0)


# --- switch_latency ----------------------------------------------------------

def _latency(cfg, n1_delay, n2_delay):
    """switch_latency over one down at T0 with each end's switch delay (s)."""
    lines = {}
    if n1_delay is not None:
        lines[N1] = [switched(T0 + n1_delay)]
    if n2_delay is not None:
        lines[N2] = [switched(T0 + n2_delay)]
    r = logs(**lines)
    return A.evaluate_switch_latency(cfg, [(T0, N1, N2)], r.path_switches)


@case("switch_latency fails a switch 1301 ms after the down at 1300", False)
def _():
    return _latency(S.SwitchLatencyAssertion(max_ms=1300), 1.301, None)


@case("switch_latency passes a switch 1299 ms after the down at 1300", True)
def _():
    return _latency(S.SwitchLatencyAssertion(max_ms=1300), 1.299, None)


@case("switch_latency each_end fails a fast switch at one end and none at the other", False)
def _():
    return _latency(S.SwitchLatencyAssertion(max_ms=1300, each_end=True), 0.2, None)


@case("switch_latency each_end passes both ends within the bound", True)
def _():
    return _latency(S.SwitchLatencyAssertion(max_ms=1300, each_end=True), 0.2, 1.1)


@case("switch_latency signalled_ms 500 fails a 600 ms switch", False)
def _():
    cfg = S.SwitchLatencyAssertion(max_ms=1000, each_end=True, signalled_ms=500)
    return _latency(cfg, 0.05, 0.6)


@case("switch_latency signalled_ms 500 passes two signalled switches", True)
def _():
    cfg = S.SwitchLatencyAssertion(max_ms=1000, each_end=True, signalled_ms=500)
    return _latency(cfg, 0.05, 0.4)


@case("switch_latency fails a run with no down", False)
def _():
    return A.evaluate_switch_latency(S.SwitchLatencyAssertion(), [], [])


# The forward-only shape: n02's sends are dropped (it is the dropped sender
# of the one-way down at T0) while n01's still reach it.
SENDER = {T0: N2}
FWD = S.SwitchLatencyAssertion(max_ms=1300, each_end=True, sender_ms=2600)


def _sender(cfg, n1_delay, n2_delay, senders):
    """switch_latency over one down at T0, ``senders`` naming its dropped
    sender by stamp (empty for a two-way down)."""
    r = logs(**{N1: [switched(T0 + n1_delay)], N2: [switched(T0 + n2_delay)]})
    return A.evaluate_switch_latency(cfg, [(T0, N1, N2)], r.path_switches, senders)


@case("switch_latency sender_ms 2600 passes the dropped sender at 2001 ms", True)
def _():
    return _sender(FWD, 1.0, 2.001, SENDER)


@case("switch_latency sender_ms 2600 fails the dropped sender at 2700 ms", False)
def _():
    return _sender(FWD, 1.0, 2.7, SENDER)


@case("switch_latency sender_ms keeps max_ms 1300 for the other end of a one-way down (1400 ms fails)", False)
def _():
    return _sender(FWD, 1.4, 2.0, SENDER)


@case("switch_latency sender_ms does not apply to a two-way down (2001 ms fails under max_ms 1300)", False)
def _():
    return _sender(FWD, 1.0, 2.001, {})


@case("switch_latency sender_ms applies to the dropped sender only, not to the other end at 2001 ms", False)
def _():
    return _sender(FWD, 2.001, 1.0, SENDER)


@case("switch_latency without sender_ms gives today's verdict and detail for a dropped sender at 2001 ms", True)
def _():
    cfg = S.SwitchLatencyAssertion(max_ms=1300, each_end=True)
    got = _sender(cfg, 1.0, 2.001, SENDER)
    today = _latency(cfg, 1.0, 2.001)
    return not got.passed and got.detail == today.detail


@case("switch_latency either end passes a one-way down whose dropped sender alone switched within sender_ms", True)
def _():
    cfg = S.SwitchLatencyAssertion(max_ms=1300, sender_ms=2600)
    r = logs(**{N2: [switched(T0 + 2.001)]})
    return A.evaluate_switch_latency(cfg, [(T0, N1, N2)], r.path_switches, SENDER)


@case("dropped_senders maps each oneway down's stamp to its from end's container, and no two-way down", True)
def _():
    records = [
        {"mode": "netem", "src": None, "down": T0 - 50},
        {"mode": "oneway", "src": "n02", "end": "n01", "down": T0},
        {"mode": "oneway", "src": "n01", "end": "n02", "down": T0 + 70},
    ]
    return A.dropped_senders(records, lambda n: f"fips-node-{n}") == {T0: N2, T0 + 70: N1}


@case("the runner hands switch_latency each oneway down's dropped sender", True)
def _():
    from types import SimpleNamespace

    from sim import runner as R

    r = R.SimRunner(_scenario(SCHEDULED))
    r.scenario.assertions = S.AssertionsConfig(switch_latency=FWD)
    r.topology = _twonodes()
    r.schedule = SimpleNamespace(
        records=[{"mode": "oneway", "src": "n02", "end": "n01", "down": T0}],
        links=SimpleNamespace(flap_events=[(T0, "down", "n01", "n02")]),
    )
    r.assertion_outcomes = []
    r._evaluatepaths(logs(**{
        N1: [switched(T0 - 30, "discretionary", to="10.222.0.2:2122", transport="transport:2"),
             switched(T0 + 1.0)],
        N2: [switched(T0 - 30, "discretionary", to="10.222.0.1:2122", transport="transport:2"),
             switched(T0 + 2.001)],
    }), [], [])
    out = r.assertion_outcomes
    return len(out) == 1 and out[0].passed and "(dropped sender)" in out[0].detail


def _twonodes():
    """A stand-in topology of the forward-only pair: n01 at 10.222.0.1 on
    its veth, n02 at 10.222.0.2, no Ethernet MACs."""
    from types import SimpleNamespace

    return SimpleNamespace(
        nodes={"n01": SimpleNamespace(ethernet_macs={}), "n02": SimpleNamespace(ethernet_macs={})},
        container_name=lambda n: f"fips-node-{n}",
        veth_ip=lambda node, peer: {"n01": "10.222.0.1", "n02": "10.222.0.2"}[node],
    )


@case("the runner refuses the end whose link was not on the down's veth address", True)
def _():
    from types import SimpleNamespace

    from sim import runner as R

    r = R.SimRunner(_scenario(SCHEDULED))
    r.scenario.assertions = S.AssertionsConfig(switch_latency=FWD)
    r.topology = _twonodes()
    r.schedule = SimpleNamespace(
        records=[{"mode": "oneway", "src": "n02", "end": "n01", "down": T0}],
        links=SimpleNamespace(flap_events=[(T0, "down", "n01", "n02")]),
    )
    r.assertion_outcomes = []
    r._evaluatepaths(logs(**{
        N1: [switched(T0 - 30, "discretionary", to="10.222.0.2:2122", transport="transport:2"),
             switched(T0 + 1.0, to="10.30.0.12:2121")],
        N2: [switched(T0 + 40, "discretionary", to="10.222.0.1:2122", transport="transport:2")],
    }), [], [])
    out = r.assertion_outcomes
    return (
        len(out) == 1 and not out[0].passed
        and f"{N2} after {N1}--{N2} down" in out[0].detail
        and "precondition not met" in out[0].detail
        and f"{N1}=1000" in out[0].detail
    )


# --- switch_latency: the down's path must carry the link ----------------------

# The down's path at each end: the other end's veth address.
DOWNPATH = {(T0, N1): {"10.222.0.2"}, (T0, N2): {"10.222.0.1"}}


def _carriedlatency(n1_on_veth: bool, n2_on_veth: bool, cfg=FWD):
    """switch_latency over the forward-only down at T0, each end's link on
    the veth beforehand or not: an end on the veth switches to the bridge
    1.0 or 2.0 s after the down, one on the bridge moves to the veth 40 s
    after it (the fail-back after the restore)."""
    def end(on_veth: bool, veth: str, bridge: str, delay: float) -> list[str]:
        """One end's switch lines."""
        if on_veth:
            return [switched(T0 - 30, "discretionary", to=veth, transport="transport:2"),
                    switched(T0 + delay, to=bridge)]
        return [switched(T0 + 40, "discretionary", to=veth, transport="transport:2")]
    r = logs(**{
        N1: end(n1_on_veth, "10.222.0.2:2122", "10.30.0.12:2121", 1.0),
        N2: end(n2_on_veth, "10.222.0.1:2122", "10.30.0.11:2121", 2.0),
    })
    downs = [(T0, N1, N2)]
    un = A.uncarried_downs(downs, r.path_lines, DOWNPATH)
    return (
        A.evaluate_switch_latency(cfg, downs, r.path_switches, SENDER, un),
        A.evaluate_switch_latency(cfg, downs, r.path_switches, SENDER),
    )


@case("switch_latency refuses a down whose path did not carry the link at that end, naming the end and the down", True)
def _():
    got, _today = _carriedlatency(n1_on_veth=False, n2_on_veth=True)
    return (
        not got.passed
        and f"{N1} after {N1}--{N2} down at" in got.detail
        and "precondition not met" in got.detail
        and "(it was on 10.30.0.11:2121)" in got.detail
        and "40000 ms" not in got.detail
        and f"{N1}=not measured" in got.detail
    )


@case("switch_latency fails a run when a down's path did not carry the link at one end", False)
def _():
    return _carriedlatency(n1_on_veth=True, n2_on_veth=False)[0]


@case("switch_latency gives today's verdict and detail for a down whose path carried the link at both ends", True)
def _():
    got, today = _carriedlatency(n1_on_veth=True, n2_on_veth=True)
    return got.passed and got.detail == today.detail


@case("switch_latency either end refuses a down whose path carried the link at neither end", True)
def _():
    cfg = S.SwitchLatencyAssertion(max_ms=1300, sender_ms=2600)
    got, today = _carriedlatency(n1_on_veth=False, n2_on_veth=False, cfg=cfg)
    return not got.passed and got.detail.count("precondition not met") == 2


@case("uncarried_downs reads where the link was before its first switch from that switch's from", True)
def _():
    line = switched(T0 + 5, to="10.222.0.2:2122").replace(
        "from=10.30.0.11:2121", "from=10.30.0.12:2121")
    lines = logs(**{N1: [line]}).path_lines
    return A.uncarried_downs([(T0, N1, N2)], lines, DOWNPATH) == {(T0, N1): "10.30.0.12:2121"}


@case("uncarried_downs matches an Ethernet path by its MAC", True)
def _():
    mac = "e2:36:d0:87:92:fd"
    lines = logs(**{N1: [switched(T0 - 30, to=mac, transport="transport:2")]}).path_lines
    on = A.uncarried_downs([(T0, N1, N2)], lines, {(T0, N1): {mac.upper()}})
    off = A.uncarried_downs([(T0, N1, N2)], lines, {(T0, N1): {"aa:bb:cc:dd:ee:ff"}})
    return on == {} and off == {(T0, N1): mac}


@case("forward-only declares the dropped sender's ceiling 2600 ms and 1300 ms at the other end", True)
def _():
    scen = S.load_scenario(os.path.join(HERE, "scenarios", "forward-only.yaml"))
    sl = scen.assertions.switch_latency
    return (sl.max_ms, sl.sender_ms, sl.each_end) == (1300, 2600, True)


def _nooneway(sender: str = "2600") -> str:
    """The schedule fixture (no oneway down) declaring ``sender_ms``."""
    return SCHEDULED + (
        "assertions:\n"
        f"  switch_latency: {{max_ms: 1300, each_end: true, sender_ms: {sender}}}\n"
    )


@case("loading refuses switch_latency sender_ms in a scenario with no oneway down", False)
def _():
    try:
        _scenario(_nooneway())
    except ValueError as e:
        return "sender_ms" not in str(e)
    return True


@case("loading refuses a switch_latency sender_ms that is not a positive integer", False)
def _():
    for bad in ("0", "true", "2.6"):
        try:
            _scenario(_nooneway(bad))
        except ValueError as e:
            if "sender_ms: must be an integer" not in str(e):
                return True
            continue
        return True
    return False


# --- max_promotions ----------------------------------------------------------

@case("max_promotions fails a second promotion on one node", False)
def _():
    r = logs(**{N1: [promoted(T0), promoted(T0 + 30)], N2: [promoted(T0)]})
    return A.evaluate_max_promotions(S.MaxPromotionsAssertion(per_node=1), r.peers_promoted)


@case("max_promotions passes one promotion per node", True)
def _():
    r = logs(**{N1: [promoted(T0)], N2: [promoted(T0)]})
    return A.evaluate_max_promotions(S.MaxPromotionsAssertion(per_node=1), r.peers_promoted)


# --- max_dials ---------------------------------------------------------------

@case("max_dials fails a Connection initiated after the node's first promotion", False)
def _():
    r = logs(**{N1: [dialled(T0), promoted(T0 + 1), dialled(T0 + 10)]})
    return A.evaluate_max_dials(S.MaxDialsAssertion(0), r.dials, r.peers_promoted)


@case("max_dials passes a Connection initiated before the first promotion", True)
def _():
    r = logs(**{N1: [dialled(T0), dialled(T0 + 0.5), promoted(T0 + 1)]})
    return A.evaluate_max_dials(S.MaxDialsAssertion(0), r.dials, r.peers_promoted)


@case("max_dials fails a second anonymous dial to one address after the first promotion", False)
def _():
    r = logs(**{N1: [anon_dialled(T0), promoted(T0 + 1), anon_dialled(T0 + 10)]})
    return max_dials(r)


@case("max_dials passes one anonymous dial after the first promotion", True)
def _():
    r = logs(**{N1: [promoted(T0), anon_dialled(T0 + 5)]})
    return max_dials(r)


@case("max_dials fails a node with no promotion that dials one address anonymously twice", False)
def _():
    r = logs(**{N2: [anon_dialled(T0), anon_dialled(T0 + 20)]})
    return max_dials(r)


@case("max_dials passes one anonymous dial to each of two addresses", True)
def _():
    r = logs(**{N1: [anon_dialled(T0), anon_dialled(T0 + 1, "e2:36:d0:87:92:fe")]})
    return max_dials(r)


# --- max_stall ---------------------------------------------------------------

@case("max_stall fails an iperf3 result with no receiver intervals", False)
def _():
    r = iperf(1, 1)
    del r["server_output_json"]["intervals"]
    return A.evaluate_max_stall(S.MaxStallAssertion(2), [iperf(5, 5, 5), r])


@case("max_stall fails an iperf3 result without the receiver's output", False)
def _():
    r = iperf(1, 1)
    del r["server_output_json"]
    return A.evaluate_max_stall(S.MaxStallAssertion(2), [iperf(5, 5, 5), r])


# The shape of the failing session in full local CI at 711c2e2f: after a
# switch the client wrote nothing in seconds 14 to 16 (MB per second below),
# while the receiver's frame counter showed about 0.45 MB a second arriving.
_WROTE = (3_700_000, 0, 0, 1_400_000, 0, 0, 0, 1_400_000, 0, 1_300_000, 0)


@case("max_stall passes empty client seconds while the receiver took in bytes", True)
def _():
    got = iperf(*([450_000] * len(_WROTE)), sent=_WROTE)
    return A.evaluate_max_stall(S.MaxStallAssertion(2), [got])


@case("max_stall fails three empty receiver seconds though the client wrote", False)
def _():
    got = iperf(450_000, 0, 0, 0, 450_000, sent=(5, 5, 5, 5, 5))
    return A.evaluate_max_stall(S.MaxStallAssertion(2), [got])


@case("max_stall fails an iperf3 result carrying an error", False)
def _():
    return A.evaluate_max_stall(
        S.MaxStallAssertion(2),
        [iperf(5, 5, 5), {"error": "unable to receive results: Connection reset by peer"}],
    )


@case("max_stall fails a three-second hole at ceiling 2", False)
def _():
    return A.evaluate_max_stall(S.MaxStallAssertion(2), [iperf(5, 0, 0, 0, 5)])


@case("max_stall passes a two-second hole at ceiling 2", True)
def _():
    return A.evaluate_max_stall(S.MaxStallAssertion(2), [iperf(5, 0, 0, 5)])


@case("max_stall lists a busy-server collision without measuring it", True)
def _():
    busy = {"error": "error - the server is busy running a test. try again later"}
    return A.evaluate_max_stall(S.MaxStallAssertion(2), [iperf(5, 5), busy])


@case("max_stall fails when every session collided with a busy server", False)
def _():
    busy = {"error": "error - the server is busy running a test. try again later"}
    return A.evaluate_max_stall(S.MaxStallAssertion(2), [busy])


# The shape of run load2 of the stability reruns: both ends switched in
# about 1 s, and the TCP receiver still took in nothing for three whole
# seconds while its sender waited out a retransmission timer. A UDP stream
# beside it would have stopped for the switch alone.
_TCP_HOLE = (450_000, 0, 0, 0, 450_000)
_UDP_GAP = (125_000, 0, 125_000, 125_000, 125_000)


@case("max_stall held on TCP fails a TCP receiver silent for 3 s", False)
def _():
    return A.evaluate_max_stall(S.MaxStallAssertion(2), [iperf(*_TCP_HOLE)])


@case("max_stall on the UDP stream passes a 1 s UDP gap, reporting TCP's 3 s", True)
def _():
    got = A.evaluate_max_stall(
        S.MaxStallAssertion(2, stream="udp"), [iperf(*_TCP_HOLE)], [iperf(*_UDP_GAP)]
    )
    return got.passed and "TCP (reported, not bounded): longest zero-byte run 3 s" in got.detail


@case("max_stall on the UDP stream fails three empty UDP seconds", False)
def _():
    return A.evaluate_max_stall(
        S.MaxStallAssertion(2, stream="udp"),
        [iperf(5, 5, 5, 5, 5)], [iperf(125_000, 0, 0, 0, 125_000)],
    )


@case("max_stall on the UDP stream fails when no UDP stream ran", False)
def _():
    return A.evaluate_max_stall(S.MaxStallAssertion(2, stream="udp"), [iperf(5, 5)], [])


@case("max_stall on the UDP stream fails one that did not start", False)
def _():
    lost = {"error": "the UDP stream did not start", "_meta": {"client": "n01", "server": "n02"}}
    return A.evaluate_max_stall(
        S.MaxStallAssertion(2, stream="udp"), [iperf(5, 5)], [iperf(5, 5), lost]
    )


# --- paths_live --------------------------------------------------------------

def _live(cfg, n1_lines, n2_lines):
    """paths_live over planted state lines at the two nodes."""
    r = logs(**{N1: n1_lines, N2: n2_lines})
    return A.evaluate_paths_live(cfg, r.path_lines, [N1, N2])


def _second(pid: int) -> list[str]:
    """A path created during the run that went Live."""
    return [
        state(T0, pid, "None", "Some(Probing)", "Found"),
        state(T0 + 0.1, pid, "Some(Probing)", "Some(Live)", "Answered"),
    ]


@case("paths_live passes the original with no line and one created path gone Live at min 2", True)
def _():
    return _live(S.PathsLiveAssertion(min=2), _second(11), _second(21))


@case("paths_live fails a created path that never went Live", False)
def _():
    never = [state(T0, 11, "None", "Some(Probing)", "Found"),
             state(T0 + 5, 11, "Some(Probing)", "Some(Dead)", "Exhausted")]
    return _live(S.PathsLiveAssertion(min=2), never, _second(21))


@case("paths_live does not count the original twice when it goes Dead and back Live", False)
def _():
    flap = [state(T0, 7, "Some(Live)", "Some(Dead)", "Timeout"),
            state(T0 + 9, 7, "Some(Dead)", "Some(Live)", "Answered")]
    return _live(S.PathsLiveAssertion(min=2), flap, flap)


@case("paths_live fails when only one end held a second path", False)
def _():
    return _live(S.PathsLiveAssertion(min=2), _second(11), [])


RENEWED_FROM = "10.30.0.11:2121"


def _renewed(t: float, old: int, new: int, addr: str = "10.222.0.2:2122",
             transport: str = "transport:2") -> list[str]:
    """A renewal at ``t`` as the node logs one: the old link's original
    (``old``, unlogged until then) ends and the new link's original
    (``new``, at ``addr``) begins Live, each for why=Renewed, with no
    switch line."""
    return [
        state(t, old, "Some(Live)", "None", "Renewed", addr=RENEWED_FROM,
              transport="transport:1"),
        state(t + 0.00002, new, "None", "Some(Live)", "Renewed", addr=addr,
              transport=transport),
    ]


def _relive(pid: int) -> list[str]:
    """Path ``pid`` dropped to Dead and back Live, as forward-only's
    drops take it."""
    return [
        state(T0 + 30, pid, "Some(Live)", "Some(Suspect)", "Timeout"),
        state(T0 + 32, pid, "Some(Suspect)", "Some(Dead)", "Retired"),
        state(T0 + 60, pid, "Some(Dead)", "Some(Probing)", "Probed"),
        state(T0 + 60.1, pid, "Some(Probing)", "Some(Live)", "Answered"),
    ]


@case("paths_live does not count a renewal's new original as a path created in the run", False)
def _():
    one = _renewed(T0 - 60, 1, 3) + _relive(3)
    return _live(S.PathsLiveAssertion(min=2), one, one)


@case("paths_live passes a renewal with a second path created and Live after it", True)
def _():
    two = _renewed(T0 - 60, 1, 3) + [
        state(T0 - 59, 11, "None", "Some(Probing)", "Candidate", addr=RENEWED_FROM),
        state(T0 - 58.9, 11, "Some(Probing)", "Some(Live)", "Answered", addr=RENEWED_FROM),
    ] + _relive(3)
    return _live(S.PathsLiveAssertion(min=2), two, two)


# --- max_kernel_drops --------------------------------------------------------

def drops_entry(drops: int | None, recv: int | None, kind: str = "ethernet",
                tid: int = 2) -> dict:
    """One transport's entry in a congestion snapshot's ``kernel_drops``."""
    return {"transport_id": tid, "name": None, "type": kind,
            "kernel_drops": drops, "frames_recv": recv}


def drops_snapshot(*per_node: list[dict]) -> dict:
    """A final congestion snapshot with these transports at n01, n02, ..."""
    return {f"n{i + 1:02d}": {"congestion": {}, "kernel_drops": entries}
            for i, entries in enumerate(per_node)}


KD = S.MaxKernelDropsAssertion(max_pct=1.0, min_nodes=2)


@case("max_kernel_drops fails a cable socket that dropped 5% of its frames", False)
def _():
    # The shape of the unforced 416 KB socket under uncapped iperf3 traffic.
    snap = drops_snapshot([drops_entry(50_000, 950_000)], [drops_entry(0, 900_000)])
    return A.evaluate_max_kernel_drops(KD, snap)


@case("max_kernel_drops passes a cable socket that dropped 0.1% of its frames", True)
def _():
    snap = drops_snapshot([drops_entry(1_220, 1_000_000)], [drops_entry(0, 900_000)])
    return A.evaluate_max_kernel_drops(KD, snap)


@case("max_kernel_drops fails an Ethernet transport that reports no drop count", False)
def _():
    # What a build without the counter reports: null, which is not zero.
    snap = drops_snapshot([drops_entry(None, 950_000)], [drops_entry(0, 900_000)])
    return A.evaluate_max_kernel_drops(KD, snap)


@case("max_kernel_drops reads only Ethernet transports", True)
def _():
    udp = drops_entry(11_073, None, kind="udp", tid=1)
    snap = drops_snapshot([udp, drops_entry(0, 950_000)], [udp, drops_entry(0, 900_000)])
    return A.evaluate_max_kernel_drops(KD, snap)


@case("max_kernel_drops fails when fewer nodes than min_nodes report a count", False)
def _():
    snap = drops_snapshot([drops_entry(0, 950_000)],
                          [drops_entry(0, None, kind="udp", tid=1)])
    return A.evaluate_max_kernel_drops(KD, snap)


@case("max_kernel_drops fails a run with no final snapshot", False)
def _():
    return A.evaluate_max_kernel_drops(KD, None)


@case("validation refuses a max_kernel_drops ceiling of 100%", False)
def _():
    try:
        S._parse_max_kernel_drops({"max_pct": 100})
    except ValueError:
        return False
    return True


@case("validation accepts a max_kernel_drops ceiling of 1%", True)
def _():
    cfg = S._parse_max_kernel_drops({"max_pct": 1, "min_nodes": 2})
    return cfg.max_pct == 1.0 and cfg.min_nodes == 2


# --- max_replay_refusals -----------------------------------------------------

def refusals_snapshot(*per_node: list) -> dict:
    """A final congestion snapshot with these peer totals at n01, n02, ..."""
    return {f"n{i + 1:02d}": {"congestion": {}, "replay_refusals": [
        {"peer": "other", "total": total} for total in totals
    ]} for i, totals in enumerate(per_node)}


RR = S.MaxReplayRefusalsAssertion(max_total=0, min_nodes=2)


@case("max_replay_refusals fails a node that refused a replay", False)
def _():
    # The shape of the base's bulk run: refusals at the receiver alone.
    return A.evaluate_max_replay_refusals(RR, refusals_snapshot([0], [6]))


@case("max_replay_refusals passes two nodes that refused nothing", True)
def _():
    return A.evaluate_max_replay_refusals(RR, refusals_snapshot([0], [0]))


@case("max_replay_refusals adds up the peers of every node", False)
def _():
    ceiling = S.MaxReplayRefusalsAssertion(max_total=2, min_nodes=2)
    return A.evaluate_max_replay_refusals(ceiling, refusals_snapshot([1, 1], [1]))


@case("max_replay_refusals fails a peer that reports no total", False)
def _():
    # What a build without the field reports: null, which is not zero.
    return A.evaluate_max_replay_refusals(RR, refusals_snapshot([None], [0]))


@case("max_replay_refusals fails when fewer nodes than min_nodes report a count", False)
def _():
    return A.evaluate_max_replay_refusals(RR, refusals_snapshot([0], []))


@case("max_replay_refusals fails a snapshot taken without the peer query", False)
def _():
    snap = {"n01": {"congestion": {}}, "n02": {"congestion": {}}}
    return A.evaluate_max_replay_refusals(RR, snap)


@case("max_replay_refusals fails a run with no final snapshot", False)
def _():
    return A.evaluate_max_replay_refusals(RR, None)


@case("validation refuses a negative max_replay_refusals ceiling", False)
def _():
    try:
        S._parse_max_replay_refusals({"max_total": -1})
    except ValueError:
        return False
    return True


@case("validation accepts a max_replay_refusals ceiling of zero", True)
def _():
    cfg = S._parse_max_replay_refusals({"max_total": 0, "min_nodes": 2})
    return cfg.max_total == 0 and cfg.min_nodes == 2


# --- validation --------------------------------------------------------------

def _load(rust_log: str, assertion: str) -> None:
    """Validate a minimal scenario carrying one path assertion."""
    s = S.Scenario()
    s.topology.num_nodes = 2
    s.topology.algorithm = "explicit"
    s.topology.params = {"adjacency": [["n01", "n02", "ethernet+udp"]]}
    s.logging.rust_log = rust_log
    if assertion == "paths_live":
        s.assertions.paths_live = S.PathsLiveAssertion()
    else:
        s.assertions.max_dials = S.MaxDialsAssertion()
    S._validate(s)


@case("validation refuses rust_log info with a path-line assertion", False)
def _():
    try:
        _load("info", "paths_live")
    except ValueError:
        return False
    return True


@case("validation accepts the path handler at debug with a path-line assertion", True)
def _():
    _load("info,fips::node::handlers::path=debug", "paths_live")
    return True


@case("validation refuses max_dials without the lifecycle target at debug", False)
def _():
    try:
        _load("info,fips::node::handlers::path=debug", "max_dials")
    except ValueError:
        return False
    return True


@case("validation accepts a wider debug directive for max_dials", True)
def _():
    _load("info,fips::node=debug", "max_dials")
    return True


# --- path floor and discovery limit ------------------------------------------

def sent(t: float, msg_type: int = 82, length: int = 60, addr: str = "10.222.0.2:2122") -> str:
    """A "Path message sent" line at ``t``."""
    return (
        f"{stamp(t)} DEBUG fips::node::handlers::path: Path message sent "
        f"peer=npub17cx8...wz28 transport_id=transport:2 remote_addr={addr} "
        f"msg_type={msg_type} len={length}"
    )


def _stopped(offsets: list[float], end_why: str | None = "Answered",
             frm: str = "Some(Suspect)") -> list[str]:
    """Path 9 created, Live, then Dead at T0 (from ``frm``) and probed at
    T0 + each cumulative offset; ended 0.5 s after the last probe by
    ``end_why`` (None: never ended)."""
    lines = [
        state(T0 - 30, 9, "None", "Some(Probing)", "Found"),
        state(T0 - 29, 9, "Some(Probing)", "Some(Live)", "Answered"),
    ]
    if frm == "Some(Suspect)":
        lines += [sent(T0 - 3.2), sent(T0 - 2.2), sent(T0 - 1.2)]
        lines.append(state(T0 - 1, 9, "Some(Live)", "Some(Suspect)", "Timeout"))
    lines.append(state(T0, 9, frm, "Some(Dead)", "Timeout" if frm != "Some(Live)" else "Closed"))
    t = T0
    for off in offsets:
        t += off
        lines.append(sent(t))
    if end_why == "Returned":
        lines.append(state(t + 0.5, 9, "Some(Dead)", "Some(Probing)", "Returned"))
    elif end_why is not None:
        lines.append(state(t + 0.5, 9, "Some(Dead)", "Some(Live)", end_why))
    return lines


def _floor(lines: list[str], min_stops: int = 1):
    """path_floor over one node's planted lines."""
    r = logs(**{N1: lines})
    return A.evaluate_path_floor(S.PathFloorAssertion(min_stops=min_stops), r.path_lines)


@case("one planted Path message sent with msg_type=82 adds one probe and its len", True)
def _():
    from sim import paths as P

    lines = _stopped([1.0, 1.0])
    base = P.stops(P.timelines(logs(**{N1: lines}).path_lines)[N1]["npub17cx8...wz28"])
    more = lines[:-1] + [sent(T0 + 2.2, length=77)] + lines[-1:]
    grown = P.stops(P.timelines(logs(**{N1: more}).path_lines)[N1]["npub17cx8...wz28"])
    return (
        len(grown[0].probes) == len(base[0].probes) + 1
        and grown[0].bytes == base[0].bytes + 77
    )


@case("path_floor passes a stop with gaps 1, 1, 2, 4 s", True)
def _():
    return _floor(_stopped([1, 1, 2, 4]))


@case("path_floor fails a stop with gaps 1, 1, 1 s (the standby cadence)", False)
def _():
    return _floor(_stopped([1, 1, 1]))


@case("path_floor fails 1, 1, 2, 2 s (doubling the smallest gap seen would pass it)", False)
def _():
    return _floor(_stopped([1, 1, 2, 2]))


@case("path_floor passes a gap a fifth of the stamp allowance short (1, 1, 1.990)", True)
def _():
    return _floor(_stopped([1, 1, 1.990]))


@case("path_floor fails a gap twice the stamp allowance short (1, 1, 1.900)", False)
def _():
    return _floor(_stopped([1, 1, 1.900]))


@case("path_floor fails a run in which no path stopped", False)
def _():
    return _floor(_second(11))


@case("a stop ended by why=Returned stays open", True)
def _():
    from sim import paths as P

    lines = _stopped([1, 1, 2], end_why="Returned") + [sent(T0 + 4.5), sent(T0 + 8.5)]
    st = P.stops(P.timelines(logs(**{N1: lines}).path_lines)[N1]["npub17cx8...wz28"])
    return len(st) == 1 and st[0].end is None and len(st[0].probes) == 5


@case("path_floor holds the probes after a Returned to the floor", False)
def _():
    lines = _stopped([1, 1, 2], end_why="Returned") + [sent(T0 + 4.6), sent(T0 + 5.6)]
    return _floor(lines)


@case("path_floor checks a 660 s outage whose stop began at a Dead entry (long run)", True)
def _():
    # The far end of the long run: Dead at once on the peer's close, then
    # the floor's own cadence to the grace: 1, 2, 4, 8, 16, 32, then 30 s.
    offs = [1, 1, 2, 4, 8, 16] + [30] * 19
    return _floor(_stopped(offs, end_why="Answered", frm="Some(Live)"))


@case("path_floor refuses a stop whose Dead entry came over 60 s after its first unanswered probe", False)
def _():
    lines = [
        state(T0 - 100, 9, "None", "Some(Probing)", "Found"),
        state(T0 - 99, 9, "Some(Probing)", "Some(Live)", "Answered"),
        sent(T0 - 70), sent(T0 - 69.8), sent(T0 - 69.6),
        state(T0 - 69, 9, "Some(Live)", "Some(Suspect)", "Timeout"),
        state(T0, 9, "Some(Suspect)", "Some(Dead)", "Timeout"),
        sent(T0 + 1), sent(T0 + 2), sent(T0 + 4),
        state(T0 + 5, 9, "Some(Dead)", "Some(Live)", "Answered"),
    ]
    return _floor(lines)


def _ackprobe(at: float, lag: float) -> list[str]:
    """A stop probed at 1, 1, 2 s, then an ack and ``lag`` later a probe at
    ``at`` s into the stop, ended 0.5 s later."""
    lines = _stopped([1, 1, 2], end_why=None)
    lines += [sent(T0 + at, msg_type=83), sent(T0 + at + lag)]
    lines.append(state(T0 + at + lag + 0.5, 9, "Some(Dead)", "Some(Live)", "Answered"))
    return lines


@case("path_floor exempts the probe sent with an answer (the peer cleared ACTIVE)", True)
def _():
    return _floor(_ackprobe(5.0, 0.00003))


@case("path_floor holds a probe sent 10 ms after an answer", False)
def _():
    return _floor(_ackprobe(5.0, 0.010))


@case("path_floor exempts one probe per stop, not a second sent with an answer", False)
def _():
    lines = _ackprobe(5.0, 0.00003)[:-1]
    lines += [sent(T0 + 5.5, msg_type=83), sent(T0 + 5.50003)]
    lines.append(state(T0 + 6, 9, "Some(Dead)", "Some(Live)", "Answered"))
    return _floor(lines)


def received(t: float, msg_type: int = 83, length: int = 27,
             addr: str = "10.222.0.2:2122") -> str:
    """A "Path message received" line at ``t``: by default an answer of
    the smallest size, as a Live path's probes get."""
    return (
        f"{stamp(t)} DEBUG fips::node::handlers::path: Path message received "
        f"peer=npub17cx8...wz28 transport_id=transport:2 remote_addr={addr} "
        f"msg_type={msg_type} len={length}"
    )


VETH = "10.222.0.2:2122"


def _carrier(before: list[str], dead: list[str], n: int, first: float = 1.0,
             end: bool = True) -> list[str]:
    """Path 9 created and Live, made the active path by a switch at
    T0 - 28, then ``before`` (its lines before the stop) and ``dead`` (its
    Dead entry at T0), then ``n`` probes, the first ``first`` s after the
    stop and each later one 1 s after the last; answered 0.5 s after the
    last probe unless not ``end``."""
    lines = [
        state(T0 - 30, 9, "None", "Some(Probing)", "Found"),
        state(T0 - 29, 9, "Some(Probing)", "Some(Live)", "Answered"),
        switched(T0 - 28, "discretionary", to=VETH, transport="transport:2"),
    ] + before + dead
    t = T0 + first
    for _ in range(n):
        lines.append(sent(t, length=27))
        t += 1
    if end:
        lines.append(state(t - 0.5, 9, "Some(Dead)", "Some(Live)", "Answered"))
    return lines


def _closed(n: int, first: float = 1.0) -> list[str]:
    """A carried stop from Live on the peer's close at T0, no probe
    outstanding, so the re-check runs to T0 + 30 s; ``n`` probes at 1 s."""
    return _carrier([], [state(T0, 9, "Some(Live)", "Some(Dead)", "Closed")], n, first)


# The silence clock before a carried stop: an answer at T0 - 4.2 to the
# probe before it, then four probes of the smallest size, the first
# T0 - 4.0, and Suspect at T0 - 3.2 with the fourth still in flight, so
# the node's clock starts at T0 - 4.0 (the re-check runs to T0 + 26.0)
# where the three probes last sent before Suspect would place it at
# T0 - 3.75.
QUIET = [
    sent(T0 - 4.25, length=27), received(T0 - 4.2),
    sent(T0 - 4.0, length=27), sent(T0 - 3.75, length=27),
    sent(T0 - 3.5, length=27), sent(T0 - 3.25, length=27),
    state(T0 - 3.2, 9, "Some(Live)", "Some(Suspect)", "Timeout"),
]
QUIET_DEAD = [state(T0, 9, "Some(Suspect)", "Some(Dead)", "Timeout")]


@case("path_floor passes a carried stop probed at 1 s inside the re-check span", True)
def _():
    return _floor(_closed(20))


@case("path_floor passes a carried stop at 1 s to the span's end plus the one 1 s gap after it (32 probes)", True)
def _():
    return _floor(_closed(32))


@case("path_floor fails a carried stop still at 1 s past the span plus that gap (33 probes)", False)
def _():
    return _floor(_closed(33))


@case("path_floor counts a probe within the stamp allowance of the span's end inside it (first 1.04 s, 32 probes)", True)
def _():
    return _floor(_closed(32, first=1.04))


@case("path_floor counts a probe past the span's end by more than the allowance outside it (first 1.06 s, 32 probes)", False)
def _():
    return _floor(_closed(32, first=1.06))


@case("path_floor starts the re-check at the first probe since the latest answer (27 probes at 1 s from 1.1 s pass)", True)
def _():
    return _floor(_carrier(QUIET, QUIET_DEAD, 27, first=1.1))


@case("path_floor starts the re-check at the first probe since the latest answer, not three before Suspect (28 probes fail)", False)
def _():
    return _floor(_carrier(QUIET, QUIET_DEAD, 28, first=1.1))


@case("path_floor restarts the silence clock at an answer (28 probes at 1 s from 1.02 s pass)", True)
def _():
    return _floor(_carrier(QUIET, QUIET_DEAD, 28, first=1.02))


@case("path_floor does not start the silence clock at an MTU search probe on the Live path (28 probes from 1.02 s pass)", True)
def _():
    before = QUIET[:2] + [sent(T0 - 4.1, length=1436)] + QUIET[2:]
    return _floor(_carrier(before, QUIET_DEAD, 28, first=1.02))


@case("path_floor fails an uncarried stop at 1, 1, 1 s: the link left the path before it left Live", False)
def _():
    lines = _carrier([switched(T0 - 20, to=BRIDGE)], [], 0, end=False)
    lines += [
        state(T0 - 1, 9, "Some(Live)", "Some(Suspect)", "Timeout"),
        state(T0, 9, "Some(Suspect)", "Some(Dead)", "Timeout"),
        sent(T0 + 1), sent(T0 + 2), sent(T0 + 3),
        state(T0 + 3.5, 9, "Some(Dead)", "Some(Live)", "Answered"),
    ]
    return _floor(lines)


def _twostops(switch_away: bool) -> list[str]:
    """A carried stop at T0 probed at 1, 1 s, revived by the peer's probe
    at T0 + 2.5 and probed in Probing, then Dead again at T0 + 4 with no
    Live between, probed every 1 s six times; with ``switch_away`` the
    link has moved to the bridge before the second Dead entry."""
    lines = _closed(2)[:-1]
    lines += [
        state(T0 + 2.5, 9, "Some(Dead)", "Some(Probing)", "Probed"),
        sent(T0 + 2.6), sent(T0 + 2.8),
    ]
    if switch_away:
        lines.append(switched(T0 + 3.0, to=BRIDGE))
    lines.append(state(T0 + 4.0, 9, "Some(Probing)", "Some(Dead)", "Timeout"))
    lines += [sent(T0 + 4.0 + k) for k in range(1, 7)]
    lines.append(state(T0 + 11.5, 9, "Some(Dead)", "Some(Live)", "Answered"))
    return lines


@case("path_floor fails a second stop in one Live departure at 1 s: the re-check is taken once", False)
def _():
    return _floor(_twostops(switch_away=True))


@case("path_floor re-checks a second stop again when the path is active at its own Dead entry", True)
def _():
    return _floor(_twostops(switch_away=False))


@case("a capture's tcpdump lines parse into frames with their sources", True)
def _():
    from sim.capture import parse

    text = (
        "1793661476.700001 42:78:29:a1:1e:88 > 36:d4:70:e5:dc:31, ethertype Unknown "
        "(0x2121), length 1475: \n"
        "        0x0000:  0102 0304\n"
        "1793661476.800002 aa:bb:cc:dd:ee:01 > aa:bb:cc:dd:ee:02, ethertype IPv4 (0x0800), "
        "length 102: 10.222.0.2.2122 > 10.222.0.1.2122: UDP, length 60\n"
    )
    f = parse(text)
    return (
        len(f) == 2
        and f[0]["src"] == "42:78:29:a1:1e:88" and f[0]["len"] == 1475 and "ip_src" not in f[0]
        and f[1]["ip_src"] == "10.222.0.2.2122" and f[1]["t"] == 1793661476.800002
    )


BRIDGE = "10.30.2.11:2121"


def bridge(t: float, frm: str, nxt: str, why: str = "Timeout") -> str:
    """A state line of the link's original path (1, the bridge), which
    logs nothing until its first change."""
    return state(t, 1, frm, nxt, why, addr=BRIDGE, transport="transport:1")


def moved(t: float, frm: str, to: str) -> str:
    """A "Path moved to a new address" line at ``t``."""
    return (
        f"{stamp(t)} DEBUG fips::node::handlers::path: Path moved to a new address "
        f"peer=npub17cx8...wz28 from={frm} to={to} transport_id=transport:2"
    )


def _atonce(other_next: str, third_live: bool) -> list[str]:
    """A stop probed at 1, 1, 2 s, then at 5 s the active path (7, made
    active when the original went Suspect) leaves Live for ``other_next``
    and the stopped path is probed at once; with ``third_live`` a third
    path (8) is Live at the time."""
    lines = [
        state(T0 - 40, 7, "None", "Some(Probing)", "Found", addr="10.30.0.11:2121"),
        state(T0 - 39, 7, "Some(Probing)", "Some(Live)", "Answered", addr="10.30.0.11:2121"),
        bridge(T0 - 38.5, "Some(Live)", "Some(Suspect)"),
        switched(T0 - 38.49, to="10.30.0.11:2121", transport="transport:2"),
    ]
    if third_live:
        lines += [
            state(T0 - 38, 8, "None", "Some(Probing)", "Found", addr="10.40.0.11:2121"),
            state(T0 - 37, 8, "Some(Probing)", "Some(Live)", "Answered", addr="10.40.0.11:2121"),
        ]
    lines += _stopped([1, 1, 2], end_why=None)
    lines += [
        state(T0 + 5, 7, "Some(Live)", other_next, "Timeout", addr="10.30.0.11:2121"),
        sent(T0 + 5.00008),
        state(T0 + 6, 9, "Some(Dead)", "Some(Live)", "Answered"),
    ]
    return lines


@case("path_floor exempts the at-once probe when the active path fails with nothing Live", True)
def _():
    return _floor(_atonce("Some(Suspect)", third_live=False))


def _cabledies(active: bool, gone: str | None = None) -> list[str]:
    """Path 9 (the cable) created and Live, made active by a discretionary
    switch when ``active``; the original (the bridge) Suspect at T0 - 3;
    the cable Suspect on a carrier loss at T0 - 0.04 and Dead on the
    peer's close at T0, probed 60 us later and then at 1, 2 and 4 s. With
    ``gone``, the cable moved to that address at T0 - 2 first."""
    addr = gone or "10.222.0.2:2122"
    lines = [
        state(T0 - 60, 9, "None", "Some(Probing)", "Found"),
        state(T0 - 59, 9, "Some(Probing)", "Some(Live)", "Answered"),
    ]
    if active:
        lines.append(switched(T0 - 58, "discretionary", to="10.222.0.2:2122",
                              transport="transport:2"))
    lines.append(bridge(T0 - 3, "Some(Live)", "Some(Suspect)"))
    if gone:
        lines.append(moved(T0 - 2, "10.222.0.2:2122", gone))
    lines += [
        state(T0 - 0.04, 9, "Some(Live)", "Some(Suspect)", "Carrier", addr=addr),
        state(T0, 9, "Some(Suspect)", "Some(Dead)", "Closed", addr=addr),
        sent(T0 + 0.00006, addr=addr),
        sent(T0 + 1, addr=addr), sent(T0 + 2, addr=addr), sent(T0 + 4, addr=addr),
        state(T0 + 5, 9, "Some(Dead)", "Some(Live)", "Answered", addr=addr),
    ]
    return lines


@case("path_floor exempts the at-once probe on the active path going Dead with nothing Live", True)
def _():
    return _floor(_cabledies(active=True))


@case("path_floor follows the active path to a new address", True)
def _():
    return _floor(_cabledies(active=True, gone="10.222.0.3:2122"))


@case("path_floor holds a probe at a Dead entry of a path that was not the active one", False)
def _():
    return _floor(_cabledies(active=False))


@case("path_floor takes no prompt from a state line that changes nothing", False)
def _():
    lines = _atonce("Some(Suspect)", third_live=False)
    at = lines.index(state(T0 + 5, 7, "Some(Live)", "Some(Suspect)", "Timeout",
                           addr="10.30.0.11:2121"))
    lines[at:at + 1] = [
        state(T0 + 4.5, 7, "Some(Live)", "Some(Suspect)", "Timeout", addr="10.30.0.11:2121"),
        state(T0 + 5, 7, "Some(Suspect)", "Some(Suspect)", "Timeout", addr="10.30.0.11:2121"),
    ]
    return _floor(lines)


@case("path_floor holds a probe beside another path's failure while a third is Live", False)
def _():
    return _floor(_atonce("Some(Suspect)", third_live=True))


def _deadbeside(original: list[str], switch: bool) -> list[str]:
    """Path 9 Live, then Suspect on a carrier loss, then Dead on the peer's
    close at T0 and probed 1 ms later, then at 1, 2 and 4 s, while the
    original (the bridge) is Live: after ``original``'s lines, and, with
    ``switch``, the mandatory switch to it on path 9's Suspect entry."""
    lines = [
        state(T0 - 30, 9, "None", "Some(Probing)", "Found"),
        state(T0 - 29, 9, "Some(Probing)", "Some(Live)", "Answered"),
    ]
    if switch:
        lines.append(switched(T0 - 28, "discretionary", to="10.222.0.2:2122",
                              transport="transport:2"))
    lines += original
    lines.append(state(T0 - 0.04, 9, "Some(Live)", "Some(Suspect)", "Carrier"))
    if switch:
        lines.append(switched(T0 - 0.03996, to=BRIDGE))
    lines += [
        state(T0, 9, "Some(Suspect)", "Some(Dead)", "Closed"),
        sent(T0 + 0.001), sent(T0 + 1.001), sent(T0 + 3.001), sent(T0 + 7.001),
        state(T0 + 8, 9, "Some(Dead)", "Some(Live)", "Answered"),
    ]
    return lines


@case("path_floor holds a probe at a Dead entry while the original is Live and unlogged", False)
def _():
    return _floor(_deadbeside([], switch=False))


@case("path_floor holds it after a mandatory switch to the unlogged original", False)
def _():
    return _floor(_deadbeside([], switch=True))


@case("path_floor holds it when the failing path was active and the original is Live, unlogged", False)
def _():
    return _floor([
        state(T0 - 30, 9, "None", "Some(Probing)", "Found"),
        state(T0 - 29, 9, "Some(Probing)", "Some(Live)", "Answered"),
        switched(T0 - 28, "discretionary", to="10.222.0.2:2122", transport="transport:2"),
        state(T0, 9, "Some(Live)", "Some(Dead)", "Closed"),
        switched(T0 + 0.00004, to=BRIDGE),
        sent(T0 + 0.001), sent(T0 + 1.001), sent(T0 + 3.001), sent(T0 + 7.001),
        state(T0 + 8, 9, "Some(Dead)", "Some(Live)", "Answered"),
    ])


@case("path_floor holds it while the original is Live by its own line", False)
def _():
    return _floor(_deadbeside(
        [bridge(T0 - 20, "Some(Live)", "Some(Suspect)"),
         bridge(T0 - 19, "Some(Suspect)", "Some(Live)", "Answered")],
        switch=False,
    ))


def _renewtimeline():
    """n01's timeline of a renewal at T0 that keeps a Probing candidate's
    pair, after a switch to the original's pair: the original (1), Suspect
    with nothing Live at T0 - 3, and the candidate (2) end, and 3 begins
    Live at the candidate's pair, then goes Suspect at T0 + 5."""
    from sim import paths as P

    lines = [
        state(T0 - 10, 2, "None", "Some(Probing)", "Candidate"),
        switched(T0 - 5, "discretionary", to=BRIDGE, transport="transport:1"),
        bridge(T0 - 3, "Some(Live)", "Some(Suspect)"),
        bridge(T0, "Some(Suspect)", "None", "Renewed"),
        state(T0, 2, "Some(Probing)", "None", "Renewed"),
        state(T0 + 0.00002, 3, "None", "Some(Live)", "Renewed"),
        state(T0 + 5, 3, "Some(Live)", "Some(Suspect)", "Timeout"),
    ]
    return P.timelines(logs(**{N1: lines}).path_lines)[N1]["npub17cx8...wz28"]


@case("a renewal's new path is the link's original from then on, active until a switch", True)
def _():
    tl = _renewtimeline()
    return tl.original == "3" and all(c.active for c in tl.changes if c.path_id == "3")


@case("a renewal ending the old link's paths is no failure; the old and new originals' are", True)
def _():
    from sim import paths as P

    return P._failures(_renewtimeline()) == [(T0 - 3, "1"), (T0 + 5, "3")]


@case("path_floor exempts the at-once probe when a renewed link's original fails with nothing Live", True)
def _():
    return _floor([
        bridge(T0 - 60, "Some(Live)", "None", "Renewed"),
        state(T0 - 59.99998, 3, "None", "Some(Live)", "Renewed", addr="10.30.0.11:2121"),
        state(T0 - 30, 9, "None", "Some(Probing)", "Candidate"),
        state(T0 - 29, 9, "Some(Probing)", "Some(Live)", "Answered"),
        state(T0, 9, "Some(Live)", "Some(Dead)", "Closed"),
        sent(T0 + 1), sent(T0 + 2),
        state(T0 + 3, 3, "Some(Live)", "Some(Dead)", "Closed", addr="10.30.0.11:2121"),
        sent(T0 + 3.00006), sent(T0 + 4),
        state(T0 + 5, 9, "Some(Dead)", "Some(Live)", "Answered"),
    ])


def _episode(n: int) -> list[str]:
    """A path's Probing episode with ``n`` probes, then Dead."""
    lines = [state(T0, 5, "None", "Some(Probing)", "Found")]
    lines += [sent(T0 + 0.2 * (i + 1)) for i in range(n)]
    lines.append(state(T0 + 0.2 * (n + 1), 5, "Some(Probing)", "Some(Dead)", "Exhausted"))
    return lines


@case("discovery_limit fails nine probes in one Probing episode", False)
def _():
    r = logs(**{N1: _episode(9)})
    return A.evaluate_discovery_limit(S.DiscoveryLimitAssertion(), r.path_lines)


@case("discovery_limit passes eight probes in one Probing episode", True)
def _():
    r = logs(**{N1: _episode(8)})
    return A.evaluate_discovery_limit(S.DiscoveryLimitAssertion(), r.path_lines)


# --- reverse_heard -------------------------------------------------------------

ONEWAY_DOWN, ONEWAY_UP = T0, T0 + 30
REACHABLE = {"n01": "10.222.0.2 lladdr aa:bb:cc:dd:ee:02 REACHABLE",
             "n02": "10.222.0.1 lladdr aa:bb:cc:dd:ee:01 STALE"}


def _oneway(sent_at: list[float], captured_at: list[float], neigh: dict | None = None):
    """reverse_heard over one oneway step (n02's frames dropped at n01):
    n01 logs path messages to n02 at ``sent_at``, and the capture at n02
    sees n01's frames at ``captured_at``."""
    rec = {
        "mode": "oneway", "src": "n02", "end": "n01", "edge": ["n01", "n02"],
        "down": ONEWAY_DOWN, "up": ONEWAY_UP,
        "captures": {"n02": {"iface": "ve-n02-n01", "frames": [
            {"t": t, "src": "aa", "dst": "bb", "type": "0x0800", "len": 102,
             "ip_src": "10.222.0.1.2122", "ip_dst": "10.222.0.2.2122"}
            for t in captured_at
        ]}},
        "neigh": neigh if neigh is not None else REACHABLE,
    }
    r = logs(**{N1: [sent(t, addr="10.222.0.2:2122") for t in sent_at]})
    ip = {("n01", "n02"): "10.222.0.1", ("n02", "n01"): "10.222.0.2"}
    return A.evaluate_reverse_heard(
        S.ReverseHeardAssertion(), [rec], r.path_lines,
        lambda n: f"fips-node-{n}", lambda a, b: ip[(a, b)],
    )


@case("reverse_heard passes messages in the second half all seen, neighbours good", True)
def _():
    times = [T0 + 19, T0 + 27]
    return _oneway(times, [t + 0.0005 for t in times])


@case("reverse_heard fails more messages logged in the second half than captured", False)
def _():
    times = [T0 + 19, T0 + 27]
    return _oneway(times, [times[0] + 0.0005])


@case("reverse_heard fails a step with no message during it", False)
def _():
    return _oneway([T0 - 2], [T0 - 1.999])


@case("reverse_heard reaches back to the last message before an empty second half", True)
def _():
    return _oneway([T0 + 12, T0 + 14.2], [T0 + 12.001, T0 + 14.201])


@case("reverse_heard fails the reached-back message missing from the capture", False)
def _():
    return _oneway([T0 + 12, T0 + 14.2], [T0 + 12.001])


@case("reverse_heard fails a FAILED neighbour entry at either end", False)
def _():
    times = [T0 + 19, T0 + 27]
    neigh = dict(REACHABLE, n02="10.222.0.1 FAILED")
    return _oneway(times, [t + 0.0005 for t in times], neigh)


@case("reverse_heard counts a frame stamped just before the half's start", True)
def _():
    return _oneway([T0 + 15.0001], [T0 + 14.9999])


# --- rescue ---------------------------------------------------------------------

BRIDGE = "10.30.0.11:2121"


def _rescueend(lag: float, standby: str = "Some(Dead)", leave: str = "Some(Suspect)") -> list[str]:
    """One end of loaded-standby: standby path 5 on the bridge in state
    ``standby`` before the down at T0, the cable path 9 leaving Live at
    T0 + 2 ms for ``leave``, a probe on the standby ``lag`` s after that,
    and the standby Live 1.1 s after the down."""
    lines = [
        state(T0 - 60, 9, "None", "Some(Probing)", "Candidate", addr="aa:bb:cc:dd:ee:02"),
        state(T0 - 59, 9, "Some(Probing)", "Some(Live)", "Answered", addr="aa:bb:cc:dd:ee:02"),
        state(T0 - 20, 5, "Some(Live)", "Some(Suspect)", "Timeout", addr=BRIDGE),
    ]
    if standby == "Some(Dead)":
        lines.append(state(T0 - 8, 5, "Some(Suspect)", "Some(Dead)", "Retired", addr=BRIDGE))
    lines += [
        state(T0 + 0.002, 9, "Some(Live)", leave, "Carrier", addr="aa:bb:cc:dd:ee:02"),
        sent(T0 + 0.002 + lag, addr=BRIDGE),
        state(T0 + 1.1, 5, standby, "Some(Live)", "Answered", addr=BRIDGE),
    ]
    return lines


def _rescue(n01: list[str], n02: list[str]):
    """rescue over an admin down of n01's cable at T0."""
    rec = {"mode": "admin", "edge": ["n01", "n02"], "end": "n01", "down": T0, "up": T0 + 20}
    r = logs(**{N1: n01, N2: n02})
    return A.evaluate_rescue(
        S.RescueAssertion(delay_ms=500), [rec], r.path_lines,
        lambda n: f"fips-node-{n}", r.peer_drops, r.decrypt_failures,
    )


@case("rescue passes the Dead standby probed with the active path's failure at both ends", True)
def _():
    return _rescue(_rescueend(0.00005, leave="None"), _rescueend(0.00005))


@case("rescue fails a rescue probe 61 ms after the active path left Live", False)
def _():
    return _rescue(_rescueend(0.00005, leave="None"), _rescueend(0.061))


@case("rescue fails the control when the standby was Suspect, not Dead", False)
def _():
    return _rescue(_rescueend(0.00005, leave="None"),
                   _rescueend(0.00005, standby="Some(Suspect)"))


# --- lanes ----------------------------------------------------------------------

LANE_PAIRS = {("transport:1", "10.222.0.2:2122"), ("transport:1", "10.222.0.4:2122"),
              ("transport:2", "10.222.0.2:2122"), ("transport:2", "10.222.0.4:2122")}


def _lanepath(pid: int, tid: str, addr: str, t: float = 2) -> list[str]:
    """A lane path created and Live at ``(tid, addr)``."""
    line = state(T0 + t, pid, "None", "Some(Probing)", "Candidate", addr=addr)
    live = state(T0 + t + 0.1, pid, "Some(Probing)", "Some(Live)", "Answered", addr=addr)
    return [line.replace("transport:2", tid), live.replace("transport:2", tid)]


def _laneslive(paths: list[tuple[int, str, str]], before: list[str] | None = None):
    """paths_live with configured over planted lane paths at n01, after
    the lines ``before``."""
    lines = (before or []) + [l for pid, tid, addr in paths for l in _lanepath(pid, tid, addr)]
    r = logs(**{N1: lines})
    return A.evaluate_paths_live(
        S.PathsLiveAssertion(min=4, configured=True, within_secs=30), r.path_lines,
        [N1], {N1: LANE_PAIRS}, T0,
    )


@case("paths_live configured passes three created paths Live at three distinct configured pairs", True)
def _():
    return _laneslive([(1, "transport:1", "10.222.0.4:2122"), (2, "transport:2", "10.222.0.2:2122"),
                        (3, "transport:2", "10.222.0.4:2122")])


@case("paths_live configured fails two of the three at one pair", False)
def _():
    return _laneslive([(1, "transport:1", "10.222.0.4:2122"), (2, "transport:2", "10.222.0.2:2122"),
                        (3, "transport:2", "10.222.0.2:2122")])


@case("paths_live configured does not count a renewal's new original at a configured pair", False)
def _():
    lane = "10.222.0.4:2122"
    renewal = _renewed(T0 + 1, 5, 6, addr=lane) + [
        state(T0 + 3, 6, "Some(Live)", "Some(Dead)", "Closed", addr=lane),
        state(T0 + 4, 6, "Some(Dead)", "Some(Live)", "Answered", addr=lane),
    ]
    return _laneslive([(1, "transport:1", "10.222.0.4:2122"), (2, "transport:2", "10.222.0.2:2122")],
                      before=renewal)


def _lanes(frames_a: list[str], extra: list[str] | None = None):
    """The lanes assertion: the dialler n01 with lanes vl0 (.1) and vl1
    (.3), its captured frames' destinations on vl0, planted lines."""
    info = {
        N1: {"lanes": [("vl0-n01", "10.222.0.1"), ("vl1-n01", "10.222.0.3")],
             "dialler": True, "configured": LANE_PAIRS, "sentinel": "10.222.0.250:2122"},
        N2: {"lanes": [("vl0-n02", "10.222.0.2"), ("vl1-n02", "10.222.0.4")],
             "dialler": False, "configured": set(), "sentinel": "10.222.0.250:2122"},
    }
    frames = {N1: {"vl0-n01": [{"t": T0, "src": "a", "dst": "b", "type": "0x0800", "len": 90,
                                "ip_src": "10.222.0.2.2122", "ip_dst": d} for d in frames_a]}}
    lines = _lanepath(1, "transport:1", "10.222.0.4:2122") + (extra or [])
    r = logs(**{N1: lines})
    return A.evaluate_lanes(S.LanesAssertion(), r.path_lines, info, frames)


@case("lanes passes a crossed frame at the dialler and a stable configured path", True)
def _():
    return _lanes(["10.222.0.3.2122"])


@case("lanes fails a run with no frame crossed at the dialler (the control)", False)
def _():
    return _lanes(["10.222.0.1.2122"])


@case("lanes fails a planted Live line for the sentinel", False)
def _():
    sentinel = _lanepath(7, "transport:1", "10.222.0.250:2122", t=5)
    return _lanes(["10.222.0.3.2122"], sentinel)


@case("lanes fails a configured lane path that went Live and then Suspect", False)
def _():
    flap = [state(T0 + 9, 1, "Some(Live)", "Some(Suspect)", "Timeout",
                  addr="10.222.0.4:2122").replace("transport:2", "transport:1")]
    return _lanes(["10.222.0.3.2122"], flap)


# --- transport overrides -------------------------------------------------------

@case("transport_overrides reach the injected Ethernet instance and only it", True)
def _():
    import random

    import yaml
    from sim.config_gen import generate_node_config
    from sim.topology import generate_topology

    scen = _scenario(SCHEDULED)
    topo = generate_topology(scen.topology, random.Random(1), "selftest")
    out = topo.directed_outbound()
    cfg = yaml.safe_load(generate_node_config(
        topo, "n01", out["n01"], None, transport_overrides={"ethernet": {"role": "preferred"}},
    ))
    t = cfg["transports"]
    return t["ethernet"].get("role") == "preferred" and "role" not in t["udp"]


# --- both dials ------------------------------------------------------------------

# Two edges dialed from both ends, one UDP and one TCP, beside a one-way UDP
# edge, a one-way TCP edge and an Ethernet edge, which nothing dials.
BOTHDIAL = """
scenario: {name: bothdial, seed: 1, duration_secs: 60}
topology:
  algorithm: explicit
  num_nodes: 4
  params:
    adjacency:
      - [n01, n02, udp, {dial: both}]
      - [n02, n03, tcp, {dial: both}]
      - [n03, n04, udp]
      - [n01, n04, tcp]
      - [n02, n04, ethernet]
netem: {enabled: true}
"""


def _bothtopo(text: str = BOTHDIAL):
    """The topology the real loader and generator build from ``text``."""
    import random

    from sim.topology import generate_topology

    scen = _scenario(text)
    return generate_topology(scen.topology, random.Random(1), "selftest")


def _written(text: str) -> dict[str, dict[str, str]]:
    """Per node, the alias and transport of each static peer in the config
    write_configs writes for the topology of ``text``."""
    import tempfile

    import yaml
    from sim.config_gen import write_configs

    topo = _bothtopo(text)
    got = {}
    with tempfile.TemporaryDirectory() as tmp:
        write_configs(topo, tmp)
        for nid in topo.nodes:
            with open(os.path.join(tmp, f"{nid}.yaml")) as f:
                peers = yaml.safe_load(f).get("peers") or []
            got[nid] = {p["alias"]: p["addresses"][0]["transport"] for p in peers}
    return got


def _onedial(text: str) -> str:
    """``text`` with every ``{dial: both}`` removed."""
    return text.replace(", {dial: both}", "")


@case("{dial: both} puts each end in the other's peers, and every other edge keeps its dialer", True)
def _():
    both = _written(BOTHDIAL)
    base = _written(_onedial(BOTHDIAL))
    crossed = (
        both["n01"].get("n02") == "udp" and both["n02"].get("n01") == "udp"
        and both["n02"].get("n03") == "tcp" and both["n03"].get("n02") == "tcp"
    )
    pairs = {("n01", "n02"), ("n02", "n03")}

    def rest(written: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
        """Each node's peers but those across a both-dial edge."""
        return {
            nid: {p: t for p, t in peers.items() if tuple(sorted((nid, p))) not in pairs}
            for nid, peers in written.items()
        }

    others = rest(base)
    return crossed and rest(both) == others and sum(map(len, others.values())) == 2


@case("directed_outbound names both ends of a {dial: both} edge, one end of each other "
      "static edge, and neither end of an Ethernet edge", True)
def _():
    out = _bothtopo().directed_outbound()

    def dialers(a: str, b: str) -> set[str]:
        """The ends whose outbound list names the other end."""
        return {x for x, y in ((a, b), (b, a)) if y in out[x]}

    return (
        dialers("n01", "n02") == {"n01", "n02"}
        and dialers("n02", "n03") == {"n02", "n03"}
        and len(dialers("n03", "n04")) == 1
        and len(dialers("n01", "n04")) == 1
        and dialers("n02", "n04") == set()
        and all(len(peers) == len(set(peers)) for peers in out.values())
    )


@case("a scenario with {dial: both} edges loads and records exactly those edges", True)
def _():
    topo = _bothtopo()
    return topo.both_dial == {("n01", "n02"), ("n02", "n03")} and not topo.edge_lanes


def _refusesboth(edge: str) -> bool:
    """Whether BOTHDIAL with its first edge replaced by ``edge`` loads;
    False when the loader refuses it."""
    try:
        _scenario(BOTHDIAL.replace("[n01, n02, udp, {dial: both}]", edge))
    except ValueError:
        return False
    return True


for _edge in (
    "[n01, n02, ethernet, {dial: both}]",
    "[n01, n02, ethernet+udp, {dial: both}]",
    "[n01, n02, udp-veth, {dial: both}]",
    "[n01, n02, udp-veth+udp, {dial: both}]",
    "[n01, n02, udp-veth, {lanes: 2, dial: both}]",
    "[n01, n02, udp, {lanes: 2, dial: both}]",
    "[n01, n02, udp, {dial: sideways}]",
    "[n01, n02, udp, {dial: both, speed: 1}]",
    "[n01, n02, udp, {speed: 1}]",
    "[n01, n02, udp-veth, {lanes: 2, speed: 1}]",
    "[n01, n02, udp, {}]",
    "[n01, n02, udp, {lanes: 2}]",
    "[n01, n02, udp-veth, {lanes: 5}]",
):
    case(f"loading refuses {_edge}", False)(lambda e=_edge: _refusesboth(e))


@case("an edge with {lanes: 2} still loads and keeps its lanes", True)
def _():
    topo = _bothtopo(BOTHDIAL.replace("[n01, n02, udp, {dial: both}]",
                                      "[n01, n02, udp-veth, {lanes: 2}]"))
    return topo.lanes("n01", "n02") == 2 and topo.both_dial == {("n02", "n03")}


# --- both dials: the startup delay that makes them cross -----------------------


def _bothcompose(text: str) -> dict[str, list[str]]:
    """Each service's environment in the compose file the sim writes for the
    topology of ``text``."""
    import tempfile

    import yaml
    from sim.compose import generate_compose

    with tempfile.TemporaryDirectory() as out:
        with open(generate_compose(_bothtopo(text), _scenario(text), out, "selftest-net")) as f:
            doc = yaml.safe_load(f)
    return {name: svc["environment"] for name, svc in doc["services"].items()}


@case("the sim starts every daemon on the runner's word when an edge is dialed from both ends",
      True)
def _():
    env = _bothcompose(BOTHDIAL)
    return (sorted(env) == ["n01", "n02", "n03", "n04"]
            and all("FIPS_START_ON_READY=1" in e for e in env.values()))


@case("the sim lets every daemon start at once when no edge is dialed from both ends", True)
def _():
    env = _bothcompose(_onedial(BOTHDIAL))
    return (sorted(env) == ["n01", "n02", "n03", "n04"]
            and not any(v.startswith("FIPS_START_ON_READY") for e in env.values() for v in e))


class _Tc:
    """Stands in for the docker calls of sim.netem: records each command run
    in a container, and answers every container as running."""

    def __enter__(self):
        import sim.netem as N

        self.N, self.ran = N, []
        self.saved = (N.docker_exec_quiet, N.is_container_running)
        N.docker_exec_quiet = lambda c, cmd, timeout=None: self.ran.append((c, cmd)) or ""
        N.is_container_running = lambda c: True
        return self

    def __exit__(self, *exc):
        self.N.docker_exec_quiet, self.N.is_container_running = self.saved


def _heldnetem():
    """A NetemManager over BOTHDIAL's topology after its initial netem, with
    a default policy whose sampled delay is not the hold's, and the commands
    that initial netem ran."""
    import random

    import sim.netem as N

    scen = _scenario(BOTHDIAL.replace("netem: {enabled: true}",
                                      "netem: {enabled: true, default_policy: {delay_ms: [20, 30]}}"))
    nm = N.NetemManager(_bothtopo(), scen.netem, random.Random(1))
    with _Tc() as tc:
        nm.setup_initial()
    return nm, tc.ran


def _ipstates(nm) -> dict[tuple[str, str], object]:
    """Each UDP or TCP link direction's state, keyed (from node, to node)."""
    byip = {n.docker_ip: nid for nid, n in nm.topology.nodes.items()}
    return {
        (c.split("-")[2], byip[ip]): st
        for c, states in nm.states.items() for ip, st in states.items()
    }


@case("the initial netem holds both directions of each edge dialed from both ends at the "
      "startup delay, and only those", True)
def _():
    import sim.netem as N

    nm, ran = _heldnetem()
    states = _ipstates(nm)
    held = {k for k, st in states.items() if st.held_cross}
    want = {("n01", "n02"), ("n02", "n01"), ("n02", "n03"), ("n03", "n02")}
    installed = " ".join(cmd for _, cmd in ran)
    return (
        held == want
        and len(states) == 8
        and all(states[k].tc_args() == f"delay {N.CROSS_HOLD_MS}ms" for k in want)
        and all(f"handle {st.netem_handle} netem {st.tc_args()}" in installed
                for st in states.values())
        and all(st.params.delay_ms >= 20 for st in states.values())
    )


@case("ending the startup delay gives each held direction its sampled netem and touches "
      "no other", True)
def _():
    nm, _ = _heldnetem()
    states = _ipstates(nm)
    sampled = {k: st.params.to_tc_args() for k, st in states.items() if st.held_cross}
    with _Tc() as tc:
        nm.release_holds()
    got = {}
    for container, cmd in tc.ran:
        for k, st in states.items():
            if container.split("-")[2] == k[0] and f"handle {st.netem_handle} " in cmd:
                got[k] = cmd.split(" netem ", 1)[1]
    return (
        len(sampled) == 4
        and got == sampled
        and not any(st.held_cross for st in states.values())
    )


@case("a netem mutation during the startup delay waits for its end, which installs it", True)
def _():
    import sim.netem as N

    nm, _ = _heldnetem()
    st = _ipstates(nm)[("n01", "n02")]
    mutated = N.NetemParams(delay_ms=77)
    with _Tc() as during:
        nm._update_link("n01", "n02", mutated)
    held_args = st.tc_args()
    with _Tc() as after:
        nm.release_holds()
    return (
        during.ran == []
        and held_args == f"delay {N.CROSS_HOLD_MS}ms"
        and st.params == mutated
        and any(cmd.endswith("netem delay 77ms") for _, cmd in after.ran)
    )


@case("a flap holding a direction down during the startup delay holds it at a loss, and "
      "keeps it down when the delay ends", True)
def _():
    nm, _ = _heldnetem()
    st = _ipstates(nm)[("n02", "n03")]
    st.held_down = True
    during = st.tc_args()
    with _Tc() as tc:
        nm.release_holds()
    return (during == "loss 100%" and not st.held_cross
            and any(f"handle {st.netem_handle} netem loss 100%" in cmd for _, cmd in tc.ran))


@case("the runner tells every node to start when an edge is dialed from both ends, and "
      "ends the startup delay when the warmup ends", True)
def _():
    from types import SimpleNamespace

    from sim import runner as R

    r = R.SimRunner(_scenario(BOTHDIAL))
    r.topology = _bothtopo()
    told, events = [], []
    saved = R.mark_ready
    R.mark_ready = lambda topo, nid: told.append(nid)
    try:
        r._startall()
    finally:
        R.mark_ready = saved
    r.netem_mgr = SimpleNamespace(release_holds=lambda: events.append("release"))
    r._sleep = lambda secs: events.append(f"sleep {secs}")
    r._take_snapshot = lambda label: events.append(f"snapshot {label}")
    r.peer_churn_mgr = r.link_swap_mgr = None
    r._warmup()
    return sorted(told) == ["n01", "n02", "n03", "n04"] and events == [
        "sleep 10", "release", "snapshot warmup"]


@case("the runner leaves the netem alone at the warmup's end when no edge is dialed from "
      "both ends", True)
def _():
    from types import SimpleNamespace

    from sim import runner as R

    r = R.SimRunner(_scenario(_onedial(BOTHDIAL)))
    r.topology = _bothtopo(_onedial(BOTHDIAL))
    events = []
    r.netem_mgr = SimpleNamespace(release_holds=lambda: events.append("release"))
    r._sleep = lambda secs: events.append(f"sleep {secs}")
    r._take_snapshot = lambda label: events.append(f"snapshot {label}")
    r.peer_churn_mgr = r.link_swap_mgr = None
    r._warmup()
    return events == ["sleep 10", "snapshot warmup"]


def _setuporder(text: str) -> list[str]:
    """What the runner's setup does to the nodes of ``text``, in order, with
    every docker, network and file step replaced by a stand-in."""
    import logging
    import tempfile
    from types import SimpleNamespace

    from sim import runner as R

    events: list[str] = []

    class Veth:
        """Stands in for VethManager, recording its calls."""

        def __init__(self, topology):
            pass

        def setup_all(self):
            events.append("veth setup")

        def mark_ready(self, nid):
            events.append(f"veth ready {nid}")

    class Netem:
        """Stands in for NetemManager, recording its initial netem."""

        def __init__(self, *args, **kwargs):
            pass

        def setup_initial(self):
            events.append("netem initial")

    saved = {k: getattr(R, k) for k in (
        "claim_network", "write_configs", "generate_compose", "docker_compose",
        "VethManager", "NetemManager", "mark_ready")}
    run = R.subprocess.run
    image = os.environ.get("FIPS_TEST_IMAGE")
    root = logging.getLogger()
    handlers = list(root.handlers)
    R.claim_network = lambda *a, **k: "172.20.0.0/24"
    R.write_configs = lambda *a, **k: None
    R.generate_compose = lambda *a, **k: "compose.yml"
    R.docker_compose = lambda *a, **k: events.append("compose up")
    R.VethManager = Veth
    R.NetemManager = Netem
    R.mark_ready = lambda topo, nid: events.append(f"start {nid}")
    R.subprocess.run = lambda *a, **k: SimpleNamespace(returncode=0)
    os.environ["FIPS_TEST_IMAGE"] = "selftest"
    try:
        with tempfile.TemporaryDirectory() as tmp:
            r = R.SimRunner(_scenario(text))
            r.output_dir = tmp
            r._setup()
    finally:
        for k, v in saved.items():
            setattr(R, k, v)
        R.subprocess.run = run
        if image is None:
            os.environ.pop("FIPS_TEST_IMAGE", None)
        else:
            os.environ["FIPS_TEST_IMAGE"] = image
        for h in root.handlers[:]:
            if h not in handlers:
                root.removeHandler(h)
                h.close()
    # The words go out in parallel, so their order among themselves is not
    # the runner's; their place in the sequence is.
    starts = [e for e in events if e.startswith("start ")]
    if starts:
        first = events.index(starts[0])
        rest = [e for e in events if not e.startswith("start ")]
        events = rest[:first] + ["start " + ",".join(sorted(s[6:] for s in starts))] + rest[first:]
    return events


@case("setup starts every node only after the initial netem when an edge is dialed from "
      "both ends", True)
def _():
    return _setuporder(BOTHDIAL) == [
        "compose up", "veth setup", "netem initial", "start n01,n02,n03,n04",
        "veth ready n02", "veth ready n04"]


@case("setup tells only the nodes with bound interfaces when no edge is dialed from both "
      "ends", True)
def _():
    return _setuporder(_onedial(BOTHDIAL)) == [
        "compose up", "veth setup", "netem initial", "veth ready n02", "veth ready n04"]


def _entrywait(ready: str | None, word: bool) -> str:
    """The output of the entrypoint's wait_for_ethernet for a node with no
    bound interface, FIPS_START_ON_READY set to ``ready`` (unset if None),
    and the harness's word written first if ``word``. The wait's backstop is
    cut to a second, so a wait that never sees the word times out."""
    import subprocess
    import tempfile

    script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "..", "docker", "entrypoint.sh")
    with open(script) as f:
        text = f.read()
    body = text[text.index("wait_for_ethernet() {"):]
    body = body[:body.index("\n}\n") + 3]
    with tempfile.TemporaryDirectory() as tmp:
        flag = os.path.join(tmp, "ready")
        conf = os.path.join(tmp, "fips.yaml")
        with open(conf, "w") as f:
            f.write("transports:\n  udp:\n    bind_addr: 0.0.0.0:2121\n")
        if word:
            with open(flag, "w") as f:
                f.write("42\n")
        env = {k: v for k, v in os.environ.items() if k != "FIPS_START_ON_READY"}
        if ready is not None:
            env["FIPS_START_ON_READY"] = ready
        prog = (f"CONFIG={conf}\nVETH_READY={flag}\nIFACE_WAIT_SECS=1\n"
                "bootid() { echo 42; }\n" + body + "wait_for_ethernet\n")
        out = subprocess.run(["bash", "-c", prog], env=env, capture_output=True,
                             text=True, timeout=30)
    return out.stdout if out.returncode == 0 else f"exit {out.returncode}"


@case("the entrypoint of a node started on the runner's word waits for it with no "
      "interface bound", True)
def _():
    got = _entrywait("1", word=False)
    return "harness ready: none" in got and "Timed out" in got


@case("the entrypoint of a node started on the runner's word starts once the word is "
      "there", True)
def _():
    got = _entrywait("1", word=True)
    return "harness ready: none" in got and "the harness ready after" in got


@case("the entrypoint of a node with no bound interface and no start word does not wait",
      True)
def _():
    return _entrywait(None, word=False) == "" and _entrywait("0", word=False) == ""


def _loadsboth(netem: str) -> bool:
    """Whether BOTHDIAL loads with its netem line replaced by ``netem``;
    False when the loader refuses it."""
    try:
        _scenario(BOTHDIAL.replace("netem: {enabled: true}", netem))
    except ValueError:
        return False
    return True


case("loading refuses {dial: both} with netem off", False)(
    lambda: _loadsboth("netem: {enabled: false}"))
case("loading refuses {dial: both} with node churn", False)(
    lambda: _loadsboth("netem: {enabled: true}\nnode_churn: {enabled: true}"))


# --- schedule ----------------------------------------------------------------

SCHEDULED = """
scenario: {name: sched, seed: 1, duration_secs: 120}
topology:
  algorithm: explicit
  num_nodes: 2
  params: {adjacency: [[n01, n02, ethernet+udp]]}
netem: {enabled: true}
schedule:
  - {at: 75, down: [n02, n01], mode: admin, end: n02, secs: 20}
  - {at: 20, down: [n01, n02], mode: admin, end: n01, secs: 15}
  - {at: 10, load: [n01, n02], secs: 50, streams: 4, bidir: true}
  - {at: 100, down: [n01, n02], secs: 10}
"""


def _scenario(text: str):
    """Load a scenario from YAML text through the real loader."""
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(text)
    try:
        return S.load_scenario(f.name)
    finally:
        os.unlink(f.name)


@case("a schedule parses into its steps at their offsets", True)
def _():
    from sim.schedule import Step

    got = _scenario(SCHEDULED).schedule
    want = [
        Step(at=75, kind="down", secs=20, edge=("n01", "n02"), mode="admin", end="n02"),
        Step(at=20, kind="down", secs=15, edge=("n01", "n02"), mode="admin", end="n01"),
        Step(at=10, kind="load", secs=50, pair=("n01", "n02"), streams=4, bidir=True),
        Step(at=100, kind="down", secs=10, edge=("n01", "n02"), mode="netem"),
    ]
    return got == want


@case("a schedule fires its steps in time order and ends each after its secs", True)
def _():
    from sim.schedule import Schedule

    calls = []

    class Links:
        """Records the downs and restores the schedule asks for."""

        flap_events: list = []

        def scripted_down(self, edge, mode, end, secs, src=None):
            """Record a down of ``mode`` at ``end``."""
            calls.append(("down", mode, end))

        def scripted_up(self, edge, mode, end):
            """Record the restore of a down of ``mode`` at ``end``."""
            calls.append(("up", mode, end))

    sched = Schedule(
        [st for st in _scenario(SCHEDULED).schedule if st.kind == "down"],
        None, Links(), lambda n: n,
    )
    for t in (0, 19.9, 20, 34.9, 35, 75, 95, 100, 110):
        sched.tick(t)
        calls.append(("t", t))
    return calls == [
        ("t", 0), ("t", 19.9), ("down", "admin", "n01"), ("t", 20), ("t", 34.9),
        ("up", "admin", "n01"), ("t", 35), ("down", "admin", "n02"), ("t", 75),
        ("up", "admin", "n02"), ("t", 95), ("down", "netem", None), ("t", 100),
        ("up", "netem", None), ("t", 110),
    ]


@case("loading refuses an admin down on a udp-veth edge", False)
def _():
    try:
        _scenario(SCHEDULED.replace("ethernet+udp", "udp-veth+udp"))
    except ValueError:
        return False
    return True


@case("loading refuses a step that ends after the run", False)
def _():
    try:
        _scenario(SCHEDULED.replace("secs: 10}", "secs: 30}"))
    except ValueError:
        return False
    return True


def _fakedocker(tmp: str) -> dict:
    """An environment with veth-host-test's fake docker first on PATH."""
    shim = os.path.join(tmp, "docker")
    fake = os.path.join(HERE, "veth-host-test", "fake_docker.py")
    with open(shim, "w") as f:
        f.write(f'#!/bin/bash\nexec python3 "{fake}" "$@"\n')
    os.chmod(shim, 0o755)
    state = os.path.join(tmp, "state")
    os.makedirs(state)
    return {"PATH": f"{tmp}:{os.environ['PATH']}", "FAKE_DOCKER_STATE": state}


@case("an admin down whose command fails raises StepError (fake docker)", False)
def _():
    import tempfile

    from sim.links import LinkManager
    from sim.schedule import StepError
    from sim.topology import generate_topology

    scen = _scenario(SCHEDULED)
    topo = generate_topology(scen.topology, __import__("random").Random(1), "selftest")
    links = LinkManager(topo, scen.link_flaps, __import__("random").Random(1))
    with tempfile.TemporaryDirectory() as tmp:
        saved = dict(os.environ)
        os.environ.update(_fakedocker(tmp))
        try:
            links.scripted_down(("n01", "n02"), "admin", "n01", 15)
        except StepError:
            # Only a failure the fake docker saw counts: the exec must be
            # in its call log, so a real docker answering cannot pass this.
            with open(os.path.join(tmp, "state", "calls.log")) as f:
                return "ip link set dev ve-n01-n02 down" not in f.read()
        finally:
            os.environ.clear()
            os.environ.update(saved)
    return True


@case("an admin down that runs records its in-container stamp as the down", True)
def _():
    from sim import schedule as sched
    from sim.links import LinkManager
    from sim.topology import generate_topology

    scen = _scenario(SCHEDULED)
    topo = generate_topology(scen.topology, __import__("random").Random(1), "selftest")
    links = LinkManager(topo, scen.link_flaps, __import__("random").Random(1))
    ran = []
    real = sched.docker_exec
    sched.docker_exec = lambda c, cmd, timeout=30: ran.append((c, cmd)) or "1793650000.250000000\n"
    try:
        t = links.scripted_down(("n01", "n02"), "admin", "n01", 15)
    finally:
        sched.docker_exec = real
    return (
        t == 1793650000.25
        and links.flap_events == [(t, "down", "n01", "n02")]
        and ran[0][1].endswith("ip link set dev ve-n01-n02 down")
        and ran[0][0] == topo.container_name("n01")
    )


@case("a step that fails mid-run scores the run NOT SCORED", True)
def _():
    from sim import runner as R
    from sim.schedule import StepError

    r = R.SimRunner(_scenario(SCHEDULED))
    r._setup = lambda: None
    r._warmup = lambda: None
    r._teardown = lambda: None

    def loop():
        """Stand in for the simulation loop: a step's command fails."""
        raise StepError("fips-node-n01: 'ip link set dev ve-n01-n02 down' failed")

    r._simulation_loop = loop
    logging_level = R.log.level
    R.log.setLevel(100)
    try:
        r.run()
    finally:
        R.log.setLevel(logging_level)
    return r.aborted and (r.setup_abort or "").startswith(R.UNSCORED_STEP)


# --- traffic rate cap ---------------------------------------------------------

def _traffic(extra: str):
    """Load a two-node scenario whose traffic section adds ``extra``."""
    return _scenario(
        "scenario: {name: rate, seed: 1, duration_secs: 60}\n"
        "topology:\n"
        "  algorithm: explicit\n"
        "  num_nodes: 2\n"
        "  params: {adjacency: [[n01, n02, udp]]}\n"
        "traffic:\n"
        "  enabled: true\n"
        "  parallel_streams: 2\n"
        f"{extra}"
    )


def _refused(extra: str) -> bool:
    """True when the loader refuses a traffic section adding ``extra``."""
    try:
        _traffic(extra)
    except ValueError:
        return True
    return False


@case("traffic.rate_mbps caps each stream with iperf3 -b", True)
def _():
    from sim.traffic import tcp_command

    cfg = _traffic("  rate_mbps: 8\n").traffic
    cmd = tcp_command(cfg, "npub1x.fips", 12, "/tmp/r.json")
    return cfg.rate_mbps == 8 and " -P 2 -b 8M --json " in cmd


@case("without traffic.rate_mbps the client command is the uncapped one", True)
def _():
    from sim.traffic import tcp_command

    cfg = _traffic("").traffic
    return cfg.rate_mbps is None and tcp_command(cfg, "npub1x.fips", 12, "/tmp/r.json") == (
        "nohup iperf3 -c npub1x.fips -t 12 -P 2 --json --get-server-output "
        "> /tmp/r.json 2>&1 &"
    )


@case("traffic.rate_mbps of zero, below zero, a fraction or a bool is refused", True)
def _():
    return all(_refused(f"  rate_mbps: {v}\n") for v in ("0", "-8", "0.5", "true"))


@case("an unknown traffic key is still refused", True)
def _():
    return _refused("  rate_mbit: 8\n")


# --- the UDP stream beside a session ---------------------------------------------

@case("traffic.udp_mbps starts a constant-rate UDP stream to the second server", True)
def _():
    from sim.traffic import udp_command

    cfg = _traffic("  udp_mbps: 1\n").traffic
    return cfg.udp_mbps == 1 and udp_command(cfg, "npub1x.fips", 12, "/tmp/u.json") == (
        "nohup iperf3 -c npub1x.fips -p 5202 -u -b 1M -l 1000 -t 12 --json-stream "
        "--get-server-output > /tmp/u.json 2>&1 & echo $!"
    )


@case("traffic.udp_mbps of zero or a fraction is refused", True)
def _():
    return all(_refused(f"  udp_mbps: {v}\n") for v in ("0", "0.5"))


@case("validation refuses max_stall on the UDP stream without traffic.udp_mbps", True)
def _():
    return _refused("assertions: {max_stall: {max_secs: 2, stream: udp}}\n")


@case("validation refuses a max_stall stream other than tcp or udp", True)
def _():
    return _refused("  udp_mbps: 1\nassertions: {max_stall: {max_secs: 2, stream: icmp}}\n")


@case("validation accepts max_stall on the UDP stream with traffic.udp_mbps", True)
def _():
    s = _traffic("  udp_mbps: 1\nassertions: {max_stall: {max_secs: 2, stream: udp}}\n")
    return s.assertions.max_stall.stream == "udp"


def _collected(udp_text: str, killed: bool) -> list[dict]:
    """The UDP results a session leaves when its stream's file holds
    ``udp_text``, collected at its end or after the run killed it."""
    import json
    import random as rnd
    from sim import traffic as TR

    files = {"/tmp/t.json": json.dumps(iperf(5, 5)), "/tmp/u.json": udp_text}
    real = TR.docker_exec_quiet
    TR.docker_exec_quiet = lambda _c, cmd: files.get(cmd.split()[1], "")
    try:
        cfg = _traffic("  udp_mbps: 1\n").traffic
        mgr = TR.TrafficManager(None, cfg, rnd.Random(1))
        sess = TR.TrafficSession("n01", "n02", 0.0, 12, "c", "/tmp/t.json", "/tmp/u.json")
        mgr._collect_result(sess, killed=killed)
        mgr._collect_result(sess, killed=killed)
    finally:
        TR.docker_exec_quiet = real
    return mgr.udp_results


@case("a UDP stream that left no readable result is kept as unreadable", True)
def _():
    got = _collected("", killed=False)
    return len(got) == 1 and "no readable result" in got[0].get("error", "")


@case("a UDP stream killed at the end of the run is dropped, as TCP's is", True)
def _():
    return _collected("", killed=True) == []


@case("a UDP stream's result is collected once", True)
def _():
    got = _collected(_stream(5, 5), killed=False)
    return len(got) == 1 and "_meta" in got[0] and "error" not in got[0]


# --- what a UDP stream leaves, and when it is read -----------------------------

class Box:
    """One container as traffic.py's commands see it: its files, the iperf3
    clients running in it by pid, and what each client started writes."""

    def __init__(self, files=None, alive=(), writes=()):
        self.files = dict(files or {})
        self.alive = set(alive)
        self.writes = list(writes)
        self.ran: list[str] = []
        self.next_pid = 500

    def __call__(self, _container, cmd):
        """The stdout of ``cmd``, each of its parts run in turn."""
        self.ran.append(cmd)
        out = ""
        for part in cmd.split(";"):
            words = part.split()
            if not words:
                continue
            if words[0] == "cat":
                out += self.files.get(words[1], "")
            elif words[0] == "rm":
                self.files.pop(words[2], None)
            elif words[0] == "stat":
                if words[3] in self.files:
                    out += f"{len(self.files[words[3]])}\n"
            elif words[0] == "grep":
                out += "alive\n" if words[3].split("/")[2] in self.alive else ""
            elif words[0] == "kill":
                self.alive.discard(words[1])
            elif words[0] == "killall":
                self.alive.clear()
            elif words[0] == "nohup":
                self.next_pid += 1
                self.alive.add(str(self.next_pid))
                self.files[words[words.index(">") + 1]] = (
                    self.writes.pop(0) if self.writes else ""
                )
                out += f"{self.next_pid}\n"
        return out


def _stream(*rates: int, end: bool = True) -> str:
    """What a --json-stream client leaves after these seconds at the receiver,
    with ``end`` the receiver's own output and the closing event."""
    import json

    done = iperf(*rates)
    lines = [{"event": "start", "data": done["start"]}]
    lines += [{"event": "interval", "data": iv} for iv in done["intervals"]]
    if end:
        lines.append({"event": "server_output_json", "data": done["server_output_json"]})
        lines.append({"event": "end", "data": {}})
    return "".join(json.dumps(line) + "\n" for line in lines)


def _manager(box: Box, ago: float, udp_ago: float | None = None, secs: int = 20):
    """A traffic manager over ``box`` holding one session started ``ago`` s
    back, its UDP stream ``udp_ago`` back (the same by default) at /tmp/u.json
    under pid 400; returns the module, the manager and the session."""
    import random as rnd
    import time
    from sim import traffic as TR

    TR.docker_exec_quiet = box
    cfg = _traffic("  udp_mbps: 1\n").traffic
    mgr = TR.TrafficManager(None, cfg, rnd.Random(1))
    now = time.time()
    sess = TR.TrafficSession("n01", "n02", now - ago, secs, "c", "/tmp/t.json", "/tmp/u.json")
    sess.udp_pid = "400"
    sess.udp_host = "npub1x.fips"
    sess.udp_started = now - (ago if udp_ago is None else udp_ago)
    sess.udp_secs = secs
    box.alive.add("400")
    mgr.active_sessions.append(sess)
    return TR, mgr, sess


def _with_box(fn):
    """Run ``fn`` and put the real docker exec back, whatever it does."""
    from sim import traffic as TR

    real = TR.docker_exec_quiet
    try:
        return fn()
    finally:
        TR.docker_exec_quiet = real


def _unread_stream(text: str, alive: bool = False) -> dict:
    """The result a stream leaves when its file holds ``text`` at the end of
    the run, its client still running if ``alive``."""
    def run():
        box = Box({"/tmp/u.json": text, "/tmp/t.json": ""})
        _, mgr, sess = _manager(box, 30)
        if not alive:
            box.alive.discard("400")
        mgr._collect_result(sess)
        mgr.active_sessions.clear()
        mgr.stop_all()
        return mgr.udp_results[0]
    return _with_box(run)


@case("a stream that does not parse keeps its size and first bytes", True)
def _():
    got = _unread_stream('{"start": {"cut')
    meta = got["_meta"]
    return (
        meta.get("size") == 15 and meta.get("head") == '{"start": {"cut'
        and meta.get("alive") is False and "15 bytes" in got["error"]
    )


@case("the stall check's message prints what an unreadable stream left", True)
def _():
    got = _unread_stream('{"start": {"cut')
    r = A.evaluate_max_stall(
        S.MaxStallAssertion(max_secs=2, stream="udp"), [iperf(5, 5)], [got]
    )
    return not r.passed and "15 bytes" in r.detail and '{"start": {"cut' in r.detail


@case("a file that did not parse stays in the container", True)
def _():
    def run():
        box = Box({"/tmp/u.json": "not json", "/tmp/t.json": "not json either"})
        _, mgr, sess = _manager(box, 30)
        box.alive.discard("400")
        mgr._collect_result(sess)
        return set(box.files) == {"/tmp/u.json", "/tmp/t.json"}
    return _with_box(run)


@case("a file that did parse is removed", True)
def _():
    def run():
        import json
        box = Box({"/tmp/u.json": _stream(5, 5), "/tmp/t.json": json.dumps(iperf(5))})
        _, mgr, sess = _manager(box, 30)
        mgr._collect_result(sess)
        return box.files == {}
    return _with_box(run)


@case("a parse failure is logged at warning", True)
def _():
    seen: list[str] = []

    class Hold(logging.Handler):
        """Keep each record's level and text."""

        def emit(self, record):
            seen.append(f"{record.levelname} {record.getMessage()}")

    from sim import traffic as TR

    hold = Hold()
    TR.log.addHandler(hold)
    try:
        _unread_stream("not json")
    finally:
        TR.log.removeHandler(hold)
    return any(line.startswith("WARNING") and "n01" in line for line in seen)


@case("a client still running when its session expires is read before the kill", True)
def _():
    def run():
        box = Box({"/tmp/u.json": _stream(5, end=False), "/tmp/t.json": ""})
        _, mgr, sess = _manager(box, 30)
        mgr.cleanup_expired()
        waiting = mgr.active_sessions == [] and mgr.late == [sess] and mgr.udp_results == []
        box.files["/tmp/u.json"] = _stream(5, 5)
        box.alive.discard("400")
        mgr.stop_all()
        return waiting and len(mgr.udp_results) == 1 and "error" not in mgr.udp_results[0]
    return _with_box(run)


@case("stop_all reads a late stream ahead of its killall", True)
def _():
    def run():
        box = Box({"/tmp/u.json": _stream(5, end=False), "/tmp/t.json": "", "/tmp/t2.json": ""})
        TR, mgr, sess = _manager(box, 30)
        mgr.cleanup_expired()
        # A second session on the same container is what gets the killall.
        mgr.active_sessions.append(TR.TrafficSession("n01", "n02", 0.0, 20, "c", "/tmp/t2.json"))
        mgr.stop_all()
        cat = next(i for i, c in enumerate(box.ran[::-1]) if "u.json" in c)
        kill = next(i for i, c in enumerate(box.ran[::-1]) if "killall" in c)
        return cat > kill  # reversed: the read comes earlier in the run
    return _with_box(run)


@case("a late stream still running at the end is unreadable, with its evidence", True)
def _():
    got = _unread_stream(_stream(5, 5, end=False), alive=True)
    return (
        "no readable result" in got.get("error", "")
        and got["_meta"].get("alive") is True and got["_meta"].get("size", 0) > 0
    )


@case("a late stream is read once", True)
def _():
    def run():
        box = Box({"/tmp/u.json": _stream(5, end=False), "/tmp/t.json": ""})
        _, mgr, sess = _manager(box, 30)
        mgr.cleanup_expired()
        mgr.stop_all()
        mgr.stop_all()
        return len(mgr.udp_results) == 1 and mgr.late == []
    return _with_box(run)


@case("a late stream whose client node went down is not read and not held", True)
def _():
    def run():
        box = Box({"/tmp/u.json": _stream(5, end=False), "/tmp/t.json": ""})
        _, mgr, sess = _manager(box, 30)
        mgr.cleanup_expired()
        mgr.down_nodes.add(sess.client_node)
        reads = len([c for c in box.ran if "u.json" in c])
        mgr.stop_all()
        return (
            len([c for c in box.ran if "u.json" in c]) == reads
            and mgr.udp_results == [] and mgr.late == []
        )
    return _with_box(run)


@case("the UDP stream's grace counts from its own start", True)
def _():
    def run():
        box = Box({"/tmp/u.json": _stream(5, 5), "/tmp/t.json": ""})
        # The session is 6 s past its length, the stream 4 s: inside the grace.
        _, mgr, _sess = _manager(box, 26, udp_ago=24)
        mgr.cleanup_expired()
        return len(mgr.active_sessions) == 1 and mgr.udp_results == []
    return _with_box(run)


@case("a session past both graces is collected", True)
def _():
    def run():
        box = Box({"/tmp/u.json": _stream(5, 5), "/tmp/t.json": ""})
        _, mgr, _sess = _manager(box, 27, udp_ago=26)
        mgr.cleanup_expired()
        return mgr.active_sessions == [] and len(mgr.udp_results) == 1
    return _with_box(run)


# --- the stream's events ---------------------------------------------------------

@case("the receiver's seconds survive the stream parser", True)
def _():
    from sim.traffic import assemble

    got = assemble(_stream(5, 0, 5))
    return A._stall(got) == 1.0 and len(got["intervals"]) == 3 and "start" in got


@case("a sender's empty seconds read through the stream parser are no stall", True)
def _():
    import json
    from sim.traffic import assemble

    # The planted shape of the filed red: the sender wrote in bursts, the
    # receiver took bytes every second.
    done = iperf(*([450_000] * len(_WROTE)), sent=_WROTE)
    text = "".join(
        json.dumps(line) + "\n" for line in (
            [{"event": "start", "data": done["start"]}]
            + [{"event": "interval", "data": iv} for iv in done["intervals"]]
            + [{"event": "server_output_json", "data": done["server_output_json"]},
               {"event": "end", "data": {}}]
        )
    )
    return A.evaluate_max_stall(
        S.MaxStallAssertion(max_secs=2, stream="udp"), [iperf(5, 5)], [assemble(text)]
    )


@case("a cut last line does not lose the stream", True)
def _():
    from sim.traffic import assemble

    got = assemble(_stream(5, 5) + '{"event": "end", "da')
    return got is not None and A._stall(got) == 0.0


@case("a stream with no receiver's output is unreadable", True)
def _():
    from sim.traffic import assemble

    return assemble(_stream(5, 5, end=False)) is None


@case("an empty stream is unreadable", True)
def _():
    from sim.traffic import assemble

    return assemble("") is None


@case("a busy server read through the stream parser is still a collision", True)
def _():
    from sim.traffic import assemble

    got = assemble(
        '{"event":"error","data":"the server is busy running a test. try again later"}\n'
        '{"event":"end","data":{}}\n'
    )
    return A.evaluate_max_stall(
        S.MaxStallAssertion(max_secs=2, stream="udp"), [iperf(5, 5)],
        [got, iperf(5, 5)],
    )


def _stallcheck(mgr, extra=()) -> A.AssertionOutcome:
    """The stall check on ``mgr``'s streams and ``extra``, as a run calls it."""
    return A.evaluate_max_stall(
        S.MaxStallAssertion(max_secs=2, stream="udp"), [iperf(5)],
        mgr.udp_results + list(extra), mgr.restarts,
    )


def _checked(ago: float, writes=(), first: str = ""):
    """A stream ``ago`` s old whose file holds ``first`` at its check, seen
    by one cleanup; returns the box, the manager and the session."""
    box = Box({"/tmp/u.json": first, "/tmp/t.json": ""}, writes=writes)
    _, mgr, sess = _manager(box, ago)
    mgr.cleanup_expired()
    return box, mgr, sess


@case("a stream with an empty file at its check is killed and started again", True)
def _():
    def run():
        box, mgr, sess = _checked(6, writes=[_stream(5)])
        return (
            "400" not in box.alive and sess.udp_pid == "501"
            and sess.udp_file != "/tmp/u.json" and "/tmp/u.json" in box.files
            and any("-t 13 " in c or "-t 14 " in c for c in box.ran)
            and sess.udp_restarted
        )
    return _with_box(run)


@case("a stream with a start line at its check is left running", True)
def _():
    def run():
        box, _mgr, sess = _checked(6, first=_stream(5, end=False))
        return sess.udp_pid == "400" and "400" in box.alive and not sess.udp_restarted
    return _with_box(run)


@case("a stream younger than the check is not looked at", True)
def _():
    def run():
        box, _mgr, sess = _checked(3)
        return sess.udp_pid == "400" and not any(c.startswith("stat") for c in box.ran)
    return _with_box(run)


@case("a stream is checked once", True)
def _():
    def run():
        box, mgr, sess = _checked(6, first=_stream(5, end=False))
        box.files[sess.udp_file] = ""
        mgr.cleanup_expired()
        return sess.udp_pid == "400" and len([c for c in box.ran if c.startswith("stat")]) == 1
    return _with_box(run)


@case("a restarted stream that also stays empty did not start, and fails the check", True)
def _():
    def run():
        box, mgr, sess = _checked(6)
        sess.udp_started -= 6
        mgr.cleanup_expired()
        got = mgr.udp_results
        ok = (
            len(got) == 1 and "did not start" in got[0]["error"]
            and got[0]["_meta"].get("size") == 0 and got[0]["_meta"].get("alive") is True
            and got[0]["_meta"].get("restarted") is True and "501" not in box.alive
            and sess.udp_file == ""
        )
        r = _stallcheck(mgr)
        return (
            ok and not r.passed and "did not start" in r.detail
            and "1 UDP stream(s) restarted" in r.detail
        )
    return _with_box(run)


@case("a restarted stream that runs passes, and the message says it restarted", True)
def _():
    def run():
        box, mgr, sess = _checked(6, writes=[_stream(5, 5)])
        sess.started_at -= 30
        sess.udp_started -= 30
        box.alive.discard(sess.udp_pid)
        mgr.cleanup_expired()
        got = mgr.udp_results
        r = _stallcheck(mgr)
        return (
            r.passed and "1 UDP stream(s) restarted" in r.detail
            and got[0]["_meta"].get("restarted") is True
        )
    return _with_box(run)


@case("a restarted stream the run kills at its end is counted, and stays unmeasured", True)
def _():
    def run():
        _, mgr, _sess = _checked(6, writes=[_stream(5, end=False)])
        mgr.stop_all()
        mgr.collect_results()
        r = _stallcheck(mgr, [iperf(5, 5)])
        return (
            mgr.udp_results == [] and r.passed
            and "1 UDP stream(s) restarted" in r.detail and "across 1 UDP" in r.detail
        )
    return _with_box(run)


@case("a run whose only stream restarted and was killed still counts the restart", True)
def _():
    def run():
        _, mgr, _sess = _checked(6, writes=[_stream(5, end=False)])
        mgr.stop_all()
        r = _stallcheck(mgr)
        return not r.passed and "1 UDP stream(s) restarted" in r.detail
    return _with_box(run)


@case("a restarted stream whose client node went down is counted", True)
def _():
    def run():
        _, mgr, sess = _checked(6, writes=[_stream(5, 5)])
        mgr.down_nodes.add(sess.client_node)
        mgr.stop_all()
        return mgr.udp_results == [] and "1 UDP stream(s) restarted" in _stallcheck(mgr).detail
    return _with_box(run)


@case("each restarted stream is counted once", True)
def _():
    def run():
        box, mgr, sess = _checked(6)
        sess.udp_started -= 6
        mgr.cleanup_expired()
        mgr.cleanup_expired()
        return mgr.restarts == 1 and "2 UDP" not in _stallcheck(mgr).detail
    return _with_box(run)


@case("a run hands its restart count to the stall check", True)
def _():
    from types import SimpleNamespace as NS
    from sim import runner as R

    r = R.SimRunner(_traffic(
        "  udp_mbps: 1\nassertions:\n  max_stall: {max_secs: 2, stream: udp}\n"
    ))
    r.topology = NS(nodes={}, container_name=lambda n: n)
    r._downs = lambda: []
    r.traffic_mgr = NS(restarts=1)
    r._evaluatepaths(logs(), [iperf(5)], [iperf(5, 5)])
    return any("1 UDP stream(s) restarted" in o.detail for o in r.assertion_outcomes)


@case("a stream whose client node is down is not checked", True)
def _():
    def run():
        box = Box({"/tmp/u.json": "", "/tmp/t.json": ""})
        _, mgr, sess = _manager(box, 6)
        mgr.down_nodes.add(sess.client_node)
        mgr.cleanup_expired()
        return not sess.udp_restarted and not any(c.startswith("stat") for c in box.ran)
    return _with_box(run)


@case("no restart, no restart in the message", True)
def _():
    r = A.evaluate_max_stall(
        S.MaxStallAssertion(max_secs=2, stream="udp"), [iperf(5)], [iperf(5, 5)]
    )
    return r.passed and "restarted" not in r.detail


@case("a stream the run killed is dropped whatever its file holds", True)
def _():
    def run():
        box = Box({"/tmp/u.json": _stream(5, 5, end=False)
                   + '{"event":"error","data":"interrupt - the client has terminated"}\n'
                   + '{"event":"end","data":{}}\n', "/tmp/t.json": ""})
        _, mgr, _sess = _manager(box, 10)
        mgr.stop_all()
        return mgr.udp_results == []
    return _with_box(run)


# --- active_timeouts -------------------------------------------------------------

def waited(t: float, ms: int) -> str:
    """A "Task wait" line at ``t``."""
    return (
        f"{stamp(t)} DEBUG fips::node::dataplane::wait: Task wait worst_ms={ms}"
    )


def _timeouts(n1=(), n2=(), downs=()):
    """The report on planted lines, for a pair and the given downs."""
    result = logs(**{N1: list(n1), N2: list(n2)})
    return A.evaluate_active_timeouts(
        S.ActiveTimeoutsAssertion(), result.path_lines, list(downs), result.task_waits,
        [N1, N2],
    )


# The active path's own timeout, 2 s after the run began.
_HIT = state(T0 + 2, 1, "Some(Live)", "Some(Suspect)", why="Timeout")


@case("a timeout on the active path between flaps is reported", True)
def _():
    r = _timeouts(n1=[_HIT], downs=[(T0 + 50, N1, N2)])
    return r.passed and "1 outside a flap" in r.detail and "n01" in r.detail


@case("the report does not fail a run", True)
def _():
    return _timeouts(n1=[_HIT] * 2)


@case("a timeout inside the K bound after a down is not a hit", True)
def _():
    r = _timeouts(n1=[_HIT], downs=[(T0 + 1, N1, N2)])
    return "0 outside a flap" in r.detail and "1 inside" in r.detail


@case("a timeout just past the K bound after a down is a hit", True)
def _():
    r = _timeouts(n1=[_HIT], downs=[(T0 + 0.69, N1, N2)])
    return "1 outside a flap" in r.detail


@case("a timeout just before a down is a hit", True)
def _():
    r = _timeouts(n1=[_HIT], downs=[(T0 + 2.01, N1, N2)])
    return "1 outside a flap" in r.detail


@case("a down on another edge does not excuse a timeout", True)
def _():
    r = _timeouts(n1=[_HIT], downs=[(T0 + 1.5, "fips-node-n03", N2)])
    return "1 outside a flap" in r.detail


@case("a timeout on a standby path is no hit", True)
def _():
    # Path 1 is the original and active; path 2 stands by.
    r = _timeouts(n1=[
        state(T0, 2, "None", "Some(Probing)", why="Added"),
        state(T0 + 1, 1, "Some(Live)", "Some(Live)", why="Answered"),
        state(T0 + 2, 2, "Some(Live)", "Some(Suspect)", why="Timeout",
              addr="10.222.0.9:2122"),
    ])
    return "0 outside a flap" in r.detail


@case("a suspect for another reason is no hit", True)
def _():
    r = _timeouts(n1=[state(T0 + 2, 1, "Some(Live)", "Some(Suspect)", why="Carrier")])
    return "0 outside a flap" in r.detail


@case("each hit prints each node's largest task wait in the 2 s before it", True)
def _():
    r = _timeouts(
        n1=[waited(T0 - 5, 900), waited(T0 + 0.5, 40), waited(T0 + 1.5, 120), _HIT],
        n2=[waited(T0 + 1, 9)],
    )
    return "n01 120 ms" in r.detail and "n02 9 ms" in r.detail and "900" not in r.detail


@case("a wait logged in the second after the hit counts toward it", True)
def _():
    r = _timeouts(n1=[_HIT, waited(T0 + 2.9, 650), waited(T0 + 3.2, 700)])
    return "n01 650 ms" in r.detail


@case("a node with no task wait lines reads not kept", True)
def _():
    r = _timeouts(n1=[_HIT], n2=[waited(T0 - 30, 9)])
    return "n01 not kept" in r.detail


@case("a node with lines but none near the hit reads under the line's floor", True)
def _():
    r = _timeouts(n1=[_HIT], n2=[waited(T0 - 30, 9)])
    return "n02 under 5 ms" in r.detail


@case("task wait lines are read from the logs", True)
def _():
    result = logs(n01=[waited(T0, 12)])
    return len(result.task_waits) == 1


@case("validation refuses active_timeouts without the path handler at debug", True)
def _():
    return _timeouts_refused("info,fips::node::dataplane::wait=debug")


@case("validation refuses active_timeouts without the wait line at debug", True)
def _():
    return _timeouts_refused("info,fips::node::handlers::path=debug")


@case("validation accepts active_timeouts with both at debug", True)
def _():
    S._validate(_timeouts_scenario(
        "info,fips::node::handlers::path=debug,fips::node::dataplane::wait=debug"
    ))
    return True


def _timeouts_scenario(rust_log: str):
    """A minimal scenario declaring the report at ``rust_log``."""
    s = S.Scenario()
    s.topology.num_nodes = 2
    s.topology.algorithm = "explicit"
    s.topology.params = {"adjacency": [["n01", "n02", "ethernet+udp"]]}
    s.logging.rust_log = rust_log
    s.assertions.active_timeouts = S.ActiveTimeoutsAssertion()
    return s


def _timeouts_refused(rust_log: str) -> bool:
    """True when validation refuses the report at ``rust_log``."""
    try:
        S._validate(_timeouts_scenario(rust_log))
    except ValueError:
        return True
    return False


@case("the three two-path suites declare the report, the bulk suite the wait line", True)
def _():
    def load(name):
        return S.load_scenario(os.path.join(HERE, "scenarios", f"{name}.yaml"))

    three = [load(n) for n in ("dual-path-flap", "dual-udp-flap", "steady-dual-path")]
    bulk = load("two-bound-udp-bulk")
    target = "fips::node::dataplane::wait"
    return (
        all(s.assertions.active_timeouts is not None for s in three)
        and all(S.log_enables(s.logging.rust_log, target, "debug") for s in three + [bulk])
    )


# --- edge_agreement: the read clauses ------------------------------------------

# Identities from a real churn-mixed run (sim-results 20260726-142044): each
# node's npub and node_addr as its startup lines logged them.
_NPUB = {
    "n01": "npub1xw8a2v4c987kmwxkzm8c87evfpsjsfkny749j523jgmu5hk57xzsjr8ekk",
    "n02": "npub1dvn480ww83c7frz5xytf383ecy3g84ndzu76geajgmpwg4vwfzcshfnfv6",
    "n03": "npub1etj07lxvxmdqzuz6lwkx5c6s33z5c7y4hxuwjvnwv7p7060rr83q5l3wxc",
    "n04": "npub1wnqcet5vgl0kklzcn4sa7hltqsjhegd3alxw99k98v0j29hmhtds793eeh",
    "n06": "npub12plr4fgdpku7l0gteep2y04hhzq8syegvkaausjxzm6wkc03amjs98ceep",
    "n09": "npub1y6l49pa2jh6mk9vdyw6xveu7w0jgqrhxdld7mu5srtp6sdjk0mfq0j2mry",
}
_ADDR = {
    "n01": "3d3de38d7efeeeed5e81a6f5dd5843f2",
    "n02": "6224fe254bf38afc7a3714b69f6dbf37",
    "n03": "649a3f8d5ddaed386f29cf7e99447ddb",
    "n04": "90118bf964c18364bb8dd81661d84088",
    "n06": "da188b0a719f076c9c922f8c15c8f233",
    "n09": "e6f81ba75745b70e2208467ac9d3d13f",
}


def _edge(a: str, b: str, transport: str = "udp", dialers=None,
          net: str = "10.30.4") -> A.AgreementEdge:
    """An edge between two planted nodes, dialed by ``a`` unless ``dialers``
    says otherwise; each node's Docker address is ``net`` and 9 plus its
    number, as the planning runs' were."""
    return A.AgreementEdge(
        a, b, transport,
        npub={n: _NPUB[n] for n in (a, b)},
        ip={n: f"{net}.{9 + int(n[1:])}" for n in (a, b)},
        dialers=frozenset({a} if dialers is None else dialers),
    )


def _row(peer: str, our: str | None, their: str | None, direction: str,
         transport: str, addr: str, **extra) -> dict:
    """A ``show_peers`` row for ``peer`` carrying the fields the assertion
    reads; ``None`` leaves an index key out, as the node does with no
    session."""
    row = {"npub": _NPUB[peer], "node_addr": _ADDR[peer], "direction": direction,
           "transport_type": transport, "transport_addr": addr}
    if our is not None:
        row["our_session_index"] = our
    if their is not None:
        row["their_session_index"] = their
    row.update(extra)
    return row


def _clauses(faults: list[str]) -> list[str]:
    """The clause each fault names."""
    return [f.split(":", 1)[0] for f in faults]


# Real final rows of the planning runs (plan logs/planning-results.txt): the
# indices, direction, transport and address each end listed for the other.
def _udp_ok():
    """tcp-mesh on master, n01-n02, one-way from n01."""
    return (_edge("n01", "n02"),
            [_row("n02", "a4bfa56b", "8cb13a9d", "outbound", "udp", "10.30.4.11:2121")],
            [_row("n01", "8cb13a9d", "a4bfa56b", "inbound", "udp", "10.30.4.10:2121")])


@case("a healthy UDP edge agrees", True)
def _():
    return A.edge_faults(*_udp_ok()) == []


@case("a healthy TCP edge agrees though its inbound end lists an ephemeral port", True)
def _():
    edge = _edge("n01", "n04", "tcp")
    ra = [_row("n04", "8cf1b7a3", "301008e3", "outbound", "tcp", "10.30.4.13:443")]
    rb = [_row("n01", "301008e3", "8cf1b7a3", "inbound", "tcp", "10.30.4.10:55798")]
    return A.edge_faults(edge, ra, rb) == []


@case("a healthy Ethernet edge agrees with MACs for addresses", True)
def _():
    # churn-mixed on master, n01-n09, found by beacon at both ends.
    edge = _edge("n01", "n09", "ethernet", dialers=(), net="10.30.2")
    ra = [_row("n09", "f8b19503", "e1fcdf6a", "outbound", "ethernet", "4e:ad:52:d7:a0:6c")]
    rb = [_row("n01", "e1fcdf6a", "f8b19503", "inbound", "ethernet", "a6:a5:e1:7a:0a:f2")]
    return A.edge_faults(edge, ra, rb) == []


@case("both ends inbound, master's crossed rows, fails at direction alone", True)
def _():
    # tcp-mesh on master with UDP edges dialed from both ends, at 79ee9c2c.
    edge = _edge("n01", "n02", dialers=("n01", "n02"), net="10.30.5")
    ra = [_row("n02", "16856bd9", "c28b7830", "inbound", "udp", "10.30.5.11:2121")]
    rb = [_row("n01", "c28b7830", "16856bd9", "inbound", "udp", "10.30.5.10:2121")]
    return _clauses(A.edge_faults(edge, ra, rb)) == ["direction"]


@case("both ends outbound, next's crossed rows, fails at direction alone", True)
def _():
    edge = _edge("n01", "n02", dialers=("n01", "n02"))
    ra = [_row("n02", "309c7707", "7888b708", "outbound", "udp", "10.30.4.11:2121")]
    rb = [_row("n01", "7888b708", "309c7707", "outbound", "udp", "10.30.4.10:2121")]
    return _clauses(A.edge_faults(edge, ra, rb)) == ["direction"]


@case("a one-way edge whose dialer is inbound fails at dialer", True)
def _():
    # churn-mixed on master, n02-n03, dialed by n03; planted here as n02's.
    edge = _edge("n02", "n03", dialers=("n02",), net="10.30.2")
    ra = [_row("n03", "1f692404", "e63fe9c7", "inbound", "udp", "10.30.2.12:2121")]
    rb = [_row("n02", "e63fe9c7", "1f692404", "outbound", "udp", "10.30.2.11:2121")]
    return _clauses(A.edge_faults(edge, ra, rb)) == ["dialer"]


@case("an edge dialed from both ends passes with the smaller node outbound "
      "though the lower name is the larger address", True)
def _():
    # n01 holds the larger address here, so the smaller is n02, outbound.
    edge = _edge("n01", "n02", dialers=("n01", "n02"))
    ra = [_row("n02", "fea7b6a0", "b2527821", "inbound", "udp", "10.30.4.11:2121")]
    rb = [_row("n01", "b2527821", "fea7b6a0", "outbound", "udp", "10.30.4.10:2121",
               node_addr="eb2aa74bfaf4c56738e40420722602e9")]
    return A.edge_faults(edge, ra, rb) == []


@case("an Ethernet edge with no dialer passes with its first end outbound", True)
def _():
    # churn-mixed on master, n03-n10's rows, planted on n03-n06.
    edge = _edge("n03", "n06", "ethernet", dialers=())
    ra = [_row("n06", "d4c1878d", "c8755a11", "outbound", "ethernet", "7e:57:10:37:6c:fb")]
    rb = [_row("n03", "c8755a11", "d4c1878d", "inbound", "ethernet", "86:8b:98:ee:c8:b6")]
    return A.edge_faults(edge, ra, rb) == []


@case("an index pair apart with no rekey flag fails and says no flag was set", True)
def _():
    edge, ra, rb = _udp_ok()
    rb[0]["our_session_index"] = "0badf00d"
    faults = A.edge_faults(edge, ra, rb)
    return _clauses(faults) == ["pair"] and "no rekey flag set" in faults[0]


@case("an index pair apart with a rekey flag at the bound fails naming the flag", True)
def _():
    edge, ra, rb = _udp_ok()
    rb[0]["our_session_index"] = "0badf00d"
    rb[0]["rekey_in_progress"] = True
    faults = A.edge_faults(edge, ra, rb)
    return _clauses(faults) == ["pair"] and "n02 rekey_in_progress" in faults[0]


@case("rows listing no session index at either end fail at pair", True)
def _():
    edge = _edge("n01", "n02")
    ra = [_row("n02", None, None, "outbound", "udp", "10.30.4.11:2121",
               their_session_index=None)]
    rb = [_row("n01", None, None, "inbound", "udp", "10.30.4.10:2121",
               their_session_index=None)]
    return _clauses(A.edge_faults(edge, ra, rb)) == ["pair"]


@case("a row with no their_session_index fails as a harness error", True)
def _():
    edge, ra, rb = _udp_ok()
    for rows in (ra, rb):
        del rows[0]["their_session_index"]
    return _clauses(A.edge_faults(edge, ra, rb)) == ["harness"]


@case("a row absent at one end fails at present, naming that end", True)
def _():
    edge, ra, _rb = _udp_ok()
    faults = A.edge_faults(edge, ra, [])
    return _clauses(faults) == ["present"] and "n02 lists no row for n01" in faults[0]


@case("a node that gave no listing fails the edge as observed nothing", True)
def _():
    edge, ra, _rb = _udp_ok()
    faults = A.edge_faults(edge, ra, None)
    return _clauses(faults) == ["unread"] and "nothing was observed" in faults[0]


@case("a row on another transport fails at transport", True)
def _():
    edge, ra, rb = _udp_ok()
    rb[0]["transport_type"] = "tcp"
    return _clauses(A.edge_faults(edge, ra, rb)) == ["transport"]


@case("a row naming another IP fails at address", True)
def _():
    edge, ra, rb = _udp_ok()
    rb[0]["transport_addr"] = "10.30.4.99:2121"
    return _clauses(A.edge_faults(edge, ra, rb)) == ["address"]


# --- edge_agreement: the crossing reader ----------------------------------------

def _topology(*edges: tuple[str, str, str], npubs: dict | None = None):
    """A planted topology over ``(a, b, transport)`` edges, each node with its
    planted npub (``npubs`` adds or replaces some) and the planning runs'
    addresses."""
    from sim.topology import SimNode, SimTopology

    npub = {**_NPUB, **(npubs or {})}
    t = SimTopology()
    for a, b, transport in edges:
        for n in (a, b):
            t.nodes.setdefault(n, SimNode(n, f"10.30.4.{9 + int(n[1:])}", "00" * 32, npub[n]))
        t.edges.add((a, b))
        t.edge_transport[(a, b)] = transport
    return t


def _swapped(t: float, peer: str) -> str:
    """A "swapped to outbound session" line at ``t`` naming ``peer``, in the
    form the node writes it."""
    return (
        f"{stamp(t)} DEBUG fips::node::settle::exec::cross: Cross-connection: swapped "
        f"to outbound session (our outbound wins) peer={peer} new_our_index=9bcbbe9b "
        f"new_their_index=225ac706 transport_id=transport:1 "
        f"remote_addr=10.30.4.11:2121 msg1_sidx=9bcbbe9b msg1_dg=3f0c2a91 epoch=7d1e44b0"
    )


def _kept(t: float, peer: str) -> str:
    """A "keeping inbound session" line at ``t`` naming ``peer``."""
    return (
        f"{stamp(t)} DEBUG fips::node::settle::exec::cross: Cross-connection: keeping "
        f"inbound session and original their_index (peer outbound wins) peer={peer} "
        f"kept_their_index=Some(SessionIndex(2613821083)) transport_id=transport:1 "
        f"remote_addr=10.30.4.10:2121 epoch=7d1e44b0"
    )


def _answered(t: float, peer: str) -> str:
    """A "Second dial answered" line: a swap onto the answer to this node's own
    earlier dial, which is not a crossing."""
    return (
        f"{stamp(t)} DEBUG fips::node::settle::exec::cross: Second dial answered: "
        f"swapped to its session (the answer supersedes our earlier dial's) peer={peer} "
        f"new_our_index=9bcbbe9b new_their_index=225ac706 transport_id=transport:1 "
        f"remote_addr=10.30.4.11:2121 msg1_sidx=9bcbbe9b msg1_dg=3f0c2a91 epoch=7d1e44b0"
    )


def _installed(t: float, peer: str) -> str:
    """A "Peer promoted to active" line at ``t``: this node's dial installed
    ``peer``."""
    return (f"{stamp(t)}  INFO fips::node::handlers::handshake: Peer promoted to active "
            f"peer={peer}")


def _connected(t: float, peer: str, direction: str = "inbound") -> str:
    """A "Connection promoted to active peer" line at ``t``."""
    return (
        f"{stamp(t)} DEBUG fips::node::handlers::handshake: Connection promoted to "
        f"active peer peer={peer} link_id=4 our_index=5755bfa8 their_index=2adc7214 "
        f"transport_id=transport:1 remote_addr=10.30.4.11:2121 direction={direction} "
        f"msg1_sidx=5755bfa8 msg1_dg=3f0c2a91 epoch=7d1e44b0"
    )


def _adopted(t: float, peer: str) -> str:
    """The line at ``t`` for this node's adoption of a rekey answer it sent on
    the connection ``peer``'s msg1 arrived on."""
    return (
        f"{stamp(t)} DEBUG fips::node::handlers::rekey: Rekey answered on the msg1's "
        f"connection adopted, link held as the peer's dial peer={peer} dir=Inbound"
    )


def _crossings(**per_node: list[str]):
    """``edge_crossings`` over planted lines, one list per node id, on the
    planted n01-n02 UDP edge."""
    logs = {f"fips-node-{n}": "\n".join(lines) for n, lines in per_node.items()}
    return A.edge_crossings(logs, _topology(("n01", "n02", "udp")))


# n01 holds the smaller address. Its swap follows its own promotion of n02 by
# 9 ms, as in the planning runs' crossings, and n02 kept its inbound session.
_CROSSED = {
    "n01": [_connected(T0 - 0.009, "n02"), _swapped(T0, "n02")],
    "n02": [_kept(T0 - 0.004, "n01")],
}


@case("a swap whose far end kept its inbound session within 30 s is a crossed record", True)
def _():
    c = _crossings(**_CROSSED)
    recs = c.edges.get(("n01", "n02"), [])
    return (not c.errors and [(r.end, r.peer, r.kind) for r in recs] == [("n01", "n02", "crossed")]
            and "keeping inbound" in recs[0].far and recs[0].ended is None)


@case("a later Peer promoted to active for the peer at the swap end ends the crossed record", True)
def _():
    c = _crossings(n01=_CROSSED["n01"] + [_installed(T0 + 5, "n02")], n02=_CROSSED["n02"])
    return [r.ended for r in c.edges[("n01", "n02")]] == [T0 + 5]


@case("a later Connection promoted to active peer alone ends the crossed record", True)
def _():
    # The responder form: the peer's dial re-established it, which logs no
    # Peer promoted to active at this end.
    c = _crossings(n01=_CROSSED["n01"] + [_connected(T0 + 5, "n02")], n02=_CROSSED["n02"])
    return [r.ended for r in c.edges[("n01", "n02")]] == [T0 + 5]


@case("a later adoption of a rekey answer on the msg1's connection at the swap end ends "
      "the crossed record", True)
def _():
    c = _crossings(n01=_CROSSED["n01"] + [_adopted(T0 + 5, "n02")], n02=_CROSSED["n02"])
    return not c.errors and [r.ended for r in c.edges[("n01", "n02")]] == [T0 + 5]


@case("an adoption at the far end does not end the crossed record", True)
def _():
    c = _crossings(n01=_CROSSED["n01"], n02=_CROSSED["n02"] + [_adopted(T0 + 5, "n01")])
    return not c.errors and [r.ended for r in c.edges[("n01", "n02")]] == [None]


@case("a keeping inbound line alone makes no record", True)
def _():
    c = _crossings(n01=[], n02=_CROSSED["n02"])
    return not c.errors and not c.edges


@case("a Second dial answered swap makes no record", True)
def _():
    c = _crossings(n01=[_answered(T0, "n02")], n02=[_kept(T0, "n01")])
    return not c.errors and not c.edges


# The archived re-dial (sim-results 20260726-142044-churn-mixed): n03 re-dialed
# n06, which it held, over Ethernet, and n06 answered it as a rekey. The lines
# are n03's and n06's as logged, the peer= values their real short npubs.
_REDIAL = {
    "n03": [
        "2026-07-26T14:20:49.480232Z DEBUG fips::node::handlers::handshake: Connection "
        "promoted to active peer peer=npub12plr...ceep link_id=link:1 our_index=a3400b9b "
        "their_index=f822cfa0",
        "2026-07-26T14:22:59.435030Z  INFO fips::node::lifecycle: Auto-connecting to "
        "discovered peer peer=npub12plr...ceep transport_id=transport:2 "
        "remote_addr=aa:96:55:43:75:c0 active_refresh=true",
        "2026-07-26T14:22:59.587867Z DEBUG fips::node::handlers::handshake: "
        "Cross-connection: swapped to outbound session (our outbound wins) "
        "peer=npub12plr...ceep new_our_index=d3c3f31f new_their_index=a5f97614",
    ],
    "n06": [
        "2026-07-26T14:20:49.480353Z DEBUG fips::node::handlers::handshake: Connection "
        "promoted to active peer peer=npub1etj0...3wxc link_id=link:2 our_index=f822cfa0 "
        "their_index=a3400b9b",
        "2026-07-26T14:20:49.480376Z  INFO fips::node::handlers::handshake: Peer promoted "
        "to active peer=npub1etj0...3wxc",
        "2026-07-26T14:22:59.508374Z DEBUG fips::node::handlers::handshake: Dual rekey "
        "initiation: we lose (larger addr), abandoning ours peer=npub1etj0...3wxc",
    ],
}


def _redial():
    """``edge_crossings`` over the archived re-dial on a planted Ethernet edge."""
    logs = {f"fips-node-{n}": "\n".join(lines) for n, lines in _REDIAL.items()}
    return A.edge_crossings(logs, _topology(("n03", "n06", "ethernet")))


@case("the archived re-dial answered as a rekey is a rekey record, not a crossing", True)
def _():
    c = _redial()
    recs = c.edges.get(("n03", "n06"), [])
    return (not c.errors and [(r.end, r.kind) for r in recs] == [("n03", "rekey")]
            and "Dual rekey initiation" in recs[0].far)


@case("a swap whose far end logged neither line is unpaired", True)
def _():
    c = _crossings(n01=[_swapped(T0, "n02")], n02=[])
    return [r.kind for r in c.edges[("n01", "n02")]] == ["unpaired"]


@case("a keeping line naming another peer leaves the swap unpaired", True)
def _():
    logs = {"fips-node-n01": _swapped(T0, "n02"), "fips-node-n02": _kept(T0, "n03")}
    c = A.edge_crossings(logs, _topology(("n01", "n02", "udp"), ("n02", "n03", "udp")))
    return not c.errors and [r.kind for r in c.edges[("n01", "n02")]] == ["unpaired"]


@case("a keeping line 31 s from the swap leaves it unpaired", True)
def _():
    c = _crossings(n01=[_swapped(T0, "n02")], n02=[_kept(T0 + 31, "n01")])
    return [r.kind for r in c.edges[("n01", "n02")]] == ["unpaired"]


@case("a keeping line logged by another node leaves the swap unpaired", True)
def _():
    logs = {"fips-node-n01": _swapped(T0, "n02"), "fips-node-n03": _kept(T0, "n01")}
    c = A.edge_crossings(logs, _topology(("n01", "n02", "udp"), ("n01", "n03", "udp")))
    return not c.errors and [r.kind for r in c.edges[("n01", "n02")]] == ["unpaired"]


@case("a swap naming its peer by alias and by short npub both resolve to the edge", True)
def _():
    # Each short form as the node writes it: npub1, four, "...", the last four.
    by_alias = _crossings(n01=[_swapped(T0, "n02")], n02=[_kept(T0, "n01")])
    by_npub = _crossings(n01=[_swapped(T0, "npub1dvn4...nfv6")],
                         n02=[_kept(T0, "npub1xw8a...8ekk")])
    return ([r.kind for r in by_alias.edges.get(("n01", "n02"), [])] == ["crossed"]
            and [r.kind for r in by_npub.edges.get(("n01", "n02"), [])] == ["crossed"])


@case("a peer= value that names no node is a harness error", True)
def _():
    c = _crossings(n01=[_swapped(T0, "npub1zzzz...zzzz")], n02=[])
    return not c.edges and len(c.errors) == 1 and "names no node" in c.errors[0]


@case("a peer= value that names two nodes is a harness error", True)
def _():
    twin = "npub1xw8a" + "q" * 50 + "8ekk"   # n01's short form, another key
    logs = {"fips-node-n02": _swapped(T0, "npub1xw8a...8ekk")}
    t = _topology(("n01", "n02", "udp"), ("n02", "n05", "udp"), npubs={"n05": twin})
    c = A.edge_crossings(logs, t)
    return not c.edges and len(c.errors) == 1 and "names n01 and n05" in c.errors[0]


@case("a crossing line with no timestamp is a harness error", True)
def _():
    # A swap line as the node writes it, its leading timestamp cut off.
    untimed = _swapped(T0, "n02").split(" ", 1)[1]
    c = _crossings(n01=[untimed], n02=[_kept(T0, "n01")])
    return not c.edges and len(c.errors) == 1 and "a crossing line with no time" in c.errors[0]


@case("a swap between two nodes that share no edge is a harness error", True)
def _():
    # n01 and n03 are both in the topology, each on an edge with n02.
    logs = {"fips-node-n01": _swapped(T0, "n03"), "fips-node-n03": _kept(T0, "n01")}
    c = A.edge_crossings(logs, _topology(("n01", "n02", "udp"), ("n02", "n03", "udp")))
    return (not c.edges and len(c.errors) == 1
            and "a swap for n03, with which it shares no edge" in c.errors[0])


# --- edge_agreement: the score ----------------------------------------------------

def _agreement(min_crossings: int = 0, rust_log: str = "debug"):
    """The assertion's config as loading sets it at ``rust_log``."""
    return S.EdgeAgreementAssertion(min_crossings=min_crossings,
                                    crossings_logged=S.logs_crossings(rust_log))


def _both(da: str, db: str, at: float = T0 + 60, n01_addr: str | None = None) -> A.Judged:
    """n01-n02, dialed from both ends, scored on rows read at ``at``: n01 ``da``
    and n02 ``db``. n01 holds the smaller address unless ``n01_addr`` replaces
    it in n02's row."""
    edge = _edge("n01", "n02", dialers=("n01", "n02"))
    extra = {} if n01_addr is None else {"node_addr": n01_addr}
    return A.judge(edge,
                   [_row("n02", "9bcbbe9b", "225ac706", da, "udp", "10.30.4.11:2121")],
                   [_row("n01", "225ac706", "9bcbbe9b", db, "udp", "10.30.4.10:2121",
                         **extra)], at)


# An address for n01 larger than n02's, so the second-named end is the smaller.
_N01_LARGER = "eb2aa74bfaf4c56738e40420722602e9"

# The crossing as it runs when n02 holds the smaller address: n02 swaps to its
# own dial's session and n01 keeps its inbound one.
_CROSSED_BY_N02 = {
    "n02": [_connected(T0 - 0.009, "n01"), _swapped(T0, "n01")],
    "n01": [_kept(T0 - 0.004, "n02")],
}


def _scored(outcome: A.AssertionOutcome) -> list[str]:
    """The bracketed clauses of each failing edge's line."""
    return [text.split("[", 1)[1].split("]", 1)[0]
            for text in outcome.detail.splitlines() if "] scored at " in text]


@case("a crossed edge with the smaller end outbound passes and counts", True)
def _():
    r = A.evaluate_agreement(_agreement(1), [_both("outbound", "inbound")],
                             _crossings(**_CROSSED))
    return r.passed and "1 edge(s) with a crossed record (floor 1)" in r.detail


@case("a crossed edge with the smaller end inbound fails at crossing", True)
def _():
    r = A.evaluate_agreement(_agreement(), [_both("inbound", "outbound")],
                             _crossings(**_CROSSED))
    return not r.passed and _scored(r) == ["crossing"]


@case("a crossed edge whose second-named end is the smaller passes with that end "
      "outbound", True)
def _():
    r = A.evaluate_agreement(_agreement(1),
                             [_both("inbound", "outbound", n01_addr=_N01_LARGER)],
                             _crossings(**_CROSSED_BY_N02))
    return r.passed and "1 edge(s) with a crossed record (floor 1)" in r.detail


@case("a crossed edge whose second-named end is the smaller fails at crossing with "
      "that end inbound", True)
def _():
    r = A.evaluate_agreement(_agreement(),
                             [_both("outbound", "inbound", n01_addr=_N01_LARGER)],
                             _crossings(**_CROSSED_BY_N02))
    return (not r.passed and _scored(r) == ["crossing"]
            and "crossing: n02, the smaller end, is inbound" in r.detail)


@case("a crossed edge whose row lists no node_addr fails as a harness error", True)
def _():
    j = _both("outbound", "inbound")
    del j.row_a["node_addr"]
    r = A.evaluate_agreement(_agreement(), [j], _crossings(**_CROSSED))
    return not r.passed and _scored(r) == ["harness"] and "lists no node_addr" in r.detail


@case("at rust_log info a crossed record with the smaller end inbound is not judged", True)
def _():
    # At a level that does not emit every crossing line a record may lack the
    # line that would class it, so the clause stands down rather than judge.
    r = A.evaluate_agreement(_agreement(0, "info"), [_both("inbound", "outbound")],
                             _crossings(**_CROSSED))
    return r.passed and "crossing clause was not observed" in r.detail


@case("both ends inbound on a crossed edge fails at direction and crossing", True)
def _():
    # The shape the crossed-dial switch leaves.
    r = A.evaluate_agreement(_agreement(), [_both("inbound", "inbound")],
                             _crossings(**_CROSSED))
    return not r.passed and _scored(r) == ["direction, crossing"]


@case("a crossed record ended by a later Peer promoted to active is not scored", True)
def _():
    c = _crossings(n01=_CROSSED["n01"] + [_installed(T0 + 5, "n02")], n02=_CROSSED["n02"])
    return A.evaluate_agreement(_agreement(), [_both("inbound", "outbound")], c)


@case("the responder form: a later Connection promoted to active peer ends the record "
      "and an inbound smaller end passes", True)
def _():
    c = _crossings(n01=_CROSSED["n01"] + [_connected(T0 + 5, "n02")], n02=_CROSSED["n02"])
    return A.evaluate_agreement(_agreement(), [_both("inbound", "outbound")], c)


@case("a crossed record ended by a later adoption at the swap end is not scored", True)
def _():
    c = _crossings(n01=_CROSSED["n01"] + [_adopted(T0 + 5, "n02")], n02=_CROSSED["n02"])
    return A.evaluate_agreement(_agreement(), [_both("inbound", "outbound")], c)


@case("a promotion after the scored read does not end the record for that read", True)
def _():
    c = _crossings(n01=_CROSSED["n01"] + [_installed(T0 + 90, "n02")], n02=_CROSSED["n02"])
    r = A.evaluate_agreement(_agreement(), [_both("inbound", "outbound")], c)
    return not r.passed and _scored(r) == ["crossing"]


@case("a crossed record timed after the scored read is listed, not scored or counted", True)
def _():
    r = A.evaluate_agreement(_agreement(), [_both("inbound", "outbound", at=T0 - 1)],
                             _crossings(**_CROSSED))
    return (r.passed and "crossed: n01 swapped" in r.detail and "after the read, not scored" in r.detail
            and "0 edge(s) with a crossed record" in r.detail)


def _redial_rows(d03: str, d06: str) -> A.Judged:
    """The archived re-dial's edge scored after it, n03 ``d03``, n06 ``d06``."""
    edge = _edge("n03", "n06", "ethernet", dialers=())
    at = datetime(2026, 7, 26, 14, 23, 30, tzinfo=timezone.utc).timestamp()
    return A.judge(edge,
                   [_row("n06", "d3c3f31f", "a5f97614", d03, "ethernet", "aa:96:55:43:75:c0")],
                   [_row("n03", "a5f97614", "d3c3f31f", d06, "ethernet", "4e:ad:52:d7:a0:6c")],
                   at)


@case("the archived re-dial is listed as a rekey record, not counted, and its edge "
      "passes with n03 inbound and n06 outbound", True)
def _():
    r = A.evaluate_agreement(_agreement(), [_redial_rows("inbound", "outbound")], _redial())
    return (r.passed and "rekey: n03 swapped" in r.detail
            and "far: 2026-07-26T14:22:59.508374Z" in r.detail
            and "0 edge(s) with a crossed record" in r.detail)


@case("the archived re-dial with both ends outbound fails at direction, not at crossing", True)
def _():
    r = A.evaluate_agreement(_agreement(), [_redial_rows("outbound", "outbound")], _redial())
    return (not r.passed and _scored(r) == ["direction"]
            and "0 edge(s) with a crossed record" in r.detail)


@case("at rust_log info the read clauses stand and the PASS line says the crossing "
      "clause was not observed", True)
def _():
    edge, ra, rb = _udp_ok()
    r = A.evaluate_agreement(_agreement(0, "info"), [A.judge(edge, ra, rb, T0)], A.Crossings())
    return r.passed and "crossing clause was not observed" in r.detail


@case("at rust_log info a failing read clause still fails", True)
def _():
    r = A.evaluate_agreement(_agreement(0, "info"), [_both("inbound", "inbound")],
                             A.Crossings())
    return not r.passed and _scored(r) == ["direction"]


@case("min_crossings 2 with one crossed record fails as observing nothing", True)
def _():
    r = A.evaluate_agreement(_agreement(2), [_both("outbound", "inbound")],
                             _crossings(**_CROSSED))
    return not r.passed and "observed nothing" in r.detail


@case("min_crossings 2 with one crossed and one rekey record fails", True)
def _():
    redial = _redial()
    c = _crossings(**_CROSSED)
    c.edges.update(redial.edges)
    r = A.evaluate_agreement(_agreement(2), [_both("outbound", "inbound"),
                                             _redial_rows("inbound", "outbound")], c)
    return not r.passed and "observed nothing" in r.detail


@case("min_crossings 2 counts edges, not swap lines", True)
def _():
    later = {"n01": _CROSSED["n01"] + [_swapped(T0 + 20, "n02")],
             "n02": _CROSSED["n02"] + [_kept(T0 + 19.99, "n01")]}
    c = _crossings(**later)
    r = A.evaluate_agreement(_agreement(2), [_both("outbound", "inbound")], c)
    return len(c.edges[("n01", "n02")]) == 2 and not r.passed and "observed nothing" in r.detail


@case("a crossing line the reader could not resolve fails the run", True)
def _():
    c = _crossings(n01=[_swapped(T0, "npub1zzzz...zzzz")], n02=[])
    edge, ra, rb = _udp_ok()
    r = A.evaluate_agreement(_agreement(), [A.judge(edge, ra, rb, T0 + 60)], c)
    return not r.passed and "harness: n01: peer=npub1zzzz...zzzz names no node" in r.detail


@case("swap lines on an edge that was not read fail the run", True)
def _():
    edge, ra, rb = _udp_ok()
    c = A.Crossings(edges={("n03", "n06"): _redial().edges[("n03", "n06")]})
    r = A.evaluate_agreement(_agreement(), [A.judge(edge, ra, rb, T0 + 60)], c)
    return not r.passed and "an edge that was not read" in r.detail


@case("no edge read at all fails as observing nothing", True)
def _():
    r = A.evaluate_agreement(_agreement(), [], A.Crossings())
    return not r.passed and "nothing was observed" in r.detail


# --- edge_agreement: the runner's read and score -----------------------------------

class _Reads:
    """Planted ``show_peers`` answers on a fake clock.

    ``script`` gives each node's listings, one per read, the last repeated;
    ``None`` is a node that does not answer. Each read takes 0.2 s and a
    sleep passes its time. A read loop that never stops raises instead of
    hanging the suite.
    """

    def __init__(self, start: float, **script):
        self.t = start
        self.script = script
        self.count = {n: 0 for n in script}

    def clock(self) -> float:
        """The fake wall clock."""
        return self.t

    def sleep(self, secs: float) -> None:
        """Pass ``secs`` on the fake clock."""
        self.t += secs

    def read(self, node: str):
        """The node's next planted listing."""
        if sum(self.count.values()) > 500:
            raise RuntimeError("the read loop did not stop")
        seq = self.script[node]
        i = self.count[node]
        self.count[node] += 1
        self.t += 0.2
        return seq[min(i, len(seq) - 1)]


def _link(x: str, y: str, our: str, their: str, direction: str,
          transport: str = "udp", **extra) -> dict:
    """The row ``x`` lists for ``y``: the session pair from ``x``'s side,
    ``x``'s link direction, and ``y``'s planted Docker address."""
    return _row(y, our, their, direction, transport,
                f"10.30.4.{9 + int(y[1:])}:2121", **extra)


def _agreement_runner(*edges: tuple[str, str, str], outbound: dict | None = None,
                      rust_log: str = "info"):
    """A runner over a planted topology whose scenario declares
    edge_agreement at ``rust_log``; ``outbound`` replaces the topology's
    ``directed_outbound()``."""
    import tempfile

    from sim import runner as R

    r = R.SimRunner(_scenario(_agreement_scenario(rust_log)))
    r.topology = _topology(*edges)
    if outbound is not None:
        r.topology.directed_outbound = lambda: {n: list(p) for n, p in outbound.items()}
    r.output_dir = tempfile.mkdtemp(prefix="sim-assert-agree-")
    return r


def _readrun(r, reads: _Reads):
    """``_readedges`` on planted reads, then the score with no crossing lines;
    the runner's directory removed afterwards."""
    import shutil

    try:
        r._readedges(read=reads.read, clock=reads.clock, sleep=reads.sleep)
        r.assertion_outcomes = []
        r._scoreagreement({})
        return r.assertion_outcomes[0]
    finally:
        shutil.rmtree(r.output_dir, ignore_errors=True)


@case("the read: an edge apart at the first read and agreeing at the second passes, "
      "scored on the second", True)
def _():
    r = _agreement_runner(("n01", "n02", "udp"))
    reads = _Reads(T0 + 60,
                   n01=[[_link("n01", "n02", "a4bfa56b", "8cb13a9d", "outbound")]],
                   n02=[[_link("n02", "n01", "5d0e11c2", "a4bfa56b", "inbound",
                               rekey_in_progress=True)],
                        [_link("n02", "n01", "8cb13a9d", "a4bfa56b", "inbound")]])
    out = _readrun(r, reads)
    j = r.agreement_judged[0]
    return out.passed and j.faults == [] and j.at > T0 + 63 and reads.count["n02"] == 2


@case("the read: an edge apart at every read fails at the bound, read no longer "
      "than the bound", True)
def _():
    r = _agreement_runner(("n01", "n02", "udp"))
    reads = _Reads(T0 + 60,
                   n01=[[_link("n01", "n02", "a4bfa56b", "8cb13a9d", "outbound")]],
                   n02=[[_link("n02", "n01", "5d0e11c2", "a4bfa56b", "inbound")]])
    out = _readrun(r, reads)
    return (not out.passed and _scored(out) == ["pair"] and "no rekey flag set" in out.detail
            and 20 <= reads.count["n02"] <= 31 and reads.t <= T0 + 60 + 90 + 1)


@case("the read: a node that never answers fails its edges as observed nothing", True)
def _():
    r = _agreement_runner(("n01", "n02", "udp"), ("n01", "n03", "udp"))
    reads = _Reads(T0 + 60,
                   n01=[[_link("n01", "n02", "a4bfa56b", "8cb13a9d", "outbound"),
                         _link("n01", "n03", "11aa22bb", "33cc44dd", "outbound")]],
                   n02=[None],
                   n03=[[_link("n03", "n01", "33cc44dd", "11aa22bb", "inbound")]])
    out = _readrun(r, reads)
    return (not out.passed and _scored(out) == ["unread"]
            and "n02 gave no peer listing" in out.detail and reads.count["n02"] > 1)


@case("the read: an edge that agreed is not read again for it", True)
def _():
    r = _agreement_runner(("n01", "n02", "udp"), ("n02", "n03", "udp"))
    reads = _Reads(T0 + 60,
                   n01=[[_link("n01", "n02", "a4bfa56b", "8cb13a9d", "outbound")]],
                   n02=[[_link("n02", "n01", "8cb13a9d", "a4bfa56b", "inbound"),
                         _link("n02", "n03", "11aa22bb", "33cc44dd", "outbound")]],
                   n03=[[_link("n03", "n02", "5d0e11c2", "11aa22bb", "inbound")],
                        [_link("n03", "n02", "33cc44dd", "11aa22bb", "inbound")]])
    out = _readrun(r, reads)
    return out.passed and reads.count == {"n01": 1, "n02": 2, "n03": 2}


@case("the read: an edge that agreed keeps its round's rows when one end is re-read "
      "for another edge mid-rekey", True)
def _():
    # n01-n02 agrees in round 1. n01 is re-read in round 2 for n01-n03, and by
    # then a rekey of n01-n02 has moved n01's side of that pair.
    r = _agreement_runner(("n01", "n02", "udp"), ("n01", "n03", "udp"))
    reads = _Reads(T0 + 60,
                   n01=[[_link("n01", "n02", "a4bfa56b", "8cb13a9d", "outbound"),
                         _link("n01", "n03", "11aa22bb", "33cc44dd", "outbound")],
                        [_link("n01", "n02", "77e0c1d4", "8cb13a9d", "outbound",
                               rekey_in_progress=True),
                         _link("n01", "n03", "11aa22bb", "33cc44dd", "outbound")]],
                   n02=[[_link("n02", "n01", "8cb13a9d", "a4bfa56b", "inbound")]],
                   n03=[[_link("n03", "n01", "5d0e11c2", "11aa22bb", "inbound")],
                        [_link("n03", "n01", "33cc44dd", "11aa22bb", "inbound")]])
    out = _readrun(r, reads)
    first = r.agreement_judged[0]
    return (out.passed and first.edge.key == ("n01", "n02")
            and first.row_a["our_session_index"] == "a4bfa56b"
            and reads.count["n01"] == 2)


@case("the runner scores the crossings the logs show: both ends inbound after a crossing "
      "fails at direction and crossing", True)
def _():
    import shutil

    r = _agreement_runner(("n01", "n02", "udp"), rust_log="debug",
                          outbound={"n01": ["n02"], "n02": ["n01"]})
    reads = _Reads(T0 + 60,
                   n01=[[_link("n01", "n02", "9bcbbe9b", "225ac706", "inbound")]],
                   n02=[[_link("n02", "n01", "225ac706", "9bcbbe9b", "inbound")]])
    try:
        r._readedges(read=reads.read, clock=reads.clock, sleep=reads.sleep)
        r.assertion_outcomes = []
        r._scoreagreement({f"fips-node-{n}": "\n".join(lines) for n, lines in _CROSSED.items()})
        out = r.assertion_outcomes[0]
    finally:
        shutil.rmtree(r.output_dir, ignore_errors=True)
    return (not out.passed and _scored(out) == ["direction, crossing"]
            and "1 edge(s) with a crossed record" in out.detail)


@case("the runner gives each edge its dialers from directed_outbound read both ways, "
      "and a both-dial edge whose second end dialed outbound passes", True)
def _():
    # n01-n02 is listed from both ends, n02-n03 from n02 alone, n01-n03 is
    # Ethernet and listed by neither. On the both-dial edge n01 holds the
    # larger address and is inbound, so naming n01 its one dialer, as the
    # lanes' idiom would, fails it at the dialer clause.
    r = _agreement_runner(("n01", "n02", "udp"), ("n02", "n03", "udp"),
                          ("n01", "n03", "ethernet"),
                          outbound={"n01": ["n02"], "n02": ["n01", "n03"], "n03": []})
    reads = _Reads(T0 + 60,
                   n01=[[_link("n01", "n02", "9bcbbe9b", "225ac706", "inbound"),
                         _row("n03", "d3c3f31f", "a5f97614", "outbound", "ethernet",
                              "aa:96:55:43:75:c0")]],
                   n02=[[_link("n02", "n01", "225ac706", "9bcbbe9b", "outbound",
                               node_addr=_N01_LARGER),
                         _link("n02", "n03", "11aa22bb", "33cc44dd", "outbound")]],
                   n03=[[_link("n03", "n02", "33cc44dd", "11aa22bb", "inbound"),
                         _row("n01", "a5f97614", "d3c3f31f", "inbound", "ethernet",
                              "4e:ad:52:d7:a0:6c")]])
    dialers = {e.key: e.dialers for e in r._agreementedges()}
    out = _readrun(r, reads)
    return out.passed and dialers == {
        ("n01", "n02"): frozenset({"n01", "n02"}),
        ("n02", "n03"): frozenset({"n02"}),
        ("n01", "n03"): frozenset(),
    }


@case("the runner fails a declared edge_agreement whose read never ran", True)
def _():
    import shutil

    r = _agreement_runner(("n01", "n02", "udp"))
    shutil.rmtree(r.output_dir, ignore_errors=True)
    r.assertion_outcomes = []
    r._scoreagreement({})
    out = r.assertion_outcomes[0]
    return not out.passed and "never read" in out.detail


@case("the read writes each node's last listing to peers-final.json", True)
def _():
    import json
    import shutil

    r = _agreement_runner(("n01", "n02", "udp"))
    reads = _Reads(T0 + 60,
                   n01=[[_link("n01", "n02", "a4bfa56b", "8cb13a9d", "outbound")]],
                   n02=[None])
    try:
        r._readedges(read=reads.read, clock=reads.clock, sleep=reads.sleep)
        with open(os.path.join(r.output_dir, "peers-final.json")) as f:
            got = json.load(f)
    finally:
        shutil.rmtree(r.output_dir, ignore_errors=True)
    return set(got) == {"n01", "n02"} and got["n02"] is None and len(got["n01"]) == 1


def _agreement_scenario(rust_log: str, **block) -> str:
    """A two-node explicit scenario carrying edge_agreement, as YAML."""
    body = ", ".join(f"{k}: {v}" for k, v in block.items())
    return (
        "scenario: {name: agree, duration_secs: 60}\n"
        "topology:\n  num_nodes: 2\n  algorithm: explicit\n"
        "  params: {adjacency: [[n01, n02, udp]]}\n"
        f"assertions:\n  edge_agreement: {{{body}}}\n"
        f"logging: {{rust_log: \"{rust_log}\"}}\n"
    )


def _agreement_refused(text: str) -> bool:
    """True when loading refuses ``text`` for its edge_agreement block."""
    try:
        _scenario(text)
    except ValueError as e:
        return "edge_agreement" in str(e)
    return False


@case("edge_agreement loads with its bound and floor and logs crossings at debug", True)
def _():
    text = _agreement_scenario("debug", within_secs=90, min_crossings=2)
    ea = _scenario(text).assertions.edge_agreement
    return (ea.within_secs, ea.min_crossings, ea.crossings_logged) == (90, 2, True)


@case("edge_agreement refuses an unknown key", True)
def _():
    return _agreement_refused(_agreement_scenario("debug", min_crossing=2))


@case("min_crossings 2 at rust_log info is refused at load", True)
def _():
    return _agreement_refused(_agreement_scenario("info", min_crossings=2))


@case("min_crossings 2 with only the handshake target at debug is refused at load", True)
def _():
    return _agreement_refused(
        _agreement_scenario("fips::node::handlers::handshake=debug", min_crossings=2))


@case("min_crossings 2 at debug with fips::node at info is refused at load", True)
def _():
    return _agreement_refused(_agreement_scenario("debug,fips::node=info", min_crossings=2))


@case("edge_agreement with no floor loads at rust_log info", True)
def _():
    ea = _scenario(_agreement_scenario("info")).assertions.edge_agreement
    return ea is not None and ea.min_crossings == 0 and not ea.crossings_logged


def _transport_scenario(topology: str, agreement: bool = True) -> str:
    """A three-node scenario whose ``topology`` lines name its transports."""
    return (
        "scenario: {name: agree, duration_secs: 60}\n"
        f"topology:\n  num_nodes: 3\n{topology}"
        + ("assertions:\n  edge_agreement: {}\n" if agreement else "")
    )


_REFUSED_TOPOLOGIES = {
    "an explicit udp-veth edge":
        "  algorithm: explicit\n  params: {adjacency: [[n01, n02, udp-veth], [n02, n03, udp]]}\n",
    "an explicit ethernet+udp edge":
        "  algorithm: explicit\n  params: {adjacency: [[n01, n02, ethernet+udp], [n02, n03]]}\n",
    "an explicit udp-veth+udp edge":
        "  algorithm: explicit\n  params: {adjacency: [[n01, n02, udp-veth+udp], [n02, n03]]}\n",
    "udp-veth in transport_mix":
        "  algorithm: chain\n  transport_mix: {udp: 0.5, udp-veth: 0.5}\n",
    "udp-veth as default_transport":
        "  algorithm: chain\n  default_transport: udp-veth\n",
}

for _what, _topology_text in _REFUSED_TOPOLOGIES.items():
    @case(f"edge_agreement on a scenario with {_what} is refused at load", True)
    def _(text=_topology_text):
        _scenario(_transport_scenario(text, agreement=False))   # loads without it
        return _agreement_refused(_transport_scenario(text))


@case("edge_agreement with peer_churn is refused at load", True)
def _():
    return _agreement_refused(
        _transport_scenario("  algorithm: chain\n")
        + "peer_churn: {enabled: true, interval_secs: {min: 30, max: 60}}\n"
    )


def main() -> int:
    """Run every case; print each verdict; fail on any unexpected one."""
    bad = 0
    for name, expect, fn in CASES:
        try:
            got = fn()
        except Exception as e:  # a crash is never the verdict sought
            print(f"ERROR {name}: {type(e).__name__}: {e}")
            bad += 1
            continue
        passed = got.passed if isinstance(got, A.AssertionOutcome) else bool(got)
        ok = passed == expect
        print(f"{'ok  ' if ok else 'FAIL'} {name} (verdict {'pass' if passed else 'fail'})")
        if VERBOSE or not ok:
            if isinstance(got, A.AssertionOutcome):
                print(f"     {got.detail}")
        bad += not ok
    print(f"sim-assert-test: {len(CASES) - bad} of {len(CASES)} cases gave their expected verdict")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
