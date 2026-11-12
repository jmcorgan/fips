#!/usr/bin/env python3
"""Hermetic tests of the chaos assertions that read path lines, and of the
Ethernet kernel drop ceiling, which reads the final congestion snapshot.

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
