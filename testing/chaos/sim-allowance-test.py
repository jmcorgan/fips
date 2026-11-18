#!/usr/bin/env python3
"""Hermetic tests of the switch ceiling's allowance for the probe timeout.

``switch_latency`` with ``timeout_allowance`` adds to each end's ceiling for a
down the part above the 400 ms floor of the probe timeout the end had in
force when the down's path went Suspect: the ``timeout_ms`` of its "Path state
changed" line from ``Some(Live)`` to ``Some(Suspect)`` for ``why=Timeout``.
These cases plant those lines and the switches, with no container, and check
that an unloaded host is held to the ceiling as written, that a long timeout
explains a late switch and a floor timeout does not, that a timeout of
another path, peer, end, change or down is never used, that an end with no
such line gets no allowance and says so, and that the verdict prints each
end's base, allowance and the timeout it came from. The floor it subtracts is
checked against the node's, and the loader's side too: the key is refused
without the debug lines it reads, and the two flap suites set it.

Usage: testing/chaos/sim-allowance-test.py [-v]
Exit:  0 every case passed, 1 otherwise.
"""

from __future__ import annotations

import logging
import os
import sys
import unittest
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from sim import assertions as A  # noqa: E402
from sim import scenario as S  # noqa: E402

# The planted failures log warnings on purpose.
logging.getLogger("sim").addHandler(logging.NullHandler())

T0 = 1793650000.0
N1 = "fips-node-n01"
N2 = "fips-node-n02"
# The down's path at each end: the other end's veth address.
VETH = {N1: "10.222.0.2", N2: "10.222.0.1"}
# Each end's other path to the same peer, over the bridge.
BRIDGE = {N1: "172.20.0.3", N2: "172.20.0.2"}
PEER = {N1: "npub1n02...aaaa", N2: "npub1n01...bbbb"}
ADDRS = {(T0, end): {ip} for end, ip in VETH.items()}


def stamp(t: float) -> str:
    """The node's own timestamp for epoch ``t``."""
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def switched(t: float, end: str) -> tuple[str, str]:
    """``end``'s "Path switched" line at ``t``, onto its bridge path."""
    return end, (
        f"{stamp(t)}  INFO fips::node::handlers::path: Path switched "
        f"peer={PEER[end]} from={VETH[end]}:2121 to={BRIDGE[end]}:2121 "
        f"transport_id=transport:1 why=\"mandatory\""
    )


def suspect(t: float, end: str, timeout_ms: int | None, addr: str | None = None,
            peer: str | None = None, frm: str = "Some(Live)",
            nxt: str = "Some(Suspect)", why: str = "Timeout") -> tuple[str, str]:
    """``end``'s "Path state changed" line at ``t``, by default its veth
    path going from Live to Suspect for a timeout, as the node writes it:
    ``timeout_ms`` after ``why``, and absent when the node had none."""
    tail = "" if timeout_ms is None else f" timeout_ms={timeout_ms}"
    return end, (
        f"{stamp(t)} DEBUG fips::node::handlers::path: Path state changed "
        f"peer={peer or PEER[end]} transport_id=transport:2 "
        f"remote_addr={addr or VETH[end]}:2122 path_id=7 from={frm} next={nxt} "
        f"why={why}{tail}"
    )


def verdict(lines: list[tuple[str, str]], allow: bool = True,
            downs: list[tuple[float, str, str]] | None = None) -> A.AssertionOutcome:
    """``switch_latency`` at 1300 ms each end over ``lines``: the planted
    switches and state changes, for one down at T0 unless ``downs`` says."""
    downs = downs or [(T0, N1, N2)]
    switches = [x for x in lines if "Path switched" in x[1]]
    paths = [x for x in lines if "Path state changed" in x[1]] + switches
    cfg = S.SwitchLatencyAssertion(max_ms=1300, each_end=True, timeout_allowance=allow)
    timeouts = A.switch_timeouts(downs, switches, paths, ADDRS)
    return A.evaluate_switch_latency(cfg, downs, switches, timeouts=timeouts)


def at_both(delay: float, timeout_ms: int | None, extra=()) -> list[tuple[str, str]]:
    """Both ends going Suspect ``delay`` s after the down under
    ``timeout_ms`` (no line for None) and switching at that instant."""
    lines = list(extra)
    for end in (N1, N2):
        if timeout_ms is not None:
            lines.append(suspect(T0 + delay, end, timeout_ms))
        lines.append(switched(T0 + delay, end))
    return lines


class Unloaded(unittest.TestCase):
    """A timeout at its floor earns nothing: the ceiling is 1300 ms."""

    def test_switches_at_the_floor_timeout_pass_with_an_allowance_of_0(self):
        out = verdict(at_both(1.2, 400))
        self.assertTrue(out.passed, out.detail)
        self.assertIn("base 1300 + allowance 0 = 1300, from timeout_ms 400", out.detail)

    def test_a_switch_1301_ms_after_the_down_fails_at_the_floor_timeout(self):
        out = verdict(at_both(1.301, 400))
        self.assertFalse(out.passed, out.detail)

    def test_a_switch_1300_ms_after_the_down_passes_at_the_floor_timeout(self):
        out = verdict(at_both(1.300, 400))
        self.assertTrue(out.passed, out.detail)


class Loaded(unittest.TestCase):
    """A timeout stretched by load is allowed for, by its excess over 400 ms."""

    def test_a_long_timeout_explains_a_late_switch(self):
        out = verdict(at_both(1.55, 700))
        self.assertTrue(out.passed, out.detail)
        self.assertIn("base 1300 + allowance 300 = 1600, from timeout_ms 700", out.detail)

    def test_a_switch_later_than_the_long_timeout_allows_still_fails(self):
        out = verdict(at_both(1.65, 700))
        self.assertFalse(out.passed, out.detail)
        self.assertIn("allowance 300 = 1600", out.detail)

    def test_each_end_takes_its_own_timeout(self):
        lines = [
            suspect(T0 + 1.55, N1, 700), switched(T0 + 1.55, N1),
            suspect(T0 + 1.55, N2, 400), switched(T0 + 1.55, N2),
        ]
        out = verdict(lines)
        self.assertFalse(out.passed, out.detail)
        self.assertIn(f"{N2} after", out.detail)
        self.assertNotIn(f"{N1} after", out.detail)

    def test_without_the_key_a_long_timeout_allows_nothing(self):
        out = verdict(at_both(1.55, 700), allow=False)
        self.assertFalse(out.passed, out.detail)
        self.assertNotIn("allowance", out.detail)


class SlowAtTheFloor(unittest.TestCase):
    """A slow switch whose timeout was at the floor is the node's to answer."""

    def test_a_slow_switch_under_a_floor_timeout_fails(self):
        out = verdict(at_both(1.35, 400))
        self.assertFalse(out.passed, out.detail)
        self.assertIn("allowance 0 = 1300, from timeout_ms 400", out.detail)


class NotThisDown(unittest.TestCase):
    """A long timeout logged anywhere but on this down's path, at this end,
    for this change, between the down and the end's switch, is not used.
    n01 switches late and logs no timeout line of its own, so only the stray
    line could pass it; n02 switches in time at the floor."""

    def stray(self, line: tuple[str, str]) -> A.AssertionOutcome:
        """n01 switching 1.5 s after the down with no Suspect line, and n02
        at 1.2 s at the floor, with ``line`` planted beside them."""
        return verdict([
            line, switched(T0 + 1.5, N1),
            suspect(T0 + 1.2, N2, 400), switched(T0 + 1.2, N2),
        ])

    def test_the_stray_line_on_this_downs_path_would_pass_the_switch(self):
        # The control: the same line, on n01's veth path in the window,
        # is used, so every case below fails only for where its line is.
        out = self.stray(suspect(T0 + 1.4, N1, 900))
        self.assertTrue(out.passed, out.detail)

    def test_a_timeout_of_the_ends_other_path_is_not_used(self):
        out = self.stray(suspect(T0 + 1.4, N1, 900, addr=BRIDGE[N1]))
        self.assertFalse(out.passed, out.detail)
        self.assertIn(f"{N1} after", out.detail)

    def test_a_timeout_of_another_peer_is_not_used(self):
        # Peers are told apart by address, as each veth edge has its own;
        # the line's peer field is not read.
        out = self.stray(suspect(T0 + 1.4, N1, 900, addr="10.222.5.9", peer="npub1n05...cccc"))
        self.assertFalse(out.passed, out.detail)
        self.assertIn(f"{N1} after", out.detail)

    def test_a_timeout_logged_by_the_other_end_is_not_used(self):
        # N2's line on N1's veth address: right path, wrong end.
        out = self.stray(suspect(T0 + 1.4, N2, 900, addr=VETH[N1]))
        self.assertFalse(out.passed, out.detail)

    def test_a_timeout_of_an_earlier_down_is_not_used(self):
        out = self.stray(suspect(T0 - 30.0, N1, 900))
        self.assertFalse(out.passed, out.detail)
        self.assertIn(f"{N1} after", out.detail)

    def test_a_timeout_after_the_ends_switch_is_not_used(self):
        out = self.stray(suspect(T0 + 1.6, N1, 900))
        self.assertFalse(out.passed, out.detail)
        self.assertIn(f"{N1} after", out.detail)

    def test_the_last_suspect_change_before_the_switch_is_the_one_used(self):
        # The path went Suspect at the floor, came back and went Suspect
        # again under 900 ms just before the switch: the switch followed
        # the second.
        out = verdict([
            suspect(T0 + 0.5, N1, 400), suspect(T0 + 1.4, N1, 900),
            switched(T0 + 1.5, N1),
            suspect(T0 + 1.2, N2, 400), switched(T0 + 1.2, N2),
        ])
        self.assertTrue(out.passed, out.detail)
        self.assertIn("allowance 500 = 1800, from timeout_ms 900", out.detail)

    def test_a_timeout_of_the_next_down_is_not_used(self):
        # A second down at T0 + 40: its Suspect line belongs to it alone.
        later = T0 + 40.0
        downs = [(T0, N1, N2), (later, N1, N2)]
        for end in (N1, N2):
            ADDRS[(later, end)] = {VETH[end]}
        try:
            lines = at_both(1.5, 400) + [
                suspect(later + 1.5, N1, 900), switched(later + 1.5, N1),
                suspect(later + 1.2, N2, 400), switched(later + 1.2, N2),
            ]
            out = verdict(lines, downs=downs)
        finally:
            for end in (N1, N2):
                del ADDRS[(later, end)]
        self.assertFalse(out.passed, out.detail)
        self.assertIn(f"{N1} after {N1}--{N2} down at", out.detail)
        self.assertIn("allowance 500 = 1800, from timeout_ms 900", out.detail)

    def test_a_line_at_or_after_the_next_down_is_not_this_downs_even_before_the_ends_switch(self):
        # n01 switches only after a second down at T0 + 40, and logs Suspect
        # lines on the same path in between, the first at the second down's
        # own stamp: they are the second down's, and the first down's window
        # ends at the second down.
        later = T0 + 40.0
        downs = [(T0, N1, N2), (later, N1, N2)]
        addrs = {(t, end): {ip} for t in (T0, later) for end, ip in VETH.items()}
        switches = [switched(later + 1.5, N1)]
        paths = [suspect(later, N1, 700), suspect(later + 1.4, N1, 900)] + switches
        got = A.switch_timeouts(downs, switches, paths, addrs)
        self.assertEqual(got, {(later, N1): 900})

    def test_a_timeout_of_another_change_is_not_used(self):
        for frm, nxt, why in (
            ("Some(Suspect)", "Some(Dead)", "Retired"),
            ("Some(Live)", "Some(Suspect)", "Carrier"),
        ):
            with self.subTest(why=why):
                out = self.stray(suspect(T0 + 1.4, N1, 900, frm=frm, nxt=nxt, why=why))
                self.assertFalse(out.passed, out.detail)
                self.assertIn(f"{N1} after", out.detail)


class Missing(unittest.TestCase):
    """An end with no timeout line for the down gets no allowance."""

    def test_a_switch_with_no_suspect_line_gets_no_allowance_and_says_so(self):
        out = verdict(at_both(1.35, None))
        self.assertFalse(out.passed, out.detail)
        self.assertIn("allowance 0 = 1300, no Live to Suspect timeout line", out.detail)

    def test_a_suspect_line_without_timeout_ms_gets_no_allowance(self):
        # A node built before the field: the line is there, the value is not.
        lines = [suspect(T0 + 1.35, end, None) for end in (N1, N2)]
        out = verdict(at_both(1.35, None, extra=lines))
        self.assertFalse(out.passed, out.detail)
        self.assertIn("no Live to Suspect timeout line", out.detail)

    def test_an_unloaded_switch_with_no_suspect_line_still_passes(self):
        out = verdict(at_both(1.2, None))
        self.assertTrue(out.passed, out.detail)


class Floor(unittest.TestCase):
    """The floor the allowance subtracts is the node's."""

    def test_the_floor_is_the_probe_timeout_floor_the_node_is_built_with(self):
        # The node takes its probe timeout floor from Config::draft(), which
        # no node setting overrides; a change there must change the harness.
        import re

        params = os.path.join(HERE, "..", "..", "core", "src", "proto", "path", "params.rs")
        with open(params) as f:
            text = f.read()
        draft = text[text.index("pub const fn draft()"):]
        got = re.search(r"\btimeout: Duration::from_millis\((\d+)\)", draft)
        self.assertIsNotNone(got, "no timeout floor in Config::draft()")
        self.assertEqual(int(got.group(1)), A.TIMEOUT_FLOOR_MS)


class Loader(unittest.TestCase):
    """The scenario key, and the suites that set it."""

    def scenario(self, rust_log: str, allow) -> dict:
        """A minimal two-node scenario with ``switch_latency`` and
        ``timeout_allowance`` set to ``allow``."""
        return {
            "scenario": {"name": "t", "seed": 1, "duration_secs": 60},
            "topology": {"algorithm": "chain", "num_nodes": 2},
            "assertions": {
                "switch_latency": {"max_ms": 1300, "each_end": True,
                                   "timeout_allowance": allow},
            },
            "logging": {"rust_log": rust_log},
        }

    def load(self, raw: dict):
        """Load ``raw`` through the scenario loader's YAML path."""
        import tempfile

        import yaml

        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(raw, f)
        try:
            return S.load_scenario(f.name)
        finally:
            os.unlink(f.name)

    def test_the_key_is_refused_without_the_paths_debug_lines(self):
        with self.assertRaisesRegex(ValueError, "timeout_allowance reads debug lines"):
            self.load(self.scenario("info", True))

    def test_the_key_loads_with_the_paths_debug_lines(self):
        s = self.load(self.scenario("info,fips::node::handlers::path=debug", True))
        self.assertTrue(s.assertions.switch_latency.timeout_allowance)

    def test_the_key_must_be_a_boolean(self):
        with self.assertRaisesRegex(ValueError, "must be true or false"):
            self.load(self.scenario("info,fips::node::handlers::path=debug", "yes"))

    def test_both_flap_suites_take_the_allowance_at_1300_ms(self):
        for name in ("dual-path-flap", "dual-udp-flap"):
            with self.subTest(name=name):
                s = S.load_scenario(os.path.join(HERE, "scenarios", f"{name}.yaml"))
                sl = s.assertions.switch_latency
                self.assertEqual((sl.max_ms, sl.each_end, sl.timeout_allowance),
                                 (1300, True, True))


if __name__ == "__main__":
    verbosity = 2 if "-v" in sys.argv[1:] else 1
    result = unittest.main(argv=[sys.argv[0]], verbosity=verbosity, exit=False).result
    sys.exit(0 if result.wasSuccessful() else 1)
