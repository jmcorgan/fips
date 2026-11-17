#!/usr/bin/env python3
"""Hermetic tests of how the chaos harness takes a link down.

A down holds both directions of an edge at 100% loss, each by a ``docker
exec`` into its own container. Under host load one exec can take hundreds of
ms, so the two must be issued at once: cut one after the other, the down is
one-way for the length of the first, and the end whose frames go first keeps
hearing its peer and switches late by that gap. These cases stand in an
install that meets the other direction's at a barrier for the exec, with no
container, and check that the two directions' installs run at the same time,
that the down is stamped at the earlier cut whichever direction it was, that
the log line gives the gap between the two cuts, and that a scheduled down
whose either direction did not install is an error that records no down.

Usage: testing/chaos/sim-links-test.py [-v]
Exit:  0 every case passed, 1 otherwise.
"""

from __future__ import annotations

import os
import random
import sys
import threading
import time
import unittest
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from sim.links import LinkManager  # noqa: E402
from sim.scenario import LinkFlapsConfig  # noqa: E402
from sim.schedule import StepError  # noqa: E402

A, B = "n01", "n02"

# How long one direction's install waits for the other's to start before it
# is taken as run apart. Only a failing case waits it out, so it is set far
# above any thread start-up delay on a loaded host.
WAIT = 5.0


class SlowInstall:
    """A stand-in for ``LinkManager._set_held`` that records whether the
    two directions' installs ran at the same time.

    Each install waits at a two-party barrier for the other: run together,
    both pass it at once; run one after the other, the first waits ``WAIT``
    and the barrier breaks. That holds however slowly the host schedules
    the threads, unlike comparing the installs' start and end times.

    ``stamps`` gives the stamp each direction returns, by ``(src, dst)``;
    a direction absent from it returns the wall clock at its start, and one
    mapped to None did not install."""

    def __init__(self, stamps: dict[tuple[str, str], float | None] | None = None):
        self.stamps = stamps or {}
        self.calls: list[tuple[str, str]] = []
        self.apart = False
        self.barrier = threading.Barrier(2)
        self.lock = threading.Lock()

    def __call__(self, src: str, dst: str, held: bool) -> float | None:
        """Install ``src -> dst``, meeting the other direction; return its stamp."""
        wall = time.time()
        with self.lock:
            self.calls.append((src, dst))
        try:
            self.barrier.wait(timeout=WAIT)
        except threading.BrokenBarrierError:
            with self.lock:
                self.apart = True
        return self.stamps.get((src, dst), wall)

    def overlapped(self) -> bool:
        """Whether the two directions' installs ran at the same time."""
        return sorted(self.calls) == sorted([(A, B), (B, A)]) and not self.apart


def manager(install: SlowInstall) -> LinkManager:
    """A link manager over one edge whose installs are ``install``."""
    topology = SimpleNamespace(edges=[(A, B)])
    lm = LinkManager(topology, LinkFlapsConfig(), random.Random(0))
    lm._set_held = install
    return lm


class LinkDown(unittest.TestCase):
    """The random flap's down, ``LinkManager._link_down``."""

    def test_random_down_installs_both_directions_at_once(self):
        install = SlowInstall()
        manager(install)._link_down((A, B), 10.0)
        self.assertTrue(install.overlapped(), f"installs ran apart: {install.calls}")

    def test_random_down_is_stamped_at_the_earlier_cut(self):
        for ab, ba in ((1000.25, 1000.0), (1000.0, 1000.25)):
            with self.subTest(ab=ab, ba=ba):
                lm = manager(SlowInstall({(A, B): ab, (B, A): ba}))
                lm._link_down((A, B), 10.0)
                self.assertEqual(lm.link_states[(A, B)].down_since, 1000.0)
                self.assertEqual(lm.flap_events, [(1000.0, "down", A, B)])

    def test_random_down_logs_how_far_apart_the_two_cuts_were(self):
        lm = manager(SlowInstall({(A, B): 1000.049, (B, A): 1000.0}))
        with self.assertLogs("sim.links", "INFO") as logs:
            lm._link_down((A, B), 10.0)
        self.assertIn(f"one-way gap 49.0 ms, {B}->{A} cut first", logs.output[-1])

    def test_random_down_uses_the_stamp_that_installed_when_the_other_did_not(self):
        install = SlowInstall({(A, B): None, (B, A): 1000.5})
        lm = manager(install)
        lm._link_down((A, B), 10.0)
        self.assertEqual(lm.link_states[(A, B)].down_since, 1000.5)

    def test_random_down_falls_back_to_the_host_clock_when_neither_installed(self):
        install = SlowInstall({(A, B): None, (B, A): None})
        lm = manager(install)
        before = time.time()
        lm._link_down((A, B), 10.0)
        since = lm.link_states[(A, B)].down_since
        self.assertTrue(before <= since <= before + 0.05, since)


class ScriptedDown(unittest.TestCase):
    """A scheduled step's two-way down, ``scripted_down`` in ``netem`` mode."""

    def test_scheduled_netem_down_installs_both_directions_at_once(self):
        install = SlowInstall()
        manager(install).scripted_down((A, B), "netem", None, 10.0)
        self.assertTrue(install.overlapped(), f"installs ran apart: {install.calls}")

    def test_scheduled_netem_down_returns_the_earlier_cut(self):
        for ab, ba in ((1000.0, 1000.25), (1000.25, 1000.0)):
            with self.subTest(ab=ab, ba=ba):
                lm = manager(SlowInstall({(A, B): ab, (B, A): ba}))
                self.assertEqual(lm.scripted_down((A, B), "netem", None, 10.0), 1000.0)
                self.assertEqual(lm.flap_events, [(1000.0, "down", A, B)])

    def test_scheduled_netem_down_logs_how_far_apart_the_two_cuts_were(self):
        lm = manager(SlowInstall({(A, B): 1000.0, (B, A): 1000.049}))
        with self.assertLogs("sim.links", "INFO") as logs:
            lm.scripted_down((A, B), "netem", None, 10.0)
        self.assertIn(f"one-way gap 49.0 ms, {A}->{B} cut first", logs.output[-1])

    def test_scheduled_netem_down_fails_when_either_direction_did_not_install(self):
        for missing in ((A, B), (B, A)):
            with self.subTest(missing=missing):
                lm = manager(SlowInstall({missing: None}))
                with self.assertRaisesRegex(StepError, f"netem down of {A}--{B} did not install"):
                    lm.scripted_down((A, B), "netem", None, 10.0)
                self.assertEqual(lm.flap_events, [])
                self.assertFalse(lm.link_states[(A, B)].is_down)

if __name__ == "__main__":
    verbosity = 2 if "-v" in sys.argv[1:] else 1
    result = unittest.main(argv=[sys.argv[0]], verbosity=verbosity, exit=False).result
    sys.exit(0 if result.wasSuccessful() else 1)
