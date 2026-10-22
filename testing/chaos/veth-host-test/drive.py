#!/usr/bin/env python3
"""Drive the chaos runner's veth setup against the stand-in docker.

Two modes, both run from veth-host-test.sh with the fake docker first on PATH:

  pair SIM_PARENT       set up one Ethernet pair, n01--n02, through
                        VethManager.setup_all, and print RESULT ok or
                        RESULT VethSetupError with the elapsed time
  runner SIM_PARENT SCENARIO
                        run the whole runner on SCENARIO, as `python -m sim`
                        does, and print RESULT exit=N

SIM_PARENT is the directory holding the `sim` package under test. When
HOST_TIMEOUT is set in the environment it replaces the module's bound on a
host command, so the cases that time a command out twice need not wait for
the real bound twice. A tree with no such bound ignores it.
"""

from __future__ import annotations

import logging
import os
import sys
import time
import types


class PairTopology:
    """The parts of SimTopology that VethManager reads, for one pair."""

    veth_token = ""

    def __init__(self):
        self.nodes = {
            n: types.SimpleNamespace(ethernet_macs={}) for n in ("n01", "n02")
        }

    def ethernet_edges(self):
        """The one Ethernet edge."""
        return [("n01", "n02")]

    def container_name(self, node_id):
        """Container name for a node, as the runner renders it."""
        return f"fips-node-{node_id}"

    def veth_host_name(self, a, b, end):
        """Temporary host-side name for one end of a pair."""
        return f"vh{a[1:]}{b[1:]}{end}"


def apply_timeout(veth) -> None:
    """Shorten the host-command bound when the case asks for it."""
    value = os.environ.get("HOST_TIMEOUT")
    if value:
        veth.HOST_CMD_TIMEOUT_SECS = float(value)


def run_pair() -> int:
    """Set up the pair and report how it ended."""
    from sim import veth

    apply_timeout(veth)
    mgr = veth.VethManager(PairTopology())
    start = time.monotonic()
    try:
        mgr.setup_all()
    except veth.VethSetupError as e:
        print(f"RESULT VethSetupError after {time.monotonic() - start:.1f}s: {e}")
        return 0
    print(f"RESULT ok after {time.monotonic() - start:.1f}s pairs={len(mgr._host_pairs)}")
    return 0


def run_runner(scenario: str) -> int:
    """Run the runner's own entry point and report its exit status."""
    from sim import veth
    from sim.__main__ import main

    apply_timeout(veth)
    sys.argv = ["sim", scenario]
    try:
        main()
        code = 0
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    print(f"RESULT exit={code}", flush=True)
    return 0


def entry() -> int:
    """Parse the mode and run it."""
    mode, sim_parent = sys.argv[1], sys.argv[2]
    sys.path.insert(0, sim_parent)
    if mode == "pair":
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
        return run_pair()
    if mode == "runner":
        return run_runner(sys.argv[3])
    print(f"drive.py: unknown mode {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(entry())
