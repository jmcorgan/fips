#!/usr/bin/env python3
"""Hermetic tests of the compose file the chaos simulator writes: every node
is given fixed worker-pool sizes, whatever host renders it.

Left to itself the node sizes its encrypt and decrypt worker pools by the
host's CPU count, and each decrypt worker holds about 51 MiB from startup.
On the 20-CPU builder that put every chaos node at about 1.05 GiB, and two
nightly chaos parts whose long scenarios overlapped ran the host out of
memory: the kernel's OOM killer took nodes from both runs, and each run's
scenario failed at its next step on a node that was gone. The compose file
now pins both pools (testing/chaos/sim/compose.py, WORKERS_DEFAULT).

Each case renders the compose file for a scenario from
testing/chaos/scenarios/ with the simulator's own code, reads it back as
YAML (so the `<<: *fips-common` merge is resolved as compose resolves it),
and checks every service's environment. A further case checks that the
variable names the compose file sets are the ones the node reads, so a
rename in the node cannot leave the pins setting nothing.

Usage: testing/chaos/sim-compose-test.py [-v]
Exit:  0 every case passed, 1 a case failed, 2 the test could not run.
"""

from __future__ import annotations

import os
import random
import re
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True

from sim import compose as C  # noqa: E402
from sim.scenario import load_scenario  # noqa: E402
from sim.topology import generate_topology  # noqa: E402

VERBOSE = "-v" in sys.argv[1:]
SCENARIOS = HERE / "scenarios"
WORKER_VARS = ("FIPS_ENCRYPT_WORKERS", "FIPS_DECRYPT_WORKERS")

# The most decrypt workers a chaos node may be given. Each holds about 51 MiB
# from startup (measured on core-vm: 1.03 GiB at 20 decrypt workers, 0.12 GiB
# at 2), so 4 keeps a node near 0.23 GiB, and the nightly chaos part's
# long-scenario tail (72 nodes) near 17 GiB rather than 76 GiB.
MAX_DECRYPT = 4


class Failed(Exception):
    """A case's check did not hold."""


def render(scenario: str, env: dict[str, str]) -> dict[str, dict[str, str]]:
    """Each service's merged environment in the compose file for ``scenario``.

    ``env`` replaces the worker variables in this process's environment for
    the render; a name absent from it is unset.
    """
    s = load_scenario(str(SCENARIOS / f"{scenario}.yaml"))
    topo = generate_topology(s.topology, random.Random(s.seed), "sim-compose-test")
    saved = {k: os.environ.pop(k) for k in WORKER_VARS if k in os.environ}
    os.environ.update(env)
    try:
        with tempfile.TemporaryDirectory() as out:
            path = C.generate_compose(topo, s, out, "sim-compose-test-net")
            doc = yaml.safe_load(Path(path).read_text())
    finally:
        for k in WORKER_VARS:
            os.environ.pop(k, None)
        os.environ.update(saved)
    services = doc.get("services") or {}
    if len(services) != len(topo.nodes):
        raise Failed(f"{scenario}: {len(services)} services for {len(topo.nodes)} nodes")
    result = {}
    for name, svc in services.items():
        pairs = (str(e).split("=", 1) for e in svc.get("environment") or [])
        result[name] = {p[0]: p[1] for p in pairs if len(p) == 2}
    return result


def expect_counts(scenario: str, env: dict[str, str], want: dict[str, str]) -> None:
    """Every service in ``scenario``'s compose file carries exactly ``want``."""
    for svc, envs in render(scenario, env).items():
        for var, value in want.items():
            got = envs.get(var)
            if got != value:
                raise Failed(f"{scenario}: service {svc} has {var}={got!r}, want {value!r}")


def case_every_scenario_pins_both_pools() -> None:
    """Unset in the environment, every node of every scenario gets the default."""
    want = {v: str(C.WORKERS_DEFAULT) for v in WORKER_VARS}
    names = sorted(p.stem for p in SCENARIOS.glob("*.yaml"))
    if not names:
        raise Failed(f"no scenarios under {SCENARIOS}")
    for name in names:
        expect_counts(name, {}, want)


def case_default_bounds_decrypt_memory() -> None:
    """The default decrypt pool stays within the per-node memory budget."""
    if not 1 <= C.WORKERS_DEFAULT <= MAX_DECRYPT:
        raise Failed(f"WORKERS_DEFAULT={C.WORKERS_DEFAULT}, want 1..{MAX_DECRYPT}")


def case_override_passes_through() -> None:
    """A count in the simulation's environment reaches every node."""
    env = {"FIPS_ENCRYPT_WORKERS": "3", "FIPS_DECRYPT_WORKERS": "0"}
    expect_counts("maelstrom", env, env)


def case_empty_override_is_the_default() -> None:
    """An empty variable, as a `${X:-}` passthrough leaves it, is unset."""
    want = {v: str(C.WORKERS_DEFAULT) for v in WORKER_VARS}
    expect_counts("dead-grace-long", {v: "" for v in WORKER_VARS}, want)


def case_bad_override_is_refused() -> None:
    """An override the node could not parse stops the render."""
    for bad in ("auto", "-1", "2.5", "²"):
        try:
            render("dead-grace-long", {"FIPS_DECRYPT_WORKERS": bad})
        except ValueError:
            continue
        raise Failed(f"FIPS_DECRYPT_WORKERS={bad!r} rendered")


def case_node_reads_these_names() -> None:
    """The node reads each variable the compose file sets, by that name."""
    sources = "\n".join(p.read_text() for p in (ROOT / "src").rglob("*.rs"))
    for var in WORKER_VARS:
        if not re.search(rf'env::var\(\s*"{var}"\s*\)', sources):
            raise Failed(f"no env::var(\"{var}\") under src/")


CASES: list[Callable[[], None]] = [
    case_every_scenario_pins_both_pools,
    case_default_bounds_decrypt_memory,
    case_override_passes_through,
    case_empty_override_is_the_default,
    case_bad_override_is_refused,
    case_node_reads_these_names,
]


def main() -> int:
    """Run every case and report each failure."""
    if not (ROOT / "src").is_dir():
        print(f"sim-compose-test: no src/ under {ROOT}", file=sys.stderr)
        return 2
    bad = 0
    for case in CASES:
        try:
            case()
        except Failed as e:
            bad += 1
            print(f"FAIL {case.__name__}: {e}")
            continue
        if VERBOSE:
            print(f"ok   {case.__name__}")
    print(f"sim-compose-test: {len(CASES) - bad} of {len(CASES)} cases passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
