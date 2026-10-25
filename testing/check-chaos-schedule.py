#!/usr/bin/env python3
"""Fail when a chaos scenario's seeded draws depend on Python's string hash seed.

The chaos simulator draws its schedule from streams seeded by the scenario's
`seed`. Iterating a set of strings gives an order that follows the
interpreter's per-process string hash seed, which is random unless
PYTHONHASHSEED is set. Wherever that order decides which edge a draw lands
on, "seed 42" draws a different schedule on every run, a floor is calibrated
on a moving target, and a red run cannot be replayed. Nothing in a single run
shows it, so this check runs the draws under several hash seeds and compares.

How: the parent runs this file again as a child (`--emit <case>`) once per
PYTHONHASHSEED in HASH_SEEDS, with one seed repeated. Each child loads
testing/chaos/scenarios/churn-mixed.yaml, builds the topology and the netem,
link-flap, node-churn and peer-churn managers from the simulator's own
classes, replaces their side-effecting methods with recorders, drives a few
rounds of each, and prints every draw. Each manager gets its own stream, so
one site's dependence can neither hide nor be blamed on another's. Cases:

  ci   churn-mixed at 10 nodes, the invocation local and GitHub CI gate on;
  all  churn-mixed at its own 20 nodes, with ingress policing (four tiers)
       and peer churn turned on, so every known site is exercised. 20 nodes
       is what makes the dial-direction site reliably visible.

A child's printed outbound lists are sorted per node, because the generated
config sorts them; only which node dials which reaches a run.

Before it compares anything, the parent requires proof that the comparison
can see a difference:

  - the repeated hash seed printed the same `hash()` value both times, and
    the distinct seeds printed distinct ones. Under `python -E` or `-I` the
    interpreter ignores PYTHONHASHSEED and randomises every process, which
    the repeat catches and distinctness alone does not;
  - the repeated seed printed the same draws both times, so a difference
    between the other seeds can be put down to the hash seed and not to some
    other source of variation;
  - a control draw, made on purpose over the unsorted edge set, differed
    between the distinct seeds, so a site that walks the set unsorted would
    show here.

The recorders replace private methods by name. Each name is checked to exist
on its class first, because assigning to a renamed method succeeds silently
and the real one would then run `docker`; subprocess is also disabled in the
child as a backstop. A rename in testing/chaos/sim/ therefore exits 2 here
and needs the matching one-line change in STUBS.

Runs the simulator from disk beside this file, needs pyyaml and nothing
built, and takes a few seconds.

Exit codes:
    0 - every draw identical across the hash seeds
    1 - a draw differs between two hash seeds; the key and seeds are named
    2 - the check could not run or could not show it can see a difference
        (a child failed, a key was missing or empty, or a proof above
        failed); never a pass
"""

from __future__ import annotations

import os
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHAOS_DIR = HERE / "chaos"
SCENARIO = CHAOS_DIR / "scenarios" / "churn-mixed.yaml"

DISTINCT_SEEDS = ("0", "1", "2", "3")
REPEAT_SEED = "1"
HASH_SEEDS = DISTINCT_SEEDS + (REPEAT_SEED,)

HASH_PROBE = "chaos-schedule-probe"
ROUNDS = 3
CHILD_TIMEOUT_SECS = 120

# Draw keys each case must print, all non-empty, in report order. "control"
# is the deliberately unsorted draw and is not compared as a draw.
CASES: dict[str, tuple[str, ...]] = {
    "ci": ("outbound", "tiers", "mutate", "flaps", "nodechurn"),
    "all": ("outbound", "tiers", "ingress", "mutate", "flaps", "nodechurn", "peerchurn"),
}

# (module, class, method) replaced by a recorder in the child.
STUBS = (
    ("netem", "NetemManager", "_update_link"),
    ("links", "LinkManager", "_link_down"),
    ("nodes", "NodeManager", "_stop_node"),
    ("peer_churn", "PeerChurnManager", "_disconnect_edge"),
    ("peer_churn", "PeerChurnManager", "_connect_edge"),
)


class GuardError(Exception):
    """The child cannot set up a faithful run of the draws."""


def _forbidden(*args, **kwargs):
    """Stand in for subprocess.Popen, so no stray call can reach docker."""
    raise GuardError(f"a simulator call tried to run a command: {args[:1]!r}")


def _check_stubs(modules: dict) -> None:
    """Fail unless every method STUBS names still exists on its class."""
    for module, cls, method in STUBS:
        klass = getattr(modules[module], cls, None)
        if klass is None or not callable(getattr(klass, method, None)):
            raise GuardError(
                f"sim.{module}.{cls}.{method} not found; it was renamed or "
                "removed, so update STUBS in this file"
            )


def _stub(obj, method: str, fn) -> None:
    """Replace obj.method with fn; only methods checked through STUBS."""
    if not any(type(obj).__name__ == c and method == m for _, c, m in STUBS):
        raise GuardError(f"no STUBS entry for {type(obj).__name__}.{method}")
    setattr(obj, method, fn)


def emit(case: str) -> int:
    """Child mode: print every draw for one case under this process's hash seed."""
    if case not in CASES:
        print(f"check-chaos-schedule: unknown case {case!r}", file=sys.stderr)
        return 2
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(CHAOS_DIR))
    subprocess.Popen = _forbidden  # type: ignore[misc,assignment]

    import sim.links
    import sim.netem
    import sim.nodes
    import sim.peer_churn
    from sim.scenario import load_scenario
    from sim.topology import generate_topology

    modules = {
        "netem": sim.netem,
        "links": sim.links,
        "nodes": sim.nodes,
        "peer_churn": sim.peer_churn,
    }
    _check_stubs(modules)

    s = load_scenario(str(SCENARIO))
    if case == "ci":
        s.topology.num_nodes = 10
    else:
        s.ingress.enabled = True
        s.ingress.tiers_kbps = [250, 500, 1000, 2000]
        s.peer_churn.enabled = True

    def stream(name: str) -> random.Random:
        """One stream per consumer, named as master's runner names them."""
        return random.Random(f"{s.seed}:{name}")

    out: dict[str, str] = {}
    topo = generate_topology(s.topology, random.Random(s.seed), "chaos-schedule")

    outbound = topo.directed_outbound()
    out["outbound"] = ";".join(
        f"{n}>{','.join(sorted(peers))}" for n, peers in sorted(outbound.items())
    )

    if s.netem.enabled:
        nm = sim.netem.NetemManager(
            topo,
            s.netem,
            stream("netem"),
            bandwidth=s.bandwidth if s.bandwidth.enabled else None,
            ingress=s.ingress if s.ingress.enabled else None,
        )
        out["tiers"] = " ".join(
            f"{a}-{b}={r}" for (a, b), r in sorted(nm._edge_rates.items()) if a < b
        )
        out["ingress"] = " ".join(
            f"{a}-{b}={r}" for (a, b), r in sorted(nm._ingress_rates.items()) if a < b
        )
        mutated: list[str] = []
        _stub(nm, "_update_link", lambda a, b, p: mutated.append(f"{a}-{b}"))
        for _ in range(ROUNDS):
            nm.mutate()
            mutated.append("|")
        out["mutate"] = ",".join(mutated)

    if s.link_flaps.enabled:
        lm = sim.links.LinkManager(topo, s.link_flaps, stream("flaps"), netem_mgr=None)
        flapped: list[str] = []

        def link_down(edge, duration):
            """Record the flap and mark the link down, as the real one does."""
            flapped.append(f"{edge[0]}-{edge[1]}@{duration:.3f}")
            lm.link_states[edge].is_down = True

        _stub(lm, "_link_down", link_down)
        for _ in range(ROUNDS):
            lm.maybe_flap()
        out["flaps"] = ",".join(flapped)

    if s.node_churn.enabled:
        down: set[str] = set()
        ndm = sim.nodes.NodeManager(topo, s.node_churn, stream("churn"), down_nodes=down)
        stopped: list[str] = []

        def stop_node(node_id, duration):
            """Record the stop and mark the node down, as the real one does."""
            stopped.append(f"{node_id}@{duration:.3f}")
            ndm.node_states[node_id].is_down = True
            down.add(node_id)

        _stub(ndm, "_stop_node", stop_node)
        for _ in range(ROUNDS):
            ndm.maybe_kill()
        out["nodechurn"] = ",".join(stopped)

    if s.peer_churn.enabled:
        pc = sim.peer_churn.PeerChurnManager(
            topo, s.peer_churn, stream("peer-churn"), down_nodes=set()
        )
        churned: list[str] = []
        _stub(pc, "_disconnect_edge", lambda a, b: churned.append(f"-{a}-{b}") or True)
        _stub(pc, "_connect_edge", lambda a, b: churned.append(f"+{a}-{b}") or True)
        for _ in range(ROUNDS):
            pc.maybe_churn()
        out["peerchurn"] = ",".join(churned)

    # Deliberately unsorted: a draw over the set itself, to show these hash
    # seeds would expose a site that walks it.
    control = random.Random(f"{s.seed}:control").sample(list(topo.edges), 5)
    out["control"] = ",".join(f"{a}-{b}" for a, b in control)

    for key, value in out.items():
        print(f"{key}: {value}")
    print(f"hash: {hash(HASH_PROBE)}")
    return 0


def run_child(case: str, hash_seed: str) -> tuple[dict[str, str] | None, str]:
    """Run one child; return its parsed output, or None and the reason."""
    env = dict(os.environ, PYTHONHASHSEED=hash_seed, PYTHONDONTWRITEBYTECODE="1")
    try:
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--emit", case],
            env=env,
            capture_output=True,
            text=True,
            timeout=CHILD_TIMEOUT_SECS,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"could not run: {e}"
    if proc.returncode != 0:
        return None, f"exited {proc.returncode}:\n{proc.stderr.rstrip()}"
    parsed: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        key, sep, value = line.partition(": ")
        if sep:
            parsed[key] = value
    return parsed, ""


def check_case(case: str, results: dict) -> int:
    """Compare one case's children across the hash seeds; return its exit code."""
    keys = CASES[case]
    runs: list[tuple[str, dict[str, str]]] = []
    for i, hs in enumerate(HASH_SEEDS):
        parsed, why = results[(case, i)]
        if parsed is None:
            print(f"[{case}] child PYTHONHASHSEED={hs} {why}")
            return 2
        for key in keys + ("control", "hash"):
            if not parsed.get(key):
                print(f"[{case}] child PYTHONHASHSEED={hs} printed no {key!r} "
                      "(missing or empty): a site this case must exercise drew "
                      "nothing, so agreement there would prove nothing")
                return 2
        runs.append((hs, parsed))

    distinct = runs[: len(DISTINCT_SEEDS)]
    first = next(p for hs, p in distinct if hs == REPEAT_SEED)
    repeat = runs[-1][1]

    if first["hash"] != repeat["hash"]:
        print(f"[{case}] PYTHONHASHSEED={REPEAT_SEED} gave two different hash() "
              "values: the children ignore PYTHONHASHSEED (run under -E or -I?), "
              "so their agreement would prove nothing")
        return 2
    hashes = [p["hash"] for _, p in distinct]
    if len(set(hashes)) != len(hashes):
        print(f"[{case}] the hash seeds {', '.join(DISTINCT_SEEDS)} did not all "
              "give distinct hash() values, so they did not take effect")
        return 2
    for key in keys + ("control",):
        if first[key] != repeat[key]:
            print(f"[{case}] {key!r} differs between two runs under the same "
                  f"PYTHONHASHSEED={REPEAT_SEED}: something other than the hash "
                  "seed varies, so a difference cannot be put down to it")
            print(f"  first:  {first[key]}")
            print(f"  repeat: {repeat[key]}")
            return 2
    if len({p["control"] for _, p in distinct}) < 2:
        print(f"[{case}] the unsorted control draw was the same under every hash "
              "seed, so these seeds would not expose a set-order dependence")
        return 2

    base_hs, base = distinct[0]
    differing = []
    for key in keys:
        for hs, p in distinct[1:]:
            if p[key] != base[key]:
                differing.append((key, hs, p[key]))
                break
    if differing:
        key, hs, value = differing[0]
        print(f"[{case}] {key!r} differs between PYTHONHASHSEED={base_hs} and "
              f"PYTHONHASHSEED={hs}: a draw depends on set iteration order")
        print(f"  {base_hs}: {base[key]}")
        print(f"  {hs}: {value}")
        if len(differing) > 1:
            print(f"  also differing: {', '.join(k for k, _, _ in differing[1:])}")
        return 1
    print(f"[{case}] {len(keys)} draw keys identical under PYTHONHASHSEED "
          f"{', '.join(DISTINCT_SEEDS)} (and {REPEAT_SEED} repeated)")
    return 0


def main(argv: list[str]) -> int:
    """Parent mode, or child mode with --emit <case>."""
    if len(argv) == 2 and argv[0] == "--emit":
        try:
            return emit(argv[1])
        except GuardError as e:
            print(f"check-chaos-schedule: {e}", file=sys.stderr)
            return 2
    if argv:
        print("usage: check-chaos-schedule.py [--emit <case>]", file=sys.stderr)
        return 2
    if not SCENARIO.is_file():
        print(f"check-chaos-schedule: missing {SCENARIO}", file=sys.stderr)
        return 2
    start = time.monotonic()
    # Children are independent processes, so they run side by side. Results
    # are keyed by position, because the repeated seed appears twice.
    jobs = [(case, i, hs) for case in CASES for i, hs in enumerate(HASH_SEEDS)]
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        done = list(pool.map(lambda j: run_child(j[0], j[2]), jobs))
    worst = 0
    for case in CASES:
        results = {}
        for (c, i, hs), result in zip(jobs, done):
            if c == case:
                results[(c, i)] = result
        worst = max(worst, check_case(case, results))
    elapsed = time.monotonic() - start
    verdict = {0: "ok", 1: "FAILED", 2: "could not check"}[worst]
    print(f"check-chaos-schedule: {verdict} ({len(CASES)} cases, "
          f"{len(CASES) * len(HASH_SEEDS)} children, {elapsed:.1f} s)")
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
