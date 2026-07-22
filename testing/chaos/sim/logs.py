"""Log collection and post-run analysis for chaos simulations.

Delegates core analysis to the shared testing.lib.log_analysis module.
Adds chaos-specific collection (Docker container logs, sim metadata).
"""

from __future__ import annotations

import logging
import os
import subprocess

# Import shared analysis from testing/lib/
import sys
_TESTING_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
if _TESTING_DIR not in sys.path:
    sys.path.insert(0, _TESTING_DIR)

from lib.log_analysis import (  # noqa: E402
    AnalysisResult,
    analyze_logs,
    strip_ansi,
)

log = logging.getLogger(__name__)

# Re-export for existing callers
__all__ = ["AnalysisResult", "analyze_logs", "collect_logs", "write_sim_metadata"]


def collect_logs(container_names: list[str], output_dir: str) -> dict[str, str]:
    """Collect all output (stdout + stderr) from all containers.

    Raises RuntimeError if any container's output could not be read, or if
    there was nothing to read. `docker logs` writes its own failures to
    stderr and exits non-zero, so without the returncode check the daemon's
    "No such container" reply was stored as though it were the node's log
    and analysed as a mesh with no panics, no errors and no sessions --
    which reads exactly like a clean run.
    """
    os.makedirs(output_dir, exist_ok=True)
    logs = {}
    failed = []

    for name in container_names:
        try:
            result = subprocess.run(
                ["docker", "logs", name],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except Exception as e:
            log.warning("Failed to collect logs from %s: %s", name, e)
            failed.append(name)
            continue

        if result.returncode != 0:
            log.warning(
                "docker logs %s exited %d: %s",
                name, result.returncode, result.stderr.strip(),
            )
            failed.append(name)
            continue

        # A container's own stderr comes back on our stderr, so both
        # streams are log content on the success path.
        log_text = strip_ansi(result.stdout + result.stderr)
        logs[name] = log_text

        path = os.path.join(output_dir, f"{name}.log")
        with open(path, "w") as f:
            f.write(log_text)

    if failed:
        raise RuntimeError(
            f"could not collect logs from {len(failed)}/{len(container_names)} "
            f"containers: {', '.join(failed)}"
        )
    if not logs:
        raise RuntimeError("no container logs were collected")

    return logs


def write_sim_metadata(
    output_dir: str,
    scenario_name: str,
    seed: int,
    num_nodes: int,
    num_edges: int,
    duration_secs: int,
    topology=None,
):
    """Write simulation metadata for reproducibility."""
    path = os.path.join(output_dir, "metadata.txt")
    with open(path, "w") as f:
        f.write(f"scenario: {scenario_name}\n")
        f.write(f"seed: {seed}\n")
        f.write(f"nodes: {num_nodes}\n")
        f.write(f"edges: {num_edges}\n")
        f.write(f"duration_secs: {duration_secs}\n")

        if topology:
            f.write("\nadjacency:\n")
            for nid in sorted(topology.nodes):
                node = topology.nodes[nid]
                peers = sorted(node.peers)
                f.write(f"  {nid} ({node.docker_ip}): {', '.join(peers)}\n")
            f.write("\nedges:\n")
            for a, b in sorted(topology.edges):
                f.write(f"  {a} -- {b}\n")
