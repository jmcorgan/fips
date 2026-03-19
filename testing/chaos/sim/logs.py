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
    """Collect all output (stdout + stderr) from all containers."""
    os.makedirs(output_dir, exist_ok=True)
    logs = {}

    for name in container_names:
        try:
            result = subprocess.run(
                ["docker", "logs", name],
                capture_output=True,
                text=True,
                timeout=30,
            )
            raw = result.stdout + result.stderr
            log_text = strip_ansi(raw)
            logs[name] = log_text

            path = os.path.join(output_dir, f"{name}.log")
            with open(path, "w") as f:
                f.write(log_text)

        except (subprocess.TimeoutExpired, Exception) as e:
            log.warning("Failed to collect logs from %s: %s", name, e)
            logs[name] = ""

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
