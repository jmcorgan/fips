"""Random iperf3 traffic generation between node pairs.

Spawns iperf3 clients as background processes in containers. The iperf3
server is already running in each container (started by the Dockerfile
entrypoint).
"""

from __future__ import annotations

import json
import logging
import random
import time
from dataclasses import dataclass, field

from .docker_exec import docker_exec_quiet
from .scenario import TrafficConfig
from .topology import SimTopology

log = logging.getLogger(__name__)


@dataclass
class TrafficSession:
    client_node: str
    server_node: str
    started_at: float
    duration_secs: int
    container: str
    result_file: str = ""


class TrafficManager:
    """Manages random iperf3 sessions across the mesh."""

    def __init__(
        self,
        topology: SimTopology,
        config: TrafficConfig,
        rng: random.Random,
        down_nodes: set[str] | None = None,
        npub_cache: dict[str, str] | None = None,
    ):
        self.topology = topology
        self.config = config
        self.rng = rng
        # `is not None`, not `or`: the runner passes its shared set while it
        # is still empty, and an empty set is falsy, so `or` replaced it with
        # a private one and no other manager ever saw a node go down.
        self.down_nodes = down_nodes if down_nodes is not None else set()
        self.npub_cache = npub_cache or {}
        self.active_sessions: list[TrafficSession] = []
        self.completed_results: list[dict] = []

    @property
    def active_count(self) -> int:
        return len(self.active_sessions)

    def maybe_spawn(self):
        """Spawn a new iperf3 session if under the concurrency limit."""
        if self.active_count >= self.config.max_concurrent:
            log.debug(
                "At max_concurrent (%d), skipping traffic spawn",
                self.config.max_concurrent,
            )
            return

        node_ids = [nid for nid in self.topology.nodes if nid not in self.down_nodes]
        if len(node_ids) < 2:
            return

        # Pick random client and server (different nodes, both up)
        client, server = self.rng.sample(node_ids, 2)
        server_npub = self.npub_cache.get(server, self.topology.nodes[server].npub)
        container = self.topology.container_name(client)

        duration = int(
            self.rng.uniform(
                self.config.duration_secs.min,
                self.config.duration_secs.max,
            )
        )
        streams = self.config.parallel_streams

        # Result file inside the container for JSON capture
        ts = int(time.time())
        result_file = f"/tmp/iperf3-{client}-{server}-{ts}.json"

        # Start iperf3 in background with JSON output
        cmd = (
            f"nohup iperf3 -c {server_npub}.fips -t {duration} "
            f"-P {streams} --json > {result_file} 2>&1 &"
        )
        result = docker_exec_quiet(container, cmd)
        if result is not None:
            session = TrafficSession(
                client_node=client,
                server_node=server,
                started_at=time.time(),
                duration_secs=duration,
                container=container,
                result_file=result_file,
            )
            self.active_sessions.append(session)
            log.info(
                "Traffic: %s -> %s (%ds, %d streams)",
                client,
                server,
                duration,
                streams,
            )
        else:
            log.warning("Failed to start iperf3 on %s", container)

    def cleanup_expired(self):
        """Remove sessions that have completed (based on time)."""
        now = time.time()
        grace = 5  # seconds after expected completion
        still_active = []
        for s in self.active_sessions:
            if now - s.started_at >= s.duration_secs + grace:
                self._collect_result(s)
            else:
                still_active.append(s)
        removed = len(self.active_sessions) - len(still_active)
        self.active_sessions = still_active
        if removed > 0:
            log.debug("Cleaned up %d expired traffic sessions", removed)

    def _collect_result(self, session: TrafficSession):
        """Retrieve iperf3 JSON result from container."""
        if not session.result_file:
            return
        if session.client_node in self.down_nodes:
            return
        stdout = docker_exec_quiet(
            session.container,
            f"cat {session.result_file} 2>/dev/null; rm -f {session.result_file}",
        )
        if stdout is None:
            return
        try:
            data = json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            log.debug("Could not parse iperf3 result for %s -> %s",
                       session.client_node, session.server_node)
            return
        data["_meta"] = {
            "client": session.client_node,
            "server": session.server_node,
            "duration_secs": session.duration_secs,
        }
        self.completed_results.append(data)

    def collect_results(self) -> list[dict]:
        """Return all completed iperf3 JSON results."""
        # Collect any remaining active sessions that may have finished
        for s in self.active_sessions:
            self._collect_result(s)
        return self.completed_results

    def stop_all(self):
        """Kill all iperf3 client processes in running containers."""
        seen = set()
        for session in self.active_sessions:
            if session.container not in seen:
                if session.client_node not in self.down_nodes:
                    docker_exec_quiet(
                        session.container,
                        "killall iperf3 2>/dev/null; true",
                    )
                seen.add(session.container)
        # Collect results before clearing (iperf3 writes partial JSON on kill)
        for s in self.active_sessions:
            self._collect_result(s)
        self.active_sessions.clear()
