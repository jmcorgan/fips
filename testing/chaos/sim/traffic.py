"""Random iperf3 traffic generation between node pairs.

Spawns iperf3 clients as background processes in containers. The iperf3
server is already running in each container (started by the Dockerfile
entrypoint, with --json, so a client's --get-server-output brings back the
receiver's intervals as JSON).

A TCP client writes one JSON document when it ends. A UDP stream's client
writes a line per event (--json-stream), so a stream that never got going can
be told from one still running while it runs: iperf3's UDP start is one
datagram and one reply with no retry, and a lost one leaves a client that
writes nothing for 30 s, then an error event, and exits. Such a stream is
started once more, and the restart is reported, since the seconds before it
are not measured.
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


def tcp_command(cfg: TrafficConfig, host: str, duration: int, out: str) -> str:
    """The shell command that starts one TCP session's iperf3 client.

    The server's own per-second intervals, which count what arrived, come
    back in the result (`server_output_json`, from a server run with
    --json) for the stall check. With ``rate_mbps`` set, each stream is
    capped at that rate (iperf3's -b applies per stream).
    """
    rate = f" -b {cfg.rate_mbps}M" if cfg.rate_mbps is not None else ""
    return (
        f"nohup iperf3 -c {host} -t {duration} "
        f"-P {cfg.parallel_streams}{rate} --json --get-server-output "
        f"> {out} 2>&1 &"
    )


# The test image's second iperf3 server, for the UDP stream beside a
# session: one server runs one test at a time, so the stream cannot share
# the session's.
UDP_PORT = 5202

# How long past its expected end a client gets to finish, before its result
# is read.
GRACE_SECS = 5

# How much of a file that did not parse its record keeps.
HEAD_CHARS = 200

# How long a new UDP stream has to write its first line. A running stream has
# one by 1.5 s; this leaves room for a slow start under load.
START_CHECK = 5


def udp_command(cfg: TrafficConfig, host: str, duration: int, out: str) -> str:
    """The shell command that starts a session's constant-rate UDP stream.

    ``udp_mbps`` Mbit/s in 1000-byte datagrams (inside the 1280-byte TUN
    MTU with room for the headers), to the second server, for the
    session's length; the receiver's intervals come back as for TCP, in
    their own event (`assemble`). The command prints the client's pid.
    """
    return (
        f"nohup iperf3 -c {host} -p {UDP_PORT} -u -b {cfg.udp_mbps}M -l 1000 "
        f"-t {duration} --json-stream --get-server-output > {out} 2>&1 & echo $!"
    )


def assemble(text: str) -> dict | None:
    """One --json-stream client's lines as the document --json would give.

    The events are ``start``, ``interval`` for each second,
    ``server_output_json``, ``end``, or an ``error`` in their place. Returns
    None when the lines hold neither the receiver's output nor an error, as
    a stream cut short does. A line that does not parse is skipped: a client
    killed in mid-write leaves its last line cut.
    """
    out: dict = {"intervals": []}
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        kind, data = event.get("event"), event.get("data")
        if kind == "interval":
            out["intervals"].append(data)
        elif kind in ("start", "server_output_json", "end", "error"):
            out[kind] = data
    return out if "server_output_json" in out or "error" in out else None


@dataclass
class TrafficSession:
    client_node: str
    server_node: str
    started_at: float
    duration_secs: int
    container: str
    result_file: str = ""
    # The UDP stream's result file, when the session runs one, its client's
    # pid, and when and for how long that client was started; what it dials,
    # whether its start was checked, and whether this is its second start.
    udp_file: str = ""
    udp_pid: str = ""
    udp_started: float = 0.0
    udp_secs: int = 0
    udp_host: str = ""
    udp_checked: bool = False
    udp_restarted: bool = False

    def due(self) -> float:
        """When its clients should be done, grace included. A UDP stream
        counts from its own start, which comes after the TCP client's."""
        ends = self.started_at + self.duration_secs
        if self.udp_file:
            ends = max(ends, self.udp_started + self.udp_secs)
        return ends + GRACE_SECS


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
        # The UDP streams' results, kept apart so no TCP figure counts them.
        self.udp_results: list[dict] = []
        # Sessions past their end whose UDP client was still running. They
        # are out of active_sessions, so stop_all reads them from here.
        self.late: list[TrafficSession] = []
        # Streams started a second time. Counted here and not read from their
        # results: a stream the run kills at its end leaves no result.
        self.restarts = 0

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

        cmd = tcp_command(self.config, f"{server_npub}.fips", duration, result_file)
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
            if self.config.udp_mbps:
                self._start_udp(session, f"{server_npub}.fips", ts)
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

    def _start_udp(self, session: TrafficSession, host: str, ts: int):
        """Start the session's UDP stream."""
        session.udp_host = host
        out = f"/tmp/iperf3-udp-{session.client_node}-{session.server_node}-{ts}.json"
        self._launch_udp(session, out, session.duration_secs)

    def _launch_udp(self, session: TrafficSession, out: str, secs: int):
        """Start a UDP client writing to ``out``; a stream that fails to
        start is recorded as an unreadable result, so the stall check fails
        on it rather than measuring one stream fewer."""
        cmd = udp_command(self.config, session.udp_host, secs, out)
        pid = docker_exec_quiet(session.container, cmd)
        if pid is None:
            log.warning("Failed to start the UDP stream on %s", session.container)
            self.udp_results.append(self._unread(session, "the UDP stream did not start"))
            session.udp_file = ""
            return
        session.udp_file = out
        session.udp_pid = pid.strip()
        session.udp_started = time.time()
        session.udp_secs = secs

    def _check_start(self, session: TrafficSession, now: float):
        """Look once, START_CHECK after a client started, for a stream
        that never got going: an empty file. Its client is killed by its
        pid and the stream started once more for the time left, under a new
        name, since the empty file stays. A second empty file is recorded,
        and fails the stall check.
        """
        if (
            not session.udp_file
            or session.udp_checked
            or now - session.udp_started < START_CHECK
            or session.client_node in self.down_nodes
        ):
            return
        session.udp_checked = True
        size = docker_exec_quiet(
            session.container, f"stat -c %s {session.udp_file} 2>/dev/null"
        )
        if size is None or size.strip() != "0":
            return
        alive = self._alive(session)
        docker_exec_quiet(session.container, f"kill {session.udp_pid} 2>/dev/null; true")
        if session.udp_restarted:
            log.warning("The UDP stream %s -> %s did not start, twice",
                        session.client_node, session.server_node)
            self.udp_results.append(
                self._unread(session, "the UDP stream did not start", "", alive)
            )
            session.udp_file = ""
            return
        left = max(1, int(session.started_at + session.duration_secs - now))
        log.warning("The UDP stream %s -> %s did not start; starting it again for %d s",
                    session.client_node, session.server_node, left)
        session.udp_restarted = True
        self.restarts += 1
        session.udp_checked = False
        self._launch_udp(session, session.udp_file.replace(".json", "-again.json"), left)

    @staticmethod
    def _unread(session: TrafficSession, why: str, text: str | None = None,
                alive: bool = False) -> dict:
        """A stand-in result for a UDP stream that left nothing to read.

        ``text`` is what its file held, None when that could not be read.
        The file's size, its first bytes and whether the client was still
        running go in the record and in its error, so the stall check's
        message carries them: the container, and the file, go with the run.
        """
        meta = {"client": session.client_node, "server": session.server_node,
                "duration_secs": session.duration_secs}
        if session.udp_restarted:
            meta["restarted"] = True
        if text is None:
            return {"error": why, "_meta": meta}
        size = len(text.encode())
        head = text[:HEAD_CHARS]
        meta.update(size=size, head=head, alive=alive)
        state = "still running" if alive else "gone"
        return {"error": f"{why}: {size} bytes, client {state}, first bytes {head!r}",
                "_meta": meta}

    def cleanup_expired(self):
        """Remove sessions that have completed (based on time)."""
        now = time.time()
        still_active = []
        for s in self.active_sessions:
            self._check_start(s, now)
            if now >= s.due():
                self._collect_result(s)
            else:
                still_active.append(s)
        removed = len(self.active_sessions) - len(still_active)
        self.active_sessions = still_active
        if removed > 0:
            log.debug("Cleaned up %d expired traffic sessions", removed)

    def _collect_result(self, session: TrafficSession, killed: bool = False):
        """Retrieve the session's iperf3 JSON results from its container.

        A TCP result that cannot be read is dropped, as it always was (a
        session killed at the end of the run leaves none).
        """
        if session.client_node in self.down_nodes:
            return
        data, _ = self._read(session, session.result_file, quiet=killed)
        if data is not None:
            self.completed_results.append(data)
        session.result_file = ""
        self._collect_udp(session, killed)

    def _collect_udp(self, session: TrafficSession, killed: bool = False,
                     last: bool = False):
        """Retrieve the session's UDP stream result.

        One the run killed is dropped unless it had finished: the kill ends
        it with an error and no receiver's output. A stream that cannot be
        read otherwise is held: a client still running goes on the late
        list for a last look, unless this is that look, and after that the
        stream is recorded as unreadable, with what it left, since the
        stall check holds its bound on it.
        """
        if not session.udp_file:
            return
        data, text = self._read(session, session.udp_file, assemble, quiet=killed)
        if data is not None and (not killed or "server_output_json" in data):
            if session.udp_restarted:
                data["_meta"]["restarted"] = True
            self.udp_results.append(data)
        elif not killed:
            alive = self._alive(session)
            if alive and not last:
                self.late.append(session)
                return
            self.udp_results.append(
                self._unread(session, "the UDP stream left no readable result", text, alive)
            )
        session.udp_file = ""

    def _alive(self, session: TrafficSession) -> bool:
        """Whether the session's UDP client is still running.

        Reads its command line rather than signalling it: an exited client
        whose parent is gone can linger as a zombie, which answers a signal
        and has no command line.
        """
        out = docker_exec_quiet(
            session.container,
            f"grep -qa iperf3 /proc/{session.udp_pid}/cmdline 2>/dev/null "
            f"&& echo alive; true",
        )
        return bool(out) and "alive" in out

    def _read(self, session: TrafficSession, path: str, parse=json.loads,
              quiet: bool = False) -> tuple[dict | None, str | None]:
        """Read one iperf3 result with ``parse``, tagged with its pair.

        Returns the result, or None, and the text the file held, or None if
        it could not be read. A file that parsed is removed. One that did
        not stays in the container and is logged at warning, or at debug
        with ``quiet``, for a client the run killed.
        """
        if not path:
            return None, None
        text = docker_exec_quiet(session.container, f"cat {path} 2>/dev/null")
        if text is None:
            return None, None
        try:
            data = parse(text.strip())
        except (json.JSONDecodeError, ValueError):
            data = None
        if not isinstance(data, dict):
            log.log(
                logging.DEBUG if quiet else logging.WARNING,
                "Could not parse iperf3 result %s for %s -> %s: %d bytes",
                path, session.client_node, session.server_node, len(text),
            )
            return None, text
        docker_exec_quiet(session.container, f"rm -f {path}")
        data["_meta"] = {
            "client": session.client_node,
            "server": session.server_node,
            "duration_secs": session.duration_secs,
        }
        return data, text

    def collect_results(self) -> list[dict]:
        """Return all completed iperf3 JSON results."""
        # Collect any remaining active sessions that may have finished
        for s in self.active_sessions:
            self._collect_result(s)
        return self.completed_results

    def stop_all(self):
        """Kill all iperf3 client processes in running containers.

        The late streams are read first: a client still working through its
        end-of-test exchange may have finished by now, and a kill would
        cost it the receiver's output.
        """
        for session in self.late:
            if session.client_node not in self.down_nodes:
                self._collect_udp(session, last=True)
        self.late.clear()
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
            self._collect_result(s, killed=True)
        self.active_sessions.clear()
