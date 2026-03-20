"""Control socket querying via docker exec.

Queries FIPS nodes' control sockets to observe runtime state (tree
structure, MMP metrics, peers) without requiring fipsctl in the
container. Uses a Python one-liner inside docker exec since python3
is available in the Docker image.
"""

from __future__ import annotations

import json
import logging

from .docker_exec import docker_exec, docker_exec_quiet
from .topology import SimTopology

log = logging.getLogger(__name__)

# Default control socket path inside containers (running as root,
# so /run/fips/ is created by the daemon).
CONTROL_SOCKET = "/run/fips/control.sock"


def query_node(container: str, command: str, timeout: int = 10) -> dict | None:
    """Send a command to a node's control socket, return the data dict.

    Returns None if the query fails (node down, socket not ready, etc.).
    """
    # Python one-liner that connects to the Unix socket, sends the JSON
    # command, and prints the response.  Runs inside the container.
    script = (
        "import socket,json,sys; "
        "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); "
        f"s.connect('{CONTROL_SOCKET}'); "
        f"s.sendall(json.dumps({{'command':'{command}'}}).encode()+b'\\n'); "
        "s.shutdown(socket.SHUT_WR); "
        "chunks=[]; "
        "[chunks.append(d) for d in iter(lambda:s.recv(65536),b'')]; "
        "print(b''.join(chunks).decode())"
    )
    stdout = docker_exec_quiet(container, f"python3 -c \"{script}\"", timeout=timeout)
    if stdout is None:
        return None

    try:
        response = json.loads(stdout.strip())
    except json.JSONDecodeError as e:
        log.warning("Invalid JSON from %s: %s", container, e)
        return None

    if response.get("status") != "ok":
        msg = response.get("message", "unknown error")
        log.warning("Control query %s on %s failed: %s", command, container, msg)
        return None

    return response.get("data", {})


def send_command(
    container: str, command: str, params: dict, timeout: int = 10
) -> dict | None:
    """Send a mutating command with params to a node's control socket.

    Returns the response data dict, or None on failure.
    Uses base64-encoded JSON to avoid shell quoting issues with
    embedded quotes in the payload.
    """
    import base64

    payload = json.dumps({"command": command, "params": params})
    b64 = base64.b64encode(payload.encode()).decode()
    script = (
        "import socket,json,sys,base64; "
        "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); "
        f"s.connect('{CONTROL_SOCKET}'); "
        f"s.sendall(base64.b64decode('{b64}')+b'\\n'); "
        "s.shutdown(socket.SHUT_WR); "
        "chunks=[]; "
        "[chunks.append(d) for d in iter(lambda:s.recv(65536),b'')]; "
        "print(b''.join(chunks).decode())"
    )
    stdout = docker_exec_quiet(container, f"python3 -c \"{script}\"", timeout=timeout)
    if stdout is None:
        return None

    try:
        response = json.loads(stdout.strip())
    except json.JSONDecodeError as e:
        log.warning("Invalid JSON from %s: %s", container, e)
        return None

    if response.get("status") != "ok":
        msg = response.get("message", "unknown error")
        log.debug("Command %s on %s: %s", command, container, msg)
        return None

    return response.get("data", {})


def query_status(container: str) -> dict | None:
    """Query a node's status (npub, ipv6, uptime, etc.)."""
    return query_node(container, "show_status")


def query_tree(container: str) -> dict | None:
    """Query a node's spanning tree state."""
    return query_node(container, "show_tree")


def query_mmp(container: str) -> dict | None:
    """Query a node's MMP metrics."""
    return query_node(container, "show_mmp")


def query_peers(container: str) -> dict | None:
    """Query a node's peer list with MMP metrics."""
    return query_node(container, "show_peers")


def snapshot_all_trees(topology: SimTopology) -> dict[str, dict]:
    """Query show_tree on all nodes, return {node_id: tree_data}.

    Nodes that fail to respond are omitted from the result.
    """
    result = {}
    for node_id in sorted(topology.nodes):
        container = topology.container_name(node_id)
        data = query_tree(container)
        if data is not None:
            result[node_id] = data
        else:
            log.warning("No tree data from %s", node_id)
    return result


def snapshot_all_mmp(topology: SimTopology) -> dict[str, dict]:
    """Query show_mmp on all nodes, return {node_id: mmp_data}.

    Nodes that fail to respond are omitted from the result.
    """
    result = {}
    for node_id in sorted(topology.nodes):
        container = topology.container_name(node_id)
        data = query_mmp(container)
        if data is not None:
            result[node_id] = data
        else:
            log.warning("No MMP data from %s", node_id)
    return result


def query_routing(container: str) -> dict | None:
    """Query a node's routing stats (includes congestion counters)."""
    return query_node(container, "show_routing")


def query_transports(container: str) -> dict | None:
    """Query a node's transport state (includes kernel drop counters)."""
    return query_node(container, "show_transports")


def snapshot_all_congestion(topology: SimTopology) -> dict[str, dict]:
    """Query show_routing on all nodes to capture congestion counters.

    Returns {node_id: {"congestion": {...}, "kernel_drops": [...]}}.
    Nodes that fail to respond are omitted from the result.
    """
    result = {}
    for node_id in sorted(topology.nodes):
        container = topology.container_name(node_id)
        routing = query_routing(container)
        transports = query_transports(container)
        if routing is not None:
            entry = {"congestion": routing.get("congestion", {})}
            if transports is not None:
                drops = []
                for t in transports.get("transports", []):
                    stats = t.get("stats", {})
                    drops.append({
                        "transport_id": t.get("transport_id"),
                        "name": t.get("name"),
                        "kernel_drops": stats.get("kernel_drops"),
                    })
                entry["kernel_drops"] = drops
            result[node_id] = entry
        else:
            log.warning("No routing data from %s", node_id)
    return result
