"""Veth pair management for Ethernet transport edges.

Creates veth pairs between Docker containers for Ethernet-transport
edges. Each Ethernet edge gets a veth pair with one end moved into
each container's network namespace. Naming:

  Host (temporary):  vh{NN}{MM}a / vh{NN}{MM}b
  Container:         ve-{local}-{peer}  (via veth_interface_name())

After creation, the container-side MAC addresses are queried and
stored in SimNode.ethernet_macs for use in config generation.

Implementation note
-------------------
All ``ip link`` operations that manipulate the host network stack are
executed inside a short-lived privileged Docker container that shares
the host network and PID namespaces (``--net=host --pid=host``).  This
works on both Linux and macOS:

* **Linux** – the helper container shares the real host network/PID
  namespaces, so ``ip link set ... netns <pid>`` behaves identically to
  running ``ip`` directly on the host.
* **macOS** – Docker containers run inside a Linux VM; the helper
  container shares *that* VM's namespaces, which is exactly where the
  simulation containers live.  Running ``ip`` on the macOS host would
  never work because the container PIDs are in the VM, not macOS.

The helper image is resolved from the running simulation containers
(which already have ``iproute2`` from the chaos Dockerfile).
"""

from __future__ import annotations

import logging
import subprocess

from .docker_exec import docker_exec_quiet
from .topology import SimTopology, veth_interface_name

log = logging.getLogger(__name__)

class VethManager:
    """Manages veth pairs for Ethernet-transport edges."""

    def __init__(self, topology: SimTopology):
        self.topology = topology
        # Track created host-side temp names for cleanup
        self._host_pairs: list[tuple[str, str, str, str]] = []
        # (node_a, node_b, host_name_a, host_name_b)
        self._ip_image: str | None = None

    def _get_image(self) -> str:
        """Resolve the Docker image to use for ip(8) helper containers.

        Uses the image of the first simulation container (which already has
        iproute2 installed via the chaos Dockerfile).  Must be called after
        containers are started.
        """
        if self._ip_image is not None:
            return self._ip_image

        first_node = next(iter(sorted(self.topology.nodes)))
        container = self.topology.container_name(first_node)
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.Config.Image}}", container],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0 or not result.stdout.strip():
            raise RuntimeError(
                f"Cannot determine Docker image for ip(8) helper "
                f"(docker inspect {container} failed): {result.stderr.strip()}"
            )
        self._ip_image = result.stdout.strip()
        log.debug("Using sim image %s for ip(8) helper", self._ip_image)
        return self._ip_image

    def setup_all(self):
        """Create veth pairs for all Ethernet edges.

        For each Ethernet edge:
        1. Get container PIDs
        2. Create veth pair on host with temp names
        3. Move ends into container network namespaces
        4. Rename to final names and bring up
        5. Query MACs and store in SimNode.ethernet_macs
        """
        eth_edges = self.topology.ethernet_edges()
        if not eth_edges:
            return

        image = self._get_image()
        log.info("Setting up %d Ethernet veth pairs (helper image: %s)...", len(eth_edges), image)

        for a, b in eth_edges:
            self._create_veth_pair(a, b, image)

        log.info(
            "Veth setup complete: %d pairs",
            len(self._host_pairs),
        )

    def setup_node(self, node_id: str):
        """Re-create veth endpoints for a single node after container restart.

        When a container restarts (node churn), its network namespace is
        destroyed. We re-create the veth pairs for all Ethernet edges
        involving this node.
        """
        image = self._get_image()
        for a, b in self.topology.ethernet_edges():
            if a != node_id and b != node_id:
                continue
            # Remove existing pair if any (host-side might still exist)
            nn_a = a.replace("n", "")
            nn_b = b.replace("n", "")
            host_a = f"vh{nn_a}{nn_b}a"
            _run_host(["ip", "link", "delete", host_a], image, check=False)
            # Re-create
            self._create_veth_pair(a, b, image)

    def teardown_all(self):
        """Clean up all veth pairs."""
        image = self._get_image()
        for _, _, host_a, _ in self._host_pairs:
            _run_host(["ip", "link", "delete", host_a], image, check=False)
        self._host_pairs.clear()

    def _create_veth_pair(self, node_a: str, node_b: str, image: str):
        """Create a single veth pair between two containers."""
        container_a = self.topology.container_name(node_a)
        container_b = self.topology.container_name(node_b)

        # Get container PIDs
        pid_a = _get_container_pid(container_a)
        pid_b = _get_container_pid(container_b)
        if pid_a is None or pid_b is None:
            log.warning(
                "Cannot create veth %s--%s: container PID not found", node_a, node_b
            )
            return

        # Generate names
        nn_a = node_a.replace("n", "")
        nn_b = node_b.replace("n", "")
        host_a = f"vh{nn_a}{nn_b}a"
        host_b = f"vh{nn_a}{nn_b}b"
        final_a = veth_interface_name(node_a, node_b)
        final_b = veth_interface_name(node_b, node_a)

        # Clean up any stale pair
        _run_host(["ip", "link", "delete", host_a], image, check=False)

        # Create veth pair on host
        ok = _run_host([
            "ip", "link", "add", host_a, "type", "veth", "peer", "name", host_b,
        ], image)
        if not ok:
            log.warning("Failed to create veth pair %s/%s", host_a, host_b)
            return

        # Move into container namespaces
        _run_host(["ip", "link", "set", host_a, "netns", str(pid_a)], image)
        _run_host(["ip", "link", "set", host_b, "netns", str(pid_b)], image)

        # Rename and bring up inside containers
        docker_exec_quiet(
            container_a,
            f"ip link set {host_a} name {final_a} && ip link set {final_a} up",
            timeout=10,
        )
        docker_exec_quiet(
            container_b,
            f"ip link set {host_b} name {final_b} && ip link set {final_b} up",
            timeout=10,
        )

        # Query MAC addresses
        mac_a = _get_mac_in_container(container_a, final_a)
        mac_b = _get_mac_in_container(container_b, final_b)

        if mac_a:
            self.topology.nodes[node_a].ethernet_macs[node_b] = mac_a
        if mac_b:
            self.topology.nodes[node_b].ethernet_macs[node_a] = mac_b

        self._host_pairs.append((node_a, node_b, host_a, host_b))

        log.info(
            "Veth %s(%s) -- %s(%s)  MAC: %s / %s",
            node_a, final_a, node_b, final_b,
            mac_a or "?", mac_b or "?",
        )


def _get_container_pid(container: str) -> int | None:
    """Get the PID of a running Docker container."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Pid}}", container],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            pid = int(result.stdout.strip())
            return pid if pid > 0 else None
    except (subprocess.TimeoutExpired, ValueError):
        pass
    return None


def _get_mac_in_container(container: str, iface: str) -> str | None:
    """Query the MAC address of an interface inside a container."""
    result = docker_exec_quiet(
        container,
        f"cat /sys/class/net/{iface}/address",
        timeout=5,
    )
    if result is not None:
        return result.strip()
    return None


def _run_host(cmd: list[str], image: str, check: bool = True) -> bool:
    """Run an ``ip`` command via a privileged Docker container.

    Uses ``--net=host --pid=host --privileged`` so the container shares
    the Docker host's (or Docker Desktop VM's) network and PID
    namespaces.  This makes ``ip link set ... netns <pid>`` work
    correctly on both Linux and macOS.

    ``image`` should be a Docker image that has ``iproute2`` installed
    (e.g. the simulation's own image built from the chaos Dockerfile).

    ``--entrypoint ip`` overrides the image's default entrypoint so the
    simulation entrypoint script is not executed.
    """
    docker_cmd = [
        "docker", "run", "--rm",
        "--privileged",
        "--net=host",
        "--pid=host",
        "--entrypoint", "ip",
        image,
    ] + cmd[1:]  # cmd[0] is "ip", skip it since it's now the entrypoint
    try:
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if check and result.returncode != 0:
            log.debug(
                "ip cmd failed: %s -> %s",
                " ".join(cmd),
                result.stderr.strip(),
            )
            return False
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        log.warning("ip cmd timed out: %s", " ".join(cmd))
        return False
