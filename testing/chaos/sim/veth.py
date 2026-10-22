"""Veth pair management for Ethernet transport edges.

Creates veth pairs between Docker containers for Ethernet-transport
edges. Each Ethernet edge gets a veth pair with one end moved into
each container's network namespace. Naming:

  Host (temporary):  vh{token}{NN}{MM}a / vh{token}{NN}{MM}b
                     (via SimTopology.veth_host_name())
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

import enum
import logging
import subprocess
import time
import uuid

from .docker_exec import DockerExecError, docker_exec, docker_exec_quiet
from .naming import name_suffix
from .topology import SimTopology, veth_interface_name

log = logging.getLogger(__name__)

# How long a freshly raised veth end may take to report operstate up. The
# kernel publishes the carrier change through linkwatch, which is deferred, so
# a read straight after `ip link set up` can still see the old state. Long
# enough for at least two reads under host load, since one slow `docker exec`
# must not abort a run whose link is up.
OPERSTATE_WAIT_SECS = 15

# Timeout for each `docker exec` a restore makes. The run blocks on these, and
# a timeout aborts it, so this errs long: a loaded host is the normal case.
EXEC_TIMEOUT_SECS = 30

# Bound on one attempt at a host `ip` command, which runs in a helper
# container. On a GitHub runner one netns move took over 30 s while the six
# docker calls before it in the same pair took 0.64 s together, and the fixed
# 30 s bound this replaces aborted the run. Across 964 pairs in 241 GitHub
# logs the slowest pair took 2.26 s, so this is far above any healthy
# command, and a command that does run out is checked and tried once more
# (see `_require_host`).
HOST_CMD_TIMEOUT_SECS = 90

# Attempts at a host command that times out without taking effect.
HOST_CMD_ATTEMPTS = 2

# Bound on each docker call made after a helper times out: reading its state,
# removing it, and looking for the link in the host namespace.
HELPER_CHECK_TIMEOUT_SECS = 30

# The namespace name `_link_place` reports for the host's own.
HOST_NS = "host"


class HostOutcome(enum.Enum):
    """How one host command ended."""

    OK = "ok"
    FAILED = "failed"
    TIMEOUT = "timed out"


class VethSetupError(RuntimeError):
    """A veth pair could not be created, placed, renamed or raised.

    Raised rather than logged. A pair that fails part way leaves a ring link
    down while the run carries on, and what reaches the verdict is then a tree
    that did not converge: a daemon failure in every respect a reader can see.
    Letting this propagate aborts the run, so the fault is reported as the
    harness's own.
    """


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

    def setup_node(self, node_id: str, down_nodes: set[str] | None = None):
        """Re-create veth endpoints for a single node after container restart.

        When a container restarts (node churn), its network namespace is
        destroyed. We re-create the veth pairs for all Ethernet edges
        involving this node. ``down_nodes`` names the neighbours churn has
        stopped, whose pairs are left for their own restart.
        """
        image = self._get_image()
        for a, b in self.topology.ethernet_edges():
            if a != node_id and b != node_id:
                continue
            # Remove existing pair if any (host-side might still exist)
            host_a = self.topology.veth_host_name(a, b, "a")
            _run_host(["ip", "link", "delete", host_a], image, check=False)
            # Re-create
            self._create_veth_pair(a, b, image, down_nodes or set())

    def teardown_all(self):
        """Clean up all veth pairs."""
        image = self._get_image()
        for _, _, host_a, _ in self._host_pairs:
            _run_host(["ip", "link", "delete", host_a], image, check=False)
        self._host_pairs.clear()

    def _create_veth_pair(
        self, node_a: str, node_b: str, image: str, down_nodes: set[str] | None = None
    ):
        """Create a single veth pair between two containers.

        ``down_nodes`` is None at first setup, when every container must be
        running. On a restore it names the nodes churn has stopped.
        """
        container_a = self.topology.container_name(node_a)
        container_b = self.topology.container_name(node_b)

        pid_a = _container_pid(container_a)
        pid_b = _container_pid(container_b)
        if pid_a is None or pid_b is None:
            stopped = [n for n, pid in ((node_a, pid_a), (node_b, pid_b)) if pid is None]
            names = ", ".join(stopped)
            if down_nodes is None:
                raise VethSetupError(
                    f"veth {node_a}--{node_b}: {names} not running at setup"
                )
            if all(n in down_nodes for n in stopped):
                # Stopped by churn: it has no namespace to join, and its own
                # restart recreates this pair.
                log.info("Veth %s--%s deferred: %s down", node_a, node_b, names)
            else:
                # Not raised: a container that exited on its own is a daemon
                # failure, and aborting here would report it as the harness's.
                # Nothing recreates this pair, so say so loudly.
                log.warning(
                    "Veth %s--%s not recreated: %s not running, and churn did "
                    "not stop all of them; the link stays absent for the rest "
                    "of the run",
                    node_a, node_b, names,
                )
            return

        # Generate names
        host_a = self.topology.veth_host_name(node_a, node_b, "a")
        host_b = self.topology.veth_host_name(node_a, node_b, "b")
        final_a = veth_interface_name(node_a, node_b)
        final_b = veth_interface_name(node_b, node_a)

        # Clear both final names and both temporary names out of the
        # containers first. A stopped node's network namespace can outlive
        # the stop by minutes, and while it does the survivor still holds its
        # old `ve-X-Y`, whose peer sits in that namespace; the rename below
        # then fails with "File exists". Deleting the survivor's end removes
        # its peer too. A temporary name is left behind only by a restore
        # that failed after the move, and it blocks the next move the same
        # way.
        _purge_links(container_a, [final_a, host_a])
        _purge_links(container_b, [final_b, host_b])

        # Clean up a stale pair left by this scenario. The token makes the
        # name unique to this run, so a pair orphaned by an earlier run is
        # no longer reclaimed here — `ci-cleanup.sh` reaps those instead.
        _run_host(["ip", "link", "delete", host_a], image, check=False)

        _require_host(
            ["ip", "link", "add", host_a, "type", "veth", "peer", "name", host_b],
            image, host_a, HOST_NS,
        )
        _require_host(
            ["ip", "link", "set", host_a, "netns", str(pid_a)],
            image, host_a, container_a,
        )
        _require_host(
            ["ip", "link", "set", host_b, "netns", str(pid_b)],
            image, host_b, container_b,
        )

        _raise_link(container_a, host_a, final_a)
        _raise_link(container_b, host_b, final_b)
        _await_up(container_a, final_a)
        _await_up(container_b, final_b)

        # Read only after both ends are proven renamed and up. Before, a
        # failed rename left the old interface under the final name, and this
        # read its MAC and reported the restore as a success.
        mac_a = _get_mac_in_container(container_a, final_a)
        mac_b = _get_mac_in_container(container_b, final_b)
        if not mac_a or not mac_b:
            raise VethSetupError(
                f"veth {node_a}--{node_b} is up but its MAC could not be read "
                f"({final_a}: {mac_a or '?'}, {final_b}: {mac_b or '?'})"
            )
        self.topology.nodes[node_a].ethernet_macs[node_b] = mac_a
        self.topology.nodes[node_b].ethernet_macs[node_a] = mac_b

        self._host_pairs.append((node_a, node_b, host_a, host_b))

        log.info(
            "Veth %s(%s) -- %s(%s)  MAC: %s / %s",
            node_a, final_a, node_b, final_b, mac_a, mac_b,
        )


def _in_container(container: str, cmd: str, what: str, timeout: int = EXEC_TIMEOUT_SECS) -> str:
    """Run a command inside a container, raising `VethSetupError` on failure."""
    try:
        return docker_exec(container, cmd, timeout=timeout)
    except (DockerExecError, subprocess.TimeoutExpired) as e:
        raise VethSetupError(f"{what} in {container} failed: {e}") from e


def _purge_links(container: str, names: list[str]):
    """Delete each named interface in a container if it exists, in one exec.

    An absent name is the ordinary case and is skipped. A delete that fails
    raises, since the rename that follows would then fail on the name too,
    unless the name is gone by then: a lingering namespace can be reaped
    between the check and the delete, taking the survivor's end with it.
    """
    script = "; ".join(
        f"if ip link show {name} >/dev/null 2>&1; then "
        f"ip link delete {name} || ! ip link show {name} >/dev/null 2>&1 || exit 1; fi"
        for name in names
    )
    _in_container(container, script, f"deleting stale {', '.join(names)}")


def _require_host(cmd: list[str], image: str, link: str, want: str):
    """Run a host-namespace ``ip`` command, raising `VethSetupError` on failure.

    ``link`` and ``want`` are the command's effect: ``link`` sits in
    namespace ``want``, which is `HOST_NS` or a container name. A command
    that fails outright raises at once. One that times out may still have
    taken effect, since its helper can finish after the client is killed, so
    the link is looked for first: found where the command puts it, the
    command is not repeated, because a second move or add of the same link
    fails. Otherwise it is tried again, up to `HOST_CMD_ATTEMPTS` in all.

    A retry that fails is checked the same way before it raises. A timed-out
    helper docker did not yet know when it was removed can still start, and
    if it does so between the check and the retry, its command is the one
    that takes effect and the retry's fails on the link it moved or made.
    """
    text = " ".join(cmd)
    for attempt in range(1, HOST_CMD_ATTEMPTS + 1):
        outcome = _run_host(cmd, image)
        if outcome is HostOutcome.OK:
            return
        containers = [] if want == HOST_NS else [want]
        if outcome is HostOutcome.FAILED:
            if attempt > 1 and _link_place(link, image, containers) == want:
                log.warning(
                    "%s failed on attempt %d, but an earlier attempt's helper "
                    "had already taken effect",
                    text, attempt,
                )
                return
            raise VethSetupError(f"host command failed: {text}")
        place = _link_place(link, image, containers)
        if place == want:
            log.warning(
                "%s has taken effect though attempt %d timed out; not repeated",
                text, attempt,
            )
            return
    raise VethSetupError(
        f"host command timed out {HOST_CMD_ATTEMPTS} times, "
        f"{HOST_CMD_TIMEOUT_SECS:g}s each: {text}"
    )


def _link_place(link: str, image: str, containers: list[str]) -> str:
    """Find which namespace a link is in, logging the answer.

    Returns a container name from ``containers``, `HOST_NS`, ``"absent"``, or
    ``"unknown"`` when a read could not be made. The containers are read first,
    through `docker exec`, and the host only if the link is in none of them,
    since that read needs another helper container.
    """
    unread = []
    for container in containers:
        try:
            answer = docker_exec(
                container,
                f"ip link show {link} >/dev/null 2>&1 && echo present || echo absent",
                timeout=EXEC_TIMEOUT_SECS,
            ).strip()
        except (DockerExecError, subprocess.TimeoutExpired) as e:
            log.warning("could not look for %s in %s: %s", link, container, e)
            unread.append(container)
            continue
        if answer == "present":
            log.warning("%s is in %s", link, container)
            return container
    outcome = _run_host(
        ["ip", "link", "show", link], image, check=False,
        timeout=HELPER_CHECK_TIMEOUT_SECS,
    )
    if outcome is HostOutcome.OK:
        log.warning("%s is in the host namespace", link)
        return HOST_NS
    if outcome is HostOutcome.TIMEOUT or unread:
        log.warning("%s could not be found: a read of its namespace failed", link)
        return "unknown"
    log.warning(
        "%s is in neither the host namespace nor %s",
        link, ", ".join(containers) or "a container",
    )
    return "absent"


def _raise_link(container: str, temp: str, final: str):
    """Rename a moved veth end to its final name and set it up."""
    _in_container(
        container,
        f"ip link set {temp} name {final} && ip link set {final} up",
        f"renaming {temp} to {final}",
    )


def _await_up(container: str, iface: str):
    """Wait for an interface's operstate to read ``up``, else raise.

    A veth end reports up only once both ends are up, so this proves the
    pair is joined as well as that this end was raised.
    """
    deadline = time.monotonic() + OPERSTATE_WAIT_SECS
    state = None
    reads = 0
    while True:
        state = docker_exec_quiet(
            container, f"cat /sys/class/net/{iface}/operstate", timeout=EXEC_TIMEOUT_SECS
        )
        state = state.strip() if state is not None else None
        reads += 1
        if state == "up":
            return
        if reads >= 2 and time.monotonic() >= deadline:
            raise VethSetupError(
                f"{iface} in {container} reads operstate {state or '?'}, "
                f"not up, {OPERSTATE_WAIT_SECS}s after it was raised"
            )
        time.sleep(0.2)


def _container_pid(container: str) -> int | None:
    """Return a container's PID, or None when docker reports it not running.

    Raises `VethSetupError` when docker cannot be asked. A timed-out or failed
    inspect of a running container used to read as "not running", so under
    host load a live link was skipped and never recreated.
    """
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Pid}}", container],
            capture_output=True,
            text=True,
            timeout=EXEC_TIMEOUT_SECS,
        )
    except subprocess.TimeoutExpired as e:
        raise VethSetupError(f"docker inspect {container} timed out") from e
    if result.returncode != 0:
        raise VethSetupError(
            f"docker inspect {container} failed: {result.stderr.strip()}"
        )
    try:
        pid = int(result.stdout.strip())
    except ValueError as e:
        raise VethSetupError(
            f"docker inspect {container} returned no PID: {result.stdout.strip()!r}"
        ) from e
    return pid if pid > 0 else None


def _get_mac_in_container(container: str, iface: str) -> str | None:
    """Query the MAC address of an interface inside a container."""
    result = docker_exec_quiet(
        container,
        f"cat /sys/class/net/{iface}/address",
        timeout=EXEC_TIMEOUT_SECS,
    )
    if result is not None:
        return result.strip()
    return None


def _run_host(
    cmd: list[str],
    image: str,
    check: bool = True,
    timeout: float | None = None,
) -> HostOutcome:
    """Run an ``ip`` command via a privileged Docker container.

    Uses ``--net=host --pid=host --privileged`` so the container shares
    the Docker host's (or Docker Desktop VM's) network and PID
    namespaces.  This makes ``ip link set ... netns <pid>`` work
    correctly on both Linux and macOS.

    ``image`` should be a Docker image that has ``iproute2`` installed
    (e.g. the simulation's own image built from the chaos Dockerfile).

    ``--entrypoint ip`` overrides the image's default entrypoint so the
    simulation entrypoint script is not executed.

    Each helper gets a unique name, so one that times out can be found and
    removed: the timeout kills only the docker client, and the container
    goes on running the command. ``timeout`` defaults to
    `HOST_CMD_TIMEOUT_SECS`.
    """
    if timeout is None:
        timeout = HOST_CMD_TIMEOUT_SECS
    helper = f"fips-ip{name_suffix()}-{uuid.uuid4().hex[:12]}"
    docker_cmd = [
        "docker", "run", "--rm",
        "--name", helper,
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
            timeout=timeout,
        )
        if check and result.returncode != 0:
            # Warning, not debug: the runner logs at INFO unless asked for
            # -v, so at debug this never reached runner.log and the callers
            # below report only that a pair could not be created. The
            # check=False deletes are expected to fail and stay silent.
            log.warning(
                "ip cmd failed: %s -> %s",
                " ".join(cmd),
                result.stderr.strip(),
            )
            return HostOutcome.FAILED
        return HostOutcome.OK if result.returncode == 0 else HostOutcome.FAILED
    except subprocess.TimeoutExpired:
        log.warning("ip cmd timed out after %gs: %s (helper %s)", timeout, " ".join(cmd), helper)
        _remove_helper(helper)
        return HostOutcome.TIMEOUT


def _remove_helper(helper: str) -> None:
    """Record a timed-out helper's state, then remove it by name.

    The state is read first because it is the evidence for why the command
    stalled: a helper still being created points at the docker daemon, one
    running at the kernel. A helper docker does not know may not have been
    created yet. One that starts after this cannot undo a retry. A late move
    fails, because the link has left the host. A late add succeeds once the
    retry has moved both ends out, and leaves a stray pair under the same vh
    names in the host namespace. It is not one of the run's links: the host
    delete before the pair's next restore, teardown_all, or ci-cleanup's
    vh<token> sweep removes it.
    """
    state = _docker_quiet(["docker", "inspect", "-f", "{{json .State}}", helper])
    log.warning("helper %s state at timeout: %s", helper, state)
    removed = _docker_quiet(["docker", "rm", "-f", helper])
    log.warning("helper %s removal: %s", helper, removed)


def _docker_quiet(cmd: list[str]) -> str:
    """Run a docker command for the record; return its output or why it failed."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=HELPER_CHECK_TIMEOUT_SECS
        )
    except subprocess.TimeoutExpired:
        return f"timed out after {HELPER_CHECK_TIMEOUT_SECS}s"
    if result.returncode != 0:
        return f"exit {result.returncode}: {result.stderr.strip()}"
    return result.stdout.strip() or "ok"
