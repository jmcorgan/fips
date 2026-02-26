"""Thin wrapper around subprocess for docker exec calls."""

from __future__ import annotations

import subprocess
import logging

log = logging.getLogger(__name__)


class DockerExecError(Exception):
    def __init__(self, container, cmd, returncode, stderr):
        self.container = container
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(
            f"docker exec {container}: {cmd!r} returned {returncode}: {stderr}"
        )


def docker_exec(container: str, cmd: str, timeout: int = 30) -> str:
    """Execute a command in a running container, return stdout."""
    result = subprocess.run(
        ["docker", "exec", container, "/bin/bash", "-c", cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise DockerExecError(container, cmd, result.returncode, result.stderr)
    return result.stdout


def docker_exec_quiet(container: str, cmd: str, timeout: int = 30) -> str | None:
    """Execute a command, return stdout on success or None on failure (logged)."""
    try:
        return docker_exec(container, cmd, timeout)
    except (DockerExecError, subprocess.TimeoutExpired) as e:
        log.warning("docker exec failed on %s: %s", container, e)
        return None


def docker_compose(
    compose_file: str,
    args: list[str],
    timeout: int = 300,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run a docker compose command with the given compose file."""
    cmd = ["docker", "compose", "-f", compose_file] + args
    log.info("Running: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def is_container_running(container: str) -> bool:
    """Check if a container is running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    except subprocess.TimeoutExpired:
        return False
