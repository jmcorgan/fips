"""Thin wrapper around subprocess for docker exec calls."""

from __future__ import annotations

import subprocess
import logging

log = logging.getLogger(__name__)

# `docker compose` renders its progress UI on stderr, so a failed command can
# have hundreds of lines of captured output behind it. Log the tail: whatever
# the daemon refused is the last thing it wrote.
OUTPUT_TAIL_CHARS = 2000


def _tail(text: str) -> str:
    """Trim captured output to its last few KB for logging."""
    text = text.strip()
    if not text:
        return "(empty)"
    if len(text) <= OUTPUT_TAIL_CHARS:
        return text
    return "...\n" + text[-OUTPUT_TAIL_CHARS:]


def _decode(output) -> str:
    """Render captured output as text.

    A timed-out command hands back what it had written as bytes, even when
    the call asked for text, so the timeout path cannot assume either.
    """
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode(errors="replace")
    return output


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
    """Run a docker compose command with the given compose file.

    Output is captured, so a failure's stderr is logged here before anything
    else sees it. `CalledProcessError` reports only the argv and the exit
    status, and a `check=False` caller reads neither, so without this the one
    place the daemon says what it objected to -- a container name already in
    use, an unusable subnet, a missing image -- is captured and then thrown
    away. Nothing about the success path changes.
    """
    cmd = ["docker", "compose", "-f", compose_file] + args
    log.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        # A timeout raises from inside communicate(), so the return-code
        # branch below never runs and this is the only chance to say what
        # the command had managed to emit. The partials arrive as bytes
        # even under text=True.
        log.error(
            "%s timed out after %ds\nstderr: %s\nstdout: %s",
            " ".join(cmd),
            timeout,
            _tail(_decode(e.stderr)),
            _tail(_decode(e.stdout)),
        )
        raise
    if result.returncode != 0:
        log.error(
            "%s exited %d\nstderr: %s\nstdout: %s",
            " ".join(cmd),
            result.returncode,
            _tail(result.stderr),
            _tail(result.stdout),
        )
        if check:
            raise subprocess.CalledProcessError(
                result.returncode, cmd, result.stdout, result.stderr
            )
    return result


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
