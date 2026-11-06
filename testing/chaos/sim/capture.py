"""Packet captures on a container's interface for a scheduled step.

A capture runs ``tcpdump -w`` in the node's container on one interface,
from just before a step to just after it, and is read back with
``tcpdump -r -e -tt`` into one record per frame: its time, its source and
destination MAC, its ethertype and length, and for an IPv4 frame its source
and destination address and port. The figures compare the frames a capture
saw from an address with the path messages its node logged sending there.
"""

from __future__ import annotations

import logging
import re
import time

from .docker_exec import DockerExecError, docker_exec
from .schedule import StepError

log = logging.getLogger(__name__)

# How long a capture may take to start listening, or to stop, before the
# step fails rather than score frames nobody captured.
READY_SECS = 5.0

_FRAME = re.compile(
    r"^(\d+\.\d+) (\S+) > (\S+), ethertype (.+?) \((0x[0-9a-f]+)\), length (\d+): ?(.*)$"
)
_IPPAIR = re.compile(r"^(\d+\.\d+\.\d+\.\d+\.\d+) > (\d+\.\d+\.\d+\.\d+\.\d+):")


def parse(text: str) -> list[dict]:
    """Frames from ``tcpdump -r FILE -nn -e -tt`` output."""
    frames = []
    for line in text.splitlines():
        m = _FRAME.match(line.strip())
        if not m:
            continue
        frame = {
            "t": float(m.group(1)),
            "src": m.group(2),
            "dst": m.group(3),
            "type": m.group(5),
            "len": int(m.group(6)),
        }
        ip = _IPPAIR.match(m.group(7))
        if ip:
            frame["ip_src"], frame["ip_dst"] = ip.group(1), ip.group(2)
        frames.append(frame)
    return frames


def _exec(container: str, cmd: str) -> str:
    """Run ``cmd`` in ``container``; a failure fails the step."""
    try:
        return docker_exec(container, cmd)
    except (DockerExecError, OSError) as e:
        raise StepError(f"capture command in {container} failed: {e}") from e


class Capture:
    """One tcpdump on ``iface`` in ``container``, started and stopped by the
    schedule around a step."""

    def __init__(self, container: str, iface: str, tag: str,
                 filt: str = "", limit: int | None = None):
        """A capture on ``iface`` in ``container``, its files under
        ``/tmp/fips-cap-<tag>.*`` there; not started until ``start``."""
        self.container = container
        self.iface = iface
        self.base = f"/tmp/fips-cap-{tag}"
        self.pid: str | None = None
        # A tcpdump filter expression, and a count after which tcpdump
        # stops: for a run-long capture that needs only some frames.
        self.filt = filt
        self.limit = limit

    def start(self) -> None:
        """Start the capture and wait until tcpdump is listening."""
        # --immediate-mode: without it libpcap hands frames over a block at
        # a time, and the SIGTERM in `stop` ends tcpdump with the frames of
        # roughly the last second received but never written.
        out = _exec(
            self.container,
            f"nohup tcpdump -i {self.iface} -nn -U --immediate-mode "
            + (f"-c {self.limit} " if self.limit else "")
            + f"-w {self.base}.pcap "
            + (f"'{self.filt}' " if self.filt else "")
            + f"> {self.base}.err 2>&1 & echo $!",
        )
        self.pid = out.strip().splitlines()[-1] if out.strip() else None
        err = ""
        deadline = time.monotonic() + READY_SECS
        while time.monotonic() < deadline:
            err = _exec(self.container, f"cat {self.base}.err 2>/dev/null; true")
            if "listening on" in err:
                return
            time.sleep(0.1)
        raise StepError(f"capture on {self.container}:{self.iface} did not start: {err!r:.120}")

    def stop(self) -> list[dict]:
        """Stop the capture and return its frames."""
        if self.pid is None:
            raise StepError(f"capture on {self.container}:{self.iface} was not started")
        # TERM, not INT: a job started with & by a non-interactive shell
        # ignores SIGINT, and tcpdump keeps an ignored SIGINT ignored.
        _exec(self.container, f"kill -TERM {self.pid} 2>/dev/null; true")
        deadline = time.monotonic() + READY_SECS
        while time.monotonic() < deadline:
            # An exited tcpdump stays a zombie until the container's init
            # reaps it, and kill -0 still finds a zombie, so read its state.
            alive = _exec(
                self.container,
                f"s=$(awk '/^State:/ {{print $2}}' /proc/{self.pid}/status 2>/dev/null); "
                f"[ -n \"$s\" ] && [ \"$s\" != Z ] && echo y; true",
            )
            if not alive.strip():
                break
            time.sleep(0.1)
        else:
            raise StepError(f"capture on {self.container}:{self.iface} did not stop")
        text = _exec(
            self.container,
            f"tcpdump -r {self.base}.pcap -nn -e -tt 2>/dev/null; "
            f"rm -f {self.base}.pcap {self.base}.err",
        )
        frames = parse(text)
        log.info("Capture %s:%s: %d frames", self.container, self.iface, len(frames))
        return frames
