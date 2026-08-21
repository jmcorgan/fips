#!/usr/bin/env python3
"""Native datagram API client for the increment checks.

Speaks the line-delimited JSON command protocol on the daemon's native API
socket. A run takes a script: a list of steps sent over ONE connection. The
connection owns nothing — a flow lives until its own descriptor is closed, and a
listener until its own is — so the single connection is a convenience for the
checks rather than a lifetime the daemon respects. Descriptors are what keep
things alive, and this tool holds them until the step that closes them or until
it exits.

Kinds of step:

  RPC step:  {"command": str, "params": {...}?, "expect": {"dotted.key": val}?,
              "keep_fd": name?, "keep_listener": name?, "keep_flow": name?}
             Sends a command and checks the reply. `keep_fd` stores a flow
             descriptor under that name, `keep_listener` a listener descriptor;
             every reply that carries one must name it, because a descriptor
             nothing named is a flow or a port silently dropped. `keep_flow`
             stores the reply's data.flow_id.

             A parameter or expectation whose value is the string "@name" is
             replaced by the flow identifier stored under `name`. Identifiers
             are assigned by the node and keep counting up for its lifetime, so
             a check that asserted a literal 1 would hold only for the first
             flow the daemon ever made.

  Accept step: {"accept": listener, "keep_fd": name, "expect": {...}?,
                "keep_flow": name?}
             One recvmsg on a stored listener descriptor. There is no accept
             command: an arriving flow is one SOCK_SEQPACKET message on the
             listener itself, carrying the flow's descriptor as ancillary data
             and the arrival object as its payload. Expectations are checked
             against that object, whose peer is an npub and never a hex address.

  Sleep step: {"sleep": seconds}
             Holds every descriptor open for a while, which is what a check that
             reads the daemon's own view of a live flow needs.

  Flow step: {"fd": name, ...} operating on a stored descriptor:
               "write": hex, "repeat": n?   send n datagrams of those bytes
               "read": n, "expect_bytes": hex?, "sizes": [..]?
                                            read n datagrams and check them
               "readable": bool             check poll readability now
               "close": true                close the descriptor
             `readable` and `close` work on a listener descriptor too: a
             listener is pollable, and closing it unbinds its port.

Reading is per-datagram: the descriptor is SOCK_SEQPACKET, so one recv is one
datagram. A check that reads three and gets one concatenated blob is a real
failure, not a quirk of the tool.

Usage:
  client.py --socket PATH --script '<json list of steps>'
  client.py --socket PATH --script-file steps.json

Exit 0 when every expectation holds, 1 otherwise, 2 on a connection failure.
"""

from __future__ import annotations

import argparse
import array
import json
import os
import select
import socket
import sys
import time
from typing import Any

# A flow's descriptor and a listener's are both AF_UNIX SOCK_SEQPACKET, so the
# wrap happens to be the same for both. Naming the roles anyway is the point:
# the next descriptor kind that is not one of these must not be wrapped
# correctly by accident.
FLOW = "flow"
LISTENER = "listener"


def recvfds(sock: socket.socket, bufsize: int, maxfds: int) -> tuple[bytes, list[int]]:
    """One recvmsg, returning its payload and whatever descriptors it carried.

    Written out rather than calling `socket.recv_fds`, which takes a `flags`
    argument and never forwards it to `recvmsg`: MSG_CMSG_CLOEXEC passed to that
    helper does nothing, and a descriptor the harness kept would then survive
    into any child process it forked. Measured on CPython 3.12 by reading
    FD_CLOEXEC back with `fcntl.F_GETFD` after each of the two calls.
    """
    fds = array.array("i")
    data, ancillary, _flags, _addr = sock.recvmsg(
        bufsize, socket.CMSG_LEN(maxfds * fds.itemsize), socket.MSG_CMSG_CLOEXEC
    )
    for level, kind, payload in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            # Truncated to whole descriptors: the kernel may cut the array
            # short, and a partial one names nothing.
            fds.frombytes(payload[: len(payload) - (len(payload) % fds.itemsize)])
    return data, list(fds)


class Protocol(Exception):
    """The daemon broke the local protocol, so the run cannot continue."""


class Client:
    """One connection to the native API socket, plus the descriptors it holds."""

    def __init__(self, path: str, timeout: float) -> None:
        """Connect to the socket at `path`, failing after `timeout` seconds."""
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(path)
        self.timeout = timeout
        self.buf = b""
        # Complete lines, oldest first, each with the descriptor it arrived
        # with. See `fill` for the rule that decides which line that is.
        self.lines: list[list[Any]] = []
        self.fds: dict[str, tuple[socket.socket, str]] = {}
        self.flows: dict[str, int] = {}

    def call(self, command: str, params: dict | None) -> tuple[dict, int | None]:
        """Send one command; return the decoded reply and any descriptor.

        The socket carries replies only, in command order, so the next complete
        line is this command's answer and there is nothing to separate out.
        """
        request: dict[str, Any] = {"command": command}
        if params is not None:
            request["params"] = params
        self.sock.sendall(json.dumps(request).encode() + b"\n")
        line, fd = self.line()
        return json.loads(line), fd

    def line(self) -> tuple[bytes, int | None]:
        """Take the next complete line, reading until one is available."""
        while not self.lines:
            self.fill()
        line, fd = self.lines.pop(0)
        return line, fd

    def fill(self) -> None:
        """One recvmsg, split into lines, with any descriptor placed by the rule.

        A DESCRIPTOR BELONGS TO THE LAST COMPLETE LINE OF THE READ THAT CARRIED
        IT, never to the next line the reader assembles. A recvmsg returning
        ancillary data ends exactly at the end of the sendmsg that carried it,
        but it may begin with any amount of data written before it, so a reader
        that attached the descriptor to the first line it completed would hand a
        flow to the wrong reply. Both reply kinds carry a descriptor now, so
        this is reachable rather than theoretical.

        A read that carries a descriptor and completes no line is reported
        rather than guessed at: holding it would mean choosing a later line for
        it, and choosing wrong loses a flow with no error anywhere.
        """
        chunk, fds = recvfds(self.sock, 65536, 4)
        if not chunk:
            for stray in fds:
                # Closed rather than leaked: nothing can name it now.
                os.close(stray)
            raise ConnectionError("daemon closed the connection")
        self.buf += chunk

        produced = 0
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            self.lines.append([line, None])
            produced += 1

        if not fds:
            return
        # This protocol never sends two at once. Extras are closed rather than
        # left open with no owner.
        for stray in fds[1:]:
            os.close(stray)
        if produced == 0:
            os.close(fds[0])
            raise Protocol("a descriptor arrived on a read that completed no line")
        self.lines[-1][1] = fds[0]

    def accept(self, listener: str) -> tuple[dict, int]:
        """Take the next arriving flow off a stored listener descriptor.

        One recvmsg, one arrival: SOCK_SEQPACKET means the message carries
        exactly its own descriptor, so the association rule the RPC socket needs
        does not arise here. The payload has no trailing newline, because the
        message boundary is the framing.
        """
        sock = self.held(listener, LISTENER)
        data, fds = recvfds(sock, 65536, 1)
        if not fds:
            raise Protocol(f"{listener!r} produced an arrival with no descriptor")
        if not data:
            os.close(fds[0])
            raise Protocol(f"{listener!r} produced a descriptor with no arrival")
        return json.loads(data), fds[0]

    def held(self, name: str, want: str) -> socket.socket:
        """Return a stored descriptor, refusing one of the wrong kind."""
        if name not in self.fds:
            raise Protocol(f"no descriptor named {name!r}")
        sock, role = self.fds[name]
        if role != want:
            raise Protocol(f"{name!r} is a {role} descriptor, not a {want} one")
        return sock

    def keep(self, name: str, fd: int, role: str) -> None:
        """Store a received descriptor under `name`, wrapped for its kind."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET, fileno=fd)
        sock.settimeout(self.timeout)
        self.fds[name] = (sock, role)

    def close(self) -> None:
        """Close every descriptor, then the connection itself."""
        for sock, _role in self.fds.values():
            sock.close()
        self.sock.close()


def substitute(value: Any, flows: dict[str, int]) -> Any:
    """Replace every "@name" with the flow identifier stored under `name`."""
    if isinstance(value, str) and value.startswith("@"):
        name = value[1:]
        if name not in flows:
            raise KeyError(f"no flow captured as {name!r}")
        return flows[name]
    if isinstance(value, dict):
        return {key: substitute(item, flows) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute(item, flows) for item in value]
    return value


def dig(value: Any, dotted: str) -> Any:
    """Read a dotted path out of a decoded reply, or None where it is absent."""
    for key in dotted.split("."):
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def check(reply: dict, expect: dict) -> list[str]:
    """Return one message per expectation the reply does not satisfy."""
    problems = []
    for dotted, wanted in expect.items():
        got = dig(reply, dotted)
        if got != wanted:
            problems.append(f"{dotted}: wanted {wanted!r}, got {got!r}")
    return problems


def store(client: Client, step: dict, body: dict, fd: int | None) -> list[str]:
    """Store what a step asked to keep, reporting a descriptor nobody named."""
    problems: list[str] = []

    keep = step.get("keep_flow")
    if keep is not None:
        # A reply nests the identifier under `data`; an arrival message is the
        # object itself. One reader for both, because a step should not have to
        # know which produced it.
        flow = dig(body, "data.flow_id")
        if flow is None:
            flow = body.get("flow_id")
        if flow is None:
            problems.append("keep_flow: nothing carried a flow_id")
        else:
            client.flows[keep] = flow

    wanted = [(step.get("keep_fd"), FLOW), (step.get("keep_listener"), LISTENER)]
    named = [(name, role) for name, role in wanted if name is not None]
    if len(named) > 1:
        if fd is not None:
            os.close(fd)
        problems.append("a step named both keep_fd and keep_listener")
    elif named and fd is None:
        problems.append(f"{named[0][0]!r}: no descriptor arrived to keep")
    elif named:
        client.keep(named[0][0], fd, named[0][1])
    elif fd is not None:
        # Leaving it unnamed would leak a flow or a held port for the rest of
        # the run, with nothing to say so.
        os.close(fd)
        problems.append("a descriptor arrived that the step did not name")

    return problems


def run_rpc(client: Client, step: dict) -> list[str]:
    """Send one command and report what did not hold."""
    command = step["command"]
    try:
        params = substitute(step.get("params"), client.flows)
        expect = substitute(step.get("expect", {}), client.flows)
    except KeyError as error:
        return [str(error)]

    reply, fd = client.call(command, params)
    problems = check(reply, expect)
    problems += store(client, step, reply, fd)

    if problems:
        problems.append(f"reply: {json.dumps(reply)}")
    return problems


def run_accept(client: Client, step: dict) -> list[str]:
    """Take one arrival off a listener and report what did not hold."""
    try:
        arrival, fd = client.accept(step["accept"])
    except socket.timeout:
        return [f"timed out waiting for an arrival on {step['accept']!r}"]

    problems = check(arrival, substitute(step.get("expect", {}), client.flows))
    problems += store(client, step, arrival, fd)

    if problems:
        problems.append(f"arrival: {json.dumps(arrival)}")
    return problems


def run_sleep(step: dict) -> list[str]:
    """Hold every descriptor open for a while, failing nothing."""
    time.sleep(float(step["sleep"]))
    return []


def run_flow(client: Client, step: dict) -> list[str]:
    """Operate on a stored descriptor and report what did not hold."""
    name = step["fd"]
    if name not in client.fds:
        return [f"no descriptor named {name!r}"]
    flow, _role = client.fds[name]

    problems: list[str] = []

    if "readable" in step:
        ready, _, _ = select.select([flow], [], [], 0.25)
        got = bool(ready)
        if got != step["readable"]:
            problems.append(f"readable: wanted {step['readable']}, got {got}")

    if "write" in step:
        payload = bytes.fromhex(step["write"])
        for _ in range(step.get("repeat", 1)):
            flow.send(payload)

    if "read" in step:
        wanted = bytes.fromhex(step["expect_bytes"]) if "expect_bytes" in step else None
        sizes = []
        for index in range(step["read"]):
            try:
                got = flow.recv(65536)
            except socket.timeout:
                problems.append(f"read {index}: timed out waiting for a datagram")
                break
            sizes.append(len(got))
            if wanted is not None and got != wanted:
                problems.append(
                    f"read {index}: wanted {wanted.hex()}, got {got.hex()}"
                )
        if "sizes" in step and sizes != step["sizes"]:
            problems.append(f"sizes: wanted {step['sizes']}, got {sizes}")

    if step.get("close"):
        flow.close()
        del client.fds[name]

    return problems


def label_of(step: dict) -> str:
    """The name a step is reported under, which callers wait on by substring."""
    if "fd" in step:
        return f"fd {step['fd']}"
    if "accept" in step:
        return f"accept {step['accept']}"
    if "sleep" in step:
        return f"sleep {step['sleep']}"
    return step.get("command", "?")


def main() -> int:
    """Run the script against the socket and report every failing step."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, help="native API socket path")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--script", help="steps as a JSON list")
    group.add_argument("--script-file", help="file holding the steps as a JSON list")
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="socket timeout in seconds (default: 5)",
    )
    args = parser.parse_args()

    text = args.script
    if text is None:
        with open(args.script_file, encoding="utf-8") as handle:
            text = handle.read()
    steps = json.loads(text)

    try:
        client = Client(args.socket, args.timeout)
    except OSError as error:
        print(f"connect to {args.socket} failed: {error}", file=sys.stderr)
        return 2

    failures = 0
    try:
        for index, step in enumerate(steps):
            label = label_of(step)
            try:
                if "fd" in step:
                    problems = run_flow(client, step)
                elif "accept" in step:
                    problems = run_accept(client, step)
                elif "sleep" in step:
                    problems = run_sleep(step)
                else:
                    problems = run_rpc(client, step)
            except (OSError, ConnectionError, Protocol, json.JSONDecodeError) as error:
                print(f"step {index} ({label}): {error}", file=sys.stderr)
                return 2

            if problems:
                failures += 1
                print(f"step {index} ({label}) FAILED", file=sys.stderr)
                for problem in problems:
                    print(f"  {problem}", file=sys.stderr)
            else:
                print(f"step {index} ({label}) ok")
    finally:
        client.close()

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
