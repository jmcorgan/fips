#!/usr/bin/env python3
"""Control socket client for the native API checks.

Speaks the control socket's line-delimited JSON protocol: one request line, one
response line, one command per connection. That is a different protocol from the
native API's — whose connection outlives its first command and carries
descriptors — which is why this is a separate tool rather than another step type
in `client.py`.

It runs in a container for the same reason the native API client does: both
sockets are bound 0o770 root:fips, so the host user running the harness cannot
open either, while a client container mounting the same directory runs as root
and can.

Usage:
  control.py --socket PATH --command show_native_flows
  control.py --socket PATH --command show_native_flows --expect data.flows.0.local_port=4501

An expectation is `dotted.path=value` or `dotted.path>value`. A path segment of
digits indexes a list, so `data.flows.0.state` reads the first flow's state. The
value is parsed as JSON where it parses and taken as a plain string where it
does not, so both `4501` and `established` say what they look like. `>` compares
numerically and is how a check asserts a counter moved without pinning a total
that the wire is free to reach by more than one datagram.

Exit 0 when every expectation holds, 1 when one does not, 2 on a connection or
protocol failure. The reply is printed either way, because a check that missed
one field needs the whole object to say why.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from typing import Any

MISSING = object()
"""Distinguishes a path that is absent from one whose value is JSON null."""


def query(path: str, command: str, timeout: float) -> dict:
    """Send one command over its own connection and return the decoded reply."""
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(timeout)
    try:
        conn.connect(path)
        conn.sendall((json.dumps({"command": command}) + "\n").encode())
        buffer = b""
        while b"\n" not in buffer:
            chunk = conn.recv(65536)
            if not chunk:
                raise ConnectionError("the control socket closed before replying")
            buffer += chunk
        return json.loads(buffer.split(b"\n", 1)[0].decode())
    finally:
        conn.close()


def dig(value: Any, dotted: str) -> Any:
    """Read a dotted path out of a reply, indexing lists on a numeric segment."""
    for key in dotted.split("."):
        if isinstance(value, list):
            if not key.isdigit() or int(key) >= len(value):
                return MISSING
            value = value[int(key)]
        elif isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return MISSING
    return value


def parse(text: str) -> Any:
    """Read an expectation's value as JSON, falling back to a plain string."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def split(expectation: str) -> tuple[str, str, Any]:
    """Split `path=value` or `path>value` on whichever operator comes first."""
    cuts = [(expectation.index(op), op) for op in ("=", ">") if op in expectation]
    if not cuts:
        raise ValueError(f"{expectation!r} carries neither '=' nor '>'")
    at, op = min(cuts)
    return expectation[:at], op, parse(expectation[at + 1:])


def check(reply: dict, expectation: str) -> str | None:
    """Return a message when the expectation does not hold, else None."""
    dotted, op, wanted = split(expectation)
    got = dig(reply, dotted)
    if got is MISSING:
        return f"{dotted}: wanted {op}{wanted!r}, but the path is absent"
    if op == "=":
        return None if got == wanted else f"{dotted}: wanted {wanted!r}, got {got!r}"
    if isinstance(got, bool) or not isinstance(got, (int, float)) or got <= wanted:
        return f"{dotted}: wanted more than {wanted!r}, got {got!r}"
    return None


def main() -> int:
    """Query the control socket and report every expectation that did not hold."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, help="control socket path")
    parser.add_argument("--command", required=True, help="control command to send")
    parser.add_argument(
        "--expect",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="dotted-path expectation; repeatable",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="socket timeout in seconds (default: 5)",
    )
    args = parser.parse_args()

    try:
        reply = query(args.socket, args.command, args.timeout)
    except (OSError, ConnectionError, json.JSONDecodeError) as error:
        print(f"{args.command} on {args.socket} failed: {error}", file=sys.stderr)
        return 2

    print(json.dumps(reply))

    if reply.get("status") != "ok":
        print(f"{args.command} answered {reply.get('status')!r}", file=sys.stderr)
        return 1

    try:
        problems = [
            message
            for message in (check(reply, expectation) for expectation in args.expect)
            if message is not None
        ]
    except ValueError as error:
        print(f"  {error}", file=sys.stderr)
        return 2
    for message in problems:
        print(f"  {message}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
