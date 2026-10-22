#!/usr/bin/env python3
"""A stand-in for the `docker` CLI, for veth-host-test.sh.

It answers the calls the chaos runner's veth setup makes, and the few the
runner makes around it, from a state directory named by FAKE_DOCKER_STATE.
Nothing reaches a real daemon or a real network namespace.

The state is a set of links, each in a namespace: "host", or the name of a
node container. `docker exec` runs the runner's own shell script under bash
with `ip` and `cat` replaced by functions that read and change that state, so
the script's own control flow is what decides the result.

A host helper (`docker run --rm ... --entrypoint ip IMAGE ARGS`) is modelled
the way docker behaves when the client is killed: the `ip` command runs in a
detached process standing for the helper container, and the client only waits
for it. A client killed by a subprocess timeout therefore leaves the helper
running, and only `docker rm -f NAME` stops it. A plan file, named by
FAKE_DOCKER_PLAN, can make a given attempt at a given host command stall:

  stall-before  the helper exists and waits SECS, then runs the command
  stall-after   the helper runs the command, then waits SECS before exiting
  late-start    the helper does not exist for SECS, then runs the command

Every call is appended to calls.log, and every change to the links to
effects.log, both in the state directory.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import signal
import subprocess
import sys
import time
from contextlib import contextmanager

STATE = os.environ.get("FAKE_DOCKER_STATE", "")
SELF = os.path.abspath(__file__)

# Node containers the fake knows, and the PID each reports. Moves address a
# namespace by PID, as `ip link set X netns PID` does.
NODE_RE = re.compile(r"^fips-node-n(\d+)")
PID_BASE = 4000
IMAGE = "fake-sim-image"

# The bash functions that stand in for `ip` and for sysfs reads inside a node
# container. FAKE_NS names the container whose namespace they act on.
PRELUDE = r'''
ip() { python3 "$FAKE_SELF" ipcmd "$FAKE_NS" "$@"; }
cat() {
    case "$1" in
        /sys/class/net/*) python3 "$FAKE_SELF" sysfs "$FAKE_NS" "$1" ;;
        *) command cat "$@" ;;
    esac
}
'''


def path(*parts: str) -> str:
    """Return a path inside the state directory."""
    return os.path.join(STATE, *parts)


def append(name: str, line: str) -> None:
    """Append one line to a log in the state directory."""
    with open(path(name), "a") as f:
        f.write(line + "\n")


@contextmanager
def locked():
    """Hold the state lock, so concurrent helpers see consistent links."""
    with open(path("lock"), "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def load_links() -> dict:
    """Read the link table: name -> {"ns", "peer", "up"}."""
    try:
        with open(path("links.json")) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_links(links: dict) -> None:
    """Write the link table."""
    with open(path("links.json"), "w") as f:
        json.dump(links, f, indent=1, sort_keys=True)


def node_pid(container: str) -> int | None:
    """Return the PID a node container reports, or None if it is not a node."""
    m = NODE_RE.match(container)
    return PID_BASE + int(m.group(1)) if m else None


def container_for_pid(pid: int) -> str | None:
    """Return the node container a PID belongs to, from the names seen so far."""
    try:
        with open(path("nodes.json")) as f:
            nodes = json.load(f)
    except FileNotFoundError:
        return None
    for name, p in nodes.items():
        if p == pid:
            return name
    return None


def remember_node(container: str, pid: int) -> None:
    """Record a node container's PID so a move can find it by PID."""
    with locked():
        try:
            with open(path("nodes.json")) as f:
                nodes = json.load(f)
        except FileNotFoundError:
            nodes = {}
        nodes[container] = pid
        with open(path("nodes.json"), "w") as f:
            json.dump(nodes, f)


# --- ip(8) on the link table --------------------------------------------


def ipcmd(ns: str, args: list[str], who: str) -> int:
    """Apply one `ip link` command in namespace ns. Returns its exit status."""
    with locked():
        links = load_links()
        rc, effect = _ip(links, ns, args)
        if effect:
            save_links(links)
            append("effects.log", f"{effect} by={who}")
    return rc


def _ip(links: dict, ns: str, args: list[str]) -> tuple[int, str]:
    """Interpret `ip link ...` against links. Returns (status, effect or '')."""
    def here(name: str) -> bool:
        return name in links and links[name]["ns"] == ns

    def missing(name: str) -> tuple[int, str]:
        print(f'Cannot find device "{name}"', file=sys.stderr)
        return 1, ""

    if args[:2] == ["link", "show"]:
        name = args[2]
        if here(name):
            print(f"1: {name}: <BROADCAST,MULTICAST> mtu 1500")
            return 0, ""
        print(f'Device "{name}" does not exist.', file=sys.stderr)
        return 1, ""
    if args[:2] == ["link", "delete"]:
        name = args[2]
        if not here(name):
            return missing(name)
        peer = links[name]["peer"]
        links.pop(name, None)
        links.pop(peer, None)
        return 0, f"delete {name} ns={ns}"
    if args[:2] == ["link", "add"]:
        # ip link add A type veth peer name B
        a, b = args[2], args[-1]
        if here(a) or here(b):
            print("RTNETLINK answers: File exists", file=sys.stderr)
            return 2, ""
        links[a] = {"ns": ns, "peer": b, "up": False}
        links[b] = {"ns": ns, "peer": a, "up": False}
        return 0, f"add {a} {b} ns={ns}"
    if args[:2] == ["link", "set"] and len(args) >= 5 and args[3] == "netns":
        name, pid = args[2], int(args[4])
        if not here(name):
            return missing(name)
        target = container_for_pid(pid)
        if target is None:
            print(f"Invalid pid {pid}", file=sys.stderr)
            return 1, ""
        links[name]["ns"] = target
        return 0, f"move {name} {ns}->{target}"
    if args[:2] == ["link", "set"] and len(args) >= 5 and args[3] == "name":
        old, new = args[2], args[4]
        if not here(old):
            return missing(old)
        if here(new):
            print("RTNETLINK answers: File exists", file=sys.stderr)
            return 2, ""
        entry = links.pop(old)
        links[new] = entry
        links[entry["peer"]]["peer"] = new
        return 0, f"rename {old}->{new} ns={ns}"
    if args[:2] == ["link", "set"] and len(args) >= 4 and args[3] == "up":
        name = args[2]
        if not here(name):
            return missing(name)
        links[name]["up"] = True
        return 0, f"up {name} ns={ns}"
    print(f"fake ip: unhandled: {' '.join(args)}", file=sys.stderr)
    return 1, ""


def sysfs(ns: str, file: str) -> int:
    """Answer a read of /sys/class/net/IFACE/{operstate,address}."""
    m = re.match(r"/sys/class/net/([^/]+)/(operstate|address)$", file)
    links = load_links()
    if not m or m.group(1) not in links or links[m.group(1)]["ns"] != ns:
        print(f"cat: {file}: No such file or directory", file=sys.stderr)
        return 1
    name, what = m.groups()
    if what == "operstate":
        peer = links[name]["peer"]
        both = links[name]["up"] and links.get(peer, {}).get("up", False)
        print("up" if both else "down")
    else:
        digits = sum(ord(c) for c in name) % 256
        print(f"02:00:00:00:00:{digits:02x}")
    return 0


# --- Helper containers ---------------------------------------------------


def helper_file(name: str, ext: str) -> str:
    """Return the path of one of a helper container's files."""
    return path("helpers", f"{name}.{ext}")


def register(name: str) -> None:
    """Make a helper container exist, as `docker create` and `start` do."""
    with open(helper_file(name, "pid"), "w") as f:
        f.write(str(os.getpid()))
    append("helpers.log", f"start {name} t={time.time():.2f}")


def unregister(name: str) -> None:
    """Remove a helper container that exited, as `--rm` does."""
    try:
        os.remove(helper_file(name, "pid"))
    except FileNotFoundError:
        pass


def helper_main(name: str, mode: str, secs: float, args: list[str]) -> None:
    """Run as the detached process standing for one helper container."""
    rc = 1
    try:
        if mode == "late-start":
            time.sleep(secs)
        register(name)
        if mode == "stall-before":
            time.sleep(secs)
        rc = ipcmd("host", args, name)
        if mode == "stall-after":
            time.sleep(secs)
        append("helpers.log", f"exit {name} rc={rc} t={time.time():.2f}")
    finally:
        unregister(name)
        with open(helper_file(name, "rc.tmp"), "w") as f:
            f.write(str(rc))
        os.rename(helper_file(name, "rc.tmp"), helper_file(name, "rc"))


def plan_for(args: list[str]) -> tuple[str, float]:
    """Return (mode, secs) for this attempt at a host command, from the plan."""
    plan_path = os.environ.get("FAKE_DOCKER_PLAN")
    if not plan_path:
        return "none", 0.0
    with open(plan_path) as f:
        rules = json.load(f)
    text = " ".join(args)
    with locked():
        try:
            with open(path("attempts.json")) as f:
                attempts = json.load(f)
        except FileNotFoundError:
            attempts = {}
        chosen = ("none", 0.0)
        bumped = set()
        for rule in rules:
            if re.search(rule["match"], text):
                key = rule["match"]
                if key not in bumped:
                    attempts[key] = attempts.get(key, 0) + 1
                    bumped.add(key)
                if attempts[key] in rule["attempts"]:
                    chosen = (rule["mode"], float(rule["secs"]))
        with open(path("attempts.json"), "w") as f:
            json.dump(attempts, f)
    return chosen


def docker_run(argv: list[str]) -> int:
    """`docker run --rm [--name N] ... --entrypoint ip IMAGE ARGS`."""
    name = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--name":
            name = argv[i + 1]
            i += 2
            continue
        if a == "--entrypoint":
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        break
    args = argv[i + 1:]
    if name is None:
        with locked():
            n = len(os.listdir(path("helpers")))
        name = f"auto-{os.getpid()}-{n}"
    mode, secs = plan_for(args)
    append("helpers.log", f"run {name} mode={mode} secs={secs} cmd={' '.join(args)}")
    subprocess.Popen(
        [sys.executable, SELF, "helper", name, mode, str(secs)] + args,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=open(helper_file(name, "out"), "w"),
        stderr=open(helper_file(name, "err"), "w"),
        env=os.environ,
    )
    # The client waits for the helper; killing the client does not stop it.
    while not os.path.exists(helper_file(name, "rc")):
        time.sleep(0.05)
    with open(helper_file(name, "out")) as f:
        sys.stdout.write(f.read())
    with open(helper_file(name, "err")) as f:
        sys.stderr.write(f.read())
    with open(helper_file(name, "rc")) as f:
        return int(f.read())


def docker_rm(argv: list[str]) -> int:
    """`docker rm -f NAME...`: kill and remove each named helper."""
    rc = 0
    for name in [a for a in argv if not a.startswith("-")]:
        pidfile = helper_file(name, "pid")
        try:
            with open(pidfile) as f:
                pid = int(f.read())
        except FileNotFoundError:
            print(f"Error response from daemon: No such container: {name}", file=sys.stderr)
            append("helpers.log", f"rm {name} absent")
            rc = 1
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        unregister(name)
        # The client waiting on it sees the container gone with status 137.
        with open(helper_file(name, "rc"), "w") as f:
            f.write("137")
        append("helpers.log", f"rm {name} killed")
        print(name)
    return rc


def docker_inspect(argv: list[str]) -> int:
    """`docker inspect -f FORMAT NAME`."""
    fmt, name = argv[1], argv[2]
    pid = node_pid(name)
    if pid is not None:
        if fmt == "{{.State.Pid}}":
            remember_node(name, pid)
            print(pid)
        elif fmt == "{{.Config.Image}}":
            print(IMAGE)
        elif fmt == "{{.State.Running}}":
            print("true")
        else:
            print("{}")
        return 0
    pidfile = helper_file(name, "pid")
    if os.path.exists(pidfile):
        with open(pidfile) as f:
            hpid = f.read()
        print(json.dumps({"Status": "running", "Running": True, "Pid": int(hpid)}))
        return 0
    print(f"Error: No such object: {name}", file=sys.stderr)
    return 1


def docker_exec(argv: list[str]) -> int:
    """`docker exec CONTAINER /bin/bash -c SCRIPT` with the fake ip and cat."""
    container, script = argv[0], argv[-1]
    env = dict(os.environ, FAKE_NS=container, FAKE_SELF=SELF)
    return subprocess.run(["bash", "-c", PRELUDE + script], env=env).returncode


def main(argv: list[str]) -> int:
    """Dispatch one docker invocation, or one of the fake's own subcommands."""
    if argv and argv[0] == "ipcmd":
        return ipcmd(argv[1], argv[2:], f"exec:{argv[1]}")
    if argv and argv[0] == "sysfs":
        return sysfs(argv[1], argv[2])
    if argv and argv[0] == "helper":
        helper_main(argv[1], argv[2], float(argv[3]), argv[4:])
        return 0

    append("calls.log", " ".join(argv))
    verb = argv[0] if argv else ""
    if verb == "run":
        return docker_run(argv[1:])
    if verb == "rm":
        return docker_rm(argv[1:])
    if verb == "inspect":
        return docker_inspect(argv[1:])
    if verb == "exec":
        return docker_exec(argv[1:])
    if verb == "logs":
        print("fake node log")
        return 0
    if verb == "network" and argv[1:2] == ["create"]:
        print("fakenetworkid")
        return 0
    # compose, image inspect, ps, network rm: succeed with nothing to say.
    return 0


if __name__ == "__main__":
    if not STATE:
        print("fake docker: FAKE_DOCKER_STATE is not set", file=sys.stderr)
        sys.exit(2)
    os.makedirs(path("helpers"), exist_ok=True)
    sys.exit(main(sys.argv[1:]))
