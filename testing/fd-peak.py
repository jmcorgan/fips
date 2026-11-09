#!/usr/bin/env python3
"""Run a command and report the most descriptors each test binary held.

A test process that runs out of descriptors fails whichever test opens the
next one, and that test is rarely the one holding them. This wrapper runs a
`cargo test` (or `cargo nextest`) command unchanged and, while it runs, counts
the open descriptors of every test binary the command starts: a process whose
executable sits in a cargo `deps/` directory. When it ends it prints, for each
binary, the highest count seen, when, and what the descriptors were at that
moment: by kind, sockets by protocol, and the most frequent file paths. A run
that hits the open-file limit then says what filled it, and a green run says
how close it came.

Usage: fd-peak.py COMMAND [ARGS...]

The command's own exit status is passed through, so wrapping a command never
changes whether it passes. The report goes to stderr, each line starting
`fd-peak:`. It is a measurement, not a check: where /proc cannot be read, the
report says that nothing was sampled. Descendants are looked for every 50 ms
and a known test process is counted every 2 ms, so a process that lives less
than 50 ms, or a burst shorter than 2 ms, can be missed; the open-file limit
itself, set by the caller, still catches any burst.
"""

import os
import resource
import signal
import subprocess
import sys
import time
from collections import Counter

SAMPLE_S = 0.002
SCAN_S = 0.05
# A socket census reads the process's /proc/net tables, so a rising count
# repeats it only this often, or once the count has grown by a tenth.
CENSUS_S = 0.1
# Each /proc/net table a socket can be listed in, and its inode column.
NET_TABLES = {
    "tcp": 9, "tcp6": 9, "udp": 9, "udp6": 9, "raw": 9, "raw6": 9,
    "netlink": 9, "packet": 8, "unix": 6,
}
TOP_PATHS = 5


def children(pid):
    """Return the pids of the direct children of every thread of `pid`."""
    out = []
    try:
        tids = os.listdir(f"/proc/{pid}/task")
    except OSError:
        return out
    for tid in tids:
        try:
            with open(f"/proc/{pid}/task/{tid}/children") as f:
                out.extend(int(p) for p in f.read().split())
        except OSError:
            pass
    return out


def descendants(root):
    """Return every live descendant of `root`."""
    seen, todo = [], [root]
    while todo:
        for child in children(todo.pop()):
            seen.append(child)
            todo.append(child)
    return seen


def test_binary(pid):
    """Return the executable's name if `pid` runs a cargo test binary."""
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None
    parent = os.path.basename(os.path.dirname(exe))
    return os.path.basename(exe) if parent == "deps" else None


def socket_protocols(pid):
    """Map each socket inode the process can see to its /proc/net table."""
    proto = {}
    for table, col in NET_TABLES.items():
        try:
            with open(f"/proc/{pid}/net/{table}") as f:
                rows = f.read().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            fields = row.split()
            if len(fields) > col:
                proto[fields[col]] = table
    return proto


def census(pid, with_sockets):
    """Classify the descriptors `pid` holds now; None if it has gone."""
    fddir = f"/proc/{pid}/fd"
    kinds, sockets, paths = Counter(), Counter(), Counter()
    try:
        names = os.listdir(fddir)
    except OSError:
        return None
    proto = socket_protocols(pid) if with_sockets else {}
    for name in names:
        try:
            link = os.readlink(f"{fddir}/{name}")
        except OSError:
            continue
        if link.startswith("socket:["):
            kinds["socket"] += 1
            if with_sockets:
                sockets[proto.get(link[8:-1], "other")] += 1
        elif link.startswith("pipe:"):
            kinds["pipe"] += 1
        elif link.startswith("anon_inode:"):
            kinds[link[len("anon_inode:"):].strip("[]")] += 1
        else:
            kinds["file"] += 1
            paths[link] += 1
    return len(names), kinds, sockets, paths


class Peak:
    """The highest descriptor count seen for one test binary."""

    def __init__(self):
        """Start with nothing seen."""
        self.count = -1
        self.at = 0.0
        self.pids = set()
        self.kinds = None
        self.paths = None
        # The last socket census: the count it was taken at, and its split.
        self.sockets = None
        self.census_at = -1.0

    def offer(self, pid, n, now):
        """Take a new count, and a census when it is a new high."""
        self.pids.add(pid)
        if n <= self.count:
            return
        last = self.sockets[0] if self.sockets else 0
        with_sockets = now - self.census_at >= CENSUS_S or n >= last * 1.1
        got = census(pid, with_sockets)
        if got is None or got[0] <= self.count:
            return
        self.count, self.kinds, sockets, self.paths = got
        self.at = now
        if with_sockets:
            self.sockets = (self.count, sockets)
            self.census_at = now


def report(peaks, elapsed, err):
    """Print one block per test binary, highest count first."""
    soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    limit = "unlimited" if soft == resource.RLIM_INFINITY else str(soft)

    def put(line):
        """Print one report line."""
        print(f"fd-peak: {line}", file=sys.stderr)

    put(f"open-file soft limit {limit}; run took {elapsed:.1f} s")
    if err:
        put(f"nothing sampled: {err}")
        return
    if not peaks:
        put("no test binary was seen")
        return
    for name, p in sorted(peaks.items(), key=lambda kv: -kv[1].count):
        if p.kinds is None:
            put(f"{name}: no count read ({len(p.pids)} processes)")
            continue
        put(f"{name}: peak {p.count} descriptors at {p.at:.1f} s"
            f" ({len(p.pids)} process{'es' if len(p.pids) != 1 else ''})")
        put("  by kind: " + ", ".join(f"{k} {v}" for k, v in p.kinds.most_common()))
        if p.sockets and p.sockets[1]:
            at, split = p.sockets
            put(f"  sockets at {at} descriptors: "
                + ", ".join(f"{k} {v}" for k, v in split.most_common()))
        if p.paths:
            put("  files: " + ", ".join(f"{k} x{v}" for k, v in p.paths.most_common(TOP_PATHS)))


def main():
    """Run the command, sample its test binaries, report, pass its status on."""
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(sys.argv[1:])
    except OSError as e:
        print(f"fd-peak: cannot run {sys.argv[1]}: {e}", file=sys.stderr)
        return 127
    # The command shares the terminal's process group, so a Ctrl-C reaches it
    # directly; this process only waits for it to finish. A TERM sent to this
    # process alone is passed on, so the command does not outlive it.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, lambda *_: proc.send_signal(signal.SIGTERM))
    peaks, tracked, err = {}, {}, None
    if not os.path.isdir("/proc/self/task"):
        err = "/proc is not readable here"
    next_scan = 0.0
    while proc.poll() is None:
        now = time.monotonic() - t0
        if err is None and now >= next_scan:
            next_scan = now + SCAN_S
            # Looked up afresh each time: a child cargo has forked but not
            # yet exec'd still runs cargo, and a pid can be reused.
            tracked = {pid: test_binary(pid) for pid in descendants(proc.pid)}
        for pid, name in list(tracked.items()):
            if name is None:
                continue
            try:
                n = len(os.listdir(f"/proc/{pid}/fd"))
            except OSError:
                del tracked[pid]
                continue
            peaks.setdefault(name, Peak()).offer(pid, n, now)
        time.sleep(SAMPLE_S)
    report(peaks, time.monotonic() - t0, err)
    rc = proc.returncode
    return 128 - rc if rc < 0 else rc


if __name__ == "__main__":
    sys.exit(main())
