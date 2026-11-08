#!/usr/bin/env python3
"""Reach of the node's live map audit over a run of the root lib suite.

In a debug test build every node entry that can change a per-peer map audits
the maps on its way out, except on a node a test wrote past the map writers,
which the audit skips for the rest of the test. A helper that marks a node it
did not need to would switch the audit off for every test that uses it, and
the suite would stay green. This check is what notices.

With FIPS_AUDIT_REACH naming a file, each audit appends one row per test
thread, node and outcome: `audited <thread> <node>`, or `planted <thread>
<node>` where the node was skipped. A (thread, node) pair is audited when it
has at least one `audited` row. The suite must run as threads in one process
(`cargo test`), where a test's thread is named for it; under nextest every
row would carry the same thread name.

Usage: check-audit-reach.py <rows file>

Exit 0 = both floors hold. Exit 1 = the share of pairs audited, or the count
of pairs audited, is under its floor; the numbers are printed. Exit 2 = the
file is unreadable, empty or holds a malformed row, so nothing was measured;
never treated as a pass.

The floors are the two constants below. Lowering one is an edit here, which
a review sees.
"""

import sys

# Least share of (thread, node) pairs reaching the audit that it checks, in
# percent.
SHARE_FLOOR = 97.0
# Least count of pairs audited, so a shrinking suite cannot hold the share up.
COUNT_FLOOR = 2300

OUTCOMES = ("audited", "planted")


def main() -> int:
    """Read the rows, count the pairs and hold them to the floors."""
    if len(sys.argv) != 2:
        print("usage: check-audit-reach.py <rows file>", file=sys.stderr)
        return 2
    path = sys.argv[1]
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as e:
        print(f"audit-reach: cannot read {path}: {e}", file=sys.stderr)
        return 2
    pairs = {}
    for n, line in enumerate(lines, 1):
        fields = line.split()
        if len(fields) != 3 or fields[0] not in OUTCOMES:
            print(f"audit-reach: {path}:{n}: malformed row {line!r}", file=sys.stderr)
            return 2
        outcome, thread, node = fields
        seen = pairs.setdefault((thread, node), set())
        seen.add(outcome)
    if not pairs:
        print(f"audit-reach: {path} holds no rows: nothing was measured", file=sys.stderr)
        return 2
    audited = {p for p, seen in pairs.items() if "audited" in seen}
    threads = {t for t, _ in pairs}
    covered = {t for t, _ in audited}
    share = 100.0 * len(audited) / len(pairs)
    print(
        f"audit-reach: {len(pairs)} (test, node) pairs reached the audit, "
        f"{len(audited)} audited ({share:.2f}%), "
        f"{len(pairs) - len(audited)} only planted; "
        f"{len(threads)} tests, {len(threads - covered)} with no audited node"
    )
    failed = False
    if share < SHARE_FLOOR:
        print(f"audit-reach: {share:.2f}% of pairs audited is under the floor of {SHARE_FLOOR}%")
        failed = True
    if len(audited) < COUNT_FLOOR:
        print(f"audit-reach: {len(audited)} pairs audited is under the floor of {COUNT_FLOOR}")
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
