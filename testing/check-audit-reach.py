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
has at least one `audited` row.

Beside an audited row the `links-mirror` clause writes two more. `unmirrored
<thread> <node>`: it skipped a peer a test changed past the feed of the
settlement core's link records, with a test mutator of the peer's paths. And
`letoff <thread> <node>`: it let off a peer whose record differs from its
bundle only in the active path, recorded Live at a switch to it while the
bundle holds it acknowledged. Each is a check not made, so each is held to a
ceiling: the count of pairs that wrote it.

The suite must run as threads in one process (`cargo test`), where a test's
thread is named for it; under nextest every row would carry the same thread
name.

Usage: check-audit-reach.py <rows file>

Exit 0 = both floors and both ceilings hold. Exit 1 = the share of pairs
audited, or the count of pairs audited, is under its floor, or the count of
pairs skipped or let off by `links-mirror` is over its ceiling; the numbers
are printed. Exit 2 = the file is unreadable, empty or holds a malformed row,
so nothing was measured; never treated as a pass.

The floors and ceilings are the constants below. Lowering a floor or raising
a ceiling is an edit here, which a review sees.
"""

import sys

# Least share of (thread, node) pairs reaching the audit that it checks, in
# percent.
SHARE_FLOOR = 97.0
# Least count of pairs audited, so a shrinking suite cannot hold the share up.
# Five runs of one binary audited 2279 to 2316 pairs, since a test that retries
# adds pairs at random, so this sits under that range rather than inside it.
COUNT_FLOOR = 2200
# Most pairs `links-mirror` may skip for a peer a test changed past the feed:
# the count at both multipath settings when the clause was added. On next it is
# 44: 33 in tests master shares and 11 in next's own, the cells tests of the
# crossing settled at the msg3 and of the restart at the msg3, and a beacon
# test, each of which changes a bundle with a test mutator.
UNMIRRORED_CEILING = 44
# Most pairs `links-mirror` may let off for a switch to an acknowledged path:
# the count at both multipath settings when the clause was added.
LETOFF_CEILING = 4

OUTCOMES = ("audited", "planted", "unmirrored", "letoff")


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
    unmirrored = sum(1 for seen in pairs.values() if "unmirrored" in seen)
    letoff = sum(1 for seen in pairs.values() if "letoff" in seen)
    threads = {t for t, _ in pairs}
    covered = {t for t, _ in audited}
    share = 100.0 * len(audited) / len(pairs)
    print(
        f"audit-reach: {len(pairs)} (test, node) pairs reached the audit, "
        f"{len(audited)} audited ({share:.2f}%), "
        f"{len(pairs) - len(audited)} only planted; "
        f"{len(threads)} tests, {len(threads - covered)} with no audited node; "
        f"links-mirror skipped {unmirrored} and let off {letoff}"
    )
    failed = False
    if share < SHARE_FLOOR:
        print(f"audit-reach: {share:.2f}% of pairs audited is under the floor of {SHARE_FLOOR}%")
        failed = True
    if len(audited) < COUNT_FLOOR:
        print(f"audit-reach: {len(audited)} pairs audited is under the floor of {COUNT_FLOOR}")
        failed = True
    if unmirrored > UNMIRRORED_CEILING:
        print(
            f"audit-reach: links-mirror skipped {unmirrored} pairs, "
            f"over the ceiling of {UNMIRRORED_CEILING}"
        )
        failed = True
    if letoff > LETOFF_CEILING:
        print(
            f"audit-reach: links-mirror let off {letoff} pairs, over the ceiling of {LETOFF_CEILING}"
        )
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
