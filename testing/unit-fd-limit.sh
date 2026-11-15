#!/bin/bash
# Print the open-file soft limit the unit-test stage runs under.
#
# testing/ci-local.sh (UNIT_FD_LIMIT) and each unprivileged test step of
# .github/workflows/ci.yml's Linux job take the limit from here, so the two
# cannot drift apart. See "The open-file limit and fd-peak.py" in
# testing/README.md for the measurements behind the numbers.
#
# The limit is one bound for every runner, so that a leak, or a test that
# needs far more descriptors than the rest, reds everywhere rather than only
# on the host whose limit happens to be lowest. Under `cargo test` a test
# binary runs as many tests at once as it has test threads (RUST_TEST_THREADS,
# or else the CPU count), and the root lib suite's peak still grows by a few
# descriptors per test thread once its settlement explorer's walks are held
# to a fixed number per process. 512 holds that suite with room to spare up to
# 48 test threads; past 48 the limit grows by 8 per thread, about twice the
# most each added thread was measured to add, so a host with more CPUs than
# any runner has today is not failed by the test count alone.
#
# Usage: unit-fd-limit.sh   (prints one number; exits 2 on a bad
#                            RUST_TEST_THREADS or an unreadable CPU count)
set -euo pipefail

BASE=512
UPTO=48
PER_THREAD=8

threads=${RUST_TEST_THREADS:-$(nproc 2>/dev/null || true)}
if ! [[ "$threads" =~ ^[1-9][0-9]*$ ]]; then
    echo "unit-fd-limit.sh: cannot read a test thread count (got '$threads')" >&2
    exit 2
fi
if ((threads > UPTO)); then
    echo $((BASE + PER_THREAD * (threads - UPTO)))
else
    echo "$BASE"
fi
