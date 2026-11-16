#!/bin/sh
# The interface-binding tests with privilege, as GitHub CI's test-root job
# runs them: the Ethernet and socket-buffer tests with FIPS_TEST_PRIVILEGED=1,
# so a test that needs a raw socket or a forced buffer fails, rather than
# skips, when it cannot have one. Runs <bin>, the fips-mesh library test
# binary, as root; testing/ci-local.sh runs it in the root tests' container
# (root_container).
#
# In a network namespace other than the host's, one test cannot run:
# with_cap_net_admin_a_buffer_is_granted_past_the_kernel_ceiling reads
# /proc/sys/net/core/rmem_max, which the kernel shows only in the initial
# namespace, and the container is never given the host's network. --netns
# leaves that test out; GitHub runs it on its runner's own network.
#
# Usage: privileged.sh <bin> [--netns]
# Exit 0 only if the binary passed and at least one test passed, since a
# filter that matches nothing passes.
set -u
bin="$1"
skip=""
[ "${2:-}" = --netns ] \
    && skip="--skip transport::sockbuf::tests::with_cap_net_admin_a_buffer_is_granted_past_the_kernel_ceiling"
# shellcheck disable=SC2086  # $skip is two words or none
out=$(FIPS_TEST_PRIVILEGED=1 "$bin" transport::ethernet transport::sockbuf $skip --test-threads=1 2>&1)
rc=$?
echo "$out"
[ "$rc" -eq 0 ] && echo "$out" | grep -qE '^test result: ok\. [1-9][0-9]* passed;' && exit 0
echo "privileged: the binary failed or no test passed (exit $rc)" >&2
exit 1
