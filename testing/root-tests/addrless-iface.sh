#!/bin/sh
# The address-less interface fixture, as GitHub CI's Linux and musl unit-test
# jobs create it, and the one test that reads it, run against <bin>, a
# fips-mesh library test binary (glibc or musl). Runs as root in a network
# namespace of its own: testing/ci-local.sh runs it in the root tests'
# container (root_container), which has NET_ADMIN and no network.
#
# The interface is a dummy brought up with `addrgenmode none`, so the kernel
# gives it no IPv6 link-local; one that acquired an address anyway fails the
# fixture rather than testing the wrong thing. FIPS_TEST_REQUIRE_FIXTURES=1
# makes the test fail, not skip, if the fixture variable is missing.
#
# Usage: addrless-iface.sh <bin>
# Exit 0 = the test ran and passed; 1 = it failed or did not run; 2 = the
# fixture could not be made.
set -u
bin="$1"
test=transport::ethernet::tests::an_interface_with_no_addresses_is_still_present
ip link add fips-probe0 type dummy || exit 2
ip link set fips-probe0 addrgenmode none || exit 2
ip link set fips-probe0 up || exit 2
if ip addr show fips-probe0 | grep -qE "inet6? "; then
    echo "fips-probe0 has an address; it cannot test the address-less case" >&2
    exit 2
fi
out=$(FIPS_TEST_ADDRLESS_IFACE=fips-probe0 FIPS_TEST_REQUIRE_FIXTURES=1 \
    "$bin" --exact "$test" 2>&1)
rc=$?
echo "$out"
[ "$rc" -eq 0 ] && echo "$out" | grep -q '^test result: ok\. 1 passed;' && exit 0
echo "addrless-iface: $test did not run and pass (exit $rc)" >&2
exit 1
