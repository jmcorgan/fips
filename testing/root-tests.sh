#!/bin/bash
# ── Root-only unit tests ────────────────────────────────────────────────────
# Runs the unit tests that need root and network namespaces. They are
# `#[ignore]`d, so the ordinary unit-test runs skip them, and this script is
# the one place that says which `--ignored` filters run and how many tests
# each must pass.
#
# Usage:
#   testing/root-tests.sh <bin>
#
#   <bin>  the built `fips-mesh` library test executable (cargo's `fips` lib
#          target), for instance the path printed for it by
#          `cargo test -p fips-mesh --lib --no-run --message-format=json`.
#          A bare name with no slash is a file in the current directory,
#          not a command looked up on PATH.
#
# The script builds and locates nothing, and needs neither cargo nor git, so
# it runs wherever the binary and this file are present. It never calls sudo:
# it must already be running as root, and the caller decides how. GitHub's
# Linux job and testing/ci-local.sh --root-tests run it under sudo; a
# container runs it as uid 0.
#
# A container needs, besides uid 0: the NET_ADMIN and SYS_ADMIN capabilities,
# /dev/net/tun, an AppArmor profile that allows the network-namespace mount
# (Docker's default profile refuses `mount --make-shared /run/netns`; for
# instance --security-opt apparmor=unconfined), and a writable /proc/sys (a
# default Docker container mounts it read-only; for instance
# --security-opt systempaths=unconfined). Before any test runs, the script
# creates and deletes a namespace and checks /dev/net/tun, plus, where the
# tests set sysctls, writes one inside the namespace, so a missing permission
# is reported as such rather than as a set of failing tests.
#
# Each group runs as one `<bin> --ignored <filters> --test-threads=1`, and
# passes only if the binary exits 0 and libtest reports exactly the group's
# count passed. The count is the guard against a filter that quietly matches
# fewer tests: a filter that matches nothing still reports `ok`. Adding or
# removing a root-only test therefore changes the count here. Every group
# runs even after one fails, so one run reports every failure.
#
# Output: the test output, then one line per group, then a final line that is
# always last:
#   root-tests: PASS: <g> groups, <n> tests
#   root-tests: FAIL: <k> of <g> groups failed
#   root-tests: ERROR: <reason>
#
# Exit 0 = every group passed with its exact count. Exit 1 = a test failed,
# the binary failed or a count did not match. Exit 2 = the script could not
# run (usage, the binary, privilege, a missing tool or permission); never a
# pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

# The groups, each "<count>|<filters>", run in order.
TEST_GROUPS=(
    "18|node::tests::tun_warning:: ipv6tun::dns:: gateway::dns::mesh_tests::"
    "13|ipv6tun::tun::name_tests::"
)

# The tools the tests in the groups above run: ip for the namespaces, nft for
# the DNS tests' rules and packet counters, and sysctl for the TUN tests that
# turn IPv6 off inside a namespace. When sysctl is listed, the probe also
# writes a sysctl inside its namespace, as those tests do.
TEST_TOOLS=(ip nft sysctl)

PROBE_NS="root-tests-probe-$$"
probe_made=false
tmp=""

# Remove the output file and the probe namespace, whichever exist.
# shellcheck disable=SC2317  # run by the EXIT trap
cleanup() {
    [[ -n "$tmp" ]] && rm -f "$tmp"
    if [[ "$probe_made" == true ]]; then
        ip netns del "$PROBE_NS" 2>/dev/null
    fi
    return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Print the could-not-run reason as the last line and exit 2.
die() {
    echo "root-tests: ERROR: $1" >&2
    exit 2
}

# Print the usage on stderr.
usage() {
    echo "usage: $0 <bin>" >&2
    echo "  <bin>  the fips-mesh library test executable; run as root" >&2
}

# The checks that decide whether the tests can run at all.
preflight() {
    local t out
    [[ ${#TEST_GROUPS[@]} -ge 1 ]] || die "no test groups are listed in $0"
    for t in "${TEST_GROUPS[@]}"; do
        [[ "$t" =~ ^[1-9][0-9]*\|[^[:space:]] ]] \
            || die "malformed test group in $0: '$t' (want <count>|<filters>)"
    done
    for t in mktemp tee grep sed "${TEST_TOOLS[@]}"; do
        command -v "$t" >/dev/null 2>&1 || die "$t not found on PATH"
    done
    [[ "$(id -u)" -eq 0 ]] \
        || die "must run as root: under sudo, or as uid 0 in a container with NET_ADMIN and SYS_ADMIN"

    out=$(ip netns add "$PROBE_NS" 2>&1) \
        || die "cannot create a network namespace (ip netns add): ${out:-no message}"
    probe_made=true
    [[ -c /dev/net/tun ]] || die "/dev/net/tun is not a character device"
    for t in "${TEST_TOOLS[@]}"; do
        [[ "$t" == sysctl ]] || continue
        out=$(ip netns exec "$PROBE_NS" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>&1) \
            || die "cannot write /proc/sys inside a network namespace (sysctl -w): ${out:-no message}"
    done
    out=$(ip netns del "$PROBE_NS" 2>&1) \
        || die "cannot delete a network namespace (ip netns del): ${out:-no message}"
    probe_made=false
    return 0
}

# run_group <count> <filters...>: run one group, print its line, and return
# 0 if it passed.
run_group() {
    local n="$1" rc result name
    shift
    "$bin" --ignored "$@" --test-threads=1 2>&1 | tee "$tmp"
    rc=${PIPESTATUS[0]}
    if [[ $rc -eq 0 ]] && grep -qE "^test result: ok\. $n passed;" "$tmp"; then
        echo "root-tests: ok: $*: $n passed"
        return 0
    fi
    result=$(grep -m 1 -E '^test result: ' "$tmp")
    echo "root-tests: FAILED: $*: expected $n passed; exit $rc; ${result:-no test result line}"
    while IFS= read -r name; do
        echo "root-tests: failed test: $name"
    done < <(sed -n 's/^test \(.*\) \.\.\. FAILED$/\1/p' "$tmp")
    return 1
}

if [[ $# -ne 1 ]]; then
    usage
    die "expected one argument, got $#"
fi
bin="$1"
# Without a slash the shell would look the name up on PATH when running it.
[[ "$bin" == */* ]] || bin="./$bin"
[[ -e "$bin" ]] || die "$bin does not exist"
[[ -f "$bin" && -x "$bin" ]] || die "$bin is not an executable file"

preflight

tmp=$(mktemp) || die "mktemp failed"

failed=0
total=0
for entry in "${TEST_GROUPS[@]}"; do
    count="${entry%%|*}"
    read -r -a filters <<< "${entry#*|}"
    if run_group "$count" "${filters[@]}"; then
        total=$((total + count))
    else
        failed=$((failed + 1))
    fi
done

if [[ $failed -eq 0 ]]; then
    echo "root-tests: PASS: ${#TEST_GROUPS[@]} groups, $total tests"
    exit 0
fi
echo "root-tests: FAIL: $failed of ${#TEST_GROUPS[@]} groups failed"
exit 1
