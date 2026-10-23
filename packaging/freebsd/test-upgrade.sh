#!/bin/sh
# Test what `pkg install` of a newer fips package does to a running daemon.
#
# pkg 2.8.4 ends a process that a package script starts, even under
# daemon(8), once pkg returns. So an upgrade that stops the daemon and starts
# it again from the new package's post-install leaves the node with no daemon.
# The contract tested here: an upgrade leaves the running daemon alone, prints
# the restart instruction, and the documented `service fips restart` then
# moves the daemon onto the new binary.
#
# Cases:
#   upgrade_over_running_enabled_service_leaves_a_daemon_running_after_pkg_returns
#   upgrade_prints_the_restart_instruction
#   documented_restart_after_upgrade_moves_the_daemon_onto_the_new_binary
#
# Run as root on a FreeBSD host where the package built from this tree by
# build-pkg.sh is installed and target/release still holds its binaries. The
# test builds a second package from the same binaries at version 99.0.0 with
# `build-pkg.sh --no-build`, so both packages carry this tree's scripts and
# the installed package's pre-deinstall is the one under test.
#
# It changes the host: fips_enable is set to YES for the run, the daemon is
# started, and fips 99.0.0 is left installed. At exit the daemon is stopped,
# fips_enable is put back as it was, and the 99.0.0 package file is removed.
#
# Usage: sh packaging/freebsd/test-upgrade.sh
# Exit 0 = every case passed. 1 = a case failed. 2 = the test could not run.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
UPGRADE_VERSION="99.0.0"
PIDFILE="/var/run/fips/fips.pid"
BINARY="/usr/local/bin/fips"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/fips-upgrade-test.XXXXXX")"
FAILURES=0

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }
cannot() { echo "test-upgrade: $*; cannot run" >&2; exit 2; }

[ "$(id -u)" -eq 0 ] || cannot "must run as root"
pkg info -e fips || cannot "the fips package is not installed"
[ -x "${PROJECT_ROOT}/target/release/fips" ] || cannot "target/release/fips is missing"

enable_was="$(sysrc -n fips_enable 2>/dev/null || true)"

cleanup() {
    service fips onestop >/dev/null 2>&1 || true
    if [ -n "$enable_was" ]; then
        sysrc fips_enable="$enable_was" >/dev/null
    else
        sysrc -x fips_enable >/dev/null 2>&1 || true
    fi
    rm -f "${PROJECT_ROOT}/deploy/fips-${UPGRADE_VERSION}-freebsd-"*.pkg
    rm -rf "$WORK"
}
trap cleanup EXIT

# Print the daemon's pid once its pidfile names a live process, waiting up to
# 15 seconds; print nothing if it never does.
daemon_pid() {
    i=0
    while [ "$i" -lt 15 ]; do
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "$pid"
            return 0
        fi
        i=$((i + 1))
        sleep 1
    done
    return 0
}

# Precondition: an enabled daemon is running before the upgrade.
sysrc fips_enable=YES >/dev/null
service fips onestop >/dev/null 2>&1 || true
service fips start
pid_before="$(daemon_pid)"
if [ -z "$pid_before" ] || ! service fips status >/dev/null 2>&1; then
    echo "test-upgrade: the daemon did not start before the upgrade" >&2
    tail -20 /var/log/fips.log 2>/dev/null >&2 || true
    exit 2
fi
echo "daemon running before the upgrade: pid $pid_before ($(pkg query '%n-%v' fips))"

if ! "${SCRIPT_DIR}/build-pkg.sh" --no-build --version "$UPGRADE_VERSION" >"$WORK/build.log" 2>&1; then
    cat "$WORK/build.log" >&2
    cannot "build-pkg.sh could not build the ${UPGRADE_VERSION} package"
fi
new_pkg=""
for f in "${PROJECT_ROOT}/deploy/fips-${UPGRADE_VERSION}-freebsd-"*.pkg; do
    [ -f "$f" ] && new_pkg="$f"
done
[ -n "$new_pkg" ] || cannot "build-pkg.sh left no ${UPGRADE_VERSION} package in deploy/"

pkg_rc=0
pkg install -y -U "$new_pkg" >"$WORK/pkg.log" 2>&1 || pkg_rc=$?
echo "--- pkg install -y -U $(basename "$new_pkg") (exit $pkg_rc) ---"
cat "$WORK/pkg.log"
echo "---"
installed="$(pkg query '%v' fips)"
if [ "$pkg_rc" -ne 0 ] || [ "$installed" != "$UPGRADE_VERSION" ]; then
    cannot "pkg install exited $pkg_rc and left fips $installed installed"
fi

# Polled at 0, 2, 5 and 10 seconds after pkg returns: a daemon a package
# script started is gone within about 2 seconds.
start=$(date +%s)
down=""
for at in 0 2 5 10; do
    while [ $(( $(date +%s) - start )) -lt "$at" ]; do
        sleep 1
    done
    if service fips status >/dev/null 2>&1; then
        echo "  ${at}s after pkg returned: running"
    else
        echo "  ${at}s after pkg returned: not running"
        down="$down ${at}s"
    fi
done
if [ -z "$down" ]; then
    pass "upgrade_over_running_enabled_service_leaves_a_daemon_running_after_pkg_returns"
else
    fail "upgrade_over_running_enabled_service_leaves_a_daemon_running_after_pkg_returns  (not running at:$down)"
fi

if grep -q "service fips restart" "$WORK/pkg.log"; then
    pass "upgrade_prints_the_restart_instruction"
else
    fail "upgrade_prints_the_restart_instruction  (pkg printed no 'service fips restart')"
fi

service fips restart >/dev/null 2>&1 || true
pid_after="$(daemon_pid)"
count="$(pgrep -x fips | wc -l | tr -d ' ')"
path="$(procstat -b "${pid_after:-0}" 2>/dev/null | awk 'NR == 2 { print $NF }')"
if [ -n "$pid_after" ] && [ "$pid_after" != "$pid_before" ] &&
    [ "$count" -eq 1 ] && [ "$path" = "$BINARY" ]; then
    pass "documented_restart_after_upgrade_moves_the_daemon_onto_the_new_binary  (pid $pid_before -> $pid_after)"
else
    fail "documented_restart_after_upgrade_moves_the_daemon_onto_the_new_binary  (pid $pid_before -> ${pid_after:-none}, $count fips processes, binary '${path}'; want a new pid, one process, $BINARY)"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "test-upgrade: all cases passed"
    exit 0
fi
echo "test-upgrade: $FAILURES case(s) failed"
exit 1
