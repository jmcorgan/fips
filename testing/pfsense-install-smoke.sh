#!/bin/sh
# ── pfSense package install smoke test ──────────────────────────────────────
# Installs a built pfSense .pkg on the FreeBSD system this runs on and drives
# it through the life it has on a firewall: pkg add, the boot script's start
# (twice, the second being what pfSense's rc.start_packages does on every WAN
# address change), the daemon answering on its control socket and its DNS
# port, restart, stop, and pkg delete taking everything back out.
#
# check-pfsense-pkg.sh reads the package from the outside and exercises the
# boot script against a stub; this runs the real binary under the real
# daemon(8) on a real kernel of the target's major. The two cover different
# failures: a package can pass every structural check and still ship a
# daemon that dies at TUN setup, a post-install that leaves fips.yaml
# world-readable, or a pre-deinstall that lets pkg delete pull the binary
# out from under a running process.
#
# Runs on a plain FreeBSD host of the package's ABI major (CI: the 15.1 and
# 16.0-CURRENT VMs), and on pfSense itself, where it is meant to be the first
# thing run against a new package. What it does NOT reach on plain FreeBSD,
# stated so a pass is not read as more than it is: the config.xml edit in
# fips-unbound-custom.php (needs pfSense's PHP includes), unbound forwarding
# .fips, /var as a RAM disk, and pf. On pfSense the DNS integration is still
# a manual step, because installing a test package must not rewrite the
# firewall's config.xml.
#
# It changes the system it runs on: installs and removes the package, starts
# and stops the daemon, creates a fips group. Run it on a throwaway VM or a
# box you are about to install on anyway, as root. Plain sh, because pfSense
# ships no bash and a test package should not need one installed to be tried.
#
# Usage: testing/pfsense-install-smoke.sh <package.pkg>
#
# Exit 0 = every check passed. Exit 1 = at least one failed. Exit 2 = the
# test could not run; never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
# daemon_answers, no_daemon and cleanup are called through wait_for and the
# EXIT trap, which shellcheck cannot follow: SC2317 in 0.9, SC2329 in 0.10+.
# shellcheck disable=SC2317,SC2329
set -u

failures=0
checks=0
skipped=0

pass() { checks=$((checks + 1)); printf '  PASS  %s\n' "$1"; }
fail() {
    checks=$((checks + 1))
    failures=$((failures + 1))
    printf '  FAIL  %s\n' "$1"
    [ $# -gt 1 ] && printf '        %s\n' "$2"
    return 0
}
skip() { skipped=$((skipped + 1)); printf '  SKIP  %s\n' "$1"; }
bail() { printf 'pfsense-install-smoke: %s\n' "$1" >&2; exit 2; }

PKG="${1:-}"
if [ -z "$PKG" ] || [ ! -f "$PKG" ]; then bail "usage: $0 <package.pkg>"; fi
[ "$(id -u)" -eq 0 ] || bail "must run as root: it installs the package and starts the daemon"
if ! { command -v pkg >/dev/null 2>&1 && pkg config abi >/dev/null 2>&1; }; then
    bail "needs pkg(8) on a FreeBSD-based host"
fi
pkg info fips >/dev/null 2>&1 && bail "fips is already installed here; this test needs a clean host"

RC=/usr/local/etc/rc.d/fips.sh
CONF_DIR=/usr/local/etc/fips
RUN_DIR=/var/run/fips
LOG=/var/log/fips.log
DNS_PORT=5354

# fipsctl and the daemon agree on the control socket under /var/run/fips
# once that directory exists; fips.sh creates it before starting the daemon.
daemon_answers() { fipsctl show status >/dev/null 2>&1; }
daemon_pids() { pgrep -x fips 2>/dev/null | wc -l | tr -d ' '; }
no_daemon() { [ "$(daemon_pids)" = "0" ]; }

# Wait up to $1 seconds for a command to succeed.
wait_for() {
    _seconds="$1"; shift
    _i=0
    while [ "$_i" -lt "$_seconds" ]; do
        "$@" && return 0
        sleep 1
        _i=$((_i + 1))
    done
    return 1
}

# fips.sh start leaves daemon(8)'s supervisor behind, and the supervisor
# inherits whatever stdout it was given. Captured in a command substitution
# that pipe never closes and the substitution blocks for the daemon's whole
# life (fips.sh itself says so). So the boot script's output goes to a file
# and is read back afterwards.
OUT=$(mktemp "${TMPDIR:-/tmp}/fips-smoke.XXXXXX") || bail "mktemp failed"
run_rc() {
    "$RC" "$@" >"$OUT" 2>&1
}

on_pfsense=0
[ -f /etc/inc/config.inc ] && on_pfsense=1

# Leave nothing behind on a failure part-way: the daemon stopped and the
# package removed, so a re-run starts clean. Runs from the EXIT trap.
cleanup() {
    if pkg info fips >/dev/null 2>&1; then
        "$RC" stop >/dev/null 2>&1 || true
        pkg delete -y fips >/dev/null 2>&1 || true
    fi
    rm -f "$OUT"
}
trap cleanup EXIT

ABI=$(pkg config abi)
where="$ABI"
[ "$on_pfsense" = 1 ] && where="$ABI (pfSense)"
echo "==> install smoke test of $(basename "$PKG") on $where"

# ── 1. Install ──────────────────────────────────────────────────────────────
echo "-- pkg add"
if out=$(pkg add "$PKG" 2>&1); then
    pass "pkg add"
else
    fail "pkg add" "$(printf '%s' "$out" | tail -3)"
    echo "==> cannot continue without the package installed" >&2
    exit 1
fi

for bin in fips fipsctl fipstop; do
    if [ -x "/usr/local/bin/$bin" ]; then pass "/usr/local/bin/$bin installed"
    else fail "/usr/local/bin/$bin missing"; fi
done
# The boot script must carry the .sh suffix, or pfSense never runs it.
if [ -x "$RC" ]; then pass "boot script is $RC"; else fail "boot script $RC missing or not executable"; fi

# post-install seeds the configs from the samples; fips.yaml may hold a
# private key, so it must not be world-readable.
for f in fips.yaml hosts fips.conf; do
    if [ -f "$CONF_DIR/$f" ]; then pass "$CONF_DIR/$f seeded from its sample"
    else fail "$CONF_DIR/$f was not seeded by post-install"; fi
done
mode=$(stat -f %Lp "$CONF_DIR/fips.yaml" 2>/dev/null || echo "?")
if [ "$mode" = "600" ]; then pass "fips.yaml is 0600"; else fail "fips.yaml mode is $mode, expected 600"; fi
if pw groupshow fips >/dev/null 2>&1; then pass "fips group exists"; else fail "post-install did not create the fips group"; fi
if grep -q 'bind_addr: "127.0.0.1"' "$CONF_DIR/fips.yaml"; then pass "shipped config binds the responder on 127.0.0.1"
else fail "shipped fips.yaml does not bind the DNS responder on 127.0.0.1"; fi

# ── 2. Lifecycle ────────────────────────────────────────────────────────────
echo "-- start"
if run_rc start; then pass "fips.sh start exits 0"; else fail "fips.sh start exited non-zero" "$(cat "$OUT")"; fi
if [ -s "$RUN_DIR/fips.pid" ]; then pass "pidfile written"; else fail "no pidfile at $RUN_DIR/fips.pid"; fi
if "$RC" status >/dev/null 2>&1; then pass "fips.sh status reports running"; else fail "fips.sh status says not running after start"; fi
if wait_for 30 daemon_answers; then
    pass "daemon answers fipsctl show status"
else
    fail "daemon did not answer on its control socket within 30s" "$(tail -n 5 "$LOG" 2>/dev/null)"
fi
n=$(daemon_pids)
if [ "$n" = "1" ]; then pass "exactly one fips process"; else fail "expected one fips process, found $n"; fi

# The responder itself, before unbound. drill(1) is in FreeBSD base; any
# answer, including NXDOMAIN, shows the port is served by our daemon.
if command -v drill >/dev/null 2>&1; then
    if wait_for 10 sh -c "drill -p $DNS_PORT smoke.fips @127.0.0.1 AAAA 2>/dev/null | grep -q '>>HEADER<<'"; then
        pass "DNS responder answers on 127.0.0.1:$DNS_PORT"
    else
        fail "no DNS answer from 127.0.0.1:$DNS_PORT" "$(sockstat -4l 2>/dev/null | grep ":$DNS_PORT" || echo 'nothing listening on the port')"
    fi
else
    skip "DNS responder query (drill not installed)"
fi
if [ -s "$LOG" ]; then pass "daemon log $LOG is being written"; else fail "$LOG is empty or missing"; fi
if [ "$on_pfsense" = 1 ]; then
    if [ -f /var/etc/newsyslog.conf.d/fips.conf ]; then pass "newsyslog entry placed for /var/etc"
    else fail "start did not place /var/etc/newsyslog.conf.d/fips.conf"; fi
fi

# What rc.start_packages does on every WAN address change: start again
# while running. Must exit 0, say so, and not fork a second daemon.
echo "-- start while running"
if run_rc start; then pass "re-entrant start exits 0"; else fail "re-entrant start exited non-zero" "$(cat "$OUT")"; fi
if grep -q 'already running' "$OUT"; then pass "re-entrant start reports already running"
else fail "re-entrant start did not say 'already running'" "$(cat "$OUT")"; fi
n=$(daemon_pids)
if [ "$n" = "1" ]; then pass "still exactly one fips process"; else fail "re-entrant start left $n fips processes"; fi

echo "-- restart"
old_pid=$(cat "$RUN_DIR/fips.pid" 2>/dev/null)
if run_rc restart; then pass "fips.sh restart exits 0"; else fail "fips.sh restart failed" "$(cat "$OUT")"; fi
new_pid=$(cat "$RUN_DIR/fips.pid" 2>/dev/null)
if [ -n "$new_pid" ] && [ "$new_pid" != "$old_pid" ]; then pass "restart produced a new pid ($old_pid -> $new_pid)"
else fail "restart did not replace the daemon (pid $old_pid -> ${new_pid:-none})"; fi
if wait_for 30 daemon_answers; then pass "daemon answers after restart"; else fail "daemon not answering after restart"; fi

echo "-- stop"
if run_rc stop; then pass "fips.sh stop exits 0"; else fail "fips.sh stop failed" "$(cat "$OUT")"; fi
if wait_for 15 no_daemon; then pass "no fips process after stop"
else fail "fips still running after stop"; fi
if "$RC" status >/dev/null 2>&1; then fail "fips.sh status still reports running after stop"; else pass "fips.sh status reports not running"; fi
if [ ! -e "$RUN_DIR/fips.pid" ]; then pass "pidfile removed"; else fail "pidfile left behind after stop"; fi

# ── 3. Remove ───────────────────────────────────────────────────────────────
# pre-deinstall stops a running daemon first, so start it again and let pkg
# delete do the stopping. On plain FreeBSD fips-dns-teardown reports there
# is no config.xml to edit and pre-deinstall prints the hint; that is
# expected here and not a failure.
echo "-- pkg delete"
run_rc start || true
if out=$(pkg delete -y fips 2>&1); then pass "pkg delete"; else fail "pkg delete failed" "$(printf '%s' "$out" | tail -3)"; fi
if wait_for 15 no_daemon; then pass "pre-deinstall stopped the running daemon"
else fail "daemon still running after pkg delete"; fi
for bin in fips fipsctl fipstop; do
    if [ ! -e "/usr/local/bin/$bin" ]; then pass "/usr/local/bin/$bin removed"; else fail "/usr/local/bin/$bin left behind"; fi
done
if [ ! -e "$RC" ]; then pass "boot script removed"; else fail "$RC left behind"; fi
# Unmodified configs go with the package; an edited fips.yaml (and the key
# it may hold) would stay, which is not tested here since none was edited.
for f in fips.yaml hosts fips.conf; do
    if [ ! -e "$CONF_DIR/$f" ]; then pass "unmodified $f purged"; else fail "$CONF_DIR/$f left behind although unmodified"; fi
done

# ── Result ──────────────────────────────────────────────────────────────────
echo
if [ "$failures" -eq 0 ]; then
    echo "==> pfSense install smoke test PASSED (${checks} checks, ${skipped} skipped)"
    exit 0
fi
echo "==> pfSense install smoke test FAILED (${failures} of ${checks})" >&2
exit 1
