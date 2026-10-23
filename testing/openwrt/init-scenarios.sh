#!/bin/sh
# fips-gateway init script scenarios, run inside an openwrt/rootfs image so the
# image's own rc.common, procd.sh, flock and uci run the script under ash.
#
# Driven by testing/openwrt/maintainer-scripts-test.sh, once per pinned image,
# in a container with no network. There is no procd and no ubusd: ubus fails at
# once with "Failed to connect to ubus", so rc.common's procd calls return
# quickly and procd_running reports nothing running, unless a case installs
# the ubus stub. The gateway is a stub that records its open descriptors and
# sleeps until it is signalled; /etc/init.d/network, odhcpd and dnsmasq are
# recorders that log each call to $CALLS. The container cannot create fips0, so
# ip is a stub that reports fips0 present exactly while $FIPS0 exists and
# passes every other call to busybox.
#
# Seams:
#   INIT_GATEWAY  the init script under test; default the one built into the
#                 .ipk, as package-test.sh --keep extracts it under /apk.
#   PRERM         the prerm the removal case runs; default the package's, read
#                 from the checkout under $REPO.
#   INIT_CASES    case function names to run, separated by spaces; default all.
#
# Facts about the images this allows for: /var links to /tmp and /var/lock
# does not exist, so it is created; there is no timeout binary, so a command
# that may hang is bounded by a background sleep and kill; there is no pkill,
# and sleep takes whole seconds only.
#
# Every case that reaches its end is counted, and a run that counts fewer
# cases than it selected exits 2.
#
# Exit 0 = every case passed. Exit 1 = at least one failed. Exit 2 = the
# harness could not run; never treated as a pass.

set -u

REPO="${REPO:-/src}"
INIT_GATEWAY="${INIT_GATEWAY:-/apk/ipk-root/etc/init.d/fips-gateway}"
PRERM="${PRERM:-$REPO/packaging/openwrt-ipk/scripts/prerm}"
INIT_CASES="${INIT_CASES:-}"

INIT=/etc/init.d/fips-gateway
LOCK=/var/lock/procd_fips-gateway.lock
CALLS=/tmp/init-calls
FDS=/tmp/init-gateway-fds
SUPLOG=/tmp/init-supervise.log
FIPS0=/tmp/init-fips0
UBUS_REAL=/tmp/init-ubus.real
DHCP_STOCK=/tmp/init-dhcp.stock
INSTROOT=/tmp/init-instroot
PREFIX=2001:2:f1b5::1/64
OPERATOR=2001:db8:1::1/64

# The number of cases in the full run, counted by hand from the list at the
# end of this file. A run that completes fewer exits 2.
ALL_CASES=13

FAILURES=0
CASES=0
RAN=0
CUR=""

ok() {
	CASES=$((CASES + 1))
	echo "  ok   $CUR: $*"
	return 0
}

bad() {
	CASES=$((CASES + 1))
	FAILURES=$((FAILURES + 1))
	echo "  FAIL $CUR: $*"
	return 0
}

harness_fail() {
	echo "init-scenarios: $*" >&2
	exit 2
}

# check <description> <command...>: passes when the command succeeds.
check() {
	local d="$1"
	shift
	if "$@"; then ok "$d"; else bad "$d"; fi
	return 0
}

# precond <description> <command...>: like check, but returns the verdict so
# the case can skip to its end.
precond() {
	local d="$1"
	shift
	if "$@"; then
		ok "precondition: $d"
		return 0
	fi
	bad "precondition: $d"
	return 1
}

begin() {
	CUR="$1"
	echo "  $CUR"
}

finish() {
	RAN=$((RAN + 1))
	echo "  done $CUR"
}

# bounded <seconds> <command...>: run the command, killing it after <seconds>.
# Returns its status, or 124 when it had to be killed.
bounded() {
	local secs="$1" pid killer rc
	shift
	rm -f /tmp/init-timedout
	"$@" &
	pid=$!
	(
		sleep "$secs"
		if kill -0 "$pid" 2>/dev/null; then
			touch /tmp/init-timedout
			kill -KILL "$pid"
		fi
	) &
	killer=$!
	rc=0
	wait "$pid" || rc=$?
	kill "$killer" 2>/dev/null
	wait "$killer" 2>/dev/null
	[ -e /tmp/init-timedout ] && return 124
	return "$rc"
}

# Kill every process whose command line matches $1.
kill_matching() {
	local p
	for p in $(pgrep -f "$1"); do
		kill "$p" 2>/dev/null
	done
	return 0
}

# A recorder installed as $1: logs its own name and arguments. The path is
# removed first, since it may be a link to busybox.
recorder() {
	rm -f "$1"
	printf '#!/bin/sh\necho "%s $*" >> %s\nexit 0\n' "${1##*/}" "$CALLS" > "$1"
	chmod 0755 "$1"
}

# Install the ip stub at the path the image's ip has. In every pinned image
# that is a link to busybox, so it is removed first, and the calls the stub
# does not answer go to busybox's own ip rather than to a saved copy.
ip_stub() {
	local p
	p="$(command -v ip)"
	[ -n "$p" ] || p=/sbin/ip
	rm -f "$p"
	cat > "$p" <<STUB
#!/bin/sh
if [ "\$*" = "link show fips0" ]; then
	[ -e $FIPS0 ]
	exit \$?
fi
exec /bin/busybox ip "\$@"
STUB
	chmod 0755 "$p"
}

# The image as each case starts from: the init script under test, the stub
# gateway and the recorders, a gateway-enabled fips.yaml, a LAN interface in
# the network config, no boot links, the real ubus, and fips0 present.
reset() {
	kill_matching "$INIT supervise"
	kill_matching /usr/bin/fips-gateway
	rm -f "$CALLS" "$FDS" "$SUPLOG" /var/run/fips-gateway.pid /var/run/fips-gateway-install-hold
	mkdir -p /var/lock /var/run /etc/fips /etc/rc.d
	cp "$INIT_GATEWAY" "$INIT" || harness_fail "cannot install $INIT_GATEWAY"
	chmod 0755 "$INIT"
	rm -f /etc/rc.d/S??fips-gateway /etc/rc.d/K??fips-gateway
	cat > /usr/bin/fips-gateway <<STUB
#!/bin/sh
ls /proc/\$\$/fd > $FDS.tmp && mv $FDS.tmp $FDS
trap 'exit 0' TERM INT
while :; do sleep 1; done
STUB
	chmod 0755 /usr/bin/fips-gateway
	recorder /etc/init.d/network
	recorder /etc/init.d/odhcpd
	recorder /etc/init.d/dnsmasq
	recorder /etc/init.d/fips
	recorder /usr/bin/logger
	ip_stub
	touch "$FIPS0"
	cp "$DHCP_STOCK" /etc/config/dhcp
	cat > /etc/fips/fips.yaml <<'YAML'
gateway:
  enabled: true
  pool: "fd01::/112"
  lan_interface: br-lan
YAML
	cat > /etc/config/network <<'UCI'
config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.168.1.1'
	option netmask '255.255.255.0'
UCI
	[ -e "$UBUS_REAL" ] && cp "$UBUS_REAL" /bin/ubus
	: > "$CALLS"
	return 0
}

# gateway_within <seconds>: wait up to <seconds> for the stub gateway to
# record its descriptors, which it does as it starts.
gateway_within() {
	local i=0
	while [ ! -s "$FDS" ] && [ "$i" -lt "$1" ]; do
		sleep 1
		i=$((i + 1))
	done
	[ -s "$FDS" ]
}

# Start supervise as procd would, in the background, without waiting.
supervise_spawn() {
	"$INIT" supervise > "$SUPLOG" 2>&1 &
	SUP=$!
}

# Start supervise as procd would, and wait for the stub gateway to record its
# descriptors.
supervise_start() {
	supervise_spawn
	gateway_within 10
}

# supervise_exits_within <seconds>: wait for supervise to exit, killing it
# when it is still running after <seconds>. Fails when it had to be killed.
supervise_exits_within() {
	local killer
	rm -f /tmp/init-timedout
	(
		sleep "$1"
		if kill -0 "$SUP" 2>/dev/null; then
			touch /tmp/init-timedout
			kill -KILL "$SUP"
		fi
	) &
	killer=$!
	wait "$SUP" >/dev/null 2>&1
	kill "$killer" 2>/dev/null
	wait "$killer" 2>/dev/null
	[ ! -e /tmp/init-timedout ]
}

# Stop supervise as procd would: SIGTERM to the shell, which passes it on,
# and wait up to 10 seconds for its teardown to finish, so it cannot run into
# the next case. Only this shell can wait for supervise, its child, so the
# wait runs here and a background sleep kills supervise if it overruns.
supervise_stop() {
	local killer
	kill -TERM "$SUP" 2>/dev/null
	(
		sleep 10
		kill -KILL "$SUP" 2>/dev/null
	) &
	killer=$!
	wait "$SUP" >/dev/null 2>&1
	kill "$killer" 2>/dev/null
	wait "$killer" 2>/dev/null
	kill_matching /usr/bin/fips-gateway
	return 0
}

# Make ubus report the gateway's instance as running, as procd would while
# it runs; reset puts the real ubus back.
ubus_running() {
	cat > /bin/ubus <<'UBUS'
#!/bin/sh
case "$*" in
"call service list"*) echo '{"fips-gateway":{"instances":{"instance1":{"running":true}}}}' ;;
esac
exit 0
UBUS
	chmod 0755 /bin/ubus
}

ubus_real() { cp "$UBUS_REAL" /bin/ubus; }

ip6addr() { uci -q get network.lan.ip6addr; }
has_prefix() { [ "$(ip6addr)" = "$PREFIX" ]; }
has_operator() { [ "$(ip6addr)" = "$OPERATOR" ]; }
no_prefix() { [ -z "$(ip6addr)" ]; }
no_ra_default() { [ -z "$(uci -q get dhcp.lan.ra_default)" ]; }

# Calls recorded since the last mark.
mark() { MARK=$(wc -l < "$CALLS"); }
since() { tail -n +"$((MARK + 1))" "$CALLS"; }
reloads_since() { since | grep -c '^network reload'; }
reloads_since_are() { [ "$(reloads_since)" = "$1" ]; }
odhcpd_restarts_since_are() { [ "$(since | grep -c '^odhcpd restart')" = "$1" ]; }
logged_since() { since | grep -qF "$1"; }

# Run the init script with an action, as a user or procd would.
init() { "$INIT" "$@" >/dev/null 2>&1; }
enable_start() { init enable && init start; }

no_fd_1000() { ! grep -qx 1000 "$FDS"; }
lock_free() { flock -n "$LOCK" true; }
stop_returns() { bounded 10 "$INIT" stop >/dev/null 2>&1; [ "$?" -ne 124 ]; }

# ── Cases ───────────────────────────────────────────────────────────────────

# procd runs `fips-gateway supervise`; rc.common took procd's service lock on
# fd 1000 when it sourced procd.sh. Held for the gateway's lifetime, it makes
# every later stop, restart and reload wait forever.
lock_released_while_gateway_runs() {
	begin lock_released_while_gateway_runs
	reset
	if precond "supervise starts the stub gateway" supervise_start; then
		check "L1: the gateway does not hold fd 1000" no_fd_1000
		check "L2: procd's service lock is free while the gateway runs" lock_free
		check "L3: stop returns within 10 s while the gateway runs" stop_returns
	fi
	supervise_stop
	finish
}

# The first start sets the prefix and reloads the network once; a second
# start, a stop, and a start after the stop leave it and reload nothing.
prefix_kept_across_stops_and_starts() {
	begin prefix_kept_across_stops_and_starts
	reset
	if precond "enable" init enable; then
		mark
		init start
		check "P1: the first start sets network.lan.ip6addr to $PREFIX" has_prefix
		check "P1: the first start reloads the network once" reloads_since_are 1
		mark
		init start
		check "P2: a second start does not reload the network" reloads_since_are 0
		mark
		init stop
		check "P3: stop keeps the prefix" has_prefix
		check "P3: stop does not reload the network" reloads_since_are 0
		check "P3: stop deletes dhcp.lan.ra_default" no_ra_default
		# One restart drops the RA route, the other applies ra_default's removal.
		check "P3: stop restarts odhcpd twice, for the RA route and for ra_default" odhcpd_restarts_since_are 2
		mark
		init start
		check "P4: a start after a stop does not reload the network" reloads_since_are 0
		check "P4: the prefix is still set" has_prefix
	fi
	finish
}

# The stops an upgrade and a shutdown make, with the service enabled.
stop_of_an_enabled_gateway_keeps_prefix() {
	begin stop_of_an_enabled_gateway_keeps_prefix
	reset
	if precond "enable and start" enable_start && precond "the prefix is set" has_prefix; then
		mark
		init stop
		check "P12: stop of an enabled gateway keeps the prefix" has_prefix
		check "P12: stop of an enabled gateway does not reload the network" reloads_since_are 0
		init start
		mark
		init shutdown
		check "P12: shutdown keeps the prefix" has_prefix
		check "P12: shutdown does not reload the network" reloads_since_are 0
	fi
	finish
}

# disable of a stopped gateway deletes the prefix it set, and only that.
disable_deletes_prefix() {
	begin disable_deletes_prefix
	reset
	init enable
	uci set network.lan.ip6addr="$PREFIX"
	uci commit network
	mark
	init disable
	check "P5: disable deletes the prefix" no_prefix
	check "P5: disable reloads the network once" reloads_since_are 1
	reset
	init enable
	uci set network.lan.ip6addr="$OPERATOR"
	uci commit network
	mark
	init disable
	check "P5: disable leaves an operator's address alone" has_operator
	check "P5: disable reloads nothing when the address is not the prefix" reloads_since_are 0
	finish
}

# In an image build IPKG_INSTROOT names the image's root, and the build host's
# uci must not be touched.
disable_in_image_build_changes_nothing() {
	begin disable_in_image_build_changes_nothing
	reset
	rm -rf "$INSTROOT"
	mkdir -p "$INSTROOT/etc/rc.d" "$INSTROOT/var/lock"
	ln -s /lib "$INSTROOT/lib"
	ln -s /usr "$INSTROOT/usr"
	ln -s ../init.d/fips-gateway "$INSTROOT/etc/rc.d/S96fips-gateway"
	uci set network.lan.ip6addr="$PREFIX"
	uci commit network
	mark
	IPKG_INSTROOT="$INSTROOT" "$INIT" disable >/dev/null 2>&1
	check "P6: the image's boot link is removed (the disable ran)" test ! -L "$INSTROOT/etc/rc.d/S96fips-gateway"
	check "P6: the host's prefix is untouched" has_prefix
	check "P6: the host's network is not reloaded" reloads_since_are 0
	rm -rf "$INSTROOT"
	finish
}

# Disabling a running gateway must not pull the prefix from under it.
disable_of_running_gateway_keeps_prefix() {
	begin disable_of_running_gateway_keeps_prefix
	reset
	if precond "enable and start" enable_start && precond "the prefix is set" has_prefix; then
		ubus_running
		mark
		init disable
		check "P7: disable of a running gateway keeps the prefix" has_prefix
		check "P7: disable of a running gateway does not reload the network" reloads_since_are 0
		check "P7: the boot links are removed" test ! -L /etc/rc.d/S96fips-gateway
	fi
	finish
}

# A start with the gateway turned off in fips.yaml declines and cleans up.
start_turned_off_in_config_deletes_prefix() {
	begin start_turned_off_in_config_deletes_prefix
	reset
	init enable
	uci set network.lan.ip6addr="$PREFIX"
	uci commit network
	sed -i 's/enabled: true/enabled: false/' /etc/fips/fips.yaml
	mark
	init start
	check "P8: the start declines (logged)" logged_since "gateway.enabled is not true"
	check "P8: the start deletes the prefix" no_prefix
	check "P8: the start reloads the network once" reloads_since_are 1
	check "P8: the start advertises no pool route" test -z "$(uci -q get 'dhcp.@route6[0]')"
	finish
}

# Package removal: the prerm runs stop, then disable.
removal_deletes_prefix() {
	begin removal_deletes_prefix
	reset
	if precond "enable and start" enable_start && precond "the prefix is set" has_prefix; then
		mark
		sh "$PRERM" >/dev/null 2>&1
		check "P9: removal deletes the prefix" no_prefix
		check "P9: removal disables the gateway" test ! -L /etc/rc.d/S96fips-gateway
	fi
	finish
}

# disable while the gateway runs, then stop: the stop deletes the prefix.
disable_then_stop_deletes_prefix() {
	begin disable_then_stop_deletes_prefix
	reset
	if precond "enable and start" enable_start && precond "the prefix is set" has_prefix; then
		ubus_running
		mark
		init disable
		check "P10: disable of the running gateway keeps the prefix" has_prefix
		check "P10: disable of the running gateway does not reload the network" reloads_since_are 0
		ubus_real
		mark
		init stop
		check "P10: the stop that follows deletes the prefix" no_prefix
		check "P10: the stop that follows reloads the network once" reloads_since_are 1
	fi
	finish
}

# restart of a disabled but running gateway: the stop half runs with action
# restart, keeps the prefix, and so nothing reloads the network.
restart_of_disabled_gateway_keeps_prefix() {
	begin restart_of_disabled_gateway_keeps_prefix
	reset
	if precond "enable and start" enable_start && precond "the prefix is set" has_prefix; then
		ubus_running
		init disable
		ubus_real
		if precond "disabled with the prefix kept" has_prefix; then
			mark
			init restart
			check "P11: restart of a disabled gateway does not reload the network" reloads_since_are 0
			check "P11: the prefix is still set" has_prefix
		fi
	fi
	finish
}

# An upgrade restarts fips and the gateway together, and the gateway exits
# when fips0 does not exist yet. supervise waits for fips0 before starting it.
gateway_waits_for_fips0() {
	begin gateway_waits_for_fips0
	reset
	rm -f "$FIPS0"
	supervise_spawn
	sleep 3
	check "W1: the gateway is not started while fips0 is absent" test ! -s "$FDS"
	touch "$FIPS0"
	check "W2: the gateway starts within 5 s of fips0 appearing" gateway_within 5
	supervise_stop
	finish
}

# procd's stop arrives while supervise is still waiting for fips0.
stop_during_the_fips0_wait_starts_nothing() {
	begin stop_during_the_fips0_wait_starts_nothing
	reset
	rm -f "$FIPS0"
	supervise_spawn
	sleep 2
	kill -TERM "$SUP" 2>/dev/null
	check "W3: supervise exits within 5 s" supervise_exits_within 5
	check "W4: the gateway was never started" test ! -e "$FDS"
	supervise_stop
	finish
}

# fips0 never appears: the gateway is started once the wait runs out, so its
# own error is reported and procd's respawn takes over, and the timeout is
# logged.
gateway_starts_after_the_fips0_wait_runs_out() {
	begin gateway_starts_after_the_fips0_wait_runs_out
	reset
	rm -f "$FIPS0"
	mark
	FIPS0_WAIT=2 "$INIT" supervise > "$SUPLOG" 2>&1 &
	SUP=$!
	check "W5: the gateway is started after the bound" gateway_within 5
	check "W6: the timeout is logged" logged_since "fips0 did not appear"
	supervise_stop
	finish
}

# ── Runner ──────────────────────────────────────────────────────────────────

[ -f "$INIT_GATEWAY" ] || harness_fail "no init script at $INIT_GATEWAY"
for tool in flock uci pgrep ip; do
	command -v "$tool" >/dev/null 2>&1 || harness_fail "$tool is missing from the image"
done
for f in /etc/rc.common /lib/functions/procd.sh; do
	[ -f "$f" ] || harness_fail "the image has no $f"
done
cp /bin/ubus "$UBUS_REAL" || harness_fail "cannot save /bin/ubus"
cp /etc/config/dhcp "$DHCP_STOCK" || harness_fail "cannot save /etc/config/dhcp"
[ -f "$PRERM" ] || harness_fail "no prerm at $PRERM"

ALL="lock_released_while_gateway_runs
prefix_kept_across_stops_and_starts
stop_of_an_enabled_gateway_keeps_prefix
disable_deletes_prefix
disable_in_image_build_changes_nothing
disable_of_running_gateway_keeps_prefix
start_turned_off_in_config_deletes_prefix
removal_deletes_prefix
disable_then_stop_deletes_prefix
restart_of_disabled_gateway_keeps_prefix
gateway_waits_for_fips0
stop_during_the_fips0_wait_starts_nothing
gateway_starts_after_the_fips0_wait_runs_out"

if [ -n "$INIT_CASES" ]; then
	SELECTED="$INIT_CASES"
	EXPECTED=$(echo "$INIT_CASES" | wc -w)
	for c in $INIT_CASES; do
		printf '%s\n' "$ALL" | grep -qxF "$c" || harness_fail "unknown case in INIT_CASES: $c"
	done
else
	SELECTED="$ALL"
	EXPECTED=$ALL_CASES
fi

for c in $SELECTED; do
	"$c"
done

echo ""
echo "ran $RAN of $EXPECTED cases"
if [ "$RAN" -ne "$EXPECTED" ]; then
	echo "init-scenarios: $((EXPECTED - RAN)) case(s) did not reach their end" >&2
	exit 2
fi
if [ "$FAILURES" -eq 0 ]; then
	echo "init-scenarios: all $CASES checks passed"
	exit 0
fi
echo "init-scenarios: $FAILURES of $CASES checks failed"
exit 1
