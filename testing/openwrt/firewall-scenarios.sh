#!/bin/sh
# OpenWrt firewall scenarios for 90-fips-setup and fips-mesh-setup, run inside
# an openwrt/rootfs image so the real uci, fw4 and nft are exercised under ash.
#
# Driven by testing/openwrt/maintainer-scripts-test.sh, once per pinned image,
# with the container started with --cap-add NET_ADMIN so fw4 can load its
# table into the container's own network namespace, and with a small tmpfs at
# /fw-small that the cases saving onto a full overlay put /etc/config on. Each case resets the
# container to the image's stock configuration, starts fw4, builds a starting
# state (often the one the 0.5.2 package left), runs the setup under test and
# asserts on uci and on the loaded nftables ruleset.
#
# Seams:
#   FW_SETUP     the setup script under test; default the one built into the
#                .ipk, as package-test.sh --keep extracts it under /apk.
#   FW_SNIPPETS  a directory laid out like /usr/share/nftables.d, copied there
#                before each case; default the .ipk's. "none" installs none.
#   FW_MESH_SETUP  the mesh helper under test; default the one built into the
#                .ipk.
#   FW_FIPS_YAML the fips.yaml the no-touch cases install; default the one
#                built into the .ipk.
#   FW_CASES     case function names to run, separated by spaces; default all.
#
# The mesh cases have no radio: the zone holds each interface by device name,
# which fw4 renders without netifd, and wifi is a stub that logs its call to
# the same file as the firewall reloads, so the log gives their order.
#
# Assertions do not stop a case. A failed precondition records a failure and
# the case skips to its end. Every case that reaches its end is counted, and a
# run that counts fewer cases than it selected exits 2.
#
# Exit 0 = every case passed. Exit 1 = at least one failed. Exit 2 = the
# harness could not run; never treated as a pass.

set -u

REPO="${REPO:-/src}"
FW_SETUP="${FW_SETUP:-/apk/ipk-root/etc/uci-defaults/90-fips-setup}"
FW_SNIPPETS="${FW_SNIPPETS:-/apk/ipk-root/usr/share/nftables.d}"
FW_MESH_SETUP="${FW_MESH_SETUP:-/apk/ipk-root/usr/bin/fips-mesh-setup}"
FW_FIPS_YAML="${FW_FIPS_YAML:-/apk/ipk-root/etc/fips/fips.yaml}"
FW_CASES="${FW_CASES:-}"
FIXTURES="$REPO/testing/openwrt/fixtures"

WORK=/tmp/fw-work
STOCK=/tmp/fw-stock
WRAP=/tmp/fw-wrap
RELOADLOG=/tmp/fw-reload.log
FLUSHONLY=/tmp/fw-flush-only
FLUSHLIST=/tmp/fw-flush-listing
SMALL=/fw-small
COPY=/tmp/fips-firewall.uci
MCOPY=/tmp/fips-mesh-firewall.uci
WCOPY=/tmp/fips-mesh-wireless.uci
STUB=/tmp/fw-wrap/stub
DAEMONPID=/tmp/fw-daemon.pid
OUT="$WORK/out"
SYSPATH=/usr/sbin:/usr/bin:/sbin:/bin

# The number of cases in the full run, counted by hand from the list at the
# end of this file. A run that completes fewer exits 2.
ALL_CASES=82

FAILURES=0
CASES=0
RAN=0
CUR=""
LIST=""
RC=0

note() { echo "  $*"; }

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
	echo "firewall-scenarios: $*" >&2
	exit 2
}

# check <description> <command...>: passes when the command succeeds.
check() {
	local d="$1"
	shift
	if "$@"; then ok "$d"; else bad "$d"; fi
	return 0
}

# refute <description> <command...>: passes when the command fails.
refute() {
	local d="$1"
	shift
	if "$@"; then bad "$d"; else ok "$d"; fi
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

same() { [ "$1" = "$2" ]; }

# ── The loaded ruleset ──────────────────────────────────────────────────────
# Every predicate fails when the listing itself fails, so an absent table can
# never read as an absent rule.

listing() { LIST="$(nft list chain inet fw4 "$1" 2>/dev/null)"; }

has() { listing "$1" && printf '%s\n' "$LIST" | grep -qF -- "$2"; }

lacks() { listing "$1" && ! printf '%s\n' "$LIST" | grep -qF -- "$2"; }

table_lacks() {
	local t
	t="$(nft list table inet fw4 2>/dev/null)" || return 1
	! printf '%s\n' "$t" | grep -qF -- "$1"
}

table_has() {
	local t
	t="$(nft list table inet fw4 2>/dev/null)" || return 1
	case "$t" in
	*"$1"*) return 0 ;;
	esac
	return 1
}

# The rules of a chain that name fips0, in order, without indentation.
naming() {
	listing "$1" || return 1
	printf '%s\n' "$LIST" | grep -F '"fips0"' | sed 's/^[[:space:]]*//'
}

ACCEPTPAIR='iifname "fips0" ct state established,related accept comment "fips-reload-failed"'
DROPPAIR='iifname "fips0" drop comment "fips-reload-failed"'

# In input, forward and output, the only rule naming fips0 is fw4's jump into
# the fips zone's chain.
only_zone_jumps() {
	local c dir lines
	for c in input forward output; do
		dir=iifname
		[ "$c" = output ] && dir=oifname
		lines="$(naming "$c")" || return 1
		[ "$(printf '%s\n' "$lines" | grep -c .)" = 1 ] || return 1
		case "$lines" in
		"$dir \"fips0\" jump ${c}_fips "*) ;;
		*) return 1 ;;
		esac
	done
	return 0
}

# The failsafe pair heads the rules naming fips0 in <chain>, and a later rule
# naming fips0 jumps to <target>.
pair_heads() {
	local lines
	lines="$(naming "$1")" || return 1
	[ "$(printf '%s\n' "$lines" | sed -n 1p)" = "$ACCEPTPAIR" ] || return 1
	[ "$(printf '%s\n' "$lines" | sed -n 2p)" = "$DROPPAIR" ] || return 1
	printf '%s\n' "$lines" | sed -n '3,$p' | grep -qF "jump $2 "
}

# The failsafe pair, once each, is everything naming fips0 in <chain>.
pair_only() {
	local lines
	lines="$(naming "$1")" || return 1
	[ "$lines" = "$(printf '%s\n%s' "$ACCEPTPAIR" "$DROPPAIR")" ]
}

# <chain> holds exactly one rule of each half of the failsafe pair.
pair_once() {
	listing "$1" || return 1
	[ "$(printf '%s\n' "$LIST" | grep -cF "$ACCEPTPAIR")" = 1 ] &&
		[ "$(printf '%s\n' "$LIST" | grep -cF "$DROPPAIR")" = 1 ]
}

# A rule in <chain> jumps to <target> and names fips0 (the lan set jump).
lan_jump() {
	naming "$1" | grep -qF "jump $2 "
}

# In <chain>, the first line containing <a> comes before the first containing
# <b>, and both are present.
before() {
	local la lb
	listing "$1" || return 1
	la="$(printf '%s\n' "$LIST" | grep -nF -- "$2" | sed -n '1s/:.*//p')"
	lb="$(printf '%s\n' "$LIST" | grep -nF -- "$3" | sed -n '1s/:.*//p')"
	[ -n "$la" ] && [ -n "$lb" ] && [ "$la" -lt "$lb" ]
}

# The rules of <chain> in order, without indentation, counters or the table and
# chain lines.
rules_of() {
	listing "$1" || return 1
	printf '%s\n' "$LIST" | sed -e 's/^[[:space:]]*//' -e '/^table /d' -e '/^chain /d' -e '/^}$/d' -e '/^$/d' \
		-e 's/counter packets [0-9]* bytes [0-9]* //'
}

# Everything the fips zone accepts from FIPS peers, as fw4 renders the zone the
# setup creates with the packaged include: ping and port forwards to the router,
# port forwards through it, and nothing else.
INPUT_FIPS='icmpv6 type echo-request accept comment "!fw4: Allow-FIPS-Ping"
ct status dnat accept comment "fips: accept fips-gateway port forwards"
jump reject_from_fips'
FORWARD_FIPS='ct status dnat accept comment "fips: accept fips-gateway port forwards"
jump reject_to_fips'

zone_rules_exact() {
	[ "$(rules_of input_fips)" = "$INPUT_FIPS" ] && [ "$(rules_of forward_fips)" = "$FORWARD_FIPS" ]
}

# The packaged wan include is the first rule of forward_wan, so it refuses
# ICMPv6 into fips0 before OpenWrt's stock Allow-ICMPv6-Forward accepts it.
WAN_ICMPV6='oifname "fips0" meta l4proto ipv6-icmp reject comment "fips: no ICMPv6 from wan into the mesh"'

wan_icmpv6_first() {
	[ "$(rules_of forward_wan | sed -n 1p)" = "$WAN_ICMPV6" ] &&
		before forward_wan 'comment "fips: no ICMPv6 from wan into the mesh"' 'Allow-ICMPv6-Forward'
}

no_reload_rules() {
	table_lacks 'fips-reload-failed' && table_lacks 'fips-reload-probe'
}

no_old_accepts() { table_lacks 'comment "fips"'; }

# ── uci ─────────────────────────────────────────────────────────────────────

uget() { uci -q get "$1"; }

# A section's options, without its name: uci names an anonymous section by an
# id that changes when the sections before it change.
dump() { uci -q show "$1" | sed 's/^[^.]*\.[^.=]*//'; }

# The section of the first zone named <name>, as @zone[N].
zone_of() {
	local z=0
	while uci -q get "firewall.@zone[$z]" >/dev/null; do
		if [ "$(uci -q get "firewall.@zone[$z].name")" = "$1" ]; then
			echo "@zone[$z]"
			return 0
		fi
		z=$((z + 1))
	done
	return 1
}

lan_device() {
	local z d
	z="$(zone_of lan)" || return 1
	for d in $(uci -q get "firewall.$z.device"); do
		[ "$d" = "$1" ] && return 0
	done
	return 1
}

# lan is found and lists br-lan, so a missing fips0 entry is not a missing zone.
lan_lacks_fips0() { lan_device br-lan && ! lan_device fips0; }

old_include() { uci -q show firewall | grep -qF "path='/etc/fips/firewall.sh'"; }

no_old_include() {
	local s
	s="$(uci -q show firewall)" || return 1
	printf '%s\n' "$s" | grep -qF "=defaults" || return 1
	! printf '%s\n' "$s" | grep -qF "path='/etc/fips/firewall.sh'"
}

zone_made() {
	[ "$(uget firewall.fips)" = zone ] &&
		[ "$(uget firewall.fips.name)" = fips ] &&
		[ "$(uget firewall.fips.device)" = fips0 ] &&
		[ "$(uget firewall.fips.input)" = REJECT ] &&
		[ "$(uget firewall.fips.output)" = ACCEPT ] &&
		[ "$(uget firewall.fips.forward)" = REJECT ] &&
		[ "$(uget firewall.fips.auto_helper)" = 0 ]
}

forwarding_made() {
	[ "$(uget firewall.fips_lan)" = forwarding ] &&
		[ "$(uget firewall.fips_lan.src)" = lan ] &&
		[ "$(uget firewall.fips_lan.dest)" = fips ]
}

ping_made() {
	[ "$(uget firewall.fips_ping)" = rule ] &&
		[ "$(uget firewall.fips_ping.src)" = fips ] &&
		[ "$(uget firewall.fips_ping.proto)" = icmp ] &&
		[ "$(uget firewall.fips_ping.icmp_type)" = echo-request ] &&
		[ "$(uget firewall.fips_ping.family)" = ipv6 ] &&
		[ "$(uget firewall.fips_ping.target)" = ACCEPT ]
}

# ── Output and reloads ──────────────────────────────────────────────────────

said() { grep -qF -- "$1" "$OUT"; }

said_once() { [ "$(grep -cF -- "$1" "$OUT")" = 1 ]; }

reloads() { grep -cx reload "$RELOADLOG" 2>/dev/null; }

one_reload() { [ "$(reloads)" = 1 ]; }

no_reload() { [ -f "$RELOADLOG" ] && [ "$(reloads)" = 0 ]; }

# ── Case scaffolding ────────────────────────────────────────────────────────

install_snippets() {
	[ "$FW_SNIPPETS" = none ] && return 0
	cp -R "$FW_SNIPPETS/." /usr/share/nftables.d/ ||
		harness_fail "cannot copy the snippets from $FW_SNIPPETS"
}

# The container as the image ships it, with fw4 not running.
fw_clean() {
	if [ -e /usr/sbin/nft.hidden ]; then
		mv /usr/sbin/nft.hidden /usr/sbin/nft || harness_fail "cannot restore /usr/sbin/nft"
	fi
	fw4 -q flush >/dev/null 2>&1
	rm -f /var/run/fw4.state /var/run/fw3.state
	rm -rf /tmp/.uci "$WRAP" "$WORK"
	rm -f /etc/nftables.d/zz-*.nft "$FLUSHONLY" "$FLUSHLIST" "$RELOADLOG"
	rm -f /etc/fips/firewall.sh /etc/hotplug.d/net/99-fips /etc/uci-defaults/90-fips-setup
	rm -f "$COPY" "$COPY.staged" "$COPY.now" "$MCOPY" "$MCOPY.staged" "$MCOPY.now"
	rm -f "$WCOPY" "$WCOPY.staged" "$WCOPY.now"
	rm -f /usr/bin/fips-mesh-setup /etc/fips/fips.yaml /etc/init.d/fips
	if [ -f "$DAEMONPID" ]; then
		kill "$(cat "$DAEMONPID")" >/dev/null 2>&1
		rm -f "$DAEMONPID"
	fi
	for l in /sys/class/net/fips-mesh*; do
		[ -e "$l" ] && ip link del "${l##*/}" >/dev/null 2>&1
	done
	# A symbolic link when the case before put /etc/config on the small tmpfs.
	rm -rf /etc/config /usr/share/nftables.d
	[ -d "$SMALL" ] && rm -rf "$SMALL/config" "$SMALL/fill"
	cp -a "$STOCK/config" /etc/config || harness_fail "cannot restore /etc/config"
	cp -a "$STOCK/nftables.d" /usr/share/nftables.d || harness_fail "cannot restore /usr/share/nftables.d"
	install_snippets
	mkdir -p /var/run /var/lock /etc/fips /etc/hotplug.d/net /etc/uci-defaults "$WORK" "$WRAP"
	# No netifd here, so lan gets a device of its own to render with, as a
	# router's br-lan does.
	uci add_list "firewall.$(zone_of lan).device=br-lan" && uci commit firewall ||
		harness_fail "cannot add br-lan to the lan zone"
	: > "$RELOADLOG"
}

# fw_begin <name> <what it shows> [nostart]: reset and start fw4.
fw_begin() {
	CUR="$1"
	note "$1: $2"
	fw_clean
	[ "${3:-}" = nostart ] && return 0
	fw4 -q start >/dev/null 2>&1 || harness_fail "$CUR: fw4 -q start failed after the reset"
	nft list table inet fw4 >/dev/null 2>&1 || harness_fail "$CUR: fw4 started but inet fw4 is not loaded"
	return 0
}

fw_end() {
	RAN=$((RAN + 1))
	echo "  done $CUR"
	return 0
}

# The state the 0.5.2 package leaves: its setup, the firewall reload that runs
# its include, and its hotplug hook for fips0.
released_state() {
	cp "$FIXTURES/released-firewall.sh" /etc/fips/firewall.sh &&
		cp "$FIXTURES/released-99-fips" /etc/hotplug.d/net/99-fips &&
		chmod 0755 /etc/fips/firewall.sh /etc/hotplug.d/net/99-fips ||
		harness_fail "cannot install the released firewall files"
	sh "$FIXTURES/released-90-fips-setup" >/dev/null 2>&1
	/etc/init.d/firewall reload >/dev/null 2>&1
	INTERFACE=fips0 ACTION=add sh /etc/hotplug.d/net/99-fips >/dev/null 2>&1
	return 0
}

released_reached() {
	has input 'iifname "fips0" accept comment "fips"' &&
		has forward 'iifname "fips0" accept comment "fips"' &&
		has forward 'oifname "fips0" accept comment "fips"' &&
		has output 'oifname "fips0" accept comment "fips"' &&
		lan_jump input input_lan &&
		lan_device fips0 && old_include
}

# What opkg and apk do with the previous package's files that the new one no
# longer carries.
drop_released_files() {
	rm -f /etc/fips/firewall.sh /etc/hotplug.d/net/99-fips
}

# run_setup [how]: run the setup under test, keeping its output in $OUT and
# its status in RC. how: exec (default), apk, sourced, path=<PATH>, wrap.
run_setup() {
	: > "$RELOADLOG"
	case "${1:-exec}" in
	exec) sh "$FW_SETUP" > "$OUT" 2>&1 ;;
	apk) env -i PATH="$SYSPATH" sh "$FW_SETUP" > "$OUT" 2>&1 ;;
	sourced) (. "$FW_SETUP") > "$OUT" 2>&1 ;;
	path=*) PATH="${1#path=}" sh "$FW_SETUP" > "$OUT" 2>&1 ;;
	wrap) PATH="$WRAP:$PATH" sh "$FW_SETUP" > "$OUT" 2>&1 ;;
	esac
	RC=$?
	sed 's/^/    | /' "$OUT"
	return 0
}

# hook_path [wrap]: the PATH the setup runs with. The wifi stub comes first,
# so a wifi reload the mesh hook makes is logged; outside the mesh cases the
# stub does not exist. wrap puts the uci and nft wrappers next.
hook_path() {
	if [ "${1:-}" = wrap ]; then
		printf '%s' "$STUB:$WRAP:$PATH"
	else
		printf '%s' "$STUB:$PATH"
	fi
}

# run_postinst [wrap]: install the setup in /etc/uci-defaults and run it as the
# package's postinst does, deleting it only when it ends with status 0.
run_postinst() {
	local p
	p="$(hook_path "${1:-}")"
	cp "$FW_SETUP" /etc/uci-defaults/90-fips-setup && chmod 0755 /etc/uci-defaults/90-fips-setup ||
		harness_fail "cannot install the setup in /etc/uci-defaults"
	: > "$RELOADLOG"
	PATH="$p" sh -c '/etc/uci-defaults/90-fips-setup && rm -f /etc/uci-defaults/90-fips-setup' > "$OUT" 2>&1
	RC=$?
	sed 's/^/    | /' "$OUT"
	return 0
}

# Run the kept setup as the uci-defaults loop at boot does.
run_boot() {
	: > "$RELOADLOG"
	PATH="$(hook_path)" sh -c '( cd /etc/uci-defaults && . ./90-fips-setup ) && rm -f /etc/uci-defaults/90-fips-setup' > "$OUT" 2>&1
	RC=$?
	sed 's/^/    | /' "$OUT"
	return 0
}

# Put /etc/config on the small tmpfs, so a save can run out of space as it
# does on a full overlay.
small_config() {
	local size
	size="$(df -k "$SMALL" 2>/dev/null | awk 'NR == 2 { print $2 }')"
	[ -n "$size" ] && [ "$size" -le 256 ] ||
		harness_fail "$SMALL is not a small tmpfs; the driver mounts one with --tmpfs"
	mkdir "$SMALL/config" && cp -a /etc/config/. "$SMALL/config/" &&
		rm -rf /etc/config && ln -s "$SMALL/config" /etc/config ||
		harness_fail "cannot move /etc/config onto $SMALL"
}

# small_free <pages>: fill the small tmpfs until only <pages> 4 KiB pages are
# free.
small_free() {
	local avail
	avail="$(df -k "$SMALL" | awk 'NR == 2 { print $4 }')"
	dd if=/dev/zero of="$SMALL/fill" bs=4096 count=$((avail / 4 - $1)) 2>/dev/null
	[ "$(df -k "$SMALL" | awk 'NR == 2 { print $4 }')" = $(($1 * 4)) ]
}

wrap_uci_commit_fails() {
	cat > "$WRAP/uci" <<'EOF'
#!/bin/sh
echo "$*" >> /tmp/fw-wrap/uci.log
[ "$*" = "commit firewall" ] && exit 1
exec /sbin/uci "$@"
EOF
	chmod 0755 "$WRAP/uci"
}

# wrap_nft_fails <exact argument string to fail>
wrap_nft_fails() {
	{
		echo '#!/bin/sh'
		echo 'echo "$*" >> /tmp/fw-wrap/nft.log'
		printf '[ "$*" = %s ] && exit 1\n' "'$1'"
		echo 'exec /usr/sbin/nft "$@"'
	} > "$WRAP/nft"
	chmod 0755 "$WRAP/nft"
}

wrap_called() { grep -qxF -- "$2" "$WRAP/$1.log" 2>/dev/null; }

# ── Successful upgrades ─────────────────────────────────────────────────────

# The assertions of an upgrade from 0.5.2 that loads cleanly.
upgrade_ok() {
	check "the setup exits 0" same "$RC" 0
	check "exactly one firewall reload" one_reload
	check "fips0 is no longer a lan device" lan_lacks_fips0
	check "no include names /etc/fips/firewall.sh" no_old_include
	check "the fips zone is REJECT/ACCEPT/REJECT on fips0 with auto_helper 0" zone_made
	check "the lan to fips forwarding exists" forwarding_made
	check "the fips ping rule exists" ping_made
	if table_has 'jump helper_lan'; then
		check "no helper chain for the fips zone" table_lacks helper_fips
	else
		note "helper assertion not exercised on this host"
	fi
	check "base chains name fips0 only in the fips zone jumps" only_zone_jumps
	check "input_fips accepts echo-request" has input_fips 'Allow-FIPS-Ping'
	check "input_fips accepts port forwards" has input_fips 'ct status dnat accept'
	check "input_fips ends in the reject jump" before input_fips 'ct status dnat accept' 'jump reject_from_fips'
	check "forward_fips accepts port forwards" has forward_fips 'ct status dnat accept'
	check "forward_lan jumps to accept_to_fips" has forward_lan 'jump accept_to_fips'
	check "input_fips and forward_fips hold exactly the ping, port-forward and reject rules" zone_rules_exact
	check "forward_wan refuses ICMPv6 into fips0 before the stock Allow-ICMPv6-Forward" wan_icmpv6_first
	refute "no reload-failure warning" said 'firewall reload failed'
	refute "no not-loaded warning" said 'firewall is not loaded'
	refute "no could-not-be-checked warning" said 'could not be checked'
	check "no failsafe or probe rule" no_reload_rules
	check "no copy of the staged configuration is left in /tmp" eval '[ ! -e "$COPY" ]'
	return 0
}

fw_upgrade_moves_fips0_into_its_own_zone() {
	fw_begin fw_upgrade_moves_fips0_into_its_own_zone "an upgrade from 0.5.2 moves fips0 out of lan into the fips zone"
	released_state
	if precond "the 0.5.2 accepts, lan jump and include are live" released_reached; then
		drop_released_files
		run_setup
		upgrade_ok
	fi
	fw_end
}

fw_upgrade_under_apk_environment_moves_fips0() {
	fw_begin fw_upgrade_under_apk_environment_moves_fips0 "the same upgrade with apk-tools' PATH-only environment"
	released_state
	if precond "the 0.5.2 accepts, lan jump and include are live" released_reached; then
		drop_released_files
		run_setup apk
		upgrade_ok
	fi
	fw_end
}

fw_path_without_sbin_still_migrates() {
	fw_begin fw_path_without_sbin_still_migrates "a caller's PATH without /usr/sbin still loads the migration"
	released_state
	if precond "the 0.5.2 accepts, lan jump and include are live" released_reached; then
		drop_released_files
		run_setup path=/usr/bin:/sbin:/bin
		upgrade_ok
	fi
	fw_end
}

fw_second_run_changes_nothing() {
	fw_begin fw_second_run_changes_nothing "a later upgrade changes nothing and does not reload"
	released_state
	if precond "the 0.5.2 accepts, lan jump and include are live" released_reached; then
		drop_released_files
		run_setup
		uci export firewall > "$WORK/first.uci"
		run_setup
		uci export firewall > "$WORK/second.uci"
		check "the second run exits 0" same "$RC" 0
		check "uci export firewall is byte-identical" cmp -s "$WORK/first.uci" "$WORK/second.uci"
		check "the second run does not reload" no_reload
	fi
	fw_end
}

# operator_zone <input policy> [device]: the 0.5.2 state plus a zone of the
# operator's own holding fips0 by device, fips0 unless given.
operator_zone() {
	released_state
	uci add firewall zone >/dev/null &&
		uci set firewall.@zone[-1].name=mesh &&
		uci add_list "firewall.@zone[-1].device=${2:-fips0}" &&
		uci set "firewall.@zone[-1].input=$1" &&
		uci set firewall.@zone[-1].output=ACCEPT &&
		uci set firewall.@zone[-1].forward=REJECT &&
		uci commit firewall || harness_fail "cannot add the operator's zone"
	dump "firewall.$(zone_of mesh)" > "$WORK/mesh.before"
}

operator_zone_ok() {
	check "the setup exits 0" same "$RC" 0
	check "no fips zone is created" same "$(uget firewall.fips)" ""
	check "fips0 is no longer a lan device" lan_lacks_fips0
	check "no include names /etc/fips/firewall.sh" no_old_include
	dump "firewall.$(zone_of mesh)" > "$WORK/mesh.after"
	check "the operator's zone is unchanged" cmp -s "$WORK/mesh.before" "$WORK/mesh.after"
	check "exactly one firewall reload" one_reload
	check "input jumps fips0 into the operator's zone" has input 'iifname "fips0" jump input_mesh'
	refute "no reload-failure warning" said 'firewall reload failed'
	refute "no could-not-be-checked warning" said 'could not be checked'
	check "no failsafe or probe rule" no_reload_rules
	check "the operator's zone is named as needing its own rules" \
		said 'fips0 is in firewall zone mesh, not in the fips zone; fips-gateway port forwards into it'
	check "forward_mesh has no port-forward accept" lacks forward_mesh 'ct status dnat accept'
}

fw_operator_zone_is_kept_and_named() {
	fw_begin fw_operator_zone_is_kept_and_named "an operator's own zone holding fips0 is kept, and the upgrade says it needs rules"
	operator_zone REJECT
	if precond "the 0.5.2 accepts, lan jump and include are live" released_reached; then
		drop_released_files
		run_setup
		operator_zone_ok
		refute "no exposure line for a REJECT zone" said 'router services are reachable'
	fi
	fw_end
}

fw_operator_zone_accepting_input_is_reported() {
	local v
	# fw4 reads a policy in any case and from any leading part of its name.
	for v in ACCEPT accept acc; do
		fw_begin fw_operator_zone_accepting_input_is_reported "an operator's zone with input $v is reported as exposing router services"
		operator_zone "$v"
		if precond "input $v: the 0.5.2 accepts, lan jump and include are live" released_reached; then
			drop_released_files
			run_setup
			operator_zone_ok
			check "input $v: the exposure is reported" \
				said 'fips0 is in firewall zone mesh, whose input policy is ACCEPT, so router services are reachable from FIPS peers'
		fi
	done
	fw_end
}

fw_operator_wildcard_zone_holds_fips0() {
	fw_begin fw_operator_wildcard_zone_holds_fips0 "an operator's zone holding fips0 by the device wildcard fips+ is kept, and no fips zone is made"
	operator_zone REJECT fips+
	if precond "the 0.5.2 accepts, lan jump and include are live" released_reached; then
		drop_released_files
		run_setup
		check "the setup exits 0" same "$RC" 0
		check "no fips zone is created" same "$(uget firewall.fips)" ""
		check "no zone named fips" eval '! uci -q show firewall | grep -q "\.name=.fips.$"'
		check "fips0 is no longer a lan device" lan_lacks_fips0
		check "no include names /etc/fips/firewall.sh" no_old_include
		dump "firewall.$(zone_of mesh)" > "$WORK/mesh.after"
		check "the operator's zone is unchanged" cmp -s "$WORK/mesh.before" "$WORK/mesh.after"
		check "exactly one firewall reload" one_reload
		check "input jumps the fips wildcard into the operator's zone" has input 'iifname "fips*" jump input_mesh'
		check "no failsafe or probe rule" no_reload_rules
		check "the operator's zone is named as needing its own rules" \
			said 'fips0 is in firewall zone mesh, not in the fips zone; fips-gateway port forwards into it'
	fi
	fw_end
}

# ── Fresh installs and an operator's configuration ──────────────────────────

fresh_ok() {
	check "the setup exits 0" same "$RC" 0
	check "the fips zone is REJECT/ACCEPT/REJECT on fips0 with auto_helper 0" zone_made
	check "the lan to fips forwarding exists" forwarding_made
	check "the fips ping rule exists" ping_made
	check "exactly one firewall reload" one_reload
	check "base chains name fips0 only in the fips zone jumps" only_zone_jumps
	check "input_fips accepts echo-request" has input_fips 'Allow-FIPS-Ping'
	check "input_fips accepts port forwards" has input_fips 'ct status dnat accept'
	check "forward_fips accepts port forwards" has forward_fips 'ct status dnat accept'
	check "forward_lan jumps to accept_to_fips" has forward_lan 'jump accept_to_fips'
	check "input_fips and forward_fips hold exactly the ping, port-forward and reject rules" zone_rules_exact
	check "forward_wan refuses ICMPv6 into fips0 before the stock Allow-ICMPv6-Forward" wan_icmpv6_first
	check "no failsafe or probe rule" no_reload_rules
}

fw_fresh_install_creates_live_zone() {
	fw_begin fw_fresh_install_creates_live_zone "a fresh install creates the zone, forwarding and rule, live"
	run_setup
	fresh_ok
	fw_end
}

fw_sourced_setup_does_not_leak() {
	fw_begin fw_sourced_setup_does_not_leak "sourced in a subshell, the setup works and leaks neither PATH nor its device variable"
	: > "$RELOADLOG"
	(
		tundev=caller
		before="$PATH"
		trap 'printf "%s\n%s\n%s\n" "$before" "$PATH" "$tundev" > /tmp/fw-work/leak' EXIT
		. "$FW_SETUP"
	) > "$OUT" 2>&1
	RC=$?
	sed 's/^/    | /' "$OUT"
	fresh_ok
	if precond "the subshell wrote its PATH record" eval '[ -n "$(sed -n 1p "$WORK/leak" 2>/dev/null)" ]'; then
		check "PATH after sourcing equals PATH before" same "$(sed -n 1p "$WORK/leak")" "$(sed -n 2p "$WORK/leak")"
		check "the caller's tundev is unchanged" same "$(sed -n 3p "$WORK/leak")" caller
	fi
	fw_end
}

fw_operator_edits_survive_rerun() {
	fw_begin fw_operator_edits_survive_rerun "an operator's edits to the zone survive a later run byte for byte"
	run_setup
	if precond "the first run created the fips zone" eval '[ "$(uget firewall.fips)" = zone ]'; then
		uci set firewall.fips.input=ACCEPT &&
			uci set firewall.op_ssh=rule &&
			uci set firewall.op_ssh.name=Op-SSH &&
			uci set firewall.op_ssh.src=fips &&
			uci set firewall.op_ssh.proto=tcp &&
			uci set firewall.op_ssh.dest_port=22 &&
			uci set firewall.op_ssh.target=ACCEPT &&
			uci commit firewall || harness_fail "cannot edit the zone"
		uci export firewall > "$WORK/edited.uci"
		run_setup
		uci export firewall > "$WORK/after.uci"
		check "the setup exits 0" same "$RC" 0
		check "the edited configuration is byte-identical" cmp -s "$WORK/edited.uci" "$WORK/after.uci"
	fi
	fw_end
}

fw_lan_through_network_is_reported() {
	local v opt
	# The interface names fips0 by device, or by ifname as before OpenWrt 21.02;
	# and by device again with lan's input hardened to REJECT, which is not an
	# ACCEPT exposure but still gives FIPS peers the access of LAN hosts.
	for v in device ifname reject; do
		opt=$v
		[ "$v" = reject ] && opt=device
		fw_begin fw_lan_through_network_is_reported "fips0 in lan through a network interface's $opt option is left alone and reported ($v)"
		# The image has no network configuration of its own.
		touch /etc/config/network
		uci set network.fipsnet=interface &&
			uci set "network.fipsnet.$opt=fips0" &&
			uci set network.fipsnet.proto=none &&
			uci commit network &&
			uci add_list "firewall.$(zone_of lan).network=fipsnet" &&
			uci commit firewall || harness_fail "cannot add fipsnet to lan"
		if [ "$v" = reject ]; then
			uci set "firewall.$(zone_of lan).input=REJECT" && uci commit firewall ||
				harness_fail "cannot harden the lan zone's input"
		fi
		dump "firewall.$(zone_of lan)" > "$WORK/lan.before"
		run_setup
		dump "firewall.$(zone_of lan)" > "$WORK/lan.after"
		check "$v: the setup exits 0" same "$RC" 0
		check "$v: no fips zone is created" same "$(uget firewall.fips)" ""
		check "$v: the lan zone is untouched" cmp -s "$WORK/lan.before" "$WORK/lan.after"
		if [ "$v" = reject ]; then
			check "reject: the lan membership is reported" \
				said_once 'fips0 is in the lan firewall zone, so FIPS peers have the access of LAN hosts'
			refute "reject: no ACCEPT exposure line" said 'whose input policy is ACCEPT'
		else
			check "$v: the exposure is reported" \
				said 'fips0 is in firewall zone lan, whose input policy is ACCEPT, so router services are reachable from FIPS peers'
		fi
	done
	fw_end
}

fw_old_include_and_files_removed() {
	fw_begin fw_old_include_and_files_removed "with fips0 already out of lan by hand, the include, its accepts and the old files go"
	released_state
	uci del_list "firewall.$(zone_of lan).device=fips0" && uci commit firewall ||
		harness_fail "cannot remove fips0 from lan"
	if precond "the inserted input accept is live and both old files are present" \
		eval 'has input "iifname \"fips0\" accept comment \"fips\"" && [ -f /etc/fips/firewall.sh ] && [ -f /etc/hotplug.d/net/99-fips ]'; then
		run_setup
		check "the setup exits 0" same "$RC" 0
		check "no include names /etc/fips/firewall.sh" no_old_include
		check "base chains name fips0 only in the fips zone jumps" only_zone_jumps
		check "/etc/fips/firewall.sh is gone" eval '[ ! -e /etc/fips/firewall.sh ]'
		check "/etc/hotplug.d/net/99-fips is gone" eval '[ ! -e /etc/hotplug.d/net/99-fips ]'
	fi
	fw_end
}

# A second copy of the old include follows the first, so a walk that steps past
# the index uci has just renumbered leaves one behind.
fw_unrelated_include_survives() {
	fw_begin fw_unrelated_include_survives "an unrelated include survives and every copy of the old one goes"
	printf '#!/bin/sh\n' > /etc/fw-unrelated.sh
	chmod 0755 /etc/fw-unrelated.sh
	uci add firewall include >/dev/null &&
		uci set firewall.@include[-1].path=/etc/fw-unrelated.sh &&
		uci set firewall.@include[-1].type=script &&
		uci commit firewall || harness_fail "cannot add the unrelated include"
	released_state
	uci add firewall include >/dev/null &&
		uci set firewall.@include[-1].path=/etc/fips/firewall.sh &&
		uci set firewall.@include[-1].reload=1 &&
		uci commit firewall || harness_fail "cannot add the second old include"
	if precond "the unrelated include precedes two copies of the old one" \
		eval '[ "$(uget firewall.@include[0].path)" = /etc/fw-unrelated.sh ] && [ "$(uget firewall.@include[1].path)" = /etc/fips/firewall.sh ] && [ "$(uget firewall.@include[2].path)" = /etc/fips/firewall.sh ]'; then
		drop_released_files
		run_setup
		check "the setup exits 0" same "$RC" 0
		check "the unrelated include survives" same "$(uget firewall.@include[0].path)" /etc/fw-unrelated.sh
		check "no include names /etc/fips/firewall.sh" no_old_include
		check "only one include is left" eval '! uci -q get firewall.@include[1] >/dev/null'
	fi
	rm -f /etc/fw-unrelated.sh
	fw_end
}

fw_no_lan_zone_creates_zone_without_forwarding() {
	local how
	for how in fresh upgrade; do
		fw_begin fw_no_lan_zone_creates_zone_without_forwarding "with no lan zone ($how), the zone and rule are created and the missing forwarding is reported once"
		uci delete "firewall.$(zone_of lan)" && uci commit firewall || harness_fail "cannot delete the lan zone"
		if [ "$how" = upgrade ]; then
			released_state
			precond "upgrade: the 0.5.2 include is present" old_include || continue
			drop_released_files
		fi
		run_setup
		check "$how: the setup exits 0" same "$RC" 0
		check "$how: the fips zone is created" zone_made
		check "$how: the fips ping rule exists" ping_made
		check "$how: no forwarding is created" same "$(uget firewall.fips_lan)" ""
		check "$how: one line reports the missing lan zone" said_once 'no lan firewall zone'
		refute "$how: no second line about the forwarding" said 'has no forwarding from lan'
	done
	fw_end
}

fw_operator_scoping_renders_before_port_forwards() {
	fw_begin fw_operator_scoping_renders_before_port_forwards "an operator's src fips rules render ahead of the port-forward accept"
	run_setup
	uci set firewall.op_in=rule &&
		uci set firewall.op_in.name=Op-Scope-Input &&
		uci set firewall.op_in.src=fips &&
		uci set firewall.op_in.proto=tcp &&
		uci set firewall.op_in.dest_port=2222 &&
		uci set firewall.op_in.target=DROP &&
		uci set firewall.op_fwd=rule &&
		uci set firewall.op_fwd.name=Op-Scope-Forward &&
		uci set firewall.op_fwd.src=fips &&
		uci set firewall.op_fwd.dest=lan &&
		uci set firewall.op_fwd.proto=tcp &&
		uci set firewall.op_fwd.dest_port=2222 &&
		uci set firewall.op_fwd.target=DROP &&
		uci commit firewall || harness_fail "cannot add the scoping rules"
	/etc/init.d/firewall reload >/dev/null 2>&1
	check "input_fips: operator rule before the port-forward accept" before input_fips 'Op-Scope-Input' 'ct status dnat accept'
	check "input_fips: port-forward accept before the policy jump" before input_fips 'ct status dnat accept' 'jump reject_from_fips'
	check "forward_fips: operator rule before the port-forward accept" before forward_fips 'Op-Scope-Forward' 'ct status dnat accept'
	check "forward_fips: port-forward accept before the policy jump" before forward_fips 'ct status dnat accept' 'jump reject_to_fips'
	fw_end
}

# ── Sections that are not ours ──────────────────────────────────────────────

fw_bare_plus_device_does_not_hold_fips0() {
	fw_begin fw_bare_plus_device_does_not_hold_fips0 "a bare + device does not hold fips0; a foreign fips_ping section is kept"
	uci add firewall zone >/dev/null &&
		uci set firewall.@zone[-1].name=plus &&
		uci add_list firewall.@zone[-1].device=+ &&
		uci set firewall.@zone[-1].input=REJECT &&
		uci set firewall.fips_ping=forwarding &&
		uci set firewall.fips_ping.src=lan &&
		uci set firewall.fips_ping.dest=wan &&
		uci commit firewall || harness_fail "cannot add the sections"
	uci show firewall.fips_ping > "$WORK/ping.before"
	run_setup
	uci show firewall.fips_ping > "$WORK/ping.after"
	check "the setup exits 0" same "$RC" 0
	check "the fips zone is created" zone_made
	check "fips_ping keeps its type and options" cmp -s "$WORK/ping.before" "$WORK/ping.after"
	check "one line names fips_ping" said_once 'firewall section fips_ping exists'
	fw_end
}

fw_operator_fips_ping_rule_kept() {
	fw_begin fw_operator_fips_ping_rule_kept "an operator's rule named fips_ping is kept byte for byte"
	uci set firewall.fips_ping=rule &&
		uci set firewall.fips_ping.name=My-Ping &&
		uci set firewall.fips_ping.src=wan &&
		uci set firewall.fips_ping.proto=icmp &&
		uci add_list firewall.fips_ping.icmp_type=echo-reply &&
		uci set firewall.fips_ping.family=ipv6 &&
		uci set firewall.fips_ping.target=ACCEPT &&
		uci commit firewall || harness_fail "cannot add the operator's fips_ping"
	uci show firewall.fips_ping > "$WORK/ping.before"
	run_setup
	uci show firewall.fips_ping > "$WORK/ping.after"
	check "the setup exits 0" same "$RC" 0
	check "the fips zone is created" zone_made
	check "fips_ping keeps its type and options" cmp -s "$WORK/ping.before" "$WORK/ping.after"
	check "one line names fips_ping" said_once 'firewall section fips_ping exists'
	fw_end
}

# foreign_fips_zone <default input>: an anonymous zone named fips that does not
# hold fips0.
foreign_fips_zone() {
	uci set "firewall.@defaults[0].input=$1" &&
		uci add firewall zone >/dev/null &&
		uci set firewall.@zone[-1].name=fips &&
		uci set firewall.@zone[-1].input=REJECT &&
		uci commit firewall || harness_fail "cannot add the anonymous fips zone"
}

foreign_zone_ok() {
	check "the setup exits 0" same "$RC" 0
	check "no firewall.fips section" same "$(uget firewall.fips)" ""
	check "no fips_lan section" same "$(uget firewall.fips_lan)" ""
	check "no fips_ping section" same "$(uget firewall.fips_ping)" ""
	check "one line names the existing zone" said_once 'a firewall zone named fips already exists'
}

fw_foreign_fips_zone_not_doubled() {
	fw_begin fw_foreign_fips_zone_not_doubled "a zone named fips in another section stops the zone being created"
	foreign_fips_zone REJECT
	run_setup
	foreign_zone_ok
	refute "no exposure line under a REJECT default" said 'router services are reachable'
	fw_end
}

fw_foreign_fips_zone_under_accept_default_reported() {
	local v
	# fw4 reads a policy in any case and from any leading part of its name.
	for v in ACCEPT accept acc; do
		fw_begin fw_foreign_fips_zone_under_accept_default_reported "with no zone for fips0 and a default input of $v, the exposure is reported"
		foreign_fips_zone "$v"
		run_setup
		foreign_zone_ok
		check "default input $v: the exposure is reported" \
			said 'fips0 is in no firewall zone and the default input policy is ACCEPT, so router services are reachable from FIPS peers'
	done
	fw_end
}

# An operator's anonymous zone named fips holds fips0 at an upgrade from 0.5.2.
# It gets the packaged port-forward include, which fw4 places by chain name,
# but no forwarding from lan is created for it, so the upgrade names that.
fw_operator_zone_named_fips_without_lan_forwarding_is_named() {
	local fwd
	for fwd in none lan disabled; do
		fw_begin fw_operator_zone_named_fips_without_lan_forwarding_is_named "an operator's zone named fips holding fips0, forwarding from lan: $fwd"
		released_state
		uci add firewall zone >/dev/null &&
			uci set firewall.@zone[-1].name=fips &&
			uci add_list firewall.@zone[-1].device=fips0 &&
			uci set firewall.@zone[-1].input=REJECT &&
			uci set firewall.@zone[-1].output=ACCEPT &&
			uci set firewall.@zone[-1].forward=REJECT &&
			uci commit firewall || harness_fail "cannot add the anonymous fips zone"
		if [ "$fwd" != none ]; then
			uci add firewall forwarding >/dev/null &&
				uci set firewall.@forwarding[-1].src=lan &&
				uci set firewall.@forwarding[-1].dest=fips &&
				uci commit firewall || harness_fail "cannot add the lan to fips forwarding"
		fi
		if [ "$fwd" = disabled ]; then
			uci set firewall.@forwarding[-1].enabled=0 && uci commit firewall ||
				harness_fail "cannot disable the lan to fips forwarding"
		fi
		if precond "$fwd: the 0.5.2 accepts, lan jump and include are live" released_reached; then
			drop_released_files
			run_setup
			check "$fwd: the setup exits 0" same "$RC" 0
			check "$fwd: no firewall.fips section" same "$(uget firewall.fips)" ""
			check "$fwd: no fips_lan section" same "$(uget firewall.fips_lan)" ""
			check "$fwd: fips0 is no longer a lan device" lan_lacks_fips0
			check "$fwd: input jumps fips0 into the zone" has input 'iifname "fips0" jump input_fips'
			refute "$fwd: no line calls it not the fips zone" said 'not in the fips zone'
			if [ "$fwd" != lan ]; then
				check "$fwd: the missing lan forwarding is named" \
					said_once 'fips0 is in a firewall zone named fips that has no forwarding from lan'
			else
				refute "lan: no line about a missing lan forwarding" said 'has no forwarding from lan'
			fi
		fi
	done
	fw_end
}

fw_disabled_zone_does_not_hold_fips0() {
	local v
	# fw4's false values for a boolean option.
	for v in 0 off false no; do
		fw_begin fw_disabled_zone_does_not_hold_fips0 "a zone holding fips0 with enabled $v does not count"
		uci add firewall zone >/dev/null &&
			uci set firewall.@zone[-1].name=off &&
			uci add_list firewall.@zone[-1].device=fips0 &&
			uci set "firewall.@zone[-1].enabled=$v" &&
			uci commit firewall || harness_fail "cannot add the disabled zone"
		run_setup
		check "enabled $v: the setup exits 0" same "$RC" 0
		check "enabled $v: the fips zone is created" zone_made
		check "enabled $v: input jumps fips0 into the fips zone" has input 'iifname "fips0" jump input_fips'
	done
	fw_end
}

fw_disabled_fips_zone_under_accept_default_reported() {
	fw_begin fw_disabled_fips_zone_under_accept_default_reported "an upgrade onto a disabled fips zone under an ACCEPT default migrates and reports the exposure"
	released_state
	uci set firewall.fips=zone &&
		uci set firewall.fips.name=fips &&
		uci add_list firewall.fips.device=fips0 &&
		uci set firewall.fips.input=REJECT &&
		uci set firewall.fips.enabled=0 &&
		uci set firewall.@defaults[0].input=ACCEPT &&
		uci commit firewall || harness_fail "cannot add the disabled fips zone"
	uci show firewall.fips > "$WORK/fips.before"
	if precond "the 0.5.2 accepts, lan jump and include are live" released_reached; then
		drop_released_files
		run_setup
		uci show firewall.fips > "$WORK/fips.after"
		check "the setup exits 0" same "$RC" 0
		check "no include names /etc/fips/firewall.sh" no_old_include
		check "fips0 is no longer a lan device" lan_lacks_fips0
		check "firewall.fips is unchanged" cmp -s "$WORK/fips.before" "$WORK/fips.after"
		check "no new zone named fips" eval '[ "$(uci -q show firewall | grep -c "\.name=.fips.$")" = 1 ]'
		check "the exposure is reported" \
			said 'fips0 is in no firewall zone and the default input policy is ACCEPT, so router services are reachable from FIPS peers'
	fi
	fw_end
}

fw_downgrade_then_upgrade_migrates_again() {
	fw_begin fw_downgrade_then_upgrade_migrates_again "after a downgrade put fips0 back in lan, an upgrade migrates again"
	run_setup
	uci show firewall.fips > "$WORK/sections.before"
	uci show firewall.fips_lan >> "$WORK/sections.before"
	uci show firewall.fips_ping >> "$WORK/sections.before"
	released_state
	if precond "fips0 is a lan device again, the include is back, and the lan jump precedes the fips jump" \
		eval 'lan_device fips0 && old_include && before input "jump input_lan" "jump input_fips" && lan_jump input input_lan'; then
		drop_released_files
		run_setup
		uci show firewall.fips > "$WORK/sections.after"
		uci show firewall.fips_lan >> "$WORK/sections.after"
		uci show firewall.fips_ping >> "$WORK/sections.after"
		check "the setup exits 0" same "$RC" 0
		check "fips0 is no longer a lan device" lan_lacks_fips0
		check "no include names /etc/fips/firewall.sh" no_old_include
		check "the zone, forwarding and rule are as before the downgrade" cmp -s "$WORK/sections.before" "$WORK/sections.after"
		check "base chains name fips0 only in the fips zone jumps" only_zone_jumps
		check "exactly one firewall reload" one_reload
		refute "no line calls the fips zone another zone" said 'not in the fips zone'
		refute "no line about a missing lan forwarding" said 'has no forwarding from lan'
	fi
	fw_end
}

# The operator renamed the fips zone, which fw4 then renders as input_mesh0,
# and a downgrade put fips0 back in lan: the upgrade checks the load by the
# zone's own name.
fw_renamed_fips_zone_is_checked_by_its_name() {
	fw_begin fw_renamed_fips_zone_is_checked_by_its_name "an upgrade onto the fips zone renamed mesh0 loads cleanly and is taken as loaded"
	run_setup
	# The setup under test creates the zone, so a missing one is a red result.
	if precond "the first run created the fips zone" eval '[ "$(uget firewall.fips)" = zone ]'; then
		uci set firewall.fips.name=mesh0 && uci commit firewall || harness_fail "cannot rename the fips zone"
		/etc/init.d/firewall reload >/dev/null 2>&1
		released_state
	fi
	if [ "$(uget firewall.fips.name)" = mesh0 ] &&
		precond "fips0 is a lan device again, the include is back, and input jumps to input_mesh0" \
			eval 'lan_device fips0 && old_include && has input "jump input_mesh0 "'; then
		drop_released_files
		run_setup
		check "the setup exits 0" same "$RC" 0
		check "exactly one firewall reload" one_reload
		check "fips0 is no longer a lan device" lan_lacks_fips0
		check "input jumps fips0 into the renamed zone" has input 'iifname "fips0" jump input_mesh0 '
		refute "no could-not-be-checked warning" said 'could not be checked'
		refute "no reload-failure warning" said 'firewall reload failed'
		check "no failsafe or probe rule" no_reload_rules
	fi
	fw_end
}

# ── No firewall running ─────────────────────────────────────────────────────

migrated() {
	check "fips0 is no longer a lan device" lan_lacks_fips0
	check "no include names /etc/fips/firewall.sh" no_old_include
	check "the fips zone is created" zone_made
}

fw_no_firewall_migrates_without_reload() {
	fw_begin fw_no_firewall_migrates_without_reload "with neither state file nor table, as at boot, the setup migrates and does not reload"
	released_state
	fw4 -q flush >/dev/null 2>&1
	if precond "fips0 in lan, the include present, and neither state file nor table" \
		eval 'lan_device fips0 && old_include && [ ! -e /var/run/fw4.state ] && ! nft list table inet fw4 >/dev/null 2>&1'; then
		run_setup
		check "the setup exits 0" same "$RC" 0
		migrated
		check "no reload is attempted" no_reload
	fi
	fw_end
}

fw_sysupgrade_first_boot_migrates() {
	fw_begin fw_sysupgrade_first_boot_migrates "the first boot after a sysupgrade migrates and removes the kept firewall.sh"
	released_state
	rm -f /etc/hotplug.d/net/99-fips
	fw4 -q flush >/dev/null 2>&1
	if precond "firewall.sh kept, 99-fips absent, no state file, fips0 in lan" \
		eval '[ -f /etc/fips/firewall.sh ] && [ ! -e /etc/hotplug.d/net/99-fips ] && [ ! -e /var/run/fw4.state ] && lan_device fips0'; then
		run_setup sourced
		check "the setup exits 0" same "$RC" 0
		migrated
		check "no reload is attempted" no_reload
		check "/etc/fips/firewall.sh is gone" eval '[ ! -e /etc/fips/firewall.sh ]'
	fi
	fw_end
}

fw_missing_state_file_blocks_fips0() {
	fw_begin fw_missing_state_file_blocks_fips0 "a loaded table without fw4's state file fails the reload, so fips0 is closed"
	released_state
	rm -f /var/run/fw4.state
	if precond "the 0.5.2 state is live, the table lists and the state file is absent" \
		eval 'released_reached && [ ! -e /var/run/fw4.state ]'; then
		drop_released_files
		run_setup
		check "the setup exits 0" same "$RC" 0
		check "exactly one firewall reload" one_reload
		check "the missing state file is reported" said "the firewall reload failed because fw4's state file is missing"
		check "input: the failsafe pair precedes the lan jump naming fips0" pair_heads input input_lan
		check "forward: the failsafe pair precedes the lan jump naming fips0" pair_heads forward forward_lan
		check "no old accept in any chain" no_old_accepts
	fi
	fw_end
}

# fw4 can load the new configuration, but no table was loaded to put the probe
# in, so the load is judged by the jump into the fips zone alone.
fw_reload_without_prior_table_is_judged_by_the_zone_jump() {
	fw_begin fw_reload_without_prior_table_is_judged_by_the_zone_jump "with the state file present and no table loaded, a clean reload is taken as loaded"
	released_state
	if precond "the 0.5.2 accepts, lan jump and include are live" released_reached; then
		nft delete table inet fw4 >/dev/null 2>&1
		if precond "the state file exists and inet fw4 is not loaded" \
			eval '[ -e /var/run/fw4.state ] && ! nft list table inet fw4 >/dev/null 2>&1'; then
			drop_released_files
			run_setup
			upgrade_ok
		fi
	fi
	fw_end
}

fw_unloaded_firewall_is_reported() {
	fw_begin fw_unloaded_firewall_is_reported "a state file with no table loaded is reported" nostart
	echo 'this is not nft;' > /etc/nftables.d/zz-invalid.nft
	fw4 -q start >/dev/null 2>&1
	if precond "the state file exists and inet fw4 is not loaded" \
		eval '[ -e /var/run/fw4.state ] && ! nft list table inet fw4 >/dev/null 2>&1'; then
		run_setup
		check "the setup exits 0" same "$RC" 0
		check "the fips zone is created" zone_made
		check "the unloaded firewall is reported" said 'fw4 firewall is not loaded, so its zones do not filter'
	fi
	fw_end
}

# ── A reload that fails ─────────────────────────────────────────────────────

failed_reload_ok() {
	check "the setup exits 0" same "$RC" 0
	migrated
	check "the failed reload is reported" \
		said 'the firewall reload failed, so new connections from FIPS peers to this router and all fips-gateway port forwards are blocked'
	check "input: the failsafe pair precedes the lan jump naming fips0" pair_heads input input_lan
	check "forward: the failsafe pair precedes the lan jump naming fips0" pair_heads forward forward_lan
	check "no old accept in any chain" no_old_accepts
	check "no probe rule" table_lacks fips-reload-probe
}

failed_reload_start() {
	released_state
	precond "the 0.5.2 accepts, lan jump and include are live" released_reached || return 1
	drop_released_files
	echo 'this is not nft;' > /etc/nftables.d/zz-invalid.nft
	precond "fw4 check fails on the invalid include" eval '! fw4 check >/dev/null 2>&1'
}

fw_failed_reload_blocks_new_fips0_connections() {
	fw_begin fw_failed_reload_blocks_new_fips0_connections "a reload that fails to load closes fips0 in the old ruleset"
	if failed_reload_start; then
		run_setup
		failed_reload_ok
	fi
	fw_end
}

fw_failed_reload_under_apk_environment_blocks_fips0() {
	fw_begin fw_failed_reload_under_apk_environment_blocks_fips0 "the same failed reload with apk-tools' PATH-only environment"
	if failed_reload_start; then
		run_setup apk
		failed_reload_ok
	fi
	fw_end
}

# Continues from fw_failed_reload_blocks_new_fips0_connections, without a reset.
fw_recovery_after_failed_reload_clears_block() {
	CUR=fw_recovery_after_failed_reload_clears_block
	note "$CUR: once the invalid include is gone, a reload clears the block"
	if precond "the failed reload left one failsafe pair in input and in forward" \
		eval 'pair_once input && pair_once forward'; then
		rm -f /etc/nftables.d/zz-invalid.nft
		/etc/init.d/firewall reload >/dev/null 2>&1
		check "no failsafe rule" table_lacks fips-reload-failed
		check "base chains name fips0 only in the fips zone jumps" only_zone_jumps
	fi
	fw_end
}

# ── A save that fails ───────────────────────────────────────────────────────

# commit_fails_start [drop]: the 0.5.2 state, then the setup run as the
# postinst runs it, with every commit firewall failing. drop removes the old
# files first, as a package upgrade does.
commit_fails_start() {
	released_state
	precond "the 0.5.2 accepts, lan jump and include are live" released_reached || return 1
	[ "${1:-}" = drop ] && drop_released_files
	cp /etc/config/firewall "$WORK/firewall.before"
	wrap_uci_commit_fails
	run_postinst wrap
	precond "the uci wrapper failed a commit firewall" wrap_called uci 'commit firewall'
}

commit_fails_ok() {
	check "the setup exits 1" same "$RC" 1
	check "the setup is kept in /etc/uci-defaults" eval '[ -f /etc/uci-defaults/90-fips-setup ]'
	check "/etc/config/firewall is unchanged" cmp -s "$WORK/firewall.before" /etc/config/firewall
	check "no reload is attempted" no_reload
	check "the failed save is reported" \
		said 'the firewall configuration could not be saved, so fips0 may still be in the lan zone; new connections'
	check "input: the failsafe pair precedes the lan jump naming fips0" pair_heads input input_lan
	check "forward: the failsafe pair precedes the lan jump naming fips0" pair_heads forward forward_lan
	check "no old accept in any chain" no_old_accepts
}

fw_failed_commit_blocks_and_keeps_setup() {
	fw_begin fw_failed_commit_blocks_and_keeps_setup "a failed save closes fips0 and keeps the setup for the next boot"
	if commit_fails_start drop; then
		commit_fails_ok
	fi
	fw_end
}

# Continues from fw_failed_commit_blocks_and_keeps_setup: the second run an
# SDK-feed install makes, with the save still failing.
fw_second_sdk_run_after_failed_commit_keeps_one_block() {
	CUR=fw_second_sdk_run_after_failed_commit_keeps_one_block
	note "$CUR: a second run in the same install retries the save and stacks no second failsafe"
	if precond "the first run's changes are still staged" eval '[ -n "$(uci -q changes firewall)" ]'; then
		: > "$RELOADLOG"
		PATH="$WRAP:$PATH" sh -c '( cd /etc/uci-defaults && . ./90-fips-setup ) && rm -f /etc/uci-defaults/90-fips-setup' > "$OUT" 2>&1
		RC=$?
		sed 's/^/    | /' "$OUT"
		check "the run ends non-zero" eval '[ "$RC" != 0 ]'
		check "the setup is still kept" eval '[ -f /etc/uci-defaults/90-fips-setup ]'
		check "the save was tried again" eval '[ "$(grep -cx "commit firewall" /tmp/fw-wrap/uci.log)" = 2 ]'
		check "the failed save is reported" said 'the firewall configuration could not be saved'
		check "input holds one failsafe pair" pair_once input
		check "forward holds one failsafe pair" pair_once forward
		check "input: the failsafe pair precedes the lan jump naming fips0" pair_heads input input_lan
		check "forward: the failsafe pair precedes the lan jump naming fips0" pair_heads forward forward_lan
	fi
	fw_end
}

# Continues from fw_second_sdk_run_after_failed_commit_keeps_one_block: the
# next boot, when the save works.
fw_boot_retry_after_failed_commit_migrates() {
	CUR=fw_boot_retry_after_failed_commit_migrates
	note "$CUR: at the next boot the kept setup migrates, then the firewall starts clean"
	rm -rf "$WRAP"
	mkdir -p "$WRAP"
	fw4 -q flush >/dev/null 2>&1
	rm -rf /tmp/.uci
	run_boot
	check "the run exits 0" same "$RC" 0
	check "the setup is removed" eval '[ ! -e /etc/uci-defaults/90-fips-setup ]'
	check "no copy of the staged configuration is left in /tmp" eval '[ ! -e "$COPY" ]'
	migrated
	check "no reload is attempted" no_reload
	fw4 -q start >/dev/null 2>&1
	check "after the start, base chains name fips0 only in the fips zone jumps" only_zone_jumps
	check "no failsafe rule" table_lacks fips-reload-failed
	fw_end
}

fw_failed_commit_removes_leftover_files() {
	fw_begin fw_failed_commit_removes_leftover_files "a failed save still removes the old files, so no hotplug re-runs firewall.sh"
	if commit_fails_start; then
		commit_fails_ok
		check "/etc/fips/firewall.sh is gone" eval '[ ! -e /etc/fips/firewall.sh ]'
		check "/etc/hotplug.d/net/99-fips is gone" eval '[ ! -e /etc/hotplug.d/net/99-fips ]'
	fi
	fw_end
}

# The first run's failed save leaves input with only the drop of the failsafe
# pair, because the accept could not be inserted; the second run an SDK-feed
# install makes must complete the pair, or replies to the router's own
# connections over fips0 stay dropped.
fw_second_run_completes_a_half_failsafe_pair() {
	fw_begin fw_second_run_completes_a_half_failsafe_pair "a second run after a failed save completes a failsafe pair the first run left half inserted"
	wrap_nft_fails 'insert rule inet fw4 input iifname fips0 ct state established,related accept comment "fips-reload-failed"'
	if commit_fails_start drop &&
		precond "the nft wrapper failed the input accept" \
			wrap_called nft 'insert rule inet fw4 input iifname fips0 ct state established,related accept comment "fips-reload-failed"' &&
		precond "input holds the drop and not the accept" eval 'has input "$DROPPAIR" && lacks input "$ACCEPTPAIR"'; then
		rm -f "$WRAP/nft"
		: > "$RELOADLOG"
		PATH="$WRAP:$PATH" sh -c '( cd /etc/uci-defaults && . ./90-fips-setup ) && rm -f /etc/uci-defaults/90-fips-setup' > "$OUT" 2>&1
		RC=$?
		sed 's/^/    | /' "$OUT"
		check "the second run ends non-zero" eval '[ "$RC" != 0 ]'
		check "the block is reported" \
			said 'the firewall configuration could not be saved, so fips0 may still be in the lan zone; new connections'
		check "input holds one failsafe pair" pair_once input
		check "forward holds one failsafe pair" pair_once forward
		check "input: the failsafe pair precedes the lan jump naming fips0" pair_heads input input_lan
		check "forward: the failsafe pair precedes the lan jump naming fips0" pair_heads forward forward_lan
	fi
	fw_end
}

# ── A save onto a full overlay ──────────────────────────────────────────────
# uci commit exits 0 there, after replacing the file with as much of the new
# configuration as fitted and dropping the staged changes.

DAMAGED='the firewall configuration could not be saved and /etc/config/firewall was left damaged, which the next firewall reload or reboot loads; new connections'

# full_save_start <free pages> [pad]: the 0.5.2 state with /etc/config on the
# small tmpfs, pad adding rules until the configuration spans several pages,
# then the setup run as the postinst runs it with only <free pages> free.
full_save_start() {
	local i=0 max=$(($1 * 4096))
	small_config
	if [ "${2:-}" = pad ]; then
		while [ "$i" -lt 40 ]; do
			uci add firewall rule >/dev/null &&
				uci set "firewall.@rule[-1].name=Pad-$i-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" &&
				uci set firewall.@rule[-1].src=wan &&
				uci set firewall.@rule[-1].target=DROP &&
				uci set firewall.@rule[-1].enabled=0 || harness_fail "cannot add the padding rules"
			i=$((i + 1))
		done
		uci commit firewall || harness_fail "cannot commit the padding rules"
	fi
	released_state
	precond "the 0.5.2 accepts, lan jump and include are live" released_reached || return 1
	drop_released_files
	precond "the small tmpfs has $1 page(s) free" small_free "$1" || return 1
	run_postinst
	precond "the save left /etc/config/firewall cut short" \
		eval '[ "$(wc -c < /etc/config/firewall)" -le "$max" ] && [ -z "$(uci -q changes firewall)" ]'
}

full_save_ok() {
	check "the setup exits 1" same "$RC" 1
	check "the setup is kept in /etc/uci-defaults" eval '[ -f /etc/uci-defaults/90-fips-setup ]'
	check "no reload is attempted" no_reload
	check "the damaged save is reported" said "$DAMAGED"
	check "the warning names the copy to import" said "uci import firewall < $COPY"
	check "input: the failsafe pair precedes the lan jump naming fips0" pair_heads input input_lan
	check "forward: the failsafe pair precedes the lan jump naming fips0" pair_heads forward forward_lan
	check "no old accept in any chain" no_old_accepts
	check "the copy holds the fips zone" grep -qF "config zone 'fips'" "$COPY"
}

fw_full_overlay_save_blocks_and_keeps_setup() {
	fw_begin fw_full_overlay_save_blocks_and_keeps_setup "a save onto a full overlay that empties the file closes fips0, keeps the setup, and the copy restores it"
	if full_save_start 0; then
		full_save_ok
		rm -f "$SMALL/fill"
		uci import firewall < "$COPY" && /etc/init.d/firewall reload >/dev/null 2>&1
		check "after the import and a reload: the fips zone is live" zone_made
		check "after the import and a reload: fips0 is no longer a lan device" lan_lacks_fips0
		check "after the import and a reload: base chains name fips0 only in the fips zone jumps" only_zone_jumps
		check "after the import and a reload: no failsafe rule" table_lacks fips-reload-failed
		run_boot
		check "the boot run exits 0" same "$RC" 0
		check "the boot run removes the setup" eval '[ ! -e /etc/uci-defaults/90-fips-setup ]'
	fi
	fw_end
}

fw_partial_save_blocks_and_keeps_setup() {
	fw_begin fw_partial_save_blocks_and_keeps_setup "a save onto an overlay with one page free cuts the file short; fips0 is closed and the setup kept"
	if full_save_start 1 pad; then
		full_save_ok
	fi
	fw_end
}

# ── nft unavailable or failing ──────────────────────────────────────────────

fw_missing_nft_is_reported() {
	fw_begin fw_missing_nft_is_reported "with nft missing, the setup says the configuration cannot have loaded"
	released_state
	if precond "the 0.5.2 accepts, lan jump and include are live" released_reached; then
		drop_released_files
		mv /usr/sbin/nft /usr/sbin/nft.hidden || harness_fail "cannot hide nft"
		run_setup
		check "the setup exits 0" same "$RC" 0
		check "exactly one firewall reload" one_reload
		check "the missing nft is reported" \
			said 'nft was not found, so the new configuration cannot have loaded and fips0 could not be closed'
		check "the old accepts are still loaded" eval '/usr/sbin/nft.hidden list chain inet fw4 input 2>/dev/null | grep -qF "iifname \"fips0\" accept comment \"fips\""'
		check "the lan jump naming fips0 is still loaded" eval '/usr/sbin/nft.hidden list chain inet fw4 input 2>/dev/null | grep -F "\"fips0\"" | grep -qF "jump input_lan "'
	fi
	fw_end
}

# unchecked_ok: the reload loaded, but could not be confirmed.
unchecked_ok() {
	check "the setup exits 0" same "$RC" 0
	check "exactly one firewall reload" one_reload
	check "the unchecked reload is reported" said 'the firewall reload could not be checked, so new connections'
	check "input: the failsafe pair precedes the fips zone jump" pair_heads input input_fips
	check "forward: the failsafe pair precedes the fips zone jump" pair_heads forward forward_fips
}

fw_probe_add_failure_blocks_fips0() {
	fw_begin fw_probe_add_failure_blocks_fips0 "when the probe rule cannot be added, the setup fails closed"
	released_state
	if precond "the 0.5.2 accepts, lan jump and include are live" released_reached; then
		drop_released_files
		wrap_nft_fails 'add rule inet fw4 input counter comment "fips-reload-probe"'
		run_setup wrap
		precond "the nft wrapper failed the probe" wrap_called nft 'add rule inet fw4 input counter comment "fips-reload-probe"' &&
			unchecked_ok
	fi
	fw_end
}

# The probe cannot be added and fw4's state file is missing, so the reload dies
# and nothing it says can be checked; only a restart recovers.
fw_unchecked_reload_without_state_file_names_restart() {
	fw_begin fw_unchecked_reload_without_state_file_names_restart "an unchecked reload with fw4's state file missing names the restart"
	released_state
	rm -f /var/run/fw4.state
	if precond "the 0.5.2 state is live and the state file is absent" \
		eval 'released_reached && [ ! -e /var/run/fw4.state ]'; then
		drop_released_files
		wrap_nft_fails 'add rule inet fw4 input counter comment "fips-reload-probe"'
		run_setup wrap
		if precond "the nft wrapper failed the probe" wrap_called nft 'add rule inet fw4 input counter comment "fips-reload-probe"'; then
			check "the setup exits 0" same "$RC" 0
			check "exactly one firewall reload" one_reload
			check "the unchecked reload and missing state file are reported" \
				said "the firewall reload could not be checked and fw4's state file is missing, so new connections"
			check "the remedy is a restart" said "run '/etc/init.d/firewall restart'"
			refute "no reload remedy" said "run '/etc/init.d/firewall reload' to clear the block"
			check "input: the failsafe pair precedes the lan jump naming fips0" pair_heads input input_lan
			check "forward: the failsafe pair precedes the lan jump naming fips0" pair_heads forward forward_lan
		fi
	fi
	fw_end
}

fw_listing_failure_blocks_fips0() {
	fw_begin fw_listing_failure_blocks_fips0 "when the input chain cannot be listed after the reload, the setup fails closed"
	released_state
	if precond "the 0.5.2 accepts, lan jump and include are live" released_reached; then
		drop_released_files
		wrap_nft_fails 'list chain inet fw4 input'
		run_setup wrap
		precond "the nft wrapper failed the listing" wrap_called nft 'list chain inet fw4 input' &&
			unchecked_ok
	fi
	fw_end
}

fw_flush_only_load_blocks_fips0() {
	fw_begin fw_flush_only_load_blocks_fips0 "a load that only flushed the table is not taken for success"
	released_state
	if precond "the 0.5.2 accepts, lan jump and include are live" released_reached; then
		drop_released_files
		: > "$FLUSHONLY"
		run_setup
		if precond "the flush left the input chain listed with no rules" \
			eval 'grep -qF "chain input" "$FLUSHLIST" && ! grep -qE "jump|accept comment|drop comment|counter|fips-reload-probe" "$FLUSHLIST"'; then
			check "the setup exits 0" same "$RC" 0
			check "exactly one firewall reload" one_reload
			check "the unchecked reload is reported" said 'the firewall reload could not be checked, so new connections'
			check "input holds the failsafe pair and nothing else naming fips0" pair_only input
			check "forward holds the failsafe pair and nothing else naming fips0" pair_only forward
		fi
	fi
	fw_end
}

# ── The 802.11s mesh zone ───────────────────────────────────────────────────
# fips-mesh-setup puts the mesh interfaces it creates in the fips_mesh zone,
# and 90-fips-setup adds those made by earlier packages to it.

MESHDROP='drop comment "fips-mesh-reload-failed"'

# mesh_begin <name> <what it shows> [nostart]: reset, start fw4, and give the
# container two radios, an empty network configuration and the wifi stub.
mesh_begin() {
	fw_begin "$@"
	touch /etc/config/network
	cat > /etc/config/wireless <<'EOF'
config wifi-device 'radio0'
	option type 'mac80211'
	option channel '36'
	option band '5g'

config wifi-device 'radio1'
	option type 'mac80211'
	option channel '1'
	option band '2g'
EOF
	mkdir -p "$STUB" && printf '#!/bin/sh\necho "wifi $*" >> %s\n' "$RELOADLOG" > "$STUB/wifi" &&
		chmod 0755 "$STUB/wifi" || harness_fail "cannot install the wifi stub"
}

# run_mesh [wrap] <args>: run the mesh helper under test, keeping its output in
# $OUT and its status in RC. wrap puts the uci and nft wrappers first.
run_mesh() {
	local p="$STUB:$PATH"
	if [ "${1:-}" = wrap ]; then
		p="$STUB:$WRAP:$PATH"
		shift
	fi
	: > "$RELOADLOG"
	PATH="$p" sh "$FW_MESH_SETUP" "$@" > "$OUT" 2>&1
	RC=$?
	sed 's/^/    | /' "$OUT"
	return 0
}

# The helper as 0.5.2 shipped it, which put the interface in no zone.
run_released_mesh() {
	PATH="$STUB:$PATH" sh "$FIXTURES/released-fips-mesh-setup" "$@" >/dev/null 2>&1
}

# Install the helper under test where 90-fips-setup looks for it.
mesh_install() {
	cp "$FW_MESH_SETUP" /usr/bin/fips-mesh-setup && chmod 0755 /usr/bin/fips-mesh-setup ||
		harness_fail "cannot install the mesh helper"
}

# The hooks' PATH finds the wifi stub, so a wifi reload they make is logged.
stub_first() { [ "$(PATH="$(hook_path)" sh -c 'command -v wifi')" = "$STUB/wifi" ]; }

# In input, forward and output, a rule naming <dev> jumps to the chain of
# zone <zone>, fips_mesh unless given.
mesh_jumps() {
	local c dir z="${2:-fips_mesh}"
	for c in input forward output; do
		dir=iifname
		[ "$c" = output ] && dir=oifname
		listing "$c" || return 1
		printf '%s\n' "$LIST" | grep -F "\"$1\"" | grep -F "$dir " | grep -qF "jump ${c}_$z " || return 1
	done
	return 0
}

# No rule names a mesh interface or jumps to a fips_mesh chain. The empty
# chains a reload leaves after the zone is deleted are allowed.
mesh_named_nowhere() {
	local t
	t="$(nft list table inet fw4 2>/dev/null)" || return 1
	! printf '%s\n' "$t" | grep -q '"fips-mesh[0-9]*"' &&
		! printf '%s\n' "$t" | grep -qE 'jump [A-Za-z_]*_fips_mesh( |$)'
}

# mesh_zone_made <device list>: the zone is exactly what the helper creates.
mesh_zone_made() {
	local want
	want="$(printf '%s\n' "=zone" ".name='fips_mesh'" ".input='REJECT'" ".output='ACCEPT'" \
		".forward='REJECT'" ".auto_helper='0'" ".device=$1")"
	[ "$(dump firewall.fips_mesh)" = "$want" ]
}

# The drop for <dev> is in <chain> once, and only failsafe rules precede it.
mesh_drop_heads() {
	local r n
	r="$(rules_of "$1" | grep -v '^type ')" || return 1
	[ "$(printf '%s\n' "$r" | grep -cxF "iifname \"$2\" $MESHDROP")" = 1 ] || return 1
	n="$(printf '%s\n' "$r" | grep -nxF "iifname \"$2\" $MESHDROP" | sed 's/:.*//')"
	[ "$(printf '%s\n' "$r" | sed -n "1,${n}p" | grep -vc 'reload-failed"$')" = 0 ]
}

mesh_failsafe() { mesh_drop_heads input "$1" && mesh_drop_heads forward "$1"; }

no_mesh_drop() { table_lacks fips-mesh-reload-failed; }

# The basic rates the helper gives every mesh interface.
RATES='6000 12000 24000'

# mesh_wireless_made <radio> <ifname>: the sections the helper makes.
mesh_wireless_made() {
	local s="fips_mesh_$1"
	[ "$(uget "wireless.$s")" = wifi-iface ] &&
		[ "$(uget "wireless.$s.device")" = "$1" ] &&
		[ "$(uget "wireless.$s.mode")" = mesh ] &&
		[ "$(uget "wireless.$s.encryption")" = none ] &&
		[ "$(uget "wireless.$s.mesh_fwding")" = 0 ] &&
		[ "$(uget "wireless.$s.basic_rate")" = "$RATES" ] &&
		[ "$(uget "wireless.$s.ifname")" = "$2" ] &&
		[ "$(uget "wireless.$s.network")" = "$s" ] &&
		[ "$(uget "network.$s")" = interface ] &&
		[ "$(uget "network.$s.proto")" = none ]
}

mesh_exports_save() {
	uci export wireless > "$WORK/wireless.before"
	uci export network > "$WORK/network.before"
}

mesh_exports_same() {
	uci export wireless > "$WORK/wireless.after"
	uci export network > "$WORK/network.after"
	cmp -s "$WORK/wireless.before" "$WORK/wireless.after" &&
		cmp -s "$WORK/network.before" "$WORK/network.after"
}

# Network is unchanged, and wireless is unchanged but for basic_rate lines
# with the helper's rates.
mesh_exports_same_but_rates() {
	uci export wireless | grep -vxF "	option basic_rate '$RATES'" > "$WORK/wireless.after"
	uci export network > "$WORK/network.after"
	cmp -s "$WORK/wireless.before" "$WORK/wireless.after" &&
		cmp -s "$WORK/network.before" "$WORK/network.after"
}

log_is() { [ "$(cat "$RELOADLOG" 2>/dev/null)" = "$1" ]; }

no_wifi() { [ -f "$RELOADLOG" ] && ! grep -q '^wifi' "$RELOADLOG"; }

# The log holds a wifi reload, and a firewall reload after it.
wifi_then_reload() {
	local w r
	w="$(grep -nx 'wifi reload' "$RELOADLOG" | sed -n '1s/:.*//p')"
	r="$(grep -nx reload "$RELOADLOG" | sed -n '$s/:.*//p')"
	[ -n "$w" ] && [ -n "$r" ] && [ "$w" -lt "$r" ]
}

ZONED='is in firewall zone fips_mesh, which rejects all IP input'
MESHCLOSED='closed to IP traffic until the firewall next reloads'

mesh_add_puts_interface_in_reject_zone() {
	mesh_begin mesh_add_puts_interface_in_reject_zone "adding a mesh puts its interface in the fips_mesh zone before the radio comes up"
	note "defaults input $(uget firewall.@defaults[0].input); loaded input chain $(nft list chain inet fw4 input 2>/dev/null | sed -n 's/.*\(policy [a-z]*\);.*/\1/p'); rules naming fips-mesh0: $(nft list chain inet fw4 input 2>/dev/null | grep -c '"fips-mesh0"')"
	run_mesh radio0
	check "the helper exits 0" same "$RC" 0
	check "the fips_mesh zone is REJECT/ACCEPT/REJECT on fips-mesh0 with auto_helper 0" mesh_zone_made "'fips-mesh0'"
	check "input, forward and output jump fips-mesh0 into the zone" mesh_jumps fips-mesh0
	check "input_fips_mesh only rejects" same "$(rules_of input_fips_mesh | grep -v '^type ')" 'jump reject_from_fips_mesh'
	check "forward_fips_mesh only rejects" same "$(rules_of forward_fips_mesh | grep -v '^type ')" 'jump reject_to_fips_mesh'
	if table_has 'jump helper_lan'; then
		check "no helper chain for the fips_mesh zone" table_lacks helper_fips_mesh
	else
		note "helper assertion not exercised on this host"
	fi
	check "the firewall reloads, then the radio" log_is "$(printf 'reload\nwifi reload')"
	check "the wireless and network sections are as before" mesh_wireless_made radio0 fips-mesh0
	check "the mesh interface has basic_rate '$RATES'" same "$(uget wireless.fips_mesh_radio0.basic_rate)" "$RATES"
	check "no failsafe rule" no_mesh_drop
	check "the closing message names the zone" said "fips-mesh0 $ZONED"
	check "the closing message says 22.03 and 23.05 ignore the rates" said 'and 23.05 ignore basic_rate on a mesh'
	fw_end
}

mesh_second_add_changes_nothing() {
	mesh_begin mesh_second_add_changes_nothing "adding the same mesh again changes no firewall configuration and does not reload"
	run_mesh radio0
	uci export firewall > "$WORK/first.uci"
	run_mesh radio0
	uci export firewall > "$WORK/second.uci"
	check "the second add exits 0" same "$RC" 0
	check "uci export firewall is byte-identical" cmp -s "$WORK/first.uci" "$WORK/second.uci"
	check "the second add does not reload the firewall" no_reload
	check "fips-mesh0 is in the zone" mesh_jumps fips-mesh0
	check "no failsafe rule" no_mesh_drop
	fw_end
}

mesh_two_radios_share_one_zone_and_remove_cleans_up() {
	mesh_begin mesh_two_radios_share_one_zone_and_remove_cleans_up "two radios share the zone; remove takes each out and the last deletes it"
	run_mesh radio0
	run_mesh radio1
	check "the zone lists both interfaces" same "$(uget firewall.fips_mesh.device)" "fips-mesh0 fips-mesh1"
	check "input sends both to the zone in one rule" \
		eval 'listing input && printf "%s\n" "$LIST" | grep -F "\"fips-mesh0\"" | grep -F "\"fips-mesh1\"" | grep -qF "jump input_fips_mesh "'
	run_mesh remove radio1
	check "remove radio1: the zone lists fips-mesh0" same "$(uget firewall.fips_mesh.device)" fips-mesh0
	check "remove radio1: no rule names fips-mesh1" table_lacks '"fips-mesh1"'
	check "remove radio1: fips-mesh0 is still in the zone" mesh_jumps fips-mesh0
	check "remove radio1: the radio reloads before the firewall" wifi_then_reload
	run_mesh remove
	check "remove: the helper exits 0" same "$RC" 0
	check "remove: no firewall.fips_mesh" same "$(uget firewall.fips_mesh)" ""
	check "remove: nothing loaded names a mesh interface or jumps to the zone" mesh_named_nowhere
	check "remove: no mesh section in wireless or network" \
		eval '! uci -q show wireless | grep -q fips_mesh_ && ! uci -q show network | grep -q fips_mesh_'
	fw_end
}

# mesh_veth_remove <deleted> [window]: the helper adds radio0, a veth stands in
# for its interface, and the wifi stub deletes it two seconds after the reload
# when <deleted> is 1. The stub logs the deletion just before making it, so a
# firewall reload logged after that line came after a two-second wait at
# least, and one that did not wait is logged before it. With window, the stub
# first reloads the firewall through fw4, not the logged init script, as
# OpenWrt's firewall hotplug script does when a zoned interface comes up
# during a radio reload, and writes to $WORK/window how many loaded rules then
# name fips-mesh0.
mesh_veth_remove() {
	run_mesh radio0
	ip link add fips-mesh0 type veth peer name fmpeer0 >/dev/null 2>&1
	if precond "ip is found and fips-mesh0 exists" eval 'command -v ip >/dev/null && [ -e /sys/class/net/fips-mesh0 ]'; then
		{
			echo '#!/bin/sh'
			echo "echo \"wifi \$*\" >> $RELOADLOG"
			[ "${2:-}" = window ] &&
				echo "fw4 -q reload >/dev/null 2>&1; nft list table inet fw4 | grep -c '\"fips-mesh0\"' > $WORK/window"
			[ "$1" = 1 ] &&
				echo "( sleep 2; echo 'gone fips-mesh0' >> $RELOADLOG; ip link del fips-mesh0 ) >/dev/null 2>&1 &"
		} > "$STUB/wifi"
		run_mesh remove
		return 0
	fi
	return 1
}

mesh_remove_waits_for_interface_before_reload() {
	mesh_begin mesh_remove_waits_for_interface_before_reload "remove reloads the firewall only once the interface is gone"
	if mesh_veth_remove 1; then
		check "remove exits 0" same "$RC" 0
		check "the radio reloads, the interface goes, then the firewall reloads" \
			log_is "$(printf 'wifi reload\ngone fips-mesh0\nreload')"
		refute "no still-present line" said 'is still present after the wifi reload'
	fi
	fw_end
}

mesh_remove_waits_for_interface_before_reload_and_reports_one_that_stays() {
	mesh_begin mesh_remove_waits_for_interface_before_reload_and_reports_one_that_stays "an interface still present after the wait is named, and the firewall reloads"
	if mesh_veth_remove 0; then
		check "remove exits 0" same "$RC" 0
		check "the line names fips-mesh0" said 'fips-mesh0 is still present after the wifi reload'
		check "the firewall reloads after the radio" log_is "$(printf 'wifi reload\nreload')"
	fi
	fw_end
}

mesh_remove_keeps_zone_until_interface_is_gone() {
	mesh_begin mesh_remove_keeps_zone_until_interface_is_gone "a firewall reload while the radio reloads leaves the interface in the zone"
	if mesh_veth_remove 1 window; then
		check "remove exits 0" same "$RC" 0
		check "the reload during the radio reload still loads rules naming fips-mesh0" \
			eval '[ "$(cat "$WORK/window" 2>/dev/null || echo 0)" -gt 0 ]'
		check "remove: no firewall.fips_mesh" same "$(uget firewall.fips_mesh)" ""
		check "remove: nothing loaded names a mesh interface or jumps to the zone" mesh_named_nowhere
	fi
	fw_end
}

mesh_add_then_remove_restores_firewall_config() {
	mesh_begin mesh_add_then_remove_restores_firewall_config "add then remove leaves the firewall configuration as it was, with the fips and fips_ap zones"
	run_setup
	uci set firewall.fips_ap=zone &&
		uci set firewall.fips_ap.name=fips_ap &&
		uci set firewall.fips_ap.input=REJECT &&
		uci set firewall.fips_ap.output=ACCEPT &&
		uci set firewall.fips_ap.forward=REJECT &&
		uci add_list firewall.fips_ap.network=fips_ap_radio1 &&
		uci set firewall.fips_ap_icmpv6=rule && uci set firewall.fips_ap_icmpv6.src=fips_ap &&
		uci set firewall.fips_ap_icmpv6.proto=icmp && uci set firewall.fips_ap_icmpv6.target=ACCEPT &&
		uci set firewall.fips_ap_dhcpv4=rule && uci set firewall.fips_ap_dhcpv4.src=fips_ap &&
		uci set firewall.fips_ap_dhcpv4.proto=udp && uci set firewall.fips_ap_dhcpv4.dest_port=67 &&
		uci set firewall.fips_ap_dhcpv4.target=ACCEPT &&
		uci set firewall.fips_ap_mdns=rule && uci set firewall.fips_ap_mdns.src=fips_ap &&
		uci set firewall.fips_ap_mdns.proto=udp && uci set firewall.fips_ap_mdns.dest_port=5353 &&
		uci set firewall.fips_ap_mdns.target=ACCEPT &&
		uci set firewall.fips_ap_fips_udp=rule && uci set firewall.fips_ap_fips_udp.src=fips_ap &&
		uci set firewall.fips_ap_fips_udp.proto=udp && uci set firewall.fips_ap_fips_udp.dest_port=2121 &&
		uci set firewall.fips_ap_fips_udp.target=ACCEPT &&
		uci set firewall.fips_ap_fips_tcp=rule && uci set firewall.fips_ap_fips_tcp.src=fips_ap &&
		uci set firewall.fips_ap_fips_tcp.proto=tcp && uci set firewall.fips_ap_fips_tcp.dest_port=8443 &&
		uci set firewall.fips_ap_fips_tcp.target=ACCEPT &&
		uci commit firewall || harness_fail "cannot add the fips_ap zone"
	/etc/init.d/firewall reload >/dev/null 2>&1
	uci export firewall > "$WORK/before.uci"
	run_mesh radio0
	run_mesh remove
	uci export firewall > "$WORK/after.uci"
	check "remove exits 0" same "$RC" 0
	check "uci export firewall is byte-identical to before the add" cmp -s "$WORK/before.uci" "$WORK/after.uci"
	check "fips0 is still in the fips zone" has input 'iifname "fips0" jump input_fips '
	fw_end
}

mesh_existing_zone_options_are_kept() {
	mesh_begin mesh_existing_zone_options_are_kept "an existing fips_mesh zone keeps its options; an ACCEPT input is reported"
	uci set firewall.fips_mesh=zone &&
		uci set firewall.fips_mesh.name=fips_mesh &&
		uci set firewall.fips_mesh.input=ACCEPT &&
		uci set firewall.fips_mesh.output=ACCEPT &&
		uci set firewall.fips_mesh.forward=REJECT &&
		uci add_list firewall.fips_mesh.device=op-dev0 &&
		uci commit firewall || harness_fail "cannot add the operator's fips_mesh zone"
	/etc/init.d/firewall reload >/dev/null 2>&1
	dump firewall.fips_mesh | sed "s/^\.device='op-dev0'\$/.device='op-dev0' 'fips-mesh0'/" > "$WORK/zone.want"
	run_mesh radio0
	dump firewall.fips_mesh > "$WORK/zone.after"
	check "the helper exits 0" same "$RC" 0
	check "the zone's options are unchanged but for fips-mesh0 appended" cmp -s "$WORK/zone.want" "$WORK/zone.after"
	check "one line reports the ACCEPT input" said_once 'has input policy ACCEPT, so router services are reachable from anyone in radio range'
	refute "the closing message does not say the zone rejects all input" said "$ZONED"
	run_mesh remove
	check "remove keeps the zone with the operator's device" same "$(uget firewall.fips_mesh.device)" op-dev0
	fw_end
}

mesh_remove_keeps_empty_zone_it_took_nothing_from() {
	mesh_begin mesh_remove_keeps_empty_zone_it_took_nothing_from "remove on a radio with no mesh leaves an empty fips_mesh zone alone"
	uci set firewall.fips_mesh=zone &&
		uci set firewall.fips_mesh.name=fips_mesh &&
		uci set firewall.fips_mesh.input=REJECT &&
		uci set firewall.fips_mesh.output=ACCEPT &&
		uci set firewall.fips_mesh.forward=REJECT &&
		uci set firewall.fips_mesh.log=1 &&
		uci commit firewall || harness_fail "cannot add the empty fips_mesh zone"
	/etc/init.d/firewall reload >/dev/null 2>&1
	uci export firewall > "$WORK/before.uci"
	run_mesh remove radio1
	uci export firewall > "$WORK/after.uci"
	check "remove exits 0" same "$RC" 0
	check "the zone is still there" same "$(uget firewall.fips_mesh)" zone
	check "uci export firewall is byte-identical to before" cmp -s "$WORK/before.uci" "$WORK/after.uci"
	check "no firewall reload" no_reload
	fw_end
}

mesh_disabled_zone_is_reported_not_failed() {
	mesh_begin mesh_disabled_zone_is_reported_not_failed "a disabled fips_mesh zone is reported as such, not as a failed reload"
	uci set firewall.fips_mesh=zone &&
		uci set firewall.fips_mesh.name=fips_mesh &&
		uci set firewall.fips_mesh.input=REJECT &&
		uci set firewall.fips_mesh.enabled=0 &&
		uci commit firewall || harness_fail "cannot add the disabled zone"
	run_mesh radio0
	check "the helper exits 0" same "$RC" 0
	check "the zone is still disabled" same "$(uget firewall.fips_mesh.enabled)" 0
	check "fips-mesh0 is listed" same "$(uget firewall.fips_mesh.device)" fips-mesh0
	check "the disabled zone is reported" said 'the fips_mesh firewall zone is disabled, so fips-mesh0 is in no firewall zone'
	refute "no reload-failure line" said 'firewall reload failed'
	check "no failsafe rule" no_mesh_drop
	check "the mesh is created" mesh_wireless_made radio0 fips-mesh0
	fw_end
}

mesh_renamed_zone_is_checked_by_its_name() {
	mesh_begin mesh_renamed_zone_is_checked_by_its_name "a fips_mesh zone named mesh is checked by that name"
	uci set firewall.fips_mesh=zone &&
		uci set firewall.fips_mesh.name=mesh &&
		uci set firewall.fips_mesh.input=REJECT &&
		uci set firewall.fips_mesh.output=ACCEPT &&
		uci set firewall.fips_mesh.forward=REJECT &&
		uci set firewall.fips_mesh.auto_helper=0 &&
		uci commit firewall || harness_fail "cannot add the renamed zone"
	/etc/init.d/firewall reload >/dev/null 2>&1
	run_mesh radio0
	check "the helper exits 0" same "$RC" 0
	check "fips-mesh0 is listed" same "$(uget firewall.fips_mesh.device)" fips-mesh0
	check "input sends fips-mesh0 to input_mesh" mesh_jumps fips-mesh0 mesh
	check "no failsafe rule" no_mesh_drop
	refute "no reload-failure line" said 'firewall reload failed'
	refute "no stays-in-zone line" said 'stays in that zone'
	run_mesh radio0
	check "second add: exits 0" same "$RC" 0
	check "second add: no firewall reload" no_reload
	refute "second add: no stays-in-zone line" said 'stays in that zone'
	fw_end
}

mesh_conflicting_firewall_section_is_refused() {
	local v
	for v in rule zone; do
		mesh_begin mesh_conflicting_firewall_section_is_refused "a fips_mesh section that is a $v the helper cannot use stops the add"
		if [ "$v" = rule ]; then
			uci set firewall.fips_mesh=rule &&
				uci set firewall.fips_mesh.src=lan &&
				uci set firewall.fips_mesh.target=ACCEPT &&
				uci commit firewall || harness_fail "cannot add the fips_mesh rule"
		else
			uci add firewall zone >/dev/null &&
				uci set firewall.@zone[-1].name=fips_mesh &&
				uci set firewall.@zone[-1].input=REJECT &&
				uci commit firewall || harness_fail "cannot add the anonymous fips_mesh zone"
		fi
		cp /etc/config/firewall "$WORK/firewall.before"
		run_mesh radio0
		check "$v: the helper exits 1" same "$RC" 1
		check "$v: /etc/config/firewall is unchanged" cmp -s "$WORK/firewall.before" /etc/config/firewall
		check "$v: no wireless section" same "$(uget wireless.fips_mesh_radio0)" ""
		check "$v: no reload of either kind" eval '[ -f "$RELOADLOG" ] && [ ! -s "$RELOADLOG" ]'
		if [ "$v" = rule ]; then
			check "rule: the line names the section" said 'firewall section fips_mesh exists and is not a zone'
		else
			check "zone: the line names the zone" said 'a firewall zone named fips_mesh already exists (firewall.cfg'
		fi
	done
	fw_end
}

mesh_conflicting_firewall_section_is_refused_unless_it_holds_the_interface() {
	mesh_begin mesh_conflicting_firewall_section_is_refused_unless_it_holds_the_interface "an anonymous zone named fips_mesh that holds the interface keeps it"
	uci add firewall zone >/dev/null &&
		uci set firewall.@zone[-1].name=fips_mesh &&
		uci set firewall.@zone[-1].input=REJECT &&
		uci set firewall.@zone[-1].output=ACCEPT &&
		uci set firewall.@zone[-1].forward=REJECT &&
		uci add_list firewall.@zone[-1].device=fips-mesh0 &&
		uci commit firewall || harness_fail "cannot add the anonymous fips_mesh zone"
	/etc/init.d/firewall reload >/dev/null 2>&1
	cp /etc/config/firewall "$WORK/firewall.before"
	run_mesh radio0
	check "the helper exits 0" same "$RC" 0
	check "no section firewall.fips_mesh" same "$(uget firewall.fips_mesh)" ""
	check "/etc/config/firewall is unchanged" cmp -s "$WORK/firewall.before" /etc/config/firewall
	check "no firewall reload" no_reload
	check "the line names the anonymous zone" said 'fips-mesh0 is in firewall zone fips_mesh (firewall.cfg'
	refute "no conflict line" said 'already exists'
	check "input sends fips-mesh0 to that zone" has input 'iifname "fips-mesh0" jump input_fips_mesh '
	check "the mesh is created" mesh_wireless_made radio0 fips-mesh0
	fw_end
}

mesh_failed_reload_start() {
	echo 'this is not nft;' > /etc/nftables.d/zz-invalid.nft
	precond "fw4 check fails on the invalid include" eval '! fw4 check >/dev/null 2>&1'
}

mesh_failed_reload_drops_mesh_input() {
	mesh_begin mesh_failed_reload_drops_mesh_input "a reload that fails to load drops IP traffic arriving on the mesh"
	if mesh_failed_reload_start; then
		run_mesh radio0
		check "the helper exits 0" same "$RC" 0
		check "the zone is in /etc/config/firewall" grep -qF "config zone 'fips_mesh'" /etc/config/firewall
		check "the drop heads input and forward" mesh_failsafe fips-mesh0
		check "the old ruleset is still loaded" lacks input 'jump input_fips_mesh'
		check "the failed reload is reported" said 'the firewall reload failed, so IP traffic arriving on fips-mesh0 is dropped'
		check "the mesh is created" mesh_wireless_made radio0 fips-mesh0
		run_mesh radio0
		check "second add: exits 0" same "$RC" 0
		check "second add: one firewall reload" one_reload
		check "second add: still one drop in each chain" mesh_failsafe fips-mesh0
		rm -f /etc/nftables.d/zz-invalid.nft
		/etc/init.d/firewall reload >/dev/null 2>&1
		check "after a clean reload: no failsafe rule" no_mesh_drop
		check "after a clean reload: fips-mesh0 is in the zone" mesh_jumps fips-mesh0
	fi
	fw_end
}

mesh_missing_state_file_names_restart() {
	mesh_begin mesh_missing_state_file_names_restart "a loaded table without fw4's state file drops mesh input and names the restart"
	rm -f /var/run/fw4.state
	if precond "the table is loaded and the state file is absent" \
		eval 'nft list table inet fw4 >/dev/null 2>&1 && [ ! -e /var/run/fw4.state ]'; then
		run_mesh radio0
		check "the helper exits 0" same "$RC" 0
		check "the drop heads input and forward" mesh_failsafe fips-mesh0
		check "the missing state file is reported" said "the firewall reload failed because fw4's state file is missing"
		check "the remedy is a restart" said "run '/etc/init.d/firewall restart'"
		refute "no fw4 check remedy" said "run 'fw4 check'"
		check "the mesh is created" mesh_wireless_made radio0 fips-mesh0
	fi
	fw_end
}

mesh_unloaded_firewall_is_reported() {
	mesh_begin mesh_unloaded_firewall_is_reported "with fw4 not running the zone is configured, not reloaded, and applies when it starts" nostart
	if precond "neither state file nor table" \
		eval '[ ! -e /var/run/fw4.state ] && ! nft list table inet fw4 >/dev/null 2>&1'; then
		run_mesh radio0
		check "the helper exits 0" same "$RC" 0
		check "the zone is configured" mesh_zone_made "'fips-mesh0'"
		check "no firewall reload" no_reload
		check "the unloaded firewall is reported" said 'firewall is not loaded'
		fw4 -q start >/dev/null 2>&1
		check "after fw4 starts: fips-mesh0 is in the zone" mesh_jumps fips-mesh0
	fi
	fw_end
}

mesh_state_file_without_table_is_reported() {
	mesh_begin mesh_state_file_without_table_is_reported "a state file with no table loaded is reported, and the mesh is created" nostart
	echo 'this is not nft;' > /etc/nftables.d/zz-invalid.nft
	fw4 -q start >/dev/null 2>&1
	if precond "the state file exists and inet fw4 is not loaded" \
		eval '[ -e /var/run/fw4.state ] && ! nft list table inet fw4 >/dev/null 2>&1'; then
		run_mesh radio0
		check "the helper exits 0" same "$RC" 0
		check "the zone is configured" mesh_zone_made "'fips-mesh0'"
		check "the unloaded firewall is reported" said 'firewall is not loaded'
		refute "no could-not-be-closed line" said 'could not be closed'
		check "the mesh is created" mesh_wireless_made radio0 fips-mesh0
		check "the radio is reloaded" grep -qx 'wifi reload' "$RELOADLOG"
	fi
	fw_end
}

# The 0.5.2 helper's two meshes, with no zone.
mesh_released_two() {
	run_released_mesh radio0
	run_released_mesh radio1
	mesh_exports_save
	precond "no fips_mesh section, nothing loaded names a mesh interface, and the hooks find the wifi stub" \
		eval '[ -z "$(uget firewall.fips_mesh)" ] && table_lacks fips-mesh && stub_first && [ "$(uget wireless.fips_mesh_radio1.ifname)" = fips-mesh1 ]'
}

mesh_upgrade_zones_existing_interfaces() {
	mesh_begin mesh_upgrade_zones_existing_interfaces "an upgrade adds the interfaces the 0.5.2 helper made to the zone"
	if mesh_released_two; then
		mesh_install
		run_postinst
		check "the setup exits 0 and is deleted" eval '[ "$RC" = 0 ] && [ ! -e /etc/uci-defaults/90-fips-setup ]'
		check "the zone holds both interfaces" mesh_zone_made "'fips-mesh0' 'fips-mesh1'"
		check "fips-mesh0 is in the zone" mesh_jumps fips-mesh0
		check "fips-mesh1 is in the zone" mesh_jumps fips-mesh1
		check "no failsafe rule" no_mesh_drop
		check "no wifi reload" no_wifi
		check "wireless and network are unchanged but for the basic rates" mesh_exports_same_but_rates
		check "the fips zone is made as in a fresh install" zone_made
	fi
	fw_end
}

mesh_second_upgrade_changes_nothing() {
	mesh_begin mesh_second_upgrade_changes_nothing "a later upgrade changes nothing and does not reload"
	if mesh_released_two; then
		mesh_install
		run_postinst
		if precond "the first upgrade zoned both interfaces" \
			eval 'mesh_zone_made "'"'fips-mesh0' 'fips-mesh1'"'" && mesh_jumps fips-mesh0 && mesh_jumps fips-mesh1'; then
			uci export firewall > "$WORK/first.uci"
			uci export wireless > "$WORK/first.wireless"
			run_postinst
			uci export firewall > "$WORK/second.uci"
			uci export wireless > "$WORK/second.wireless"
			check "uci export firewall is byte-identical" cmp -s "$WORK/first.uci" "$WORK/second.uci"
			check "uci export wireless is byte-identical" cmp -s "$WORK/first.wireless" "$WORK/second.wireless"
			check "no firewall reload" no_reload
			refute "no line about basic rates" said 'basic_rate'
		fi
	fi
	fw_end
}

mesh_first_boot_after_sysupgrade_zones_interfaces() {
	mesh_begin mesh_first_boot_after_sysupgrade_zones_interfaces "the first boot after a sysupgrade zones the mesh before the firewall starts" nostart
	run_released_mesh radio0
	if precond "no state file, no table, and the hook finds the wifi stub" \
		eval '[ ! -e /var/run/fw4.state ] && ! nft list table inet fw4 >/dev/null 2>&1 && stub_first'; then
		mesh_install
		cp "$FW_SETUP" /etc/uci-defaults/90-fips-setup || harness_fail "cannot install the setup"
		run_boot
		check "the run exits 0" same "$RC" 0
		check "the setup is removed" eval '[ ! -e /etc/uci-defaults/90-fips-setup ]'
		check "the zone is made" mesh_zone_made "'fips-mesh0'"
		check "no firewall reload" no_reload
		check "no wifi reload" no_wifi
		fw4 -q start >/dev/null 2>&1
		check "after fw4 starts: fips-mesh0 is in the zone" mesh_jumps fips-mesh0
	fi
	fw_end
}

# The 0.5.2 helper's two meshes after an upgrade, with the mesh zone deleted
# again, so only the mesh needs saving.
mesh_hook_unzoned() {
	if mesh_released_two; then
		mesh_install
		run_postinst
		# Absent when the setup under test makes no mesh zone.
		uci -q delete firewall.fips_mesh
		uci commit firewall || harness_fail "cannot delete the mesh zone"
		/etc/init.d/firewall reload >/dev/null 2>&1
		precond "the fips zone holds fips0 and no zone holds the mesh" \
			eval 'zone_made && table_lacks "\"fips-mesh0\"" && [ -z "$(uci -q changes firewall)" ]'
		return
	fi
	return 1
}

mesh_hook_failed_save_ok() {
	check "$1: the setup ends non-zero and is kept" eval '[ "$RC" != 0 ] && [ -f /etc/uci-defaults/90-fips-setup ]'
	check "$1: no firewall reload" no_reload
	check "$1: fips-mesh0 is dropped" mesh_failsafe fips-mesh0
	check "$1: fips-mesh1 is dropped" mesh_failsafe fips-mesh1
	check "$1: the failed save is reported" said 'the firewall configuration could not be saved'
	check "$1: the mesh interfaces are reported closed" said "$MESHCLOSED"
}

mesh_hook_failed_save_closes_and_keeps_setup() {
	local v
	for v in full commit; do
		mesh_begin mesh_hook_failed_save_closes_and_keeps_setup "an upgrade whose mesh save fails ($v) closes the mesh and keeps the setup"
		if mesh_hook_unzoned; then
			if [ "$v" = full ]; then
				small_config
				if precond "full: no mesh copy is left from before" eval '[ ! -e "$MCOPY" ]' &&
					precond "full: the small tmpfs has no page free" small_free 0; then
					run_postinst
					mesh_hook_failed_save_ok full
					check "full: the line names the copy to import" said "uci import firewall < $MCOPY"
					check "full: the copy holds the zone" grep -qF "config zone 'fips_mesh'" "$MCOPY"
					rm -f "$SMALL/fill"
					uci import firewall < "$MCOPY" 2>/dev/null
					/etc/init.d/firewall reload >/dev/null 2>&1
					check "full: after the import and a reload, fips-mesh0 is in the zone" mesh_jumps fips-mesh0
					check "full: after the import and a reload, fips-mesh1 is in the zone" mesh_jumps fips-mesh1
					check "full: after the import and a reload, no failsafe rule" no_mesh_drop
				fi
			else
				wrap_uci_commit_fails
				run_postinst wrap
				if precond "commit: the uci wrapper failed a commit firewall" wrap_called uci 'commit firewall'; then
					mesh_hook_failed_save_ok commit
				fi
			fi
		fi
	done
	fw_end
}

# Continues from mesh_hook_failed_save_closes_and_keeps_setup's last variant:
# the second run an SDK-feed install makes, with the save still failing.
mesh_second_sdk_run_after_failed_save_keeps_one_drop() {
	CUR=mesh_second_sdk_run_after_failed_save_keeps_one_drop
	note "$CUR: a second run retries the save and stacks no second drop"
	if precond "the mesh changes are still staged" eval '[ -n "$(uci -q changes firewall)" ]'; then
		: > "$RELOADLOG"
		PATH="$(hook_path wrap)" sh -c '( cd /etc/uci-defaults && . ./90-fips-setup ) && rm -f /etc/uci-defaults/90-fips-setup' > "$OUT" 2>&1
		RC=$?
		sed 's/^/    | /' "$OUT"
		check "the run ends non-zero and the setup is kept" eval '[ "$RC" != 0 ] && [ -f /etc/uci-defaults/90-fips-setup ]'
		check "the save was tried again" eval '[ "$(grep -cx "commit firewall" /tmp/fw-wrap/uci.log)" = 2 ]'
		check "no firewall reload" no_reload
		check "fips-mesh0 has one drop in each chain" mesh_failsafe fips-mesh0
		check "fips-mesh1 has one drop in each chain" mesh_failsafe fips-mesh1
		check "the mesh interfaces are reported closed" said "$MESHCLOSED"
	fi
	fw_end
}

mesh_hook_without_mesh_does_nothing() {
	mesh_begin mesh_hook_without_mesh_does_nothing "with no mesh the hook changes nothing and adds no reload"
	mesh_install
	run_postinst
	check "the setup exits 0" same "$RC" 0
	check "no fips_mesh section" same "$(uget firewall.fips_mesh)" ""
	check "one firewall reload, as a fresh install makes" one_reload
	refute "no line from the mesh helper" said 'fips-mesh-setup:'
	fw_end
}

mesh_hook_after_damaged_save_closes_without_reload() {
	local v
	for v in 1 0; do
		mesh_begin mesh_hook_after_damaged_save_closes_without_reload "when the fips zone's save leaves the file damaged ($v page free), the mesh is closed and nothing saved"
		run_released_mesh radio0
		uci export wireless > "$WORK/wireless.before"
		mesh_install
		if [ "$v" = 1 ]; then
			full_save_start 1 pad
		else
			full_save_start 0
		fi
		if [ "$?" = 0 ]; then
			check "$v: the setup exits 1 and is kept" eval '[ "$RC" = 1 ] && [ -f /etc/uci-defaults/90-fips-setup ]'
			check "$v: no firewall reload" no_reload
			check "$v: the mesh helper saved nothing" eval '! grep -q fips_mesh /etc/config/firewall'
			check "$v: fips-mesh0 is dropped" mesh_failsafe fips-mesh0
			check "$v: fips0's pair is in input" pair_once input
			check "$v: fips0's pair is in forward" pair_once forward
			check "$v: the damaged save is reported" said "$DAMAGED"
			check "$v: the mesh interface is reported closed" said "$MESHCLOSED"
			uci export wireless > "$WORK/wireless.after"
			check "$v: the wireless configuration is left alone" \
				eval 'cmp -s "$WORK/wireless.before" "$WORK/wireless.after" && [ -z "$(uci -q changes wireless)" ]'
			refute "$v: no line about basic rates" said 'basic_rate'
		fi
	done
	fw_end
}

mesh_interface_in_another_zone_is_left_there() {
	local v
	for v in device network hook; do
		mesh_begin mesh_interface_in_another_zone_is_left_there "an interface lan holds by $v is left in lan and reported"
		case "$v" in
		device | hook)
			[ "$v" = hook ] && run_released_mesh radio0
			uci add_list "firewall.$(zone_of lan).device=fips-mesh0" && uci commit firewall ||
				harness_fail "cannot add fips-mesh0 to lan"
			;;
		network)
			uci add_list "firewall.$(zone_of lan).network=fips_mesh_radio0" && uci commit firewall ||
				harness_fail "cannot add the mesh network to lan"
			;;
		esac
		/etc/init.d/firewall reload >/dev/null 2>&1
		if [ "$v" = hook ]; then
			mesh_install
			run_postinst
		else
			run_mesh radio0
		fi
		check "$v: exits 0" same "$RC" 0
		check "$v: no fips_mesh section" same "$(uget firewall.fips_mesh)" ""
		# The stock lan zone is an anonymous section, so the line names it too.
		check "$v: the line names lan" said 'fips-mesh0 is in firewall zone lan (firewall.'
		check "$v: the line names the exposure" \
			said 'whose input policy is ACCEPT, so router services are reachable from anyone in radio range of the mesh; it stays in that zone'
		check "$v: no failsafe rule" no_mesh_drop
		if [ "$v" != hook ]; then
			refute "$v: the closing message does not say fips_mesh rejects all input" said "$ZONED"
			check "$v: the mesh is created" mesh_wireless_made radio0 fips-mesh0
		fi
		[ "$v" = device ] && check "device: no firewall reload" no_reload
		if [ "$v" != network ]; then
			check "$v: input sends fips-mesh0 to lan" eval 'naming_dev input fips-mesh0 | grep -qF "jump input_lan "'
			check "$v: nothing jumps to input_fips_mesh" table_lacks 'jump input_fips_mesh'
		fi
	done
	fw_end
}

# The rules of <chain> naming <dev>.
naming_dev() {
	listing "$1" || return 1
	printf '%s\n' "$LIST" | grep -F "\"$2\""
}

mesh_add_failed_save_ok() {
	check "$1: the helper exits 1" same "$RC" 1
	check "$1: no reload of either kind" eval '[ -f "$RELOADLOG" ] && [ ! -s "$RELOADLOG" ]'
	check "$1: no wireless section" same "$(uget wireless.fips_mesh_radio0)" ""
	check "$1: /etc/config/wireless is unchanged" cmp -s "$WORK/wireless.conf" /etc/config/wireless
	check "$1: the line says the mesh was not created" said 'so the mesh was not created'
}

mesh_add_failed_save_does_not_create_mesh() {
	local v
	for v in full commit; do
		mesh_begin mesh_add_failed_save_does_not_create_mesh "an add whose save fails ($v) does not create the mesh"
		cp /etc/config/wireless "$WORK/wireless.conf"
		if [ "$v" = full ]; then
			small_config
			if precond "full: no mesh copy is left from before" eval '[ ! -e "$MCOPY" ]' &&
				precond "full: the small tmpfs has no page free" small_free 0; then
				run_mesh radio0
				mesh_add_failed_save_ok full
				check "full: the line names the copy to import" said "uci import firewall < $MCOPY"
			fi
		else
			wrap_uci_commit_fails
			run_mesh wrap radio0
			if precond "commit: the uci wrapper failed a commit firewall" wrap_called uci 'commit firewall'; then
				mesh_add_failed_save_ok commit
			fi
		fi
	done
	fw_end
}

# Continues from mesh_add_failed_save_does_not_create_mesh's last variant.
mesh_readd_after_failed_save_saves_staged_zone() {
	CUR=mesh_readd_after_failed_save_saves_staged_zone
	note "$CUR: an add after a failed save saves the zone left staged"
	rm -f "$WRAP/uci"
	if precond "the zone is staged, reads back as listed, and is not in the file" \
		eval '[ -n "$(uci -q changes firewall)" ] && [ "$(uget firewall.fips_mesh.device)" = fips-mesh0 ] && ! grep -q fips_mesh /etc/config/firewall'; then
		run_mesh radio0
		check "the helper exits 0" same "$RC" 0
		check "nothing is left staged" eval '[ -z "$(uci -q changes firewall)" ]'
		check "/etc/config/firewall holds the zone and fips-mesh0" \
			eval 'grep -qF "config zone '"'fips_mesh'"'" /etc/config/firewall && grep -qF "fips-mesh0" /etc/config/firewall'
		check "fips-mesh0 is in the zone" mesh_jumps fips-mesh0
		check "the firewall reloads, then the radio" log_is "$(printf 'reload\nwifi reload')"
		check "no failsafe rule" no_mesh_drop
	fi
	fw_end
}

mesh_add_failed_close_does_not_create_mesh() {
	mesh_begin mesh_add_failed_close_does_not_create_mesh "an add that cannot close the interface after a failed reload does not create the mesh"
	if mesh_failed_reload_start; then
		wrap_nft_fails 'insert rule inet fw4 input iifname fips-mesh0 drop comment "fips-mesh-reload-failed"'
		run_mesh wrap radio0
		if precond "the nft wrapper failed the insert" \
			wrap_called nft 'insert rule inet fw4 input iifname fips-mesh0 drop comment "fips-mesh-reload-failed"'; then
			check "the helper exits 1" same "$RC" 1
			check "no wifi reload" no_wifi
			check "no wireless section" same "$(uget wireless.fips_mesh_radio0)" ""
			check "the line says it could not be closed" said 'could not be closed'
		fi
	fi
	fw_end
}

mesh_readd_unnumbered_radio_moves_zone_entry() {
	mesh_begin mesh_readd_unnumbered_radio_moves_zone_entry "a re-add that renames the interface keeps the old name zoned until the rename"
	uci set wireless.radiox=wifi-device &&
		uci set wireless.radiox.type=mac80211 &&
		uci set wireless.radiox.channel=1 &&
		uci set wireless.radiox.band=2g &&
		uci commit wireless || harness_fail "cannot add radiox"
	run_mesh radiox
	if precond "the first add listed fips-mesh0" same "$(uget firewall.fips_mesh.device)" fips-mesh0; then
		run_mesh radiox
		check "the second add exits 0" same "$RC" 0
		check "the zone lists exactly fips-mesh1" same "$(uget firewall.fips_mesh.device)" fips-mesh1
		check "the file lists fips-mesh1 and not fips-mesh0" \
			eval 'grep -qF "fips-mesh1" /etc/config/firewall && ! grep -qF "fips-mesh0" /etc/config/firewall'
		check "the firewall reloads once, before the radio" log_is "$(printf 'reload\nwifi reload')"
		check "the loaded input still names both" \
			eval 'naming_dev input fips-mesh0 >/dev/null && naming_dev input fips-mesh1 >/dev/null'
		/etc/init.d/firewall reload >/dev/null 2>&1
		check "after a reload: fips-mesh1 is in the zone" mesh_jumps fips-mesh1
		check "after a reload: nothing names fips-mesh0" table_lacks '"fips-mesh0"'
	fi
	fw_end
}

mesh_hook_failed_reload_drops_mesh_input() {
	mesh_begin mesh_hook_failed_reload_drops_mesh_input "an upgrade whose reload fails drops IP traffic arriving on the mesh"
	if mesh_released_two && mesh_failed_reload_start; then
		mesh_install
		run_postinst
		check "the setup exits 0 and is deleted" eval '[ "$RC" = 0 ] && [ ! -e /etc/uci-defaults/90-fips-setup ]'
		check "fips-mesh0 is dropped" mesh_failsafe fips-mesh0
		check "fips-mesh1 is dropped" mesh_failsafe fips-mesh1
		check "fips0's pair is in input" pair_once input
		check "fips0's pair is in forward" pair_once forward
		check "the failed reload is reported" said 'the firewall reload failed, so IP traffic arriving on fips-mesh0 fips-mesh1 is dropped'
		check "no wifi reload" no_wifi
	fi
	fw_end
}

# ── The mesh's basic rates ──────────────────────────────────────────────────
# fips-mesh-setup gives each mesh interface basic_rate '6000 12000 24000', and
# 90-fips-setup gives it to those made by earlier packages, which set none.

# wrap_uci_commit_fails_for <config>: a uci wrapper whose commit of <config>
# fails.
wrap_uci_commit_fails_for() {
	cat > "$WRAP/uci" <<EOF
#!/bin/sh
echo "\$*" >> /tmp/fw-wrap/uci.log
[ "\$*" = "commit $1" ] && exit 1
exec /sbin/uci "\$@"
EOF
	chmod 0755 "$WRAP/uci"
}

mesh_upgrade_sets_basic_rate_on_existing_interfaces() {
	mesh_begin mesh_upgrade_sets_basic_rate_on_existing_interfaces "an upgrade gives the interfaces the 0.5.2 helper made the mesh's basic rates, without a wifi reload"
	if mesh_released_two &&
		precond "the 0.5.2 helper set no basic_rate" \
			eval '[ -z "$(uget wireless.fips_mesh_radio0.basic_rate)" ] && [ -z "$(uget wireless.fips_mesh_radio1.basic_rate)" ]'; then
		mesh_install
		run_postinst
		check "the setup exits 0 and is deleted" eval '[ "$RC" = 0 ] && [ ! -e /etc/uci-defaults/90-fips-setup ]'
		check "fips_mesh_radio0 has basic_rate '$RATES'" same "$(uget wireless.fips_mesh_radio0.basic_rate)" "$RATES"
		check "fips_mesh_radio1 has basic_rate '$RATES'" same "$(uget wireless.fips_mesh_radio1.basic_rate)" "$RATES"
		check "the rates are saved, not only staged" \
			eval '[ "$(grep -cxF "	option basic_rate '"'$RATES'"'" /etc/config/wireless)" = 2 ] && [ -z "$(uci -q changes wireless)" ]'
		check "nothing else in wireless or network changed" mesh_exports_same_but_rates
		check "no wifi reload" no_wifi
		check "the line names both interfaces and that any network reload applies the rates" \
			said "set basic_rate '$RATES' on fips-mesh0 fips-mesh1; it applies at the next reboot or network reload, which 'wifi reload' and a LuCI apply make, as can the fips gateway's start or stop"
		check "a line says to upgrade routers reached over the mesh farthest first" \
			said 'when you reach routers over the mesh, upgrade and reload them one at a time, farthest first'
	fi
	fw_end
}

mesh_upgrade_leaves_other_wifi_ifaces_alone() {
	mesh_begin mesh_upgrade_leaves_other_wifi_ifaces_alone "an upgrade sets no basic_rate on wifi-ifaces fips-mesh-setup did not make"
	run_released_mesh radio0
	uci set wireless.own_mesh=wifi-iface &&
		uci set wireless.own_mesh.device=radio1 &&
		uci set wireless.own_mesh.mode=mesh &&
		uci set wireless.own_mesh.mesh_id=other &&
		uci set wireless.own_mesh.encryption=none &&
		uci set wireless.default_radio1=wifi-iface &&
		uci set wireless.default_radio1.device=radio1 &&
		uci set wireless.default_radio1.mode=ap &&
		uci set wireless.default_radio1.ssid=OpenWrt &&
		uci commit wireless || harness_fail "cannot add the operator's wifi-ifaces"
	dump wireless.own_mesh > "$WORK/own.before"
	dump wireless.default_radio1 > "$WORK/ap.before"
	if precond "fips_mesh_radio0 exists without basic_rate" \
		eval '[ "$(uget wireless.fips_mesh_radio0)" = wifi-iface ] && [ -z "$(uget wireless.fips_mesh_radio0.basic_rate)" ]'; then
		mesh_install
		run_postinst
		dump wireless.own_mesh > "$WORK/own.after"
		dump wireless.default_radio1 > "$WORK/ap.after"
		check "the setup exits 0 and is deleted" eval '[ "$RC" = 0 ] && [ ! -e /etc/uci-defaults/90-fips-setup ]'
		check "fips_mesh_radio0 has basic_rate '$RATES'" same "$(uget wireless.fips_mesh_radio0.basic_rate)" "$RATES"
		check "the operator's mesh wifi-iface is unchanged" cmp -s "$WORK/own.before" "$WORK/own.after"
		check "the operator's mesh wifi-iface has no basic_rate" same "$(uget wireless.own_mesh.basic_rate)" ""
		check "the AP wifi-iface is unchanged" cmp -s "$WORK/ap.before" "$WORK/ap.after"
		check "/etc/config/wireless has one basic_rate" same "$(grep -c basic_rate /etc/config/wireless)" 1
	fi
	fw_end
}

mesh_upgrade_keeps_operator_basic_rate() {
	mesh_begin mesh_upgrade_keeps_operator_basic_rate "an upgrade keeps a basic_rate the operator set on a fips mesh interface, and names it"
	if mesh_released_two; then
		uci set wireless.fips_mesh_radio1.basic_rate='1000 2000 5500 11000' && uci commit wireless ||
			harness_fail "cannot set the operator's basic_rate"
		dump wireless.fips_mesh_radio1 > "$WORK/radio1.before"
		mesh_install
		run_postinst
		dump wireless.fips_mesh_radio1 > "$WORK/radio1.after"
		check "the setup exits 0 and is deleted" eval '[ "$RC" = 0 ] && [ ! -e /etc/uci-defaults/90-fips-setup ]'
		check "fips_mesh_radio0 has basic_rate '$RATES'" same "$(uget wireless.fips_mesh_radio0.basic_rate)" "$RATES"
		check "fips_mesh_radio1 keeps the operator's basic_rate" same "$(uget wireless.fips_mesh_radio1.basic_rate)" '1000 2000 5500 11000'
		check "fips_mesh_radio1 is otherwise unchanged" cmp -s "$WORK/radio1.before" "$WORK/radio1.after"
		check "one line names the kept rates" said_once "fips-mesh1 keeps its basic_rate '1000 2000 5500 11000'"
		check "the set line names only fips-mesh0" said "set basic_rate '$RATES' on fips-mesh0;"
	fi
	fw_end
}

mesh_readd_keeps_operator_basic_rate() {
	mesh_begin mesh_readd_keeps_operator_basic_rate "running the helper again on a radio keeps a basic_rate the operator set"
	run_mesh radio0
	if precond "the first add set basic_rate '$RATES'" same "$(uget wireless.fips_mesh_radio0.basic_rate)" "$RATES"; then
		uci set wireless.fips_mesh_radio0.basic_rate='12000 24000' && uci commit wireless ||
			harness_fail "cannot set the operator's basic_rate"
		run_mesh radio0
		check "the second add exits 0" same "$RC" 0
		check "the operator's basic_rate is kept" same "$(uget wireless.fips_mesh_radio0.basic_rate)" '12000 24000'
		check "the closing message names the kept rates" said "basic_rate '12000 24000'"
	fi
	fw_end
}

mesh_rates_failed_save_keeps_setup() {
	mesh_begin mesh_rates_failed_save_keeps_setup "an upgrade whose wireless save fails says so and keeps the setup for the next boot"
	if mesh_released_two; then
		mesh_install
		wrap_uci_commit_fails_for wireless
		run_postinst wrap
		if precond "the uci wrapper failed a commit wireless" wrap_called uci 'commit wireless'; then
			check "the setup ends non-zero and is kept" eval '[ "$RC" != 0 ] && [ -f /etc/uci-defaults/90-fips-setup ]'
			check "the failed save is reported" said "the wireless configuration could not be saved, so the mesh interfaces keep the basic rates they had"
			check "/etc/config/wireless has no basic_rate" eval '! grep -q basic_rate /etc/config/wireless'
			check "the mesh zone was still made" mesh_zone_made "'fips-mesh0' 'fips-mesh1'"
			rm -f "$WRAP/uci"
			run_boot
			check "the next boot exits 0 and removes the setup" eval '[ "$RC" = 0 ] && [ ! -e /etc/uci-defaults/90-fips-setup ]'
			check "the next boot saves the rates" same "$(grep -cxF "	option basic_rate '$RATES'" /etc/config/wireless)" 2
			check "the next boot says it saved the rates staged before, on both interfaces" \
				said "set basic_rate '$RATES' on fips-mesh0 fips-mesh1;"
		fi
	fi
	fw_end
}

mesh_rates_damaged_save_names_copy() {
	mesh_begin mesh_rates_damaged_save_names_copy "a rates save onto a full overlay that empties the wireless file says so, and its copy restores it"
	if mesh_released_two; then
		small_config
		if precond "no wireless copy is left from before" eval '[ ! -e "$WCOPY" ]' &&
			precond "the small tmpfs has no page free" small_free 0; then
			run_mesh rates
			if precond "the save left /etc/config/wireless without radio0" \
				eval '! grep -qF "config wifi-device '"'radio0'"'" /etc/config/wireless'; then
				check "the helper exits 1" same "$RC" 1
				check "the damaged save is reported" said 'the wireless configuration could not be saved and /etc/config/wireless was left damaged'
				check "the line names the copy to import" said "uci import wireless < $WCOPY"
				refute "no line says the rates were set" said "set basic_rate '$RATES' on"
				check "the copy holds radio0 and the rates" \
					eval 'grep -qF "config wifi-device '"'radio0'"'" "$WCOPY" && [ "$(grep -cxF "	option basic_rate '"'$RATES'"'" "$WCOPY")" = 2 ]'
				rm -f "$SMALL/fill"
				uci import wireless < "$WCOPY" 2>/dev/null
				check "after the import: both radios are back" \
					eval '[ "$(uget wireless.radio0)" = wifi-device ] && [ "$(uget wireless.radio1)" = wifi-device ]'
				check "after the import: both mesh interfaces have the rates" \
					eval '[ "$(uget wireless.fips_mesh_radio0.basic_rate)" = "$RATES" ] && [ "$(uget wireless.fips_mesh_radio1.basic_rate)" = "$RATES" ]'
				run_mesh rates
				check "a later run exits 0 and says nothing" eval '[ "$RC" = 0 ] && [ ! -s "$OUT" ]'
			fi
		fi
	fi
	fw_end
}

# ── The helper leaves fips.yaml and the daemon alone ────────────────────────
# The daemon binds a named mesh interface whenever it appears, so the helper
# only reads fips.yaml and restarts nothing. A stub init script logs every
# call, `service fips ...` included, and a stand-in process named fips stands
# for the daemon, so a restart, a kill or a rewrite of the file shows.

FIPSLOG=/tmp/fw-work/fips-init.log

# no_touch_begin <fips.yaml>: install the file, the logging init script and the
# stand-in daemon, and keep a copy of the file to compare against.
no_touch_begin() {
	cp "$1" /etc/fips/fips.yaml && cp "$1" "$WORK/fips.yaml.before" ||
		harness_fail "cannot install $1 as /etc/fips/fips.yaml"
	printf '#!/bin/sh\necho "$0 $*" >> %s\n' "$FIPSLOG" > /etc/init.d/fips &&
		chmod 0755 /etc/init.d/fips || harness_fail "cannot install the fips init script stub"
	printf '#!/bin/sh\nwhile :; do sleep 1; done\n' > "$WORK/fips" && chmod 0755 "$WORK/fips" ||
		harness_fail "cannot write the stand-in daemon"
	"$WORK/fips" >/dev/null 2>&1 &
	echo $! > "$DAEMONPID"
}

# fips.yaml still holds the bytes it held before the helper ran.
yaml_unchanged() { cmp -s "$WORK/fips.yaml.before" /etc/fips/fips.yaml; }

# The stand-in daemon is the one process named fips, and still alive.
daemon_untouched() {
	local pid
	pid="$(cat "$DAEMONPID")"
	kill -0 "$pid" 2>/dev/null && [ "$(pidof fips)" = "$pid" ]
}

mesh_add_and_remove_leave_fips_yaml_and_the_daemon_alone() {
	mesh_begin mesh_add_and_remove_leave_fips_yaml_and_the_daemon_alone "adding, rating, zoning and removing meshes leaves fips.yaml, the init script and the daemon alone"
	no_touch_begin "$FW_FIPS_YAML"
	if precond "the stand-in daemon runs as the one process named fips" daemon_untouched; then
		for args in radio0 radio1 rates zone "remove radio1" remove; do
			# shellcheck disable=SC2086  # the words are the helper's arguments
			run_mesh $args
			check "fips-mesh-setup $args exits 0" same "$RC" 0
		done
		check "fips.yaml is byte-identical" yaml_unchanged
		check "the fips init script was never run" eval '[ ! -s "$FIPSLOG" ]'
		check "the same daemon process is still running" daemon_untouched
	fi
	fw_end
}

mesh_released_helper_rewrites_fips_yaml_and_the_check_sees_it() {
	mesh_begin mesh_released_helper_rewrites_fips_yaml_and_the_check_sees_it "the 0.5.2 helper's fips.yaml edit is seen by the no-touch check"
	no_touch_begin "$FIXTURES/released-fips.yaml"
	if precond "fips.yaml starts as the copy kept of it" yaml_unchanged; then
		run_released_mesh radio0
		refute "fips.yaml changed under the 0.5.2 helper" yaml_unchanged
	fi
	fw_end
}

# ── Harness start ───────────────────────────────────────────────────────────

[ -r "$FW_SETUP" ] || harness_fail "cannot read the setup under test, $FW_SETUP"
[ -r "$FW_MESH_SETUP" ] || harness_fail "cannot read the mesh helper under test, $FW_MESH_SETUP"
[ -r "$FW_FIPS_YAML" ] || harness_fail "cannot read the fips.yaml under test, $FW_FIPS_YAML"
if [ "$FW_SNIPPETS" != none ] && [ ! -d "$FW_SNIPPETS" ]; then
	harness_fail "FW_SNIPPETS is neither none nor a directory: $FW_SNIPPETS"
fi
for t in uci fw4 nft; do
	command -v "$t" >/dev/null 2>&1 || harness_fail "$t is missing from this image"
done
[ -x /usr/sbin/nft ] || harness_fail "/usr/sbin/nft is missing"
[ -f /etc/init.d/firewall ] || harness_fail "/etc/init.d/firewall is missing"

rm -rf "$STOCK"
mkdir -p "$STOCK" && cp -a /etc/config "$STOCK/config" && cp -a /usr/share/nftables.d "$STOCK/nftables.d" ||
	harness_fail "cannot save the stock configuration"

# Every firewall init-script call is logged, and then runs the real script. With
# the flush-only marker, a reload only flushes the table instead, standing in
# for a ruleset whose rendering stopped right after its flush.
mv /etc/init.d/firewall /etc/init.d/firewall.real || harness_fail "cannot move the firewall init script"
cat > /etc/init.d/firewall <<EOF
#!/bin/sh
echo "\$*" >> $RELOADLOG
if [ -e $FLUSHONLY ] && [ "\$1" = reload ]; then
	nft flush table inet fw4
	nft list chain inet fw4 input > $FLUSHLIST 2>&1
	exit 0
fi
exec /etc/rc.common /etc/init.d/firewall.real "\$@"
EOF
chmod 0755 /etc/init.d/firewall || harness_fail "cannot install the firewall wrapper"

echo "OpenWrt firewall scenarios ($(. /etc/openwrt_release && echo "$DISTRIB_DESCRIPTION"))"
echo "setup under test: $FW_SETUP; mesh helper: $FW_MESH_SETUP; snippets: $FW_SNIPPETS"

ALL="fw_upgrade_moves_fips0_into_its_own_zone
fw_upgrade_under_apk_environment_moves_fips0
fw_second_run_changes_nothing
fw_operator_zone_is_kept_and_named
fw_operator_zone_accepting_input_is_reported
fw_operator_wildcard_zone_holds_fips0
fw_fresh_install_creates_live_zone
fw_operator_edits_survive_rerun
fw_lan_through_network_is_reported
fw_old_include_and_files_removed
fw_unrelated_include_survives
fw_no_lan_zone_creates_zone_without_forwarding
fw_sourced_setup_does_not_leak
fw_no_firewall_migrates_without_reload
fw_sysupgrade_first_boot_migrates
fw_missing_state_file_blocks_fips0
fw_operator_scoping_renders_before_port_forwards
fw_bare_plus_device_does_not_hold_fips0
fw_operator_fips_ping_rule_kept
fw_foreign_fips_zone_not_doubled
fw_disabled_zone_does_not_hold_fips0
fw_foreign_fips_zone_under_accept_default_reported
fw_operator_zone_named_fips_without_lan_forwarding_is_named
fw_disabled_fips_zone_under_accept_default_reported
fw_downgrade_then_upgrade_migrates_again
fw_renamed_fips_zone_is_checked_by_its_name
fw_failed_reload_blocks_new_fips0_connections
fw_recovery_after_failed_reload_clears_block
fw_failed_reload_under_apk_environment_blocks_fips0
fw_unloaded_firewall_is_reported
fw_reload_without_prior_table_is_judged_by_the_zone_jump
fw_failed_commit_blocks_and_keeps_setup
fw_second_sdk_run_after_failed_commit_keeps_one_block
fw_boot_retry_after_failed_commit_migrates
fw_failed_commit_removes_leftover_files
fw_second_run_completes_a_half_failsafe_pair
fw_full_overlay_save_blocks_and_keeps_setup
fw_partial_save_blocks_and_keeps_setup
fw_path_without_sbin_still_migrates
fw_missing_nft_is_reported
fw_probe_add_failure_blocks_fips0
fw_unchecked_reload_without_state_file_names_restart
fw_listing_failure_blocks_fips0
fw_flush_only_load_blocks_fips0
mesh_add_puts_interface_in_reject_zone
mesh_second_add_changes_nothing
mesh_two_radios_share_one_zone_and_remove_cleans_up
mesh_remove_waits_for_interface_before_reload
mesh_remove_waits_for_interface_before_reload_and_reports_one_that_stays
mesh_remove_keeps_zone_until_interface_is_gone
mesh_add_then_remove_restores_firewall_config
mesh_existing_zone_options_are_kept
mesh_remove_keeps_empty_zone_it_took_nothing_from
mesh_disabled_zone_is_reported_not_failed
mesh_renamed_zone_is_checked_by_its_name
mesh_conflicting_firewall_section_is_refused
mesh_conflicting_firewall_section_is_refused_unless_it_holds_the_interface
mesh_failed_reload_drops_mesh_input
mesh_missing_state_file_names_restart
mesh_unloaded_firewall_is_reported
mesh_state_file_without_table_is_reported
mesh_upgrade_zones_existing_interfaces
mesh_second_upgrade_changes_nothing
mesh_first_boot_after_sysupgrade_zones_interfaces
mesh_hook_failed_save_closes_and_keeps_setup
mesh_second_sdk_run_after_failed_save_keeps_one_drop
mesh_hook_without_mesh_does_nothing
mesh_hook_after_damaged_save_closes_without_reload
mesh_interface_in_another_zone_is_left_there
mesh_add_failed_save_does_not_create_mesh
mesh_readd_after_failed_save_saves_staged_zone
mesh_add_failed_close_does_not_create_mesh
mesh_readd_unnumbered_radio_moves_zone_entry
mesh_hook_failed_reload_drops_mesh_input
mesh_upgrade_sets_basic_rate_on_existing_interfaces
mesh_upgrade_leaves_other_wifi_ifaces_alone
mesh_upgrade_keeps_operator_basic_rate
mesh_readd_keeps_operator_basic_rate
mesh_rates_failed_save_keeps_setup
mesh_rates_damaged_save_names_copy
mesh_add_and_remove_leave_fips_yaml_and_the_daemon_alone
mesh_released_helper_rewrites_fips_yaml_and_the_check_sees_it"

# The five continuation cases run only right after the case they continue.
if [ -n "$FW_CASES" ]; then
	SELECTED="$FW_CASES"
	EXPECTED=$(echo "$FW_CASES" | wc -w)
	for c in $FW_CASES; do
		printf '%s\n' "$ALL" | grep -qxF "$c" || harness_fail "unknown case in FW_CASES: $c"
	done
else
	SELECTED="$ALL"
	EXPECTED=$ALL_CASES
fi

for c in $SELECTED; do
	"$c"
done

fw_clean
echo ""
echo "ran $RAN of $EXPECTED cases"
if [ "$RAN" -ne "$EXPECTED" ]; then
	echo "firewall-scenarios: $((EXPECTED - RAN)) case(s) did not reach their end" >&2
	exit 2
fi
if [ "$FAILURES" -eq 0 ]; then
	echo "firewall-scenarios: all $CASES checks passed"
	exit 0
fi
echo "firewall-scenarios: $FAILURES of $CASES checks failed"
exit 1
