#!/bin/sh
# OpenWrt firewall scenarios for 90-fips-setup, run inside an openwrt/rootfs
# image so the real uci, fw4 and nft are exercised under ash.
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
#   FW_CASES     case function names to run, separated by spaces; default all.
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
OUT="$WORK/out"
SYSPATH=/usr/sbin:/usr/bin:/sbin:/bin

# The number of cases in the full run, counted by hand from the list at the
# end of this file. A run that completes fewer exits 2.
ALL_CASES=44

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
	rm -f "$COPY" "$COPY.staged" "$COPY.now"
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

# run_postinst [wrap]: install the setup in /etc/uci-defaults and run it as the
# package's postinst does, deleting it only when it ends with status 0.
run_postinst() {
	local p="$PATH"
	[ "${1:-}" = wrap ] && p="$WRAP:$PATH"
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
	sh -c '( cd /etc/uci-defaults && . ./90-fips-setup ) && rm -f /etc/uci-defaults/90-fips-setup' > "$OUT" 2>&1
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

# ── Harness start ───────────────────────────────────────────────────────────

[ -r "$FW_SETUP" ] || harness_fail "cannot read the setup under test, $FW_SETUP"
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
echo "setup under test: $FW_SETUP; snippets: $FW_SNIPPETS"

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
fw_flush_only_load_blocks_fips0"

# The three continuation cases run only right after the case they continue.
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
