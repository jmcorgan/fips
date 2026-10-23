#!/bin/sh
# OpenWrt maintainer-script and init-guard scenarios, run under ash.
#
# Driven by testing/openwrt/maintainer-scripts-test.sh, which starts a busybox
# container so /bin/sh here is ash, the shell OpenWrt runs these scripts under.
# Nothing in this file needs opkg: the call order, the arguments and the
# PKG_UPGRADE environment are taken from opkg-lede's own sources, so what is
# exercised is the scripts' behaviour given that contract, not opkg itself.
# A real `opkg upgrade` on a router image stays uncovered.
#
# PREINST, POSTINST, PRERM and INIT_GATEWAY may be pointed at other files. That is the
# seam used to see a scenario red against the previously released scripts, and
# to re-break the fixed ones during a break-check.
#
# APK_SCRIPTS names a directory holding the four scripts the .apk registers
# (post-install, pre-upgrade, post-upgrade, pre-deinstall), as captured from
# the real build-apk.sh by package-test.sh --keep. Scenarios 8 to 10 execute
# them directly with apk-tools v3's argv and PATH-only environment, so the
# kernel reads their #! line and ash runs them. A missing directory or script
# fails those scenarios; it is never a skip.

set -u

REPO="${REPO:-/src}"
POSTINST="${POSTINST:-$REPO/packaging/openwrt-ipk/scripts/postinst}"
PREINST="${PREINST:-$REPO/packaging/openwrt-ipk/scripts/preinst}"
PRERM="${PRERM:-$REPO/packaging/openwrt-ipk/scripts/prerm}"
RELEASED_PRERM="$REPO/testing/openwrt/fixtures/released-prerm"
INIT_GATEWAY="${INIT_GATEWAY:-$REPO/packaging/openwrt-ipk/files/etc/init.d/fips-gateway}"
APK_SCRIPTS="${APK_SCRIPTS:-}"
SHIPPED_YAML="$REPO/packaging/openwrt-ipk/files/etc/fips/fips.yaml"
# The fips.yaml v0.5.0 and v0.5.1 shipped, byte for byte (from the v0.5.1 tag),
# from before the gateway's default DNS port moved. v0.3.0 to v0.4.2 shipped an
# older file with the same legacy listen line.
RELEASED_YAML="$REPO/testing/openwrt/fixtures/released-fips.yaml"
GATEWAY_RS="$REPO/src/config/gateway.rs"
SETUP_SCRIPT="$REPO/packaging/openwrt-ipk/files/etc/uci-defaults/90-fips-setup"
LEGACY_LISTEN='    listen: "[::1]:5353"'
SHIPPED_LISTEN='    # listen: "[::1]:5365"   # the default; the init script points dnsmasq at this port'
MIGRATED_MSG='fips: moved gateway.dns.listen off the mDNS port 5353 to the default [::1]:5365'

WORK=/tmp/fips-openwrt-scenarios
UPGRADE_MARKER=/tmp/fips-prerm-upgrade
# The uci stub's state and the directory holding the executable stubs. Fixed
# paths, because the .apk scripts run with only PATH in their environment.
UCI_DIR=/tmp/fips-openwrt-uci
STUB_BIN=/tmp/fips-openwrt-bin
DNSMASQ_OPT='dhcp.@dnsmasq[0].server'

FAILURES=0
CASES=0

note() { echo "  $*"; }

ok() {
    CASES=$((CASES + 1))
    echo "  ok   $*"
    return 0
}

bad() {
    CASES=$((CASES + 1))
    FAILURES=$((FAILURES + 1))
    echo "  FAIL $*"
    return 0
}

# Stub init scripts that record every call and keep an enable state file, so a
# scenario can assert both what was invoked and what the package left behind.
install_stubs() {
    mkdir -p /etc/init.d /etc/uci-defaults

    cat > /etc/init.d/fips-gateway <<'STUB'
#!/bin/sh
echo "fips-gateway $1" >> "$CALLS"
case "$1" in
    enable)  echo 1 > "$GW_STATE" ;;
    disable) echo 0 > "$GW_STATE" ;;
    enabled) [ "$(cat "$GW_STATE")" = 1 ] ;;
esac
STUB

    cat > /etc/init.d/fips <<'STUB'
#!/bin/sh
echo "fips $1" >> "$CALLS"
case "$1" in
    enable)  echo 1 > "$FIPS_STATE" ;;
    disable) echo 0 > "$FIPS_STATE" ;;
    enabled) [ "$(cat "$FIPS_STATE")" = 1 ] ;;
esac
STUB

    cat > /etc/uci-defaults/90-fips-setup <<'STUB'
#!/bin/sh
echo "uci-defaults" >> "$CALLS"
STUB

    chmod 0755 /etc/init.d/fips-gateway /etc/init.d/fips /etc/uci-defaults/90-fips-setup
    return 0
}

reset_state() {
    rm -rf "$WORK"
    mkdir -p "$WORK"
    CALLS="$WORK/calls"
    GW_STATE="$WORK/gateway-enabled"
    FIPS_STATE="$WORK/fips-enabled"
    export CALLS GW_STATE FIPS_STATE
    : > "$CALLS"
    echo 0 > "$GW_STATE"
    echo 0 > "$FIPS_STATE"
    rm -f "$UPGRADE_MARKER"
    unset PKG_UPGRADE
    install_stubs
    return 0
}

calls_oneline() {
    tr '\n' ';' < "$CALLS"
    return 0
}

assert_called() {
    # assert_called <expected call line> <what it means>
    if grep -qxF "$1" "$CALLS"; then
        ok "$2"
    else
        bad "$2 — '$1' is not among: $(calls_oneline)"
    fi
    return 0
}

assert_not_called() {
    if grep -qxF "$1" "$CALLS"; then
        bad "$2 — '$1' was called: $(calls_oneline)"
    else
        ok "$2"
    fi
    return 0
}

assert_none_called_with_prefix() {
    # assert_none_called_with_prefix <prefix> <what it means>
    # Fails if any recorded call begins with <prefix>, whatever follows it.
    if [ ! -r "$CALLS" ]; then
        bad "$2 — the call log $CALLS cannot be read"
        return 0
    fi
    matched=""
    while IFS= read -r line; do
        case "$line" in
        "$1"*) matched="$matched$line;" ;;
        esac
    done < "$CALLS"
    if [ -n "$matched" ]; then
        bad "$2 — called: $matched"
    else
        ok "$2"
    fi
    return 0
}

assert_file_is() {
    # assert_file_is <file> <expected contents> <what it means>
    got="$(cat "$1" 2>/dev/null)"
    if [ "$got" = "$2" ]; then
        ok "$3"
    else
        bad "$3 — expected '$2', got '$got'"
    fi
    return 0
}

assert_equals() {
    # assert_equals <got> <want> <what it means>
    if [ "$1" = "$2" ]; then
        ok "$3"
    else
        bad "$3 — expected '$2', got '$1'"
    fi
    return 0
}

assert_absent() {
    if [ -e "$1" ]; then
        bad "$2 — $1 still exists"
    else
        ok "$2"
    fi
    return 0
}

assert_present() {
    if [ -e "$1" ]; then
        ok "$2"
    else
        bad "$2 — $1 does not exist"
    fi
    return 0
}

first_call_line() {
    grep -nxF "$1" "$CALLS" | head -n 1 | cut -d: -f1
    return 0
}

assert_order() {
    # assert_order <first call> <second call> <what it means>
    first="$(first_call_line "$1")"
    second="$(first_call_line "$2")"
    if [ -z "$first" ] || [ -z "$second" ]; then
        bad "$3 — '$1' and '$2' were not both called: $(calls_oneline)"
    elif [ "$first" -lt "$second" ]; then
        ok "$3"
    else
        bad "$3 — '$2' came before '$1': $(calls_oneline)"
    fi
    return 0
}

# Install an executable uci that keeps each option as a file of values, one per
# line, under $UCI_DIR. Like the real uci, "get" prints a list on one line
# separated by single spaces and fails for an option with no values, and
# del_list removes every copy of the value. Other commands are only logged.
install_uci_stub() {
    rm -rf "$UCI_DIR"
    mkdir -p "$UCI_DIR" "$STUB_BIN"
    {
        echo '#!/bin/sh'
        echo "dir=$UCI_DIR"
        cat <<'STUB'
[ "${1:-}" = "-q" ] && shift
cmd="${1:-}"
[ $# -gt 0 ] && shift
echo "uci $cmd $*" >> "$dir/log"
file_of() {
    printf '%s/%s' "$dir" "$(printf '%s' "$1" | sed 's/[^A-Za-z0-9._-]/_/g')"
}
case "$cmd" in
get)
    f="$(file_of "$1")"
    [ -s "$f" ] || exit 1
    tr '\n' ' ' < "$f" | sed 's/ $//'
    echo
    ;;
add_list)
    echo "${1#*=}" >> "$(file_of "${1%%=*}")"
    ;;
del_list)
    f="$(file_of "${1%%=*}")"
    if [ -f "$f" ]; then
        grep -vxF -- "${1#*=}" "$f" > "$f.new"
        mv "$f.new" "$f"
    fi
    ;;
esac
exit 0
STUB
    } > "$STUB_BIN/uci"
    chmod 0755 "$STUB_BIN/uci"

    cat > /etc/init.d/dnsmasq <<'STUB'
#!/bin/sh
echo "dnsmasq $1" >> "$CALLS"
STUB
    chmod 0755 /etc/init.d/dnsmasq
    return 0
}

uci_seed() {
    # uci_seed <option> <value>...
    opt="$1"
    shift
    for value in "$@"; do
        "$STUB_BIN/uci" add_list "$opt=$value"
    done
    return 0
}

uci_sorted() {
    # uci_sorted <option>: the option's values, sorted, on one line.
    "$STUB_BIN/uci" -q get "$1" | tr ' ' '\n' | sort | tr '\n' ' '
    return 0
}

sorted_words() {
    printf '%s\n' "$@" | sort | tr '\n' ' '
    return 0
}

run_apk_script() {
    # run_apk_script <phase> <args...>
    # Runs one captured .apk script the way apk-tools v3 does: executed
    # directly, with only PATH in the environment. The stubs' own state
    # variables are passed through so they can record the calls.
    phase="$1"
    shift
    script="$APK_SCRIPTS/$phase"
    if [ -z "$APK_SCRIPTS" ] || [ ! -x "$script" ]; then
        bad "the .apk $phase script is not available at '$script'"
        return 1
    fi
    env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
        CALLS="$CALLS" GW_STATE="$GW_STATE" FIPS_STATE="$FIPS_STATE" \
        "$script" "$@" >/dev/null 2>&1
    return 0
}

# ── 1. Fresh install ────────────────────────────────────────────────────────
# opkg runs the postinst with "configure"; PKG_UPGRADE is set only on upgrades,
# so both its absence and an explicit 0 must leave the gateway alone.
scenario_fresh_install() {
    for pkg_upgrade in unset 0; do
        note "scenario 1: fresh install (PKG_UPGRADE $pkg_upgrade)"
        reset_state
        if [ "$pkg_upgrade" = "0" ]; then
            PKG_UPGRADE=0 sh "$POSTINST" configure >/dev/null 2>&1
        else
            sh "$POSTINST" configure >/dev/null 2>&1
        fi

        assert_called "fips enable" "the daemon is enabled on a fresh install"
        assert_called "fips start" "the daemon is started on a fresh install"
        assert_not_called "fips-gateway enable" "the gateway is not enabled on a fresh install"
        assert_not_called "fips-gateway start" "the gateway is not started on a fresh install"
        assert_file_is "$GW_STATE" "0" "the gateway is left disabled on a fresh install"
    done
    return 0
}

# ── 2. Upgrade from a released package ──────────────────────────────────────
# Its prerm disabled the gateway on its way out and left no marker, so the
# incoming postinst cannot tell an enabled gateway from a disabled one and
# re-enables it.
scenario_upgrade_from_released() {
    note "scenario 2: upgrade from a released package"
    reset_state
    echo 1 > "$GW_STATE"
    echo 1 > "$FIPS_STATE"

    sh "$RELEASED_PRERM" upgrade 0.5.1 >/dev/null 2>&1
    PKG_UPGRADE=1 sh "$POSTINST" configure >/dev/null 2>&1

    assert_called "fips-gateway enable" "the gateway is re-enabled after a released prerm disabled it"
    assert_called "fips-gateway start" "the gateway is started again"
    assert_file_is "$GW_STATE" "1" "the gateway ends up enabled"
    return 0
}

# ── 3. Upgrade from a package carrying these scripts, gateway enabled ───────
scenario_upgrade_enabled() {
    note "scenario 3: upgrade from these scripts, gateway enabled"
    reset_state
    echo 1 > "$GW_STATE"
    echo 1 > "$FIPS_STATE"

    sh "$PRERM" upgrade 0.5.2 >/dev/null 2>&1
    assert_file_is "$GW_STATE" "1" "the outgoing prerm does not disable the gateway on an upgrade"
    assert_not_called "fips-gateway disable" "the outgoing prerm does not call disable on an upgrade"
    assert_called "fips-gateway stop" "the outgoing prerm still stops the gateway"

    PKG_UPGRADE=1 sh "$POSTINST" configure >/dev/null 2>&1
    assert_file_is "$GW_STATE" "1" "the gateway stays enabled across the upgrade"
    assert_called "fips-gateway start" "an enabled gateway is started again"
    assert_not_called "fips-gateway enable" "an enabled gateway does not need re-enabling"
    assert_absent "$UPGRADE_MARKER" "the postinst removes the upgrade marker"
    return 0
}

# ── 4. Upgrade from a package carrying these scripts, gateway disabled ──────
scenario_upgrade_disabled() {
    note "scenario 4: upgrade from these scripts, gateway disabled"
    reset_state
    echo 1 > "$FIPS_STATE"

    sh "$PRERM" upgrade 0.5.2 >/dev/null 2>&1
    PKG_UPGRADE=1 sh "$POSTINST" configure >/dev/null 2>&1

    assert_file_is "$GW_STATE" "0" "a disabled gateway stays disabled across the upgrade"
    assert_not_called "fips-gateway enable" "a disabled gateway is not enabled by the upgrade"
    assert_not_called "fips-gateway start" "a disabled gateway is not started by the upgrade"
    assert_absent "$UPGRADE_MARKER" "the postinst removes the upgrade marker"
    return 0
}

# ── 5. Removal ──────────────────────────────────────────────────────────────
scenario_removal() {
    note "scenario 5: removal"
    reset_state
    echo 1 > "$GW_STATE"
    echo 1 > "$FIPS_STATE"

    sh "$PRERM" remove >/dev/null 2>&1

    assert_called "fips-gateway stop" "removal stops the gateway"
    assert_called "fips-gateway disable" "removal disables the gateway"
    assert_called "fips stop" "removal stops the daemon"
    assert_called "fips disable" "removal disables the daemon"
    assert_file_is "$GW_STATE" "0" "the gateway ends up disabled"
    assert_absent "$UPGRADE_MARKER" "removal leaves no upgrade marker"
    return 0
}

# ── 6. gateway_config_enabled reads the config ──────────────────────────────
scenario_config_reader() {
    note "scenario 6: gateway_config_enabled"
    reset_state

    # shellcheck source=/dev/null
    . "$INIT_GATEWAY"

    CONFIG="$SHIPPED_YAML"
    assert_equals "$(gateway_config_enabled)" "true" "the shipped fips.yaml reads as true"

    CONFIG="$WORK/disabled.yaml"
    cat > "$CONFIG" <<'YAML'
identity:
  key_file: "/etc/fips/node.key"

gateway:
  enabled: false
  pool: "fd01::/112"

peers: []
YAML
    assert_equals "$(gateway_config_enabled)" "false" "an explicitly disabled gateway reads as false"

    CONFIG="$WORK/no-gateway.yaml"
    cat > "$CONFIG" <<'YAML'
identity:
  key_file: "/etc/fips/node.key"

dns:
  enabled: true

peers: []
YAML
    assert_equals "$(gateway_config_enabled)" "" "a config with no gateway block reads as empty"
    return 0
}

# ── 7. start_service refuses to touch dnsmasq for a disabled gateway ────────
# The init script's helpers are redefined after sourcing it, so start_service
# runs its own decision against recorded stubs instead of uci, procd and the
# network. Where dnsmasq ends up while the gateway runs is scenario 15's.
stub_start_service_helpers() {
    # stub_start_service_helpers [keep-swap]: keep-swap leaves the real
    # dnsmasq_swap_fips_upstream in place, for a caller with the uci stub.
    if [ "${1:-}" != "keep-swap" ]; then
        dnsmasq_swap_fips_upstream() { echo "dnsmasq_swap $1" >> "$CALLS"; return 0; }
    fi
    sysctl() { return 0; }
    modprobe() { return 0; }
    logger() { return 0; }
    procd_set_param() {
        if [ "$1" = "command" ]; then
            echo "$*" >> "$CALLS"
        fi
        return 0
    }
    procd_close_instance() { return 0; }
    gateway_add_global_prefix() { echo "add_global_prefix" >> "$CALLS"; return 0; }
    prefix_remove() { echo "prefix_remove" >> "$CALLS"; return 0; }
    gateway_add_ra_route() { echo "add_ra_route" >> "$CALLS"; return 0; }
    procd_open_instance() { echo "procd_open_instance" >> "$CALLS"; return 0; }
    return 0
}

scenario_start_service_guard() {
    note "scenario 7: start_service guard"

    # shellcheck source=/dev/null
    . "$INIT_GATEWAY"
    stub_start_service_helpers

    reset_state
    CONFIG="$SHIPPED_YAML"
    start_service >/dev/null 2>&1
    assert_none_called_with_prefix "dnsmasq_swap " \
        "an enabled gateway does not point dnsmasq at a gateway that is not yet listening"
    assert_called "procd_open_instance" "an enabled gateway still starts the daemon"
    assert_called "command /etc/init.d/fips-gateway supervise" \
        "procd runs the gateway through the init script's supervise command"
    assert_not_called "prefix_remove" "an enabled gateway keeps the LAN prefix"

    reset_state
    CONFIG="$WORK/disabled.yaml"
    cat > "$CONFIG" <<'YAML'
gateway:
  enabled: false
  pool: "fd01::/112"
YAML
    start_service >/dev/null 2>&1
    assert_none_called_with_prefix "dnsmasq_swap " "a disabled gateway does not redirect dnsmasq"
    assert_not_called "add_global_prefix" "a disabled gateway does not add the LAN prefix"
    assert_called "prefix_remove" "a disabled gateway gives the LAN prefix back"
    assert_not_called "add_ra_route" "a disabled gateway does not advertise the pool route"
    assert_not_called "procd_open_instance" "a disabled gateway does not start the daemon"
    return 0
}

# ── 8. apk fresh install ────────────────────────────────────────────────────
# apk-tools v3 runs only post-install, with the new version as its argument.
scenario_apk_fresh_install() {
    note "scenario 8: apk fresh install"
    reset_state

    run_apk_script post-install 0.6.0-r1 || return 0

    assert_called "fips enable" "an apk install enables the daemon"
    assert_called "fips start" "an apk install starts the daemon"
    assert_not_called "fips-gateway enable" "an apk install does not enable the gateway"
    assert_not_called "fips-gateway start" "an apk install does not start the gateway"
    assert_file_is "$GW_STATE" "0" "an apk install leaves the gateway disabled"
    return 0
}

# ── 9. apk upgrade, gateway enabled ─────────────────────────────────────────
# apk-tools v3 runs only the new package's pre-upgrade and post-upgrade, with
# "<new-version> <old-version>"; the old package runs nothing.
scenario_apk_upgrade_enabled() {
    note "scenario 9: apk upgrade, gateway enabled"
    reset_state
    echo 1 > "$GW_STATE"
    echo 1 > "$FIPS_STATE"

    run_apk_script pre-upgrade 0.6.0-r1 0.5.2-r1 || return 0
    assert_called "fips-gateway stop" "pre-upgrade stops the gateway"
    assert_called "fips stop" "pre-upgrade stops the daemon"
    assert_not_called "fips-gateway disable" "pre-upgrade does not disable the gateway"
    assert_not_called "fips disable" "pre-upgrade does not disable the daemon"
    assert_file_is "$GW_STATE" "1" "the gateway is still enabled after pre-upgrade"
    assert_present "$UPGRADE_MARKER" "pre-upgrade leaves the upgrade marker"

    run_apk_script post-upgrade 0.6.0-r1 0.5.2-r1 || return 0
    assert_order "fips stop" "fips start" "the daemon is started again after it was stopped"
    assert_order "fips-gateway stop" "fips-gateway start" "the gateway is started again after it was stopped"
    assert_not_called "fips-gateway enable" "an enabled gateway does not need re-enabling"
    assert_file_is "$GW_STATE" "1" "the gateway stays enabled across the apk upgrade"
    assert_absent "$UPGRADE_MARKER" "post-upgrade removes the upgrade marker"
    return 0
}

# ── 10. apk upgrade, gateway disabled ───────────────────────────────────────
scenario_apk_upgrade_disabled() {
    note "scenario 10: apk upgrade, gateway disabled"
    reset_state
    echo 1 > "$FIPS_STATE"

    run_apk_script pre-upgrade 0.6.0-r1 0.5.2-r1 || return 0
    run_apk_script post-upgrade 0.6.0-r1 0.5.2-r1 || return 0

    assert_order "fips stop" "fips start" "the daemon is started again after it was stopped"
    assert_file_is "$GW_STATE" "0" "a disabled gateway stays disabled across the apk upgrade"
    assert_not_called "fips-gateway enable" "a disabled gateway is not enabled by the apk upgrade"
    assert_not_called "fips-gateway start" "a disabled gateway is not started by the apk upgrade"
    assert_absent "$UPGRADE_MARKER" "post-upgrade removes the upgrade marker"
    return 0
}

# ── 11. gateway_dns_port reads the port the gateway will bind ───────────────
scenario_dns_port_reader() {
    note "scenario 11: gateway_dns_port"
    reset_state

    # shellcheck source=/dev/null
    . "$INIT_GATEWAY"

    CONFIG="$SHIPPED_YAML"
    assert_equals "$(gateway_dns_port)" "5365" "the shipped fips.yaml reads as the default port"

    CONFIG="$RELEASED_YAML"
    assert_equals "$(gateway_dns_port)" "5353" "the previously shipped fips.yaml reads as 5353"

    CONFIG="$WORK/v4.yaml"
    cat > "$CONFIG" <<'YAML'
gateway:
  enabled: true
  dns:
    listen: '127.0.0.1:5400'
YAML
    assert_equals "$(gateway_dns_port)" "5400" "a single-quoted IPv4 listen address reads as its port"

    CONFIG="$WORK/port-forward.yaml"
    cat > "$CONFIG" <<'YAML'
gateway:
  enabled: true
  pool: "fd01::/112"
  port_forwards:
    - listen_port: 8080
      proto: tcp
      target: "[fd00::1]:80"
YAML
    assert_equals "$(gateway_dns_port)" "5365" "a port forward's listen_port is not the DNS listen port"

    CONFIG="$WORK/transport-listen.yaml"
    cat > "$CONFIG" <<'YAML'
transports:
  ethernet:
    lan:
      interface: "br-lan"
      listen: true
gateway:
  enabled: true
  pool: "fd01::/112"
YAML
    assert_equals "$(gateway_dns_port)" "5365" "a listen key outside the gateway block is ignored"

    CONFIG="$WORK/commented.yaml"
    cat > "$CONFIG" <<'YAML'
gateway:
  enabled: true
  dns:
    # listen: "[::1]:5400"
    upstream: "[::1]:5354"
YAML
    assert_equals "$(gateway_dns_port)" "5365" "a commented listen line is ignored"

    CONFIG="$WORK/no-gateway.yaml"
    cat > "$CONFIG" <<'YAML'
dns:
  enabled: true

peers: []
YAML
    assert_equals "$(gateway_dns_port)" "5365" "a config with no gateway block reads as the default port"
    return 0
}

# ── 12. The init script's default port matches the gateway's ───────────────
scenario_default_port_parity() {
    note "scenario 12: GW_DNS_DEFAULT matches DEFAULT_DNS_LISTEN"

    # shellcheck source=/dev/null
    . "$INIT_GATEWAY"

    rust_listen="$(sed -n 's/^const DEFAULT_DNS_LISTEN: &str = "\(.*\)";$/\1/p' "$GATEWAY_RS" 2>/dev/null)"
    rust_port="${rust_listen##*:}"
    case "$rust_port" in
    '' | *[!0-9]*)
        bad "could not read a port from DEFAULT_DNS_LISTEN in $GATEWAY_RS (got '$rust_listen')"
        return 0
        ;;
    esac
    assert_equals "${GW_DNS_DEFAULT:-}" "$rust_port" "the init script's GW_DNS_DEFAULT is the gateway's default port"
    return 0
}

# ── 13. The swap clears every loopback .fips forward ────────────────────────
# The real dnsmasq_swap_fips_upstream runs against the uci stub.
scenario_swap_cleanup() {
    note "scenario 13: dnsmasq_swap_fips_upstream"
    reset_state
    install_uci_stub

    # shellcheck source=/dev/null
    . "$INIT_GATEWAY"

    saved_path="$PATH"
    PATH="$STUB_BIN:$PATH"

    uci_seed "$DNSMASQ_OPT" "/fips/::1#5353" "/fips/127.0.0.1#5400" "/fips/192.168.1.5#53" "/lan/192.168.1.2"
    lines="$(uci -q get "$DNSMASQ_OPT" | wc -l | tr -d ' ')"
    assert_equals "$lines" "1" "the uci stub prints a list on one line, as uci does"

    dnsmasq_swap_fips_upstream 5365 >/dev/null 2>&1
    assert_equals "$(uci_sorted "$DNSMASQ_OPT")" \
        "$(sorted_words /lan/192.168.1.2 /fips/192.168.1.5#53 /fips/::1#5365)" \
        "the swap to 5365 clears every loopback .fips forward and keeps the others"

    dnsmasq_swap_fips_upstream 5354 >/dev/null 2>&1
    assert_equals "$(uci_sorted "$DNSMASQ_OPT")" \
        "$(sorted_words /lan/192.168.1.2 /fips/192.168.1.5#53 /fips/::1#5354)" \
        "the swap back to 5354 leaves only the daemon's loopback forward"
    assert_called "dnsmasq restart" "the swap restarts dnsmasq"

    # A swap to the port dnsmasq already forwards to, as when a gateway that
    # never started exits, leaves /etc/config/dhcp and dnsmasq alone.
    : > "$CALLS"
    : > "$UCI_DIR/log"
    dnsmasq_swap_fips_upstream 5354 >/dev/null 2>&1
    assert_equals "$(uci_sorted "$DNSMASQ_OPT")" \
        "$(sorted_words /lan/192.168.1.2 /fips/192.168.1.5#53 /fips/::1#5354)" \
        "a swap to the current port keeps the servers as they are"
    assert_not_called "dnsmasq restart" "a swap to the current port does not restart dnsmasq"
    if grep -q '^uci commit' "$UCI_DIR/log"; then
        bad "a swap to the current port committed dhcp: $(tr '\n' ';' < "$UCI_DIR/log")"
    else
        ok "a swap to the current port does not commit dhcp"
    fi

    # The right port beside a stale loopback forward is still a change.
    install_uci_stub
    uci_seed "$DNSMASQ_OPT" "/fips/::1#5354" "/fips/127.0.0.1#5354" "/lan/192.168.1.2"
    : > "$CALLS"
    dnsmasq_swap_fips_upstream 5354 >/dev/null 2>&1
    assert_equals "$(uci_sorted "$DNSMASQ_OPT")" \
        "$(sorted_words /lan/192.168.1.2 /fips/::1#5354)" \
        "a swap clears a stale loopback forward beside the current one"
    assert_called "dnsmasq restart" "clearing a stale loopback forward restarts dnsmasq"

    PATH="$saved_path"
    return 0
}

# ── 14. 90-fips-setup migrates the previously shipped listen line ──────────
# The real 90-fips-setup runs, executed by the ipk postinst and the apk
# post-upgrade script, and sourced in a subshell as OpenWrt's default_postinst
# and first-boot uci-defaults run do. uci, logger, modprobe and sysctl are
# stubs on PATH, and in /usr/sbin for the apk script, whose PATH is fixed.

install_setup_stubs() {
    install_uci_stub
    for cmd in logger modprobe sysctl; do
        printf '#!/bin/sh\necho "%s $*" >> %s/stub-calls\n' "$cmd" "$UCI_DIR" > "$STUB_BIN/$cmd"
        chmod 0755 "$STUB_BIN/$cmd"
    done
    mkdir -p /usr/sbin /etc/modules.d /etc/fips
    # rm first: cp onto a busybox applet link would overwrite busybox itself.
    for cmd in uci logger modprobe sysctl; do
        rm -f "/usr/sbin/$cmd"
        cp "$STUB_BIN/$cmd" "/usr/sbin/$cmd"
    done
    cp "$SETUP_SCRIPT" /etc/uci-defaults/90-fips-setup
    chmod 0755 /etc/uci-defaults/90-fips-setup
    return 0
}

remove_setup_stubs() {
    for cmd in uci logger modprobe sysctl; do
        rm -f "/usr/sbin/$cmd"
    done
    rm -rf "$STUB_BIN" /etc/fips
    return 0
}

install_config() {
    # install_config <file>: installed mode 0644, so a mode check can fail.
    cp "$1" /etc/fips/fips.yaml
    chmod 0644 /etc/fips/fips.yaml
    return 0
}

assert_migrated() {
    # assert_migrated <how the script ran>
    CONFIG=/etc/fips/fips.yaml
    assert_equals "$(gateway_dns_port)" "5365" "$1: the init script reads the default port"
    changes="$(diff -U0 "$RELEASED_YAML" /etc/fips/fips.yaml 2>/dev/null | grep -v '^---' | grep -v '^+++' | grep '^[-+]')"
    assert_equals "$changes" "$(printf '%s\n%s' "-$LEGACY_LISTEN" "+$SHIPPED_LISTEN")" \
        "$1: only the listen line changed, to the shipped form"
    assert_equals "$(stat -c %a /etc/fips/fips.yaml 2>/dev/null)" "600" "$1: the file is mode 0600"
    return 0
}

run_setup() {
    # run_setup <output file>: executes the installed 90-fips-setup.
    sh /etc/uci-defaults/90-fips-setup > "$1" 2>&1
    return $?
}

scenario_listen_migration() {
    note "scenario 14: 90-fips-setup migrates the shipped gateway listen line"

    # shellcheck source=/dev/null
    . "$INIT_GATEWAY"
    saved_path="$PATH"
    PATH="$STUB_BIN:$PATH"

    # 1. Executed by the ipk postinst on an upgrade.
    reset_state
    install_setup_stubs
    install_config "$RELEASED_YAML"
    touch "$UPGRADE_MARKER"
    PKG_UPGRADE=1 sh "$POSTINST" configure > "$WORK/postinst.out" 2>&1
    assert_migrated "ipk upgrade"
    if grep -qxF "$MIGRATED_MSG" "$WORK/postinst.out"; then
        ok "ipk upgrade: the migration is reported on stdout"
    else
        bad "ipk upgrade: no migration message in: $(tr '\n' ';' < "$WORK/postinst.out")"
    fi
    assert_absent /etc/uci-defaults/90-fips-setup "ipk upgrade: the postinst removed 90-fips-setup, so it exited 0"

    # 2. Executed by the apk post-upgrade script.
    reset_state
    install_setup_stubs
    install_config "$RELEASED_YAML"
    touch "$UPGRADE_MARKER"
    if run_apk_script post-upgrade 0.6.0-r1 0.5.2-r1; then
        assert_migrated "apk upgrade"
        assert_absent /etc/uci-defaults/90-fips-setup "apk upgrade: post-upgrade removed 90-fips-setup, so it exited 0"
    fi

    # 3. Sourced in a subshell, without the functions earlier scenarios define.
    reset_state
    install_setup_stubs
    install_config "$RELEASED_YAML"
    (
        unset -f logger modprobe sysctl sleep 2>/dev/null
        cd /etc/uci-defaults && . ./90-fips-setup
    ) > "$WORK/sourced.out" 2>&1
    assert_equals "$?" "0" "sourced: the subshell exits 0"
    assert_migrated "sourced"

    # 4. Anything but the exact shipped line is left byte-identical.
    for variant in other-port indent comment no-gateway; do
        reset_state
        install_setup_stubs
        input="$WORK/$variant.yaml"
        case "$variant" in
        other-port) sed 's|^    listen: "\[::1\]:5353"$|    listen: "[::1]:5400"|' "$RELEASED_YAML" > "$input" ;;
        indent) sed 's|^    listen: "\[::1\]:5353"$|      listen: "[::1]:5353"|' "$RELEASED_YAML" > "$input" ;;
        comment) sed 's|^    listen: "\[::1\]:5353"$|    listen: "[::1]:5353"  # kept|' "$RELEASED_YAML" > "$input" ;;
        no-gateway) printf 'node:\n  identity:\n    persistent: true\n\npeers: []\n' > "$input" ;;
        esac
        if [ "$variant" != "no-gateway" ] && cmp -s "$input" "$RELEASED_YAML"; then
            bad "negative case $variant: the fixture edit changed nothing, so the case would prove nothing"
            continue
        fi
        install_config "$input"
        run_setup "$WORK/$variant.out"
        if cmp -s "$input" /etc/fips/fips.yaml; then
            ok "negative case $variant: the file is left byte-identical"
        else
            bad "negative case $variant: the file was changed"
        fi
    done

    # 5. No config file.
    reset_state
    install_setup_stubs
    rm -f /etc/fips/fips.yaml
    run_setup "$WORK/no-config.out"
    assert_equals "$?" "0" "no config: the script exits 0"
    assert_absent /etc/fips/fips.yaml "no config: no file is created"
    if grep -qF "$MIGRATED_MSG" "$WORK/no-config.out"; then
        bad "no config: a migration was reported"
    else
        ok "no config: no migration is reported"
    fi

    # 6. A second run changes nothing.
    reset_state
    install_setup_stubs
    install_config "$RELEASED_YAML"
    run_setup "$WORK/first.out"
    cp /etc/fips/fips.yaml "$WORK/migrated.yaml"
    run_setup "$WORK/second.out"
    if cmp -s "$WORK/migrated.yaml" /etc/fips/fips.yaml; then
        ok "a second run leaves the migrated file byte-identical"
    else
        bad "a second run changed the migrated file"
    fi

    # 7. Stale loopback gateway entries for 5353 are removed; others are kept.
    reset_state
    install_setup_stubs
    install_config "$SHIPPED_YAML"
    uci_seed "$DNSMASQ_OPT" "/fips/::1#5353" "/fips/127.0.0.1#5353" "/fips/192.168.1.5#53"
    run_setup "$WORK/entries.out"
    assert_equals "$(uci_sorted "$DNSMASQ_OPT")" \
        "$(sorted_words /fips/192.168.1.5#53 /fips/::1#5354)" \
        "the legacy 5353 entries are removed and the daemon's entry is added"

    PATH="$saved_path"
    remove_setup_stubs
    return 0
}

# ── 15. dnsmasq points at the gateway only while it listens ───────────────
# start_service runs against recorded procd stubs, and the command it hands
# procd is then executed as procd would execute it: the real init script is
# installed at /etc/init.d/fips-gateway, whose #! line runs a stand-in
# /etc/rc.common, and /usr/bin/fips-gateway is a stub gateway. A stub that
# binds does so by becoming nc, so the socket is the stub's own, as the real
# gateway's is. dnsmasq's loopback .fips forward lives in the uci stub and
# starts on the daemon's port, as it is while the gateway is stopped. However
# the gateway exits, it must end there.

GW_STUB=/tmp/fips-gw-stub

install_supervise_env() {
    # install_supervise_env <gateway DNS listen port>
    install_uci_stub
    printf '#!/bin/sh\nexit 0\n' > "$STUB_BIN/logger"
    chmod 0755 "$STUB_BIN/logger"
    # supervise starts the gateway once fips0 exists, which this container
    # cannot create: report it present and pass every other call to busybox.
    cat > "$STUB_BIN/ip" <<'IP'
#!/bin/sh
[ "$*" = "link show fips0" ] && exit 0
exec busybox ip "$@"
IP
    chmod 0755 "$STUB_BIN/ip"

    rm -rf "$GW_STUB"
    mkdir -p "$GW_STUB" /etc/fips /usr/bin
    rm -f /var/run/fips-gateway.pid
    echo "$1" > "$GW_STUB/port"
    cat > /etc/fips/fips.yaml <<YAML
gateway:
  enabled: true
  pool: "fd01::/112"
  dns:
    listen: "[::1]:$1"
YAML

    cp "$INIT_GATEWAY" /etc/init.d/fips-gateway
    chmod 0755 /etc/init.d/fips-gateway

    cat > /etc/rc.common <<'SHIM'
#!/bin/sh
# Stand-in for OpenWrt's rc.common: runs one of the init script's commands.
initscript="$1"
action="$2"
shift 2
. "$initscript"
case " ${EXTRA_COMMANDS:-} " in
*" $action "*) "$action" "$@" ;;
*) echo "rc.common stand-in: $action is not a command of $initscript" >&2; exit 2 ;;
esac
SHIM
    chmod 0755 /etc/rc.common

    cat > /usr/bin/fips-gateway <<'STUB'
#!/bin/sh
# Stub gateway, by $GW_STUB/mode:
#   parse     exits 1 at once, as on a config it cannot parse;
#   taken     exits 1 after two seconds without binding, as when another
#             process holds its port;
#   bind      becomes nc listening on the port, until signalled;
#   stubborn  ignores SIGTERM and runs until killed, binding nothing itself.
d=/tmp/fips-gw-stub
echo $$ > "$d/pid"
port="$(cat "$d/port")"
case "$(cat "$d/mode")" in
parse) exit 1 ;;
taken) sleep 2; exit 1 ;;
stubborn)
    trap '' TERM
    while :; do sleep 1; done
    ;;
esac
exec nc -u -l -p "$port" -s ::1 </dev/null >/dev/null 2>&1
STUB
    chmod 0755 /usr/bin/fips-gateway

    uci_seed "$DNSMASQ_OPT" "/fips/::1#5354" "/lan/192.168.1.2"
    return 0
}

remove_supervise_env() {
    rm -f /etc/rc.common /usr/bin/fips-gateway /var/run/fips-gateway.pid
    rm -rf /etc/fips "$GW_STUB" "$STUB_BIN"
    return 0
}

fips_upstream() {
    # The loopback .fips forwards dnsmasq has, sorted, on one line.
    "$STUB_BIN/uci" -q get "$DNSMASQ_OPT" | tr ' ' '\n' | grep '^/fips/' | sort | tr '\n' ' '
    return 0
}

wait_for_upstream() {
    # wait_for_upstream <port> <tenths of a second>: succeeds once dnsmasq
    # forwards .fips to ::1#<port> and nowhere else on loopback.
    n=0
    while [ "$n" -lt "$2" ]; do
        [ "$(fips_upstream)" = "/fips/::1#$1 " ] && return 0
        sleep 0.1
        n=$((n + 1))
    done
    return 1
}

start_gateway_service() {
    # Runs start_service and then, in the background, the command it gave
    # procd, with the uci and logger stubs first on PATH. Sets CMD_PID.
    (
        PATH="$STUB_BIN:$PATH"
        # shellcheck source=/dev/null
        . "$INIT_GATEWAY"
        stub_start_service_helpers keep-swap
        CONFIG=/etc/fips/fips.yaml
        start_service >/dev/null 2>&1
    )
    sed -n 's/^command //p' "$CALLS" > "$WORK/command"
    # shellcheck disable=SC2046
    set -- $(cat "$WORK/command")
    if [ $# -eq 0 ]; then
        CMD_PID=""
        bad "start_service gave procd no command: $(calls_oneline)"
        return 1
    fi
    ( PATH="$STUB_BIN:$PATH" exec "$@" ) > "$WORK/command.out" 2>&1 &
    CMD_PID=$!
    return 0
}

wait_command() {
    # wait_command: waits up to 20 s for the procd command; sets CMD_RC.
    ( sleep 20; kill -KILL "$CMD_PID" 2>/dev/null ) &
    dog=$!
    CMD_RC=0
    wait "$CMD_PID" || CMD_RC=$?
    kill "$dog" 2>/dev/null
    wait "$dog" 2>/dev/null
    return 0
}

stub_pid() {
    # stub_pid: the stub gateway's pid once it has started, else empty.
    n=0
    while [ ! -s "$GW_STUB/pid" ] && [ "$n" -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
    cat "$GW_STUB/pid" 2>/dev/null
    return 0
}

assert_gone() {
    # assert_gone <pid> <what it means>
    if [ -n "$1" ] && kill -0 "$1" 2>/dev/null; then
        bad "$2 — pid $1 is still running"
        kill -KILL "$1" 2>/dev/null
    else
        ok "$2"
    fi
    return 0
}

assert_on_daemon() {
    # assert_on_daemon <what it means>
    assert_equals "$(fips_upstream)" "/fips/::1#5354 " "$1"
    return 0
}

hold_port() {
    # hold_port <port>: an unrelated process binds the port. Sets HOLDER.
    nc -u -l -p "$1" -s ::1 </dev/null >/dev/null 2>&1 &
    HOLDER=$!
    n=0
    while ! grep -q ":$(printf '%04X' "$1") " /proc/net/udp6 && [ "$n" -lt 50 ]; do
        sleep 0.1
        n=$((n + 1))
    done
    return 0
}

scenario_supervise() {
    note "scenario 15: dnsmasq follows the gateway's life"
    unset -f sleep logger sysctl modprobe 2>/dev/null

    # 1. The gateway exits before binding, as on a config it cannot parse.
    reset_state
    install_supervise_env 5365
    echo parse > "$GW_STUB/mode"
    if start_gateway_service; then
        wait_command
        assert_on_daemon "a gateway that exits before binding leaves dnsmasq on the daemon"
        assert_not_called "dnsmasq restart" \
            "a gateway that exits before binding does not restart dnsmasq"
        if [ "$CMD_RC" -ne 0 ]; then
            ok "the gateway's failure is the exit status procd sees"
        else
            bad "the procd command exited 0 although the gateway failed"
        fi
    fi
    remove_supervise_env

    # 2. Another process holds the gateway's port, as an mDNS responder holds
    #    5353, so the gateway cannot bind it and exits.
    reset_state
    install_supervise_env 5365
    echo taken > "$GW_STUB/mode"
    hold_port 5365
    if start_gateway_service; then
        if wait_for_upstream 5365 15; then
            bad "dnsmasq was pointed at a port the gateway does not hold"
        else
            ok "dnsmasq is not pointed at a port another process holds"
        fi
        wait_command
        assert_on_daemon "a gateway whose port is taken leaves dnsmasq on the daemon"
    fi
    kill "$HOLDER" 2>/dev/null
    wait "$HOLDER" 2>/dev/null
    remove_supervise_env

    # 3. The gateway binds, then fails, as on a NAT or route setup error.
    reset_state
    install_supervise_env 5365
    echo bind > "$GW_STUB/mode"
    if start_gateway_service; then
        if wait_for_upstream 5365 100; then
            ok "dnsmasq forwards .fips to the gateway once it is listening"
        else
            bad "dnsmasq never moved to the listening gateway: $(fips_upstream)"
        fi
        kill -USR1 "$(stub_pid)" 2>/dev/null
        wait_command
        assert_on_daemon "a gateway that fails after binding hands dnsmasq back to the daemon"
        assert_equals "$(uci_sorted "$DNSMASQ_OPT")" \
            "$(sorted_words /lan/192.168.1.2 /fips/::1#5354)" \
            "the swaps keep dnsmasq's other servers"
    fi
    remove_supervise_env

    # 4. procd stops a running gateway with SIGTERM, here on its own (as when
    #    procd restarts an instance), without stop_service. Port from the config.
    reset_state
    install_supervise_env 5400
    echo bind > "$GW_STUB/mode"
    if start_gateway_service; then
        if wait_for_upstream 5400 100; then
            ok "dnsmasq follows an explicit gateway.dns.listen"
        else
            bad "dnsmasq never moved to the gateway's port 5400: $(fips_upstream)"
        fi
        gw="$(stub_pid)"
        kill -TERM "$CMD_PID" 2>/dev/null
        wait_command
        assert_equals "$CMD_RC" "143" "procd's SIGTERM reaches the gateway, which exits on it"
        assert_gone "$gw" "the gateway does not outlive the procd command"
        assert_on_daemon "a gateway stopped by SIGTERM hands dnsmasq back to the daemon"
    fi
    remove_supervise_env

    # 5. A gateway that ignores SIGTERM is killed before procd's own timeout,
    #    after which procd would kill only the supervise shell.
    reset_state
    install_supervise_env 5365
    echo stubborn > "$GW_STUB/mode"
    if start_gateway_service; then
        gw="$(stub_pid)"
        kill -TERM "$CMD_PID" 2>/dev/null
        # Tenths of a second until the gateway is gone; the supervise shell
        # reaps it at once, so kill -0 fails as soon as it dies.
        tenths=0
        while [ -n "$gw" ] && kill -0 "$gw" 2>/dev/null && [ "$tenths" -lt 100 ]; do
            sleep 0.1
            tenths=$((tenths + 1))
        done
        wait_command
        assert_equals "$CMD_RC" "137" "a gateway that ignores SIGTERM is killed"
        assert_gone "$gw" "a gateway that ignores SIGTERM does not outlive the procd command"
        if [ "$tenths" -lt 45 ]; then
            ok "it is killed inside procd's 5 s stop timeout (after ${tenths} tenths of a second)"
        else
            bad "it was killed after ${tenths} tenths of a second, too close to or past procd's 5 s"
        fi
        assert_on_daemon "a killed gateway hands dnsmasq back to the daemon"
    fi
    remove_supervise_env

    # 6. The swap back after a gateway exits is skipped only when the gateway
    #    procd started in its place, named in the pid file, holds the port.
    reset_state
    install_uci_stub
    (
        PATH="$STUB_BIN:$PATH"
        # shellcheck source=/dev/null
        . "$INIT_GATEWAY"
        mkdir -p /var/run
        hold_port 5365
        uci_seed "$DNSMASQ_OPT" "/fips/::1#5365"
        echo "$HOLDER" > "$GW_PIDFILE"
        gateway_dns_release 5365 99999 >/dev/null 2>&1
        fips_upstream > "$WORK/successor"
        echo 99998 > "$GW_PIDFILE"
        gateway_dns_release 5365 99999 >/dev/null 2>&1
        fips_upstream > "$WORK/other"
        kill "$HOLDER"
        wait "$HOLDER" 2>/dev/null
        rm -f "$GW_PIDFILE"
    )
    assert_file_is "$WORK/successor" "/fips/::1#5365 " \
        "the swap back is skipped while the successor gateway holds the port"
    assert_file_is "$WORK/other" "/fips/::1#5354 " \
        "the swap back happens while only some other process holds the port"
    rm -rf "$STUB_BIN"
    return 0
}

# ── 16. A package built from the SDK feed Makefile ─────────────────────────
# OpenWrt generates that package's postinst and prerm around default_postinst
# and default_prerm (package/base-files/files/lib/functions.sh, read at OpenWrt
# main and openwrt-24.10). After its own steps, default_postinst runs a loop
# over the package's init scripts: "enable" unless PKG_UPGRADE is 1, then
# "start". Under opkg the package's postinst body is sourced before that loop;
# under apk it is appended to the generated script and runs after it.
# default_prerm sources the prerm body with the generated script's own path as
# $1, then disables (on a removal) and stops each init script. The preinst is
# the package's own, run as opkg runs it ("install" or "upgrade <old>") or as
# apk runs it (versions only, PKG_UPGRADE=1 exported on an upgrade).
#
# /etc/init.d/fips is the recording stub. /etc/init.d/fips-gateway is the real
# script, run through a stand-in rc.common that keeps enablement as the
# /etc/rc.d links OpenWrt's does and records whether start_service opened a
# procd instance, which is what starting the gateway means.

install_sdk_env() {
    install_uci_stub
    printf '#!/bin/sh\nexit 0\n' > "$STUB_BIN/logger"
    chmod 0755 "$STUB_BIN/logger"
    rm -rf /etc/rc.d
    mkdir -p /etc/rc.d /etc/fips /var/run
    cp "$SHIPPED_YAML" /etc/fips/fips.yaml
    cp "$INIT_GATEWAY" /etc/init.d/fips-gateway
    chmod 0755 /etc/init.d/fips-gateway
    rm -f /var/run/fips-gateway-install-hold
    cat > /etc/rc.common <<'SHIM'
#!/bin/sh
# Stand-in for OpenWrt's rc.common: enablement as /etc/rc.d links, and start
# runs start_service with procd's calls recorded instead of made.
initscript="$1"
action="$2"
shift 2
name="${initscript##*/}"
enable() { ln -sf "../init.d/$name" "/etc/rc.d/S${START}$name"; ln -sf "../init.d/$name" "/etc/rc.d/K${STOP}$name"; }
disable() { rm -f /etc/rc.d/S??"$name" /etc/rc.d/K??"$name"; }
enabled() { [ -L "/etc/rc.d/S${START}$name" ]; }
procd_open_instance() { echo "$name instance" >> "$CALLS"; }
procd_set_param() { :; }
procd_close_instance() { :; }
stop_service() { :; }
. "$initscript"
sysctl() { :; }
modprobe() { :; }
gateway_add_global_prefix() { :; }
gateway_add_ra_route() { :; }
stop_service() { :; }
echo "$name $action" >> "$CALLS"
case "$action" in
start) start_service ;;
stop) stop_service ;;
*) "$action" "$@" ;;
esac
SHIM
    chmod 0755 /etc/rc.common
    return 0
}

remove_sdk_env() {
    rm -rf /etc/rc.d /etc/fips "$STUB_BIN"
    rm -f /etc/rc.common /var/run/fips-gateway-install-hold
    return 0
}

sdk_loop() {
    # The init-script loop of default_postinst.
    for i in /etc/init.d/fips /etc/init.d/fips-gateway; do
        if [ "${PKG_UPGRADE:-0}" != "1" ]; then
            "$i" enable
        fi
        "$i" start
    done
    return 0
}

sdk_postinst() {
    # sdk_postinst ipk|apk
    if [ "$1" = "ipk" ]; then
        ( set -- /usr/lib/opkg/info/fips.postinst configure; . "$POSTINST" ) >/dev/null 2>&1
        sdk_loop >/dev/null 2>&1
    else
        sdk_loop >/dev/null 2>&1
        sh "$POSTINST" 2.0-r1 >/dev/null 2>&1
    fi
    return 0
}

sdk_prerm_upgrade_ipk() {
    # default_prerm for the outgoing SDK-built package on an opkg upgrade.
    ( set -- /usr/lib/opkg/info/fips.prerm upgrade 2.0-r1; . "$PRERM" ) >/dev/null 2>&1
    for i in /etc/init.d/fips /etc/init.d/fips-gateway; do
        "$i" stop >/dev/null 2>&1
    done
    return 0
}

sdk_preinst() {
    # sdk_preinst <args...>, run as a script, as opkg and apk run it.
    if [ ! -f "$PREINST" ]; then
        bad "there is no preinst at $PREINST"
        return 0
    fi
    sh "$PREINST" "$@" >/dev/null 2>&1
    return 0
}

assert_gateway() {
    # assert_gateway <enabled|disabled> <started|stopped> <case>
    if [ -L /etc/rc.d/S96fips-gateway ]; then got=enabled; else got=disabled; fi
    assert_equals "$got" "$1" "$3: fips-gateway ends $1"
    if grep -qxF "fips-gateway instance" "$CALLS"; then got=started; else got=stopped; fi
    assert_equals "$got" "$2" "$3: fips-gateway is $2"
    assert_absent /var/run/fips-gateway-install-hold "$3: no install hold is left behind"
    return 0
}

scenario_sdk_package() {
    note "scenario 16: SDK feed package, default_postinst and default_prerm"
    saved_path="$PATH"
    PATH="$STUB_BIN:$PATH"
    export PATH

    for fmt in ipk apk; do
        reset_state
        install_sdk_env
        if [ "$fmt" = "ipk" ]; then
            PKG_UPGRADE=0 sdk_preinst install
            PKG_UPGRADE=0 sdk_postinst ipk
        else
            sdk_preinst 2.0-r1
            sdk_postinst apk
        fi
        assert_called "fips start" "$fmt fresh install: the daemon is started"
        assert_file_is "$FIPS_STATE" "1" "$fmt fresh install: the daemon is enabled"
        assert_gateway disabled stopped "$fmt fresh install"
        remove_sdk_env

        for gw in enabled disabled; do
            reset_state
            install_sdk_env
            echo 1 > "$FIPS_STATE"
            [ "$gw" = "enabled" ] && /etc/init.d/fips-gateway enable >/dev/null 2>&1
            : > "$CALLS"
            if [ "$fmt" = "ipk" ]; then
                PKG_UPGRADE=1 sdk_prerm_upgrade_ipk
                PKG_UPGRADE=1 sdk_preinst upgrade 1.0-r1
                PKG_UPGRADE=1 sdk_postinst ipk
            else
                PKG_UPGRADE=1 sdk_preinst 2.0-r1 1.0-r1
                PKG_UPGRADE=1 sdk_postinst apk
            fi
            if [ "$gw" = "enabled" ]; then
                assert_gateway enabled started "$fmt upgrade, gateway enabled"
            else
                assert_gateway disabled stopped "$fmt upgrade, gateway disabled"
            fi
            assert_absent "$UPGRADE_MARKER" "$fmt upgrade, gateway $gw: the upgrade marker is removed"
            remove_sdk_env
        done
    done

    # An opkg upgrade from a released package, whose prerm disabled the
    # gateway and left no marker: the postinst body re-enables and starts it,
    # as with build-ipk.sh, which needs it to clear the hold first.
    reset_state
    install_sdk_env
    echo 1 > "$FIPS_STATE"
    /etc/init.d/fips-gateway enable >/dev/null 2>&1
    : > "$CALLS"
    PKG_UPGRADE=1 sh "$RELEASED_PRERM" upgrade 2.0-r1 >/dev/null 2>&1
    PKG_UPGRADE=1 sdk_preinst upgrade 0.5.1
    PKG_UPGRADE=1 sdk_postinst ipk
    assert_gateway enabled started "ipk upgrade from a released package"
    remove_sdk_env

    # An image build runs the scripts on the build host, with IPKG_INSTROOT
    # naming the image root: they must not touch the host at all.
    reset_state
    rm -f /var/run/fips-gateway-install-hold "$UPGRADE_MARKER"
    for pkg_upgrade in 0 1; do
        IPKG_INSTROOT=/tmp/fips-image-root PKG_UPGRADE=$pkg_upgrade sh "$PREINST" install >/dev/null 2>&1
        IPKG_INSTROOT=/tmp/fips-image-root PKG_UPGRADE=$pkg_upgrade sh "$POSTINST" configure >/dev/null 2>&1
        IPKG_INSTROOT=/tmp/fips-image-root PKG_UPGRADE=$pkg_upgrade sh "$PRERM" upgrade 2.0-r1 >/dev/null 2>&1
        IPKG_INSTROOT=/tmp/fips-image-root PKG_UPGRADE=$pkg_upgrade sh "$PRERM" remove >/dev/null 2>&1
    done
    assert_equals "$(calls_oneline)" "" "image build: no script touches the build host's services"
    assert_absent /var/run/fips-gateway-install-hold "image build: the preinst leaves no hold on the build host"
    assert_absent "$UPGRADE_MARKER" "image build: the prerm leaves no marker on the build host"

    PATH="$saved_path"
    return 0
}

echo "OpenWrt maintainer-script scenarios (shell: $(readlink -f /proc/$$/exe 2>/dev/null || echo sh))"
echo "  postinst: $POSTINST"
echo "  prerm:    $PRERM"
echo "  preinst:  $PREINST"
echo "  apk:      ${APK_SCRIPTS:-(not set)}"

scenario_fresh_install
scenario_upgrade_from_released
scenario_upgrade_enabled
scenario_upgrade_disabled
scenario_removal
scenario_config_reader
scenario_start_service_guard
scenario_apk_fresh_install
scenario_apk_upgrade_enabled
scenario_apk_upgrade_disabled
scenario_dns_port_reader
scenario_default_port_parity
scenario_swap_cleanup
scenario_listen_migration
scenario_supervise
scenario_sdk_package

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "openwrt-scripts: all $CASES checks passed"
    exit 0
fi
echo "openwrt-scripts: $FAILURES of $CASES checks failed"
exit 1
