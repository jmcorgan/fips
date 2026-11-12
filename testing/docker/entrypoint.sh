#!/bin/bash
# Unified entrypoint for FIPS test containers.
#
# Mode is selected via FIPS_TEST_MODE environment variable:
#   default        — dnsmasq + sshd + iperf3 + http server + fips
#   chaos          — above + TCP ECN + ethernet interface wait + a second
#                    iperf3 server (port 5202) for UDP streams
#   sidecar        — generate config from env + iptables isolation + fips
#   tor-socks5     — dnsmasq + sshd + fips (tor daemon is separate)
#   tor-directory  — dnsmasq + tor + wait for .onion hostname + fips

set -e

MODE="${FIPS_TEST_MODE:-default}"
CONFIG="/etc/fips/fips.yaml"

# ── Common: dnsmasq ──────────────────────────────────────────────────────

start_dnsmasq() {
    dnsmasq
}

# ── Common: background services (sshd, iperf3, http) ────────────────────

start_services() {
    /usr/sbin/sshd
    # --json so a client asking for --get-server-output gets the receiver's
    # per-second intervals as JSON (the chaos stall check reads them).
    iperf3 -s -J -D
    python3 -m http.server 8000 -d /root -b :: &>/dev/null &
}

# ── Chaos: TCP ECN + ethernet wait ──────────────────────────────────────

start_udpserver() {
    # A second iperf3 server, for the constant-rate UDP stream the chaos
    # traffic generator can run beside a TCP session (traffic.udp_mbps):
    # one server runs one test at a time.
    iperf3 -s -J -p 5202 -D
}

# The chaos harness writes this container's boot id (below) to VETH_READY
# when it has finished setting up the container's veths and applied their
# initial netem, after the first start and after every restart. The file
# outlives a restart, so the id is what tells this start's word from an
# earlier one's.
VETH_READY=/tmp/fips-veth-ready
IFACE_WAIT_SECS=600

# This start of the container: PID 1's start time, in clock ticks since the
# host booted (field 22 of /proc/1/stat). The harness reads the same field.
bootid() {
    awk '{print $22}' /proc/1/stat
}

enable_ecn() {
    sysctl -w net.ipv4.tcp_ecn=1 >/dev/null 2>&1 || true
}

wait_for_ethernet() {
    # If config binds any transport to an interface (Ethernet, or a UDP
    # instance with `interface:`), wait for the harness to say it is done
    # with this container (VETH_READY, above). Veth pairs are created from
    # the host after the container starts, and a UDP instance bound to an
    # interface that is not there yet fails to start. The harness also
    # applies its netem only once the veths exist, and a daemon started
    # before that takes round trips no shaped link would give: unshaped,
    # every path reads under a millisecond, and the path machine keeps its
    # least round trip for a minute. So the word, not the interfaces being
    # up, is what starts the daemon.
    #
    # Ready means `ip link show dev <name> up` lists it, not that
    # /sys/class/net/<name> exists. The harness renames a veth end to its
    # final name, and sysfs shows the new name several milliseconds before
    # the kernel can bind a socket to it by that name (SO_BINDTODEVICE gets
    # ENODEV meanwhile); `ip` looks the name up as the bind does. The
    # harness sets the interface up last, after the rename and the address.
    #
    # An interface still missing when the word comes is not coming: a
    # restored node whose neighbour churn has stopped. The wait has no fixed
    # bound tied to how long setup takes, because setup is a run of docker
    # calls whose time follows the host's load (37 to 41 s for one pair has
    # been seen against the 30 s this wait used to allow). IFACE_WAIT_SECS
    # is a backstop for a harness that never says, not a bound on setup.
    local eth_ifaces=""
    eth_ifaces=$(grep '^\s*interface:' "$CONFIG" 2>/dev/null \
        | sed 's/.*interface:\s*//' \
        | tr -d ' "' || true)

    if [ -n "$eth_ifaces" ]; then
        echo "Waiting for interfaces to be up and the harness ready: $eth_ifaces"
        local boot missing iface
        boot=$(bootid)
        local deadline=$((SECONDS + IFACE_WAIT_SECS))
        while true; do
            missing=""
            for iface in $eth_ifaces; do
                if [ -z "$(ip -o link show dev "$iface" up 2>/dev/null)" ]; then
                    missing="$missing $iface"
                fi
            done
            if [ "$(cat "$VETH_READY" 2>/dev/null)" = "$boot" ]; then
                if [ -z "$missing" ]; then
                    echo "All interfaces up and the harness ready after ${SECONDS}s"
                else
                    echo "Veth setup finished with interfaces not up:$missing"
                fi
                return 0
            fi
            if [ $SECONDS -ge $deadline ]; then
                echo "WARNING: Timed out waiting for interfaces to be up:$missing"
                return 0
            fi
            sleep 0.2
        done
    fi
}

# ── Sidecar: config generation + iptables isolation ─────────────────────

generate_sidecar_config() {
    FIPS_NSEC="${FIPS_NSEC:?FIPS_NSEC is required}"
    FIPS_UDP_BIND="${FIPS_UDP_BIND:-0.0.0.0:2121}"
    FIPS_TUN_MTU="${FIPS_TUN_MTU:-1280}"
    FIPS_PEER_TRANSPORT="${FIPS_PEER_TRANSPORT:-udp}"

    mkdir -p /etc/fips

    local peers_section=""
    if [ -n "$FIPS_PEER_NPUB" ] && [ -n "$FIPS_PEER_ADDR" ]; then
        FIPS_PEER_ALIAS="${FIPS_PEER_ALIAS:-peer}"
        peers_section="  - npub: \"${FIPS_PEER_NPUB}\"
    alias: \"${FIPS_PEER_ALIAS}\"
    addresses:
      - transport: ${FIPS_PEER_TRANSPORT}
        addr: \"${FIPS_PEER_ADDR}\"
    connect_policy: auto_connect"
    fi

    cat > "$CONFIG" <<EOF
node:
  identity:
    nsec: "${FIPS_NSEC}"

tun:
  enabled: true
  name: fips0
  mtu: ${FIPS_TUN_MTU}

dns:
  enabled: true

transports:
  udp:
    bind_addr: "${FIPS_UDP_BIND}"
    mtu: 1472
  tcp: {}

peers:
${peers_section:-  []}
EOF

    echo "Generated $CONFIG"
}

apply_iptables_isolation() {
    # Only FIPS transport (UDP 2121, TCP 443) may use eth0.
    # All other eth0 traffic is dropped. fips0 and loopback unrestricted.
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A INPUT  -i lo -j ACCEPT
    iptables -A OUTPUT -o eth0 -p udp --dport 2121 -j ACCEPT
    iptables -A OUTPUT -o eth0 -p udp --sport 2121 -j ACCEPT
    iptables -A INPUT  -i eth0 -p udp --dport 2121 -j ACCEPT
    iptables -A INPUT  -i eth0 -p udp --sport 2121 -j ACCEPT
    iptables -A OUTPUT -o eth0 -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT  -i eth0 -p tcp --sport 443 -j ACCEPT
    iptables -A OUTPUT -o eth0 -j DROP
    iptables -A INPUT  -i eth0 -j DROP

    ip6tables -A OUTPUT -o lo -j ACCEPT
    ip6tables -A INPUT  -i lo -j ACCEPT
    ip6tables -A OUTPUT -o fips0 -j ACCEPT
    ip6tables -A INPUT  -i fips0 -j ACCEPT
    ip6tables -A OUTPUT -o eth0 -j DROP
    ip6tables -A INPUT  -i eth0 -j DROP

    echo "iptables isolation rules applied"
}

# ── Tor directory mode: start tor + wait for hostname ────────────────────

start_tor_directory() {
    local hidden_service_dir="/var/lib/tor/fips_onion_service"
    local is_directory=false

    if grep -qE '^\s+mode:\s+"directory"' "$CONFIG" 2>/dev/null; then
        is_directory=true
    fi

    if [ "$is_directory" = true ]; then
        mkdir -p "$hidden_service_dir"
        chmod 700 "$hidden_service_dir"
    fi

    echo "Starting Tor daemon..."
    tor -f /etc/tor/torrc &

    if [ "$is_directory" = true ]; then
        local hostname_file="${hidden_service_dir}/hostname"
        echo "Waiting for Tor to create ${hostname_file}..."
        for i in $(seq 1 120); do
            if [ -f "$hostname_file" ]; then
                echo "Tor hostname file ready after ${i}s: $(cat "$hostname_file")"
                break
            fi
            sleep 1
        done
        if [ ! -f "$hostname_file" ]; then
            echo "FATAL: Tor did not create hostname file within 120s"
            exit 1
        fi
    fi
}

# ── Gateway: LAN interface and config copy ──────────────────────────────

# Print the one interface holding the IPv6 address $1. Docker may attach the
# LAN network after the container starts, so poll for up to 15 s. The rule is
# the one lan_iface uses in testing/static/scripts/gateway-test.sh: addresses
# compare as addresses, and an @ifN suffix is dropped from the name.
lanif_find() {
    local name
    for _ in $(seq 1 30); do
        if name=$(ip -6 -o addr show | python3 -c '
import ipaddress, sys
want = ipaddress.ip_address(sys.argv[1])
holders = set()
for line in sys.stdin:
    f = line.split()
    if len(f) < 4 or f[2] != "inet6":
        continue
    try:
        addr = ipaddress.ip_interface(f[3]).ip
    except ValueError:
        continue
    if addr == want:
        holders.add(f[1].split("@")[0])
if len(holders) != 1:
    sys.exit(1)
print(holders.pop())
' "$1"); then
            echo "$name"
            return 0
        fi
        sleep 0.5
    done
    echo "FATAL: no single interface holds $1" >&2
    ip -6 -o addr show >&2
    return 1
}

# Write config $2 to $3 with its lan_interface set to $1. The source is a
# read-only bind mount, so fips-gateway reads this copy instead. The image has
# no YAML parser, so the edit is line-based, and it is refused unless the
# source has exactly one lan_interface line and the result names $1 on
# exactly one. A failure leaves $3 as it was.
gwconf_write() {
    local iface="$1" src="$2" dest="$3"
    local key='^[[:space:]]*lan_interface:'
    local n
    if ! [[ "$iface" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then
        rm -f "$dest.tmp"
        echo "FATAL: invalid interface name $iface" >&2
        return 1
    fi
    n=$(grep -cE "$key" "$src") || n=0
    if [ "$n" -ne 1 ]; then
        rm -f "$dest.tmp"
        echo "FATAL: $src has $n lan_interface lines" >&2
        return 1
    fi
    # The file carries the node's nsec. The umask is set in a subshell so it
    # does not reach the daemons this script starts next.
    if ! ( umask 077 && sed -E "s/^([[:space:]]*lan_interface:).*/\1 $iface/" "$src" > "$dest.tmp" ); then
        rm -f "$dest.tmp"
        echo "FATAL: could not write $dest.tmp" >&2
        return 1
    fi
    n=$(grep -cE "$key" "$dest.tmp") || n=0
    if [ "$n" -ne 1 ] || ! grep -qE "^[[:space:]]*lan_interface: ${iface//./\\.}\$" "$dest.tmp"; then
        rm -f "$dest.tmp"
        echo "FATAL: $dest.tmp does not hold exactly one lan_interface: $iface line" >&2
        return 1
    fi
    mv -f "$dest.tmp" "$dest" || { rm -f "$dest.tmp"; return 1; }
    return 0
}

# ── Mode dispatch ────────────────────────────────────────────────────────

case "$MODE" in
    default)
        start_dnsmasq
        start_services
        exec fips --config "$CONFIG"
        ;;
    chaos)
        enable_ecn
        start_dnsmasq
        start_services
        start_udpserver
        wait_for_ethernet
        exec fips --config "$CONFIG"
        ;;
    sidecar)
        generate_sidecar_config
        apply_iptables_isolation
        start_dnsmasq
        exec fips --config "$CONFIG"
        ;;
    tor-socks5)
        start_dnsmasq
        /usr/sbin/sshd
        exec fips --config "$CONFIG"
        ;;
    tor-directory)
        start_dnsmasq
        start_tor_directory
        echo "Starting FIPS daemon..."
        exec fips --config "$CONFIG"
        ;;
    gateway)
        # No dnsmasq — gateway DNS replaces it on port 53. That resolver
        # answers only .fips names, so the container's own resolv.conf,
        # set in compose, points at Docker's resolver, where the node looks
        # up its peers' hostnames.
        start_services

        # The LAN interface is the one holding the gateway's LAN address,
        # derived at every start: Docker does not promise which ethN the LAN
        # network gets, and a restart can change it. The config's own
        # lan_interface is a placeholder; fips-gateway reads a copy that
        # names the derived interface.
        if [ -z "${FIPS_GW_LAN_ADDR:-}" ]; then
            echo "FATAL: FIPS_GW_LAN_ADDR is not set"
            exit 1
        fi
        LAN_IF=$(lanif_find "$FIPS_GW_LAN_ADDR") || exit 1
        echo "LAN interface: $LAN_IF holds $FIPS_GW_LAN_ADDR"
        gwconf_write "$LAN_IF" "$CONFIG" /etc/fips/gateway.yaml || exit 1

        # Ensure IPv6 is enabled on the LAN interface (may inherit host
        # default). The address was found on it before this runs only
        # because compose sets net.ipv6.conf.default.disable_ipv6=0 for this
        # service, so keep that sysctl if this one moves.
        sysctl -w "net.ipv6.conf.${LAN_IF}.disable_ipv6=0" >/dev/null 2>&1 || true
        sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
        sysctl -w net.ipv6.conf.all.proxy_ndp=1 >/dev/null 2>&1 || true

        # Start fips in background (gateway needs fips0)
        fips --config "$CONFIG" &
        # Wait for fips0 TUN device
        for i in $(seq 1 30); do
            [ -e /sys/class/net/fips0 ] && break
            sleep 1
        done
        if [ ! -e /sys/class/net/fips0 ]; then
            echo "FATAL: fips0 did not appear within 30s"
            exit 1
        fi

        # Wait for the daemon's DNS responder to bind [::1]:5354 before
        # exec'ing fips-gateway. The gateway binary's startup probe is
        # bounded (5 attempts × 1s with retry); this harness wait is the
        # belt to that suspenders so we get deterministic CI behaviour
        # on slow runners. Bounded to ~30 seconds; if the daemon
        # really never binds DNS, the gateway's own probe will report
        # the definitive error after this wait expires.
        for i in $(seq 1 30); do
            if dig @::1 -p 5354 +tries=1 +time=1 test.fips >/dev/null 2>&1; then
                echo "Daemon DNS ready (waited ~${i}s)"
                break
            fi
            if [ "$i" -eq 30 ]; then
                echo "WARNING: daemon DNS did not respond within ~30s; proceeding with gateway startup"
            fi
            sleep 1
        done

        echo "fips0 ready, starting gateway"
        exec fips-gateway --config /etc/fips/gateway.yaml --log-level debug
        ;;
    *)
        echo "Unknown FIPS_TEST_MODE: $MODE"
        echo "Valid modes: default, chaos, sidecar, tor-socks5, tor-directory, gateway"
        exit 1
        ;;
esac
