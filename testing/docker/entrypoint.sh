#!/bin/bash
# Unified entrypoint for FIPS test containers.
#
# Mode is selected via FIPS_TEST_MODE environment variable:
#   default        — dnsmasq + sshd + iperf3 + http server + fips
#   chaos          — above + TCP ECN + ethernet interface wait
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
    iperf3 -s -D
    python3 -m http.server 8000 -d /root -b :: &>/dev/null &
}

# ── Chaos: TCP ECN + ethernet wait ──────────────────────────────────────

enable_ecn() {
    sysctl -w net.ipv4.tcp_ecn=1 >/dev/null 2>&1 || true
}

wait_for_ethernet() {
    # If config references ethernet transports, wait for interfaces to appear.
    # Veth pairs are created from the host after the container starts.
    local eth_ifaces=""
    if grep -q 'ethernet:' "$CONFIG" 2>/dev/null; then
        eth_ifaces=$(grep '^\s*interface:' "$CONFIG" \
            | sed 's/.*interface:\s*//' \
            | tr -d ' ' || true)
    fi

    if [ -n "$eth_ifaces" ]; then
        echo "Waiting for Ethernet interfaces: $eth_ifaces"
        local deadline=$((SECONDS + 30))
        local all_found=false
        while [ $SECONDS -lt $deadline ]; do
            all_found=true
            for iface in $eth_ifaces; do
                if [ ! -e "/sys/class/net/$iface" ]; then
                    all_found=false
                    break
                fi
            done
            if $all_found; then
                echo "All Ethernet interfaces ready"
                break
            fi
            sleep 0.2
        done
        if ! $all_found; then
            echo "WARNING: Timed out waiting for Ethernet interfaces"
        fi
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
  bind_addr: "127.0.0.1"

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
    *)
        echo "Unknown FIPS_TEST_MODE: $MODE"
        echo "Valid modes: default, chaos, sidecar, tor-socks5, tor-directory"
        exit 1
        ;;
esac
