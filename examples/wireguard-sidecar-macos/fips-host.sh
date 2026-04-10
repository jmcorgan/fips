#!/bin/bash
# Privileged macOS host networking helper for fips-on/off.sh.
set -euo pipefail

WG_CONF="/etc/wireguard/fips0.conf"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo"
    exit 1
fi

fix_key_perms() {
    local real_user="$1"
    local wg_dir="$2"
    local file

    for file in "$wg_dir/client.key" "$wg_dir/client.pub"; do
        [ -e "$file" ] || continue
        chown "$real_user" "$file"
        chmod 600 "$file"
    done
}

host_on() {
    local script_dir="$1"
    local wg_dir="$script_dir/identity/wireguard"
    local client_key
    local server_pub

    if [ ! -f "$wg_dir/client.key" ] || [ ! -f "$wg_dir/server.pub" ]; then
        echo "Error: missing WireGuard keys in $wg_dir"
        exit 1
    fi

    client_key="$(cat "$wg_dir/client.key")"
    server_pub="$(cat "$wg_dir/server.pub")"

    wg-quick down fips0 2>/dev/null || true

    for svc in Wi-Fi Ethernet; do
        networksetup -setsocksfirewallproxystate "$svc" off 2>/dev/null || true
    done

    echo "Configuring WireGuard tunnel..."
    mkdir -p /etc/wireguard

    cat > "$WG_CONF" <<EOF
[Interface]
PrivateKey = $client_key
Address = 10.99.0.2/24, fc00::2/64

[Peer]
PublicKey = $server_pub
Endpoint = 127.0.0.1:51820
AllowedIPs = fd00::/8, fc00::1/128, 10.99.0.1/32
PersistentKeepalive = 25
EOF

    chmod 600 "$WG_CONF"
    wg-quick up fips0

    echo "Configuring macOS DNS resolver for .fips..."
    mkdir -p /etc/resolver
    cat > /etc/resolver/fips <<EOF
nameserver 127.0.0.1
port 5354
EOF

    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
}

host_off() {
    echo "Stopping WireGuard tunnel..."
    wg-quick down fips0 2>/dev/null || true
    rm -f "$WG_CONF"
    echo "  fips0 tunnel removed"

    echo "Clearing SOCKS proxy..."
    for svc in Wi-Fi Ethernet; do
        networksetup -setsocksfirewallproxystate "$svc" off 2>/dev/null || true
    done

    echo "Removing .fips DNS resolver..."
    rm -f /etc/resolver/fips
    rmdir /etc/resolver 2>/dev/null || true

    echo "Flushing DNS cache..."
    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
}

case "${1:-}" in
    fix-key-perms)
        fix_key_perms "$2" "$3"
        ;;
    on)
        host_on "$2"
        ;;
    off)
        host_off
        ;;
    *)
        echo "Usage: $0 {fix-key-perms <user> <wg-dir>|on <script-dir>|off}"
        exit 1
        ;;
esac
