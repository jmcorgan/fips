#!/bin/bash
# Sidecar entrypoint: WireGuard tunnel + FIPS daemon.
set -e

CONFIG="/etc/fips/fips.yaml"
WG_DIR="/etc/fips/identity/wireguard"
WG_CONF="$WG_DIR/wg0.conf"

# ── Generate WireGuard keys on first run ───────────────────────
if [ ! -f "$WG_DIR/server.key" ]; then
    echo "Generating WireGuard keypair..."
    mkdir -p "$WG_DIR"
    wg genkey | tee "$WG_DIR/server.key" | wg pubkey > "$WG_DIR/server.pub"
    chmod 600 "$WG_DIR/server.key"
fi

# Wait for client public key (written by fips-on.sh)
echo "Waiting for WireGuard client key..."
for i in $(seq 1 60); do
    if [ -f "$WG_DIR/client.pub" ]; then
        break
    fi
    sleep 0.5
done

if [ ! -f "$WG_DIR/client.pub" ]; then
    echo "WARNING: No client public key found, starting without WireGuard"
else
    SERVER_KEY=$(cat "$WG_DIR/server.key")
    CLIENT_PUB=$(cat "$WG_DIR/client.pub")

    # Write WireGuard config
    cat > "$WG_CONF" <<EOF
[Interface]
PrivateKey = $SERVER_KEY
ListenPort = 51820

[Peer]
PublicKey = $CLIENT_PUB
AllowedIPs = 10.99.0.2/32, fc00::/64
EOF

    # Bring up WireGuard
    ip link add wg0 type wireguard
    wg setconf wg0 "$WG_CONF"
    ip addr add 10.99.0.1/24 dev wg0
    ip -6 addr add fc00::1/64 dev wg0
    ip link set wg0 up

    # Enable IPv6 forwarding (fd00::/8 from wg0 → fips0)
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

    # NAT66: rewrite source of packets from wg0 to this node's FIPS address
    # so the FIPS TUN accepts them (it only processes fd00::/8 sources).
    # Responses are automatically de-NATed back to fc00::2 by conntrack.
    ip6tables -t nat -A POSTROUTING -o fips0 -s fc00::/64 -j MASQUERADE

    # Also allow WireGuard peer to send to fd00::/8 destinations
    # (AllowedIPs already permits fc00::2, add fd00::/8 for forwarded traffic)

    echo "WireGuard up: 10.99.0.1/24, fc00::1/64, port 51820 (NAT66 active)"
fi

# ── Start background services ──────────────────────────────────
dnsmasq
/usr/sbin/sshd

# ── Start FIPS ─────────────────────────────────────────────────
exec fips --config "$CONFIG"
