#!/bin/bash
# FIPS sidecar entrypoint: generate config, apply iptables isolation, launch FIPS.
set -e

# --- Generate FIPS config from environment variables ---

FIPS_NSEC="${FIPS_NSEC:?FIPS_NSEC is required}"
FIPS_UDP_BIND="${FIPS_UDP_BIND:-0.0.0.0:2121}"
FIPS_TUN_MTU="${FIPS_TUN_MTU:-1280}"
FIPS_PEER_TRANSPORT="${FIPS_PEER_TRANSPORT:-udp}"

mkdir -p /etc/fips

# Build peers section
PEERS_SECTION=""
if [ -n "$FIPS_PEER_NPUB" ] && [ -n "$FIPS_PEER_ADDR" ]; then
    FIPS_PEER_ALIAS="${FIPS_PEER_ALIAS:-peer}"
    PEERS_SECTION="  - npub: \"${FIPS_PEER_NPUB}\"
    alias: \"${FIPS_PEER_ALIAS}\"
    addresses:
      - transport: ${FIPS_PEER_TRANSPORT}
        addr: \"${FIPS_PEER_ADDR}\"
    connect_policy: auto_connect"
fi

cat > /etc/fips/fips.yaml <<EOF
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
${PEERS_SECTION:-  []}
EOF

echo "Generated /etc/fips/fips.yaml"

# --- Apply iptables rules for strict network isolation ---
#
# Goal: only FIPS UDP transport (port 2121) may use eth0.
# All other eth0 traffic is dropped. fips0 and loopback are unrestricted.
# This ensures the app container (sharing this network namespace) can only
# communicate over the FIPS mesh.

# IPv4: allow only FIPS transport on eth0
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

# IPv6: allow fips0 and loopback, block eth0
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT  -i lo -j ACCEPT
ip6tables -A OUTPUT -o fips0 -j ACCEPT
ip6tables -A INPUT  -i fips0 -j ACCEPT
ip6tables -A OUTPUT -o eth0 -j DROP
ip6tables -A INPUT  -i eth0 -j DROP

echo "iptables isolation rules applied"

# --- Start dnsmasq and launch FIPS ---

dnsmasq
exec fips --config /etc/fips/fips.yaml
