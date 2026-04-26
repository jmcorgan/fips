#!/bin/bash

set -euo pipefail

NAT_MODE="${NAT_MODE:-cone}"
LAN_HOST="${LAN_HOST:?LAN_HOST is required}"
LAN_SUBNET="${LAN_SUBNET:?LAN_SUBNET is required}"
WAN_SUBNET="${WAN_SUBNET:?WAN_SUBNET is required}"
TCP_FORWARD_PORTS="${TCP_FORWARD_PORTS:-8443}"
WAN_GATEWAY="${WAN_GATEWAY:-}"

find_iface_for_subnet() {
    local subnet="$1"
    while read -r idx iface _ cidr _; do
        case "$cidr" in
            ${subnet%0/24}*)
                echo "$iface"
                return 0
                ;;
        esac
    done < <(ip -o -4 addr show)
}

wait_for_iface() {
    local if_name="$1"
    local timeout_secs="${2:-30}"
    local deadline=$((SECONDS + timeout_secs))

    while [ "$SECONDS" -lt "$deadline" ]; do
        if ip link show dev "$if_name" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done

    return 1
}

wait_for_subnet_iface() {
    local subnet="$1"
    local timeout_secs="${2:-30}"
    local deadline=$((SECONDS + timeout_secs))
    local iface=""

    while [ "$SECONDS" -lt "$deadline" ]; do
        iface="$(find_iface_for_subnet "$subnet" || true)"
        if [ -n "$iface" ]; then
            echo "$iface"
            return 0
        fi
        sleep 0.5
    done

    return 1
}

if [ -n "${LAN_IF:-}" ]; then
    wait_for_iface "$LAN_IF"
else
    LAN_IF="$(wait_for_subnet_iface "$LAN_SUBNET")"
fi

if [ -n "${WAN_IF:-}" ]; then
    wait_for_iface "$WAN_IF"
else
    WAN_IF="$(wait_for_subnet_iface "$WAN_SUBNET")"
fi

if [ -z "${LAN_IF:-}" ] || [ -z "${WAN_IF:-}" ]; then
    echo "Failed to detect LAN/WAN interfaces"
    ip -o -4 addr show
    exit 1
fi

if [ -z "$WAN_GATEWAY" ]; then
    WAN_GATEWAY="$(echo "$WAN_SUBNET" | awk -F. '{print $1 "." $2 "." $3 ".1"}')"
fi

WAN_ADDR="$(ip -o -4 addr show dev "$WAN_IF" | awk '{print $4}' | cut -d/ -f1 | head -1)"

if [ -z "$WAN_ADDR" ]; then
    echo "Failed to determine WAN IPv4 address for ${WAN_IF}"
    ip -o -4 addr show dev "$WAN_IF" || true
    exit 1
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null || true
sysctl -w "net.ipv4.conf.${LAN_IF}.rp_filter=0" >/dev/null || true
sysctl -w "net.ipv4.conf.${WAN_IF}.rp_filter=0" >/dev/null || true

ip route replace default via "$WAN_GATEWAY" dev "$WAN_IF"

iptables -F
iptables -t nat -F
iptables -P FORWARD DROP

iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT
iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

for port in $TCP_FORWARD_PORTS; do
    iptables -t nat -A PREROUTING -i "$WAN_IF" -p tcp --dport "$port" \
        -j DNAT --to-destination "${LAN_HOST}:8443"
    iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -p tcp -d "$LAN_HOST" --dport 8443 -j ACCEPT
done

case "$NAT_MODE" in
    cone)
        # Full-cone emulation for the single LAN node in this harness:
        # preserve the UDP source port on egress and forward any inbound UDP
        # on the WAN address back to the lone LAN host on the same port.
        iptables -t nat -A PREROUTING -i "$WAN_IF" -p udp -j DNAT --to-destination "$LAN_HOST"
        iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -p udp -d "$LAN_HOST" -j ACCEPT
        iptables -t nat -A POSTROUTING -s "$LAN_SUBNET" -o "$WAN_IF" -p udp \
            -j SNAT --to-source "$WAN_ADDR"
        iptables -t nat -A POSTROUTING -s "$LAN_SUBNET" -o "$WAN_IF" ! -p udp -j MASQUERADE
        ;;
    symmetric)
        iptables -t nat -A POSTROUTING -s "$LAN_SUBNET" -o "$WAN_IF" -p udp \
            -j MASQUERADE --random-fully
        iptables -t nat -A POSTROUTING -s "$LAN_SUBNET" -o "$WAN_IF" ! -p udp -j MASQUERADE
        ;;
    *)
        echo "Unknown NAT_MODE: $NAT_MODE"
        exit 1
        ;;
esac

echo "Router ready: mode=${NAT_MODE} lan_if=${LAN_IF} wan_if=${WAN_IF}"
ip route
iptables -S
iptables -t nat -S

exec tail -f /dev/null
