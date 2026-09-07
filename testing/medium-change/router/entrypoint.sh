#!/bin/sh
# Plain forwarder between the two access paths and the far segment.
#
# Deliberately no NAT and no firewall. This lab is about which *source
# address* a node picks, so anything that rewrites one would hide the very
# thing under test — a masquerading router would make both paths look
# identical to the far node and the bug would not reproduce.
#
# Forwarding is enabled by compose's `sysctls:`, not here: docker mounts
# /proc/sys read-only in an unprivileged container, so `sysctl -w` fails and,
# under `set -e`, takes the router down with it — leaving a topology that is
# wired correctly and forwards nothing.
set -eu

forwarding="$(cat /proc/sys/net/ipv4/ip_forward)"
if [ "$forwarding" != "1" ]; then
    echo "router: ip_forward is '$forwarding', expected 1" >&2
    echo "router: compose must set net.ipv4.ip_forward=1 for this container" >&2
    exit 1
fi

echo "router: interfaces"
ip -4 -brief addr show | sed 's/^/  /'
echo "router: forwarding enabled, no NAT"

exec sleep infinity
