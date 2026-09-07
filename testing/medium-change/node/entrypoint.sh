#!/bin/bash
# Pin this node's routing before the daemon starts.
#
# Interfaces are resolved by the subnet they carry, never by name. Docker
# assigns eth0/eth1 in an order that is not the order the networks appear in
# compose, so a name-based rule silently binds the wrong path on some hosts
# and the suite then measures nothing — the default route would already be on
# the interface the test is about to "switch" to.
set -euo pipefail

WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-30}"
# "<prefix>=<router-host-octet>" for every path this node sits on.
PRIMARY_PREFIX="${PRIMARY_PREFIX:-}"
SECONDARY_PREFIX="${SECONDARY_PREFIX:-}"
FAR_PREFIX="${FAR_PREFIX:-}"
ROUTER_OCTET="${ROUTER_OCTET:-254}"
# Which path the default route starts on: primary, secondary, or far.
DEFAULT_VIA="${DEFAULT_VIA:-primary}"

iface_for_subnet() {
    local prefix="$1"
    ip -4 -oneline addr show \
        | awk -v p="${prefix}." '$4 ~ "^"p {print $2; exit}'
}

wait_for_subnet() {
    local prefix="$1" name="$2" deadline=$((SECONDS + WAIT_TIMEOUT_SECS))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if [ -n "$(iface_for_subnet "$prefix")" ]; then
            return 0
        fi
        sleep 0.5
    done
    echo "Timed out waiting for an address on ${prefix}.0/24 (${name})" >&2
    ip -4 -brief addr show >&2 || true
    return 1
}

ip link set lo up

for spec in "primary:$PRIMARY_PREFIX" "secondary:$SECONDARY_PREFIX" "far:$FAR_PREFIX"; do
    name="${spec%%:*}"
    prefix="${spec#*:}"
    [ -n "$prefix" ] || continue
    wait_for_subnet "$prefix" "$name"
    ip link set "$(iface_for_subnet "$prefix")" up
done

# The default route. Docker installs one of its own per attached bridge; on a
# multi-homed container which one wins is not something the suite can depend
# on, so it is replaced outright rather than adjusted.
case "$DEFAULT_VIA" in
    primary)   via_prefix="$PRIMARY_PREFIX" ;;
    secondary) via_prefix="$SECONDARY_PREFIX" ;;
    far)       via_prefix="$FAR_PREFIX" ;;
    *) echo "Unknown DEFAULT_VIA: $DEFAULT_VIA" >&2; exit 1 ;;
esac
via_if="$(iface_for_subnet "$via_prefix")"
# The default route, and deliberately nothing more specific.
#
# Every off-link segment in this lab is reachable through the router, so the
# default covers them all. Adding a per-subnet route as well would be worse
# than redundant: a /24 to the far segment outranks the default, so moving the
# default would leave the path to the far node exactly where it was. The suite
# would then detect a medium change, drop the sockets, and assert against a
# peer that never actually moved.
ip route replace default via "${via_prefix}.${ROUTER_OCTET}" dev "$via_if"

echo "node: addresses"
ip -4 -brief addr show | sed 's/^/  /'
echo "node: routes"
ip -4 route | sed 's/^/  /'

exec /usr/local/bin/entrypoint.sh
