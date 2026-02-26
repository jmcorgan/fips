#!/bin/bash
# Container entrypoint: start services and wait for Ethernet interfaces.
#
# If the FIPS config references Ethernet transports, wait for the
# interfaces to appear before starting the FIPS daemon. This handles
# the case where veth pairs are created from the host after the
# container starts.

set -e

# Start background services
dnsmasq
/usr/sbin/sshd
iperf3 -s -D
python3 -m http.server 8000 -d /root -b :: &>/dev/null &

CONFIG="/etc/fips/fips.yaml"

# Extract Ethernet interface names from the config file.
# Matches "interface: <name>" lines that appear under transports.ethernet.
# The sed strips the key prefix and any whitespace.
ETH_IFACES=""
if grep -q 'ethernet:' "$CONFIG" 2>/dev/null; then
    ETH_IFACES=$(grep '^\s*interface:' "$CONFIG" \
        | sed 's/.*interface:\s*//' \
        | tr -d ' ' || true)
fi

if [ -n "$ETH_IFACES" ]; then
    echo "Waiting for Ethernet interfaces: $ETH_IFACES"
    DEADLINE=$((SECONDS + 30))
    while [ $SECONDS -lt $DEADLINE ]; do
        ALL_FOUND=true
        for iface in $ETH_IFACES; do
            if [ ! -e "/sys/class/net/$iface" ]; then
                ALL_FOUND=false
                break
            fi
        done
        if $ALL_FOUND; then
            echo "All Ethernet interfaces ready"
            break
        fi
        sleep 0.2
    done
    if ! $ALL_FOUND; then
        echo "WARNING: Timed out waiting for Ethernet interfaces"
    fi
fi

exec fips --config "$CONFIG"
