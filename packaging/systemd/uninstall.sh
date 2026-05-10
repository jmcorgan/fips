#!/usr/bin/env bash
# FIPS Uninstall Script
#
# Removes the FIPS daemon, service, and optionally configuration.
#
# Usage: sudo ./uninstall.sh [--purge]
#   --purge  Also remove /etc/fips/ and the fips system group

set -euo pipefail

PURGE=false
if [ "${1:-}" = "--purge" ]; then
    PURGE=true
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)." >&2
    exit 1
fi

# --- Stop and disable services ---
# Stop dependents (firewall, gateway, dns) before the daemon to avoid
# noisy "fips0 disappeared" cascades during the teardown.

for unit in fips-gateway.service fips-firewall.service fips-dns.service fips.service; do
    if systemctl is-active --quiet "${unit}" 2>/dev/null; then
        echo "Stopping ${unit}..."
        systemctl stop "${unit}"
    fi
    if systemctl is-enabled --quiet "${unit}" 2>/dev/null; then
        systemctl disable "${unit}"
    fi
done

# --- Remove systemd units ---

rm -f /etc/systemd/system/fips.service
rm -f /etc/systemd/system/fips-dns.service
rm -f /etc/systemd/system/fips-gateway.service
rm -f /etc/systemd/system/fips-firewall.service
rm -rf /usr/lib/fips/
systemctl daemon-reload
echo "systemd units and DNS scripts removed."

# Clean up DNS config files that fips-dns-setup may have created
rm -f /etc/systemd/dns-delegate/fips.dns-delegate
rm -f /etc/dnsmasq.d/fips.conf
rm -f /etc/NetworkManager/dnsmasq.d/fips.conf

# --- Remove tmpfiles.d entry ---

rm -f /etc/tmpfiles.d/fips.conf

# --- Remove binaries ---

rm -f /usr/local/bin/fips /usr/local/bin/fipsctl /usr/local/bin/fipstop /usr/local/bin/fips-gateway
echo "Binaries removed."

# --- Optionally remove configuration and group ---

if $PURGE; then
    echo "Purging /etc/fips/ (including identity key files)..."
    rm -rf /etc/fips/

    if getent group fips &>/dev/null; then
        groupdel fips
        echo "System group 'fips' removed."
    fi

    echo "Configuration and group removed."
else
    echo "Configuration and identity preserved at /etc/fips/"
    echo "  Use --purge to remove everything (including key files and group)."
fi

echo ""
echo "Uninstall complete."
