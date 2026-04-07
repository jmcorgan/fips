#!/bin/sh
# FIPS uninstall script for macOS
#
# Run with: sudo ./uninstall.sh
set -e

PLIST="/Library/LaunchDaemons/com.fips.daemon.plist"

# Require root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (sudo $0)" >&2
    exit 1
fi

echo "Uninstalling FIPS..."

# Stop and unload the service
if launchctl list com.fips.daemon >/dev/null 2>&1; then
    launchctl unload "$PLIST" 2>/dev/null || true
    echo "  Service stopped"
fi

# Remove launchd plist
rm -f "$PLIST"
echo "  Removed $PLIST"

# Remove DNS resolver
rm -f /etc/resolver/fips
dscacheutil -flushcache
killall -HUP mDNSResponder 2>/dev/null || true
echo "  Removed /etc/resolver/fips"

# Remove binaries
for bin in fips fipsctl fipstop; do
    rm -f "/usr/local/bin/$bin"
done
echo "  Removed binaries from /usr/local/bin/"

echo ""
echo "FIPS uninstalled."
echo "Config preserved at /usr/local/etc/fips/ (remove manually if desired)"
echo "Logs preserved at /usr/local/var/log/fips/ (remove manually if desired)"
