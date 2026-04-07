#!/bin/sh
# FIPS install script for macOS
#
# Installs binaries, config, DNS resolver, and launchd service.
# Run with: sudo ./install.sh
set -e

BINDIR="/usr/local/bin"
CONFDIR="/usr/local/etc/fips"
LOGDIR="/usr/local/var/log/fips"
PLIST_DIR="/Library/LaunchDaemons"
RESOLVER_DIR="/etc/resolver"

# Require root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (sudo $0)" >&2
    exit 1
fi

# Determine source directory (where this script lives)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Check for binaries
for bin in fips fipsctl fipstop; do
    if [ ! -f "$REPO_ROOT/target/release/$bin" ]; then
        echo "Error: $REPO_ROOT/target/release/$bin not found. Run 'cargo build --release' first." >&2
        exit 1
    fi
done

echo "Installing FIPS..."

# Install binaries
install -d "$BINDIR"
for bin in fips fipsctl fipstop; do
    install -m 755 "$REPO_ROOT/target/release/$bin" "$BINDIR/$bin"
    echo "  $BINDIR/$bin"
done

# Install config (don't overwrite existing)
install -d "$CONFDIR"
if [ ! -f "$CONFDIR/fips.yaml" ]; then
    install -m 600 "$REPO_ROOT/packaging/common/fips.yaml" "$CONFDIR/fips.yaml"
    echo "  $CONFDIR/fips.yaml (new)"
else
    echo "  $CONFDIR/fips.yaml (existing, not overwritten)"
fi
if [ ! -f "$CONFDIR/hosts" ]; then
    install -m 644 "$REPO_ROOT/packaging/common/hosts" "$CONFDIR/hosts"
fi

# Create log directory
install -d "$LOGDIR"
echo "  $LOGDIR/"

# Install DNS resolver for .fips domain
install -d "$RESOLVER_DIR"
cat > "$RESOLVER_DIR/fips" <<EOF
nameserver 127.0.0.1
port 5354
EOF
echo "  $RESOLVER_DIR/fips"

# Flush DNS cache so macOS picks up the new resolver file
dscacheutil -flushcache
killall -HUP mDNSResponder 2>/dev/null || true

# Install launchd plist
install -m 644 "$SCRIPT_DIR/com.fips.daemon.plist" "$PLIST_DIR/com.fips.daemon.plist"
echo "  $PLIST_DIR/com.fips.daemon.plist"

echo ""
echo "FIPS installed. To start:"
echo "  sudo launchctl load -w $PLIST_DIR/com.fips.daemon.plist"
echo ""
echo "To stop:"
echo "  sudo launchctl unload $PLIST_DIR/com.fips.daemon.plist"
echo ""
echo "Edit config: $CONFDIR/fips.yaml"
echo "View logs:   tail -f $LOGDIR/fips.log"
