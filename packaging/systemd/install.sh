#!/usr/bin/env bash
# FIPS Install Script
#
# Installs the FIPS mesh network daemon as a systemd service.
#
# Usage: sudo ./install.sh
#
# Files installed:
#   /usr/local/bin/fips           Daemon binary
#   /usr/local/bin/fipsctl        CLI query tool
#   /usr/local/bin/fipstop        TUI monitor
#   /etc/fips/fips.yaml           Configuration (preserved if exists)
#   /etc/fips/hosts               Host-to-npub mappings (preserved if exists)
#   /etc/systemd/system/fips.service      systemd unit
#   /etc/systemd/system/fips-dns.service  DNS routing for .fips domain

set -euo pipefail

INSTALL_PREFIX="/usr/local"
CONFIG_DIR="/etc/fips"
CONFIG_FILE="${CONFIG_DIR}/fips.yaml"
SYSTEMD_DIR="/etc/systemd/system"
FIPS_GROUP="fips"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Preflight checks ---

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)." >&2
    exit 1
fi

if [ ! -f "${SCRIPT_DIR}/fips" ]; then
    echo "Error: fips binary not found in ${SCRIPT_DIR}" >&2
    exit 1
fi

if ! command -v systemctl &>/dev/null; then
    echo "Error: systemctl not found. This script requires systemd." >&2
    exit 1
fi

if [ ! -e /dev/net/tun ]; then
    echo "Warning: /dev/net/tun not found. TUN support may not work." >&2
    echo "  Load the module with: modprobe tun" >&2
fi

# --- Create fips group for control socket access ---

if ! getent group "${FIPS_GROUP}" &>/dev/null; then
    groupadd --system "${FIPS_GROUP}"
    echo "Created system group '${FIPS_GROUP}'."
fi

# --- Install binaries ---

echo "Installing binaries to ${INSTALL_PREFIX}/bin/"
install -m 0755 "${SCRIPT_DIR}/fips" "${INSTALL_PREFIX}/bin/fips"
install -m 0755 "${SCRIPT_DIR}/fipsctl" "${INSTALL_PREFIX}/bin/fipsctl"
if [ -f "${SCRIPT_DIR}/fipstop" ]; then
    install -m 0755 "${SCRIPT_DIR}/fipstop" "${INSTALL_PREFIX}/bin/fipstop"
fi

# --- Install configuration ---

mkdir -p "${CONFIG_DIR}"

if [ -f "${CONFIG_FILE}" ]; then
    echo "Configuration exists at ${CONFIG_FILE}, not overwriting."
    install -m 0644 "${SCRIPT_DIR}/fips.yaml" "${CONFIG_DIR}/fips.yaml.template"
    echo "  New template installed as ${CONFIG_DIR}/fips.yaml.template"
else
    install -m 0600 "${SCRIPT_DIR}/fips.yaml" "${CONFIG_FILE}"
    echo "Configuration installed to ${CONFIG_FILE}"
fi

HOSTS_FILE="${CONFIG_DIR}/hosts"
if [ -f "${HOSTS_FILE}" ]; then
    echo "Hosts file exists at ${HOSTS_FILE}, not overwriting."
else
    install -m 0644 "${SCRIPT_DIR}/hosts" "${HOSTS_FILE}"
    echo "Hosts file installed to ${HOSTS_FILE}"
fi

# --- Install systemd unit ---

was_active=false
if systemctl is-active --quiet fips.service 2>/dev/null; then
    was_active=true
    echo "Stopping running fips service..."
    systemctl stop fips.service
fi

dns_was_active=false
if systemctl is-active --quiet fips-dns.service 2>/dev/null; then
    dns_was_active=true
    echo "Stopping running fips-dns service..."
    systemctl stop fips-dns.service
fi

install -m 0644 "${SCRIPT_DIR}/fips.service" "${SYSTEMD_DIR}/fips.service"
install -m 0644 "${SCRIPT_DIR}/fips-dns.service" "${SYSTEMD_DIR}/fips-dns.service"
install -d -m 0755 /usr/lib/fips
install -m 0755 "${SCRIPT_DIR}/../common/fips-dns-setup" /usr/lib/fips/fips-dns-setup
install -m 0755 "${SCRIPT_DIR}/../common/fips-dns-teardown" /usr/lib/fips/fips-dns-teardown
systemctl daemon-reload
echo "systemd units and DNS scripts installed."

# --- Configure runtime directory group ownership ---
# systemd creates /run/fips/ with RuntimeDirectory, but we need the
# group set to 'fips' so group members can access the control socket.
# Create a tmpfiles.d entry for this.

cat > /etc/tmpfiles.d/fips.conf <<'TMPFILES'
d /run/fips 0750 root fips -
TMPFILES
echo "tmpfiles.d entry created for /run/fips/ ownership."

# --- Enable service ---

systemctl enable fips.service
systemctl enable fips-dns.service
echo "Services enabled (will start on boot)."

# Restart if they were running before
if $was_active; then
    echo "Restarting fips service..."
    systemctl start fips.service
fi
if $dns_was_active; then
    echo "Restarting fips-dns service..."
    systemctl start fips-dns.service
fi

echo ""
echo "=== Installation complete ==="
echo ""
echo "Before starting the service, edit ${CONFIG_FILE}:"
echo ""
echo "  1. Set a persistent identity (if publishing npub for static peers)"
echo "     Uncomment 'persistent: true' in the identity section."
echo "     A keypair will be generated and saved on first start."
echo ""
echo "  2. Configure Ethernet transport interface (if using)"
echo "     Uncomment the ethernet section and set the interface name."
echo ""
echo "  3. Add static peers (if bootstrapping over UDP/TCP)"
echo ""
echo "Start the service:"
echo "  sudo systemctl start fips"
echo ""
echo "Monitor:"
echo "  sudo journalctl -u fips -f"
echo "  fipsctl show status"
echo "  fipstop"
echo ""
echo "To use fipsctl/fipstop without sudo, add your user to the fips group:"
echo "  sudo usermod -aG fips \$USER"
echo "  (log out and back in for group membership to take effect)"
