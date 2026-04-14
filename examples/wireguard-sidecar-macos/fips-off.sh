#!/bin/bash
# Stop the WireGuard sidecar and restore macOS network settings.
#
# Safe to run multiple times (idempotent).
#
# Usage: ./fips-off.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST_HELPER="$SCRIPT_DIR/fips-host.sh"

run_as_real_user() {
    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" "$@"
    else
        "$@"
    fi
}

run_host_helper() {
    if [ "$(id -u)" -eq 0 ]; then
        "$HOST_HELPER" "$@"
    else
        sudo "$HOST_HELPER" "$@"
    fi
}

run_host_helper off

echo "Stopping WireGuard sidecar container..."
run_as_real_user docker compose -f "$SCRIPT_DIR/docker-compose.yml" down 2>/dev/null || true
echo "  Container stopped"

echo ""
echo "WireGuard sidecar is OFF. macOS network restored."
