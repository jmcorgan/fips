#!/bin/bash
# Start the WireGuard sidecar and configure macOS to reach the mesh.
#
# Sets up:
#   1. WireGuard tunnel from macOS to the FIPS Docker container
#   2. macOS DNS resolver for .fips names
#   3. fd00::/8 routed through the WireGuard tunnel
#
# Safe to run multiple times (idempotent).
#
# Usage: ./fips-on.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IDENTITY_DIR="$SCRIPT_DIR/identity"
WG_DIR="$IDENTITY_DIR/wireguard"
HOST_HELPER="$SCRIPT_DIR/fips-host.sh"
REAL_USER="${SUDO_USER:-$USER}"

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

# ── 1. Generate persistent FIPS identity if missing ───────────
mkdir -p "$IDENTITY_DIR" "$WG_DIR"

if [ ! -f "$IDENTITY_DIR/fips.key" ]; then
    echo "Generating FIPS identity keypair..."
    run_as_real_user docker run --rm \
        --entrypoint fipsctl \
        -v "$IDENTITY_DIR:/etc/fips" \
        fips-test:latest \
        keygen --dir /etc/fips
fi

# ── 2. Generate WireGuard client keys ─────────────────────────
mkdir -p "$WG_DIR"

if [ ! -f "$WG_DIR/client.key" ]; then
    echo "Generating WireGuard client keypair..."
    run_as_real_user sh -c 'umask 077; wg genkey | tee "$1/client.key" | wg pubkey > "$1/client.pub"' sh "$WG_DIR"
elif [ ! -f "$WG_DIR/client.pub" ]; then
    echo "Regenerating WireGuard client public key..."
    run_as_real_user sh -c 'wg pubkey < "$1/client.key" > "$1/client.pub" && chmod 600 "$1/client.pub"' sh "$WG_DIR"
fi

# Keep bind-mounted client keys readable to Docker Desktop on macOS.
run_host_helper fix-key-perms "$REAL_USER" "$WG_DIR"

# ── 3. Start Docker container ─────────────────────────────────
echo "Starting WireGuard sidecar container..."
run_as_real_user docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d --build --force-recreate

echo "Waiting for container..."
for i in $(seq 1 30); do
    if run_as_real_user docker exec wireguard-sidecar wg show wg0 >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

if ! run_as_real_user docker exec wireguard-sidecar wg show wg0 >/dev/null 2>&1; then
    echo "Error: WireGuard not ready in container after 30s"
    echo "Check: docker logs wireguard-sidecar"
    exit 1
fi

if [ -f "$WG_DIR/server.pub" ]; then
    echo "  Server pubkey: $(cat "$WG_DIR/server.pub")"
fi

# ── 4. Configure host networking ──────────────────────────────
run_host_helper on "$SCRIPT_DIR"

# ── Done ──────────────────────────────────────────────────────
echo ""
echo "WireGuard sidecar is ON."
echo ""
echo "  WireGuard:  fips0 tunnel active (fd00::/8 routed)"
echo "  DNS:        .fips names resolve via localhost:5354"
echo ""
echo "Usage:"
echo "  ping6 -c3 \$(dig +short AAAA your-bootstrap-peer.fips @127.0.0.1 -p 5354)"
echo ""
echo "  docker exec wireguard-sidecar fipsctl show status"
echo "  docker exec wireguard-sidecar fipsctl show peers"
echo ""
echo "To stop: ./fips-off.sh"
