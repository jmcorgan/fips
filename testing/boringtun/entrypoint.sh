#!/bin/bash
# Bring up a boringtun-userspace WireGuard tunnel and then sleep
# indefinitely so the benchmark scripts can drive it via docker exec.
#
# Required env:
#   ROLE      "alice" or "bob"
#   ALICE_WG_IP  WG inner IP for alice (e.g. 10.99.0.1/24)
#   BOB_WG_IP    WG inner IP for bob (e.g. 10.99.0.2/24)
#   ALICE_PUB   alice's WG public key
#   BOB_PUB     bob's WG public key
#   ALICE_PRIV  alice's WG private key
#   BOB_PRIV    bob's WG private key
#   PEER_HOST   the other container's hostname on the docker bridge
#   PEER_PORT   the other container's WG UDP port (default 51820)
#
# boringtun-cli runs in foreground (--foreground) so wg-quick-style
# configuration is done manually via `ip`, `wg`, and `wg set`.

set -e

PORT="${PEER_PORT:-51820}"
case "$ROLE" in
    alice)
        OUR_IP="$ALICE_WG_IP"
        OUR_PRIV="$ALICE_PRIV"
        PEER_PUB="$BOB_PUB"
        ;;
    bob)
        OUR_IP="$BOB_WG_IP"
        OUR_PRIV="$BOB_PRIV"
        PEER_PUB="$ALICE_PUB"
        ;;
    *)
        echo "ROLE must be alice or bob, got '$ROLE'" >&2
        exit 1
        ;;
esac

echo "[$ROLE] starting boringtun-cli foreground on wg0"
# `--foreground` keeps the userspace driver in the container
# foreground. boringtun-cli sets WG_TUN_NAME_FILE to /tmp/wg0.name
# when --foreground; we just hardcode the device name.
boringtun-cli --foreground --disable-drop-privileges wg0 &
BORINGTUN_PID=$!

# wait for the tun device to appear
for i in $(seq 1 50); do
    if ip link show wg0 >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

echo "[$ROLE] configuring wg0 with $OUR_IP listening on $PORT"
PRIV_FILE=$(mktemp)
chmod 600 "$PRIV_FILE"
printf '%s' "$OUR_PRIV" >"$PRIV_FILE"
wg set wg0 private-key "$PRIV_FILE" listen-port "$PORT"
rm -f "$PRIV_FILE"

ip address add "$OUR_IP" dev wg0
ip link set up dev wg0

echo "[$ROLE] adding peer pubkey, endpoint $PEER_HOST:$PORT"
wg set wg0 peer "$PEER_PUB" allowed-ips 10.99.0.0/24 endpoint "$PEER_HOST:$PORT" persistent-keepalive 25

echo "[$ROLE] ready"
wg show wg0

# Park here so the container stays up; we'll run iperf3 etc via
# docker exec.
wait $BORINGTUN_PID
