#!/bin/bash

set -euo pipefail

DATA_IF="${DATA_IF:-eth0}"
ROUTE_SUBNET="${ROUTE_SUBNET:-}"
ROUTE_VIA="${ROUTE_VIA:-}"
WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-30}"
# The data interface is not there at start: setup-topology.sh moves it in after
# `docker compose up` returns, and that waits on container starts that have
# taken seconds each on a busy daemon. So it gets its own, longer bound; the
# relay and STUN waits below keep WAIT_TIMEOUT_SECS. Set here rather than in
# docker-compose.yml so the compose file stays as it is on every branch.
IFACE_WAIT_SECS="${IFACE_WAIT_SECS:-120}"
RELAY_HOST="${RELAY_HOST:-}"
RELAY_PORT="${RELAY_PORT:-7777}"
STUN_HOST="${STUN_HOST:-}"
STUN_PORT="${STUN_PORT:-3478}"

deadline=$((SECONDS + IFACE_WAIT_SECS))
while [ "$SECONDS" -lt "$deadline" ]; do
    # Captured before matching: under pipefail, grep -q exiting at the first
    # address can kill ip with SIGPIPE before it writes the next one, and
    # turn the match into a miss.
    if grep -q 'inet ' <<<"$(ip -4 addr show dev "$DATA_IF" 2>/dev/null)"; then
        break
    fi
    sleep 0.5
done

if ! grep -q 'inet ' <<<"$(ip -4 addr show dev "$DATA_IF" 2>/dev/null)"; then
    echo "Timed out after ${IFACE_WAIT_SECS}s waiting for IPv4 on ${DATA_IF}" >&2
    ip addr >&2 || true
    exit 1
fi

ip link set lo up
ip link set "$DATA_IF" up

if [ -n "$ROUTE_SUBNET" ] && [ -n "$ROUTE_VIA" ]; then
    ip route replace "$ROUTE_SUBNET" via "$ROUTE_VIA" dev "$DATA_IF"
fi

wait_for_tcp() {
    local host="$1"
    local port="$2"
    local deadline=$((SECONDS + WAIT_TIMEOUT_SECS))

    while [ "$SECONDS" -lt "$deadline" ]; do
        if nc -z -w1 "$host" "$port" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done

    return 1
}

wait_for_udp() {
    local host="$1"
    local port="$2"
    local deadline=$((SECONDS + WAIT_TIMEOUT_SECS))

    while [ "$SECONDS" -lt "$deadline" ]; do
        if printf 'probe' | nc -u -w1 "$host" "$port" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done

    return 1
}

if [ -n "$RELAY_HOST" ]; then
    wait_for_tcp "$RELAY_HOST" "$RELAY_PORT" || {
        echo "Timed out waiting for relay ${RELAY_HOST}:${RELAY_PORT}" >&2
        exit 1
    }
fi

if [ -n "$STUN_HOST" ]; then
    wait_for_udp "$STUN_HOST" "$STUN_PORT" || {
        echo "Timed out waiting for STUN ${STUN_HOST}:${STUN_PORT}" >&2
        exit 1
    }
fi

exec /usr/local/bin/entrypoint.sh
