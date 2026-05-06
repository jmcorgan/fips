#!/bin/bash
#
# Nostr overlay advert publish/consume integration test.
#
# Exercises the round-trip:
#   Phase 1: A publishes overlay advert; B subscribes; B observes A's advert;
#            B dials A.
#   Phase 2: B publishes; A subscribes; reverse direction. (Both directions
#            are validated together via the bidirectional `peers` count.)
#   Phase 3: A malformed Kind-37195 advert event is published directly to
#            the relay; both consumers must reject it (parse error path)
#            without crashing — asserted via process liveness.
#
# UDP transport for v0.3.0 baseline. Tor / TCP variants out of scope here.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$NAT_DIR/../.." && pwd)"
BUILD_SCRIPT="$ROOT_DIR/testing/scripts/build.sh"
GENERATE_SCRIPT="$SCRIPT_DIR/generate-configs.sh"
WAIT_LIB="$ROOT_DIR/testing/lib/wait-converge.sh"

PROFILE="nostr-publish-consume"
SCENARIO="$PROFILE"
COMPOSE=(docker compose -f "$NAT_DIR/docker-compose.yml")
NODE_A="fips-nat-nostr-pub-a"
NODE_B="fips-nat-nostr-pub-b"
RELAY_HOST="172.31.10.30"
RELAY_PORT=7777
RELAY_CONTAINER="fips-nat-relay"

# shellcheck disable=SC1090
source "$WAIT_LIB"

cleanup() {
    "${COMPOSE[@]}" --profile "$PROFILE" down -v --remove-orphans \
        >/dev/null 2>&1 || true
}

trap 'echo ""; echo "nostr-relay-test interrupted"; cleanup; exit 130' INT TERM

require_docker_daemon() {
    if ! docker info >/dev/null 2>&1; then
        echo "Docker daemon is not reachable; cannot run nostr-relay-test" >&2
        exit 1
    fi
}

require_test_image() {
    if ! docker image inspect fips-test:latest >/dev/null 2>&1; then
        echo "fips-test:latest not found; building test image"
        "$BUILD_SCRIPT"
    fi
}

dump_diagnostics() {
    echo ""
    echo "=== nostr publish/consume diagnostics ==="
    for c in "$NODE_A" "$NODE_B" "$RELAY_CONTAINER"; do
        echo ""
        echo "--- $c: logs (last 80) ---"
        docker logs "$c" 2>&1 | tail -80 || true
    done
    for c in "$NODE_A" "$NODE_B"; do
        echo ""
        echo "--- $c: fipsctl show peers ---"
        docker exec "$c" fipsctl show peers 2>&1 || true
        echo "--- $c: fipsctl show links ---"
        docker exec "$c" fipsctl show links 2>&1 || true
    done
}

# Publish a malformed Kind-37195 (overlay-advert) event directly to the
# relay. The event is signed with a fresh ephemeral keypair (so the
# relay accepts it on the wire) but its `content` is gibberish that
# cannot deserialize as OverlayAdvert. Both consumer daemons must log a
# parse error and stay alive.
publish_malformed_advert() {
    local relay_host="$1"
    local relay_port="$2"

    docker exec "$NODE_A" python3 - "$relay_host" "$relay_port" <<'PY'
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import time

# ── Minimal secp256k1 BIP-340 (Schnorr) signer using only stdlib. ──────
# Reference: BIP-340, secp256k1 group order n / curve params.
P = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F
N = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
G = (
    0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798,
    0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8,
)


def inv(a, m=P):
    return pow(a, -1, m)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] != b[1] or a[1] == 0):
        return None
    if a == b:
        m = (3 * a[0] * a[0]) * inv(2 * a[1]) % P
    else:
        m = (b[1] - a[1]) * inv(b[0] - a[0]) % P
    x = (m * m - a[0] - b[0]) % P
    y = (m * (a[0] - x) - a[1]) % P
    return (x, y)


def scalar_mul(k, point=G):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def lift_x(x):
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else P - y)


def tagged_hash(tag, data):
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + data).digest()


def schnorr_sign(msg32, secret):
    d0 = int.from_bytes(secret, "big")
    if not (1 <= d0 < N):
        raise ValueError("invalid secret key")
    P_pub = scalar_mul(d0)
    d = d0 if P_pub[1] % 2 == 0 else N - d0
    t = (d ^ int.from_bytes(tagged_hash("BIP0340/aux", os.urandom(32)), "big"))
    t_bytes = t.to_bytes(32, "big")
    rand = tagged_hash(
        "BIP0340/nonce",
        t_bytes + P_pub[0].to_bytes(32, "big") + msg32,
    )
    k0 = int.from_bytes(rand, "big") % N
    if k0 == 0:
        raise ValueError("nonce gen failed")
    R = scalar_mul(k0)
    k = k0 if R[1] % 2 == 0 else N - k0
    e = int.from_bytes(
        tagged_hash(
            "BIP0340/challenge",
            R[0].to_bytes(32, "big") + P_pub[0].to_bytes(32, "big") + msg32,
        ),
        "big",
    ) % N
    s = (k + e * d) % N
    return R[0].to_bytes(32, "big") + s.to_bytes(32, "big")


def xonly_pubkey(secret):
    d0 = int.from_bytes(secret, "big")
    P_pub = scalar_mul(d0)
    return P_pub[0].to_bytes(32, "big")


# ── Build the malformed Kind-37195 event ───────────────────────────────
secret = os.urandom(32)
# Ensure 1 <= d < N
while int.from_bytes(secret, "big") == 0 or int.from_bytes(secret, "big") >= N:
    secret = os.urandom(32)

pubkey = xonly_pubkey(secret).hex()
created_at = int(time.time())
kind = 37195
tags = [
    ["d", "fips-overlay-v1-next"],
    ["app", "fips.nat.lab.v1"],
]
content = "this-is-not-a-valid-overlay-advert-{garbage}"

# Nostr event id = sha256(json([0, pubkey, created_at, kind, tags, content]))
serialized = json.dumps(
    [0, pubkey, created_at, kind, tags, content],
    separators=(",", ":"),
    ensure_ascii=False,
)
event_id = hashlib.sha256(serialized.encode("utf-8")).digest()
sig = schnorr_sign(event_id, secret).hex()

event = {
    "id": event_id.hex(),
    "pubkey": pubkey,
    "created_at": created_at,
    "kind": kind,
    "tags": tags,
    "content": content,
    "sig": sig,
}

msg = json.dumps(["EVENT", event])
print(f"publishing malformed advert id={event['id']} pubkey={pubkey}")

# ── Minimal stdlib WebSocket client (RFC 6455) ────────────────────────
relay_host = sys.argv[1]
relay_port = int(sys.argv[2])

sock = socket.create_connection((relay_host, relay_port), timeout=10)
key_b64 = base64.b64encode(os.urandom(16)).decode()
handshake = (
    f"GET / HTTP/1.1\r\n"
    f"Host: {relay_host}:{relay_port}\r\n"
    f"Upgrade: websocket\r\n"
    f"Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key_b64}\r\n"
    f"Sec-WebSocket-Version: 13\r\n\r\n"
)
sock.sendall(handshake.encode())

resp = b""
sock.settimeout(5)
while b"\r\n\r\n" not in resp:
    chunk = sock.recv(4096)
    if not chunk:
        break
    resp += chunk
if b" 101 " not in resp.split(b"\r\n", 1)[0]:
    print("websocket handshake failed:", resp[:200], file=sys.stderr)
    raise SystemExit(2)

# Build a single masked text frame (FIN=1, opcode=1).
payload = msg.encode("utf-8")
mask = os.urandom(4)
masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

frame = bytearray([0x81])  # FIN + text
plen = len(payload)
if plen < 126:
    frame.append(0x80 | plen)
elif plen < 65536:
    frame.append(0x80 | 126)
    frame += struct.pack("!H", plen)
else:
    frame.append(0x80 | 127)
    frame += struct.pack("!Q", plen)
frame += mask + masked
sock.sendall(bytes(frame))

# Read the relay's OK/NOTICE response (best-effort).
sock.settimeout(3)
try:
    reply = sock.recv(4096)
    print("relay reply:", reply[:200])
except socket.timeout:
    print("relay reply: <timeout — frame sent but no ack>")

# Polite close (opcode 0x88 = close), then drop.
try:
    sock.sendall(bytes([0x88, 0x80]) + os.urandom(4))
except OSError:
    pass
sock.close()
print("malformed advert published")
PY
}

assert_process_alive() {
    local container="$1"
    if ! docker exec "$container" pidof fips >/dev/null 2>&1; then
        echo "fips daemon NOT running in $container after malformed advert" >&2
        return 1
    fi
    echo "  $container: fips daemon still alive after malformed advert"
}

assert_no_panic() {
    local container="$1"
    local logs
    logs="$(docker logs "$container" 2>&1 || true)"
    if grep -Eq "panicked at|RUST_BACKTRACE|fatal runtime error" <<<"$logs"; then
        echo "panic detected in $container logs" >&2
        return 1
    fi
}

run_test() {
    echo "=== nostr-relay-test: phase 1 + 2 ==="
    cleanup
    "$GENERATE_SCRIPT" "$SCENARIO"

    "${COMPOSE[@]}" --profile "$PROFILE" up -d --build --force-recreate

    # Phase 1 + Phase 2 together: each side publishes its own advert,
    # subscribes for the other's, then dials. Bidirectional success
    # (peer count == 1 on both nodes) proves both directions of the
    # publish/consume round-trip.
    echo ""
    echo "--- waiting for bidirectional advert observation + dial ---"
    if ! wait_for_peers "$NODE_A" 1 60; then
        dump_diagnostics
        return 1
    fi
    if ! wait_for_peers "$NODE_B" 1 60; then
        dump_diagnostics
        return 1
    fi

    # shellcheck disable=SC1090
    source "$NAT_DIR/generated-configs/$SCENARIO/npubs.env"
    echo "  NPUB_A=$NPUB_A"
    echo "  NPUB_B=$NPUB_B"

    # Sanity: traffic actually flows (TUN-level reachability).
    if ! docker exec "$NODE_A" ping6 -c 3 -W 5 "${NPUB_B}.fips" >/dev/null; then
        echo "ping6 A->B failed" >&2
        dump_diagnostics
        return 1
    fi
    if ! docker exec "$NODE_B" ping6 -c 3 -W 5 "${NPUB_A}.fips" >/dev/null; then
        echo "ping6 B->A failed" >&2
        dump_diagnostics
        return 1
    fi

    echo ""
    echo "=== nostr-relay-test: phase 3 (malformed advert) ==="
    publish_malformed_advert "$RELAY_HOST" "$RELAY_PORT"

    # Give consumers a moment to ingest and reject.
    sleep 5

    assert_process_alive "$NODE_A" || { dump_diagnostics; return 1; }
    assert_process_alive "$NODE_B" || { dump_diagnostics; return 1; }
    assert_no_panic "$NODE_A"      || { dump_diagnostics; return 1; }
    assert_no_panic "$NODE_B"      || { dump_diagnostics; return 1; }

    # Existing peer link must still be healthy (consumer didn't tear
    # down on a bad advert).
    if ! docker exec "$NODE_A" ping6 -c 3 -W 5 "${NPUB_B}.fips" >/dev/null; then
        echo "ping6 A->B failed AFTER malformed-advert injection" >&2
        dump_diagnostics
        return 1
    fi

    cleanup
    echo "nostr-relay-test passed"
}

main() {
    require_docker_daemon
    require_test_image
    run_test
}

main "$@"
