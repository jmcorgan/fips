#!/usr/bin/env python3
"""Sign Nostr events with fresh keys and publish them to one relay.

Shared by the NAT-lab suites that put events on the lab's relay themselves:
nostr-relay-test.sh (a malformed advert) and nostr-open-discovery-test.sh
(adverts seeded before the node starts). Standard library only, so it runs in
any container with python3; callers feed it on stdin:

    docker exec -i <container> python3 - <args> < testing/lib/nostr-publish.py
    docker compose run --rm -T <service> - <args> < testing/lib/nostr-publish.py

Arguments: <relay-host> <relay-port> <label> <kind> <tags-json> <content>
[<count>]. Publishes <count> events (default 1), each signed by its own fresh
key, with the given kind, tags and content and created_at now. The kind and
tags stay in each caller, not here: they are what a daemon's subscription
filter matches, and they differ between branches.

Prints, per event, "publishing <label> id=<id> pubkey=<hex> npub=<npub>",
the relay's reply, and "<label> published: <verdict>". The verdict is
"accepted" only when the relay answered NIP-01 OK true for that event id.
Exit 0 when every event was accepted, 3 when any was not, 2 when the
WebSocket handshake failed.
"""

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
    """Modular inverse of a mod m."""
    return pow(a, -1, m)


def point_add(a, b):
    """Add two curve points (None is the point at infinity)."""
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
    """Multiply a curve point by the scalar k."""
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def tagged_hash(tag, data):
    """BIP-340 tagged hash."""
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + data).digest()


def schnorr_sign(msg32, secret):
    """BIP-340 signature of msg32 by secret, with fresh auxiliary randomness."""
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
    """The x-only public key of secret."""
    d0 = int.from_bytes(secret, "big")
    P_pub = scalar_mul(d0)
    return P_pub[0].to_bytes(32, "big")


def fresh_secret():
    """A random secret key in [1, N)."""
    secret = os.urandom(32)
    while int.from_bytes(secret, "big") == 0 or int.from_bytes(secret, "big") >= N:
        secret = os.urandom(32)
    return secret


# ── bech32 (BIP-173), for the npub a daemon logs ───────────────────────
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values):
    """BIP-173 checksum polymod."""
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def npub(pubkey):
    """bech32 npub of a 32-byte x-only public key."""
    acc, bits, data = 0, 0, []
    for byte in pubkey:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    hrp = "npub"
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    poly = bech32_polymod(expanded + data + [0] * 6) ^ 1
    checksum = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32[d] for d in data + checksum)


def signed_event(kind, tags, content):
    """An event of kind, tags and content, created now, by a fresh key."""
    secret = fresh_secret()
    pubkey = xonly_pubkey(secret)
    created_at = int(time.time())
    # Nostr event id = sha256(json([0, pubkey, created_at, kind, tags, content]))
    serialized = json.dumps(
        [0, pubkey.hex(), created_at, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    event_id = hashlib.sha256(serialized.encode("utf-8")).digest()
    sig = schnorr_sign(event_id, secret).hex()
    event = {
        "id": event_id.hex(),
        "pubkey": pubkey.hex(),
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig,
    }
    return event, pubkey


# ── Minimal stdlib WebSocket client (RFC 6455) ────────────────────────
def connect(relay_host, relay_port):
    """Open a WebSocket to the relay; exit 2 if the handshake fails."""
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
    return sock


def send_text(sock, msg):
    """Send msg as a single masked text frame (FIN=1, opcode=1)."""
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


def server_frame_payload(buf):
    """Return the payload of the first server frame in buf, or None."""
    # Decoded rather than pattern-matched: a payload of 91 bytes puts a
    # literal '[' in the length byte, so searching for the JSON would find
    # the header instead of the body.
    if len(buf) < 2:
        return None
    n = buf[1] & 0x7F
    off = 2
    if n == 126:
        if len(buf) < 4:
            return None
        n = struct.unpack("!H", buf[2:4])[0]
        off = 4
    elif n == 127:
        if len(buf) < 10:
            return None
        n = struct.unpack("!Q", buf[2:10])[0]
        off = 10
    if buf[1] & 0x80:
        # A server must not mask, but tolerate one that does.
        mask = buf[off:off + 4]
        off += 4
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(buf[off:off + n]))
    else:
        body = buf[off:off + n]
    return body if len(body) == n else None


def relay_verdict(reply, want_id):
    """Classify the relay's answer to our EVENT. Only "accepted" means stored."""
    payload = server_frame_payload(reply)
    if payload is None:
        return "unreadable-frame"
    try:
        msg = json.loads(payload.decode("utf-8", "replace"))
    except ValueError:
        return "unparsable-frame"
    # NIP-01: an OK is FOUR elements, ["OK", <id>, <true|false>, <message>],
    # and the message is mandatory even on success. Matching a substring such
    # as `,true]` therefore never fires against a conformant relay, which is
    # why this parses the array instead.
    if isinstance(msg, list) and len(msg) >= 3 and msg[0] == "OK" and msg[1] == want_id:
        return "accepted" if msg[2] is True else "rejected"
    if isinstance(msg, list) and msg and msg[0] == "NOTICE":
        return "notice"
    return "unrecognised-frame"


def publish(relay_host, relay_port, label, event, pubkey):
    """Publish one event on its own connection; return the relay's verdict."""
    print(
        f"publishing {label} id={event['id']} pubkey={pubkey.hex()} npub={npub(pubkey)}"
    )
    sock = connect(relay_host, relay_port)
    send_text(sock, json.dumps(["EVENT", event]))

    # The relay's verdict decides whether the event was delivered at all.
    # strfry verifies the event id and the BIP-340 signature and answers
    # ["OK",<id>,false,"invalid: ..."] on refusal; a refused event is never
    # stored and never broadcast, so no subscriber ever sees it. Reading the
    # reply and continuing regardless is what once let that pass unnoticed.
    #
    # The timeout is 10s rather than 3s: this is a loopback docker network to
    # a local relay, and a missing ack is a failure, so the margin is there to
    # keep that from becoming a flake.
    sock.settimeout(10)
    verdict = "no-ack"
    try:
        reply = sock.recv(4096)
        print("relay reply:", reply[:200])
        verdict = relay_verdict(reply, event["id"])
    except socket.timeout:
        print("relay reply: <timeout - frame sent but no ack>")

    # Polite close (opcode 0x88 = close), then drop.
    try:
        sock.sendall(bytes([0x88, 0x80]) + os.urandom(4))
    except OSError:
        pass
    sock.close()
    print(f"{label} published: {verdict}")
    return verdict


def main(argv):
    """Publish the events argv describes; exit 3 unless every one was accepted."""
    if len(argv) not in (6, 7):
        print(
            "usage: nostr-publish.py <relay-host> <relay-port> <label> <kind> "
            "<tags-json> <content> [<count>]",
            file=sys.stderr,
        )
        return 64
    relay_host, relay_port, label = argv[0], int(argv[1]), argv[2]
    kind, tags, content = int(argv[3]), json.loads(argv[4]), argv[5]
    count = int(argv[6]) if len(argv) == 7 else 1
    accepted = 0
    for _ in range(count):
        event, pubkey = signed_event(kind, tags, content)
        if publish(relay_host, relay_port, label, event, pubkey) == "accepted":
            accepted += 1
    return 0 if accepted == count else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
