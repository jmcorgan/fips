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
# Must track generate-configs.sh's OUTPUT_DIR and the compose bind-mounts.
CONFIG_DIR="$NAT_DIR/generated-configs${FIPS_CI_NAME_SUFFIX:-}"

PROFILE="nostr-publish-consume"
SCENARIO="$PROFILE"
COMPOSE=(docker compose -f "$NAT_DIR/docker-compose.yml")

# Optional extra compose-file overlay chain (colon-separated paths), matching
# nat-test.sh. ci-local.sh appends testing/nat/docker-compose.external-net.yml
# here so this suite attaches to the networks the run already claimed; without
# the hook compose would create its own from the base file's subnet and collide
# with the run's own claim. Paths are relative to ROOT_DIR unless absolute.
if [ -n "${FIPS_NAT_EXTRA_COMPOSE:-}" ]; then
    IFS=':' read -ra _NAT_EXTRA <<< "${FIPS_NAT_EXTRA_COMPOSE}"
    for _f in "${_NAT_EXTRA[@]}"; do
        case "$_f" in
            /*) COMPOSE+=(-f "$_f") ;;
            *)  COMPOSE+=(-f "$ROOT_DIR/$_f") ;;
        esac
    done
fi

NODE_A="fips-nat-nostr-pub-a${FIPS_CI_NAME_SUFFIX:-}"
NODE_B="fips-nat-nostr-pub-b${FIPS_CI_NAME_SUFFIX:-}"
# Claimed per run by ci-local.sh; unset renders the lab's historical address.
RELAY_HOST="${NAT_LAN_PREFIX:-172.31.10}.30"
RELAY_PORT=7777
RELAY_CONTAINER="fips-nat-relay${FIPS_CI_NAME_SUFFIX:-}"

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
    local img="${FIPS_TEST_IMAGE:-fips-test:latest}"
    if docker image inspect "$img" >/dev/null 2>&1; then
        return 0
    fi
    # Building here is right for a hand run and wrong under a harness. When
    # FIPS_TEST_IMAGE is set the caller has already built the image it named, so
    # a miss means something upstream is broken; building a substitute would
    # hide that and run binaries nobody asked for.
    if [ -n "${FIPS_TEST_IMAGE:-}" ]; then
        echo "ERROR: $img not present, and FIPS_TEST_IMAGE names the caller's own image" >&2
        echo "The harness that set it is expected to have built it." >&2
        exit 1
    fi
    echo "$img not found; building test image"
    "$BUILD_SCRIPT"
}

# State the relay's own condition, in its own words, before anything else.
#
# The relay is a third-party container and it has died mid-run before: strfry
# took a SIGSEGV twelve milliseconds after both nodes had connected, and every
# symptom under that was a correct report of a dead relay — subscriptions
# dropped, no advert consumed, empty peer lists, and a run that failed on the
# peer-count wait. That verdict is indistinguishable from a product failure
# unless the relay's state is stated, and the only evidence of the real cause
# was one container-log line ninety lines above the summary. This does not
# decide the run; it says whose failure it was, in a line a reader of the
# output can find.
#
# A relay whose state or log cannot be read has not been shown to be healthy,
# so that case is reported as unestablished rather than as "not the relay".
relay_verdict() {
    local state="" status="" exit_code="" restarts="" logs=""

    state="$(docker inspect \
        -f '{{.State.Status}} {{.State.ExitCode}} {{.RestartCount}}' \
        "$RELAY_CONTAINER" 2>/dev/null)" || state=""

    if [ -z "$state" ]; then
        echo "RELAY FAILURE: $RELAY_CONTAINER is gone; whatever this run" \
             "asserted about peering happened without a relay" >&2
        return 0
    fi

    read -r status exit_code restarts <<<"$state"

    if [ "$status" != "running" ]; then
        echo "RELAY FAILURE: $RELAY_CONTAINER is $status (exit $exit_code);" \
             "the assertions in this run are downstream of that, not of the" \
             "nodes" >&2
        return 0
    fi

    if [ "${restarts:-0}" -gt 0 ]; then
        echo "RELAY FAILURE: $RELAY_CONTAINER has restarted $restarts time(s)" \
             "during this run; the nodes lost their subscriptions with it" >&2
        return 0
    fi

    if ! logs="$(docker logs "$RELAY_CONTAINER" 2>&1)"; then
        echo "RELAY HEALTH NOT ESTABLISHED: could not read" \
             "$RELAY_CONTAINER's logs, so a crash cannot be ruled in or out" >&2
        return 0
    fi

    if grep -Eq "caught a signal|SIGSEGV|SIGABRT|terminate called" <<<"$logs"; then
        echo "RELAY FAILURE: $RELAY_CONTAINER faulted during this run:" >&2
        grep -E "caught a signal|SIGSEGV|SIGABRT|terminate called" <<<"$logs" >&2
        return 0
    fi

    echo "relay: $RELAY_CONTAINER running, no fault in its log — this run's" \
         "verdict is about the nodes"
    return 1
}

dump_diagnostics() {
    echo ""
    echo "=== relay verdict ==="
    relay_verdict || true
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
# relay. The event is signed with a fresh ephemeral keypair, so the relay
# accepts it on the wire, and both consumer daemons must reject it and
# stay alive.
#
# Which rejection they take is not what the event's gibberish `content`
# suggests. `parse_overlay_advert_event` looks for the `protocol` tag
# first (src/nostr/runtime.rs:1665-1671) and this event carries only `d`
# and `app`, so it fails with `missing required protocol tag` and never
# reaches the `serde_json::from_str` at :1679. The content is therefore
# belt and braces rather than the thing under test.
#
# Neither branch logs anything: see the coverage-gap note in run_test.
publish_malformed_advert() {
    local relay_host="$1"
    local relay_port="$2"

    # `-i` is required: without it docker attaches no stdin, `python3 -` reads an
    # empty program, runs nothing and exits 0, so the stimulus is never injected.
    docker exec -i "$NODE_A" python3 - "$relay_host" "$relay_port" <<'PY'
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
# Both of these must match the consumers' subscription filter, which is
# kind + identifier and no author clause (src/nostr/runtime.rs:1042-1044).
# The literals are ADVERT_KIND and ADVERT_IDENTIFIER in src/nostr/types.rs
# and are duplicated here rather than derived, so changing either there
# silently stops this event reaching the daemons while the relay goes on
# accepting it. `next` uses `fips-overlay-v1-next`, which is the one line
# that differs between the branches' copies of this script.
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

# The relay's verdict decides whether the stimulus was delivered at all.
# strfry verifies the event id and the BIP-340 signature and answers
# ["OK",<id>,false,"invalid: ..."] on refusal; a refused event is never
# stored and never broadcast, so the consumers never see it and phase 3
# proves nothing. Reading the reply and continuing regardless is what let
# that pass unnoticed.
#
# The timeout is 10s rather than 3s: this is a loopback docker network to a
# local relay, and a missing ack is a failure below, so the margin is there
# to keep that from becoming a flake.
sock.settimeout(10)


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


verdict = "no-ack"
try:
    reply = sock.recv(4096)
    print("relay reply:", reply[:200])
    verdict = relay_verdict(reply, event_id.hex())
except socket.timeout:
    print("relay reply: <timeout - frame sent but no ack>")

# Polite close (opcode 0x88 = close), then drop.
try:
    sock.sendall(bytes([0x88, 0x80]) + os.urandom(4))
except OSError:
    pass
sock.close()
print("malformed advert published:", verdict)
if verdict != "accepted":
    raise SystemExit(3)
PY
}

assert_process_alive() {
    local container="$1"
    if ! docker exec "$container" pidof fips >/dev/null 2>&1; then
        echo "fips daemon NOT running in $container after malformed advert" >&2
        return 1
    fi
    echo "  $container: fips daemon still alive after malformed advert"
    return 0
}

# A container whose logs cannot be read has not been shown to be panic-free.
# See the companion note in stun-faults-test.sh: the previous `|| true` made
# this assertion's failure mode indistinguishable from its success condition.
assert_no_panic() {
    local container="$1"
    local logs
    if ! logs="$(docker logs "$container" 2>&1)"; then
        echo "could not read logs from $container; absence of panics is not established" >&2
        return 1
    fi
    if grep -Eq "panicked at|RUST_BACKTRACE|fatal runtime error" <<<"$logs"; then
        echo "panic detected in $container logs" >&2
        return 1
    fi
    return 0
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
    source "$CONFIG_DIR/$SCENARIO/npubs.env"
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
    # The publisher's verdict line is the evidence that the relay STORED the
    # event. Without this check the phase passes whether or not anything was
    # published: the assertions below re-test properties that phases 1 and 2
    # already established, so they all hold when the stimulus is absent.
    #
    # Accepted by the relay is one hop short of received by the consumers.
    # A daemon whose relay socket is down at that moment, or whose `d` tag no
    # longer matches the one published above, never sees a stored event and
    # this check still passes. That hop is unguarded.
    local publish_out
    if ! publish_out="$(publish_malformed_advert "$RELAY_HOST" "$RELAY_PORT" 2>&1)"; then
        printf '%s\n' "$publish_out"
        echo "malformed-advert publisher failed: nothing was published, so" >&2
        echo "phase 3 would prove nothing about ingest." >&2
        dump_diagnostics
        return 1
    fi
    printf '%s\n' "$publish_out"
    if ! grep -q "malformed advert published: accepted" <<<"$publish_out"; then
        echo "malformed-advert publisher reported no accepted relay verdict:" >&2
        echo "the relay did not store the event, so it reached no consumer" >&2
        echo "and phase 3 would prove nothing about the reject path." >&2
        dump_diagnostics
        return 1
    fi

    # Give consumers a moment to ingest and reject.
    sleep 5

    assert_process_alive "$NODE_A" || { dump_diagnostics; return 1; }
    assert_process_alive "$NODE_B" || { dump_diagnostics; return 1; }
    assert_no_panic "$NODE_A"      || { dump_diagnostics; return 1; }
    assert_no_panic "$NODE_B"      || { dump_diagnostics; return 1; }

    # Coverage gap, deliberate and not discharged: this phase asserts that
    # the daemons did not crash on the malformed advert, not that they
    # rejected it. The reject path emits no log - src/nostr/runtime.rs:755
    # discards the error with `let Ok(advert) =` and no diagnostic - so
    # there is nothing observable from outside the process to assert on.
    # Existing peer link must still be healthy (consumer didn't tear
    # down on a bad advert).
    if ! docker exec "$NODE_A" ping6 -c 3 -W 5 "${NPUB_B}.fips" >/dev/null; then
        echo "ping6 A->B failed AFTER malformed-advert injection" >&2
        dump_diagnostics
        return 1
    fi

    # A relay that faulted while the assertions still passed is a finding
    # about the relay, not about this run, so it is reported and not made a
    # failure: the suite proved what it set out to prove.
    if relay_verdict; then
        echo "NOTE: the assertions above passed despite that." >&2
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
