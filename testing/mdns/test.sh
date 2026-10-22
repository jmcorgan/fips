#!/bin/bash
# ── mDNS LAN discovery, end to end ──────────────────────────────────────────
# Two fips daemons in separate containers on one user-defined Docker bridge,
# with LAN rendezvous on, matching scopes, no configured peers and Nostr off.
# The only way they can find each other is the mDNS advert one multicasts and
# the other browses for, so each node listing the other as an authenticated
# peer, at the other's address on this bridge, is the receive path working end
# to end.
#
# This is the coverage the unit tests in src/mdns/tests.rs cannot give. Their
# positive test needs two mDNS daemons in one process, which multicast
# loopback does not support reliably, so it is #[ignore]d; the two that run
# assert only that something was NOT seen, and would pass with the receive
# path removed. Separate containers are separate processes in separate
# network namespaces, which is the real cross-daemon path, and a user-defined
# bridge forwards link-local multicast between its containers the way a
# switch does (tested for 224.0.0.251:5353 before this harness was written).
#
# The network takes a docker-assigned subnet rather than a fixed one, so two
# concurrent runs cannot collide on address space; nothing here depends on
# the addresses beyond reading them back.
#
# Two settings exist for break-checking the harness, and leave it red when
# used; a normal run sets neither:
#   MDNS_SCOPE_B=<scope>     give node B a scope other than node A's
#   MDNS_SPLIT_BRIDGES=1     put node B on a bridge of its own
#
# Image: FIPS_TEST_IMAGE if set (ci-local.sh passes its per-run image; the
# GitHub job passes the image it built). Otherwise a minimal image is built
# from target/release, refusing binaries older than the source.
#
# Usage: ./test.sh
# Exit 0 = both nodes discovered and peered with each other. Exit 1 = they did
# not. Exit 2 = the harness could not run; never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# For CI_LABELS, the labels every resource below carries.
# shellcheck source=SCRIPTDIR/../lib/image-build.sh
. "$SCRIPT_DIR/../lib/image-build.sh"
NET_A="fips-mdns-net-$$"
NET_B="fips-mdns-net-b-$$"
NODE_A="fips-mdns-a-$$"
NODE_B="fips-mdns-b-$$"
UDP_PORT=2121
SCOPE_A="fips-mdns-test"
SCOPE_B="${MDNS_SCOPE_B:-$SCOPE_A}"
SPLIT_BRIDGES="${MDNS_SPLIT_BRIDGES:-0}"
# Seconds from both daemons running until each must list the other. mDNS
# resolution and the handshake take well under a second on a quiet host; the
# rest is headroom for a loaded CI runner.
DISCOVERY_TIMEOUT="${MDNS_DISCOVERY_TIMEOUT:-60}"
IMAGE=""
BUILT_IMAGE=""
WORK="$(mktemp -d)"

PASS=0
FAIL=0
log()  { echo "=== $*"; }
pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }

cleanup() {
    docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1
    docker network rm "$NET_A" "$NET_B" >/dev/null 2>&1
    [[ -n "$BUILT_IMAGE" ]] && docker rmi -f "$BUILT_IMAGE" >/dev/null 2>&1
    rm -rf "$WORK"
    return 0
}
trap cleanup EXIT

# Set IMAGE to FIPS_TEST_IMAGE, or build a minimal one from target/release.
resolve_image() {
    if [[ -n "${FIPS_TEST_IMAGE:-}" ]]; then
        IMAGE="$FIPS_TEST_IMAGE"
        log "Using FIPS_TEST_IMAGE=$IMAGE"
        return 0
    fi
    local bin="$REPO_ROOT/target/release"
    if [[ ! -x "$bin/fips" || ! -x "$bin/fipsctl" ]]; then
        echo "No FIPS_TEST_IMAGE and no release fips/fipsctl; build them: cargo build --release" >&2
        return 1
    fi
    # A stale daemon would give a verdict about code that is not the tree's.
    local newer
    newer="$(find "$REPO_ROOT/src" "$REPO_ROOT/core" "$REPO_ROOT/Cargo.toml" -newer "$bin/fips" -print -quit 2>/dev/null)"
    if [[ -n "$newer" ]]; then
        echo "target/release/fips is older than $newer; rebuild: cargo build --release" >&2
        return 1
    fi
    BUILT_IMAGE="fips-mdns-test:$$"
    log "Building $BUILT_IMAGE from target/release"
    local context="$WORK/context"
    mkdir -p "$context"
    cp "$bin/fips" "$bin/fipsctl" "$context/"
    cat > "$context/Dockerfile" <<'DOCKERFILE'
FROM debian:trixie-slim
# libdbus-1-3 and libsystemd0 are the daemon's dynamic dependencies.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libdbus-1-3 libsystemd0 && \
    rm -rf /var/lib/apt/lists/*
COPY fips fipsctl /usr/local/bin/
RUN chmod +x /usr/local/bin/fips /usr/local/bin/fipsctl && mkdir -p /run/fips
DOCKERFILE
    docker build -t "$BUILT_IMAGE" "${CI_LABELS[@]}" "$context" --quiet >/dev/null || return 1
    IMAGE="$BUILT_IMAGE"
    return 0
}

# write_config <file> <nsec> <scope>: LAN rendezvous on, Nostr off, no peers.
write_config() {
    cat > "$1" <<YAML
node:
  identity:
    nsec: "$2"
  rendezvous:
    nostr:
      enabled: false
    lan:
      enabled: true
      scope: "$3"

tun:
  enabled: false

dns:
  enabled: false

transports:
  udp:
    bind_addr: "0.0.0.0:$UDP_PORT"
    mtu: 1472
YAML
}

# start_node <container> <network> <config file>
start_node() {
    # fips::mdns at debug so a failed run shows what the browser saw.
    docker create --name "$1" --hostname "$1" "${CI_LABELS[@]}" --network "$2" \
        -e RUST_LOG=info,fips::mdns=debug \
        --entrypoint /usr/local/bin/fips "$IMAGE" --config /fips-mdns.yaml >/dev/null \
        && docker cp "$3" "$1:/fips-mdns.yaml" >/dev/null \
        && docker start "$1" >/dev/null
}

# wait_for_log <container> <fixed string> <timeout>: 0 once the line appears.
wait_for_log() {
    local waited=0
    while [[ $waited -lt $3 ]]; do
        docker logs "$1" 2>&1 | grep -qF "$2" && return 0
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

# peer_addr <container> <npub>: the transport address at which the node lists
# <npub> as a peer. Empty when it does not list it; status 1 when the node
# could not be asked, so a dead reader is never taken for "not yet".
peer_addr() {
    local out
    out="$(docker exec "$1" fipsctl show peers 2>/dev/null)" || return 1
    python3 -c '
import json, sys
peers = json.loads(sys.argv[1])["peers"]
print(next((p.get("transport_addr", "?") for p in peers if p["npub"] == sys.argv[2]), ""))
' "$out" "$2" 2>/dev/null
}

# container_ip <container> <network>
container_ip() {
    docker inspect -f "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$1" 2>/dev/null
}

# ─────────────────────────────────────────────────────────────────────

resolve_image || exit 2

keys_a="$(python3 "$REPO_ROOT/testing/lib/derive_keys.py" fips-mdns node-a)"
keys_b="$(python3 "$REPO_ROOT/testing/lib/derive_keys.py" fips-mdns node-b)"
nsec_a="$(sed -n 's/^nsec=//p' <<<"$keys_a")"; npub_a="$(sed -n 's/^npub=//p' <<<"$keys_a")"
nsec_b="$(sed -n 's/^nsec=//p' <<<"$keys_b")"; npub_b="$(sed -n 's/^npub=//p' <<<"$keys_b")"
if [[ -z "$nsec_a" || -z "$npub_a" || -z "$nsec_b" || -z "$npub_b" ]]; then
    echo "could not derive node keys" >&2
    exit 2
fi
write_config "$WORK/a.yaml" "$nsec_a" "$SCOPE_A"
write_config "$WORK/b.yaml" "$nsec_b" "$SCOPE_B"

net_b="$NET_A"
where="one user-defined bridge"
if [[ "$SPLIT_BRIDGES" == "1" ]]; then
    net_b="$NET_B"
    where="two separate bridges"
fi
log "Two nodes on $where, scopes '$SCOPE_A' and '$SCOPE_B'"
for net in $(printf '%s\n' "$NET_A" "$net_b" | sort -u); do
    if ! docker network create --driver bridge "${CI_LABELS[@]}" "$net" >/dev/null; then
        echo "could not create network $net" >&2
        exit 2
    fi
done
if ! start_node "$NODE_A" "$NET_A" "$WORK/a.yaml" || ! start_node "$NODE_B" "$net_b" "$WORK/b.yaml"; then
    echo "could not start the two nodes" >&2
    exit 2
fi

# Both daemons must be up with LAN discovery running before an absence of
# peers means anything: a node that never started mDNS cannot find a peer, and
# that is a setup failure, not a discovery verdict.
for node in "$NODE_A" "$NODE_B"; do
    if ! wait_for_log "$node" "lan: mDNS discovery started" 30; then
        echo "$node did not start LAN discovery; last log lines:" >&2
        docker logs "$node" 2>&1 | tail -20 >&2
        exit 2
    fi
done
pass "both daemons running with LAN discovery started"

ip_a="$(container_ip "$NODE_A" "$NET_A")"
ip_b="$(container_ip "$NODE_B" "$net_b")"
log "Waiting up to ${DISCOVERY_TIMEOUT}s for each to list the other ($NODE_A $ip_a, $NODE_B $ip_b)"
addr_ab=""; addr_ba=""; unreadable=0
for ((waited = 0; waited < DISCOVERY_TIMEOUT; waited++)); do
    addr_ab="$(peer_addr "$NODE_A" "$npub_b")" || { unreadable=$((unreadable + 1)); addr_ab=""; }
    addr_ba="$(peer_addr "$NODE_B" "$npub_a")" || { unreadable=$((unreadable + 1)); addr_ba=""; }
    [[ -n "$addr_ab" && -n "$addr_ba" ]] && break
    sleep 1
done
[[ "$unreadable" -gt 0 ]] && echo "  note: show peers could not be read $unreadable time(s) while waiting"

for row in "$NODE_A|$addr_ab|$ip_b|B" "$NODE_B|$addr_ba|$ip_a|A"; do
    IFS='|' read -r node addr want other <<<"$row"
    # transport_addr is host:port; the host must be the other node's address on
    # this bridge, which is where its advert came from.
    if [[ -z "$addr" ]]; then
        fail "$node does not list node $other as a peer after ${DISCOVERY_TIMEOUT}s"
    elif [[ "${addr%:*}" == "$want" ]]; then
        pass "$node lists node $other as an authenticated peer at $addr"
    else
        fail "$node lists node $other at $addr, not at its bridge address $want"
    fi
done

if [[ "$FAIL" -ne 0 ]]; then
    for node in "$NODE_A" "$NODE_B"; do
        echo "--- $node: lan and handshake lines"
        docker logs "$node" 2>&1 | grep -iE "lan:|mdns|handshake|peer" | tail -20
    done
fi

echo ""
echo "=== mdns: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
exit 0
