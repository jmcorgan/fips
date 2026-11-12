#!/bin/bash
#
# Nostr open-discovery startup scenario. Opt-in: run it with
# `testing/ci-local.sh --only nostr-open-discovery`; neither local CI's default
# run nor GitHub CI runs it.
#
# A node with `policy: open` and no configured peers fills its advert cache
# at startup from the relay's replay of the adverts it already holds. The
# relay is seeded with adverts from SEED_COUNT fresh keys before the node
# starts; within WINDOW_SECS of the node's "nostr notify loop entered" line,
# its log must show "advert: peer cached" for every seeded key, and it must
# not panic.
#
# This guards the order in NostrRendezvous::start (src/nostr/runtime.rs): the
# relay pool's notification receiver is taken before the advert REQ is sent.
# Taken after it, the replay is dropped, and with no configured peers nothing
# else puts those adverts in the cache until their authors publish again.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$NAT_DIR/../.." && pwd)"
BUILD_SCRIPT="$ROOT_DIR/testing/scripts/build.sh"
GENERATE_SCRIPT="$SCRIPT_DIR/generate-configs.sh"
RELAY_LIB="$ROOT_DIR/testing/lib/relay-verdict.sh"
IMAGE_LIB="$ROOT_DIR/testing/lib/image-build.sh"
# Signs and publishes events to the relay; fed to the seed container on stdin.
PUBLISH_LIB="$ROOT_DIR/testing/lib/nostr-publish.py"

PROFILE="nostr-open-discovery"
# The one-shot publisher's own profile, so `up` of the scenario does not
# start it.
SEED_PROFILE="nostr-seed"
SCENARIO="$PROFILE"
COMPOSE=(docker compose -f "$NAT_DIR/docker-compose.yml")

# Optional extra compose-file overlay chain (colon-separated paths), as in
# nostr-relay-test.sh: ci-local.sh appends the external-network overlay so
# this suite attaches to the networks the run claimed.
if [ -n "${FIPS_NAT_EXTRA_COMPOSE:-}" ]; then
    IFS=':' read -ra _NAT_EXTRA <<< "${FIPS_NAT_EXTRA_COMPOSE}"
    for _f in "${_NAT_EXTRA[@]}"; do
        case "$_f" in
            /*) COMPOSE+=(-f "$_f") ;;
            *)  COMPOSE+=(-f "$ROOT_DIR/$_f") ;;
        esac
    done
fi

NODE="fips-nat-nostr-open-node${FIPS_CI_NAME_SUFFIX:-}"
# Claimed per run by ci-local.sh; unset renders the lab's historical address.
RELAY_HOST="${NAT_LAN_PREFIX:-172.31.10}.30"
RELAY_PORT=7777
RELAY_CONTAINER="fips-nat-relay${FIPS_CI_NAME_SUFFIX:-}"

SEED_COUNT=8
WINDOW_SECS=10

# The advert identifier is ADVERT_IDENTIFIER in src/nostr/machine/types.rs, duplicated
# here rather than derived: the node subscribes by it and refuses an advert
# whose content carries another. `next` uses `fips-overlay-v1-next`, which is
# the one line that differs between the branches' copies of this script.
ADVERT_IDENTIFIER="fips-overlay-v1"
# The kind is ADVERT_KIND in src/nostr/machine/types.rs.
ADVERT_KIND=37195
# The `app` generate-configs.sh gives the lab's nodes; a seeded advert's
# `protocol` tag must equal it.
LAB_APP="fips.nat.lab.v1"
# A Tor endpoint passes the endpoint rule, and a node with no Tor transport
# has nothing to dial it with, so the open sweep stays quiet.
SEED_ENDPOINT="fipsopendiscoveryseedxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion:443"

# shellcheck disable=SC1090
source "$RELAY_LIB"
# shellcheck disable=SC1090
source "$IMAGE_LIB"

cleanup() {
    "${COMPOSE[@]}" --profile "$PROFILE" --profile "$SEED_PROFILE" \
        down -v --remove-orphans >/dev/null 2>&1 || true
}

trap 'echo ""; echo "nostr-open-discovery-test interrupted"; cleanup; exit 130' INT TERM

require_docker_daemon() {
    if ! docker info >/dev/null 2>&1; then
        echo "Docker daemon is not reachable; cannot run nostr-open-discovery-test" >&2
        exit 1
    fi
}

require_test_image() {
    local img="${FIPS_TEST_IMAGE:-fips-test:latest}"
    if docker image inspect "$img" >/dev/null 2>&1; then
        return 0
    fi
    # As in nostr-relay-test.sh: a harness that set FIPS_TEST_IMAGE built it,
    # so a miss is an upstream failure, not something to paper over.
    if [ -n "${FIPS_TEST_IMAGE:-}" ]; then
        echo "ERROR: $img not present, and FIPS_TEST_IMAGE names the caller's own image" >&2
        echo "The harness that set it is expected to have built it." >&2
        exit 1
    fi
    echo "$img not found; building test image"
    "$BUILD_SCRIPT"
}

dump_diagnostics() {
    echo ""
    echo "=== relay verdict ==="
    relay_verdict "$RELAY_CONTAINER" || true
    echo ""
    echo "=== nostr open-discovery diagnostics ==="
    for c in "$NODE" "$RELAY_CONTAINER"; do
        echo ""
        echo "--- $c: logs (last 120) ---"
        docker logs "$c" 2>&1 | tail -120 || true
    done
}

# A container whose logs cannot be read has not been shown to be panic-free.
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

# Start the relay and STUN service only; the node starts after the seeding.
# Checked here because this runs under relay_lab_start's `||`.
start_relay() {
    "${COMPOSE[@]}" --profile "$PROFILE" up -d --no-build --force-recreate \
        relay stun || return 1
    return 0
}

# Run the publisher's container with python3 as its entrypoint.
seed_run() {
    "${COMPOSE[@]}" --profile "$SEED_PROFILE" run --rm -T nostr-seed "$@"
}

# Wait until the relay accepts TCP connections from the lab network, so the
# seeding does not race the relay's own start. A TCP probe is not a websocket
# connect and publishes nothing.
wait_relay_listening() {
    local deadline=$(( SECONDS + 30 ))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if seed_run -c 'import socket, sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 2).close()' \
                "$RELAY_HOST" "$RELAY_PORT" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "relay $RELAY_HOST:$RELAY_PORT not accepting connections after 30s" >&2
    return 1
}

# Epoch milliseconds of a docker log timestamp (RFC 3339, nanoseconds).
epoch_ms() {
    local ns
    ns="$(date -d "$1" +%s%N)" || return 1
    echo $(( ns / 1000000 ))
    return 0
}

run_test() {
    echo "=== nostr-open-discovery-test ==="
    cleanup
    "$GENERATE_SCRIPT" "$SCENARIO"

    retry_build "compose build ($PROFILE)" "${COMPOSE[@]}" --profile "$PROFILE" build
    relay_lab_start "$RELAY_CONTAINER" 0 45 start_relay cleanup || {
        dump_diagnostics
        return 1
    }
    if ! wait_relay_listening; then
        dump_diagnostics
        return 1
    fi

    echo ""
    echo "--- seeding $SEED_COUNT adverts from fresh keys ---"
    local expiration tags content seed_out
    expiration=$(( $(date +%s) + 3600 ))
    tags="[[\"d\",\"$ADVERT_IDENTIFIER\"],[\"protocol\",\"$LAB_APP\"],[\"version\",\"1\"],[\"expiration\",\"$expiration\"]]"
    content="{\"identifier\":\"$ADVERT_IDENTIFIER\",\"version\":1,\"endpoints\":[{\"transport\":\"tor\",\"addr\":\"$SEED_ENDPOINT\"}]}"
    if ! seed_out="$(seed_run - "$RELAY_HOST" "$RELAY_PORT" "seed advert" \
            "$ADVERT_KIND" "$tags" "$content" "$SEED_COUNT" < "$PUBLISH_LIB" 2>&1)"; then
        printf '%s\n' "$seed_out"
        echo "the seeding did not have every advert accepted by the relay," >&2
        echo "so the node would be judged against adverts that are not there" >&2
        dump_diagnostics
        return 1
    fi
    printf '%s\n' "$seed_out"
    local accepted
    accepted="$(grep -c '^seed advert published: accepted$' <<<"$seed_out" || true)"
    if [ "$accepted" -ne "$SEED_COUNT" ]; then
        echo "expected $SEED_COUNT accepted seed adverts, the publisher reported $accepted" >&2
        dump_diagnostics
        return 1
    fi
    # The node logs a peer by short_npub (src/nostr/runtime.rs):
    # npub1 + the first four and last four characters after it.
    local -a seeded=()
    local npub
    while read -r npub; do
        seeded+=("npub1${npub:5:4}..${npub: -4}")
    done < <(grep -o 'npub=npub1[a-z0-9]*' <<<"$seed_out" | cut -d= -f2)
    if [ "${#seeded[@]}" -ne "$SEED_COUNT" ]; then
        echo "expected $SEED_COUNT seeded npubs in the publisher's output, read ${#seeded[@]}" >&2
        dump_diagnostics
        return 1
    fi

    echo ""
    echo "--- starting the node ---"
    if ! "${COMPOSE[@]}" --profile "$PROFILE" up -d --no-build --no-deps nostr-open-node; then
        dump_diagnostics
        return 1
    fi

    local deadline=$(( SECONDS + 60 )) entered=""
    while [ "$SECONDS" -lt "$deadline" ]; do
        entered="$(docker logs --timestamps "$NODE" 2>&1 \
            | grep -m1 'nostr notify loop entered' | awk '{print $1}')" || true
        [ -n "$entered" ] && break
        sleep 0.5
    done
    if [ -z "$entered" ]; then
        echo "the node never logged \"nostr notify loop entered\" within 60s" >&2
        dump_diagnostics
        return 1
    fi
    local entered_ms window_end_ms
    entered_ms="$(epoch_ms "$entered")"
    window_end_ms=$(( entered_ms + WINDOW_SECS * 1000 ))
    echo "  notify loop entered at $entered; judging the cache over the next ${WINDOW_SECS}s"
    # Wait the window out (and a second for the log to be written).
    while [ "$(date +%s%3N)" -lt $(( window_end_ms + 1000 )) ]; do
        sleep 0.5
    done

    local logs
    if ! logs="$(docker logs --timestamps "$NODE" 2>&1)"; then
        echo "could not read the node's logs; the cache is not judged" >&2
        dump_diagnostics
        return 1
    fi
    # Distinct peers cached within the window, by their logged short npub.
    local -A cached=()
    local ts line peer
    while read -r ts line; do
        [ "$(epoch_ms "$ts")" -le "$window_end_ms" ] || continue
        peer="$(grep -o 'peer=npub1[a-z0-9]*\.\.[a-z0-9]*' <<<"$line" | cut -d= -f2)" || continue
        [ -n "$peer" ] && cached["$peer"]=1
    done < <(grep 'advert: peer cached' <<<"$logs" || true)

    local missing=0 want
    for want in "${seeded[@]}"; do
        if [ -z "${cached[$want]:-}" ]; then
            echo "  seeded $want: NOT cached within ${WINDOW_SECS}s of the notify loop" >&2
            missing=$(( missing + 1 ))
        else
            echo "  seeded $want: cached"
        fi
    done
    if [ "$missing" -ne 0 ]; then
        echo "$missing of $SEED_COUNT seeded adverts were not cached from the relay's replay" >&2
        dump_diagnostics
        return 1
    fi

    assert_no_panic "$NODE" || { dump_diagnostics; return 1; }
    assert_relay "$RELAY_CONTAINER" || return 1

    cleanup
    echo "nostr-open-discovery-test passed"
}

main() {
    require_docker_daemon
    require_test_image
    run_test
}

main "$@"
