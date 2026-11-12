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
RELAY_LIB="$ROOT_DIR/testing/lib/relay-verdict.sh"
IMAGE_LIB="$ROOT_DIR/testing/lib/image-build.sh"
# Signs and publishes an event to the relay; fed to a container on stdin.
PUBLISH_LIB="$ROOT_DIR/testing/lib/nostr-publish.py"
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
# shellcheck disable=SC1090
source "$RELAY_LIB"
# shellcheck disable=SC1090
source "$IMAGE_LIB"

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

dump_diagnostics() {
    echo ""
    echo "=== relay verdict ==="
    relay_verdict "$RELAY_CONTAINER" || true
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
# first (src/nostr/runtime.rs:1657-1663) and this event carries only `d`
# and `app`, so it fails with `missing required protocol tag` and never
# reaches the `serde_json::from_str` at :1671. The content is therefore
# belt and braces rather than the thing under test.
#
# Neither branch logs anything: see the coverage-gap note in run_test.
publish_malformed_advert() {
    local relay_host="$1"
    local relay_port="$2"

    # Both of these must match the consumers' subscription filter, which is
    # kind + identifier and no author clause (src/nostr/runtime.rs:1041-1043).
    # The literals are ADVERT_KIND and ADVERT_IDENTIFIER in src/nostr/machine/types.rs
    # and are duplicated here rather than derived, so changing either there
    # silently stops this event reaching the daemons while the relay goes on
    # accepting it. `next` uses `fips-overlay-v1-next`, which is the one line
    # that differs between the branches' copies of this script.
    local kind=37195
    local tags='[["d","fips-overlay-v1"],["app","fips.nat.lab.v1"]]'
    local content='this-is-not-a-valid-overlay-advert-{garbage}'

    # `-i` is required: without it docker attaches no stdin, `python3 -` reads an
    # empty program, runs nothing and exits 0, so the stimulus is never injected.
    # The publisher exits non-zero unless the relay answered OK true, and prints
    # "malformed advert published: <verdict>" either way.
    docker exec -i "$NODE_A" python3 - "$relay_host" "$relay_port" \
        "malformed advert" "$kind" "$tags" "$content" < "$PUBLISH_LIB"
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

# Start the lab. The step is checked here because this runs under
# relay_lab_start's caller's `||`, where `set -e` does not stop on a failure.
start_lab() {
    "${COMPOSE[@]}" --profile "$PROFILE" up -d --no-build --force-recreate || return 1
    return 0
}

run_test() {
    echo "=== nostr-relay-test: phase 1 + 2 ==="
    cleanup
    "$GENERATE_SCRIPT" "$SCENARIO"

    # Build first, with retries, because the build pulls from registries that
    # time out now and then. The start is retried only when the relay faulted
    # in its start window, a strfry crash at the nodes' first connects that
    # reproduces with upstream's own image and config (relay-verdict.sh). A
    # start that fails for any other reason is not retried, and a relay fault
    # after the window still fails the run through assert_relay.
    retry_build "compose build ($PROFILE)" "${COMPOSE[@]}" --profile "$PROFILE" build
    relay_lab_start "$RELAY_CONTAINER" 2 45 start_lab cleanup || {
        dump_diagnostics
        return 1
    }

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

    assert_relay "$RELAY_CONTAINER" || return 1

    cleanup
    echo "nostr-relay-test passed"
}

main() {
    require_docker_daemon
    require_test_image
    run_test
}

main "$@"
