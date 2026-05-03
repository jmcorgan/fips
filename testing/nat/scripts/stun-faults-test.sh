#!/bin/bash
#
# STUN fault-injection integration test.
#
# Cycles the daemon through three failure modes against the existing
# in-lab STUN server, asserting graceful behavior at each step:
#
#   Phase 1 (drop)  — 100% UDP egress drop to STUN; daemon's STUN
#                     observation must time out, the daemon must log the
#                     fallback path, and it must NOT crash.
#   Phase 2 (delay) — ~5s netem delay added; rule cleared mid-phase so the
#                     next attempt succeeds. Asserts recovery.
#   Phase 3 (kill)  — STUN container fully stopped. Daemon must continue
#                     running, surface a STUN-unreachable signal in its
#                     logs / state, and not panic.
#
# Fault-injection mechanism (Approach A): faults are driven from this
# script via `docker exec` into a netns-sharing shim sidecar
# (`fips-nat-stun-fault-shim`). The shim shares the daemon's network
# namespace so `tc qdisc add dev eth0 …` rules apply to the daemon's
# egress. tc netem is preferred; falls back to iptables if tc/netem is
# unavailable in the kernel. No long-running timing logic lives in the
# shim itself; the script is the orchestrator.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$NAT_DIR/../.." && pwd)"
BUILD_SCRIPT="$ROOT_DIR/testing/scripts/build.sh"
GENERATE_SCRIPT="$SCRIPT_DIR/generate-configs.sh"

PROFILE="stun-faults"
SCENARIO="$PROFILE"
COMPOSE=(docker compose -f "$NAT_DIR/docker-compose.yml")
NODE="fips-nat-stun-fault-node"
PEER="fips-nat-stun-fault-peer"
SHIM="fips-nat-stun-fault-shim"
STUN_CONTAINER="fips-nat-stun"
STUN_HOST="172.31.10.40"
STUN_PORT=3478
DEV="eth0"

cleanup() {
    # Best-effort tc/iptables cleanup before tearing the stack down.
    docker exec "$SHIM" tc qdisc del dev "$DEV" root 2>/dev/null || true
    docker exec "$SHIM" iptables -D OUTPUT -p udp -d "$STUN_HOST" \
        --dport "$STUN_PORT" -j DROP 2>/dev/null || true
    "${COMPOSE[@]}" --profile "$PROFILE" down -v --remove-orphans \
        >/dev/null 2>&1 || true
}

trap 'echo ""; echo "stun-faults-test interrupted"; cleanup; exit 130' INT TERM

require_docker_daemon() {
    if ! docker info >/dev/null 2>&1; then
        echo "Docker daemon is not reachable; cannot run stun-faults-test" >&2
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
    echo "=== stun-faults diagnostics ==="
    for c in "$NODE" "$PEER" "$SHIM" "$STUN_CONTAINER"; do
        echo ""
        echo "--- $c: logs (last 80) ---"
        docker logs "$c" 2>&1 | tail -80 || true
    done
    echo ""
    echo "--- $SHIM: tc qdisc state ---"
    docker exec "$SHIM" tc qdisc show dev "$DEV" 2>&1 || true
    echo ""
    echo "--- $SHIM: iptables OUTPUT ---"
    docker exec "$SHIM" iptables -vnL OUTPUT 2>&1 || true
    echo ""
    echo "--- $NODE: fipsctl show status ---"
    docker exec "$NODE" fipsctl show status 2>&1 || true
    echo ""
    echo "--- $NODE: fipsctl show peers ---"
    docker exec "$NODE" fipsctl show peers 2>&1 || true
}

# Apply a UDP-egress drop rule to STUN. Tries tc netem first (so the
# daemon's send_to() calls themselves silently disappear); falls back to
# iptables if netem isn't available.
apply_drop() {
    if docker exec "$SHIM" tc qdisc add dev "$DEV" root \
            handle 1: prio 2>/dev/null \
        && docker exec "$SHIM" tc qdisc add dev "$DEV" parent 1:3 \
            handle 30: netem loss 100% 2>/dev/null \
        && docker exec "$SHIM" tc filter add dev "$DEV" protocol ip \
            parent 1:0 prio 3 u32 match ip dst "${STUN_HOST}/32" \
            match ip protocol 17 0xff flowid 1:3 2>/dev/null; then
        echo "  drop: tc netem loss 100% applied to ${STUN_HOST}"
        FAULT_MODE=tc
        return 0
    fi
    # Cleanup any partial tc state before falling back.
    docker exec "$SHIM" tc qdisc del dev "$DEV" root 2>/dev/null || true
    docker exec "$SHIM" iptables -I OUTPUT -p udp -d "$STUN_HOST" \
        --dport "$STUN_PORT" -j DROP
    echo "  drop: iptables DROP applied (tc netem unavailable)"
    FAULT_MODE=iptables
}

clear_drop() {
    if [[ "${FAULT_MODE:-}" == "tc" ]]; then
        docker exec "$SHIM" tc qdisc del dev "$DEV" root 2>/dev/null || true
    elif [[ "${FAULT_MODE:-}" == "iptables" ]]; then
        docker exec "$SHIM" iptables -D OUTPUT -p udp -d "$STUN_HOST" \
            --dport "$STUN_PORT" -j DROP 2>/dev/null || true
    fi
    FAULT_MODE=""
    echo "  drop: cleared"
}

apply_delay() {
    docker exec "$SHIM" tc qdisc add dev "$DEV" root netem delay 5000ms 2>/dev/null \
        || { echo "  delay: tc netem unavailable, skipping" >&2; return 1; }
    echo "  delay: tc netem 5000ms applied"
}

clear_delay() {
    docker exec "$SHIM" tc qdisc del dev "$DEV" root 2>/dev/null || true
    echo "  delay: cleared"
}

assert_process_alive() {
    if ! docker exec "$NODE" pidof fips >/dev/null 2>&1; then
        echo "fips daemon NOT running in $NODE" >&2
        return 1
    fi
    echo "  $NODE: fips daemon alive"
}

assert_no_panic() {
    local logs
    logs="$(docker logs "$NODE" 2>&1 || true)"
    if grep -Eq "panicked at|RUST_BACKTRACE|fatal runtime error" <<<"$logs"; then
        echo "panic detected in $NODE logs" >&2
        return 1
    fi
}

# Look for STUN-related fault evidence in the daemon's logs. The
# nostr/stun module emits "stun observation failed, falling back to
# LAN-only addresses" at debug when STUN times out. Also accept the
# generic bootstrap "timed out waiting for" / "no address for" / any
# log line containing both "stun" and ("timed out" | "fail" | "fallback"
# | "unreachable").
assert_stun_fault_observed() {
    local since="$1"  # seconds back from now
    local logs
    logs="$(docker logs --since "${since}s" "$NODE" 2>&1 || true)"
    if grep -Eiq 'stun.*(timed? ?out|fail|fallback|unreachable|no address)' <<<"$logs"; then
        echo "  $NODE: STUN fault evidence observed in logs"
        return 0
    fi
    echo "no STUN fault evidence in $NODE logs (last ${since}s)" >&2
    echo "--- recent log tail ---" >&2
    echo "$logs" | tail -40 >&2
    return 1
}

# Look for STUN observation success (debug-level) since N seconds ago.
assert_stun_success_observed() {
    local since="$1"
    local logs
    logs="$(docker logs --since "${since}s" "$NODE" 2>&1 || true)"
    if grep -Eiq 'STUN observation succeeded|STUN observed' <<<"$logs"; then
        echo "  $NODE: STUN success observed in logs"
        return 0
    fi
    echo "no STUN success evidence in $NODE logs (last ${since}s)" >&2
    return 1
}

# Pre-flight: with no fault injected, the fault-node must (a) discover
# the peer's overlay advert via the relay, and (b) successfully invoke
# the STUN client at least once. If either is missing, the rest of the
# test would only show the "no overlay advert" path — i.e. a setup bug,
# not a real fault-evidence miss. Polls up to `timeout_secs` for a
# "traversal: initiator STUN observed" or "STUN observation succeeded"
# log line in the fault-node.
preflight_assert_stun_active() {
    local timeout_secs="${1:-45}"
    local deadline=$(( SECONDS + timeout_secs ))
    while (( SECONDS < deadline )); do
        local logs
        logs="$(docker logs "$NODE" 2>&1 || true)"
        if grep -Eq 'traversal: initiator STUN observed|STUN observation succeeded' \
                <<<"$logs"; then
            echo "  $NODE: pre-flight STUN observation confirmed"
            return 0
        fi
        sleep 2
    done
    echo "pre-flight FAIL: $NODE never invoked STUN within ${timeout_secs}s" >&2
    echo "(likely cause: peer advert not yet published, or peer config wrong)" >&2
    echo "--- $NODE recent log tail ---" >&2
    docker logs "$NODE" 2>&1 | tail -40 >&2 || true
    echo "--- $PEER recent log tail ---" >&2
    docker logs "$PEER" 2>&1 | tail -40 >&2 || true
    return 1
}

run_test() {
    echo "=== stun-faults-test: setup ==="
    cleanup
    "$GENERATE_SCRIPT" "$SCENARIO"
    "${COMPOSE[@]}" --profile "$PROFILE" up -d --build --force-recreate

    # Give the daemons time to come up. Both fault-node and fault-peer
    # need to start, publish their adverts to the relay, and discover
    # each other before the fault-node will reach the STUN client.
    echo ""
    echo "--- waiting for daemons to start ---"
    sleep 10

    if ! docker exec "$NODE" pidof fips >/dev/null 2>&1; then
        dump_diagnostics
        echo "fips daemon failed to start in $NODE" >&2
        return 1
    fi
    if ! docker exec "$PEER" pidof fips >/dev/null 2>&1; then
        dump_diagnostics
        echo "fips daemon failed to start in $PEER" >&2
        return 1
    fi

    # Phase 0 / pre-flight: assert that with NO fault injected, the
    # fault-node successfully reaches the STUN client at least once.
    # Without this guard, a Phase-1 fault-evidence miss could be either
    # the real bug we're testing OR a setup bug (e.g., missing advert).
    echo ""
    echo "=== Phase 0: pre-flight — confirm STUN baseline (no faults) ==="
    if ! preflight_assert_stun_active 45; then
        dump_diagnostics
        return 1
    fi

    # Sanity dump: show the recent STUN-related lines for the operator.
    docker logs "$NODE" 2>&1 | grep -Ei 'stun|traversal' | tail -10 || true

    # IMPORTANT: STUN observation is event-driven, not periodic. The
    # daemon calls observe_traversal_addresses() once per fresh traversal
    # attempt; once the resulting reflexive address is cached, the next
    # observation does not happen until advert_refresh_secs (30 min by
    # default). To force a fresh STUN attempt during each phase, restart
    # the PEER container — fault-node sees the peer disconnect and
    # retries traversal (auto_connect with backoff), which re-invokes
    # observe_traversal_addresses() under the fault.
    #
    # Restarting fault-node itself does NOT work: the shim shares
    # fault-node's network namespace (network_mode: service:...), so a
    # fault-node restart wipes the tc/iptables rules the shim applied.
    # Restarting the peer leaves fault-node's netns + shim faults intact.

    echo ""
    echo "=== Phase 1: drop 100% UDP egress to STUN (restart peer under fault) ==="
    apply_drop
    docker restart "$PEER" >/dev/null
    local phase_start=$SECONDS
    # Wait long enough for fault-node to detect peer loss and retry.
    # Auto-connect backoff is exponential 5s base; first retry ~5s after
    # detection, second ~10s. Allow ~25s.
    sleep 25
    local phase_elapsed=$(( SECONDS - phase_start + 4 ))

    assert_process_alive            || { dump_diagnostics; return 1; }
    assert_no_panic                 || { dump_diagnostics; return 1; }
    assert_stun_fault_observed "$phase_elapsed" || {
        dump_diagnostics
        return 1
    }
    clear_drop

    echo ""
    echo "=== Phase 2: delay 5000ms then clear (peer restart for clean STUN) ==="
    if apply_delay; then
        docker restart "$PEER" >/dev/null
        # Slow STUN should eventually succeed under 5s delay.
        sleep 12
        clear_delay
        sleep 10
    else
        echo "  Phase 2 skipped (no tc netem available); proceeding to Phase 3"
    fi

    assert_process_alive || { dump_diagnostics; return 1; }
    assert_no_panic      || { dump_diagnostics; return 1; }
    # Recovery assertion: STUN must succeed at least once after the rule
    # is removed.
    if ! assert_stun_success_observed 30; then
        echo "Phase 2 recovery assertion failed (no STUN success after delay clear)" >&2
        dump_diagnostics
        return 1
    fi

    echo ""
    echo "=== Phase 3: kill STUN container, restart peer, assert survival ==="
    docker stop "$STUN_CONTAINER" >/dev/null
    docker restart "$PEER" >/dev/null
    local p3_start=$SECONDS
    sleep 25
    local p3_elapsed=$(( SECONDS - p3_start + 4 ))

    assert_process_alive            || { dump_diagnostics; return 1; }
    assert_no_panic                 || { dump_diagnostics; return 1; }
    assert_stun_fault_observed "$p3_elapsed" || {
        dump_diagnostics
        return 1
    }

    cleanup
    echo "stun-faults-test passed"
}

main() {
    require_docker_daemon
    require_test_image
    run_test
}

main "$@"
