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
RELAY_LIB="$ROOT_DIR/testing/lib/relay-verdict.sh"
IMAGE_LIB="$ROOT_DIR/testing/lib/image-build.sh"

PROFILE="stun-faults"
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

NODE="fips-nat-stun-fault-node${FIPS_CI_NAME_SUFFIX:-}"
PEER="fips-nat-stun-fault-peer${FIPS_CI_NAME_SUFFIX:-}"
SHIM="fips-nat-stun-fault-shim${FIPS_CI_NAME_SUFFIX:-}"
STUN_CONTAINER="fips-nat-stun${FIPS_CI_NAME_SUFFIX:-}"
# The node and peer find each other through this relay's adverts, so a relay
# that died takes the pre-flight down with it; the dump states it first.
RELAY_CONTAINER="fips-nat-relay${FIPS_CI_NAME_SUFFIX:-}"
# Claimed per run by ci-local.sh; unset renders the lab's historical address.
STUN_HOST="${NAT_LAN_PREFIX:-172.31.10}.40"
STUN_PORT=3478
DEV="eth0"
# Phases 1 and 3 hold the fault until FAULTED_ATTEMPTS traversal attempts
# have ended under it at the fault-node, then SURVIVAL_TAIL_SECS more,
# before the liveness and panic checks; FAULT_WAIT_SECS from the peer's
# restart bounds both the wait for the fault evidence and that hold (the
# fixed wait those phases used before). See await_fault_then_survive.
FAULT_WAIT_SECS=25
FAULTED_ATTEMPTS=2
SURVIVAL_TAIL_SECS=3
# What a STUN fault looks like in the fault-node's log; see stun_fault_logged.
STUN_FAULT_RE='stun.*(timed? ?out|fail|fallback|unreachable|no address)'
# What a successful STUN observation looks like there. The STUN client logs it
# only when a server answered (src/nostr/stun.rs). The traversal's own
# "STUN observed" line is no evidence of success: it follows every
# observation, with reflexive=- when every server failed.
STUN_SUCCESS_RE='STUN observation succeeded'
# Phase 2 stays at least this long after clearing the delay, so the attempts
# still in flight under it, which fail after the clear, have logged their
# failures well before phase 3's evidence window opens 4 s before its restart.
P2_CLEAR_HOLD_SECS=10

cleanup() {
    # Best-effort tc/iptables cleanup before tearing the stack down.
    docker exec "$SHIM" tc qdisc del dev "$DEV" root 2>/dev/null || true
    docker exec "$SHIM" iptables -D OUTPUT -p udp -d "$STUN_HOST" \
        --dport "$STUN_PORT" -j DROP 2>/dev/null || true
    "${COMPOSE[@]}" --profile "$PROFILE" down -v --remove-orphans \
        >/dev/null 2>&1 || true
}

# shellcheck disable=SC1090
source "$RELAY_LIB"
# shellcheck disable=SC1090
source "$IMAGE_LIB"

trap 'echo ""; echo "stun-faults-test interrupted"; cleanup; exit 130' INT TERM

require_docker_daemon() {
    if ! docker info >/dev/null 2>&1; then
        echo "Docker daemon is not reachable; cannot run stun-faults-test" >&2
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
    echo "=== stun-faults diagnostics ==="
    for c in "$NODE" "$PEER" "$SHIM" "$STUN_CONTAINER" "$RELAY_CONTAINER"; do
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
    return 0
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
    return 0
}

# A container whose logs cannot be read has not been shown to be panic-free.
# The previous form read `docker logs … || true`, so an unreadable container
# yielded empty output, matched no panic pattern, and returned success — the
# assertion's failure mode was indistinguishable from its success condition.
assert_no_panic() {
    local logs
    if ! logs="$(docker logs "$NODE" 2>&1)"; then
        echo "could not read logs from $NODE; absence of panics is not established" >&2
        return 1
    fi
    if grep -Eq "panicked at|RUST_BACKTRACE|fatal runtime error" <<<"$logs"; then
        echo "panic detected in $NODE logs" >&2
        return 1
    fi
    return 0
}

# Look for STUN-related fault evidence in the daemon's logs. The
# nostr/stun module emits "stun observation failed, falling back to
# LAN-only addresses" at debug when STUN times out. Also accept the
# generic bootstrap "timed out waiting for" / "no address for" / any
# log line containing both "stun" and ("timed out" | "fail" | "fallback"
# | "unreachable"). Silent, so it can be polled; a log that cannot be read
# holds no evidence.
stun_fault_logged() {
    local since="$1"  # seconds back from now
    local logs
    logs="$(docker logs --since "${since}s" "$NODE" 2>&1 || true)"
    grep -Eiq "$STUN_FAULT_RE" <<<"$logs"
}

# How many traversal attempts the fault-node has seen end under the fault
# since since_ts, an RFC 3339 time, counted from its first STUN fault line on,
# printed as "<as initiator> <as responder>". Either side may drive an
# attempt. As initiator the node logs "NAT traversal failed" (warned or
# rate-limit suppressed) when its attempt fails; as responder it logs
# "traversal: answer sent ... accepted=false" when it turns the peer's offer
# down for want of an address. When both sides start a round at once the node
# logs both for that one round, so the two are counted apart rather than
# summed. Counting from the first fault line leaves out an attempt that
# observed STUN before the fault. Prints "0 0" when the log cannot be read.
faulted_attempts() {
    local since_ts="$1" logs first
    logs="$(docker logs --since "$since_ts" "$NODE" 2>&1)" || { echo "0 0"; return 0; }
    first="$(grep -Ein -m1 "$STUN_FAULT_RE" <<<"$logs" | cut -d: -f1)" || true
    if [ -z "$first" ]; then
        echo "0 0"
        return 0
    fi
    logs="$(tail -n "+$first" <<<"$logs")"
    echo "$(grep -c 'NAT traversal failed' <<<"$logs" || true)" \
        "$(grep -Ec 'traversal: answer sent .*accepted=false' <<<"$logs" || true)"
}

# Wait for the fault to show in the fault-node's logs, then hold the fault in
# place until the fault-node has run through it, before the caller's liveness
# and panic checks.
#
# The evidence half is a wait: nothing after it can pass until the fault-node
# has retried traversal under the fault, and how soon that happens depends on
# the peer's restart and the auto-connect backoff. It polls for up to
# timeout_secs from phase_start, the length of the fixed wait it replaced, and
# its log window reaches 4 s before phase_start as that wait's did.
#
# The survival half is an observation window, sized by what it observes: it
# holds until `attempts` traversal attempts have ended under the fault, with
# the node as initiator or as responder, then tail_secs more, so the checks
# read a daemon that has gone through its failure handling more than once
# rather than one caught the moment it first logged the fault. The fixed 25 s it replaced held two or
# three such attempts. It ends at timeout_secs from phase_start in any case,
# where that fixed wait ended, and the checks then run as they did after it.
#
# Returns 1, having said why, when the evidence never appears.
await_fault_then_survive() {
    local phase_start="$1" timeout_secs="$2" attempts="$3" tail_secs="$4"
    local since_ts init=0 resp=0
    since_ts="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
    # SECONDS counts whole seconds, so one more keeps the poll from giving up
    # before timeout_secs have really passed.
    local deadline=$(( phase_start + timeout_secs + 1 ))
    until stun_fault_logged $(( SECONDS - phase_start + 4 )); do
        if (( SECONDS >= deadline )); then
            local since=$(( SECONDS - phase_start + 4 ))
            echo "no STUN fault evidence in $NODE logs (last ${since}s)" >&2
            echo "--- recent log tail ---" >&2
            docker logs --since "${since}s" "$NODE" 2>&1 | tail -40 >&2 || true
            return 1
        fi
        sleep 1
    done
    echo "  $NODE: STUN fault evidence observed in logs after $(( SECONDS - phase_start ))s"
    while :; do
        read -r init resp <<<"$(faulted_attempts "$since_ts")"
        if (( init >= attempts || resp >= attempts )); then
            break
        fi
        if (( SECONDS >= deadline )); then
            echo "  $NODE: fewer than $attempts traversal attempts ended under the fault within ${timeout_secs}s ($init as initiator, $resp as responder); checking survival now"
            return 0
        fi
        sleep 1
    done
    echo "  $NODE: $attempts traversal attempts ended under the fault after $(( SECONDS - phase_start ))s ($init as initiator, $resp as responder)"
    sleep "$tail_secs"
    return 0
}

# Whether the fault-node has logged a line matching the extended regex re
# since since_ts, an RFC 3339 time. Silent, so it can be polled; a log that
# cannot be read holds no evidence.
node_logged_since() {
    local since_ts="$1" re="$2" logs
    logs="$(docker logs --since "$since_ts" "$NODE" 2>&1)" || return 1
    grep -Eq "$re" <<<"$logs"
}

# Wait for the fault-node to log a successful STUN observation after
# since_ts, an RFC 3339 time, for up to timeout_secs from the call. Only the
# success line counts (STUN_SUCCESS_RE), and only one logged after since_ts,
# so neither a failed observation nor a success from before a fault can
# satisfy it. Returns 1, having said why, when none appears.
await_stun_success() {
    local since_ts="$1" timeout_secs="$2" start=$SECONDS
    # One more second for the whole-second SECONDS clock, as above.
    local deadline=$(( SECONDS + timeout_secs + 1 ))
    until node_logged_since "$since_ts" "$STUN_SUCCESS_RE"; do
        if (( SECONDS >= deadline )); then
            echo "no successful STUN observation in $NODE logs since $since_ts (waited ${timeout_secs}s)" >&2
            return 1
        fi
        sleep 1
    done
    echo "  $NODE: STUN observation succeeded, seen after $(( SECONDS - start ))s"
    return 0
}

# Wait until fips is running in both the fault-node and the fault-peer, for up
# to timeout_secs. Says which container it is missing from when it gives up.
wait_daemons_running() {
    local timeout_secs="$1" start=$SECONDS missing c
    # One more second for the whole-second SECONDS clock, as above.
    local deadline=$(( SECONDS + timeout_secs + 1 ))
    while :; do
        missing=""
        for c in "$NODE" "$PEER"; do
            docker exec "$c" pidof fips >/dev/null 2>&1 || missing="$missing $c"
        done
        if [ -z "$missing" ]; then
            echo "  fips daemon running in both containers after $(( SECONDS - start ))s"
            return 0
        fi
        (( SECONDS < deadline )) || break
        sleep 1
    done
    echo "fips daemon failed to start in${missing} within ${timeout_secs}s" >&2
    return 1
}

# Pre-flight: with no fault injected, the fault-node must (a) discover
# the peer's overlay advert via the relay, and (b) observe its reflexive
# address through the STUN server at least once. If either is missing, the
# rest of the test would only show the "no overlay advert" path, or a STUN
# server that never worked, i.e. a setup bug, not a real fault-evidence miss.
# Polls up to `timeout_secs` for a successful observation logged since
# since_ts, the lab's start; an observation that failed does not count.
preflight_assert_stun_active() {
    local timeout_secs="$1" since_ts="$2"
    if await_stun_success "$since_ts" "$timeout_secs"; then
        echo "  $NODE: pre-flight STUN observation confirmed"
        return 0
    fi
    echo "pre-flight FAIL: $NODE observed no reflexive address through STUN within ${timeout_secs}s" >&2
    echo "(likely cause: peer advert not yet published, or peer config wrong)" >&2
    echo "--- $NODE recent log tail ---" >&2
    docker logs "$NODE" 2>&1 | tail -40 >&2 || true
    echo "--- $PEER recent log tail ---" >&2
    docker logs "$PEER" 2>&1 | tail -40 >&2 || true
    return 1
}

# Phases that did not run, with the reason. Surfaced in the final verdict:
# the suite reports a pass per phase-level assertion, so a phase that never
# ran otherwise leaves a clean "passed" standing for work not done.
SKIPPED_PHASES=()

# Start the lab. The step is checked here because this runs under
# relay_lab_start's caller's `||`, where `set -e` does not stop on a failure.
start_lab() {
    "${COMPOSE[@]}" --profile "$PROFILE" up -d --no-build --force-recreate || return 1
    return 0
}

run_test() {
    echo "=== stun-faults-test: setup ==="
    cleanup
    "$GENERATE_SCRIPT" "$SCENARIO"
    # Build first, with retries, because the build pulls from registries that
    # time out now and then. The start is retried only when the relay faulted
    # in its start window, a strfry crash at the nodes' first connects that
    # reproduces with upstream's own image and config (relay-verdict.sh). A
    # start that fails for any other reason is not retried, and a relay fault
    # after the window still fails the run through assert_relay.
    retry_build "compose build ($PROFILE)" "${COMPOSE[@]}" --profile "$PROFILE" build
    local lab_ts
    lab_ts="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
    relay_lab_start "$RELAY_CONTAINER" 2 45 start_lab cleanup || {
        dump_diagnostics
        return 1
    }

    # Wait for both daemons to come up. They then still have to publish
    # their adverts to the relay and discover each other before the
    # fault-node reaches the STUN client, which the pre-flight waits for.
    echo ""
    echo "--- waiting for daemons to start ---"
    if ! wait_daemons_running 10; then
        dump_diagnostics
        return 1
    fi

    # Phase 0 / pre-flight: assert that with NO fault injected, the
    # fault-node successfully reaches the STUN client at least once.
    # Without this guard, a Phase-1 fault-evidence miss could be either
    # the real bug we're testing OR a setup bug (e.g., missing advert).
    # The pre-flight's 55 s is the 45 s it had plus the 10 s fixed wait
    # that used to precede it, so the daemons keep the same time from the
    # lab's start to their first STUN observation.
    echo ""
    echo "=== Phase 0: pre-flight — confirm STUN baseline (no faults) ==="
    if ! preflight_assert_stun_active 55 "$lab_ts"; then
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
    # The fault-node has to detect the peer loss and retry under the
    # fault. Auto-connect backoff is exponential 5s base; first retry ~5s
    # after detection, second ~10s.
    local p1_rc=0
    await_fault_then_survive "$phase_start" "$FAULT_WAIT_SECS" \
        "$FAULTED_ATTEMPTS" "$SURVIVAL_TAIL_SECS" \
        || p1_rc=$?

    assert_process_alive            || { dump_diagnostics; return 1; }
    assert_no_panic                 || { dump_diagnostics; return 1; }
    if [ "$p1_rc" -ne 0 ]; then
        dump_diagnostics
        return 1
    fi
    clear_drop

    echo ""
    echo "=== Phase 2: delay 5000ms then clear (peer restart for clean STUN) ==="
    local p2_rc=0
    if apply_delay; then
        docker restart "$PEER" >/dev/null
        # The fault window: the fault-node's traversal attempts observe STUN
        # under the delay, which outlasts the client's response wait.
        sleep 12
        local p2_clear_ts p2_clear_ms
        p2_clear_ts="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
        p2_clear_ms="$(date +%s%3N)"
        clear_delay
        # Recovery: STUN must succeed after the rule is removed. A success
        # from before the clear does not count, nor does a failed
        # observation. It comes at the fault-node's next traversal attempt,
        # 3 to 18 s after the clear in sixteen kept runs; 30 s is a
        # judgement, not a derived bound.
        await_stun_success "$p2_clear_ts" 30 || p2_rc=$?
        # Then hold until P2_CLEAR_HOLD_SECS after the clear, as the fixed
        # wait this replaced always did.
        local p2_hold_ms=$(( P2_CLEAR_HOLD_SECS * 1000 - ($(date +%s%3N) - p2_clear_ms) ))
        if (( p2_rc == 0 && p2_hold_ms > 0 )); then
            sleep "$(( p2_hold_ms / 1000 )).$(printf '%03d' $(( p2_hold_ms % 1000 )))"
        fi
    else
        echo "  Phase 2 skipped (no tc netem available); proceeding to Phase 3"
        SKIPPED_PHASES+=("2 (delay): tc netem unavailable")
    fi

    assert_process_alive || { dump_diagnostics; return 1; }
    assert_no_panic      || { dump_diagnostics; return 1; }
    if [ "$p2_rc" -ne 0 ]; then
        echo "Phase 2 recovery assertion failed (no STUN success after delay clear)" >&2
        dump_diagnostics
        return 1
    fi

    echo ""
    echo "=== Phase 3: kill STUN container, restart peer, assert survival ==="
    docker stop "$STUN_CONTAINER" >/dev/null
    docker restart "$PEER" >/dev/null
    local p3_start=$SECONDS
    local p3_rc=0
    await_fault_then_survive "$p3_start" "$FAULT_WAIT_SECS" \
        "$FAULTED_ATTEMPTS" "$SURVIVAL_TAIL_SECS" \
        || p3_rc=$?

    assert_process_alive            || { dump_diagnostics; return 1; }
    assert_no_panic                 || { dump_diagnostics; return 1; }
    if [ "$p3_rc" -ne 0 ]; then
        dump_diagnostics
        return 1
    fi

    assert_relay "$RELAY_CONTAINER" || return 1

    cleanup
    if [ ${#SKIPPED_PHASES[@]} -eq 0 ]; then
        echo "stun-faults-test passed (3/3 phases ran)"
        return 0
    fi
    # A phase that did not run is not a phase that passed. Say so in the line
    # a reader takes the verdict from, rather than leaving it in scrollback
    # several hundred lines up where the skip was announced.
    local ran=$(( 3 - ${#SKIPPED_PHASES[@]} ))
    echo "stun-faults-test passed ($ran/3 phases ran, ${#SKIPPED_PHASES[@]} skipped)"
    local phase
    for phase in "${SKIPPED_PHASES[@]}"; do
        echo "  SKIPPED phase $phase"
    done
    if [ "$ran" -eq 0 ]; then
        echo "stun-faults-test: every phase was skipped, so nothing was tested" >&2
        return 1
    fi
}

main() {
    require_docker_daemon
    require_test_image
    run_test
}

main "$@"
