#!/bin/bash
# Start-up stop test: a stop sent while fips or fips-gateway is still starting
# is acted on, not lost.
#
# Each case runs one container from the test image, waits until the tested
# process is PID 1 and has logged its anchor line, then sends `docker stop` a
# fixed delay after the anchor. Before the exec in the entrypoint, PID 1 is
# bash, which has no SIGTERM handler, so a stop timed from container start
# would be discarded with or without the fix; the anchor rules that out. A
# missing anchor is a failure, never a skip.
#
# Cases:
#   daemon, stop inside the grace   start-up held about 5 s by one STUN server
#                                   that never answers; stopped 2 s after
#                                   start-up began, so start-up finishes after
#                                   the stop, then the daemon drains and exits 0
#   daemon, stop past the grace     three such servers, about 15 s; stopped
#                                   0.5 s in with a 10 s stop timeout, so the
#                                   daemon must give up at its 5 s grace and
#                                   exit 0 before Docker kills it
#   daemon, healthy stop            no Nostr; stopped 5 s after start-up ended
#   gateway, stop during the probe  fips-gateway as PID 1 probing a DNS upstream
#                                   that never answers; stopped 0.5 s in
#
# Configs reach the container with `docker cp` before it starts, so nothing
# here is a bind mount and the temporary directory never has to be visible to
# the Docker daemon.
#
# Usage: ./scripts/startup-stop-test.sh   (exit 0 all checks passed, 1 otherwise)

set -u

IMAGE="${FIPS_TEST_IMAGE:-fips-test:latest}"
SUFFIX="${FIPS_CI_NAME_SUFFIX:-}"

PASSED=0
FAILED=0

check() {
    local label="$1"
    local result="$2"
    if [ "$result" -eq 0 ]; then
        echo "  $label ... OK"
        PASSED=$((PASSED + 1))
    else
        echo "  $label ... FAIL"
        FAILED=$((FAILED + 1))
    fi
}

WORK="$(mktemp -d)" || { echo "startup-stop-test: mktemp failed" >&2; exit 1; }
CONTAINERS=()

cleanup() {
    local c
    for c in "${CONTAINERS[@]}"; do
        docker rm -f "$c" >/dev/null 2>&1
    done
    rm -rf "$WORK"
    return 0
}
trap cleanup EXIT
trap 'echo ""; echo "Test interrupted"; exit 130' INT

now() {
    date +%s.%N
}

# Print arithmetic expression $1 to millisecond precision.
calc() {
    awk "BEGIN { printf \"%.3f\", $1 }"
}

# Succeed when $1 < $2, both decimal numbers.
lt() {
    awk "BEGIN { exit !($1 < $2) }"
}

# Print the docker log timestamp (seconds since the epoch) of the first line
# of container $1 matching extended regex $2, or fail when none matches.
log_time() {
    local line
    line=$(docker logs --timestamps "$1" 2>&1 | grep -E -m1 -- "$2") || return 1
    date -d "${line%% *}" +%s.%N
}

# Wait up to $3 seconds for container $1 to log a line matching $2, polling
# every 0.1 s, and print that line's timestamp. Fails when the line never
# appears.
wait_anchor() {
    local container="$1" pattern="$2" limit="$3" deadline
    deadline=$(calc "$(now) + $limit")
    while lt "$(now)" "$deadline"; do
        if log_time "$container" "$pattern"; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# Sleep until epoch time $1; return at once if it has passed.
sleep_until() {
    local wait
    wait=$(calc "$1 - $(now)")
    if lt 0 "$wait"; then
        sleep "$wait"
    fi
    return 0
}

# Write a daemon config to $WORK/$1/fips.yaml. $2 is the number of STUN
# servers (0 for no Nostr); $3, when set, adds a gateway section whose DNS
# upstream is a port nothing answers on.
write_config() {
    local dir="$WORK/$1" stun="$2" gateway="${3:-}" i
    mkdir -p "$dir" || return 1
    {
        echo "tun:"
        echo "  enabled: true"
        echo "  name: fips0"
        echo "  mtu: 1280"
        echo "dns:"
        echo "  enabled: true"
        echo "transports:"
        echo "  udp:"
        echo "    bind_addr: \"0.0.0.0:2121\""
        if [ "$stun" -gt 0 ]; then
            # A public UDP transport bound to the wildcard with no
            # external_addr makes start-up learn its address by STUN before
            # it finishes. The servers are loopback ports with no listener:
            # the probe socket is unconnected, so no ICMP error reaches it
            # and each server costs the full per-server wait. The relays
            # refuse at once and are connected in the background.
            echo "    advertise_on_nostr: true"
            echo "    public: true"
            echo "node:"
            echo "  rendezvous:"
            echo "    nostr:"
            echo "      enabled: true"
            echo "      advert_relays: [\"ws://127.0.0.1:9\"]"
            echo "      dm_relays: [\"ws://127.0.0.1:9\"]"
            echo "      stun_servers:"
            for ((i = 0; i < stun; i++)); do
                echo "        - \"stun:127.0.0.1:$((3480 + i))\""
            done
        fi
        if [ -n "$gateway" ]; then
            echo "gateway:"
            echo "  enabled: true"
            echo "  pool: \"fd01::/112\""
            echo "  lan_interface: placeholder"
            echo "  dns:"
            echo "    upstream: \"[::1]:5399\""
        fi
    } > "$dir/fips.yaml" || return 1
    return 0
}

# Create container $1 in entrypoint mode $2 with config directory $3, copy the
# config in, and start it. Extra arguments are passed to docker create.
start_container() {
    local name="$1" mode="$2" dir="$3"
    shift 3
    docker rm -f "$name" >/dev/null 2>&1
    CONTAINERS+=("$name")
    docker create --name "$name" \
        --label com.corganlabs.fips-ci=1 \
        --label "com.corganlabs.fips-ci.run=${FIPS_CI_RUN_ID:-manual}" \
        --cap-add NET_ADMIN --device /dev/net/tun:/dev/net/tun \
        --sysctl net.ipv6.conf.all.disable_ipv6=0 \
        -e RUST_LOG=info -e FIPS_TEST_MODE="$mode" \
        "$@" "$IMAGE" >/dev/null || return 1
    docker cp "$dir" "$name:/etc/fips" >/dev/null || return 1
    docker start "$name" >/dev/null || return 1
    return 0
}

# Stop container $1 with timeout $2 at epoch time $3. Sets STOP_SENT,
# STOP_ELAPSED (sent to the process's exit, seconds; empty when the exit
# time cannot be read), DOCKER_ELAPSED (sent to `docker stop` returning) and
# EXIT_CODE.
#
# The exit is timed from the container's State.FinishedAt, which Docker takes
# from the runtime's exit event for PID 1, not from `docker stop` returning:
# that also covers Docker's own teardown of the container, which on a loaded
# host has taken several seconds after the process was gone (a host-side
# watch of PID 1 showed it reaped on time while `docker stop` returned 2 to
# 4 s later). Docker's teardown is not what these cases test.
stop_at() {
    local name="$1" timeout="$2" at="$3" done_at finished
    sleep_until "$at"
    STOP_SENT=$(now)
    docker stop -t "$timeout" "$name" >/dev/null 2>&1
    done_at=$(now)
    DOCKER_ELAPSED=$(calc "$done_at - $STOP_SENT")
    STOP_ELAPSED=""
    if finished=$(docker inspect -f '{{.State.FinishedAt}}' "$name" 2>/dev/null) \
        && finished=$(date -d "$finished" +%s.%N 2>/dev/null); then
        STOP_ELAPSED=$(calc "$finished - $STOP_SENT")
    fi
    EXIT_CODE=$(docker inspect -f '{{.State.ExitCode}}' "$name" 2>/dev/null) || EXIT_CODE=unknown
    return 0
}

# Record the checks common to every case and print the container's log. An
# exit time that could not be read, or one before the stop was sent (the
# process was gone before the stop, so the stop was not tested), fails the
# bound rather than passing it.
report_stop() {
    local label="$1" want_code="$2" max_elapsed="$3"
    echo "  stop sent at anchor + $(calc "$STOP_SENT - $ANCHOR")s; process exited after ${STOP_ELAPSED:-unknown}s with code $EXIT_CODE; docker stop returned after ${DOCKER_ELAPSED}s"
    [ "$EXIT_CODE" = "$want_code" ]
    check "$label: exit code $want_code" $?
    [ -n "$STOP_ELAPSED" ] && lt 0 "$STOP_ELAPSED" && lt "$STOP_ELAPSED" "$max_elapsed"
    check "$label: exited within ${max_elapsed}s of the stop" $?
    return 0
}

# Succeed when container $1's log has a line matching extended regex $2.
logged() {
    docker logs "$1" 2>&1 | grep -qE -- "$2"
}

# Record check $1 as passed when container $2's log has no line matching $3.
check_absent() {
    if logged "$2" "$3"; then
        check "$1" 1
    else
        check "$1" 0
    fi
    return 0
}

dump_log() {
    echo "  --- $1 log ---"
    docker logs --timestamps "$1" 2>&1 | sed 's/^/    /'
    return 0
}

DAEMON_ANCHOR='fips: FIPS .+ starting'

# ── Daemon: stop inside the grace ─────────────────────────────────────────

echo ""
echo "Start-up stop: daemon, stop inside the grace"
C="fips-startup-stop-grace$SUFFIX"
if write_config grace 1 && start_container "$C" default "$WORK/grace"; then
    if ANCHOR=$(wait_anchor "$C" "$DAEMON_ANCHOR" 30); then
        check "Inside grace: daemon logged its start line as PID 1" 0
        stop_at "$C" 10 "$(calc "$ANCHOR + 2")"
        report_stop "Inside grace" 0 7
        # Shape: start-up must still have been running when the stop was
        # sent, or a fast start-up passes this case without testing it.
        if RUNNING=$(log_time "$C" 'FIPS running'); then
            lt "$STOP_SENT" "$RUNNING"
            check "Inside grace: start-up finished after the stop (shape)" $?
        else
            check "Inside grace: start-up finished after the stop (shape; no FIPS running line)" 1
        fi
        logged "$C" 'Shutdown signal received.*signal=SIGTERM'
        check "Inside grace: daemon logged receiving SIGTERM" $?
        logged "$C" 'Stop requested during start-up'
        check "Inside grace: daemon logged the stop during start-up" $?
        logged "$C" 'Node draining'
        check "Inside grace: daemon drained" $?
        logged "$C" 'FIPS shutdown complete'
        check "Inside grace: daemon completed shutdown" $?
    else
        check "Inside grace: daemon logged its start line as PID 1 (anchor not seen)" 1
    fi
    dump_log "$C"
else
    check "Inside grace: container started" 1
fi

# ── Daemon: start-up past the grace ───────────────────────────────────────

echo ""
echo "Start-up stop: daemon, start-up past the grace"
C="fips-startup-stop-past$SUFFIX"
if write_config past 3 && start_container "$C" default "$WORK/past"; then
    if ANCHOR=$(wait_anchor "$C" "$DAEMON_ANCHOR" 30); then
        check "Past grace: daemon logged its start line as PID 1" 0
        stop_at "$C" 10 "$(calc "$ANCHOR + 0.5")"
        report_stop "Past grace" 0 7
        logged "$C" 'Start-up did not finish within the stop grace'
        check "Past grace: daemon gave up at the grace" $?
        check_absent "Past grace: start-up never finished (shape)" "$C" 'FIPS running'
    else
        check "Past grace: daemon logged its start line as PID 1 (anchor not seen)" 1
    fi
    dump_log "$C"
else
    check "Past grace: container started" 1
fi

# ── Daemon: healthy stop after start-up ───────────────────────────────────

echo ""
echo "Start-up stop: daemon, stop after start-up"
C="fips-startup-stop-healthy$SUFFIX"
if write_config healthy 0 && start_container "$C" default "$WORK/healthy"; then
    if ANCHOR=$(wait_anchor "$C" 'FIPS running' 30); then
        check "Healthy: daemon finished start-up" 0
        stop_at "$C" 10 "$(calc "$ANCHOR + 5")"
        report_stop "Healthy" 0 7
        logged "$C" 'Node draining'
        check "Healthy: daemon drained" $?
        logged "$C" 'FIPS shutdown complete'
        check "Healthy: daemon completed shutdown" $?
    else
        check "Healthy: daemon finished start-up (anchor not seen)" 1
    fi
    dump_log "$C"
else
    check "Healthy: container started" 1
fi

# ── Gateway: stop during the upstream probe ───────────────────────────────

echo ""
echo "Start-up stop: gateway, stop during the DNS upstream probe"
C="fips-startup-stop-gateway$SUFFIX"
# The gateway's LAN interface is the one holding FIPS_GW_LAN_ADDR; loopback
# holds ::1, which is enough for set-up to reach the probe. The gateway exits
# at once without IPv6 forwarding, and the container is not privileged, so
# the entrypoint cannot set it.
if write_config gateway 0 gateway \
    && start_container "$C" gateway "$WORK/gateway" -e FIPS_GW_LAN_ADDR=::1 \
        --sysctl net.ipv6.conf.all.forwarding=1 --sysctl net.ipv6.conf.all.proxy_ndp=1; then
    # The entrypoint waits up to 30 s for fips0 and 30 s for the daemon's DNS
    # before it execs the gateway.
    if ANCHOR=$(wait_anchor "$C" 'Checking DNS upstream reachability' 70); then
        check "Gateway: gateway logged its probe start as PID 1" 0
        stop_at "$C" 15 "$(calc "$ANCHOR + 0.5")"
        report_stop "Gateway" 0 2
        logged "$C" 'Received SIGTERM during start-up, exiting'
        check "Gateway: gateway logged the stop during start-up" $?
        check_absent "Gateway: the probe never succeeded (shape)" "$C" 'DNS upstream is reachable'
    else
        check "Gateway: gateway logged its probe start as PID 1 (anchor not seen)" 1
    fi
    dump_log "$C"
else
    check "Gateway: container started" 1
fi

echo ""
echo "=== Start-up stop results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
