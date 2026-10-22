#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$NAT_DIR/../.." && pwd)"

SCENARIO="${1:?usage: setup-topology.sh <cone|symmetric>}"

case "$SCENARIO" in
    cone)
        node_a="fips-nat-cone-a${FIPS_CI_NAME_SUFFIX:-}"
        node_b="fips-nat-cone-b${FIPS_CI_NAME_SUFFIX:-}"
        ;;
    symmetric)
        node_a="fips-nat-symmetric-a${FIPS_CI_NAME_SUFFIX:-}"
        node_b="fips-nat-symmetric-b${FIPS_CI_NAME_SUFFIX:-}"
        ;;
    *)
        echo "Unsupported topology scenario: $SCENARIO" >&2
        exit 1
        ;;
esac

router_a="fips-nat-router-a${FIPS_CI_NAME_SUFFIX:-}"
router_b="fips-nat-router-b${FIPS_CI_NAME_SUFFIX:-}"

# Host interface names live in one global namespace and are capped at
# IFNAMSIZ-1 = 15 characters — far short of the run suffix, which is 20-plus at
# the default run-id length. Two concurrent runs both creating `vna0` damage
# each other: setup_pair deletes, adds and moves the interface as separate
# commands, so B's re-add between A's add and A's move sends B's interface
# into A's namespace and fails B's own move. Running them in one helper
# container narrows that window but does not close it; the names still have to
# differ.
#
# Scope the names with the same four-hex token the chaos simulation uses, and
# derive it by calling sim.naming rather than re-implementing sha1 here, so
# ci-cleanup.sh's reaper (which calls the same module) cannot end up matching a
# different width. Empty suffix yields an empty token and today's exact names.
#
# No fallback on a derivation failure: silently reverting to `vna0` would
# reinstate the collision this exists to remove, so let it fail loudly.
veth_token() {
    local suffix="${FIPS_CI_NAME_SUFFIX:-}"
    if [ -z "$suffix" ]; then
        echo ""
        return 0
    fi
    PYTHONPATH="$ROOT_DIR/testing/chaos" python3 -m sim.naming "$suffix"
}

helper_image() {
    if [ -n "${IP_HELPER_IMAGE:-}" ]; then
        echo "$IP_HELPER_IMAGE"
        return 0
    fi

    docker inspect -f '{{.Config.Image}}' "$router_a"
}

wait_for_pid() {
    local container="$1"
    local timeout_secs="${2:-30}"
    local deadline=$((SECONDS + timeout_secs))
    local pid="" status=""

    while [ "$SECONDS" -lt "$deadline" ]; do
        read -r pid status < <(docker inspect -f '{{.State.Pid}} {{.State.Status}}' "$container" 2>/dev/null) || true
        if [[ "$pid" =~ ^[0-9]+$ ]] && [ "$pid" -gt 0 ]; then
            echo "$pid"
            return 0
        fi
        # An exited container never gets a PID back; say so now rather than
        # after the whole wait.
        if [ "$status" = exited ] || [ "$status" = dead ]; then
            break
        fi
        sleep 0.5
    done

    echo "Timed out waiting for container PID: $container" >&2
    return 1
}

# Fail, naming the container, if it is no longer running.
#
# Both entrypoints give up and exit if their interface has not arrived within
# their wait, and a namespace move into an exited container then fails with
# only `Invalid "netns" value` and a stale PID. This turns that into a line
# that says which container exited, with its exit code and the end of its log.
require_running() {
    local container="$1"
    local state="" running="" code=""

    state="$(docker inspect -f '{{.State.Running}} {{.State.ExitCode}}' "$container" 2>/dev/null)" || state=""
    if [ -z "$state" ]; then
        echo "$container does not exist; it was removed before its interface was moved" >&2
        return 1
    fi
    read -r running code <<<"$state"
    if [ "$running" != true ]; then
        echo "$container exited (code $code) before its interface was moved; last 20 log lines:" >&2
        docker logs --tail 20 "$container" 2>&1 | sed 's/^/    /' >&2 || true
        return 1
    fi
    return 0
}

# Create one veth pair on the host and move each end into its container's
# network namespace, in a single helper container.
#
# One container per pair, not one per command: starting a container is the
# slow part, and it has been measured at 3 to 15 s at a time while other labs
# start on the same daemon. Ten serial starts then outran the entrypoints'
# interface waits. The script echoes each step so a failure shows which one.
move_pair() {
    local image="$1" host_node="$2" host_router="$3" node_pid="$4" router_pid="$5"

    docker run --rm \
        --label com.corganlabs.fips-ci=1 \
        --label "com.corganlabs.fips-ci.run=${FIPS_CI_RUN_ID:-manual}" \
        --privileged \
        --net=host \
        --pid=host \
        --entrypoint sh \
        "$image" \
        -c '
            set -e
            echo "topology: delete stale $1 and $2"
            ip link delete "$1" 2>/dev/null || true
            ip link delete "$2" 2>/dev/null || true
            echo "topology: add veth $1 <-> $2"
            ip link add "$1" type veth peer name "$2"
            echo "topology: move $1 into netns of pid $3"
            ip link set "$1" netns "$3"
            echo "topology: move $2 into netns of pid $4"
            ip link set "$2" netns "$4"
        ' sh "$host_node" "$host_router" "$node_pid" "$router_pid" || return 1
    return 0
}

configure_node_iface() {
    local container="$1"
    local current_name="$2"
    local final_name="$3"
    local cidr="$4"

    docker exec "$container" sh -lc "
        ip link set lo up &&
        ip link set '$current_name' name '$final_name' &&
        ip addr flush dev '$final_name' &&
        ip addr add '$cidr' dev '$final_name' &&
        ip link set '$final_name' up
    "
}

configure_router_iface() {
    local container="$1"
    local current_name="$2"
    local final_name="$3"
    local cidr="$4"

    docker exec "$container" sh -lc "
        ip link set lo up &&
        ip link set '$current_name' name '$final_name' &&
        ip addr flush dev '$final_name' &&
        ip addr add '$cidr' dev '$final_name' &&
        ip link set '$final_name' up
    "
}

setup_pair() {
    local image="$1"
    local node_container="$2"
    local router_container="$3"
    local host_node="$4"
    local host_router="$5"
    local node_cidr="$6"
    local router_cidr="$7"

    local node_pid router_pid
    node_pid="$(wait_for_pid "$node_container")" || {
        require_running "$node_container" || true
        return 1
    }
    router_pid="$(wait_for_pid "$router_container")" || {
        require_running "$router_container" || true
        return 1
    }

    require_running "$node_container" || return 1
    require_running "$router_container" || return 1

    # Run both checks after a failure, so each container that exited mid-run
    # is named, not only the first.
    if ! move_pair "$image" "$host_node" "$host_router" "$node_pid" "$router_pid"; then
        require_running "$node_container" || true
        require_running "$router_container" || true
        return 1
    fi

    if ! configure_node_iface "$node_container" "$host_node" eth0 "$node_cidr"; then
        require_running "$node_container" || true
        return 1
    fi
    if ! configure_router_iface "$router_container" "$host_router" eth1 "$router_cidr"; then
        require_running "$router_container" || true
        return 1
    fi
    return 0
}

main() {
    cd "$NAT_DIR"

    local image token
    image="$(helper_image)"
    token="$(veth_token)"

    setup_pair "$image" "$node_a" "$router_a" \
        "vna${token}0" "vna${token}1" 172.31.1.10/24 172.31.1.254/24 || exit 1
    setup_pair "$image" "$node_b" "$router_b" \
        "vnb${token}0" "vnb${token}1" 172.31.2.10/24 172.31.2.254/24 || exit 1
}

main "$@"
