#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SCENARIO="${1:?usage: setup-topology.sh <cone|symmetric>}"

case "$SCENARIO" in
    cone)
        node_a="fips-nat-cone-a"
        node_b="fips-nat-cone-b"
        ;;
    symmetric)
        node_a="fips-nat-symmetric-a"
        node_b="fips-nat-symmetric-b"
        ;;
    *)
        echo "Unsupported topology scenario: $SCENARIO" >&2
        exit 1
        ;;
esac

router_a="fips-nat-router-a"
router_b="fips-nat-router-b"

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
    local pid=""

    while [ "$SECONDS" -lt "$deadline" ]; do
        pid="$(docker inspect -f '{{.State.Pid}}' "$container" 2>/dev/null || true)"
        if [[ "$pid" =~ ^[0-9]+$ ]] && [ "$pid" -gt 0 ]; then
            echo "$pid"
            return 0
        fi
        sleep 0.5
    done

    echo "Timed out waiting for container PID: $container" >&2
    return 1
}

run_host_ip() {
    local image="$1"
    shift
    docker run --rm \
        --privileged \
        --net=host \
        --pid=host \
        --entrypoint ip \
        "$image" \
        "$@"
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
    node_pid="$(wait_for_pid "$node_container")"
    router_pid="$(wait_for_pid "$router_container")"

    run_host_ip "$image" link delete "$host_node" >/dev/null 2>&1 || true
    run_host_ip "$image" link delete "$host_router" >/dev/null 2>&1 || true
    run_host_ip "$image" link add "$host_node" type veth peer name "$host_router"
    run_host_ip "$image" link set "$host_node" netns "$node_pid"
    run_host_ip "$image" link set "$host_router" netns "$router_pid"

    configure_node_iface "$node_container" "$host_node" eth0 "$node_cidr"
    configure_router_iface "$router_container" "$host_router" eth1 "$router_cidr"
}

main() {
    cd "$NAT_DIR"

    local image
    image="$(helper_image)"

    setup_pair "$image" "$node_a" "$router_a" vna0 vna1 172.31.1.10/24 172.31.1.254/24
    setup_pair "$image" "$node_b" "$router_b" vnb0 vnb1 172.31.2.10/24 172.31.2.254/24
}

main "$@"
