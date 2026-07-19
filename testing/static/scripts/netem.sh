#!/bin/bash
# Network impairment simulation using tc/netem on FIPS Docker containers.
#
# Usage: ./netem.sh <mesh|chain> <apply|remove|status> [options]
#
# Actions:
#   apply   - Apply netem rules to all containers in the profile
#   remove  - Remove netem rules from all containers
#   status  - Show current tc qdisc state on each container
#
# Options (for apply):
#   --delay <ms>          Fixed delay in milliseconds
#   --jitter <ms>         Delay variation (requires --delay)
#   --loss <percent>      Packet loss percentage
#   --loss-corr <percent> Loss correlation for bursty loss
#   --duplicate <percent> Packet duplication percentage
#   --reorder <percent>   Packet reordering probability
#   --corrupt <percent>   Bit-level corruption percentage
#
# Presets (shorthand for common combinations):
#   --preset lossy        5% loss, 25% correlation
#   --preset congested    50ms delay, 20ms jitter, 2% loss
#   --preset terrible     100ms delay, 40ms jitter, 10% loss, 1% dup, 5% reorder
#
# Examples:
#   ./netem.sh mesh apply --delay 50 --loss 5
#   ./netem.sh chain apply --preset congested
#   ./netem.sh mesh status
#   ./netem.sh mesh remove
set -e

trap 'echo ""; echo "Interrupted"; exit 130' INT

NODES="a b c d e"
IFACE="eth0"

# Defaults
DELAY=0
JITTER=0
LOSS=0
LOSS_CORR=0
DUPLICATE=0
REORDER=0
CORRUPT=0

usage() {
    echo "Usage: $0 <mesh|chain> <apply|remove|status> [options]"
    echo ""
    echo "Actions:"
    echo "  apply   - Apply netem rules to all containers"
    echo "  remove  - Remove netem rules from all containers"
    echo "  status  - Show current tc qdisc on each container"
    echo ""
    echo "Options (for apply):"
    echo "  --delay <ms>          Fixed delay"
    echo "  --jitter <ms>         Delay variation (requires --delay)"
    echo "  --loss <percent>      Packet loss"
    echo "  --loss-corr <percent> Loss correlation"
    echo "  --duplicate <percent> Packet duplication"
    echo "  --reorder <percent>   Packet reordering"
    echo "  --corrupt <percent>   Bit-level corruption"
    echo "  --preset <name>       Use a named preset (lossy, congested, terrible)"
    exit 1
}

apply_preset() {
    case "$1" in
        lossy)
            LOSS=5
            LOSS_CORR=25
            ;;
        congested)
            DELAY=50
            JITTER=20
            LOSS=2
            ;;
        terrible)
            DELAY=100
            JITTER=40
            LOSS=10
            DUPLICATE=1
            REORDER=5
            ;;
        *)
            echo "Error: Unknown preset '$1'" >&2
            echo "Available presets: lossy, congested, terrible" >&2
            exit 1
            ;;
    esac
}

# Parse arguments
[ $# -lt 2 ] && usage

PROFILE="$1"
ACTION="$2"
shift 2

case "$PROFILE" in
    mesh|chain) ;;
    *) echo "Error: Profile must be 'mesh' or 'chain'" >&2; exit 1 ;;
esac

case "$ACTION" in
    apply|remove|status) ;;
    *) echo "Error: Action must be 'apply', 'remove', or 'status'" >&2; exit 1 ;;
esac

# Parse options
while [ $# -gt 0 ]; do
    case "$1" in
        --delay)    DELAY="$2";    shift 2 ;;
        --jitter)   JITTER="$2";   shift 2 ;;
        --loss)     LOSS="$2";     shift 2 ;;
        --loss-corr) LOSS_CORR="$2"; shift 2 ;;
        --duplicate) DUPLICATE="$2"; shift 2 ;;
        --reorder)  REORDER="$2";  shift 2 ;;
        --corrupt)  CORRUPT="$2";  shift 2 ;;
        --preset)   apply_preset "$2"; shift 2 ;;
        *)
            echo "Error: Unknown option '$1'" >&2
            usage
            ;;
    esac
done

# Build netem parameter string from non-zero values
build_netem_params() {
    local params=""

    if [ "$DELAY" != "0" ]; then
        params="delay ${DELAY}ms"
        if [ "$JITTER" != "0" ]; then
            params="$params ${JITTER}ms"
        fi
    fi

    if [ "$LOSS" != "0" ]; then
        params="$params loss ${LOSS}%"
        if [ "$LOSS_CORR" != "0" ]; then
            params="$params ${LOSS_CORR}%"
        fi
    fi

    if [ "$DUPLICATE" != "0" ]; then
        params="$params duplicate ${DUPLICATE}%"
    fi

    if [ "$REORDER" != "0" ]; then
        if [ "$DELAY" = "0" ]; then
            echo "Error: --reorder requires --delay (reordering needs a delay queue)" >&2
            exit 1
        fi
        params="$params reorder ${REORDER}%"
    fi

    if [ "$CORRUPT" != "0" ]; then
        params="$params corrupt ${CORRUPT}%"
    fi

    echo "$params"
}

# Check if a container is running
container_running() {
    docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null | grep -q true
}

do_apply() {
    local params
    params=$(build_netem_params)

    if [ -z "$params" ]; then
        echo "Error: No impairment parameters specified" >&2
        echo "Use --delay, --loss, --duplicate, --reorder, --corrupt, or --preset" >&2
        exit 1
    fi

    echo "=== Applying netem: $params ==="
    echo ""

    for node in $NODES; do
        local container="fips-node-${node}${FIPS_CI_NAME_SUFFIX:-}"
        echo -n "  $container ... "
        if ! container_running "$container"; then
            echo "SKIP (not running)"
            continue
        fi
        if docker exec "$container" tc qdisc replace dev "$IFACE" root netem $params 2>&1; then
            echo "OK"
        else
            echo "FAIL"
        fi
    done
}

do_remove() {
    echo "=== Removing netem rules ==="
    echo ""

    for node in $NODES; do
        local container="fips-node-${node}${FIPS_CI_NAME_SUFFIX:-}"
        echo -n "  $container ... "
        if ! container_running "$container"; then
            echo "SKIP (not running)"
            continue
        fi
        # Suppress error if no qdisc exists
        if docker exec "$container" tc qdisc del dev "$IFACE" root 2>/dev/null; then
            echo "OK"
        else
            echo "OK (no rules)"
        fi
    done
}

do_status() {
    echo "=== netem status ==="
    echo ""

    for node in $NODES; do
        local container="fips-node-${node}${FIPS_CI_NAME_SUFFIX:-}"
        echo "  $container:"
        if ! container_running "$container"; then
            echo "    (not running)"
            continue
        fi
        local output
        output=$(docker exec "$container" tc qdisc show dev "$IFACE" 2>&1)
        if echo "$output" | grep -q "netem"; then
            echo "    $output"
        else
            echo "    (no netem rules)"
        fi
    done
}

case "$ACTION" in
    apply)  do_apply  ;;
    remove) do_remove ;;
    status) do_status ;;
esac

echo ""
echo "Done."
