#!/bin/bash
# Run a FIPS stochastic network simulation.
#
# Usage: ./scripts/chaos.sh <scenario> [options]
#   scenario: path to YAML file, or scenario name (e.g., "churn-10")
#
# Options:
#   -v, --verbose          Enable debug logging
#   --seed <N>             Override scenario seed
#   --duration <secs>      Override scenario duration
#   --nodes <N>            Override topology.num_nodes
#   --list                 List available scenarios
#
# Examples:
#   ./scripts/chaos.sh churn-10
#   ./scripts/chaos.sh churn-10 --seed 123 --verbose
#   ./scripts/chaos.sh scenarios/churn-10.yaml --duration 300
#   ./scripts/chaos.sh --list
set -e

trap 'echo ""; echo "Simulation interrupted"; exit 130' INT

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHAOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SCENARIO_DIR="$CHAOS_DIR/scenarios"

usage() {
    echo "Usage: $0 <scenario> [options]"
    echo ""
    echo "Arguments:"
    echo "  scenario            Path to YAML file, or scenario name (e.g., churn-10)"
    echo ""
    echo "Options:"
    echo "  -v, --verbose       Enable debug logging"
    echo "  --seed <N>          Override scenario seed"
    echo "  --duration <secs>   Override scenario duration"
    echo "  --nodes <N>         Override topology.num_nodes"
    echo "  --list              List available scenarios"
    exit 1
}

list_scenarios() {
    echo "=== Available Scenarios ==="
    echo ""
    for f in "$SCENARIO_DIR"/*.yaml; do
        [ -f "$f" ] || continue
        echo "  $(basename "$f" .yaml)"
    done
    exit 0
}

# Handle --list before requiring a positional arg
for arg in "$@"; do
    case "$arg" in
        --list) list_scenarios ;;
    esac
done

# Require at least one argument (the scenario)
[ $# -lt 1 ] && usage

# Parse arguments
SCENARIO_ARG=""
VERBOSE=""
SEED=""
DURATION=""
NODES=""

while [ $# -gt 0 ]; do
    case "$1" in
        -v|--verbose) VERBOSE="--verbose"; shift ;;
        --seed)       SEED="$2"; shift 2 ;;
        --duration)   DURATION="$2"; shift 2 ;;
        --nodes)      NODES="$2"; shift 2 ;;
        --list)       list_scenarios ;;
        -*)           echo "Error: Unknown option '$1'" >&2; usage ;;
        *)
            if [ -z "$SCENARIO_ARG" ]; then
                SCENARIO_ARG="$1"
            else
                echo "Error: Unexpected argument '$1'" >&2
                usage
            fi
            shift
            ;;
    esac
done

[ -z "$SCENARIO_ARG" ] && usage

# Resolve scenario path
if [ -f "$SCENARIO_ARG" ]; then
    SCENARIO_FILE="$SCENARIO_ARG"
elif [ -f "$SCENARIO_DIR/$SCENARIO_ARG.yaml" ]; then
    SCENARIO_FILE="$SCENARIO_DIR/$SCENARIO_ARG.yaml"
else
    echo "Error: Scenario not found: $SCENARIO_ARG" >&2
    echo "Tried:" >&2
    echo "  $SCENARIO_ARG" >&2
    echo "  $SCENARIO_DIR/$SCENARIO_ARG.yaml" >&2
    echo "" >&2
    echo "Available scenarios:" >&2
    for f in "$SCENARIO_DIR"/*.yaml; do
        [ -f "$f" ] || continue
        echo "  $(basename "$f" .yaml)" >&2
    done
    exit 1
fi

# Check prerequisites
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 not found" >&2
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo "Error: docker not found" >&2
    exit 1
fi

if ! docker info &> /dev/null; then
    echo "Error: Docker is not running" >&2
    exit 1
fi

DOCKER_DIR="$CHAOS_DIR/../docker"
if [ ! -f "$DOCKER_DIR/fips" ]; then
    echo "Error: FIPS binary not found at $DOCKER_DIR/fips" >&2
    echo "Run testing/scripts/build.sh first" >&2
    exit 1
fi

# Build python args
PYTHON_ARGS=("$SCENARIO_FILE")
[ -n "$VERBOSE" ] && PYTHON_ARGS+=("$VERBOSE")
[ -n "$SEED" ] && PYTHON_ARGS+=("--seed" "$SEED")
[ -n "$DURATION" ] && PYTHON_ARGS+=("--duration" "$DURATION")

echo "=== FIPS Stochastic Simulation ==="
echo ""
echo "  Scenario: $(basename "$SCENARIO_FILE" .yaml)"
echo "  File:     $SCENARIO_FILE"
[ -n "$SEED" ] && echo "  Seed:     $SEED (override)"
[ -n "$DURATION" ] && echo "  Duration: ${DURATION}s (override)"
[ -n "$NODES" ] && echo "  Nodes:    $NODES (override)"
echo ""

# If --nodes is specified, create a patched copy of the scenario file
if [ -n "$NODES" ]; then
    PATCHED=$(mktemp /tmp/chaos-scenario-XXXXXX.yaml)
    sed "s/^\(  num_nodes:\).*/\1 $NODES/" "$SCENARIO_FILE" > "$PATCHED"
    PYTHON_ARGS[0]="$PATCHED"
    trap 'rm -f "$PATCHED"' EXIT
fi

# Run from testing/chaos directory (sim expects relative paths)
cd "$CHAOS_DIR"
python3 -m sim "${PYTHON_ARGS[@]}"
