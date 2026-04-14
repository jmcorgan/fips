#!/bin/bash
# Integration test for the ACL allowlist harness.
#
# Usage: ./test.sh [--skip-build] [--keep-up]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTING_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
GENERATE_CONFIGS="$SCRIPT_DIR/generate-configs.sh"

SKIP_BUILD=false
KEEP_UP=false

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-build) SKIP_BUILD=true; shift ;;
        --keep-up) KEEP_UP=true; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

cleanup() {
    if [ "$KEEP_UP" = false ]; then
        docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT

log() {
    echo "=== $*"
}

peer_npubs() {
    local container="$1"
    docker exec "$container" fipsctl show peers \
        | python3 -c 'import json,sys; data=json.load(sys.stdin); print(" ".join(sorted(p["npub"] for p in data.get("peers", []) if p.get("connectivity") == "connected")))'
}

acl_field() {
    local container="$1"
    local field="$2"
    docker exec "$container" fipsctl acl show \
        | python3 -c 'import json,sys; data=json.load(sys.stdin); field=sys.argv[1]; value=data.get(field); print(" ".join(sorted(value)) if isinstance(value, list) else ("" if value is None else value))' "$field"
}

assert_peer_set() {
    local container="$1"
    local expected="$2"
    local actual
    actual="$(peer_npubs "$container")"
    if [ "$actual" != "$expected" ]; then
        echo "FAIL: $container peers mismatch" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual" >&2
        exit 1
    fi
    echo "PASS: $container peers match expected set"
}

assert_acl_field() {
    local container="$1"
    local field="$2"
    local expected="$3"
    local actual
    actual="$(acl_field "$container" "$field")"
    if [ "$actual" != "$expected" ]; then
        echo "FAIL: $container ACL field $field mismatch" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual" >&2
        exit 1
    fi
    echo "PASS: $container ACL field $field matches expected value"
}

wait_for_peers_exact() {
    local container="$1"
    local expected_count="$2"
    local timeout="${3:-30}"

    for _ in $(seq 1 "$timeout"); do
        local count
        count=$(docker exec "$container" fipsctl show peers 2>/dev/null \
            | python3 -c 'import json,sys; data=json.load(sys.stdin); print(sum(1 for p in data.get("peers", []) if p.get("connectivity") == "connected"))' 2>/dev/null || echo 0)
        if [ "$count" -eq "$expected_count" ]; then
            return 0
        fi
        sleep 1
    done

    echo "FAIL: $container did not reach $expected_count connected peers in ${timeout}s" >&2
    docker exec "$container" fipsctl show peers >&2 || true
    exit 1
}

assert_log_contains() {
    local container="$1"
    local pattern="$2"
    local logs
    logs="$(docker logs "$container" 2>&1 | python3 -c 'import re,sys; print(re.sub(r"\x1b\[[0-9;]*m", "", sys.stdin.read()), end="")' || true)"
    if ! printf '%s' "$logs" | grep -F "$pattern" >/dev/null; then
        echo "FAIL: missing log pattern in $container: $pattern" >&2
        exit 1
    fi
    echo "PASS: $container logs contain expected ACL rejection"
}

if [ "$SKIP_BUILD" = false ]; then
    log "Building Linux test binaries"
    "$TESTING_DIR/scripts/build.sh" --no-docker
fi

log "Generating ACL allowlist fixtures"
"$GENERATE_CONFIGS"

log "Starting ACL allowlist harness"
docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
docker compose -f "$COMPOSE_FILE" up -d --build

log "Waiting for expected peer convergence"
wait_for_peers_exact fips-acl-container-a 3 40
wait_for_peers_exact fips-acl-container-b 1 40
wait_for_peers_exact fips-acl-container-c 0 5
wait_for_peers_exact fips-acl-container-d 0 5
wait_for_peers_exact fips-acl-container-e 1 40
wait_for_peers_exact fips-acl-container-f 1 40

log "Verifying peer sets"
assert_peer_set fips-acl-container-a "npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le npub1x5z9rwzzm26q9verutx4aajhf2zw2pyp34c6whhde2zduxqav40qgq36l6 npub1ytrut7gjncn2zfnhn56c0zgftf0w6p99gf6fu8j73hzw5603zglqc9av6c"
assert_peer_set fips-acl-container-b "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"
assert_peer_set fips-acl-container-c ""
assert_peer_set fips-acl-container-d ""
assert_peer_set fips-acl-container-e "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"
assert_peer_set fips-acl-container-f "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"

log "Checking alias-based ACL resolution"
assert_acl_field fips-acl-container-a allow_file_entries "node-a node-b node-e node-f"
assert_acl_field fips-acl-container-a allow_entries "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le npub1x5z9rwzzm26q9verutx4aajhf2zw2pyp34c6whhde2zduxqav40qgq36l6 npub1ytrut7gjncn2zfnhn56c0zgftf0w6p99gf6fu8j73hzw5603zglqc9av6c"
assert_acl_field fips-acl-container-c allow_file_entries "node-a node-b node-c node-d node-e node-f"
assert_acl_field fips-acl-container-c allow_entries "npub1cld9yay0u24davpu6c35l4vldrhzvaq66pcqtg9a0j2cnjrn9rtsxx2pe6 npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le npub1x5z9rwzzm26q9verutx4aajhf2zw2pyp34c6whhde2zduxqav40qgq36l6 npub1ytrut7gjncn2zfnhn56c0zgftf0w6p99gf6fu8j73hzw5603zglqc9av6c"

log "Checking ACL rejection logs"
assert_log_contains fips-acl-container-a "npub1cld9yay0u24davpu6c35l4vldrhzvaq66pcqtg9a0j2cnjrn9rtsxx2pe6"
assert_log_contains fips-acl-container-a "npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl"
assert_log_contains fips-acl-container-a "context=inbound_handshake"
assert_log_contains fips-acl-container-a "decision=denylist match"

log "ACL allowlist integration test passed"
