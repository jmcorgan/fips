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

# Connected-peer count for a container, or the empty string if it did not
# answer.
#
# Empty is deliberately distinct from a real 0, and here the distinction is
# the whole point: the ACL denial checks below expect exactly 0, so an
# `|| echo 0` fallback lets an unreachable container satisfy them on the first
# iteration and the security property is never observed. Same shape as
# admission-cap-test.sh's read_peer_count.
read_connected_peers() {
    local container="$1"
    docker exec "$container" fipsctl show peers 2>/dev/null \
        | python3 -c 'import json,sys; data=json.load(sys.stdin); print(sum(1 for p in data.get("peers", []) if p.get("connectivity") == "connected"))' 2>/dev/null \
        || true
}

wait_for_peers_exact() {
    local container="$1"
    local expected_count="$2"
    local timeout="${3:-30}"

    local count="" answered=false
    for _ in $(seq 1 "$timeout"); do
        count=$(read_connected_peers "$container")
        if [ -n "$count" ]; then
            answered=true
            if [ "$count" -eq "$expected_count" ]; then
                return 0
            fi
        fi
        sleep 1
    done

    if [ "$answered" = false ]; then
        echo "FAIL: $container never answered a peer query in ${timeout}s, so a count of $expected_count was never actually observed" >&2
    else
        echo "FAIL: $container did not reach $expected_count connected peers in ${timeout}s (last answer: $count)" >&2
    fi
    docker exec "$container" fipsctl show peers >&2 || true
    exit 1
}

# Assert that ONE log line in $container contains every one of the given
# fixed strings.
#
# Single-line matching is the point. Independent whole-log greps for an
# npub and for `decision=denylist match` are jointly satisfied by "this
# npub appears somewhere" plus "somebody was rejected by denylist", which
# is not the property this suite exists to prove. Node-a lists the denied
# peers as auto_connect peers, so it logs their npubs on the outbound
# connect path whether or not a rejection ever happened; the npub has to
# be on the rejection line itself to mean anything.
#
# Strings match in any order, by chaining fixed-string greps over the
# surviving lines, so the assertion does not depend on the order the
# tracing formatter emits a message and its fields in. A grep over empty
# input yields the empty string rather than a value that could satisfy
# the caller, so a container that cannot be read times out and fails
# rather than passing.
#
# Polls rather than reading once: under the XX handshake the
# cross-connection tie-breaker decides which side reaches its ACL check
# first, so an inbound-handshake rejection may not emit until a later
# retry. Same wait-with-timeout shape as wait_for_peers_exact above.
#
# Deliberately NOT registered in check-log-strings.py's SHELL_HELPERS,
# for two reasons, and note that registering it would in fact capture
# nothing: that extractor reads only a helper's FIRST argument and only
# when it is a quoted literal free of `$` (check-log-strings.py:116),
# whereas the first argument here is the unquoted container name
# carrying ${FIPS_CI_NAME_SUFFIX}. Verified by running the extractor
# with this helper added: zero hits. The same is true of the
# `assert_log_contains` this replaced, so nothing left the check's scope.
#
# It should stay out of scope regardless: that check exists for strings
# whose disappearance from src/ would let an assertion silently pass,
# and every string here is a positive requirement, so a missing one
# exhausts the poll and exits 1, which is loud.
assert_log_line_contains_all() {
    local container="$1"
    local timeout="$2"
    shift 2

    local logs surviving pattern
    for _ in $(seq 1 "$timeout"); do
        logs="$(docker logs "$container" 2>&1 | python3 -c 'import re,sys; print(re.sub(r"\x1b\[[0-9;]*m", "", sys.stdin.read()), end="")' || true)"
        surviving="$logs"
        for pattern in "$@"; do
            surviving="$(printf '%s' "$surviving" | grep -F -- "$pattern" || true)"
        done
        if [ -n "$surviving" ]; then
            echo "PASS: $container has a log line matching all of: $*"
            return 0
        fi
        sleep 1
    done

    echo "FAIL: no single log line in $container contains all of: $* (waited ${timeout}s)" >&2
    exit 1
}

if [ "$SKIP_BUILD" = false ]; then
    log "Building Linux test binaries"
    "$TESTING_DIR/scripts/build.sh" --no-docker
fi

log "Generating ACL allowlist fixtures"
"$GENERATE_CONFIGS"

log "Starting ACL allowlist harness"
docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
# --build only on the hand path. Under a harness, --skip-build means the caller
# has already built the image this compose file names, and rebuilding it here
# would overwrite that image from whatever the shared build context happens to
# hold — which is how a suite ends up certifying binaries it was never given.
if [ "$SKIP_BUILD" = false ]; then
    docker compose -f "$COMPOSE_FILE" up -d --build
else
    docker compose -f "$COMPOSE_FILE" up -d
fi

log "Waiting for expected peer convergence"
wait_for_peers_exact fips-acl-container-a${FIPS_CI_NAME_SUFFIX:-} 3 40
wait_for_peers_exact fips-acl-container-b${FIPS_CI_NAME_SUFFIX:-} 1 40
wait_for_peers_exact fips-acl-container-c${FIPS_CI_NAME_SUFFIX:-} 0 5
wait_for_peers_exact fips-acl-container-d${FIPS_CI_NAME_SUFFIX:-} 0 5
wait_for_peers_exact fips-acl-container-e${FIPS_CI_NAME_SUFFIX:-} 1 40
wait_for_peers_exact fips-acl-container-f${FIPS_CI_NAME_SUFFIX:-} 1 40

log "Verifying peer sets"
assert_peer_set fips-acl-container-a${FIPS_CI_NAME_SUFFIX:-} "npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le npub1x5z9rwzzm26q9verutx4aajhf2zw2pyp34c6whhde2zduxqav40qgq36l6 npub1ytrut7gjncn2zfnhn56c0zgftf0w6p99gf6fu8j73hzw5603zglqc9av6c"
assert_peer_set fips-acl-container-b${FIPS_CI_NAME_SUFFIX:-} "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"
assert_peer_set fips-acl-container-c${FIPS_CI_NAME_SUFFIX:-} ""
assert_peer_set fips-acl-container-d${FIPS_CI_NAME_SUFFIX:-} ""
assert_peer_set fips-acl-container-e${FIPS_CI_NAME_SUFFIX:-} "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"
assert_peer_set fips-acl-container-f${FIPS_CI_NAME_SUFFIX:-} "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"

log "Checking alias-based ACL resolution"
assert_acl_field fips-acl-container-a${FIPS_CI_NAME_SUFFIX:-} allow_file_entries "node-a node-b node-e node-f"
assert_acl_field fips-acl-container-a${FIPS_CI_NAME_SUFFIX:-} allow_entries "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le npub1x5z9rwzzm26q9verutx4aajhf2zw2pyp34c6whhde2zduxqav40qgq36l6 npub1ytrut7gjncn2zfnhn56c0zgftf0w6p99gf6fu8j73hzw5603zglqc9av6c"
assert_acl_field fips-acl-container-c${FIPS_CI_NAME_SUFFIX:-} allow_file_entries "node-a node-b node-c node-d node-e node-f"
assert_acl_field fips-acl-container-c${FIPS_CI_NAME_SUFFIX:-} allow_entries "npub1cld9yay0u24davpu6c35l4vldrhzvaq66pcqtg9a0j2cnjrn9rtsxx2pe6 npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le npub1x5z9rwzzm26q9verutx4aajhf2zw2pyp34c6whhde2zduxqav40qgq36l6 npub1ytrut7gjncn2zfnhn56c0zgftf0w6p99gf6fu8j73hzw5603zglqc9av6c"

log "Checking ACL rejection logs"
# One assertion per denied peer, each requiring the real message, that
# peer's npub and the denylist decision on the SAME line. The npub being
# on the rejection line is what carries the weight here: node-a rejected
# THIS peer. The `decision=` conjunct adds no discrimination, since
# PeerAclDecision::allowed() returns early for AllowList and DefaultAllow
# (src/node/acl.rs:44-46), so DenyList is the only value that can reach
# that warn! and every rejection line carries it. It is kept because the
# remediation prescribes it and it documents the expected decision.
#
# Residual, recorded rather than hidden: node-a has auto_connect stanzas
# for both denied peers and authorizes before dialing, so it emits a
# fully-formed rejection line for each on the outbound_connect path.
# These two assertions are therefore satisfiable without the inbound ACL
# check running at all. The suite still catches that, because the denied
# peer would then connect and the peer-count assertions above would time
# out; but these two lines alone do not prove the inbound path.
assert_log_line_contains_all fips-acl-container-a${FIPS_CI_NAME_SUFFIX:-} 15 \
    "Rejected peer by ACL" \
    "npub1cld9yay0u24davpu6c35l4vldrhzvaq66pcqtg9a0j2cnjrn9rtsxx2pe6" \
    "decision=denylist match"
assert_log_line_contains_all fips-acl-container-a${FIPS_CI_NAME_SUFFIX:-} 15 \
    "Rejected peer by ACL" \
    "npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl" \
    "decision=denylist match"
# The outsider-initiated path specifically, asserted separately and not
# per-npub. Node-a carries static stanzas for both denied peers, so each
# can be rejected on the outbound_connect path as well and which context
# a given npub lands in is not deterministic (see README). Requiring an
# inbound rejection of a *named* peer would red on scheduling rather than
# on a regression; requiring that one exists at all does not.
assert_log_line_contains_all fips-acl-container-a${FIPS_CI_NAME_SUFFIX:-} 15 \
    "Rejected peer by ACL" \
    "context=inbound_handshake" \
    "decision=denylist match"

log "ACL allowlist integration test passed"
