#!/bin/bash
# Tests for the chaos runner's host-command bound in sim/veth.py: the bound on
# each `docker run ... ip` helper, what happens when a helper times out, and
# the runner's verdict when veth setup aborts.
#
# `docker` is replaced by veth-host-test/fake_docker.py, first on PATH. It
# keeps links in a state directory and runs each host `ip` command in a
# detached process standing for the helper container, so a client killed by a
# timeout leaves its helper running, as docker does. A plan file makes one
# attempt at one host command stall. The stalled command in every case is the
# second end's netns move, which is the command that stalled on a GitHub
# runner. No containers or network are involved, so the suite is hermetic.
#
# Cases:
#   healthy               no stall; the pair completes with the same number of
#                         docker calls as before the bound was changed
#   stall-31              the move stalls 31 s, at the real bound, and the pair
#                         completes (the old 30 s bound aborted here)
#   retry-before-effect   attempt 1 times out before the move; its helper is
#                         removed by name, and attempt 2 moves the link
#   effect-before-timeout the move lands, then the helper hangs past the bound;
#                         the move is found in place and not repeated
#   late-start            the helper does not exist until after `docker rm -f`;
#                         attempt 2 moves the link, and the late helper's move
#                         fails harmlessly instead of undoing it
#   late-lands-first      as late-start, but the late helper moves the link
#                         while attempt 2 is starting; attempt 2's move then
#                         fails, and the link is found where it belongs
#   both-attempts         the whole runner on ethernet-only, with both attempts
#                         timing out: exit 4 and a NOT SCORED line naming the
#                         timeout, not mesh assertion verdicts
#
# Every case but stall-31 shortens the bound to 2 or 3 s through drive.py, so
# the suite does not wait out the real bound twice. stall-31 uses the bound the
# module ships with. The suite takes about a minute and a half, most of it
# stall-31.
# VETH_TEST_BOTH_STALL sets both-attempts' stall (default 6 s); 31 shows what a
# veth.py with the old fixed 30 s bound prints when its setup aborts.
# VETH_TEST_SHOW_OUTPUT=1 prints each case's driver output after its checks.
#
# Run:
#   ./veth-host-test.sh [--root DIR] [CASE...]
# --root names a tree whose testing/chaos/sim, testing/chaos/configs and
# testing/lib are tested in place of this one's, for showing that an older
# veth.py fails a case. Exits 0 only if every case run passes; 1 if any fails;
# 2 on a usage error.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SUPPORT="$SCRIPT_DIR/veth-host-test"
ALL_CASES=(healthy stall-31 retry-before-effect effect-before-timeout late-start late-lands-first
    both-attempts)

# Docker calls one pair's setup makes when nothing stalls: the image lookup,
# two PID reads, two purges, the stale delete, the add, two moves, two
# renames, two operstate reads and two MAC reads.
HEALTHY_CALLS=15

CASES=()
while [ $# -gt 0 ]; do
    case "$1" in
        --root)
            [ $# -ge 2 ] || { echo "--root needs a directory" >&2; exit 2; }
            ROOT="$(cd "$2" && pwd)" || exit 2
            shift 2
            ;;
        -*) echo "unknown option: $1" >&2; exit 2 ;;
        *) CASES+=("$1"); shift ;;
    esac
done
[ ${#CASES[@]} -gt 0 ] || CASES=("${ALL_CASES[@]}")

WORK="$(mktemp -d)"
cleanup() {
    # Kill any helper a case left behind before removing its state.
    local f
    for f in "$WORK"/state-*/helpers/*.pid; do
        [ -f "$f" ] && kill -9 "$(cat "$f")" 2>/dev/null
    done
    rm -rf "$WORK"
    return 0
}
trap cleanup EXIT

# The tree under test, copied so the runner's generated configs and results
# land in the scratch directory and not in the checkout.
mkdir -p "$WORK/tree/testing/chaos/scenarios" "$WORK/bin"
cp -r "$ROOT/testing/chaos/sim" "$ROOT/testing/chaos/configs" "$WORK/tree/testing/chaos/" || exit 2
cp -r "$ROOT/testing/lib" "$WORK/tree/testing/" || exit 2
cp "$ROOT/testing/chaos/scenarios/ethernet-only.yaml" "$WORK/tree/testing/chaos/scenarios/" || exit 2
SIM_PARENT="$WORK/tree/testing/chaos"
# The stand-in client, first on PATH for every case.
SHIM="$WORK/bin/docker"
printf '#!/bin/bash\nexec python3 %q "$@"\n' "$SUPPORT/fake_docker.py" > "$SHIM"
chmod +x "$SHIM"

FAILURES=0
RESULTS=()

# Record a single assertion result.
check() {
    local name="$1"
    local ok="$2"      # 0 = pass, anything else = fail
    local detail="${3:-}"
    if [ "$ok" -eq 0 ]; then
        RESULTS+=("PASS  $name")
        echo "PASS  $name${detail:+  ($detail)}"
    else
        RESULTS+=("FAIL  $name")
        echo "FAIL  $name${detail:+  ($detail)}"
        FAILURES=$((FAILURES + 1))
    fi
    return 0
}

# Run drive.py for a case. Sets STATE and OUT. Arguments: case name, plan
# JSON, host timeout ('' for the module's own), then drive.py's arguments.
drive() {
    local name="$1" plan="$2" host_timeout="$3"
    shift 3
    STATE="$WORK/state-$name"
    OUT="$WORK/out-$name.txt"
    mkdir -p "$STATE/helpers"
    printf '%s\n' "$plan" > "$STATE/plan.json"
    PATH="$WORK/bin:$PATH" \
        FAKE_DOCKER_STATE="$STATE" \
        FAKE_DOCKER_PLAN="$STATE/plan.json" \
        HOST_TIMEOUT="$host_timeout" \
        FIPS_CI_NAME_SUFFIX="-vethtest" \
        FIPS_TEST_IMAGE="fake-sim-image" \
        FIPS_SIM_OUTPUT="$WORK/results-$name" \
        timeout 300 python3 "$SUPPORT/drive.py" "$@" > "$OUT" 2>&1
    echo "  driver exited $? ($name)"
    return 0
}

# Count the lines of a file matching an extended regex (0 for a missing file).
count() {
    local n
    n=$(grep -cE -- "$1" "$2" 2>/dev/null) || true
    echo "${n:-0}"
    return 0
}

# The namespace a link ended in, from the fake's link table.
link_ns() {
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], {}).get("ns", "absent"))' \
        "$STATE/links.json" "$1"
}

# The name of the Nth helper started for a host command matching a regex.
helper_name() {
    grep -E "^run .* cmd=.*$1" "$STATE/helpers.log" | sed -n "${2}p" | awk '{print $2}'
}

# Wait up to $2 seconds for a line matching $1 in the helpers log.
await_helper_log() {
    local deadline=$((SECONDS + $2))
    while [ $SECONDS -lt "$deadline" ]; do
        grep -qE -- "$1" "$STATE/helpers.log" 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}

# The pair completed, the link from n02's end sits renamed in n02, and the
# move of the second end happened exactly once.
check_pair_done() {
    local name="$1"
    check "$name: pair completes" "$(grep -q '^RESULT ok' "$OUT"; echo $?)" "$(grep '^RESULT' "$OUT")"
    check "$name: n02's end ends in n02" \
        "$([ "$(link_ns ve-n02-n01)" = fips-node-n02 ]; echo $?)" "ve-n02-n01 in $(link_ns ve-n02-n01)"
    local moves
    moves=$(count '^move vh0102b host->fips-node-n02 ' "$STATE/effects.log")
    check "$name: second end moved once" "$([ "$moves" -eq 1 ]; echo $?)" "$moves moves"
}

MOVE_B='link set vh0102b netns'

case_healthy() {
    drive healthy '[]' '' pair "$SIM_PARENT"
    check_pair_done healthy
    local calls
    calls=$(wc -l < "$STATE/calls.log")
    check "healthy: docker call count unchanged" \
        "$([ "$calls" -eq "$HEALTHY_CALLS" ]; echo $?)" "$calls calls, expected $HEALTHY_CALLS"
}

case_stall_31() {
    drive stall-31 "[{\"match\": \"$MOVE_B\", \"attempts\": [1], \"mode\": \"stall-before\", \"secs\": 31}]" '' \
        pair "$SIM_PARENT"
    check_pair_done stall-31
    local runs
    runs=$(count "^run .*cmd=$MOVE_B" "$STATE/helpers.log")
    check "stall-31: no second attempt" "$([ "$runs" -eq 1 ]; echo $?)" "$runs helper runs for the move"
}

case_retry_before_effect() {
    drive retry-before-effect "[{\"match\": \"$MOVE_B\", \"attempts\": [1], \"mode\": \"stall-before\", \"secs\": 6}]" 2 \
        pair "$SIM_PARENT"
    check_pair_done retry-before-effect
    local first second
    first=$(helper_name "$MOVE_B" 1)
    second=$(helper_name "$MOVE_B" 2)
    check "retry-before-effect: timed-out helper removed by name" \
        "$(grep -q "^rm $first killed" "$STATE/helpers.log"; echo $?)" "${first:-no helper}"
    check "retry-before-effect: move made by attempt 2" \
        "$(grep -qE "^move vh0102b .* by=$second\$" "$STATE/effects.log"; echo $?)" "${second:-no second helper}"
    check "retry-before-effect: helper state recorded" \
        "$(grep -q "$first.*\"Status\": \"running\"" "$OUT"; echo $?)"
    check "retry-before-effect: link location recorded" \
        "$(grep -q "vh0102b is in the host namespace" "$OUT"; echo $?)"
    # The killed helper would have moved the link 6 s in; it must not.
    sleep 5
    check "retry-before-effect: killed helper never ran" \
        "$([ "$(count "^exit $first" "$STATE/helpers.log")" -eq 0 ]; echo $?)"
}

case_effect_before_timeout() {
    drive effect-before-timeout "[{\"match\": \"$MOVE_B\", \"attempts\": [1], \"mode\": \"stall-after\", \"secs\": 6}]" 2 \
        pair "$SIM_PARENT"
    check_pair_done effect-before-timeout
    local runs
    runs=$(count "^run .*cmd=$MOVE_B" "$STATE/helpers.log")
    check "effect-before-timeout: not retried" "$([ "$runs" -eq 1 ]; echo $?)" "$runs helper runs for the move"
    check "effect-before-timeout: landed move reported" \
        "$(grep -q "vh0102b is in fips-node-n02" "$OUT"; echo $?)"
}

case_late_start() {
    drive late-start "[{\"match\": \"$MOVE_B\", \"attempts\": [1], \"mode\": \"late-start\", \"secs\": 4}]" 2 \
        pair "$SIM_PARENT"
    local first
    first=$(helper_name "$MOVE_B" 1)
    check "late-start: helper absent at removal" \
        "$(grep -q "^rm $first absent" "$STATE/helpers.log"; echo $?)" "${first:-no helper}"
    # Let the late helper start and run its move against the finished pair.
    await_helper_log "^exit $first " 15
    check "late-start: late helper ran after the retry" \
        "$(grep -q "^exit $first rc=[1-9]" "$STATE/helpers.log"; echo $?)" \
        "$(grep "^exit $first" "$STATE/helpers.log")"
    check_pair_done late-start
}

case_late_lands_first() {
    # Bound 3 s. Attempt 1's helper appears 5 s in, after the bound, the
    # removal and the check; attempt 2's waits 2.5 s before its move, so the
    # late helper moves the link first.
    local plan="[{\"match\": \"$MOVE_B\", \"attempts\": [1], \"mode\": \"late-start\", \"secs\": 5},
        {\"match\": \"$MOVE_B\", \"attempts\": [2], \"mode\": \"stall-before\", \"secs\": 2.5}]"
    drive late-lands-first "$plan" 3 pair "$SIM_PARENT"
    check_pair_done late-lands-first
    local first
    first=$(helper_name "$MOVE_B" 1)
    check "late-lands-first: move made by the late helper" \
        "$(grep -qE "^move vh0102b .* by=$first\$" "$STATE/effects.log"; echo $?)" "${first:-no helper}"
}

case_both_attempts() {
    local stall="${VETH_TEST_BOTH_STALL:-6}"
    local plan="[{\"match\": \"link set vh[0-9a-f]*0102b netns\", \"attempts\": [1, 2], \"mode\": \"stall-before\", \"secs\": $stall}]"
    drive both-attempts "$plan" 2 runner "$SIM_PARENT" "$SIM_PARENT/scenarios/ethernet-only.yaml"
    check "both-attempts: runner exits 4" "$(grep -qx 'RESULT exit=4' "$OUT"; echo $?)" "$(grep '^RESULT' "$OUT")"
    check "both-attempts: NOT SCORED printed, naming the timeout" \
        "$(grep -q '^NOT SCORED: run aborted in setup (VethSetupError: host command timed out 2 times' "$OUT"; echo $?)" \
        "$(grep '^NOT SCORED' "$OUT")"
    check "both-attempts: no assertion verdicts printed" \
        "$([ "$(count '^(PASS|FAIL) |=== Assertions ===' "$OUT")" -eq 0 ]; echo $?)"
    local runs
    runs=$(count "^run .*cmd=link set vh[0-9a-f]*0102b netns" "$STATE/helpers.log")
    check "both-attempts: two attempts at the move" "$([ "$runs" -eq 2 ]; echo $?)" "$runs helper runs"
}

for c in "${CASES[@]}"; do
    fn="case_${c//-/_}"
    if ! declare -F "$fn" >/dev/null; then
        echo "unknown case: $c (cases: ${ALL_CASES[*]})" >&2
        exit 2
    fi
    echo "--- $c"
    start=$SECONDS
    "$fn"
    echo "  took $((SECONDS - start))s"
    if [ -n "${VETH_TEST_SHOW_OUTPUT:-}" ]; then
        cat "$OUT"
    fi
done

echo
echo "${#RESULTS[@]} checks, $FAILURES failed"
[ "$FAILURES" -eq 0 ]
