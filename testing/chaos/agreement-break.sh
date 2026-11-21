#!/bin/bash
# ── Chaos agreement break lane ──────────────────────────────────────────────
# Shows that the chaos `edge_agreement` assertion catches the defect it is
# there for. It builds a chaos image whose node switches can be turned on
# (the root crate's `test-hooks` feature), runs one scenario on it twice at
# once, one run with a switch set that puts back a real defect's shape and
# one with none, and judges the two: the switch run must red at exactly the
# clauses the defect breaks, and the other must stay green. A guard that
# never reds guards nothing, and one that reds a healthy image is noise; the
# lane fails both.
#
# Usage:
#   testing/chaos/agreement-break.sh              build, run both, judge
#   testing/chaos/agreement-break.sh --judge DIR  judge a results directory
#
# Environment:
#   BREAK_SCENARIO      the scenario, a path, relative to the repository root
#                       or absolute; default testing/chaos/scenarios/tcp-mesh.yaml.
#                       It must carry `edge_agreement`, or nothing is judged.
#   BREAK_SWITCH        the switch list (`core/src/faults.rs`) the switch run
#                       sets in FIPS_NODE_FAULTS; default MoveKeepsInboundLink
#                       (DEFAULT_SWITCH below), the shape this guard exists
#                       for: a crossed dial's move leaves the peer on the link
#                       it was held on, so both ends of the edge list it
#                       inbound. Set and empty, only the no-switch run is made,
#                       and the lane cannot pass: exit 2 when that run is
#                       green, since the guard was not exercised, and exit 1
#                       when it is red.
#   FIPS_TEST_IMAGE     the run's image name, required. The break image is
#                       tagged "$FIPS_TEST_IMAGE-break", so it is the run's own,
#                       and removed at the end.
#   FIPS_BUILD_CONTEXT  the run's build context, holding its integration
#                       binaries; default testing/docker, which
#                       testing/scripts/build.sh fills. The break image is
#                       built from a copy of it with `fips` replaced.
#   FIPS_CI_NAME_SUFFIX the run's name suffix; each of the two runs puts its
#                       own in front of it, so their containers, configs and
#                       networks are apart.
#   FIPS_CI_RUN_ID      when set, each run's compose project is named under
#                       the CI run's prefix, so its teardown reaps it.
#   FIPS_SIM_OUTPUT     the results directory, which must not hold an earlier
#                       lane's runs; default
#                       testing/chaos/sim-results/agreement-break<suffix>-<time>.
#   CARGO_TARGET_DIR    honoured by the build.
#
# The image: `cargo build --profile chaos-break --features
# test-overrides,test-hooks --bin fips`, into target/chaos-break so it never
# replaces target/integration/fips. Every node it starts logs `Test hooks
# compiled in faults=<FIPS_NODE_FAULTS>`, and the judge reads that line on
# every node of both runs: a run on an image without the feature, or started
# with another switch, is a miss. The integration image carries `fips-core`'s
# hooks too, so the variable's name in a binary cannot tell the two apart.
#
# The results directory: `healthy/` and, with a switch, `switch/`, each holding
# `sim.exit` (chaos.sh's exit status), `sim.out` (its output) and the sim's own
# `<time>-<scenario>/` directory; `switch/switch.name` holds BREAK_SWITCH.
#
# The judge, per run:
#   * no exit status or no single results directory, a `NOT SCORED` line or
#     the sim's exit 4 (aborted): not established;
#   * a node with no startup line, or one naming other switches: a miss;
#   * a panic (sim exit 2), or any other assertion not PASS: a miss;
#   * no `edge_agreement` verdict: not established;
#   * the no-switch run: `PASS edge_agreement` and sim exit 0, or a miss;
#   * the switch run: `FAIL edge_agreement` and sim exit 3, where every edge
#     that fails, fails at direction and crossing together, at least one does,
#     and nothing else is reported. That pair on an edge with a `crossed`
#     record is the one expected red (the switch leaves both ends inbound, so
#     the smaller end is inbound after the crossing too). Direction alone,
#     crossing alone, any other clause, a red on an edge with no `crossed`
#     record, a harness or floor line, and an edge holding a `crossed` record
#     before its read, listed with no end, which did not red are each a miss,
#     named with the edge and the clause. A record listed with an end does not
#     oblige its edge to red, even where the promotion that ended it came after
#     the read: the verdict gives no read time for an edge that agreed. A
#     pair fault in the verdict has held across two reads at least 2 s apart
#     (the round before or a confirming read, testing/chaos/sim/runner.py
#     _readedges), so it is a split, not a row read inside a rekey's
#     cutover, and is another reason like any other clause.
#
# Exit 0 = the switch run red as expected and the other green. Exit 1 = a
# miss: a guard that guards nothing, or a red for another reason. Exit 2 = not
# established: a run not scored, the switch run not made, or the lane could not
# run; never a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

CHAOS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$CHAOS_DIR/../.." && pwd)"
# shellcheck source-path=SCRIPTDIR source=../lib/image-build.sh
source "$ROOT/testing/lib/image-build.sh"

NAME="agreement-break"
STARTUP="Test hooks compiled in"
# The switch the switch run sets when BREAK_SWITCH is unset.
DEFAULT_SWITCH="MoveKeepsInboundLink"

say() { echo "$NAME: $*"; }

# ── The judge ───────────────────────────────────────────────────────────────

# The sim's own results directory under RUN, if there is exactly one.
run_result() {
    local run="$1" found=()
    mapfile -t found < <(find "$run" -mindepth 1 -maxdepth 1 -type d | sort)
    [[ ${#found[@]} -eq 1 ]] || return 1
    printf '%s\n' "${found[0]}"
    return 0
}

# Check that each of the run's nodes logged the startup line with WANT as its
# switch list, and only that. Returns 0, or 1 naming every node that did not,
# or 2 when the run's node count cannot be read.
startup_check() {
    local role="$1" res="$2" want="$3" nodes log seen=0 bad=0 line
    nodes="$(sed -n 's/^nodes: *\([0-9][0-9]*\)$/\1/p' "$res/metadata.txt" 2>/dev/null)"
    if [[ -z "$nodes" ]]; then
        say "$role run: not established: metadata.txt names no node count"
        return 2
    fi
    for log in "$res"/fips-node-*.log; do
        [[ -f "$log" ]] || continue
        seen=$((seen + 1))
        line="$(grep -F "$STARTUP" "$log")"
        if [[ -z "$line" ]]; then
            say "$role run: miss: $(basename "$log") has no '$STARTUP' line, so the image does not carry the switches"
            bad=1
        elif grep -F "$STARTUP" "$log" | grep -qvx ".*$STARTUP faults=$want"; then
            say "$role run: miss: $(basename "$log") was not started with faults=$want: $(grep -F "$STARTUP" "$log" | head -n 1)"
            bad=1
        fi
    done
    if [[ $seen -ne $nodes ]]; then
        say "$role run: miss: $seen node log(s) for $nodes node(s), so not every node was seen to carry the switches"
        bad=1
    fi
    return $bad
}

# Print the edge_agreement verdict: its first line and the indented lines under
# it, up to the next verdict.
agreement_block() {
    awk '/^(PASS|FAIL) edge_agreement:/ { on = 1; print; next }
         on && /^[[:space:]]/ { print; next }
         { on = 0 }' "$1/assertions.txt"
}

# What both runs are judged on before their edge_agreement verdict. Prints why
# and returns 2 (not established) or 1 (a miss), or returns 0 with RES and RC
# set and the verdict in BLOCK.
judge_common() {
    local role="$1" run="$2" want="$3" others rc
    RES="" RC="" BLOCK=""
    if [[ ! -f "$run/sim.exit" ]]; then
        say "$role run: not established: no exit status at $run/sim.exit"
        return 2
    fi
    RC="$(cat "$run/sim.exit")"
    if ! RES="$(run_result "$run")" || [[ ! -f "$RES/assertions.txt" ]]; then
        say "$role run: not established: no single results directory with assertions.txt under $run (sim exit $RC)"
        return 2
    fi
    if [[ "$RC" == 4 ]] || grep -q '^NOT SCORED' "$RES/assertions.txt"; then
        say "$role run: not established: $(grep -m 1 '^NOT SCORED' "$RES/assertions.txt" || echo "sim exit $RC, aborted")"
        return 2
    fi
    startup_check "$role" "$RES" "$want"
    rc=$?
    [[ $rc -eq 0 ]] || return $rc
    if [[ "$RC" == 2 ]]; then
        say "$role run: miss: a node panicked (sim exit 2), a red for another reason"
        return 1
    fi
    others="$(grep -E '^(PASS|FAIL) ' "$RES/assertions.txt" | grep -v '^PASS ' | grep -v '^FAIL edge_agreement:')"
    if [[ -n "$others" ]]; then
        say "$role run: miss: a red for another reason:"
        awk '{ print "    " $0 }' <<<"$others"
        return 1
    fi
    BLOCK="$(agreement_block "$RES")"
    if [[ -z "$BLOCK" ]]; then
        say "$role run: not established: no edge_agreement verdict in $RES/assertions.txt; the scenario carries none (sim exit $RC)"
        return 2
    fi
    return 0
}

# The no-switch run: green, or a miss naming each failing edge and clause.
judge_healthy() {
    local run="$1" rc
    judge_common "no-switch" "$run" ""
    rc=$?
    [[ $rc -eq 0 ]] || return $rc
    if [[ "$BLOCK" == FAIL* ]]; then
        say "no-switch run: miss: a red on the healthy image, at:"
        failing_lines | sed 's/^/    /'
        other_lines | sed 's/^/    /'
        printf '%s\n' "$BLOCK" | head -n 1 | sed 's/^/    /'
        return 1
    fi
    if [[ "$RC" != 0 ]]; then
        say "no-switch run: not established: PASS edge_agreement, but sim exit $RC"
        return 2
    fi
    say "no-switch run: green: $(printf '%s\n' "$BLOCK" | head -n 1)"
    return 0
}

# Each failing edge in BLOCK as "<edge> [<clauses>]".
failing_lines() {
    local line re='^    ([^ []+ [^ []+) \[([^]]*)\] scored at '
    while IFS= read -r line; do
        [[ "$line" =~ $re ]] && echo "${BASH_REMATCH[1]} [${BASH_REMATCH[2]}]"
    done <<<"$BLOCK"
    return 0
}

# Each line of BLOCK's body that is neither a failing edge nor a record: a
# harness or floor line, which says why the verdict failed without an edge.
other_lines() {
    local line re='^    ([^ []+ [^ []+) \[([^]]*)\] scored at '
    while IFS= read -r line; do
        [[ "$line" == "    "[!\ ]* && ! "$line" =~ $re && "$line" != "    record "* ]] \
            && echo "${line#    }"
    done < <(printf '%s\n' "$BLOCK" | tail -n +2)
    return 0
}

# The switch run: red at direction and crossing on every edge whose crossing
# the logs show, and on nothing else.
judge_switch() {
    local run="$1" want="$2" rc line edge clauses miss=0 expected=0
    local failre='^    ([^ []+ [^ []+) \[([^]]*)\] scored at '
    local recre='^    record ([^ ]+ [^ ]+) ([a-z]+): (.*)$'
    local -A red=() crossed=() open=()
    judge_common "switch" "$run" "$want"
    rc=$?
    [[ $rc -eq 0 ]] || return $rc
    if [[ "$BLOCK" == PASS* ]]; then
        say "switch run: miss: green under $want, a guard that guards nothing: $(printf '%s\n' "$BLOCK" | head -n 1)"
        return 1
    fi
    while IFS= read -r line; do
        if [[ "$line" =~ $failre ]]; then
            red["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
        elif [[ "$line" =~ $recre ]]; then
            # A record after the read is listed and not scored, so it is not
            # this edge's crossing; one ended by a later promotion may not
            # stand at the read, so its edge is not required to red.
            [[ "${BASH_REMATCH[2]}" == crossed ]] || continue
            [[ "${BASH_REMATCH[3]}" == *"after the read, not scored"* ]] && continue
            crossed["${BASH_REMATCH[1]}"]=1
            [[ "${BASH_REMATCH[3]}" == *", ended at "* ]] || open["${BASH_REMATCH[1]}"]=1
        elif [[ "$line" == "    "[!\ ]* ]]; then
            say "switch run: miss: a red for another reason: ${line#    }"
            miss=1
        fi
    done < <(printf '%s\n' "$BLOCK" | tail -n +2)
    for edge in "${!red[@]}"; do
        clauses="${red[$edge]}"
        if [[ "$clauses" == "direction, crossing" && -n "${crossed[$edge]:-}" ]]; then
            expected=$((expected + 1))
        elif [[ "$clauses" == direction && -n "${crossed[$edge]:-}" ]]; then
            say "switch run: miss: $edge red at direction without crossing on a crossed edge, a red for another reason"
            miss=1
        elif [[ -z "${crossed[$edge]:-}" ]]; then
            say "switch run: miss: $edge red at [$clauses] with no crossed record, a red for another reason"
            miss=1
        else
            say "switch run: miss: $edge red at [$clauses], a red for another reason"
            miss=1
        fi
    done
    for edge in "${!open[@]}"; do
        if [[ -z "${red[$edge]:-}" ]]; then
            say "switch run: miss: $edge crossed and did not red under $want, a guard that guards nothing there"
            miss=1
        fi
    done
    if [[ $expected -eq 0 ]]; then
        say "switch run: miss: no crossed edge red at direction and crossing under $want"
        miss=1
    fi
    if [[ $miss -ne 0 ]]; then
        printf '%s\n' "$BLOCK" | head -n 1 | sed 's/^/    /'
        return 1
    fi
    if [[ "$RC" != 3 ]]; then
        say "switch run: not established: the expected red, but sim exit $RC, not 3"
        return 2
    fi
    say "switch run: the expected red under $want, at direction and crossing on $expected crossed edge(s)"
    return 0
}

# Judge a results directory as the lane leaves it; the lane's exit status.
judge() {
    local dir="$1" want="" h=2 s=2
    if [[ ! -d "$dir/healthy" ]]; then
        say "not established: no no-switch run under $dir"
        return 2
    fi
    judge_healthy "$dir/healthy"
    h=$?
    if [[ -d "$dir/switch" ]]; then
        want="$(cat "$dir/switch/switch.name" 2>/dev/null)"
        if [[ ! "$want" =~ ^[A-Za-z0-9_,]+$ ]]; then
            say "switch run: not established: no switch list in $dir/switch/switch.name"
            s=2
        else
            judge_switch "$dir/switch" "$want"
            s=$?
        fi
    else
        say "switch run: not made (BREAK_SWITCH set empty); a guard not exercised has not passed"
    fi
    if [[ $h -eq 1 || $s -eq 1 ]]; then
        say "MISS: results in $dir"
        return 1
    fi
    if [[ $h -ne 0 || $s -ne 0 ]]; then
        say "NOT ESTABLISHED: results in $dir"
        return 2
    fi
    say "PASS: red under $want, green without it; results in $dir"
    return 0
}

if [[ "${1:-}" == "--judge" ]]; then
    if [[ $# -ne 2 || ! -d "$2" ]]; then
        echo "usage: $0 --judge <results directory>" >&2
        exit 2
    fi
    judge "$2"
    exit $?
fi
if [[ $# -ne 0 ]]; then
    echo "usage: $0 [--judge <results directory>]" >&2
    exit 2
fi

# ── The lane ────────────────────────────────────────────────────────────────

SWITCH="${BREAK_SWITCH-$DEFAULT_SWITCH}"
SCENARIO="${BREAK_SCENARIO:-testing/chaos/scenarios/tcp-mesh.yaml}"
[[ "$SCENARIO" == /* ]] || SCENARIO="$ROOT/$SCENARIO"
CONTEXT="${FIPS_BUILD_CONTEXT:-$ROOT/testing/docker}"
SUFFIX="${FIPS_CI_NAME_SUFFIX:-}"
OUT="${FIPS_SIM_OUTPUT:-$CHAOS_DIR/sim-results/$NAME$SUFFIX-$(date +%Y%m%d-%H%M%S)}"
TARGET="${CARGO_TARGET_DIR:-$ROOT/target}"
[[ "$TARGET" == /* ]] || TARGET="$ROOT/$TARGET"

if [[ -z "${FIPS_TEST_IMAGE:-}" ]]; then
    say "not established: FIPS_TEST_IMAGE is unset; the break image is named after the run's own"
    exit 2
fi
IMAGE="${FIPS_TEST_IMAGE}-break"
if [[ -n "$SWITCH" && ! "$SWITCH" =~ ^[A-Za-z0-9_,]+$ ]]; then
    say "not established: BREAK_SWITCH '$SWITCH' is not a list of switch names"
    exit 2
fi
if [[ ! -f "$SCENARIO" ]]; then
    say "not established: no scenario at $SCENARIO"
    exit 2
fi
for f in Dockerfile fips fipsctl; do
    if [[ ! -f "$CONTEXT/$f" ]]; then
        say "not established: $CONTEXT/$f missing; the build context must hold the run's binaries"
        exit 2
    fi
done
if [[ -e "$OUT/healthy" || -e "$OUT/switch" ]]; then
    say "not established: $OUT already holds a lane's runs"
    exit 2
fi
mkdir -p "$OUT" || exit 2

CTX=""
PIDS=()
# Stop any run still going, so its sim tears its mesh down, then remove the
# image and the context copy; the results stay.
# shellcheck disable=SC2317,SC2329  # called from the EXIT trap
cleanup() {
    local pid
    for pid in "${PIDS[@]}"; do
        pkill -TERM -P "$pid" 2>/dev/null
        kill -TERM "$pid" 2>/dev/null
    done
    for pid in "${PIDS[@]}"; do
        wait "$pid" 2>/dev/null
    done
    docker image rm "$IMAGE" >/dev/null 2>&1
    [[ -n "$CTX" ]] && rm -rf "$CTX"
    return 0
}
trap cleanup EXIT
trap 'exit 130' INT TERM

say "building the break image's fips (profile chaos-break, features test-overrides,test-hooks)"
if ! (cd "$ROOT" && cargo build --profile chaos-break --features test-overrides,test-hooks --bin fips); then
    say "not established: the break build failed"
    exit 2
fi
CTX="$(mktemp -d "${TMPDIR:-/tmp}/$NAME-context.XXXXXX")" || exit 2
if ! cp -a "$CONTEXT/." "$CTX/" || ! cp "$TARGET/chaos-break/fips" "$CTX/fips"; then
    say "not established: could not prepare the build context from $CONTEXT"
    exit 2
fi
say "building $IMAGE"
if ! retry_build "docker build $IMAGE" \
        run_quiet "docker build -t $IMAGE" docker build -t "$IMAGE" "${CI_LABELS[@]}" "$CTX"; then
    say "not established: the break image did not build"
    exit 2
fi

# Start one run in the background: ROLE, then the FIPS_NODE_FAULTS it is given,
# empty for none.
start_run() {
    local role="$1" faults="$2" dir="$OUT/$1" unset=() assign=()
    mkdir -p "$dir" || return 1
    # Every -u goes before every assignment: GNU env takes no option after
    # its first NAME=value, and runs a "-u" there as the command (exit 127).
    if [[ -n "$faults" ]]; then
        printf '%s\n' "$faults" > "$dir/switch.name"
        assign+=(FIPS_NODE_FAULTS="$faults")
    else
        unset+=(-u FIPS_NODE_FAULTS)
    fi
    if [[ -n "${FIPS_CI_RUN_ID:-}" ]]; then
        assign+=(COMPOSE_PROJECT_NAME="fipsci_${FIPS_CI_RUN_ID}_$NAME-$role")
    else
        unset+=(-u COMPOSE_PROJECT_NAME)
    fi
    env "${unset[@]}" "${assign[@]}" \
        FIPS_TEST_IMAGE="$IMAGE" FIPS_BUILD_CONTEXT="$CTX" \
        FIPS_CI_NAME_SUFFIX="-$NAME-$role$SUFFIX" FIPS_SIM_OUTPUT="$dir" \
        bash "$CHAOS_DIR/scripts/chaos.sh" "$SCENARIO" > "$dir/sim.out" 2>&1 &
    PIDS+=($!)
    ROLES+=("$role")
}

ROLES=()
say "running $(basename "$SCENARIO" .yaml)${SWITCH:+ with $SWITCH and} without a switch, results in $OUT"
start_run healthy "" || exit 2
if [[ -n "$SWITCH" ]]; then
    start_run switch "$SWITCH" || exit 2
fi
for i in "${!PIDS[@]}"; do
    wait "${PIDS[$i]}"
    echo "$?" > "$OUT/${ROLES[$i]}/sim.exit"
done
PIDS=()

judge "$OUT"
exit $?
