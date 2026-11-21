#!/bin/bash
# Unit tests for the judge in testing/chaos/agreement-break.sh.
#
# Each case plants a results directory in the shape the lane leaves one (a
# `healthy/` run and, with a switch, a `switch/` run, each with the sim's exit
# status and the sim's own results directory: metadata.txt, assertions.txt and
# one log per node) and runs `agreement-break.sh --judge` over it. The planted
# edge_agreement verdicts are the assertion's own text, rendered by
# evaluate_agreement (testing/chaos/sim/assertions.py) for tcp-mesh's seven
# edges with three UDP edges crossed, and the startup lines are the form the
# node logs. Two switch runs' verdicts are rendered at run time instead, by the
# runner's read and score over planted listings (switch_verdict in
# testing/chaos/sim-assert-test.py), so the lane is judged on what the runner
# writes when a pair fault is or is not confirmed. No container, image or
# build is involved, so the suite is hermetic and takes a few seconds.
#
# Run:
#   ./agreement-break-test.sh
# Exits 0 only if every case gives its expected exit status and message.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LANE="$SCRIPT_DIR/../chaos/agreement-break.sh"
SWITCH="MoveKeepsInboundLink"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/agreement-break-test.XXXXXX")" || exit 2
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
CASES=0

# --- The planted verdicts --------------------------------------------------

OTHERS="PASS max_errors: 0 ERROR line(s) mesh-wide <= ceiling 0
PASS baseline: 6 node(s) answered (need 6); 1 distinct root(s) (allowed 1); 5 node(s) have a parent (need 5)"

# The crossing records evaluate_agreement lists under its verdict, one per
# crossed UDP edge, the swap at the smaller end and the keeping at the other.
record() {
    local edge="$1" small="$2" large="$3" at="$4" tail="${5:-}"
    cat <<EOF
    record $edge udp crossed: $small swapped at 20:06:$at.000Z$tail
        swap: 2026-11-02T20:06:$at.000000Z DEBUG fips::node::settle::exec::cross: Cross-connection: swapped to outbound session (our outbound wins) peer=$large new_our_index=9bcbbe9b new_their_index=225ac706 transport_id=transport:1 remote_addr=10.30.4.11:2121
        far: 2026-11-02T20:06:41.996000Z DEBUG fips::node::settle::exec::cross: Cross-connection: keeping inbound session and original their_index (peer outbound wins) peer=$small kept_their_index=Some(SessionIndex(2613821083)) transport_id=transport:1 remote_addr=10.30.4.10:2121
EOF
}

records() {
    record "n01-n02" n01 n02 42
    record "n03-n06" n03 n06 42.5
    record "n05-n06" n05 n06 43
}

# Each crossed edge as the switch leaves it: both ends inbound, so the smaller
# end is inbound after the crossing as well.
RED_N01_N02="    n01-n02 udp [direction, crossing] scored at 20:08:40.000Z: direction: n01 inbound, n02 inbound; crossing: n01, the smaller end, is inbound after the crossing n01 logged at 20:06:42.000Z. Rows: n01 lists n02 our=00aa11bb their=00cc22dd inbound udp 10.30.4.11:2121 rekey=none; n02 lists n01 our=00cc22dd their=00aa11bb inbound udp 10.30.4.10:2121 rekey=none"
RED_N03_N06="    n03-n06 udp [direction, crossing] scored at 20:08:42.000Z: direction: n03 inbound, n06 inbound; crossing: n03, the smaller end, is inbound after the crossing n03 logged at 20:06:42.500Z. Rows: n03 lists n06 our=02aa11bb their=02cc22dd inbound udp 10.30.4.15:2121 rekey=none; n06 lists n03 our=02cc22dd their=02aa11bb inbound udp 10.30.4.12:2121 rekey=none"
RED_N05_N06="    n05-n06 udp [direction, crossing] scored at 20:08:43.000Z: direction: n05 inbound, n06 inbound; crossing: n05, the smaller end, is inbound after the crossing n05 logged at 20:06:43.000Z. Rows: n05 lists n06 our=03aa11bb their=03cc22dd inbound udp 10.30.4.15:2121 rekey=none; n06 lists n05 our=03cc22dd their=03aa11bb inbound udp 10.30.4.14:2121 rekey=none"
# The shape next leaves a crossing in: both ends outbound. Direction fails;
# the smaller end is outbound, so the crossing clause holds.
OUTOUT_N01_N02="    n01-n02 udp [direction] scored at 20:08:40.000Z: direction: n01 outbound, n02 outbound. Rows: n01 lists n02 our=00aa11bb their=00cc22dd outbound udp 10.30.4.11:2121 rekey=none; n02 lists n01 our=00cc22dd their=00aa11bb outbound udp 10.30.4.10:2121 rekey=none"
# Only the smaller end inbound: the crossing clause alone.
CROSSONLY_N01_N02="    n01-n02 udp [crossing] scored at 20:08:40.000Z: crossing: n01, the smaller end, is inbound after the crossing n01 logged at 20:06:42.000Z. Rows: n01 lists n02 our=00aa11bb their=00cc22dd inbound udp 10.30.4.11:2121 rekey=none; n02 lists n01 our=00cc22dd their=00aa11bb outbound udp 10.30.4.10:2121 rekey=none"
# A one-way edge whose dialer lists the link inbound.
DIALER_N02_N03="    n02-n03 udp [dialer] scored at 20:08:41.000Z: dialer: n02 dials the edge and is inbound. Rows: n02 lists n03 our=01aa11bb their=01cc22dd inbound udp 10.30.4.12:2121 rekey=none; n03 lists n02 our=01cc22dd their=01aa11bb outbound udp 10.30.4.11:2121 rekey=none"
# A one-way TCP edge whose index pair is apart.
PAIR_N02_N05="    n02-n05 tcp [pair] scored at 20:08:45.000Z: pair: n02 our=05aa11bb their=05cc22dd, n05 our=05cc22dd their=deadbeef; no rekey flag set. Rows: n02 lists n05 our=05aa11bb their=05cc22dd outbound tcp 10.30.4.14:443 rekey=none; n05 lists n02 our=05cc22dd their=deadbeef inbound tcp 10.30.4.11:443 rekey=none"
FLOOR="    the crossing clause observed nothing: 1 edge(s) with a crossed record before their read, need 2"

green() {
    echo "$OTHERS"
    echo "PASS edge_agreement: 7 edge(s) agree within 90 s; 3 edge(s) with a crossed record (floor 2)"
    records
}

# A FAIL verdict over the given edge lines, with the three records under it.
fail_with() {
    echo "$OTHERS"
    echo "FAIL edge_agreement: $# of 7 edge(s) disagree after up to 90 s; 3 edge(s) with a crossed record (floor 2)"
    printf '%s\n' "$@"
    records
}

expected() { fail_with "$RED_N01_N02" "$RED_N03_N06" "$RED_N05_N06"; }

# --- Planting a run --------------------------------------------------------

# plant <run dir> <sim exit> <faults the nodes logged, or - for no line> [nodes]
# with assertions.txt from stdin.
plant() {
    local run="$1" rc="$2" faults="$3" logs="${4:-6}" res n
    res="$run/20261102-200640-tcp-mesh"
    mkdir -p "$res"
    echo "$rc" > "$run/sim.exit"
    cat > "$res/assertions.txt"
    printf 'scenario: tcp-mesh\nseed: 42\nnodes: 6\nedges: 7\nduration_secs: 120\n' > "$res/metadata.txt"
    for n in $(seq 1 "$logs"); do
        {
            echo "2026-11-02T20:06:40.764225Z  INFO fips: FIPS 0.6.0-dev (rev 9d1a7564) starting"
            [[ "$faults" == - ]] || echo "2026-11-02T20:06:40.770001Z  WARN fips::node::lifecycle: Test hooks compiled in faults=$faults"
            echo "2026-11-02T20:06:40.771002Z  INFO fips::node::lifecycle: Node started"
        } > "$res/fips-node-n0$n-agreement-break.log"
    done
}

# A results directory; with a switch run named SWITCH when $2 is "switch".
newdir() {
    local dir="$WORK/$1"
    mkdir -p "$dir/healthy"
    if [[ "${2:-}" == switch ]]; then
        mkdir -p "$dir/switch"
        echo "$SWITCH" > "$dir/switch/switch.name"
    fi
    echo "$dir"
}

# expect <name> <dir> <exit> <text the output must hold>
expect() {
    local name="$1" dir="$2" want="$3" text="$4" out rc
    CASES=$((CASES + 1))
    out="$(bash "$LANE" --judge "$dir" 2>&1)"
    rc=$?
    if [[ $rc -eq $want && "$out" == *"$text"* ]]; then
        echo "PASS  $name"
    else
        echo "FAIL  $name (exit $rc, want $want, looking for: $text)"
        printf '%s\n' "$out" | sed 's/^/      /'
        FAILURES=$((FAILURES + 1))
    fi
    return 0
}

# --- Cases -----------------------------------------------------------------

d="$(newdir pass switch)"
green | plant "$d/healthy" 0 ""
expected | plant "$d/switch" 3 "$SWITCH"
expect "the expected red under the switch and green without it pass" "$d" 0 \
    "the expected red under $SWITCH, at direction and crossing on 3 crossed edge(s)"

d="$(newdir outout switch)"
green | plant "$d/healthy" 0 ""
fail_with "$OUTOUT_N01_N02" "$RED_N03_N06" "$RED_N05_N06" | plant "$d/switch" 3 "$SWITCH"
expect "direction without crossing on a crossed edge is another reason" "$d" 1 \
    "n01-n02 udp red at direction without crossing on a crossed edge"

d="$(newdir crossonly switch)"
green | plant "$d/healthy" 0 ""
fail_with "$CROSSONLY_N01_N02" "$RED_N03_N06" "$RED_N05_N06" | plant "$d/switch" 3 "$SWITCH"
expect "crossing without direction is another reason" "$d" 1 \
    "n01-n02 udp red at [crossing], a red for another reason"

d="$(newdir nostartup switch)"
green | plant "$d/healthy" 0 -
expected | plant "$d/switch" 3 "$SWITCH"
expect "a node with no startup line is a miss" "$d" 1 \
    "has no 'Test hooks compiled in' line"

d="$(newdir wrongswitch switch)"
green | plant "$d/healthy" 0 ""
expected | plant "$d/switch" 3 ""
expect "a switch run whose nodes were started with no switch is a miss" "$d" 1 \
    "was not started with faults=$SWITCH"

d="$(newdir healthyswitched switch)"
green | plant "$d/healthy" 0 "$SWITCH"
expected | plant "$d/switch" 3 "$SWITCH"
expect "a no-switch run whose nodes were started with the switch is a miss" "$d" 1 \
    "no-switch run: miss: fips-node-n01-agreement-break.log was not started with faults="

d="$(newdir missinglog switch)"
green | plant "$d/healthy" 0 "" 5
expected | plant "$d/switch" 3 "$SWITCH"
expect "a node with no log is a miss" "$d" 1 \
    "5 node log(s) for 6 node(s)"

d="$(newdir greenswitch switch)"
green | plant "$d/healthy" 0 ""
green | plant "$d/switch" 0 "$SWITCH"
expect "a green switch run is a guard that guards nothing" "$d" 1 \
    "green under $SWITCH, a guard that guards nothing"

d="$(newdir redhealthy switch)"
fail_with "$PAIR_N02_N05" | plant "$d/healthy" 3 ""
expected | plant "$d/switch" 3 "$SWITCH"
expect "a red no-switch run is a miss naming the edge and clause" "$d" 1 \
    "n02-n05 tcp [pair]"

d="$(newdir paironly switch)"
green | plant "$d/healthy" 0 ""
fail_with "$PAIR_N02_N05" | plant "$d/switch" 3 "$SWITCH"
expect "a switch run red at the pair clause only is another reason" "$d" 1 \
    "n02-n05 tcp red at [pair] with no crossed record"

d="$(newdir oneway switch)"
green | plant "$d/healthy" 0 ""
fail_with "$RED_N01_N02" "$DIALER_N02_N03" "$RED_N03_N06" "$RED_N05_N06" | plant "$d/switch" 3 "$SWITCH"
expect "a red on a one-way edge beside the expected red is another reason" "$d" 1 \
    "n02-n03 udp red at [dialer] with no crossed record"

d="$(newdir floor switch)"
green | plant "$d/healthy" 0 ""
fail_with "$RED_N01_N02" "$RED_N03_N06" "$RED_N05_N06" | sed "/^FAIL edge_agreement/a\\
$FLOOR" | plant "$d/switch" 3 "$SWITCH"
expect "a floor or harness line beside the expected red is another reason" "$d" 1 \
    "a red for another reason: the crossing clause observed nothing"

d="$(newdir unlisted switch)"
green | plant "$d/healthy" 0 ""
expected | grep -v '^    record \|^        ' | plant "$d/switch" 3 "$SWITCH"
expect "direction and crossing on an edge with no crossed record listed is a miss" "$d" 1 \
    "n01-n02 udp red at [direction, crossing] with no crossed record"

d="$(newdir unred switch)"
green | plant "$d/healthy" 0 ""
fail_with "$RED_N03_N06" "$RED_N05_N06" | plant "$d/switch" 3 "$SWITCH"
expect "a crossed edge that did not red under the switch is a miss" "$d" 1 \
    "n01-n02 udp crossed and did not red under $SWITCH"

d="$(newdir ended switch)"
green | plant "$d/healthy" 0 ""
{
    echo "$OTHERS"
    echo "FAIL edge_agreement: 2 of 7 edge(s) disagree after up to 90 s; 2 edge(s) with a crossed record (floor 2)"
    printf '%s\n' "$RED_N03_N06" "$RED_N05_N06"
    record "n01-n02" n01 n02 42 ", ended at 20:07:30.000Z"
    record "n03-n06" n03 n06 42.5
    record "n05-n06" n05 n06 43
} | plant "$d/switch" 3 "$SWITCH"
expect "a crossed edge whose crossing a later promotion ended need not red" "$d" 0 \
    "on 2 crossed edge(s)"

d="$(newdir afterread switch)"
green | plant "$d/healthy" 0 ""
{
    echo "$OTHERS"
    echo "FAIL edge_agreement: 2 of 7 edge(s) disagree after up to 90 s; 2 edge(s) with a crossed record (floor 2)"
    printf '%s\n' "$RED_N03_N06" "$RED_N05_N06"
    record "n01-n02" n01 n02 42 ", after the read, not scored"
    record "n03-n06" n03 n06 42.5
    record "n05-n06" n05 n06 43
} | plant "$d/switch" 3 "$SWITCH"
expect "a crossing after the read is not this edge's crossing" "$d" 0 \
    "on 2 crossed edge(s)"

d="$(newdir otherassert switch)"
green | plant "$d/healthy" 0 ""
expected | sed 's/^PASS baseline: 6 node(s) answered/FAIL baseline: 5 node(s) answered/' \
    | plant "$d/switch" 3 "$SWITCH"
expect "another assertion red beside the expected red is a miss" "$d" 1 \
    "FAIL baseline: 5 node(s) answered"

d="$(newdir panic switch)"
green | plant "$d/healthy" 0 ""
expected | plant "$d/switch" 2 "$SWITCH"
expect "a panic in the switch run is a miss" "$d" 1 "a node panicked (sim exit 2)"

d="$(newdir notscored switch)"
green | plant "$d/healthy" 0 ""
echo "NOT SCORED: run aborted in setup (RuntimeError: veth setup timed out)" \
    | plant "$d/switch" 4 "$SWITCH"
expect "a switch run NOT SCORED is not established" "$d" 2 \
    "switch run: not established: NOT SCORED: run aborted in setup"

d="$(newdir noexit switch)"
green | plant "$d/healthy" 0 ""
expected | plant "$d/switch" 3 "$SWITCH"
rm "$d/switch/sim.exit"
expect "a run with no exit status is not established" "$d" 2 "no exit status"

d="$(newdir noresult switch)"
green | plant "$d/healthy" 0 ""
mkdir -p "$d/switch"
echo 4 > "$d/switch/sim.exit"
expect "a run that left no results directory is not established" "$d" 2 \
    "switch run: not established: no single results directory"

d="$(newdir healthyexit switch)"
green | plant "$d/healthy" 1 ""
expected | plant "$d/switch" 3 "$SWITCH"
expect "a no-switch run that passed every verdict but exited non-zero is not established" "$d" 2 \
    "PASS edge_agreement, but sim exit 1"

d="$(newdir switchexit switch)"
green | plant "$d/healthy" 0 ""
expected | plant "$d/switch" 1 "$SWITCH"
expect "the expected red with a sim exit other than 3 is not established" "$d" 2 \
    "the expected red, but sim exit 1, not 3"

d="$(newdir emptyfail switch)"
green | plant "$d/healthy" 0 ""
{
    echo "$OTHERS"
    echo "FAIL edge_agreement: 0 of 7 edge(s) disagree after up to 90 s; 0 edge(s) with a crossed record (floor 0)"
} | plant "$d/switch" 3 "$SWITCH"
expect "a FAIL verdict with no crossed edge red is a miss" "$d" 1 \
    "no crossed edge red at direction and crossing"

d="$(newdir nohealthy switch)"
rmdir "$d/healthy"
expected | plant "$d/switch" 3 "$SWITCH"
expect "a results directory with no no-switch run is not established" "$d" 2 \
    "no no-switch run under"

d="$(newdir noname switch)"
green | plant "$d/healthy" 0 ""
expected | plant "$d/switch" 3 "$SWITCH"
: > "$d/switch/switch.name"
expect "a switch run that names no switch is not established" "$d" 2 \
    "no switch list in"

d="$(newdir unsetgreen)"
green | plant "$d/healthy" 0 ""
expect "with BREAK_SWITCH set empty a green no-switch run is not a pass" "$d" 2 \
    "a guard not exercised has not passed"

d="$(newdir unsetred)"
fail_with "$OUTOUT_N01_N02" | plant "$d/healthy" 3 ""
expect "with BREAK_SWITCH set empty a red no-switch run is a miss naming the clause" "$d" 1 \
    "n01-n02 udp [direction]"

d="$(newdir noverdict)"
echo "$OTHERS" | plant "$d/healthy" 0 ""
expect "a scenario with no edge_agreement is not established" "$d" 2 \
    "the scenario carries none"

d="$(newdir noverdictnostartup)"
echo "$OTHERS" | plant "$d/healthy" 0 -
expect "an image without the switches is a miss before the verdict is read" "$d" 1 \
    "has no 'Test hooks compiled in' line"

d="$(newdir harnessred)"
{
    echo "$OTHERS"
    echo "FAIL edge_agreement: 0 of 7 edge(s) disagree after up to 90 s; 0 edge(s) with a crossed record (floor 2)"
    echo "    harness: n03: peer=npub1abcd...wxyz names no node: a swap line"
} | plant "$d/healthy" 3 ""
expect "a no-switch run red on a harness line alone is a miss naming that line" "$d" 1 \
    "harness: n03: peer=npub1abcd...wxyz names no node"

d="$(newdir nocount switch)"
green | plant "$d/healthy" 0 ""
expected | plant "$d/switch" 3 "$SWITCH"
sed -i '/^nodes:/d' "$d"/switch/*/metadata.txt
expect "a run whose metadata names no node count is not established" "$d" 2 \
    "switch run: not established: metadata.txt names no node count"

# --- The runner's own verdict ---------------------------------------------

# The edge_agreement verdict the runner gives for n01-n02 as the switch leaves
# it, with n01's row on the old session pair at the scored read and, at the
# read 3 s later that confirms a pair fault, on the new pair ("transient") or
# still the old ("persistent"), or with the pair together after a second
# crossing whose far end answered it as a redial ("redial"): switch_verdict in
# testing/chaos/sim-assert-test.py, which reads planted listings through
# _readedges and scores them with the real code.
runner_verdict() {
    python3 - "$SCRIPT_DIR/../chaos/sim-assert-test.py" "$1" <<'PY'
import importlib.util
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("simasserttest", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(mod.switch_verdict(sys.argv[2]))
PY
}

d="$(newdir runnertransient switch)"
green | plant "$d/healthy" 0 ""
{ echo "$OTHERS"; runner_verdict transient; } | plant "$d/switch" 3 "$SWITCH"
expect "a crossed edge's pair apart at one read and together at the next is not another reason" \
    "$d" 0 "at direction and crossing on 1 crossed edge(s)"

d="$(newdir runnerpersistent switch)"
green | plant "$d/healthy" 0 ""
{ echo "$OTHERS"; runner_verdict persistent; } | plant "$d/switch" 3 "$SWITCH"
expect "a crossed edge's pair apart at two reads 3 s apart is another reason" "$d" 1 \
    "n01-n02 udp red at [pair, direction, crossing], a red for another reason"

d="$(newdir runnerredial switch)"
green | plant "$d/healthy" 0 ""
{ echo "$OTHERS"; runner_verdict redial; } | plant "$d/switch" 3 "$SWITCH"
expect "both ends inbound after a second crossing the far end answered as a redial is the expected red" \
    "$d" 0 "at direction and crossing on 1 crossed edge(s)"

# --- The default switch ----------------------------------------------------

# The lane's own lines that choose the switch, read out of the script and run
# with BREAK_SWITCH unset, set empty and set; and the default checked against
# the switches fips-core declares, since a name it does not declare panics
# every node of the switch run.
SWITCH_LINES="$(grep -E '^(DEFAULT_SWITCH|SWITCH)=' "$LANE")"
FAULTS_RS="$SCRIPT_DIR/../../core/src/faults.rs"

# expect_switch <name> <want> [BREAK_SWITCH value; omitted for unset]
expect_switch() {
    local name="$1" want="$2" got
    CASES=$((CASES + 1))
    if [[ $# -ge 3 ]]; then
        got="$(BREAK_SWITCH="$3" bash -c "$SWITCH_LINES"$'\n''printf %s "$SWITCH"')"
    else
        got="$(unset BREAK_SWITCH; bash -c "$SWITCH_LINES"$'\n''printf %s "$SWITCH"')"
    fi
    if [[ $(grep -c . <<<"$SWITCH_LINES") -eq 2 && "$got" == "$want" ]]; then
        echo "PASS  $name"
    else
        echo "FAIL  $name (got '$got', want '$want'; lines: $SWITCH_LINES)"
        FAILURES=$((FAILURES + 1))
    fi
    return 0
}

expect_switch "BREAK_SWITCH unset runs the switch run with MoveKeepsInboundLink" "$SWITCH"
expect_switch "BREAK_SWITCH set empty makes no switch run" "" ""
expect_switch "BREAK_SWITCH set names the switch run's list" "MoveKeepsOldPair" "MoveKeepsOldPair"

CASES=$((CASES + 1))
default="$(sed -n 's/^DEFAULT_SWITCH="\([A-Za-z0-9_]*\)"$/\1/p' "$LANE")"
if [[ -n "$default" ]] && grep -qE "^[[:space:]]+$default,\$" "$FAULTS_RS"; then
    echo "PASS  the default switch is one fips-core declares"
else
    echo "FAIL  the default switch '$default' is not a variant in $FAULTS_RS"
    FAILURES=$((FAILURES + 1))
fi

# --- Starting a run --------------------------------------------------------

# The lane's own start_run, read out of the script, run with a chaos.sh that
# prints the environment it was started in. The caller's environment holds a
# stale FIPS_NODE_FAULTS and COMPOSE_PROJECT_NAME, so a missing unset shows.
START_RUN="$(sed -n '/^start_run() {$/,/^}$/p' "$LANE")"

# expect_start <name> <switch list, or empty> <FIPS_CI_RUN_ID, or empty>
#              <NAME=value the run must see, or -NAME it must not>...
expect_start() {
    local name="$1" faults="$2" runid="$3" dir rc want out bad=""
    shift 3
    CASES=$((CASES + 1))
    dir="$WORK/start-$CASES"
    mkdir -p "$dir/chaos/scripts"
    echo env > "$dir/chaos/scripts/chaos.sh"
    (
        export FIPS_NODE_FAULTS=stale COMPOSE_PROJECT_NAME=stale
        if [[ -n "$runid" ]]; then export FIPS_CI_RUN_ID="$runid"; else unset FIPS_CI_RUN_ID; fi
        # shellcheck disable=SC2034  # start_run, eval'd below, reads these
        OUT="$dir/out" NAME=agreement-break IMAGE=img CTX=ctx SUFFIX="" SCENARIO=s.yaml \
            CHAOS_DIR="$dir/chaos" PIDS=() ROLES=()
        eval "$START_RUN"
        start_run switch "$faults" || exit 2
        wait "${PIDS[0]}"
    )
    rc=$?
    out="$(cat "$dir/out/switch/sim.out" 2>/dev/null)"
    [[ -n "$START_RUN" ]] || bad=" start_run not found in the lane;"
    for want in "$@"; do
        if [[ "$want" == -* ]]; then
            grep -q "^${want#-}=" <<< "$out" && bad="$bad ${want#-} set;"
        else
            grep -qxF "$want" <<< "$out" || bad="$bad no $want;"
        fi
    done
    if [[ $rc -eq 0 && -z "$bad" ]]; then
        echo "PASS  $name"
    else
        echo "FAIL  $name (exit $rc;$bad)"
        printf '%s\n' "$out" | grep -v '^[A-Z_]*=' | sed 's/^/      /'
        FAILURES=$((FAILURES + 1))
    fi
    return 0
}

expect_start "a switch run with no CI run id gets the switch and no compose project" \
    "$SWITCH" "" "FIPS_NODE_FAULTS=$SWITCH" -COMPOSE_PROJECT_NAME
expect_start "a no-switch run with a CI run id gets its compose project and no switch" \
    "" ci9 "COMPOSE_PROJECT_NAME=fipsci_ci9_agreement-break-switch" -FIPS_NODE_FAULTS
expect_start "a switch run with a CI run id gets both" \
    "$SWITCH" ci9 "FIPS_NODE_FAULTS=$SWITCH" "COMPOSE_PROJECT_NAME=fipsci_ci9_agreement-break-switch"
expect_start "a no-switch run with no CI run id gets neither" \
    "" "" -FIPS_NODE_FAULTS -COMPOSE_PROJECT_NAME

echo ""
if [[ $FAILURES -gt 0 ]]; then
    echo "agreement-break-test: $FAILURES of $CASES case(s) failed"
    exit 1
fi
echo "agreement-break-test: all $CASES cases passed"
exit 0
