#!/bin/bash
# ── Mutation lane ───────────────────────────────────────────────────────────
# Each break puts back the shape a real defect took in the node, or makes the
# smallest change that fixes a known defect. manifest.txt names, for each
# break, the tests it must turn red and the tests it must let pass.
#
# Every break is a switch: a variant of `Fault` in core/src/faults.rs,
# written in the code behind `node_fault!(Name)` and turned on for one
# process by FIPS_NODE_FAULTS=<Name>. Every line runs against one build of
# the tree as it stands, so the tree need not be clean.
#
# The script, in order:
#   1. A preflight over the sources and the manifest: every line names a
#      variant, and every variant has a manifest line and a `node_fault!`
#      site. The exception is the self-check's switches (SELF below):
#      neither may have a manifest line, and PlantedGreen may have no site.
#   2. The normal-build fence: builds the `fips` binary as a user would (or
#      reads FIPS_MUTATION_FENCE_BIN) and requires the name FIPS_NODE_FAULTS
#      to appear in it 0 times (not in
#      the explorer-only mode, below). Then
#      builds both library test binaries once with testing/lib/test-verdict.sh
#      and checks that every test the manifest or the self-check names
#      resolves. On a host whose build compiles no BLE transport (build.rs
#      sets `ble_available` for glibc Linux, Android and macOS), the fips-mesh
#      binary lists no test under transport::ble::, and then the lines whose
#      test is behind `ble_available` (BLE_ONLY below) are skipped, and their
#      count printed. Where transport::ble:: tests are listed, a BLE line
#      whose test does not resolve is a miss like any other. The tests only
#      the root crate's `explorers` feature compiles (EXPLORER_ONLY below)
#      are skipped the same way, by module, when the build lists none of the
#      module's tests: each skipped line's test must still be defined, as
#      `fn <name>(`, in its module's file, so a misspelled or renamed name
#      is a miss in every build. FIPS_MUTATION_EXPLORERS=1 builds with that
#      feature and skips none of them. FIPS_MUTATION_EXPLORERS=only builds
#      with it and runs those lines alone: every other line is skipped, the
#      fence is left to the plain lane on the same tree, and a manifest with
#      no such line fails before anything is built. The switches left with no
#      line to run are printed by name.
#   3. The self-check: each SELF entry runs its planted test with its switch
#      on and goes through the same `held` decision as a red manifest line
#      with no anchor; the decision must be the one SELF gives. PlantedRed's
#      test must be decided held, and PlantedGreen's, a test that passes,
#      must be decided not held. A wrong decision exits 1 before any manifest
#      line runs.
#   4. Every test the manifest names runs once with no switch and must pass,
#      unless testing/ignored-tests.txt marks it known-defect.
#   5. The switch lines, each test in its own process, classified with
#      testing/lib/test-verdict.sh.
#
# A `red` line holds when the test fails at the behaviour the break breaks:
#   - with no anchor, the class must be `defect` (the test's own `defect:`
#     assertion);
#   - with an anchor, the class must be `defect` or `unmarked`, and the anchor
#     must be a substring of the panic's first message line, or the panic
#     location must be at the anchor's `file:line`. An existing test that
#     predates the `defect:` marker is checked this way.
# A `pass` line holds when the test passes. `precondition`, `timeout` and
# `norun` never hold: a test that broke in setup or hung has not shown the
# break's effect.
#
# Environment:
#   FIPS_MUTATION_TIMEOUT  seconds per test run (default 120)
#   FIPS_MUTATION_ONLY     run only the break of this name (for trying one)
#   FIPS_MUTATION_FENCE_BIN  a fips binary for the normal-build fence to read
#                          instead of building one; testing/ci-local.sh passes
#                          the one from the .deb its build stage made, which is
#                          what users install. A path that is not an
#                          executable exits 2. GitHub's test-mutations job
#                          starts before its package exists and builds its own,
#                          which the check treats the same.
#   FIPS_MUTATION_EXPLORERS  1 to build the root crate's library tests with
#                          its `explorers` feature and run every line; only
#                          to build with it and run just the lines whose
#                          test that feature compiles (EXPLORER_ONLY).
#                          testing/ci-local.sh uses only, as its own stage,
#                          with --explorers and at tiers 2 and 3 on a tree
#                          that builds the root explorer, which next does
#                          not; no GitHub workflow and no tier 1 run sets
#                          it. Any other value exits 2.
# FIPS_NODE_FAULTS from the caller's environment is ignored: the lane sets
# it per run.
#
# Exit 0 = every manifest line held. Exit 1 = a line missed, the preflight,
# the fence or the self-check failed, a test name did not resolve, or a named
# test failed with no switch. Exit 2 = the lane could not run (a build failed
# or named no binary, manifest or switch list unreadable).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
unset FIPS_NODE_FAULTS

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MANIFEST="$SCRIPT_DIR/manifest.txt"
FAULTS="$PROJECT_ROOT/core/src/faults.rs"
INVENTORY="$PROJECT_ROOT/testing/ignored-tests.txt"
LIMIT="${FIPS_MUTATION_TIMEOUT:-120}"
ONLY="${FIPS_MUTATION_ONLY:-}"
EXPLORERS="${FIPS_MUTATION_EXPLORERS:-}"

cd "$PROJECT_ROOT" || exit 2
case "$EXPLORERS" in
    "" | 1 | only) ;;
    *) echo "mutation-lane: FIPS_MUTATION_EXPLORERS takes 1 or only, not: $EXPLORERS" >&2; exit 2 ;;
esac
for f in "$MANIFEST" "$FAULTS" "$INVENTORY"; do
    [[ -r "$f" ]] || { echo "mutation-lane: cannot read $f" >&2; exit 2; }
done

# shellcheck source-path=SCRIPTDIR source=../lib/test-verdict.sh disable=SC1091
source "$SCRIPT_DIR/../lib/test-verdict.sh"

# The self-check: <switch> <decision held must give> <planted test>, each test
# under node::tests::settle::lane. Neither switch has a manifest line;
# PlantedGreen has no site, so its test passes and a red line run on it must
# be decided a miss.
SELF_TESTS="node::tests::settle::lane"
declare -a S_SWITCH=() S_WANT=() S_TEST=()
while read -r sw want name; do
    S_SWITCH+=("$sw"); S_WANT+=("$want"); S_TEST+=("$SELF_TESTS::$name")
done <<'SELF'
PlantedRed   yes a_planted_switch_reds_at_its_defect_assertion
PlantedGreen no  a_planted_test_that_passes
SELF

# The tests behind `ble_available`, skipped on a host that compiles no BLE
# transport: a name ending in `::` is a module prefix, any other one test.
# Each module is gated in its parent (src/node/tests/mod.rs,
# src/transport/mod.rs, src/transport/tests/conformance/mod.rs) and the test
# by its own attribute. A BLE line missing here reds on such a host, the
# loud direction.
BLE_ONLY=(
    "node::tests::ble::"
    "node::tests::ble_lifecycle::"
    "transport::ble::close_tests::"
    "transport::ble::lane_tests::"
    "transport::ble::retry_tests::"
    "node::tests::ble_queue::"
    "transport::conformance::ble::"
    "node::tests::settle::carry::the_ble_initiators_link_is_verified_before_any_responder_frame"
    "node::tests::settle::table::promote::a_promotion_on_a_ble_link_marks_it_at_the_initiator_and_at_the_responders_first_frame"
    "node::tests::settle::table::crossing::a_crossing_won_on_a_second_ble_link_relinks_the_mark"
    "node::tests::settle::table::remove::disconnect_on_a_ble_link_leaves_the_mark_as_its_cell_says"
    "node::tests::settle::table::remove::disconnect_on_a_ble_link_leaves_the_mark_as_its_cell_says_with_multipath_on"
    "node::tests::settle::crossing::a_reaped_ble_dial_leaves_the_channel_another_dial_in_flight_uses"
    "node::tests::settle::crossing::a_reaped_ble_dial_leaves_the_channel_another_dial_in_flight_uses_with_multipath_on"
)

# The fips-mesh tests only the root crate's `explorers` feature compiles:
# the module prefix (gated in src/node/tests/settle/explore/mod.rs), then
# the file that defines its tests.
EXPLORER_ONLY=(
    "node::tests::settle::explore::oracle:: src/node/tests/settle/explore/oracle.rs"
    "node::tests::settle::explore::parity:: src/node/tests/settle/explore/parity.rs"
)

# The manifest's lines: break, expectation, crate, test, anchor.
declare -a M_BREAK=() M_WANT=() M_CRATE=() M_TEST=() M_ANCHOR=()
while IFS=$'\t' read -r brk want crate test anchor; do
    [[ -z "$brk" || "$brk" == \#* ]] && continue
    M_BREAK+=("$brk"); M_WANT+=("$want"); M_CRATE+=("$crate")
    M_TEST+=("$test"); M_ANCHOR+=("${anchor:-}")
done <"$MANIFEST"
[[ ${#M_BREAK[@]} -gt 0 ]] || { echo "mutation-lane: the manifest names no test" >&2; exit 2; }

# The variants, from the `faults!` invocation in faults.rs: one name per
# line, followed by a comma.
mapfile -t VARIANTS < <(awk '
    /^faults! \{/ { on = 1; next }
    on && /^\}/ { exit }
    on && /^[[:space:]]+[A-Z][A-Za-z0-9]*,[[:space:]]*$/ { gsub(/[[:space:],]/, ""); print }
' "$FAULTS")
[[ ${#VARIANTS[@]} -gt 0 ]] || { echo "mutation-lane: no switch found in $FAULTS" >&2; exit 2; }

in_list() {
    local x="$1" y
    shift
    for y in "$@"; do [[ "$x" == "$y" ]] && return 0; done
    return 1
}
# The number of `node_fault!(<name>)` sites in the crates' Rust sources,
# outside comment lines.
sites() {
    grep -rhE --include='*.rs' "node_fault!\\($1\\)" src core/src 2>/dev/null \
        | grep -cvE '^[[:space:]]*//'
    return 0
}

misses=0
miss() {
    echo "mutation-lane: MISS $*"
    misses=$((misses + 1))
    return 0
}

# 1. The preflight.
for i in "${!M_BREAK[@]}"; do
    n=$((i + 1)) brk="${M_BREAK[$i]}"
    case "${M_WANT[$i]}" in red | pass) ;; *) miss "line $n: expectation ${M_WANT[$i]}" ;; esac
    in_list "$brk" "${VARIANTS[@]}" || miss "line $n: $brk is no variant of Fault"
    if in_list "$brk" "${S_SWITCH[@]}"; then
        miss "line $n: $brk is a self-check switch, which takes no manifest line"
    fi
done
for sw in "${S_SWITCH[@]}"; do
    in_list "$sw" "${VARIANTS[@]}" || miss "self-check switch $sw is no variant of Fault"
done
for v in "${VARIANTS[@]}"; do
    if [[ "$v" == PlantedGreen ]]; then
        [[ $(sites "$v") -eq 0 ]] || miss "PlantedGreen has a node_fault! site; it must have none"
        continue
    fi
    in_list "$v" "${S_SWITCH[@]}" && continue
    in_list "$v" "${M_BREAK[@]}" || miss "switch $v has no manifest line"
    [[ $(sites "$v") -gt 0 ]] || miss "switch $v has no node_fault! site"
done
if [[ $misses -gt 0 ]]; then
    echo "mutation-lane: $misses problem(s) in the preflight; no test was run"
    exit 1
fi

# In the explorer-only mode, the lines whose test is in an EXPLORER_ONLY
# module, by index; a manifest with none fails here, before any build, since
# a lane that runs nothing would otherwise pass.
declare -A PICKED=()
if [[ "$EXPLORERS" == only ]]; then
    for i in "${!M_BREAK[@]}"; do
        [[ "${M_CRATE[$i]}" == fips-mesh ]] || continue
        for entry in "${EXPLORER_ONLY[@]}"; do
            read -r prefix _ <<<"$entry"
            [[ "${M_TEST[$i]}" == "$prefix"* ]] && { PICKED[$i]=1; break; }
        done
    done
    if [[ ${#PICKED[@]} -eq 0 ]]; then
        echo "mutation-lane: no manifest line's test is an explorer walk; nothing to run"
        exit 1
    fi
fi

start_all=$(date +%s)

# The normal-build fence: the switches must be absent from a normal build.
# The `fips` binary is built as a user would build it, and the variable's
# name must not appear in it: with `test-hooks` reaching a normal build, the
# core's `faults` module and its sites are linked in and the name with them.
# A failed build or a missing binary exits 2 and is never read as a count,
# since a failed build leaves the previous binary in place.
fence() {
    local fence_bin fence_count
    if [[ -n "${FIPS_MUTATION_FENCE_BIN:-}" ]]; then
        fence_bin="$FIPS_MUTATION_FENCE_BIN"
        if [[ ! -f "$fence_bin" || ! -x "$fence_bin" ]]; then
            echo "mutation-lane: fence: $fence_bin is not an executable" >&2
            exit 2
        fi
        echo "mutation-lane: the fence reads $fence_bin"
    else
        fence_build
    fi
    fence_count=$(grep -a -c FIPS_NODE_FAULTS "$fence_bin")
    case $? in
        0 | 1) ;;
        *) echo "mutation-lane: fence: could not read $fence_bin" >&2; exit 2 ;;
    esac
    if [[ "$fence_count" != 0 ]]; then
        miss "fence: FIPS_NODE_FAULTS appears $fence_count time(s) in the normal build $fence_bin"
        echo "mutation-lane: the switches reach a normal build; no test was run"
        exit 1
    fi
    echo "   fence $fence_bin: FIPS_NODE_FAULTS appears 0 times"
    return 0
}

# Build the normal fips binary for the fence and set the caller's fence_bin
# to it.
fence_build() {
    local fence_json
    echo "mutation-lane: building the normal fips binary for the fence"
    fence_json=$(cargo build -p fips-mesh --bin fips --message-format=json) || {
        echo "mutation-lane: fence: the normal build of fips failed" >&2
        exit 2
    }
    fence_bin=$(python3 -c '
import json, sys
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if msg.get("reason") == "compiler-artifact" and msg.get("executable") \
            and msg["target"]["name"] == "fips" and "bin" in msg["target"]["kind"]:
        print(msg["executable"])
' <<<"$fence_json")
    if [[ -z "$fence_bin" || ! -x "$fence_bin" ]]; then
        echo "mutation-lane: fence: the build named no fips binary" >&2
        exit 2
    fi
    return 0
}

# The explorer-only mode leaves the fence out: the plain lane runs it on the
# same tree.
if [[ "$EXPLORERS" == only ]]; then
    echo "mutation-lane: explorer lines only; the normal-build fence is the plain lane's, on the same tree"
else
    fence
fi

if [[ -n "$EXPLORERS" ]]; then
    echo "mutation-lane: building the healthy tree, with the root crate's explorers"
    test_bins fips-mesh/explorers || exit 2
else
    echo "mutation-lane: building the healthy tree"
    test_bins || exit 2
fi

# 2. Every name resolves. Each binary is listed once, into a variable: a
# `grep -q` reading the listing through a pipe would stop it early, and
# pipefail would count that as a missing name.
declare -A LISTED=()
for pkg in fips-mesh fips-core; do
    LISTED[$pkg]=$("${BIN[$pkg]}" --list --format terse 2>/dev/null) || {
        echo "mutation-lane: listing $pkg's tests failed" >&2
        exit 2
    }
done
# The lines skipped on a host with no BLE transport, by index.
declare -A SKIP=()
# The explorer-only mode runs the picked lines and no other.
if [[ "$EXPLORERS" == only ]]; then
    declare -A SWITCHES=()
    for i in "${!M_BREAK[@]}"; do
        if [[ -n "${PICKED[$i]:-}" ]]; then
            SWITCHES[${M_BREAK[$i]}]=1
        else
            SKIP[$i]=1
        fi
    done
    echo "mutation-lane: explorer lines only: ${#PICKED[@]} line(s) over ${#SWITCHES[@]} switch(es)"
fi
if ! grep -q '^transport::ble::' <<<"${LISTED[fips-mesh]}"; then
    for i in "${!M_BREAK[@]}"; do
        [[ "${M_CRATE[$i]}" == fips-mesh ]] || continue
        for b in "${BLE_ONLY[@]}"; do
            if [[ ( "$b" == *:: && "${M_TEST[$i]}" == "$b"* ) || "${M_TEST[$i]}" == "$b" ]]; then
                SKIP[$i]=1
                break
            fi
        done
    done
    echo "mutation-lane: this build has no BLE transport (no transport::ble:: test);" \
        "${#SKIP[@]} line(s) whose test is behind ble_available skipped"
fi
# The lines skipped in a build without the explorers, each test checked
# against its module's file instead of the list.
explorer_skips=0
if [[ -z "$EXPLORERS" ]]; then
    for entry in "${EXPLORER_ONLY[@]}"; do
        read -r prefix file <<<"$entry"
        grep -qF -- "$prefix" <<<"${LISTED[fips-mesh]}" && continue
        for i in "${!M_BREAK[@]}"; do
            [[ "${M_CRATE[$i]}" == fips-mesh && "${M_TEST[$i]}" == "$prefix"* ]] || continue
            [[ -n "${SKIP[$i]:-}" ]] && continue
            if grep -qE "^[[:space:]]*fn ${M_TEST[$i]#"$prefix"}\(" "$file"; then
                SKIP[$i]=1
                explorer_skips=$((explorer_skips + 1))
            else
                miss "line $((i + 1)): ${M_TEST[$i]} is defined in no fn of $file"
                SKIP[$i]=1
            fi
        done
    done
fi
if [[ $explorer_skips -gt 0 ]]; then
    declare -a BARE=()
    for b in "${M_BREAK[@]}"; do
        in_list "$b" "${BARE[@]}" && continue
        runs=false
        for i in "${!M_BREAK[@]}"; do
            [[ "${M_BREAK[$i]}" == "$b" && -z "${SKIP[$i]:-}" ]] && { runs=true; break; }
        done
        [[ "$runs" == false ]] && BARE+=("$b")
    done
    echo "mutation-lane: this build has no explorers (FIPS_MUTATION_EXPLORERS is unset);" \
        "$explorer_skips line(s) whose test only the explorers feature compiles skipped;" \
        "switches with no line left to run: ${BARE[*]:-none}"
fi
for i in "${!M_BREAK[@]}"; do
    [[ -n "${SKIP[$i]:-}" ]] && continue
    if ! grep -qxF "${M_TEST[$i]}: test" <<<"${LISTED[${M_CRATE[$i]}]:-}"; then
        miss "line $((i + 1)): ${M_CRATE[$i]} has no test ${M_TEST[$i]}"
    fi
done
for name in "${S_TEST[@]}"; do
    grep -qxF "$name: test" <<<"${LISTED[fips-mesh]}" || miss "self-check: fips-mesh has no test $name"
done
if [[ $misses -gt 0 ]]; then
    echo "mutation-lane: $misses problem(s) in the manifest; no test was run"
    exit 1
fi

# run_one <crate> <test> [<switch>]: run one test in its own process, with
# the switch on if one is given, and set class, loc, msg and took.
run_one() {
    local crate="$1" name="$2" sw="${3:-}" out rc ts tenths
    ts=$(date +%s%N)
    if [[ -n "$sw" ]]; then
        out=$(FIPS_NODE_FAULTS="$sw" timeout -k 5 "$LIMIT" "${BIN[$crate]}" --include-ignored --exact "$name" 2>&1)
    else
        out=$(timeout -k 5 "$LIMIT" "${BIN[$crate]}" --include-ignored --exact "$name" 2>&1)
    fi
    rc=$?
    IFS=$'\t' read -r class loc msg < <(verdict "$out" "$rc" "$name")
    tenths=$(( ($(date +%s%N) - ts) / 100000000 ))
    took="$((tenths / 10)).$((tenths % 10)) s"
    return 0
}

# held <want> <anchor> <class> <location> <message>: whether a run with that
# verdict holds a line with that expectation and anchor. Prints yes or no.
held() {
    local want="$1" anchor="$2" class="$3" loc="$4" msg="$5"
    if [[ "$want" == pass ]]; then
        [[ "$class" == passed ]] && { echo yes; return 0; }
    elif [[ -z "$anchor" ]]; then
        [[ "$class" == defect ]] && { echo yes; return 0; }
    elif [[ "$class" == defect || "$class" == unmarked ]]; then
        if [[ "$msg" == *"$anchor"* || "$loc" == "$anchor":* ]]; then
            echo yes
            return 0
        fi
    fi
    echo no
    return 0
}

# check <break> <line index> [<switch>]: run one manifest line and report it.
check() {
    local brk="$1" i="$2" sw="${3:-}" want anchor line
    want="${M_WANT[$i]}" anchor="${M_ANCHOR[$i]}"
    run_one "${M_CRATE[$i]}" "${M_TEST[$i]}" "$sw"
    line="$want ${M_TEST[$i]} ($took): $class${loc:+ at $loc}${msg:+: $msg}"
    if [[ $(held "$want" "$anchor" "$class" "$loc" "$msg") == yes ]]; then
        echo "   held  $line"
    else
        miss "$brk: $line${anchor:+ (anchor: $anchor)}"
    fi
    return 0
}

# 3. The self-check.
self_misses=0
for i in "${!S_SWITCH[@]}"; do
    run_one fips-mesh "${S_TEST[$i]}" "${S_SWITCH[$i]}"
    got=$(held red "" "$class" "$loc" "$msg")
    echo "   self  ${S_SWITCH[$i]} ${S_TEST[$i]} ($took): $class${loc:+ at $loc}: held $got, expected ${S_WANT[$i]}"
    if [[ "$got" != "${S_WANT[$i]}" ]]; then
        echo "mutation-lane: lane self-check: ${S_SWITCH[$i]} on ${S_TEST[$i]} was decided held $got, expected ${S_WANT[$i]}"
        self_misses=$((self_misses + 1))
    fi
done
if [[ $self_misses -gt 0 ]]; then
    echo "mutation-lane: lane self-check: $self_misses miss(es); no manifest line was run"
    exit 1
fi
echo "mutation-lane: lane self-check passed (PlantedRed held, PlantedGreen a miss)"

# The breaks, in manifest order, each once.
declare -a BREAKS=()
for b in "${M_BREAK[@]}"; do
    in_list "$b" "${BREAKS[@]}" || BREAKS+=("$b")
done
selected() { [[ -z "$ONLY" || "$1" == "$ONLY" ]]; }

# 4. Each named test, once, with no switch.
known_defect() {
    awk -v c="$1" -v t="$2" \
        '!/^[[:space:]]*#/ && $1 == "known-defect" && $2 == c && $3 == t { f = 1 } END { exit !f }' \
        "$INVENTORY"
}
declare -A HEALTHY=()
for i in "${!M_BREAK[@]}"; do
    selected "${M_BREAK[$i]}" || continue
    [[ -n "${SKIP[$i]:-}" ]] && continue
    key="${M_CRATE[$i]} ${M_TEST[$i]}"
    [[ -n "${HEALTHY[$key]:-}" ]] && continue
    HEALTHY[$key]=1
    if known_defect "${M_CRATE[$i]}" "${M_TEST[$i]}"; then
        echo "   known-defect, not run with no switch: ${M_TEST[$i]}"
        continue
    fi
    run_one "${M_CRATE[$i]}" "${M_TEST[$i]}"
    if [[ "$class" == passed ]]; then
        echo "   healthy ${M_TEST[$i]} ($took)"
    else
        miss "no switch: ${M_TEST[$i]} ($took): $class${loc:+ at $loc}${msg:+: $msg}"
    fi
done

# 5. The switches, against the one build.
for brk in "${BREAKS[@]}"; do
    selected "$brk" || continue
    # The explorer-only mode passes over the switches it runs no line of.
    [[ "$EXPLORERS" == only ]] && ! in_list "$brk" "${!SWITCHES[@]}" && continue
    t0=$(date +%s)
    echo "== $brk"
    for i in "${!M_BREAK[@]}"; do
        [[ "${M_BREAK[$i]}" == "$brk" && -z "${SKIP[$i]:-}" ]] && check "$brk" "$i" "$brk"
    done
    echo "   $brk: $(($(date +%s) - t0)) s"
done

echo "mutation-lane: total $(($(date +%s) - start_all)) s"
if [[ $misses -gt 0 ]]; then
    echo "mutation-lane: $misses miss(es)"
    exit 1
fi
echo "mutation-lane: every line of $(basename "$MANIFEST") held"
exit 0
