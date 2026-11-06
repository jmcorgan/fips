#!/bin/bash
# Mixed-version interop NETEM STRESS LOOP.
#
# Runs interop-test.sh for N repetitions under tc-netem packet loss /
# delay, then reports a pass rate plus a mixed-vs-same-pair failure
# attribution.
#
# Why repetitions: a single run under loss is a coin flip — convergence,
# rekey, and ping retries all interact with packet loss. Only across many
# reps does a SIGNAL separate from noise. The key is the CONTROL ARM: a
# node-spec with a same-version pair (the default `a a b c` gives a1<->a2)
# lets the loop distinguish:
#
#   - failures on MIXED pairs only, never the same-version pair
#         -> an interop regression — versions diverge under loss.
#   - failures on BOTH mixed and same pairs
#         -> loss-induced general instability, not version-specific.
#   - failures on the same-version pair only
#         -> the version under test is unstable even against itself.
#
# A sub-100% pass rate under loss is EXPECTED and is not, by itself, a
# failure. This script exits 1 for the interop-regression signal
# (mixed-only failures) and 3 when a failed rep's per-node logs could not
# all be saved, so its diagnostics are incomplete.
#
# Every rep runs with FIPS_INTEROP_KEEP_UP=1, because whether a rep failed
# is known only after the driver exits. The loop saves a failed rep's
# per-node logs and then tears the mesh down itself.
#
# Reps run SERIALLY — the reps of one loop share their run name's
# containers and Docker network, so two reps must never overlap. Two
# loops may run at once under different FIPS_INTEROP_NAME and
# FIPS_INTEROP_SUBNET values.
#
# Usage:
#   ./interop-stress.sh [--reps N] [--topology <name> | node-spec...]
#
#   --reps N    repetitions (default 10).
#   --topology  built-in multi-hop topology forwarded to interop-test.sh
#               (e.g. multihop-3v-cycle). Mutually exclusive with a
#               positional node-spec. Adds multi-hop forwarding,
#               data-plane continuity, and mesh-size checks to each rep.
#   node-spec   slot letters (a/b/c), default `a a b c` (the control
#               topology — one same-version pair + five mixed pairs).
#
# Environment:
#   FIPS_INTEROP_NETEM     tc-netem string passed through to interop-test.sh,
#                          which applies it per-container. A stress run
#                          normally wants this set; if unset the script
#                          warns but still runs (a clean baseline loop).
#   REKEY_AFTER_SECS       forwarded to interop-test.sh (default 35).
#   FIPS_INTEROP_RUNS_DIR  Root for harness scratch dirs (.build/,
#                          .stress-runs/, generated-configs/). When
#                          unset, falls back to in-tree paths under
#                          testing/interop/ and prints a warning to
#                          stderr; set it to a path outside the source
#                          tree to keep generated artefacts out of the
#                          checkout.
#   FIPS_INTEROP_NAME, FIPS_INTEROP_IMAGE, FIPS_INTEROP_SUBNET
#                          forwarded to interop-test.sh; see names.sh.
#
# Artifacts (per invocation): <run-base>/.stress-runs/<UTC-ts>/, where
# <run-base> is <runs-base> for the default run name and
# <runs-base>/runs/<name> otherwise.
#   rep-NN/driver.log        full interop-test.sh output for that rep.
#   rep-NN/docker-<container>.log
#                            per-container `docker logs` (FAILED reps only).
#                            A failed rep with fewer of these than nodes
#                            makes the run exit 3.
#   summary.txt              the final aggregate report.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER="$SCRIPT_DIR/interop-test.sh"

# ── Scratch-dir root ─────────────────────────────────────────────────
#
# FIPS_INTEROP_RUNS_DIR controls where the harness writes its scratch
# directories (.build/, .stress-runs/, generated-configs/). When unset
# we fall back to in-tree paths under testing/interop/ and warn the
# operator, so the warning fires exactly once per invocation. When a
# parent script has already warned it exports _FIPS_INTEROP_WARNED=1
# to suppress duplicate warnings in child scripts.
if [[ -n "${FIPS_INTEROP_RUNS_DIR:-}" ]]; then
    INTEROP_RUNS_BASE="$FIPS_INTEROP_RUNS_DIR"
    mkdir -p "$INTEROP_RUNS_BASE"
else
    INTEROP_RUNS_BASE="$SCRIPT_DIR"
    if [[ -z "${_FIPS_INTEROP_WARNED:-}" ]]; then
        echo >&2 "WARNING: FIPS_INTEROP_RUNS_DIR not set; harness output will be written under the source tree at $INTEROP_RUNS_BASE. Set FIPS_INTEROP_RUNS_DIR to a path outside the source tree to avoid this."
        export _FIPS_INTEROP_WARNED=1
    fi
fi

# The driver's generated mesh (same paths as interop-test.sh), read for the
# expected container set and used to tear a kept-up rep down. names.sh
# reads RUNS_BASE as the harness root, so it is set to that first.
RUNS_BASE="$INTEROP_RUNS_BASE"
# shellcheck source=names.sh
source "$SCRIPT_DIR/names.sh"
interop_names
RUNS_BASE="$RUN_BASE/.stress-runs"
COMPOSE_FILE="$GEN_DIR/docker-compose.generated.yml"
NODES_ENV="$GEN_DIR/nodes.env"

# Save every node's `docker logs` into a failed rep's directory.
#
# The expected containers come from the generated manifest rather than
# from `docker ps`: an empty `docker ps` result is how a harvest that saved
# nothing used to pass without a word. A container counts only when
# `docker logs` succeeded and wrote a non-empty file. Returns 0 only when
# every expected container was saved and there was at least one.
harvest_rep() {
    local rep_dir="$1" containers tok ctr n=0 k=0
    local missing=()
    # A subshell, so the manifest's variables stay out of the loop.
    # shellcheck disable=SC1090
    containers="$( [ -f "$NODES_ENV" ] && . "$NODES_ENV" \
        && printf '%s' "${INTEROP_NODE_CONTAINERS:-}" )" || containers=""
    for tok in $containers; do
        ctr="${tok#*:}"
        n=$((n + 1))
        if docker logs "$ctr" >"$rep_dir/docker-$ctr.log" 2>&1 \
            && [ -s "$rep_dir/docker-$ctr.log" ]; then
            k=$((k + 1))
        else
            missing+=("$ctr")
        fi
    done
    echo "       harvest: $k of $n per-node logs written"
    if [ "$n" -eq 0 ]; then
        echo "       HARVEST FAILED: no manifest / empty container list ($NODES_ENV)"
        return 1
    fi
    if [ "$k" -lt "$n" ]; then
        echo "       HARVEST FAILED: $k of $n; missing: ${missing[*]}"
        return 1
    fi
    return 0
}

# Tear down a rep's kept-up mesh. A failure is loud but not fatal: the
# next rep's Phase 0 also brings the mesh down before starting.
teardown_rep() {
    local rc left
    docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans \
        >/dev/null 2>&1
    rc=$?
    MESH_UP=0
    if [ "$rc" -ne 0 ]; then
        echo "       WARN: teardown failed ($rc)"
    fi
    left="$(docker ps -a --filter "name=^$INTEROP_NAME-" --format '{{.Names}}' 2>/dev/null)"
    if [ -n "$left" ]; then
        echo "       WARN: containers remain after teardown: $(echo "$left" | tr '\n' ' ')"
    fi
    return "$rc"
}

# ── Args ─────────────────────────────────────────────────────────────

REPS=10
SPEC=()
TOPOLOGY_ARG=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --topology)
            TOPOLOGY_ARG="${2:-}"
            shift 2
            ;;
        --topology=*)
            TOPOLOGY_ARG="${1#--topology=}"
            shift
            ;;
        --reps)
            REPS="${2:-}"
            if ! [[ "$REPS" =~ ^[0-9]+$ ]] || [ "$REPS" -lt 1 ]; then
                echo "ERROR: --reps needs a positive integer" >&2
                exit 1
            fi
            shift 2
            ;;
        --reps=*)
            REPS="${1#--reps=}"
            if ! [[ "$REPS" =~ ^[0-9]+$ ]] || [ "$REPS" -lt 1 ]; then
                echo "ERROR: --reps needs a positive integer" >&2
                exit 1
            fi
            shift
            ;;
        -h|--help)
            sed -n '2,40p' "$0"
            exit 0
            ;;
        --)
            shift
            SPEC+=("$@")
            break
            ;;
        -*)
            echo "ERROR: unknown option '$1'" >&2
            exit 1
            ;;
        *)
            SPEC+=("$1")
            shift
            ;;
    esac
done

# A --topology selects spec + edges inside the driver; otherwise use the
# positional node-spec (default the control-arm topology `a a b c`).
DRIVER_ARGS=()
if [ -n "$TOPOLOGY_ARG" ]; then
    if [ "${#SPEC[@]}" -gt 0 ]; then
        echo "ERROR: pass either --topology or a node-spec, not both" >&2
        exit 1
    fi
    DRIVER_ARGS=(--topology "$TOPOLOGY_ARG")
    SPEC_STR="(topology: $TOPOLOGY_ARG)"
else
    if [ "${#SPEC[@]}" -eq 0 ]; then
        SPEC=(a a b c)
    fi
    DRIVER_ARGS=("${SPEC[@]}")
    SPEC_STR="${SPEC[*]}"
fi

# ── Preflight ────────────────────────────────────────────────────────

if [ ! -x "$DRIVER" ] && [ ! -f "$DRIVER" ]; then
    echo "ERROR: driver not found: $DRIVER" >&2
    exit 2
fi

if [ -z "${FIPS_INTEROP_NETEM:-}" ]; then
    echo "WARN: FIPS_INTEROP_NETEM is unset — a stress run normally wants"
    echo "      netem packet loss/delay. Running a clean (no-impairment)"
    echo "      loop anyway. Example:"
    echo "        FIPS_INTEROP_NETEM=\"delay 10ms 5ms 25% loss 2%\" $0"
    echo ""
fi

# ── Run directory ────────────────────────────────────────────────────

RUN_TS="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
RUN_DIR="$RUNS_BASE/$RUN_TS"
mkdir -p "$RUN_DIR"

# A rep runs kept up, so an interrupted or aborted loop must still take
# its mesh down. The INT and TERM traps exit, which runs the EXIT trap.
MESH_UP=0
trap '[ "$MESH_UP" -eq 1 ] && teardown_rep' EXIT
trap 'echo ""; echo "Interrupted"; exit 130' INT
trap 'echo ""; echo "Terminated"; exit 143' TERM

echo "=============================================================="
echo " FIPS Interop Netem Stress Loop"
echo "=============================================================="
echo ""
echo "Node-spec : $SPEC_STR"
echo "Reps      : $REPS"
echo "Netem     : ${FIPS_INTEROP_NETEM:-<none>}"
echo "Artifacts : $RUN_DIR"
echo ""

# ── Serial rep loop ──────────────────────────────────────────────────

PASS_COUNT=0
FAIL_COUNT=0
FAILED_REPS=()
# Failed reps whose per-node logs were not all saved.
HARVEST_FAILS=0
HARVEST_FAILED_REPS=()
# Phase 5b outcomes over the reps that measured a control window (Phase
# 1b ran): reps that abstained, and reps that re-measured at least once.
STREAM_REPS=0
ABSTAIN_REPS=0
REMEASURE_REPS=0
# Per-kind connectivity-failure tallies, summed across all failed reps.
MIXED_FAILS=0
SAME_FAILS=0

for ((rep = 1; rep <= REPS; rep++)); do
    rep_id="$(printf 'rep-%02d' "$rep")"
    rep_dir="$RUN_DIR/$rep_id"
    mkdir -p "$rep_dir"
    driver_log="$rep_dir/driver.log"

    echo "── $rep_id / $REPS ──────────────────────────────────────────"

    # Run the driver, capturing full output and exit code. Netem is
    # passed through the environment; interop-test.sh applies it. The
    # mesh is kept up so a failed rep can be harvested below.
    MESH_UP=1
    FIPS_INTEROP_KEEP_UP=1 FIPS_INTEROP_NETEM="${FIPS_INTEROP_NETEM:-}" \
        bash "$DRIVER" "${DRIVER_ARGS[@]}" >"$driver_log" 2>&1
    rc=$?

    # Tallied for every rep whatever its verdict: abstaining is the absence
    # of a verdict rather than a failure, so without this count a run whose
    # Phase 5b always abstains would pass unnoticed.
    if grep -q '^Phase 1b: ' "$driver_log"; then
        STREAM_REPS=$((STREAM_REPS + 1))
        if grep -q '^  ABSTAIN  Data-plane continuity' "$driver_log"; then
            ABSTAIN_REPS=$((ABSTAIN_REPS + 1))
            echo "  Phase 5b abstained (no clean control window)"
        fi
        if grep -q 'control window attempt .*re-measuring' "$driver_log"; then
            REMEASURE_REPS=$((REMEASURE_REPS + 1))
        fi
    fi

    if [ "$rc" -eq 0 ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  PASS (exit 0)"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_REPS+=("$rep_id")
        echo "  FAIL (exit $rc)"

        # Preserve each node's full docker logs before the teardown below.
        if ! harvest_rep "$rep_dir"; then
            HARVEST_FAILS=$((HARVEST_FAILS + 1))
            HARVEST_FAILED_REPS+=("$rep_id")
        fi

        # Tally connectivity failures by pair kind, reusing the
        # pair-attributed lines interop-test.sh prints. Each line is
        # like: "  - [baseline] MIXED pair a1[...] <-> c1[...]: ping ..."
        m="$(grep -cE '^\s*-\s*\[[^]]+\]\s+MIXED pair' "$driver_log" || true)"
        s="$(grep -cE '^\s*-\s*\[[^]]+\]\s+same pair'  "$driver_log" || true)"
        MIXED_FAILS=$((MIXED_FAILS + m))
        SAME_FAILS=$((SAME_FAILS + s))
        echo "       connectivity-failure lines: mixed=$m same=$s"
    fi

    teardown_rep
done

echo ""

# ── Aggregate report ─────────────────────────────────────────────────

# Pass rate as an integer percent.
if [ "$REPS" -gt 0 ]; then
    PASS_RATE=$(( PASS_COUNT * 100 / REPS ))
else
    PASS_RATE=0
fi

# ── Verdict ──────────────────────────────────────────────────────────
#
# Count mixed vs same-version pairs from a completed rep's banner so the
# verdict can normalise for the pair-count asymmetry: a spec like
# `a a b c` has 5 mixed pairs but only 1 same-version control, so an
# isolated loss blip lands on a mixed pair ~5x more often by pure chance.
# A single mixed-only failure is therefore NOT a regression signal — a
# genuine interop regression shows a concentrated, repeated mixed-only
# pattern. Require at least REGRESSION_MIN_MIXED mixed failures before
# calling it; below that, a mixed-only result is reported as loss noise.

REGRESSION_MIN_MIXED=3

MIXED_PAIRS=0
SAME_PAIRS=0
_banner="$RUN_DIR/rep-01/driver.log"
if [ -f "$_banner" ]; then
    MIXED_PAIRS=$(grep -cE '^  MIXED  ' "$_banner" || true)
    SAME_PAIRS=$(grep -cE '^  same  ' "$_banner" || true)
fi

EXIT_CODE=0
if [ "$MIXED_FAILS" -eq 0 ] && [ "$SAME_FAILS" -eq 0 ] && [ "$FAIL_COUNT" -eq 0 ]; then
    VERDICT="ALL $REPS reps passed cleanly: every pair stayed healthy across"
    VERDICT2="every rep under the applied netem profile."
elif [ "$MIXED_FAILS" -ge "$REGRESSION_MIN_MIXED" ] && [ "$SAME_FAILS" -eq 0 ]; then
    VERDICT="INTEROP REGRESSION: $MIXED_FAILS connectivity failures on MIXED-version"
    VERDICT2="pairs, none on the same-version control — a concentrated mixed-only pattern above the noise threshold. Versions diverge under loss."
    EXIT_CODE=1
elif [ "$MIXED_FAILS" -gt 0 ] && [ "$SAME_FAILS" -gt 0 ]; then
    VERDICT="LOSS-INDUCED INSTABILITY: failures on both mixed ($MIXED_FAILS) and"
    VERDICT2="same-version ($SAME_FAILS) pairs — general instability under loss, not version-specific."
elif [ "$SAME_FAILS" -gt 0 ]; then
    VERDICT="SAME-VERSION INSTABILITY: $SAME_FAILS failure(s) on the same-version"
    VERDICT2="control pair — a build is unstable even against itself, not an interop issue."
elif [ "$MIXED_FAILS" -gt 0 ]; then
    VERDICT="NO INTEROP-REGRESSION SIGNAL: $MIXED_FAILS isolated mixed-pair failure(s)"
    VERDICT2="across $FAIL_COUNT rep(s), none on the same-version control, below the regression threshold ($REGRESSION_MIN_MIXED). With $MIXED_PAIRS mixed pairs vs $SAME_PAIRS same-version, isolated loss blips land on mixed pairs more often — consistent with loss noise, not a regression."
else
    VERDICT="NO connectivity-pair failures recorded, but $FAIL_COUNT rep(s) still"
    VERDICT2="failed — on non-connectivity signatures (global-health log patterns or a missing rekey). Check the per-rep driver logs."
fi
# A regression keeps precedence; otherwise missing diagnostics fail the run.
if [ "$EXIT_CODE" -eq 0 ] && [ "$HARVEST_FAILS" -gt 0 ]; then
    EXIT_CODE=3
fi

{
    echo "=============================================================="
    echo " Interop Netem Stress — Aggregate Report"
    echo "=============================================================="
    echo ""
    echo "Run        : $RUN_TS"
    echo "Node-spec  : $SPEC_STR"
    echo "Netem      : ${FIPS_INTEROP_NETEM:-<none>}"
    echo ""
    echo "Reps run   : $REPS"
    echo "Passed     : $PASS_COUNT"
    echo "Failed     : $FAIL_COUNT"
    echo "Pass rate  : ${PASS_RATE}%"
    if [ "${#FAILED_REPS[@]}" -gt 0 ]; then
        echo "Failed reps: ${FAILED_REPS[*]}"
    fi
    if [ "$HARVEST_FAILS" -gt 0 ]; then
        echo "Harvest    : $HARVEST_FAILS failed rep(s) with incomplete per-node logs: ${HARVEST_FAILED_REPS[*]}"
    fi
    if [ "$STREAM_REPS" -gt 0 ]; then
        echo "Phase 5b   : abstained in $ABSTAIN_REPS of $STREAM_REPS reps; re-measured in $REMEASURE_REPS of $STREAM_REPS reps"
    fi
    echo ""
    echo "-- Connectivity-failure attribution (summed over failed reps) --"
    echo "  mixed-version : $MIXED_FAILS failure(s) over $MIXED_PAIRS mixed pairs x $REPS reps"
    echo "  same-version  : $SAME_FAILS failure(s) over $SAME_PAIRS same pair(s) x $REPS reps"
    echo "  regression threshold: >= $REGRESSION_MIN_MIXED mixed-only failures"
    echo ""
    echo "Verdict:"
    echo "  $VERDICT"
    echo "  $VERDICT2"
    echo ""
    if [ "$EXIT_CODE" -eq 0 ]; then
        echo "Exit 0: no interop-regression signal (a sub-100% rate under loss"
        echo "        is expected and is not by itself a failure)."
    elif [ "$EXIT_CODE" -eq 3 ]; then
        echo "Exit 3: per-node logs missing for a failed rep; the run's"
        echo "        diagnostics are incomplete."
    else
        echo "Exit 1: interop-regression signal present."
    fi
    echo ""
    echo "Artifacts: $RUN_DIR"
} | tee "$RUN_DIR/summary.txt"

exit "$EXIT_CODE"
