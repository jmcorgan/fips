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
# failure. This script exits non-zero ONLY for the interop-regression
# signal (mixed-only failures).
#
# Reps run SERIALLY — interop-test.sh uses fixed container names and a
# fixed Docker network, so two reps must never overlap.
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
#
# Artifacts (per invocation): <runs-base>/.stress-runs/<UTC-ts>/
#   rep-NN/driver.log        full interop-test.sh output for that rep.
#   rep-NN/docker-<node>.log per-container `docker logs` (FAILED reps only).
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

RUNS_BASE="$INTEROP_RUNS_BASE/.stress-runs"

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
    # passed through the environment; interop-test.sh applies it.
    FIPS_INTEROP_NETEM="${FIPS_INTEROP_NETEM:-}" \
        bash "$DRIVER" "${DRIVER_ARGS[@]}" >"$driver_log" 2>&1
    rc=$?

    if [ "$rc" -eq 0 ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  PASS (exit 0)"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_REPS+=("$rep_id")
        echo "  FAIL (exit $rc)"

        # Preserve each failed container's full docker logs. The driver
        # uses fixed container names fips-interop-<nodeid>; harvest every
        # container matching that prefix that still exists.
        while read -r ctr; do
            [ -n "$ctr" ] || continue
            docker logs "$ctr" >"$rep_dir/docker-${ctr}.log" 2>&1 || true
        done < <(docker ps -a --filter 'name=fips-interop-' \
                    --format '{{.Names}}' 2>/dev/null)

        # Tally connectivity failures by pair kind, reusing the
        # pair-attributed lines interop-test.sh prints. Each line is
        # like: "  - [baseline] MIXED pair a1[...] <-> c1[...]: ping ..."
        m="$(grep -cE '^\s*-\s*\[[^]]+\]\s+MIXED pair' "$driver_log" || true)"
        s="$(grep -cE '^\s*-\s*\[[^]]+\]\s+same pair'  "$driver_log" || true)"
        MIXED_FAILS=$((MIXED_FAILS + m))
        SAME_FAILS=$((SAME_FAILS + s))
        echo "       connectivity-failure lines: mixed=$m same=$s"
    fi
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
    else
        echo "Exit 1: interop-regression signal present."
    fi
    echo ""
    echo "Artifacts: $RUN_DIR"
} | tee "$RUN_DIR/summary.txt"

exit "$EXIT_CODE"
