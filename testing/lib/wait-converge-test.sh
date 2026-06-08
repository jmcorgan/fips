#!/bin/bash
# Unit tests for wait_until_connected() in wait-converge.sh.
#
# These tests drive the convergence gate with synthetic connectivity
# checks (ping_fn stand-ins) that report scripted PASSED/FAILED counts
# keyed off the same SECONDS clock the gate uses. No containers or
# network are involved, so the whole suite runs in a few seconds and is
# safe to run in CI.
#
# Run:
#   ./wait-converge-test.sh
# Exits 0 only if every case passes; non-zero if any case fails.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/wait-converge.sh"

RESULTS=()
FAILURES=0

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
}

# Each ping_fn records its own start on first call so its schedule is
# measured from when the gate began polling it, regardless of the wall
# clock at suite start. PT (ping-elapsed time) is computed inline in each
# ping_fn — NOT via a subshell — so the PING_START assignment persists.
PING_START=-1
reset_ping() {
    PING_START=-1
}

# --- Synthetic connectivity checks ------------------------------------

# Sets global PT to ping-elapsed seconds. Must be called (not subshelled)
# at the top of each ping_fn so the first-call timestamp persists.
PT=0
set_pt() {
    if (( PING_START < 0 )); then
        PING_START=$SECONDS
    fi
    PT=$(( SECONDS - PING_START ))
}

# Case 1 trace: improves (16 reachable) early, climbs to 18, then holds
# at FAILED=1 (within slack) until late, then fully converges. Mirrors a
# deep node whose last pair clears only after stacked discovery backoff.
ping_near_converged_hold() {
    set_pt; local t=$PT
    if (( t < 3 )); then
        PASSED=16; FAILED=4
    elif (( t < 6 )); then
        PASSED=18; FAILED=2
    elif (( t < 12 )); then
        # Stuck within slack: one straggling pair pending.
        PASSED=19; FAILED=1
    else
        PASSED=20; FAILED=0
    fi
}

# Case 2 trace: climbs a little, then wedges far from convergence with
# FAILED well above the slack. Should fast-bail on stall.
ping_far_stall() {
    set_pt; local t=$PT
    if (( t < 3 )); then
        PASSED=8; FAILED=12
    else
        # Stuck for good, many pairs still pending (> slack).
        PASSED=10; FAILED=10
    fi
}

# Case 3 trace: never converges; always one pair pending and never makes
# further progress after the first reading. Should hit the hard cap.
# FAILED stays at exactly 1 here so it is within the default slack=2 and
# the near-converged hold keeps polling all the way to max_secs.
ping_never_converges() {
    PASSED=19; FAILED=1
}

# Case 4 trace: backward-compat. Same shape as case 1 (near-converged
# straggler) but driven with only 4 args so the default slack applies.
ping_backcompat_hold() {
    set_pt; local t=$PT
    if (( t < 3 )); then
        PASSED=16; FAILED=4
    elif (( t < 6 )); then
        PASSED=18; FAILED=2
    elif (( t < 12 )); then
        PASSED=19; FAILED=1
    else
        PASSED=20; FAILED=0
    fi
}

HOLD_MSG="holding for full budget"
STUCK_MSG="STUCK"

# --- Case 1: near-converged hold --------------------------------------
echo
echo "== Case 1: near-converged hold (slack saves it) =="
reset_ping
out=$(wait_until_connected ping_near_converged_hold 20 4 1 2); rc=$?
echo "$out"
c1_rc_ok=1; [ "$rc" -eq 0 ] && c1_rc_ok=0
check "case1: returns 0 (eventually converges)" "$c1_rc_ok" "rc=$rc"
c1_hold_ok=1; echo "$out" | grep -q "$HOLD_MSG" && c1_hold_ok=0
check "case1: near-converged hold branch taken" "$c1_hold_ok" "expected '$HOLD_MSG' in output"

# Same trace with slack=0 must fail (old behavior) — proves slack matters.
echo "-- Case 1b: same trace, slack=0 (old behavior) must bail --"
reset_ping
out0=$(wait_until_connected ping_near_converged_hold 20 4 1 0); rc0=$?
echo "$out0"
c1b_rc_ok=1; [ "$rc0" -ne 0 ] && c1b_rc_ok=0
check "case1b: returns 1 with slack=0" "$c1b_rc_ok" "rc=$rc0"
c1b_stuck_ok=1; echo "$out0" | grep -q "$STUCK_MSG" && c1b_stuck_ok=0
check "case1b: bailed via STUCK (not hold)" "$c1b_stuck_ok" "expected '$STUCK_MSG' in output"

# --- Case 2: far-from-converged stall (fast-bail) ---------------------
echo
echo "== Case 2: far-from-converged stall (fast-bail) =="
reset_ping
start=$SECONDS
out=$(wait_until_connected ping_far_stall 30 4 1 2); rc=$?
elapsed=$((SECONDS - start))
echo "$out"
c2_rc_ok=1; [ "$rc" -ne 0 ] && c2_rc_ok=0
check "case2: returns 1 (stall bail)" "$c2_rc_ok" "rc=$rc"
c2_stuck_ok=1; echo "$out" | grep -q "$STUCK_MSG" && c2_stuck_ok=0
check "case2: bailed via STUCK message" "$c2_stuck_ok"
# Fast-bail: must finish well before the 30s hard cap.
c2_fast_ok=1; [ "$elapsed" -lt 20 ] && c2_fast_ok=0
check "case2: fast-bail (before hard cap)" "$c2_fast_ok" "elapsed=${elapsed}s < 20s"
c2_nocap_ok=1; echo "$out" | grep -q "TIMEOUT" || c2_nocap_ok=0
check "case2: did NOT hit hard-cap TIMEOUT" "$c2_nocap_ok"

# --- Case 3: never converges (hard cap) -------------------------------
echo
echo "== Case 3: never converges (hard cap) =="
reset_ping
start=$SECONDS
out=$(wait_until_connected ping_never_converges 6 3 1 2); rc=$?
elapsed=$((SECONDS - start))
echo "$out"
c3_rc_ok=1; [ "$rc" -ne 0 ] && c3_rc_ok=0
check "case3: returns 1 (never converges)" "$c3_rc_ok" "rc=$rc"
c3_cap_ok=1; echo "$out" | grep -q "TIMEOUT" && c3_cap_ok=0
check "case3: hit hard-cap TIMEOUT message" "$c3_cap_ok"
# Hard cap: must run roughly to max_secs (6s), not bail early.
c3_dur_ok=1; [ "$elapsed" -ge 6 ] && c3_dur_ok=0
check "case3: ran to hard cap (~max_secs)" "$c3_dur_ok" "elapsed=${elapsed}s >= 6s"

# --- Case 4: backward-compat (4 args, default slack=2) ----------------
echo
echo "== Case 4: backward-compat, no slack arg (default=2) =="
reset_ping
out=$(wait_until_connected ping_backcompat_hold 20 4 1); rc=$?
echo "$out"
c4_rc_ok=1; [ "$rc" -eq 0 ] && c4_rc_ok=0
check "case4: returns 0 with 4 args" "$c4_rc_ok" "rc=$rc"
c4_hold_ok=1; echo "$out" | grep -q "$HOLD_MSG" && c4_hold_ok=0
check "case4: default slack triggered near-converged hold" "$c4_hold_ok"

# --- Summary ----------------------------------------------------------
echo
echo "=============================================="
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo "=============================================="
if [ "$FAILURES" -ne 0 ]; then
    echo "RESULT: $FAILURES assertion(s) FAILED"
    exit 1
fi
echo "RESULT: all assertions passed"
exit 0
