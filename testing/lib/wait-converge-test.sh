#!/bin/bash
# Unit tests for wait_until_connected() in wait-converge.sh.
#
# These tests drive the convergence gate with synthetic connectivity
# checks (ping_fn stand-ins) that report scripted PASSED/FAILED counts
# keyed off the same SECONDS clock the gate uses. No containers or
# network are involved, so the suite is hermetic and safe to run in CI.
#
# It is not fast, though: it drives real timeouts against the real clock
# and took about 45 seconds when measured 2026-07-23, before case 7 added
# roughly another minute. The header claimed "a
# few seconds" from the day it was written until then, which nothing had
# contradicted because no runner had ever invoked it.
#
# The clock both the gate and the traces read is SECONDS, which counts whole
# seconds, so every timing verdict below needs at least a second of margin
# and most of the run is that margin. The traces were cut on 2026-10-21 to
# drop the time no assertion reads (a second climb step in cases 1 and 4, a
# second of stall in the hard-cap cases, two seconds of climb in 7d) without
# narrowing any margin. That took it from 133 s to about 116 s.
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

# Case 1 trace: improves (16 reachable) early, climbs to 19, then holds
# at FAILED=1 (within slack) until late, then fully converges. Mirrors a
# deep node whose last pair clears only after stacked discovery backoff.
# With stall_secs=4 the hold arms at t~7, two seconds before convergence;
# with slack=0 (case 1b) the same stall bails at t~7 instead.
ping_near_converged_hold() {
    set_pt; local t=$PT
    if (( t < 3 )); then
        PASSED=16; FAILED=4
    elif (( t < 9 )); then
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
# the near-converged hold keeps polling all the way to max_secs. Driven with
# max_secs=5 and stall_secs=2, so the hold arms at t~2 and is ~3s old at the
# cap.
ping_never_converges() {
    PASSED=19; FAILED=1
}

# Case 4 trace: backward-compat. Same shape as case 1 (near-converged
# straggler) but driven with only 4 args so the default slack applies.
ping_backcompat_hold() {
    set_pt; local t=$PT
    if (( t < 3 )); then
        PASSED=16; FAILED=4
    elif (( t < 9 )); then
        PASSED=19; FAILED=1
    else
        PASSED=20; FAILED=0
    fi
}

# Case 6 trace: converges quickly, so the verdict case that needs a
# converged run does not spend the near-converged hold's twelve seconds.
ping_quick_converge() {
    set_pt; local t=$PT
    if (( t < 2 )); then
        PASSED=18; FAILED=2
    else
        PASSED=20; FAILED=0
    fi
}

# Case 7 traces: the near-converged acceptance window. Each is keyed off
# PT like the traces above, and each is shaped so its expected verdict holds
# with at least a second of margin on either side of the accept window.

# 7d: still progressing until t=2, so the hold that follows (armed at t=4
# with stall_secs=2) has lasted only ~2s when the cap falls at 6s, short of
# a 4s accept window.
ping_late_progress() {
    set_pt; local t=$PT
    if (( t < 2 )); then
        PASSED=$(( 15 + t )); FAILED=$(( 5 - t ))
    else
        PASSED=19; FAILED=1
    fi
}

# 7f: holds at 19/1 from the start and converges at t=6, before a 10s cap.
# A gate that accepted as soon as the accept window elapsed (t~4) would
# report near_converged here instead of converged.
ping_converges_after_window() {
    set_pt; local t=$PT
    if (( t < 6 )); then
        PASSED=19; FAILED=1
    else
        PASSED=20; FAILED=0
    fi
}

# 7g: enters the hold at 18/2 (armed at t=2), makes progress to 19/1 at
# t=4, then holds there long enough (re-armed at t=6, cap 11) to exceed a
# 3s accept window. Reds under a gate that arms the hold once and never
# re-arms it after progress.
ping_rearm_hold() {
    set_pt; local t=$PT
    if (( t < 4 )); then
        PASSED=18; FAILED=2
    else
        PASSED=19; FAILED=1
    fi
}

# 7h: the same shape, but the progress to 19/1 comes at t=8, so the second
# hold (re-armed at t=10) is ~1s old when the cap falls at 11s. Reds under a
# gate that keeps the first hold's start across the progress.
ping_late_rearm() {
    set_pt; local t=$PT
    if (( t < 8 )); then
        PASSED=18; FAILED=2
    else
        PASSED=19; FAILED=1
    fi
}

HOLD_MSG="holding for full budget"
STUCK_MSG="STUCK"
NOCONV_MSG="tree did not converge"

# Run the gate in THIS shell (not a subshell) so the CONVERGE_* verdict
# globals survive, capturing its output to a file instead. `$(...)` runs the
# gate in a fork, which discards those assignments — that is why cases 1-4
# can only assert on text.
VERDICT_OUT=$(mktemp)
run_gate() {
    reset_ping
    CONVERGE_OUTCOME=""; CONVERGE_REACHED=-1; CONVERGE_PENDING=-1
    wait_until_connected "$@" >"$VERDICT_OUT" 2>&1
}

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
out=$(wait_until_connected ping_never_converges 5 2 1 2); rc=$?
elapsed=$((SECONDS - start))
echo "$out"
c3_rc_ok=1; [ "$rc" -ne 0 ] && c3_rc_ok=0
check "case3: returns 1 (never converges)" "$c3_rc_ok" "rc=$rc"
c3_cap_ok=1; echo "$out" | grep -q "TIMEOUT" && c3_cap_ok=0
check "case3: hit hard-cap TIMEOUT message" "$c3_cap_ok"
# Hard cap: must run roughly to max_secs (5s), not bail early.
c3_dur_ok=1; [ "$elapsed" -ge 5 ] && c3_dur_ok=0
check "case3: ran to hard cap (~max_secs)" "$c3_dur_ok" "elapsed=${elapsed}s >= 5s"

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

# --- Case 5: wait_for_peers refuses a floor of zero -------------------
#
# The reader inside wait_for_peers falls back to 0 when a container does
# not answer. That is safe against a floor of 1 or more, where 0 reads as
# "not converged yet", and unsafe against a floor of 0, where the first
# read from a dead container satisfies the wait immediately. This case is
# the break-what-it-guards check for the rejection: drive the guard with a
# floor of 0 and confirm it refuses, then drive the same dead container
# with a floor of 1 and confirm the refusal is specific to the dangerous
# input rather than a blanket failure.
#
# `docker` is stubbed to fail, which is what an unreachable container looks
# like to this reader, so no container or network is involved and the suite
# stays hermetic.
echo
echo "== Case 5: wait_for_peers refuses a zero floor =="
docker() { return 1; }

out=$(wait_for_peers stub-container 0 2 2>&1); rc=$?
echo "$out"
c5_reject_ok=1; [ "$rc" -eq 2 ] && c5_reject_ok=0
check "case5: floor of 0 is refused" "$c5_reject_ok" "rc=$rc"
c5_msg_ok=1; echo "$out" | grep -q "refusing a minimum" && c5_msg_ok=0
check "case5: refusal names the reason" "$c5_msg_ok"
# The pre-guard behaviour, asserted so a regression is visible rather than
# quiet: without the rejection this returned 0 on its first iteration
# against a container that never answered.
c5_notpass_ok=1; [ "$rc" -ne 0 ] && c5_notpass_ok=0
check "case5: floor of 0 does not report success" "$c5_notpass_ok" "rc=$rc"

start=$SECONDS
out=$(wait_for_peers stub-container 1 2 2>&1); rc=$?
elapsed=$((SECONDS - start))
echo "$out"
c5_floor1_ok=1; [ "$rc" -eq 1 ] && c5_floor1_ok=0
check "case5: floor of 1 times out rather than being refused" "$c5_floor1_ok" "rc=$rc"
c5_polled_ok=1; [ "$elapsed" -ge 2 ] && c5_polled_ok=0
check "case5: floor of 1 polled its full budget" "$c5_polled_ok" "elapsed=${elapsed}s >= 2s"

unset -f docker

# --- Case 6: the verdict discriminates non-convergence from connectivity --
#
# This is the break-what-it-guards check for the verdict itself. The recorded
# failure exited 1 while reporting "20 passed, 0 failed": every connectivity
# pair passed and only the tree fell short, and nothing in the summary told
# the two apart. The gate now names its verdict, so drive it into each
# outcome and assert the verdict is the one that outcome deserves.
echo
echo "== Case 6: verdict names which condition failed =="

echo "-- Case 6a: genuinely unconverged tree, hard cap --"
run_gate ping_never_converges 5 2 1 2; rc=$?
cat "$VERDICT_OUT"
c6a_rc_ok=1; [ "$rc" -ne 0 ] && c6a_rc_ok=0
check "case6a: unconverged tree still reds" "$c6a_rc_ok" "rc=$rc"
c6a_out_ok=1; [ "$CONVERGE_OUTCOME" = "timeout" ] && c6a_out_ok=0
check "case6a: verdict is timeout" "$c6a_out_ok" "CONVERGE_OUTCOME=$CONVERGE_OUTCOME"
c6a_cnt_ok=1
[ "$CONVERGE_REACHED" -eq 19 ] && [ "$CONVERGE_PENDING" -eq 1 ] && c6a_cnt_ok=0
check "case6a: verdict carries the shortfall" "$c6a_cnt_ok" \
    "reached=$CONVERGE_REACHED pending=$CONVERGE_PENDING"
c6a_msg_ok=1; grep -q "$NOCONV_MSG" "$VERDICT_OUT" && c6a_msg_ok=0
check "case6a: message says the tree did not converge" "$c6a_msg_ok"

echo "-- Case 6b: wedged far from convergence, stall bail --"
run_gate ping_far_stall 30 4 1 2; rc=$?
cat "$VERDICT_OUT"
c6b_rc_ok=1; [ "$rc" -ne 0 ] && c6b_rc_ok=0
check "case6b: wedged tree still reds" "$c6b_rc_ok" "rc=$rc"
c6b_out_ok=1; [ "$CONVERGE_OUTCOME" = "stalled" ] && c6b_out_ok=0
check "case6b: verdict is stalled" "$c6b_out_ok" "CONVERGE_OUTCOME=$CONVERGE_OUTCOME"
c6b_msg_ok=1; grep -q "$NOCONV_MSG" "$VERDICT_OUT" && c6b_msg_ok=0
check "case6b: message says the tree did not converge" "$c6b_msg_ok"

echo "-- Case 6c: converged tree, and the verdict does not cry non-convergence --"
run_gate ping_quick_converge 20 4 1 2; rc=$?
cat "$VERDICT_OUT"
c6c_rc_ok=1; [ "$rc" -eq 0 ] && c6c_rc_ok=0
check "case6c: converged tree still passes" "$c6c_rc_ok" "rc=$rc"
c6c_out_ok=1; [ "$CONVERGE_OUTCOME" = "converged" ] && c6c_out_ok=0
check "case6c: verdict is converged" "$c6c_out_ok" "CONVERGE_OUTCOME=$CONVERGE_OUTCOME"
c6c_cnt_ok=1
[ "$CONVERGE_REACHED" -eq 20 ] && [ "$CONVERGE_PENDING" -eq 0 ] && c6c_cnt_ok=0
check "case6c: verdict carries a clean tree" "$c6c_cnt_ok" \
    "reached=$CONVERGE_REACHED pending=$CONVERGE_PENDING"
c6c_quiet_ok=0; grep -q "$NOCONV_MSG" "$VERDICT_OUT" && c6c_quiet_ok=1
check "case6c: no non-convergence message on a clean run" "$c6c_quiet_ok"

# --- Case 7: near-converged acceptance at the hard cap -----------------
#
# The sixth argument lets a caller hand a mesh that has held within slack for
# at least that many seconds to its own strict assertion instead of failing
# the gate. It acts only at the hard cap, which is reachable only in states
# that are red without it, so it can never turn a run that would have
# converged by the cap into a red. With the argument absent or 0 the gate
# must behave exactly as before.
echo
echo "== Case 7: near-converged acceptance at the hard cap =="

echo "-- Case 7a: held within slack past the accept window, accepted at the cap --"
run_gate ping_never_converges 5 2 1 2 2; rc=$?
cat "$VERDICT_OUT"
c7a_rc_ok=1; [ "$rc" -eq 0 ] && c7a_rc_ok=0
check "case7a: near-converged hold past the window returns 0" "$c7a_rc_ok" "rc=$rc"
c7a_out_ok=1; [ "$CONVERGE_OUTCOME" = "near_converged" ] && c7a_out_ok=0
check "case7a: verdict is near_converged" "$c7a_out_ok" "CONVERGE_OUTCOME=$CONVERGE_OUTCOME"
c7a_cnt_ok=1
[ "$CONVERGE_REACHED" -eq 19 ] && [ "$CONVERGE_PENDING" -eq 1 ] && c7a_cnt_ok=0
check "case7a: verdict carries the shortfall" "$c7a_cnt_ok" \
    "reached=$CONVERGE_REACHED pending=$CONVERGE_PENDING"

echo "-- Case 7b: the same trace with five arguments, then with an explicit 0 --"
run_gate ping_never_converges 5 2 1 2; rc=$?
cat "$VERDICT_OUT"
c7b_rc_ok=1; [ "$rc" -eq 1 ] && c7b_rc_ok=0
check "case7b: five arguments still time out" "$c7b_rc_ok" "rc=$rc"
c7b_out_ok=1; [ "$CONVERGE_OUTCOME" = "timeout" ] && c7b_out_ok=0
check "case7b: five arguments give verdict timeout" "$c7b_out_ok" "CONVERGE_OUTCOME=$CONVERGE_OUTCOME"
run_gate ping_never_converges 5 2 1 2 0; rc=$?
cat "$VERDICT_OUT"
c7b0_rc_ok=1; [ "$rc" -eq 1 ] && c7b0_rc_ok=0
check "case7b: an explicit 0 still times out" "$c7b0_rc_ok" "rc=$rc"
c7b0_out_ok=1; [ "$CONVERGE_OUTCOME" = "timeout" ] && c7b0_out_ok=0
check "case7b: an explicit 0 gives verdict timeout" "$c7b0_out_ok" "CONVERGE_OUTCOME=$CONVERGE_OUTCOME"

echo "-- Case 7c: wedged far from convergence, acceptance does not rescue it --"
run_gate ping_far_stall 30 4 1 2 2; rc=$?
cat "$VERDICT_OUT"
c7c_rc_ok=1; [ "$rc" -eq 1 ] && c7c_rc_ok=0
check "case7c: a stall beyond slack still reds with acceptance enabled" "$c7c_rc_ok" "rc=$rc"
c7c_out_ok=1; [ "$CONVERGE_OUTCOME" = "stalled" ] && c7c_out_ok=0
check "case7c: verdict is stalled" "$c7c_out_ok" "CONVERGE_OUTCOME=$CONVERGE_OUTCOME"

echo "-- Case 7d: hold shorter than the accept window at the cap --"
run_gate ping_late_progress 6 2 1 2 4; rc=$?
cat "$VERDICT_OUT"
c7d_rc_ok=1; [ "$rc" -eq 1 ] && c7d_rc_ok=0
check "case7d: a hold shorter than the window still times out" "$c7d_rc_ok" "rc=$rc"
c7d_out_ok=1; [ "$CONVERGE_OUTCOME" = "timeout" ] && c7d_out_ok=0
check "case7d: verdict is timeout" "$c7d_out_ok" "CONVERGE_OUTCOME=$CONVERGE_OUTCOME"

echo "-- Case 7e: converged tree with acceptance enabled --"
run_gate ping_quick_converge 20 4 1 2 2; rc=$?
cat "$VERDICT_OUT"
c7e_rc_ok=1; [ "$rc" -eq 0 ] && c7e_rc_ok=0
check "case7e: converged tree passes with acceptance enabled" "$c7e_rc_ok" "rc=$rc"
c7e_out_ok=1; [ "$CONVERGE_OUTCOME" = "converged" ] && c7e_out_ok=0
check "case7e: verdict is converged" "$c7e_out_ok" "CONVERGE_OUTCOME=$CONVERGE_OUTCOME"

echo "-- Case 7f: converges after the window would have elapsed, before the cap --"
run_gate ping_converges_after_window 10 2 1 2 2; rc=$?
cat "$VERDICT_OUT"
c7f_rc_ok=1; [ "$rc" -eq 0 ] && c7f_rc_ok=0
check "case7f: late convergence before the cap passes" "$c7f_rc_ok" "rc=$rc"
c7f_out_ok=1; [ "$CONVERGE_OUTCOME" = "converged" ] && c7f_out_ok=0
check "case7f: acceptance waits for the cap, verdict is converged" "$c7f_out_ok" \
    "CONVERGE_OUTCOME=$CONVERGE_OUTCOME"

echo "-- Case 7g: hold, progress, then a second hold past the window --"
run_gate ping_rearm_hold 11 2 1 2 3; rc=$?
cat "$VERDICT_OUT"
c7g_rc_ok=1; [ "$rc" -eq 0 ] && c7g_rc_ok=0
check "case7g: a re-armed hold past the window returns 0" "$c7g_rc_ok" "rc=$rc"
c7g_out_ok=1; [ "$CONVERGE_OUTCOME" = "near_converged" ] && c7g_out_ok=0
check "case7g: verdict is near_converged" "$c7g_out_ok" "CONVERGE_OUTCOME=$CONVERGE_OUTCOME"
c7g_cnt_ok=1
[ "$CONVERGE_REACHED" -eq 19 ] && [ "$CONVERGE_PENDING" -eq 1 ] && c7g_cnt_ok=0
check "case7g: verdict carries the shortfall" "$c7g_cnt_ok" \
    "reached=$CONVERGE_REACHED pending=$CONVERGE_PENDING"

echo "-- Case 7h: hold, late progress, second hold shorter than the window --"
run_gate ping_late_rearm 11 2 1 2 3; rc=$?
cat "$VERDICT_OUT"
c7h_rc_ok=1; [ "$rc" -eq 1 ] && c7h_rc_ok=0
check "case7h: progress resets the hold, so a short second hold times out" "$c7h_rc_ok" "rc=$rc"
c7h_out_ok=1; [ "$CONVERGE_OUTCOME" = "timeout" ] && c7h_out_ok=0
check "case7h: verdict is timeout" "$c7h_out_ok" "CONVERGE_OUTCOME=$CONVERGE_OUTCOME"

echo "-- Case 7i: hold armed, but shorter than the window when the cap falls --"
# The hold arms at t~2 (stall_secs after the first reading) and the cap falls
# at 5, so it is ~3s old against a 10s window: seven seconds of margin, far
# above SECONDS' one-second granularity. This is the case that carries the
# duration condition; 7d and 7h pass even with it removed if their hold
# happens not to arm.
run_gate ping_never_converges 5 2 1 2 10; rc=$?
cat "$VERDICT_OUT"
c7i_rc_ok=1; [ "$rc" -eq 1 ] && c7i_rc_ok=0
check "case7i: an armed hold shorter than the window still times out" "$c7i_rc_ok" "rc=$rc"
c7i_out_ok=1; [ "$CONVERGE_OUTCOME" = "timeout" ] && c7i_out_ok=0
check "case7i: verdict is timeout" "$c7i_out_ok" "CONVERGE_OUTCOME=$CONVERGE_OUTCOME"
c7i_hold_ok=1; grep -q "$HOLD_MSG" "$VERDICT_OUT" && c7i_hold_ok=0
check "case7i: the hold was armed" "$c7i_hold_ok" "expected '$HOLD_MSG' in output"

rm -f "$VERDICT_OUT"

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
