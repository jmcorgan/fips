#!/bin/bash
# Pressure profiles for the mesh-lab. Sourced by run-loop.sh.
#
# Each profile is a function `pressure_start_<name>` that spawns
# stress-ng (or whatever) in the background and writes its PID to the
# variable PRESSURE_PIDS (a bash array). The harness uses
# `pressure_stop` (defined at the bottom) to kill everything cleanly.
#
# Profiles are intentionally simple stubs until calibrated against
# actual reproduction of a known flake class.

set -u

PRESSURE_PIDS=()

# Track which profile is active for the summary.json.
PRESSURE_PROFILE_ACTIVE="idle"

# ── idle ─────────────────────────────────────────────────────────────
# No pressure. Baseline. A healthy mesh should run all reps green on
# this profile; failures here are a different bug class than what the
# lab is built to chase.

pressure_start_idle() {
    PRESSURE_PROFILE_ACTIVE="idle"
    # nothing to do
}

# ── light ────────────────────────────────────────────────────────────
# Single stress-ng cpu worker at ~50% load. Placeholder; calibration
# will determine the right intensity for surfacing tail behavior
# without saturating the host.

pressure_start_light() {
    PRESSURE_PROFILE_ACTIVE="light"
    require_stress_ng || return 1
    stress-ng --cpu 1 --cpu-load 50 --quiet &
    PRESSURE_PIDS+=("$!")
}

# ── github-runner-equivalent ────────────────────────────────────────
# Calibrated to approximate the headroom a 2-core GitHub Actions
# ubuntu-latest runner has when also juggling four concurrent package-
# build workflows. Target effective per-host load: ~75% of cores
# consumed, ~30% of RAM allocated, so the test+daemon containers
# compete for ~2 effective cores and ~7-8 GiB headroom — close to a
# runner under quad-package-build contention.
#
# Calibration target: ≥20% mechanism-match rate over 5-rep pilots on
# the `rekey` suite. Calibration history (host = 8c/62GiB):
#
#   2026-05-16 first cut  --cpu 1 --vm 1 --vm-bytes 512m
#                         25 reps, 1 mechanism-match (4%)
#                         (stochastic pilot fire; not contention-driven)
#   2026-05-16 second cut --cpu 6 --vm 2 --vm-bytes 10g
#                         5 reps, 0 mechanism-match
#                         (host load=8.25/8 cores, 20GiB resident; the
#                         mechanism did not surface even at saturation)
#
# Layered with the mesh-lab/compose-resource-limits.yml override
# (per-daemon cpus=0.3 + mem_limit=1g) and in-container tc qdisc netem
# (10ms ± 5ms delay + 1% loss), the rekey Phase 5 mechanism still did
# not reproduce above the stub's stochastic baseline on this host —
# implying the GHA fires are more likely code-side (tokio task stall,
# channel backpressure, mutex contention) than environment-side.

pressure_start_github_runner_equivalent() {
    PRESSURE_PROFILE_ACTIVE="github-runner-equivalent"
    require_stress_ng || return 1
    # CPU pressure: six full-load cpu workers (75% of an 8-core host).
    # On smaller hosts the per-worker share rises; on larger hosts the
    # absolute headroom rises proportionally — the profile is anchored
    # to "what's left after the pressure," not to a target host size.
    stress-ng --cpu 6 --quiet &
    PRESSURE_PIDS+=("$!")
    # Memory pressure: two vm workers, 20 GiB total resident. Sized to
    # eat ~30% of a 62 GiB host. --vm-keep holds pages resident rather
    # than churning the allocator, which mirrors a peer workflow that
    # has allocated and is using its working set, not one trashing it.
    stress-ng --vm 2 --vm-bytes 10g --vm-keep --quiet &
    PRESSURE_PIDS+=("$!")
}

# ── heavy ────────────────────────────────────────────────────────────
# Two cpu workers + memory pressure. Worst-case profile for stall-
# finding work once the milder profiles are characterized.

pressure_start_heavy() {
    PRESSURE_PROFILE_ACTIVE="heavy"
    require_stress_ng || return 1
    stress-ng --cpu 2 --quiet &
    PRESSURE_PIDS+=("$!")
    stress-ng --vm 1 --vm-bytes 1g --vm-keep --quiet &
    PRESSURE_PIDS+=("$!")
}

# ── helpers ──────────────────────────────────────────────────────────

require_stress_ng() {
    if ! command -v stress-ng >/dev/null 2>&1; then
        echo "  ERROR: stress-ng not installed; cannot run pressure profile '$PRESSURE_PROFILE_ACTIVE'" >&2
        echo "  install on Debian/Ubuntu: sudo apt-get install stress-ng" >&2
        return 1
    fi
    return 0
}

pressure_start() {
    local profile="$1"
    PRESSURE_PIDS=()
    case "$profile" in
        idle)
            pressure_start_idle ;;
        light)
            pressure_start_light ;;
        github-runner-equivalent | github | gha)
            pressure_start_github_runner_equivalent ;;
        heavy)
            pressure_start_heavy ;;
        *)
            echo "  ERROR: unknown pressure profile '$profile'" >&2
            echo "  available: idle, light, github-runner-equivalent, heavy" >&2
            return 1 ;;
    esac
}

pressure_stop() {
    if [ "${#PRESSURE_PIDS[@]}" -eq 0 ]; then
        return 0
    fi
    for pid in "${PRESSURE_PIDS[@]}"; do
        # kill the process group; stress-ng spawns children
        kill -TERM "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    done
    # Brief grace, then SIGKILL stragglers
    sleep 1
    for pid in "${PRESSURE_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
    PRESSURE_PIDS=()
}
