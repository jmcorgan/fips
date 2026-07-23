#!/bin/bash
# Run the CI pipeline locally: CI parity check, build, unit tests,
# integration tests.
#
# Usage: ./ci-local.sh [options]
#
# Options:
#   --build-only         Only run build + clippy
#   --test-only          Only run unit tests (skip build, skip integration)
#   --skip-integration   Skip integration tests
#   --skip-chaos         Skip chaos scenarios
#   --with-tor           Include Tor harnesses (off by default — needs live Tor)
#   --only <suite>       Run a single integration suite
#   -j, --jobs <N>       Max parallel chaos scenarios (default: 4)
#   --list               List available integration suites
#   --check-parity       Verify this suite set matches ci.yml's integration
#                        matrix (see testing/check-ci-parity.sh), then exit
#   --reap               Force-remove all leftover FIPS CI resources
#                        (containers/networks/volumes carrying the CI label or a
#                        fipsci_ compose project, plus every chaos-simulation
#                        host veth interface), then exit. See ci-cleanup.sh.
#                        Host interfaces carry no label, so they are matched by
#                        name shape: this reaps a bare chaos.sh run's live
#                        interfaces too, though not its containers. Don't run
#                        it while a bare simulation is up.
#   -h, --help           Show this help
#
# Integration suites (default coverage):
#   static-mesh, static-chain, rekey, rekey-accept-off,
#   rekey-outbound-only, mixed-profile, gateway,
#   acl-allowlist, firewall, nat-cone, nat-symmetric, nat-lan,
#   nostr-publish-consume, stun-faults,
#   chaos-smoke-10, chaos-churn-mixed-10, chaos-ethernet-mesh,
#   chaos-ethernet-only, chaos-tcp-mesh, chaos-bottleneck-parent,
#   chaos-cost-avoidance, chaos-cost-reeval, chaos-cost-stability,
#   chaos-depth-vs-cost, chaos-mixed-technology, chaos-congestion-stress,
#   chaos-bloom-storm,
#   sidecar, dns-resolver, deb-install
#
# Opt-in (require --with-tor; depend on live Tor network):
#   tor-socks5, tor-directory
#
# Exit codes:
#   0   — all stages passed
#   1   — one or more stages failed
#   130 — interrupted by SIGINT  (128 + 2;  run was cancelled, not a failure)
#   143 — terminated by SIGTERM  (128 + 15; run was cancelled, not a failure)
#
# A preempting CI worker maps 130/143 → "cancelled" (discard, do not record a
# failing commit), 0 → green, any other non-zero → red.
#
# ── CI parity invariant ─────────────────────────────────────────────────────
# This local default suite set and the GitHub integration matrix
# (.github/workflows/ci.yml) MUST run the same integration suites, EXCEPT for
# the deliberate local-only entries below. Adding a suite to one runner
# without the other means "local green" and "GitHub green" stop being
# equivalent. testing/check-ci-parity.sh enforces this and fails on drift; it
# runs as the first stage of every local run, before the build.
#
# Deliberate local-only (NOT on the GitHub gate), with reason:
#   tor-socks5     — requires live Tor network; opt-in via --with-tor,
#                    unreliable on GitHub-hosted runners.
#   tor-directory  — same; live Tor dependency.
#
# The two runners express the same work in different matrix shapes, and the
# guard compares through that shape rather than around it: chaos legs are
# compared per scenario (and per flag), deb-install legs per distro. The one
# leg still compared at leg granularity is dns-resolver — a single suite on
# both sides that runs all of its scenarios internally.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ ! -f "$PROJECT_ROOT/Cargo.toml" ]]; then
    echo "Error: Cannot find Cargo.toml at $PROJECT_ROOT" >&2
    exit 1
fi

cd "$PROJECT_ROOT" || exit 1

# ── Configuration ──────────────────────────────────────────────────────────

PARALLEL_JOBS=4
BUILD_ONLY=false
TEST_ONLY=false
SKIP_INTEGRATION=false
SKIP_CHAOS=false
WITH_TOR=false
ONLY_SUITE=""

# All integration suites matching ci.yml
STATIC_SUITES=(static-mesh static-chain)
REKEY_SUITES=(rekey rekey-accept-off rekey-outbound-only)
MIXED_PROFILE_SUITES=(mixed-profile)
ADMISSION_SUITES=(admission-cap)
# Each entry: "display-name scenario [--flag value ...]"
CHAOS_SUITES=(
    "smoke-10 smoke-10"
    "churn-mixed-10 churn-mixed --nodes 10 --duration 120"
    "ethernet-mesh ethernet-mesh"
    "ethernet-only ethernet-only"
    "tcp-mesh tcp-mesh"
    "bottleneck-parent bottleneck-parent"
    "cost-avoidance cost-avoidance"
    "cost-reeval cost-reeval"
    "cost-stability cost-stability"
    "depth-vs-cost depth-vs-cost"
    "mixed-technology mixed-technology"
    "congestion-stress congestion-stress"
    "bloom-storm bloom-storm"
)
SIDECAR_SUITES=(sidecar)
GATEWAY_SUITES=(gateway)
ACL_SUITES=(acl-allowlist)
FIREWALL_SUITES=(firewall)
NAT_SUITES=(cone symmetric lan)
NOSTR_RELAY_SUITES=(nostr-publish-consume)
STUN_FAULTS_SUITES=(stun-faults)
DNS_RESOLVER_SUITES=(dns-resolver)
DEB_INSTALL_SUITES=(deb-install)
TOR_SUITES=(tor-socks5 tor-directory)

# ── Colors ─────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Helpers ────────────────────────────────────────────────────────────────

stamp() { date '+%H:%M:%S'; }

info()  { echo -e "${CYAN}[$(stamp)]${RESET} $*"; }
pass()  { echo -e "${GREEN}[$(stamp)] PASS${RESET} $*"; }
fail()  { echo -e "${RED}[$(stamp)] FAIL${RESET} $*"; }
stage() { echo -e "\n${BOLD}${YELLOW}═══ $* ═══${RESET}\n"; }

list_suites() {
    echo "Available integration suites:"
    echo ""
    echo "  Static topologies:"
    for s in "${STATIC_SUITES[@]}"; do echo "    $s"; done
    echo ""
    echo "  Rekey:"
    for s in "${REKEY_SUITES[@]}"; do echo "    $s"; done
    echo ""
    echo "  Mixed profile:"
    for s in "${MIXED_PROFILE_SUITES[@]}"; do echo "    $s"; done
    echo ""
    echo "  Admission cap:"
    for s in "${ADMISSION_SUITES[@]}"; do echo "    $s"; done
    echo ""
    echo "  Gateway:"
    for s in "${GATEWAY_SUITES[@]}"; do echo "    $s"; done
    echo ""
    echo "  ACL allowlist:"
    for s in "${ACL_SUITES[@]}"; do echo "    $s"; done
    echo ""
    echo "  Firewall baseline:"
    for s in "${FIREWALL_SUITES[@]}"; do echo "    $s"; done
    echo ""
    echo "  NAT scenarios:"
    for s in "${NAT_SUITES[@]}"; do echo "    nat-$s"; done
    echo ""
    echo "  Nostr publish/consume:"
    for s in "${NOSTR_RELAY_SUITES[@]}"; do echo "    $s"; done
    echo ""
    echo "  STUN fault-injection:"
    for s in "${STUN_FAULTS_SUITES[@]}"; do echo "    $s"; done
    echo ""
    echo "  Chaos scenarios:"
    for entry in "${CHAOS_SUITES[@]}"; do
        read -ra parts <<< "$entry"
        echo "    chaos-${parts[0]}  (${parts[*]:1})"
    done
    echo ""
    echo "  Sidecar:"
    for s in "${SIDECAR_SUITES[@]}"; do echo "    $s"; done
    echo ""
    echo "  DNS resolver:"
    for s in "${DNS_RESOLVER_SUITES[@]}"; do echo "    $s"; done
    echo ""
    echo "  Deb-install:"
    for s in "${DEB_INSTALL_SUITES[@]}"; do echo "    $s"; done
    echo ""
    echo "  Tor (opt-in via --with-tor):"
    for s in "${TOR_SUITES[@]}"; do echo "    $s"; done
    exit 0
}

usage() {
    sed -n '2,/^$/{ s/^# \?//; p }' "$0"
    exit 0
}

# ── Parse arguments ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-only)       BUILD_ONLY=true; shift ;;
        --test-only)        TEST_ONLY=true; shift ;;
        --skip-integration) SKIP_INTEGRATION=true; shift ;;
        --skip-chaos)       SKIP_CHAOS=true; shift ;;
        --with-tor)         WITH_TOR=true; shift ;;
        --only)             ONLY_SUITE="$2"; shift 2 ;;
        -j|--jobs)          PARALLEL_JOBS="$2"; shift 2 ;;
        --list)             list_suites ;;
        --check-parity)     exec "$SCRIPT_DIR/check-ci-parity.sh" ;;
        --reap)             exec "$SCRIPT_DIR/ci-cleanup.sh" ;;
        -h|--help)          usage ;;
        *)                  echo "Unknown option: $1"; usage ;;
    esac
done

# ── Results tracking ──────────────────────────────────────────────────────

declare -A RESULTS
OVERALL=0

record() {
    local name="$1" rc="$2"
    RESULTS["$name"]=$rc
    if [[ $rc -ne 0 ]]; then
        OVERALL=1
        fail "$name"
    else
        pass "$name"
    fi
}

# ── Per-run isolation + signal-safe teardown ───────────────────────────────
#
# This script may be preempted (a CI worker sends SIGTERM, waits ~30s, then
# SIGKILL) so it can restart on a newer tip. To make that safe:
#   * every docker resource is namespaced to THIS run (compose project prefix
#     + per-run image tags) so a restart never collides with a dying run;
#   * a trap tears down everything this run created on signal/exit, bounded by
#     `timeout` so a stuck `down` cannot wedge the trap (SIGKILL is the backstop).

# Derive a run id: honor the worker's $FIPS_CI_RUN_ID, else <short-sha>-<rand>,
# else $$-<timestamp>. Sanitize to a valid compose project / image-tag token.
if [[ -n "${FIPS_CI_RUN_ID:-}" ]]; then
    CI_RUN_ID="$FIPS_CI_RUN_ID"
else
    _ci_sha="$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || true)"
    if [[ -n "$_ci_sha" ]]; then
        CI_RUN_ID="${_ci_sha}-${RANDOM}${RANDOM}"
    else
        CI_RUN_ID="$$-$(date +%s)"
    fi
fi
CI_RUN_ID="$(printf '%s' "$CI_RUN_ID" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_-' '-')"
# A docker image tag and a compose project name must both START with an
# alphanumeric, so strip any leading -/_ left by sanitization.
CI_RUN_ID="$(printf '%s' "$CI_RUN_ID" | sed -E 's/^[^a-z0-9]+//')"
[[ -z "$CI_RUN_ID" ]] && CI_RUN_ID="r$$"

CI_PROJECT_PREFIX="fipsci_${CI_RUN_ID}"
CI_IMAGE_TEST="fips-test:${CI_RUN_ID}"
CI_IMAGE_APP="fips-test-app:${CI_RUN_ID}"
CI_LABEL="com.corganlabs.fips-ci=1"
# Run-scoped companion to CI_LABEL. The generic label is shared by every run on
# the host, so teardown filters on this one instead — otherwise this run's reap
# would force-remove a concurrent run's containers out from under it.
CI_LABEL_RUN="com.corganlabs.fips-ci.run=${CI_RUN_ID}"

# Exported so child suite scripts + their compose/`docker run` invocations
# inherit the run identity. Compose files read FIPS_TEST_IMAGE/FIPS_TEST_APP_IMAGE
# (default :latest when unset, preserving manual `docker compose` use).
export FIPS_CI_RUN_ID="$CI_RUN_ID"
export FIPS_TEST_IMAGE="$CI_IMAGE_TEST"
export FIPS_TEST_APP_IMAGE="$CI_IMAGE_APP"
# Docker container names are GLOBAL — a compose project name does not scope
# them — so the suite compose files append this suffix to every explicit
# container_name, and the suite scripts append it wherever they address a
# container by name. Empty when unset, so a bare `docker compose up` outside
# this harness still produces today's plain names.
export FIPS_CI_NAME_SUFFIX="-${CI_RUN_ID}"
# run_chaos narrows that export to one scenario, and bash scopes a `local`
# dynamically: a function called while run_chaos is on the stack — the signal
# trap, on the `--only chaos-*` path where run_chaos is not a subshell — reads
# the narrowed value, not this one. Snapshot the run-wide value so the rebuild
# below always sees it, and make it readonly so no scope can shadow it either.
CI_RUN_NAME_SUFFIX="$FIPS_CI_NAME_SUFFIX"
readonly CI_RUN_NAME_SUFFIX

# Per-suite compose project name: ${prefix}_<suite-or-compose-basename>. Keeps
# today's intra-run distinctness (one project per compose file / chaos child)
# while adding the cross-run prefix that scopes the reap.
ci_project() { printf '%s_%s' "$CI_PROJECT_PREFIX" "$1"; }

# The name suffix one chaos scenario runs under. Its container names, its
# generated-config directory and the token in its host veth names all derive
# from this, so teardown recomputes it to know which interfaces are ours. Reads
# the snapshot rather than the export for the reason given above.
ci_chaos_suffix() { printf -- '-%s%s' "$1" "$CI_RUN_NAME_SUFFIX"; }

# PIDs of in-flight parallel chaos children (subshells). The trap signals these.
CI_CHAOS_PIDS=()
CI_CLEANED=0

# Best-effort, BOUNDED teardown of every docker resource THIS run may have
# created. Idempotent (guarded), so the signal and EXIT paths don't double-run.
# Takes the run's exit status; defaults to non-zero, which is the conservative
# reading for the signal path.
ci_teardown() {
    [[ $CI_CLEANED -eq 1 ]] && return 0
    CI_CLEANED=1
    local run_status="${1:-1}"

    # 1. Propagate to parallel chaos children and reap them (bounded).
    if [[ ${#CI_CHAOS_PIDS[@]} -gt 0 ]]; then
        kill -TERM "${CI_CHAOS_PIDS[@]}" 2>/dev/null || true
        local _end=$(( SECONDS + 10 )) _p
        for _p in "${CI_CHAOS_PIDS[@]}"; do
            while kill -0 "$_p" 2>/dev/null && (( SECONDS < _end )); do
                sleep 0.3
            done
        done
        kill -KILL "${CI_CHAOS_PIDS[@]}" 2>/dev/null || true
        wait "${CI_CHAOS_PIDS[@]}" 2>/dev/null || true
    fi

    # 2. Remove all compose projects + direct-run resources + per-run images
    #    for this run, plus any host veth interface a chaos scenario was
    #    killed part-way through creating. Host interfaces carry no docker
    #    label, so hand over the suffixes this run's scenarios used and let
    #    the reap derive their names — a blind sweep would take a concurrent
    #    run's live interfaces with it. ci-cleanup.sh wraps each docker op in
    #    `timeout`; bound the whole sweep too so the trap can never wedge.
    #    Its stdout is routine progress and goes nowhere, but stderr carries
    #    only a skipped sweep or a bad option, and a sweep that quietly stops
    #    reaping is how interfaces would accumulate unnoticed. Let it through.
    local _suffixes=() _entry
    for _entry in "${CHAOS_SUITES[@]}"; do
        _suffixes+=("$(ci_chaos_suffix "${_entry%% *}")")
    done
    timeout 150 bash "$SCRIPT_DIR/ci-cleanup.sh" \
        --label "$CI_LABEL" \
        --run-id "$CI_RUN_ID" \
        --project-prefix "$CI_PROJECT_PREFIX" \
        --images "$CI_IMAGE_TEST $CI_IMAGE_APP" \
        --veth-suffixes "${_suffixes[*]}" >/dev/null || true

    # 3. The static suite's generated configs are per-run (a shared directory
    #    would let concurrent runs overwrite each other's node configs), so
    #    they are this run's to remove. Only on a green run: after a failure
    #    they are the evidence of what the failing nodes were actually
    #    configured with. Guarded on a non-empty suffix too, since without one
    #    the path is the unscoped working directory a developer uses by hand,
    #    which is not ours to delete.
    if [[ $run_status -eq 0 && -n "${CI_RUN_NAME_SUFFIX:-}" ]]; then
        rm -rf "$SCRIPT_DIR/static/generated-configs${CI_RUN_NAME_SUFFIX}"
    fi
}

on_signal() {
    local sig="$1"
    # Block re-entry and stop the EXIT trap from overriding the signal code.
    trap '' TERM INT EXIT
    echo "" >&2
    fail "Received SIG$sig — cancelling run, tearing down ${CI_PROJECT_PREFIX}"
    ci_teardown
    # 128 + signal number: distinct from 0 (green) / 1 (stage failed).
    if [[ "$sig" == "TERM" ]]; then exit 143; else exit 130; fi
}

on_exit() {
    local code=$?
    trap '' TERM INT EXIT
    ci_teardown "$code"
    exit "$code"
}

trap 'on_signal TERM' TERM
trap 'on_signal INT'  INT
trap 'on_exit'        EXIT

# ── Stage 1: Build ─────────────────────────────────────────────────────────

run_build() {
    stage "Stage 1: Build"

    info "sudo nft -c -f packaging/common/fips.nft (nftables ruleset syntax check)"
    if command -v nft &>/dev/null; then
        if sudo nft -c -f packaging/common/fips.nft 2>&1; then
            record "nft-syntax" 0
        else
            record "nft-syntax" 1
            return 1
        fi
    else
        info "nftables not installed; install with 'apt install nftables' to validate fips.nft"
        record "nft-syntax" 1
        return 1
    fi

    info "cargo build --release"
    if cargo build --release 2>&1; then
        record "build" 0
    else
        record "build" 1
        return 1
    fi

    info "cargo fmt --check"
    if cargo fmt --check 2>&1; then
        record "fmt" 0
    else
        record "fmt" 1
        return 1
    fi

    info "cargo clippy --all-targets --all-features -- -D warnings"
    if cargo clippy --all-targets --all-features -- -D warnings 2>&1; then
        record "clippy" 0
    else
        record "clippy" 1
        return 1
    fi

    # Guard: the effectively-immutable state lives solely in NodeContext. The
    # Node struct must not re-declare a bundled field (config/identity/
    # startup_epoch/started_at/is_leaf_only/node_profile/max_*) — a shadow field
    # would silently reopen dual-store divergence between the struct and the
    # context. Checks the struct *declaration*, so it is wrap-insensitive.
    info "node-context single-store guard"
    if awk '/^pub struct Node \{/,/^\}/' src/node/mod.rs \
        | grep -qE '^[[:space:]]+(config|identity|startup_epoch|started_at|is_leaf_only|node_profile|max_connections|max_peers|max_links):'; then
        fail "Node struct re-declares a bundled immutable field; it must live solely in NodeContext"
        record "node-context-guard" 1
        return 1
    else
        record "node-context-guard" 0
    fi
}

# ── Stage 2: Unit Tests ───────────────────────────────────────────────────

run_tests() {
    stage "Stage 2: Unit Tests"

    local cmd
    if command -v cargo-nextest &>/dev/null; then
        cmd="cargo nextest run --all"
        info "$cmd"
        if $cmd 2>&1; then
            record "unit-tests" 0
        else
            record "unit-tests" 1
        fi
    else
        cmd="cargo test --all"
        info "$cmd (nextest not found, using cargo test)"
        if $cmd 2>&1; then
            record "unit-tests" 0
        else
            record "unit-tests" 1
        fi
    fi
}

# ── Stage 3: Integration Tests ─────────────────────────────────────────────

# Copy release binaries into a testing subdirectory
install_binaries() {
    local dest="$1"
    cp target/release/fips "$dest/fips"
    cp target/release/fipsctl "$dest/fipsctl"
    [[ -f target/release/fipstop ]] && cp target/release/fipstop "$dest/fipstop" || true
    [[ -f target/release/fips-gateway ]] && cp target/release/fips-gateway "$dest/fips-gateway" || true
    chmod +x "$dest/fips" "$dest/fipsctl"
    [[ -f "$dest/fipstop" ]] && chmod +x "$dest/fipstop" || true
    [[ -f "$dest/fips-gateway" ]] && chmod +x "$dest/fips-gateway" || true
}

# Run a static topology test (mesh, chain)
run_static() {
    local topology="$1"
    local compose="testing/static/docker-compose.yml"
    local rc=0
    export COMPOSE_PROJECT_NAME="$(ci_project static)"

    info "[$topology] Generating configs"
    bash testing/static/scripts/generate-configs.sh "$topology" || { record "static-$topology" 1; return; }

    info "[$topology] Starting containers"
    docker compose -f "$compose" --profile "$topology" up -d || { record "static-$topology" 1; return; }

    info "[$topology] Running ping test"
    if bash testing/static/scripts/ping-test.sh "$topology"; then
        rc=0
    else
        rc=1
        info "[$topology] Collecting failure logs"
        docker compose -f "$compose" --profile "$topology" logs --no-color 2>&1 | tail -100
    fi

    docker compose -f "$compose" --profile "$topology" down --volumes --remove-orphans 2>/dev/null
    record "static-$topology" $rc
}

# Run the rekey integration test
run_rekey() {
    local compose="testing/static/docker-compose.yml"
    local rc=0
    export COMPOSE_PROJECT_NAME="$(ci_project static)"

    info "[rekey] Generating configs"
    bash testing/static/scripts/generate-configs.sh rekey || { record "rekey" 1; return; }
    bash testing/static/scripts/rekey-test.sh inject-config || { record "rekey" 1; return; }

    info "[rekey] Starting containers"
    docker compose -f "$compose" --profile rekey up -d || { record "rekey" 1; return; }

    info "[rekey] Running rekey test"
    if bash testing/static/scripts/rekey-test.sh; then
        rc=0
    else
        rc=1
        info "[rekey] Collecting failure logs"
        docker compose -f "$compose" --profile rekey logs --no-color 2>&1 | tail -100
    fi

    docker compose -f "$compose" --profile rekey down --volumes --remove-orphans 2>/dev/null
    record "rekey" $rc
}

# Run the mixed-profile integration test (Full + NonRouting + Leaf)
run_mixed_profile() {
    local compose="testing/static/docker-compose.yml"
    local rc=0

    info "[mixed-profile] Generating configs"
    bash testing/static/scripts/generate-configs.sh mixed-profile || { record "mixed-profile" 1; return; }
    bash testing/static/scripts/mixed-profile-test.sh inject-config || { record "mixed-profile" 1; return; }

    info "[mixed-profile] Starting containers"
    docker compose -f "$compose" --profile mixed-profile up -d || { record "mixed-profile" 1; return; }

    info "[mixed-profile] Running mixed-profile test"
    if bash testing/static/scripts/mixed-profile-test.sh; then
        rc=0
    else
        rc=1
        info "[mixed-profile] Collecting failure logs"
        docker compose -f "$compose" --profile mixed-profile logs --no-color 2>&1 | tail -100
    fi

    docker compose -f "$compose" --profile mixed-profile down --volumes --remove-orphans 2>/dev/null
    record "mixed-profile" $rc
}

# Run the admission-cap integration test
# Verifies the inbound max_peers early-gate silent-drops at scale by
# lowering node.max_peers on one mesh node and asserting via tcpdump
# that no Msg2 responses go to the sustained-retrying denied peers.
run_admission_cap() {
    local compose="testing/static/docker-compose.yml"
    local rc=0
    export COMPOSE_PROJECT_NAME="$(ci_project static)"

    info "[admission-cap] Generating configs"
    bash testing/static/scripts/generate-configs.sh mesh || { record "admission-cap" 1; return; }
    bash testing/static/scripts/admission-cap-test.sh inject-config || { record "admission-cap" 1; return; }

    info "[admission-cap] Starting containers (mesh profile)"
    docker compose -f "$compose" --profile mesh up -d || { record "admission-cap" 1; return; }

    info "[admission-cap] Running admission-cap test"
    if bash testing/static/scripts/admission-cap-test.sh; then
        rc=0
    else
        rc=1
        info "[admission-cap] Collecting failure logs"
        docker compose -f "$compose" --profile mesh logs --no-color 2>&1 | tail -100
    fi

    docker compose -f "$compose" --profile mesh down --volumes --remove-orphans 2>/dev/null
    record "admission-cap" $rc
}

# Run a chaos scenario
run_chaos() {
    local name="$1"
    shift
    local rc=0
    # Distinct project per scenario (chaos children run in parallel). Scoped to
    # this function so the --only path cannot leak it into a later suite.
    local -x COMPOSE_PROJECT_NAME="$(ci_project "chaos-$name")"

    # Container names and the generated-config directory are GLOBAL and are not
    # scoped by the compose project, so narrow the run-wide suffix to this
    # scenario. Parallel children then cannot claim each other's names or
    # overwrite each other's compose file.
    local suffix
    suffix="$(ci_chaos_suffix "$name")"
    local -x FIPS_CI_NAME_SUFFIX="$suffix"

    info "[chaos/$name] Running simulation"
    if bash testing/chaos/scripts/chaos.sh "$@" 2>&1; then
        rc=0
    else
        rc=1
    fi

    record "chaos-$name" $rc

    # record() ends in pass()/fail(), which are echoes, so it returns 0 for any
    # rc — and without this return so does run_chaos. On the parallel path the
    # function's status is the child subshell's status, and that is the only
    # thing the waiting parent can see: the child's own RESULTS entry and its
    # OVERALL=1 die with its process, and its FAIL line goes to a logfile only
    # the unreachable branch reads. So a bare record() left every scenario
    # recorded as a pass whatever the simulation reported. On the --only path
    # record() already wrote the true rc into the parent's own RESULTS, and
    # returning it as well is inert: this script does not set -e.
    return $rc
}

# Run gateway integration test
run_gateway() {
    local compose="testing/static/docker-compose.yml"
    local rc=0
    export COMPOSE_PROJECT_NAME="$(ci_project static)"

    info "[gateway] Generating configs"
    bash testing/static/scripts/generate-configs.sh gateway gateway-test || { record "gateway" 1; return; }
    bash testing/static/scripts/gateway-test.sh inject-config || { record "gateway" 1; return; }

    info "[gateway] Starting containers"
    docker compose -f "$compose" --profile gateway up -d || { record "gateway" 1; return; }

    info "[gateway] Running gateway test"
    if bash testing/static/scripts/gateway-test.sh; then
        rc=0
    else
        rc=1
        info "[gateway] Collecting failure logs"
        docker compose -f "$compose" --profile gateway logs --no-color 2>&1 | tail -100
    fi

    docker compose -f "$compose" --profile gateway down --volumes --remove-orphans 2>/dev/null
    record "gateway" $rc
}

# Run sidecar test
run_sidecar() {
    local rc=0
    export COMPOSE_PROJECT_NAME="$(ci_project sidecar)"

    info "[sidecar] Running integration test"
    if bash testing/sidecar/scripts/test-sidecar.sh --skip-build 2>&1; then
        rc=0
    else
        rc=1
    fi

    record "sidecar" $rc
}

# Run the rekey-accept-off integration variant. Same harness as run_rekey
# but on a 2-node topology with udp.accept_connections=false on node-b.
run_rekey_accept_off() {
    local compose="testing/static/docker-compose.yml"
    local rc=0
    export COMPOSE_PROJECT_NAME="$(ci_project static)"

    info "[rekey-accept-off] Generating configs"
    bash testing/static/scripts/generate-configs.sh rekey-accept-off || \
        { record "rekey-accept-off" 1; return; }
    REKEY_TOPOLOGY=rekey-accept-off REKEY_ACCEPT_OFF_NODES=b \
        bash testing/static/scripts/rekey-test.sh inject-config || \
        { record "rekey-accept-off" 1; return; }

    info "[rekey-accept-off] Starting containers"
    docker compose -f "$compose" --profile rekey-accept-off up -d || \
        { record "rekey-accept-off" 1; return; }

    info "[rekey-accept-off] Running rekey test"
    if REKEY_TOPOLOGY=rekey-accept-off REKEY_ACCEPT_OFF_NODES=b \
        bash testing/static/scripts/rekey-test.sh; then
        rc=0
    else
        rc=1
        info "[rekey-accept-off] Collecting failure logs"
        docker compose -f "$compose" --profile rekey-accept-off logs --no-color 2>&1 | tail -100
    fi

    docker compose -f "$compose" --profile rekey-accept-off down --volumes --remove-orphans 2>/dev/null
    record "rekey-accept-off" $rc
}

# Run the rekey-outbound-only integration variant. Same harness as
# run_rekey but with udp.outbound_only=true on node-b plus its peer
# addrs rewritten from numeric docker IPs to docker hostnames so the
# addr_to_link key form mismatches inbound packet source addrs (the
# production trigger for the rekey-msg1 carve-out gap).
run_rekey_outbound_only() {
    local compose="testing/static/docker-compose.yml"
    local rc=0
    export COMPOSE_PROJECT_NAME="$(ci_project static)"

    info "[rekey-outbound-only] Generating configs"
    bash testing/static/scripts/generate-configs.sh rekey-outbound-only || \
        { record "rekey-outbound-only" 1; return; }
    REKEY_TOPOLOGY=rekey-outbound-only REKEY_OUTBOUND_ONLY_NODES=b \
        bash testing/static/scripts/rekey-test.sh inject-config || \
        { record "rekey-outbound-only" 1; return; }

    info "[rekey-outbound-only] Starting containers"
    docker compose -f "$compose" --profile rekey-outbound-only up -d || \
        { record "rekey-outbound-only" 1; return; }

    info "[rekey-outbound-only] Running rekey test"
    if REKEY_TOPOLOGY=rekey-outbound-only REKEY_OUTBOUND_ONLY_NODES=b \
        bash testing/static/scripts/rekey-test.sh; then
        rc=0
    else
        rc=1
        info "[rekey-outbound-only] Collecting failure logs"
        docker compose -f "$compose" --profile rekey-outbound-only logs --no-color 2>&1 | tail -100
    fi

    docker compose -f "$compose" --profile rekey-outbound-only down --volumes --remove-orphans 2>/dev/null
    record "rekey-outbound-only" $rc
}

# Run ACL allowlist integration test
run_acl_allowlist() {
    export COMPOSE_PROJECT_NAME="$(ci_project acl)"
    info "[acl-allowlist] Running integration test"
    if bash testing/acl-allowlist/test.sh --skip-build 2>&1; then
        record "acl-allowlist" 0
    else
        record "acl-allowlist" 1
    fi
}

# Run firewall baseline integration test
run_firewall() {
    export COMPOSE_PROJECT_NAME="$(ci_project firewall)"
    info "[firewall] Running integration test"
    if bash testing/firewall/test.sh --skip-build 2>&1; then
        record "firewall" 0
    else
        record "firewall" 1
    fi
}

# Run a NAT scenario (cone, symmetric, lan)
run_nat() {
    local scenario="$1"
    export COMPOSE_PROJECT_NAME="$(ci_project nat)"
    info "[nat-$scenario] Running NAT lab"
    if bash testing/nat/scripts/nat-test.sh "$scenario" 2>&1; then
        record "nat-$scenario" 0
    else
        record "nat-$scenario" 1
    fi
}

# Run the Nostr overlay advert publish/consume integration test.
# Two FIPS daemons + the existing strfry relay; exercises Phase 1
# (A→B publish/consume), Phase 2 (B→A reverse), and Phase 3 (malformed
# advert injected directly to the relay; consumer-liveness assertion).
run_nostr_publish_consume() {
    export COMPOSE_PROJECT_NAME="$(ci_project nat)"
    info "[nostr-publish-consume] Running Nostr publish/consume test"
    if bash testing/nat/scripts/nostr-relay-test.sh 2>&1; then
        record "nostr-publish-consume" 0
    else
        record "nostr-publish-consume" 1
    fi
}

# Run the STUN fault-injection integration test.
# One FIPS daemon + a netns-sharing shim that injects tc/iptables faults
# against UDP egress to the STUN service. Three phases: drop, delay,
# kill. Asserts the daemon detects each fault, recovers from delay, and
# never panics.
run_stun_faults() {
    export COMPOSE_PROJECT_NAME="$(ci_project nat)"
    info "[stun-faults] Running STUN fault-injection test"
    if bash testing/nat/scripts/stun-faults-test.sh 2>&1; then
        record "stun-faults" 0
    else
        record "stun-faults" 1
    fi
}

# Run dns-resolver harness (multi-distro + e2e scenarios)
run_dns_resolver() {
    info "[dns-resolver] Running multi-distro test (slow — builds per-distro images)"
    if bash testing/dns-resolver/test.sh 2>&1; then
        record "dns-resolver" 0
    else
        record "dns-resolver" 1
    fi
}

# Run deb-install harness (multi-distro real-package install)
run_deb_install() {
    info "[deb-install] Running multi-distro test (slow — builds .deb + per-distro install)"
    if bash testing/deb-install/test.sh 2>&1; then
        record "deb-install" 0
    else
        record "deb-install" 1
    fi
}

# Run Tor SOCKS5 outbound test (live Tor network)
run_tor_socks5() {
    export COMPOSE_PROJECT_NAME="$(ci_project tor-socks5)"
    info "[tor-socks5] Running Tor SOCKS5 outbound test (live Tor)"
    if bash testing/tor/socks5-outbound/scripts/tor-test.sh 2>&1; then
        record "tor-socks5" 0
    else
        record "tor-socks5" 1
    fi
}

# Run Tor directory-mode test (live Tor network)
run_tor_directory() {
    export COMPOSE_PROJECT_NAME="$(ci_project tor-directory)"
    info "[tor-directory] Running Tor directory-mode test (live Tor)"
    if bash testing/tor/directory-mode/scripts/directory-test.sh 2>&1; then
        record "tor-directory" 0
    else
        record "tor-directory" 1
    fi
}

# Determine which suites to run and execute them
run_integration() {
    stage "Stage 3: Integration Tests"

    # Install binaries to shared docker context
    info "Installing release binaries"
    install_binaries testing/docker

    # Build unified test image once (used by all harnesses). Tag per-run
    # (fips-test:${run}) so a build killed mid-flight never wedges the next
    # run's rebuild, and concurrent runs never clobber each other's image.
    # Then retag :latest for the compose files / harness scripts that still
    # reference fips-test:latest directly; the retag happens only after BOTH
    # builds succeed, so :latest never points at a half-built image.
    info "Building $CI_IMAGE_TEST Docker image"
    docker build -t "$CI_IMAGE_TEST" --label "$CI_LABEL" --label "$CI_LABEL_RUN" testing/docker --quiet \
        || { record "docker-build" 1; return; }
    docker build -t "$CI_IMAGE_APP" --label "$CI_LABEL" --label "$CI_LABEL_RUN" \
        -f testing/docker/Dockerfile.app testing/docker --quiet \
        || { record "docker-build-app" 1; return; }
    docker tag "$CI_IMAGE_TEST" fips-test:latest
    docker tag "$CI_IMAGE_APP" fips-test-app:latest

    # Single suite mode
    if [[ -n "$ONLY_SUITE" ]]; then
        run_suite "$ONLY_SUITE"
        return
    fi

    # Static topologies (sequential — profiles share container names)
    for topo in "${STATIC_SUITES[@]}"; do
        local topology="${topo#static-}"
        run_static "$topology"
    done

    # Rekey + rekey-accept-off + rekey-outbound-only variants
    run_rekey
    run_rekey_accept_off
    run_rekey_outbound_only

    # Mixed-profile (Full + NonRouting + Leaf)
    for _suite in "${MIXED_PROFILE_SUITES[@]}"; do
        run_mixed_profile
    done

    # Admission cap (mesh profile, max_peers=1 on one node)
    for _suite in "${ADMISSION_SUITES[@]}"; do
        run_admission_cap
    done

    # Gateway
    run_gateway

    # ACL allowlist
    run_acl_allowlist

    # Firewall baseline
    run_firewall

    # NAT scenarios (sequential — each owns its compose project)
    for scenario in "${NAT_SUITES[@]}"; do
        run_nat "$scenario"
    done

    # Nostr publish/consume (sequential — shares the NAT compose project)
    for _suite in "${NOSTR_RELAY_SUITES[@]}"; do
        run_nostr_publish_consume
    done

    # STUN fault-injection (sequential — shares the NAT compose project)
    for _suite in "${STUN_FAULTS_SUITES[@]}"; do
        run_stun_faults
    done

    # Chaos scenarios (parallel, throttled)
    if [[ "$SKIP_CHAOS" != true ]]; then
        info "Running ${#CHAOS_SUITES[@]} chaos scenarios (max $PARALLEL_JOBS parallel)"
        local pids=()
        local suite_names=()
        local running=0
        local chaos_idx=0

        for entry in "${CHAOS_SUITES[@]}"; do
            # Parse: "display-name scenario [flags...]"
            read -ra parts <<< "$entry"
            local name="${parts[0]}"
            local args=("${parts[@]:1}")

            # Give each chaos child a unique, non-overlapping /24 in 10.30.x so
            # parallel children never collide with each other, and so a chaos
            # net can never swallow a fixed-subnet suite (sidecar/static/nat in
            # 172.x). 10.30.x sits outside docker's default-address-pool range
            # (172.17-31 / 192.168), so auto-assigned nets can't land on it
            # either. Node IPs derive from this subnet inside the sim.
            args+=("--subnet" "10.30.${chaos_idx}.0/24")
            chaos_idx=$((chaos_idx + 1))

            # Throttle: wait for a slot
            while [[ $running -ge $PARALLEL_JOBS ]]; do
                wait -n -p done_pid 2>/dev/null || true
                running=$((running - 1))
            done

            # Run in background, capture output to temp file
            local logfile
            logfile=$(mktemp "/tmp/ci-chaos-${name}.XXXXXX")
            (
                run_chaos "$name" "${args[@]}" >"$logfile" 2>&1
            ) &
            pids+=($!)
            CI_CHAOS_PIDS+=("$!")
            suite_names+=("$name:$logfile")
            running=$((running + 1))
        done

        # Wait for all and collect results
        for i in "${!pids[@]}"; do
            local pid="${pids[$i]}"
            local entry="${suite_names[$i]}"
            local scenario="${entry%%:*}"
            local logfile="${entry#*:}"

            if wait "$pid" 2>/dev/null; then
                record "chaos-$scenario" 0
            else
                record "chaos-$scenario" 1
                # Show tail of failure log
                echo "--- chaos-$scenario output (last 20 lines) ---"
                tail -20 "$logfile" 2>/dev/null || true
                echo "---"
            fi
            rm -f "$logfile"
        done
        # All chaos children have been waited on; clear so a later signal does
        # not try to kill already-reaped PIDs.
        CI_CHAOS_PIDS=()
    fi

    # Sidecar
    run_sidecar

    # DNS resolver multi-distro suite (heavy — per-distro systemd images)
    run_dns_resolver

    # Deb-install multi-distro suite (heavy — builds .deb + per-distro install)
    run_deb_install

    # Tor (opt-in via --with-tor; depends on live Tor network)
    if [[ "$WITH_TOR" == true ]]; then
        run_tor_socks5
        run_tor_directory
    fi
}

# Run a single named suite
run_suite() {
    local suite="$1"
    case "$suite" in
        static-mesh|static-chain)
            run_static "${suite#static-}" ;;
        rekey)
            run_rekey ;;
        rekey-accept-off)
            run_rekey_accept_off ;;
        rekey-outbound-only)
            run_rekey_outbound_only ;;
        mixed-profile)
            run_mixed_profile ;;
        admission-cap)
            run_admission_cap ;;
        gateway)
            run_gateway ;;
        acl-allowlist)
            run_acl_allowlist ;;
        firewall)
            run_firewall ;;
        nat-cone|nat-symmetric|nat-lan)
            run_nat "${suite#nat-}" ;;
        nostr-publish-consume)
            run_nostr_publish_consume ;;
        stun-faults)
            run_stun_faults ;;
        chaos-*)
            local chaos_name="${suite#chaos-}"
            local found=false
            for entry in "${CHAOS_SUITES[@]}"; do
                read -ra parts <<< "$entry"
                if [[ "${parts[0]}" == "$chaos_name" ]]; then
                    run_chaos "$chaos_name" "${parts[@]:1}"
                    found=true
                    break
                fi
            done
            if [[ "$found" != true ]]; then
                # Fall back to using the name as the scenario directly. Note
                # teardown rebuilds veth suffixes from CHAOS_SUITES only, so a
                # scenario named here but absent from that list is outside the
                # host-interface reap. Harmless while every ethernet-transport
                # scenario is declared there; add one that isn't and its
                # orphaned pairs will need an unscoped `--reap` to clear.
                run_chaos "$chaos_name" "$chaos_name"
            fi
            ;;
        sidecar)
            run_sidecar ;;
        dns-resolver)
            run_dns_resolver ;;
        deb-install)
            run_deb_install ;;
        tor-socks5)
            run_tor_socks5 ;;
        tor-directory)
            run_tor_directory ;;
        *)
            fail "Unknown suite: $suite"
            record "$suite" 1 ;;
    esac
}

# ── Summary ────────────────────────────────────────────────────────────────

print_summary() {
    stage "Summary"

    local passed=0 failed=0 total=0
    for name in $(echo "${!RESULTS[@]}" | tr ' ' '\n' | sort); do
        local rc="${RESULTS[$name]}"
        total=$((total + 1))
        if [[ $rc -eq 0 ]]; then
            passed=$((passed + 1))
            echo -e "  ${GREEN}✓${RESET} $name"
        else
            failed=$((failed + 1))
            echo -e "  ${RED}✗${RESET} $name"
        fi
    done

    echo ""
    echo -e "  ${BOLD}Total: $total  Passed: $passed  Failed: $failed${RESET}"
    echo ""

    if [[ $OVERALL -eq 0 ]]; then
        echo -e "  ${GREEN}${BOLD}ALL PASSED${RESET}"
    else
        echo -e "  ${RED}${BOLD}FAILED${RESET}"
    fi
    echo ""
}

# Verify the local default suite set and the GitHub matrix still cover the
# same work. Runs first: it takes about a second, and a divergence should be
# reported before a half-hour suite rather than after it.
run_ci_parity() {
    local rc=0
    info "[ci-parity] Comparing the local suite set against the GitHub matrix"
    "$SCRIPT_DIR/check-ci-parity.sh" || rc=$?
    record "ci-parity" $rc
}

# ── Main ───────────────────────────────────────────────────────────────────

main() {
    local start_time=$SECONDS

    stage "FIPS Local CI"
    info "Project root: $PROJECT_ROOT"

    # Above the mode branches deliberately, so --only, --test-only and
    # --build-only are gated too: a divergence invalidates any claim that a
    # local run means what a GitHub run means, whichever subset was asked for.
    run_ci_parity

    if [[ "$TEST_ONLY" == true ]]; then
        run_tests
    elif [[ "$BUILD_ONLY" == true ]]; then
        run_build
    else
        run_build
        if [[ "${RESULTS[build]:-1}" -ne 0 ]]; then
            fail "Build failed, skipping remaining stages"
        else
            run_tests
            if [[ "$SKIP_INTEGRATION" != true ]]; then
                run_integration
            fi
        fi
    fi

    print_summary

    local elapsed=$(( SECONDS - start_time ))
    local mins=$(( elapsed / 60 ))
    local secs=$(( elapsed % 60 ))
    info "Total time: ${mins}m ${secs}s"

    exit $OVERALL
}

main
