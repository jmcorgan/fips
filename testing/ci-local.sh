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
#   static-mesh, static-chain, gateway,
#   firewall, nat-cone, nat-symmetric,
#   nat-lan, nostr-publish-consume, stun-faults,
#   chaos-churn-mixed-10, chaos-ethernet-mesh,
#   chaos-ethernet-only, chaos-tcp-mesh, chaos-congestion-stress,
#   chaos-bloom-storm,
#   sidecar, dns-resolver, deb-install
#
# Opt-in (require --with-tor; depend on live Tor network):
#   tor-socks5, tor-directory
#
# Deliberately not run by either runner, with the reason for each. Recorded
# here so that "not in the suite list" stops being indistinguishable from
# "forgotten", which is what it was until 2026-07-23:
#   interop/         Manual. Driven by interop-stress.sh, which runs N
#                    repetitions serially under netem and takes far longer
#                    than a CI slot. No CI-sized entry point exists yet;
#                    writing one is the work, not adding a line here.
#   boringtun/       Comparative benchmark against a non-FIPS implementation.
#                    Measures rather than asserts, and needs a boringtun
#                    build CI does not have.
#   iperf-test.sh    Bandwidth measurement, no pass/fail. Driven manually by
#                    iperf-compare-refs.sh.
#   ecn-ab-compare.sh  Manual A/B comparison, renamed from ecn-ab-test.sh
#                    because it asserts nothing. Making it gateable needs a
#                    calibration corpus that does not exist; see its header.
#   mesh-lab/        Long-running multi-host lab, not a suite.
#   acl-allowlist/   Retired from CI 2026-07-24 as redundant, not unrunnable.
#                    The ACL decision is exhaustively unit-tested per npub over
#                    real loaded allow/deny files (src/node/acl.rs mod tests:
#                    allow-wins, allowlist-miss, deny-only, deny-all,
#                    allow_all-override), and the inbound/outbound handshake-
#                    admission path is covered in-process over loopback
#                    (src/node/tests/acl.rs). The Docker suite's only unique
#                    coverage was real-UDP admission, exercised by every other
#                    real-transport suite. Still runnable by hand:
#                    bash testing/acl-allowlist/test.sh
#   admission-cap    Retired from CI 2026-07-24 as redundant, not unrunnable.
#                    The inbound max_peers cap on the XX FMP handshake is
#                    enforced at msg3 and unit-tested by
#                    handle_msg3_silent_drops_at_cap_for_new_peer in
#                    src/node/tests/unit.rs: it pumps an over-cap handshake
#                    from a fresh identity into a saturated node and asserts
#                    the path-agnostic invariant — no promotion over cap, peer
#                    count unchanged — plus handle_msg3_admits_existing_peer_at_cap
#                    for the known-peer bypass. Still runnable by hand:
#                    bash testing/static/scripts/admission-cap-test.sh
#   rekey, rekey-accept-off, rekey-outbound-only
#                    Retired from CI 2026-07-24 as redundant, not unrunnable.
#                    The rekey timing/choreography decision (trigger, K-bit
#                    cutover, drain, jitter, guards) is covered by the sans-IO
#                    poll_rekey tests (src/proto/fsp/tests/core.rs,
#                    src/proto/fmp/tests/core.rs); the data-plane continuity
#                    across a real cutover by rekey_cutover_preserves_data_plane
#                    (src/node/tests/session.rs, a real XX rekey over loopback,
#                    the responder classifying it from the msg3 rekey marker);
#                    the accept-off dual-init regression and the
#                    udp.outbound_only rekey loop by the should_admit_msg1 tests
#                    (src/node/tests/handshake.rs) and the establish_inbound /
#                    establish_outbound decision tests (src/proto/fmp/tests/core.rs,
#                    src/peer/machine.rs). Still runnable by hand:
#                    bash testing/static/scripts/rekey-test.sh
#   mixed-profile    Retired from CI 2026-07-25 as redundant, not unrunnable.
#                    Mixed Full/NonRouting/Leaf convergence, peer degrees and
#                    every reachability pair it asserted, including the
#                    Leaf-to-Full multi-hop pair through the Full node between
#                    them, are covered in-process over loopback by
#                    mixed_profile_nodes_converge_and_forward
#                    (src/node/tests/session.rs). The in-process test covers a
#                    superset: it asserts the multi-hop path in BOTH directions
#                    where this suite covered one. Retired only after the
#                    multi-hop assertion was shown to discriminate — reverting
#                    the leaf root-election gate reds it in roughly a third of
#                    runs — rather than on a green run alone. Still runnable by
#                    hand: bash testing/static/scripts/mixed-profile-test.sh
#   ecn-ab-on, ecn-ab-off, maelstrom, maelstrom-sparse
#                    Chaos scenarios excluded from CHAOS_SUITES. The two
#                    ecn-ab ones are halves of the manual comparison above.
#                    The two maelstrom ones are 600 s stress runs kept for
#                    manual investigation. All four still load-check and
#                    carry the default max_errors ceiling if run by hand.
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
# Each entry: "display-name scenario [--flag value ...]"
CHAOS_SUITES=(
    "churn-mixed-10 churn-mixed --nodes 10 --duration 120"
    "ethernet-mesh ethernet-mesh"
    "ethernet-only ethernet-only"
    "tcp-mesh tcp-mesh"
    "congestion-stress congestion-stress"
    "bloom-storm bloom-storm"
)
# Scenarios retired 2026-07-23 because their subject was a pure decision the
# Docker harness could not test reliably, now covered by sans-IO unit tests
# of the parent-selection cost/depth/hysteresis decision and the transport
# drop-detection edge:
#   - cost-reeval, cost-avoidance, cost-stability, depth-vs-cost,
#     mixed-technology, bottleneck-parent (root election, MMP measurement lag
#     and hold-down timing all confounded the Docker assertions).
#   - congestion-drops (never landed): a fresh daemon reader keeps up with
#     container-speed traffic, so SO_RXQ_OVFL could not be provoked.
# congestion-stress stays: it exercises the ECN/MMP congestion signals,
# which do need the real shaped bottleneck queue.
#
# Retired 2026-07-24 for a different reason — redundant, not unreliable:
#   - smoke-10: a no-stressor 10-node tree-convergence sanity check (netem
#     off, no ping). The convergence logic it exercised is covered in-process,
#     faster and deterministically, by the loopback spanning-tree harness
#     (src/node/tests/spanning_tree.rs: ring/star/chain/100-node/disconnected)
#     plus end-to-end datagram delivery (src/node/tests/forwarding.rs). Real-
#     UDP convergence smoke still runs via static-mesh and the other chaos
#     scenarios' baseline assertions, so no Docker coverage is lost.
GATEWAY_SUITES=(gateway)
SIDECAR_SUITES=(sidecar)
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
    echo "  Gateway:"
    for s in "${GATEWAY_SUITES[@]}"; do echo "    $s"; done
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

    # 3. The static and firewall suites' generated configs are per-run (a
    #    shared directory would let concurrent runs overwrite each other's node
    #    configs), so they are this run's to remove. Only on a green run: after
    #    a failure they are the evidence of what the failing nodes were actually
    #    configured with. Guarded on a non-empty suffix too, since without one
    #    the path is the unscoped working directory a developer uses by hand,
    #    which is not ours to delete.
    #
    #    Every suite whose configs become per-run owes a line here. acl-allowlist
    #    also generates per-run now but is not in this runner's suite list, so
    #    this teardown never creates its directory and must not remove one.
    if [[ $run_status -eq 0 && -n "${CI_RUN_NAME_SUFFIX:-}" ]]; then
        rm -rf "$SCRIPT_DIR/static/generated-configs${CI_RUN_NAME_SUFFIX}"
        rm -rf "$SCRIPT_DIR/firewall/generated-configs${CI_RUN_NAME_SUFFIX}"
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

# Claim a free /64 for this run's gateway-lan network (Mechanism B).
#
# gateway-lan cannot float like fips-net: the LAN clients' resolv.conf pins the
# gateway's LAN address as their nameserver, which must be a literal known
# before they start. So instead of a fixed fd02::/64 that two concurrent runs
# both request (the second failing on "Pool overlaps"), claim-and-advance a
# candidate /64 and let docker's create be the atomic arbiter. The claimed
# prefix is threaded — via the exported FIPS_GW_LAN6_PREFIX — into the compose
# ipv6_address pins, the generated resolv.conf, and gateway-test.sh, so every
# LAN address moves with the claim. i=0 renders today's fd02::/64.
#
# Mirrors sidecar/scripts/test-sidecar.sh:alloc_network. Deliberately does NOT
# discard stderr: only an address-pool conflict is worth advancing on; any other
# failure is real and burning through 256 candidates would bury the reason.
claim_gateway_lan6() {
    local net="$1" i err
    for (( i = 0; i < 256; i++ )); do
        if err=$(docker network create --ipv6 \
                --subnet "fd02:0:0:${i}::/64" \
                --label "$CI_LABEL" --label "$CI_LABEL_RUN" \
                "$net" 2>&1); then
            export FIPS_GW_LAN6_PREFIX="fd02:0:0:${i}"
            info "[gateway] Claimed $net on fd02:0:0:${i}::/64"
            return 0
        fi
        case "$err" in
            *"Pool overlaps"*|*"pool overlaps"*) continue ;;
            *) fail "[gateway] docker network create: $err"; return 1 ;;
        esac
    done
    fail "[gateway] no free /64 in fd02:0:0:0-255::/64 after 256 attempts"
    return 1
}

# Run gateway integration test
run_gateway() {
    local compose="testing/static/docker-compose.yml"
    local ext="testing/static/docker-compose.gateway-external-net.yml"
    local rc=0
    export COMPOSE_PROJECT_NAME="$(ci_project static)"
    export FIPS_GW_LAN_NET="fips-gateway-lan${FIPS_CI_NAME_SUFFIX:-}"

    # Claim the LAN /64 first: generate-configs writes resolv.conf from the
    # claimed prefix, and inject-config renders the port-forward targets from
    # it, so both must see FIPS_GW_LAN6_PREFIX before they run.
    info "[gateway] Claiming LAN network"
    if ! claim_gateway_lan6 "$FIPS_GW_LAN_NET"; then
        record "gateway" 1
        return
    fi

    info "[gateway] Generating configs"
    if bash testing/static/scripts/generate-configs.sh gateway gateway-test \
        && bash testing/static/scripts/gateway-test.sh inject-config \
        && { info "[gateway] Starting containers"; \
             docker compose -f "$compose" -f "$ext" --profile gateway up -d; }; then
        info "[gateway] Running gateway test"
        if bash testing/static/scripts/gateway-test.sh; then
            rc=0
        else
            rc=1
            info "[gateway] Collecting failure logs"
            docker compose -f "$compose" -f "$ext" --profile gateway logs --no-color 2>&1 | tail -100
        fi
    else
        rc=1
    fi

    # compose down does not remove an external network, so drop it explicitly.
    docker compose -f "$compose" -f "$ext" --profile gateway down --volumes --remove-orphans 2>/dev/null
    docker network rm "$FIPS_GW_LAN_NET" >/dev/null 2>&1 || true
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

    # Gateway
    run_gateway

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

        for entry in "${CHAOS_SUITES[@]}"; do
            # Parse: "display-name scenario [flags...]"
            read -ra parts <<< "$entry"
            local name="${parts[0]}"
            local args=("${parts[@]:1}")

            # No --subnet: the sim claims a free /24 itself (sim/netclaim.py).
            # This used to pass 10.30.${chaos_idx}.0/24, which uniquified the
            # children of ONE run against each other and was byte-identical
            # between runs -- so two concurrent ci-local runs both walked
            # 10.30.0 through 10.30.12 and collided on every one. A claim makes
            # the daemon the arbiter, so an overlap is impossible rather than
            # merely unlikely. The range still sits in 10.30.0.0/16, clear of
            # docker's default pool (172.17-31 / 192.168) and of the
            # fixed-subnet suites in 172.x.

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
        gateway)
            run_gateway ;;
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

# Every daemon log string a test matches on must still be emitted by src/.
# A stale one does not fail — it stops observing, and an expect-zero assertion
# built on it then passes for the wrong reason.
run_log_strings() {
    local rc=0
    info "[log-strings] Checking test log matchers against the strings src/ emits"
    python3 "$SCRIPT_DIR/check-log-strings.py" || rc=$?
    record "log-strings" $rc
}

# A shell function's exit status is its last command's. One ending in a log
# call returns 0 whatever it did, so a caller testing that status has a dead
# gate — the run_chaos and build_fips_for_e2e defects, one of which certified
# unbuilt code as green. This enforces an explicit terminal return wherever a
# caller consumes the status, which makes the class unreachable rather than
# repairing instances of it.
run_trailing_log() {
    local rc=0
    info "[trailing-log] Checking for functions whose status is a log call's"
    python3 "$SCRIPT_DIR/check-trailing-log.py" || rc=$?
    record "trailing-log" $rc
}

# Unit tests for the convergence gate every static suite waits on. Hermetic —
# synthetic ping functions against the same SECONDS clock, no containers — but
# it drives real timeouts, so it costs about 45 seconds rather than the "few
# seconds" its own header used to claim.
#
# It is here with the other two rather than in the integration stage because it
# needs nothing built. Note what that buys: wait_until_connected decides whether
# every static suite proceeds or gives up, so a regression in it turns those
# suites' verdicts into noise, and until now nothing ran this at all.
run_wait_converge() {
    local rc=0
    info "[wait-converge] Running convergence-gate unit tests"
    bash "$SCRIPT_DIR/lib/wait-converge-test.sh" || rc=$?
    record "wait-converge" $rc
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
    run_log_strings
    run_trailing_log
    run_wait_converge

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
