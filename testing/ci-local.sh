#!/bin/bash
# Run the CI pipeline locally: build, unit tests, integration tests.
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
#   -h, --help           Show this help
#
# Integration suites (default coverage):
#   static-mesh, static-chain, rekey, rekey-accept-off,
#   rekey-outbound-only, gateway,
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
#   0 — all stages passed
#   1 — one or more stages failed
#
# ── CI parity invariant ─────────────────────────────────────────────────────
# This local default suite set and the GitHub integration matrix
# (.github/workflows/ci.yml) MUST run the same integration suites, EXCEPT for
# the deliberate local-only entries below. Adding a suite to one runner
# without the other means "local green" and "GitHub green" stop being
# equivalent. testing/check-ci-parity.sh enforces this and fails on drift.
#
# Deliberate local-only (NOT on the GitHub gate), with reason:
#   tor-socks5     — requires live Tor network; opt-in via --with-tor,
#                    unreliable on GitHub-hosted runners.
#   tor-directory  — same; live Tor dependency.
#
# Granularity-only differences (same coverage, different matrix shape —
# NOT a divergence):
#   deb-install    — local runs all distros sequentially in one suite; GitHub
#                    splits into per-distro legs (debian12/debian13/ubuntu22/
#                    ubuntu24/ubuntu26 — the same distro set).
#   dns-resolver   — single suite both sides; runs all scenarios.
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
GATEWAY_SUITES=(gateway)
SIDECAR_SUITES=(sidecar)
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

# Run the admission-cap integration test
# Verifies the inbound max_peers early-gate silent-drops at scale by
# lowering node.max_peers on one mesh node and asserting via tcpdump
# that no Msg2 responses go to the sustained-retrying denied peers.
run_admission_cap() {
    local compose="testing/static/docker-compose.yml"
    local rc=0

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

    info "[chaos/$name] Running simulation"
    if bash testing/chaos/scripts/chaos.sh "$@" 2>&1; then
        rc=0
    else
        rc=1
    fi

    record "chaos-$name" $rc
}

# Run gateway integration test
run_gateway() {
    local compose="testing/static/docker-compose.yml"
    local rc=0

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
    info "[acl-allowlist] Running integration test"
    if bash testing/acl-allowlist/test.sh --skip-build 2>&1; then
        record "acl-allowlist" 0
    else
        record "acl-allowlist" 1
    fi
}

# Run firewall baseline integration test
run_firewall() {
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
    info "[tor-socks5] Running Tor SOCKS5 outbound test (live Tor)"
    if bash testing/tor/socks5-outbound/scripts/tor-test.sh 2>&1; then
        record "tor-socks5" 0
    else
        record "tor-socks5" 1
    fi
}

# Run Tor directory-mode test (live Tor network)
run_tor_directory() {
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

    # Build unified test image once (used by all harnesses)
    info "Building fips-test Docker image"
    docker build -t fips-test:latest testing/docker --quiet || { record "docker-build" 1; return; }
    docker build -t fips-test-app:latest -f testing/docker/Dockerfile.app testing/docker --quiet || { record "docker-build-app" 1; return; }

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

        for entry in "${CHAOS_SUITES[@]}"; do
            # Parse: "display-name scenario [flags...]"
            read -ra parts <<< "$entry"
            local name="${parts[0]}"
            local args=("${parts[@]:1}")

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
                # Fall back to using the name as the scenario directly
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

# ── Main ───────────────────────────────────────────────────────────────────

main() {
    local start_time=$SECONDS

    stage "FIPS Local CI"
    info "Project root: $PROJECT_ROOT"

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
