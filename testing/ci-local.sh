#!/bin/bash
# Run the CI pipeline locally: build, unit tests, integration tests.
#
# Usage: ./ci-local.sh [options]
#
# Options:
#   --build-only         Only run build + clippy
#   --test-only          Only run unit tests (skip build, skip integration)
#   --skip-integration   Skip integration tests
#   --skip-chaos         Skip chaos scenarios (run static + rekey + sidecar only)
#   --only <suite>       Run a single integration suite
#   -j, --jobs <N>       Max parallel chaos scenarios (default: 4)
#   --list               List available integration suites
#   -h, --help           Show this help
#
# Integration suites:
#   static-mesh, static-chain, rekey, mixed-profile,
#   chaos-smoke-10, chaos-churn-mixed-10, chaos-ethernet-mesh,
#   chaos-ethernet-only, chaos-tcp-mesh, chaos-bottleneck-parent,
#   chaos-cost-avoidance, chaos-cost-reeval, chaos-cost-stability,
#   chaos-depth-vs-cost, chaos-mixed-technology, chaos-congestion-stress,
#   sidecar
#
# Exit codes:
#   0 — all stages passed
#   1 — one or more stages failed
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
ONLY_SUITE=""

# All integration suites matching ci.yml
STATIC_SUITES=(static-mesh static-chain)
REKEY_SUITES=(rekey)
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
)
SIDECAR_SUITES=(sidecar)

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
    echo "  Chaos scenarios:"
    for entry in "${CHAOS_SUITES[@]}"; do
        read -ra parts <<< "$entry"
        echo "    chaos-${parts[0]}  (${parts[*]:1})"
    done
    echo ""
    echo "  Sidecar:"
    for s in "${SIDECAR_SUITES[@]}"; do echo "    $s"; done
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
        --only)             ONLY_SUITE="$2"; shift 2 ;;
        -j|--jobs)          PARALLEL_JOBS="$2"; shift 2 ;;
        --list)             list_suites ;;
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

    info "cargo build --release"
    if cargo build --release 2>&1; then
        record "build" 0
    else
        record "build" 1
        return 1
    fi

    info "cargo clippy --all -- -D warnings"
    if cargo clippy --all -- -D warnings 2>&1; then
        record "clippy" 0
    else
        record "clippy" 1
        return 1
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
    chmod +x "$dest/fips" "$dest/fipsctl"
    [[ -f "$dest/fipstop" ]] && chmod +x "$dest/fipstop" || true
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

    # Rekey
    run_rekey

    # Mixed-profile (Full + NonRouting + Leaf)
    run_mixed_profile

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
}

# Run a single named suite
run_suite() {
    local suite="$1"
    case "$suite" in
        static-mesh|static-chain)
            run_static "${suite#static-}" ;;
        rekey)
            run_rekey ;;
        mixed-profile)
            run_mixed_profile ;;
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
