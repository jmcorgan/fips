#!/bin/bash
# Test fips-dns-setup across different Linux resolver backends.
#
# Each scenario runs a systemd-based Docker container, creates a dummy
# fips0 interface, runs the setup script, verifies the detected backend
# and generated config, runs teardown, and verifies cleanup.
#
# Usage: ./test.sh [scenario ...]
#   No args = run all scenarios.
#   Named args = run only those (e.g., ./test.sh debian12-resolved dnsmasq)
#
# Requirements: Docker with privileged container support.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SETUP_SCRIPT="$REPO_ROOT/packaging/common/fips-dns-setup"
TEARDOWN_SCRIPT="$REPO_ROOT/packaging/common/fips-dns-teardown"

# Timeout for systemd boot inside container
BOOT_TIMEOUT=30

PASS=0
FAIL=0
SKIP=0

# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────

log()  { echo "=== $*"; }
pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP: $*"; SKIP=$((SKIP + 1)); }

cleanup_container() {
    local name="$1"
    docker rm -f "$name" >/dev/null 2>&1 || true
}

# Build an image from an inline Dockerfile.
build_image() {
    local tag="$1"
    shift
    echo "$@" | docker build -t "$tag" -f - "$REPO_ROOT" >/dev/null 2>&1
}

# Start a systemd container in the background.
start_systemd_container() {
    local name="$1" image="$2"
    cleanup_container "$name"
    docker run -d --name "$name" \
        --privileged \
        --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock \
        "$image" >/dev/null 2>&1
}

# Wait for systemd to reach a bootable state inside the container.
wait_for_systemd() {
    local name="$1"
    for _i in $(seq 1 "$BOOT_TIMEOUT"); do
        if docker exec "$name" systemctl is-system-running --wait 2>/dev/null | grep -qE 'running|degraded'; then
            return 0
        fi
        sleep 1
    done
    echo "  WARNING: systemd did not reach running state in ${BOOT_TIMEOUT}s (may still work)"
    return 0
}

# Create dummy fips0 interface inside the container.
create_fips0() {
    local name="$1"
    docker exec "$name" ip link add fips0 type dummy 2>/dev/null
    docker exec "$name" ip link set fips0 up 2>/dev/null
}

# Copy scripts into the container and run setup.
run_setup() {
    local name="$1"
    docker cp "$SETUP_SCRIPT" "$name:/usr/local/bin/fips-dns-setup"
    docker cp "$TEARDOWN_SCRIPT" "$name:/usr/local/bin/fips-dns-teardown"
    docker exec "$name" chmod +x /usr/local/bin/fips-dns-setup /usr/local/bin/fips-dns-teardown
    # Exit code may be non-zero due to service reload failures in containers.
    # We test detection and config generation, not service operation.
    docker exec "$name" /usr/local/bin/fips-dns-setup 2>&1 || true
}

run_teardown() {
    local name="$1"
    docker exec "$name" /usr/local/bin/fips-dns-teardown 2>&1 || true
}

get_backend() {
    local name="$1"
    docker exec "$name" cat /run/fips/dns-backend 2>/dev/null || echo "(missing)"
}

file_exists() {
    local name="$1" path="$2"
    docker exec "$name" test -f "$path" 2>/dev/null
}

# ─────────────────────────────────────────────────────────────────────
# Scenarios
# ─────────────────────────────────────────────────────────────────────

test_debian12_resolved() {
    local name="fips-dns-test-deb12-resolved"
    local image="fips-dns-test:debian12-resolved"
    log "Debian 12 + systemd-resolved"

    build_image "$image" "$(cat <<'DOCKERFILE'
FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-resolved iproute2 dbus && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    systemctl enable systemd-resolved
CMD ["/lib/systemd/systemd"]
DOCKERFILE
    )" || { fail "build failed"; return; }

    start_systemd_container "$name" "$image"
    wait_for_systemd "$name"
    create_fips0 "$name"

    local output
    output=$(run_setup "$name" 2>&1)
    echo "  output: $output"

    local backend
    backend=$(get_backend "$name")
    if [ "$backend" = "resolvectl" ]; then
        pass "detected backend: resolvectl"
    else
        fail "expected resolvectl, got: $backend"
    fi

    # Teardown
    run_teardown "$name" >/dev/null 2>&1
    if ! file_exists "$name" /run/fips/dns-backend; then
        pass "teardown cleaned state file"
    else
        fail "state file still exists after teardown"
    fi

    cleanup_container "$name"
}

test_debian13_resolved() {
    local name="fips-dns-test-deb13-resolved"
    local image="fips-dns-test:debian13-resolved"
    log "Debian 13 (trixie) + systemd-resolved"

    build_image "$image" "$(cat <<'DOCKERFILE'
FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-resolved iproute2 dbus && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    systemctl enable systemd-resolved
CMD ["/lib/systemd/systemd"]
DOCKERFILE
    )" || { fail "build failed"; return; }

    start_systemd_container "$name" "$image"
    wait_for_systemd "$name"
    create_fips0 "$name"

    local output
    output=$(run_setup "$name" 2>&1)
    echo "  output: $output"

    local backend
    backend=$(get_backend "$name")
    if [ "$backend" = "resolvectl" ]; then
        pass "detected backend: resolvectl"
    else
        fail "expected resolvectl, got: $backend"
    fi

    run_teardown "$name" >/dev/null 2>&1
    if ! file_exists "$name" /run/fips/dns-backend; then
        pass "teardown cleaned state file"
    else
        fail "state file still exists after teardown"
    fi

    cleanup_container "$name"
}

test_dnsmasq() {
    local name="fips-dns-test-dnsmasq"
    local image="fips-dns-test:dnsmasq"
    log "Debian 12 + dnsmasq standalone"

    build_image "$image" "$(cat <<'DOCKERFILE'
FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd dnsmasq iproute2 dbus && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    systemctl enable dnsmasq && \
    mkdir -p /etc/dnsmasq.d
CMD ["/lib/systemd/systemd"]
DOCKERFILE
    )" || { fail "build failed"; return; }

    start_systemd_container "$name" "$image"
    wait_for_systemd "$name"
    create_fips0 "$name"

    local output
    output=$(run_setup "$name" 2>&1)
    echo "  output: $output"

    local backend
    backend=$(get_backend "$name")
    if [ "$backend" = "dnsmasq" ]; then
        pass "detected backend: dnsmasq"
    else
        fail "expected dnsmasq, got: $backend"
    fi

    # Verify config file was written
    if file_exists "$name" /etc/dnsmasq.d/fips.conf; then
        pass "dnsmasq config written"
        echo "  config: $(docker exec "$name" cat /etc/dnsmasq.d/fips.conf)"
    else
        fail "dnsmasq config not found"
    fi

    # Teardown
    run_teardown "$name" >/dev/null 2>&1
    if ! file_exists "$name" /etc/dnsmasq.d/fips.conf; then
        pass "teardown removed dnsmasq config"
    else
        fail "dnsmasq config still exists after teardown"
    fi
    if ! file_exists "$name" /run/fips/dns-backend; then
        pass "teardown cleaned state file"
    else
        fail "state file still exists after teardown"
    fi

    cleanup_container "$name"
}

test_nm_dnsmasq() {
    local name="fips-dns-test-nm-dnsmasq"
    local image="fips-dns-test:nm-dnsmasq"
    log "Fedora + NetworkManager + dnsmasq plugin"

    build_image "$image" "$(cat <<'DOCKERFILE'
FROM fedora:latest
RUN dnf install -y systemd NetworkManager dnsmasq iproute && \
    dnf clean all && \
    mkdir -p /etc/NetworkManager/conf.d /etc/NetworkManager/dnsmasq.d && \
    printf '[main]\ndns=dnsmasq\n' > /etc/NetworkManager/conf.d/dns.conf && \
    systemctl enable NetworkManager && \
    systemctl disable systemd-resolved && \
    systemctl mask systemd-resolved
CMD ["/sbin/init"]
DOCKERFILE
    )" || { fail "build failed"; return; }

    start_systemd_container "$name" "$image"
    wait_for_systemd "$name"
    create_fips0 "$name"

    local output
    output=$(run_setup "$name" 2>&1)
    echo "  output: $output"

    local backend
    backend=$(get_backend "$name")
    if [ "$backend" = "nm-dnsmasq" ]; then
        pass "detected backend: nm-dnsmasq"
    else
        fail "expected nm-dnsmasq, got: $backend"
    fi

    if file_exists "$name" /etc/NetworkManager/dnsmasq.d/fips.conf; then
        pass "NM dnsmasq config written"
        echo "  config: $(docker exec "$name" cat /etc/NetworkManager/dnsmasq.d/fips.conf)"
    else
        fail "NM dnsmasq config not found"
    fi

    # Teardown
    run_teardown "$name" >/dev/null 2>&1
    if ! file_exists "$name" /etc/NetworkManager/dnsmasq.d/fips.conf; then
        pass "teardown removed NM dnsmasq config"
    else
        fail "NM dnsmasq config still exists after teardown"
    fi
    if ! file_exists "$name" /run/fips/dns-backend; then
        pass "teardown cleaned state file"
    else
        fail "state file still exists after teardown"
    fi

    cleanup_container "$name"
}

test_no_resolver() {
    local name="fips-dns-test-none"
    local image="fips-dns-test:none"
    log "Debian 12 bare (no resolver)"

    build_image "$image" "$(cat <<'DOCKERFILE'
FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd iproute2 dbus && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
CMD ["/lib/systemd/systemd"]
DOCKERFILE
    )" || { fail "build failed"; return; }

    start_systemd_container "$name" "$image"
    wait_for_systemd "$name"
    create_fips0 "$name"

    local output
    output=$(run_setup "$name" 2>&1)
    echo "  output: $output"

    local backend
    backend=$(get_backend "$name")
    if [ "$backend" = "none" ]; then
        pass "detected backend: none (correct fallback)"
    else
        fail "expected none, got: $backend"
    fi

    # Verify it printed the warning
    if echo "$output" | grep -q "No supported DNS resolver"; then
        pass "printed manual instructions warning"
    else
        fail "missing manual instructions warning"
    fi

    run_teardown "$name" >/dev/null 2>&1
    if ! file_exists "$name" /run/fips/dns-backend; then
        pass "teardown cleaned state file"
    else
        fail "state file still exists after teardown"
    fi

    cleanup_container "$name"
}

# ─────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────

ALL_SCENARIOS="debian12-resolved debian13-resolved dnsmasq nm-dnsmasq no-resolver"

if [ $# -eq 0 ]; then
    scenarios="$ALL_SCENARIOS"
else
    scenarios="$*"
fi

for scenario in $scenarios; do
    case "$scenario" in
        debian12-resolved) test_debian12_resolved ;;
        debian13-resolved) test_debian13_resolved ;;
        dnsmasq)           test_dnsmasq ;;
        nm-dnsmasq)        test_nm_dnsmasq ;;
        no-resolver)       test_no_resolver ;;
        *)
            echo "Unknown scenario: $scenario"
            echo "Available: $ALL_SCENARIOS"
            exit 1
            ;;
    esac
    echo
done

echo "═══════════════════════════════════════"
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "═══════════════════════════════════════"

[ "$FAIL" -eq 0 ]
