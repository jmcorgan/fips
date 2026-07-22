#!/bin/bash
# Test fips-dns-setup across different Linux resolver backends, plus
# an end-to-end scenario that verifies a real fips answers .fips
# queries through the configured backend.
#
# Each scenario runs a systemd-based Docker container, creates a dummy
# fips0 interface (or a real one for the e2e scenario), runs the setup
# script, verifies the detected backend and generated config, runs
# teardown, and verifies cleanup.
#
# The end-to-end scenario additionally builds fips in a Debian 12
# builder image (cached between runs) so the binary is glibc-compatible
# across all target distros. It then starts the daemon, configures DNS
# via the script, and confirms `dig @127.0.0.53 AAAA <npub>.fips`
# returns a non-empty AAAA answer.
#
# Usage: ./test.sh [scenario ...]
#   No args = run all scenarios.
#   Named args = run only those (e.g., ./test.sh debian12-resolved e2e-debian12)
#
# Requirements: Docker with privileged container support. The e2e
# scenario also needs /dev/net/tun on the host (standard).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SETUP_SCRIPT="$REPO_ROOT/packaging/common/fips-dns-setup"
TEARDOWN_SCRIPT="$REPO_ROOT/packaging/common/fips-dns-teardown"
CACHE_DIR="$SCRIPT_DIR/.cache"
FIPS_BIN_CACHE="$CACHE_DIR/fips"
FIPS_GATEWAY_BIN_CACHE="$CACHE_DIR/fips-gateway"

# Timeout for systemd boot inside container
BOOT_TIMEOUT=30

# Timeout for fips to start serving DNS in the e2e scenario
DAEMON_TIMEOUT=15

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
        --label com.corganlabs.fips-ci=1 \
        --privileged \
        --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock \
        "$image" >/dev/null 2>&1
}

# Same, but with TUN device for the e2e scenario.
start_systemd_container_with_tun() {
    local name="$1" image="$2"
    cleanup_container "$name"
    docker run -d --name "$name" \
        --label com.corganlabs.fips-ci=1 \
        --privileged \
        --cgroupns=host \
        --device /dev/net/tun \
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

file_contains() {
    local name="$1" path="$2" needle="$3"
    docker exec "$name" grep -qF "$needle" "$path" 2>/dev/null
}

# Get the major systemd version inside a container.
container_systemd_version() {
    local name="$1"
    docker exec "$name" systemctl --version 2>/dev/null | head -1 \
        | grep -oE '[0-9]+' | head -1
}

# Verify the expected systemd-resolved-flavoured backend was picked
# and that its config file targets the new [::1]:5354 daemon bind.
# On systemd >= 258 the dns-delegate backend wins; otherwise
# global-drop-in. Either way the daemon target must be ::1 — that's
# the regression we're locking in.
verify_resolved_backend() {
    local name="$1"
    local ver
    ver=$(container_systemd_version "$name")
    local backend
    backend=$(get_backend "$name")

    local expected_backend expected_path
    if [ -n "$ver" ] && [ "$ver" -ge 258 ]; then
        expected_backend="dns-delegate"
        expected_path="/etc/systemd/dns-delegate.d/fips.dns-delegate"
    else
        expected_backend="global-drop-in"
        expected_path="/etc/systemd/resolved.conf.d/fips.conf"
    fi

    if [ "$backend" = "$expected_backend" ]; then
        pass "detected backend: $expected_backend (systemd $ver)"
    else
        fail "expected $expected_backend (systemd $ver), got: $backend"
    fi

    if file_exists "$name" "$expected_path"; then
        pass "config file written at $expected_path"
    else
        fail "config file missing at $expected_path"
        return
    fi

    # All systemd-flavoured backends must target [::1]:5354 to match
    # the daemon's default bind. If they don't, queries silently fail
    # — Linux IPv6 sockets bound to ::1 do not accept v4 traffic.
    if file_contains "$name" "$expected_path" "[::1]:5354"; then
        pass "config DNS target is [::1]:5354 (matches daemon default)"
    else
        fail "config DNS target wrong — must be [::1]:5354"
        echo "  contents: $(docker exec "$name" cat "$expected_path")"
    fi

    # Domain forwarding line: dns-delegate uses 'Domains=fips',
    # global-drop-in uses 'Domains=~fips' (wildcard prefix).
    local expected_domain_line
    if [ "$expected_backend" = "dns-delegate" ]; then
        expected_domain_line="Domains=fips"
    else
        expected_domain_line="Domains=~fips"
    fi
    if file_contains "$name" "$expected_path" "$expected_domain_line"; then
        pass "config Domains line correct ($expected_domain_line)"
    else
        fail "config Domains line incorrect — expected $expected_domain_line"
    fi

    run_teardown "$name" >/dev/null 2>&1
    if ! file_exists "$name" "$expected_path"; then
        pass "teardown removed config file"
    else
        fail "config file still exists after teardown"
    fi
    if ! file_exists "$name" /run/fips/dns-backend; then
        pass "teardown cleaned state file"
    else
        fail "state file still exists after teardown"
    fi
}

# ─────────────────────────────────────────────────────────────────────
# Build the fips binary once in a Debian 12 builder image so it's
# glibc-compatible with every target distro (Debian 12/13, Ubuntu 22/24).
# Cached at testing/dns-resolver/.cache/fips between runs; rebuild if
# any source file is newer than the cached binary.
# ─────────────────────────────────────────────────────────────────────

build_fips_for_e2e() {
    mkdir -p "$CACHE_DIR"

    if [ -f "$FIPS_BIN_CACHE" ] && [ -f "$FIPS_GATEWAY_BIN_CACHE" ]; then
        local newest_src
        newest_src=$(find "$REPO_ROOT/src" "$REPO_ROOT/Cargo.toml" "$REPO_ROOT/Cargo.lock" \
            -type f -printf '%T@\n' 2>/dev/null | sort -nr | head -1)
        local cached_age
        cached_age=$(stat -c '%Y' "$FIPS_BIN_CACHE" 2>/dev/null || echo 0)
        local cached_gateway_age
        cached_gateway_age=$(stat -c '%Y' "$FIPS_GATEWAY_BIN_CACHE" 2>/dev/null || echo 0)
        local oldest_cached=$((cached_age < cached_gateway_age ? cached_age : cached_gateway_age))
        if awk "BEGIN { exit !($oldest_cached >= $newest_src) }"; then
            log "Using cached fips + fips-gateway binaries at $CACHE_DIR"
            return 0
        fi
        log "Cached binaries are stale, rebuilding"
    else
        log "No cached binaries, building"
    fi

    local builder_tag="fips-dns-test:builder"
    log "Building Debian 12 builder image (this may take a few minutes on first run)"
    docker build -t "$builder_tag" -f - "$REPO_ROOT" <<'DOCKERFILE' >/dev/null
FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libdbus-1-dev curl ca-certificates \
    libclang-dev clang && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
RUN cargo build --release --bin fips --bin fips-gateway
DOCKERFILE

    if [ ! "$(docker images -q "$builder_tag" 2>/dev/null)" ]; then
        echo "  ERROR: builder image build failed"
        return 1
    fi

    log "Extracting fips + fips-gateway binaries from builder image"
    # Drop the previous run's binaries before extracting. Without this, a failed
    # extraction below leaves them in place, they satisfy the caller's -x check,
    # and the e2e scenarios silently exercise the previous commit's code.
    rm -f "$FIPS_BIN_CACHE" "$FIPS_GATEWAY_BIN_CACHE"

    local cid err
    if ! cid=$(docker create "$builder_tag" 2>&1); then
        echo "  ERROR: docker create failed: $cid"
        return 1
    fi

    local rc=0 spec bin dest
    for spec in "fips:$FIPS_BIN_CACHE" "fips-gateway:$FIPS_GATEWAY_BIN_CACHE"; do
        bin="${spec%%:*}"
        dest="${spec#*:}"
        if ! err=$(docker cp "$cid:/src/target/release/$bin" "$dest" 2>&1); then
            echo "  ERROR: extracting $bin from the builder image failed: $err"
            rc=1
        fi
    done
    docker rm "$cid" >/dev/null
    [ "$rc" -eq 0 ] || return 1

    if ! chmod +x "$FIPS_BIN_CACHE" "$FIPS_GATEWAY_BIN_CACHE"; then
        echo "  ERROR: chmod +x failed on the extracted binaries"
        return 1
    fi

    for dest in "$FIPS_BIN_CACHE" "$FIPS_GATEWAY_BIN_CACHE"; do
        if [ ! -s "$dest" ] || [ ! -x "$dest" ]; then
            echo "  ERROR: extracted binary missing, empty or not executable: $dest"
            return 1
        fi
    done

    log "Cached fips ($(stat -c %s "$FIPS_BIN_CACHE") bytes) + fips-gateway ($(stat -c %s "$FIPS_GATEWAY_BIN_CACHE") bytes)"
    return 0
}

# ─────────────────────────────────────────────────────────────────────
# Scenarios — script-behavior tests across distros (no daemon)
# ─────────────────────────────────────────────────────────────────────

test_debian12_resolved() {
    local name="fips-dns-test-deb12-resolved${FIPS_CI_NAME_SUFFIX:-}"
    local image="fips-dns-test:debian12-resolved"
    log "Debian 12 + systemd-resolved (expects global-drop-in)"

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

    verify_resolved_backend "$name"
    cleanup_container "$name"
}

test_debian13_resolved() {
    local name="fips-dns-test-deb13-resolved${FIPS_CI_NAME_SUFFIX:-}"
    local image="fips-dns-test:debian13-resolved"
    log "Debian 13 (trixie) + systemd-resolved (expects global-drop-in)"

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

    verify_resolved_backend "$name"
    cleanup_container "$name"
}

test_ubuntu22_resolved() {
    local name="fips-dns-test-u22-resolved${FIPS_CI_NAME_SUFFIX:-}"
    local image="fips-dns-test:ubuntu22-resolved"
    log "Ubuntu 22.04 + systemd-resolved (expects global-drop-in)"

    # On Ubuntu 22.04 systemd-resolved is bundled with systemd (not a
    # separate package). Just enable the service.
    build_image "$image" "$(cat <<'DOCKERFILE'
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd iproute2 dbus && \
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

    verify_resolved_backend "$name"
    cleanup_container "$name"
}

test_ubuntu24_resolved() {
    local name="fips-dns-test-u24-resolved${FIPS_CI_NAME_SUFFIX:-}"
    local image="fips-dns-test:ubuntu24-resolved"
    log "Ubuntu 24.04 + systemd-resolved (expects global-drop-in)"

    build_image "$image" "$(cat <<'DOCKERFILE'
FROM ubuntu:24.04
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

    verify_resolved_backend "$name"
    cleanup_container "$name"
}

test_ubuntu26_resolved() {
    local name="fips-dns-test-u26-resolved${FIPS_CI_NAME_SUFFIX:-}"
    local image="fips-dns-test:ubuntu26-resolved"
    log "Ubuntu 26.04 + systemd-resolved (expects global-drop-in)"

    build_image "$image" "$(cat <<'DOCKERFILE'
FROM ubuntu:26.04
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

    verify_resolved_backend "$name"
    cleanup_container "$name"
}

test_dnsmasq() {
    local name="fips-dns-test-dnsmasq${FIPS_CI_NAME_SUFFIX:-}"
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

    # Verify config targets ::1#5354 (the daemon's default IPv6
    # loopback bind). Drift from this constant would silently break
    # resolution on hosts using this backend.
    if file_contains "$name" /etc/dnsmasq.d/fips.conf "server=/fips/::1#5354"; then
        pass "dnsmasq config targets ::1#5354 (matches daemon default)"
    else
        fail "dnsmasq config target wrong — must be server=/fips/::1#5354"
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
    local name="fips-dns-test-nm-dnsmasq${FIPS_CI_NAME_SUFFIX:-}"
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

    if file_contains "$name" /etc/NetworkManager/dnsmasq.d/fips.conf "server=/fips/::1#5354"; then
        pass "NM dnsmasq config targets ::1#5354 (matches daemon default)"
    else
        fail "NM dnsmasq config target wrong — must be server=/fips/::1#5354"
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
    local name="fips-dns-test-none${FIPS_CI_NAME_SUFFIX:-}"
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
# End-to-end scenarios — run a real fips + fips-gateway, configure
# DNS via the script, dig through systemd-resolved.
#
# Parameterized across Debian 12/13 and Ubuntu 22/24/26. The fips
# and fips-gateway binaries are built once in a Debian 12 builder
# image (lowest glibc target → forward-compatible with all newer
# distros) and copied into each per-distro runtime image.
# ─────────────────────────────────────────────────────────────────────

# Args: <distro_label> <docker_base_image> <apt_packages>
# distro_label: short tag for container/image names (e.g. "debian12")
# docker_base_image: e.g. "debian:12", "ubuntu:26.04"
# apt_packages: space-separated apt-get install list. Ubuntu 22.04
#   bundles systemd-resolved into systemd, so the package list there
#   is "systemd iproute2 dbus dnsutils libdbus-1-3 procps" (no
#   separate systemd-resolved). Other distros want
#   "systemd systemd-resolved iproute2 dbus dnsutils libdbus-1-3 procps".
_run_e2e_scenario() {
    local distro_label="$1"
    local base_image="$2"
    local apt_packages="$3"

    local name="fips-dns-test-e2e-${distro_label}${FIPS_CI_NAME_SUFFIX:-}"
    local image="fips-dns-test:e2e-${distro_label}"
    log "End-to-end: ${base_image} + systemd-resolved + real fips + fips-gateway + dig"

    build_fips_for_e2e || { fail "fips build failed"; return; }

    if [ ! -x "$FIPS_BIN_CACHE" ] || [ ! -x "$FIPS_GATEWAY_BIN_CACHE" ]; then
        fail "binaries not available at $CACHE_DIR"
        return
    fi

    log "Building e2e runtime image (${base_image})"
    cp "$FIPS_BIN_CACHE" "$CACHE_DIR/fips-bin-for-image"
    cp "$FIPS_GATEWAY_BIN_CACHE" "$CACHE_DIR/fips-gateway-bin-for-image"
    build_image "$image" "$(cat <<DOCKERFILE
FROM ${base_image}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \\
    ${apt_packages} && \\
    apt-get clean && rm -rf /var/lib/apt/lists/* && \\
    systemctl enable systemd-resolved && \\
    mkdir -p /etc/fips
COPY testing/dns-resolver/.cache/fips-bin-for-image /usr/bin/fips
COPY testing/dns-resolver/.cache/fips-gateway-bin-for-image /usr/bin/fips-gateway
RUN chmod +x /usr/bin/fips /usr/bin/fips-gateway
CMD ["/lib/systemd/systemd"]
DOCKERFILE
    )" || { fail "runtime build failed"; rm -f "$CACHE_DIR/fips-bin-for-image" "$CACHE_DIR/fips-gateway-bin-for-image"; return; }
    rm -f "$CACHE_DIR/fips-bin-for-image" "$CACHE_DIR/fips-gateway-bin-for-image"

    start_systemd_container_with_tun "$name" "$image"
    wait_for_systemd "$name"

    # Write a minimal fips.yaml that exercises the new defaults.
    # tun.enabled: true so the daemon creates fips0 itself; identity
    # persistent so /etc/fips/fips.pub gives us a stable npub to query.
    docker exec "$name" bash -c 'cat > /etc/fips/fips.yaml <<EOF
node:
  identity:
    persistent: true
  log_level: debug
tun:
  enabled: true
  name: fips0
dns:
  enabled: true
  port: 5354
EOF'

    # Start fips in the background.
    log "Starting fips in container"
    docker exec -d "$name" bash -c '/usr/bin/fips --config /etc/fips/fips.yaml >/var/log/fips.log 2>&1'

    # Wait for the DNS responder to bind.
    local ready=0
    for _i in $(seq 1 "$DAEMON_TIMEOUT"); do
        if docker exec "$name" ss -uln 2>/dev/null | grep -q ':5354'; then
            ready=1
            break
        fi
        sleep 1
    done
    if [ "$ready" = "1" ]; then
        pass "fips DNS listener up on port 5354"
    else
        fail "fips DNS listener did not appear within ${DAEMON_TIMEOUT}s"
        echo "  --- fips log ---"
        docker exec "$name" tail -30 /var/log/fips.log 2>&1 || true
        echo "  --- ss -uln ---"
        docker exec "$name" ss -ulnp 2>&1 || true
        cleanup_container "$name"
        return
    fi

    # Confirm the daemon picked up the new ::1 default bind. Strip
    # ANSI color codes from the log line before matching since the
    # tracing-subscriber default formatter wraps fields in escape codes.
    local bind_line
    bind_line=$(docker exec "$name" grep -m1 "DNS responder started" /var/log/fips.log 2>/dev/null \
                | sed -r 's/\x1b\[[0-9;]*m//g' || echo "")
    echo "  daemon log: $bind_line"
    if echo "$bind_line" | grep -qE "bind=\[?::1\]?:5354"; then
        pass "daemon bound on [::1]:5354 (new default)"
    else
        fail "daemon bind line missing or wrong: $bind_line"
    fi

    # Run setup.
    local output
    output=$(run_setup "$name" 2>&1)
    echo "  setup output: $output"

    # Pick expected backend based on systemd version: dns-delegate
    # on >= 258, global-drop-in otherwise. Either way the backend
    # must target [::1]:5354 for the daemon to receive queries.
    local ver
    ver=$(container_systemd_version "$name")
    local expected_backend
    if [ -n "$ver" ] && [ "$ver" -ge 258 ]; then
        expected_backend="dns-delegate"
    else
        expected_backend="global-drop-in"
    fi
    local backend
    backend=$(get_backend "$name")
    if [ "$backend" = "$expected_backend" ]; then
        pass "setup picked $expected_backend backend (systemd $ver)"
    else
        fail "expected $expected_backend (systemd $ver), got: $backend"
    fi

    # Wait briefly for systemd-resolved to apply the new config.
    sleep 2

    # Pull the daemon's npub from the persistent identity file.
    local npub
    npub=$(docker exec "$name" cat /etc/fips/fips.pub 2>/dev/null | tr -d '[:space:]')
    if [ -z "$npub" ]; then
        fail "no /etc/fips/fips.pub after daemon start"
        echo "  --- /etc/fips ---"
        docker exec "$name" ls -la /etc/fips/ 2>&1 || true
        cleanup_container "$name"
        return
    fi
    echo "  daemon npub: $npub"

    # Direct dig to the daemon's loopback bind — must succeed.
    local direct_output
    direct_output=$(docker exec "$name" dig +tries=1 +time=3 @::1 -p 5354 AAAA "${npub}.fips" 2>&1)
    if echo "$direct_output" | grep -qE '^[a-zA-Z0-9].*\sAAAA\s+[0-9a-f:]+'; then
        pass "direct dig @::1#5354 returns AAAA"
    else
        fail "direct dig @::1#5354 did not return AAAA"
        echo "  --- dig output ---"
        echo "$direct_output" | tail -15
    fi

    # End-to-end via systemd-resolved stub.
    local stub_output
    stub_output=$(docker exec "$name" dig +tries=1 +time=3 @127.0.0.53 AAAA "${npub}.fips" 2>&1)
    if echo "$stub_output" | grep -qE '^[a-zA-Z0-9].*\sAAAA\s+[0-9a-f:]+'; then
        pass "end-to-end dig @127.0.0.53 returns AAAA (the bug fix)"
    else
        fail "end-to-end dig @127.0.0.53 did not return AAAA"
        echo "  --- dig output ---"
        echo "$stub_output" | tail -15
        echo "  --- resolved status ---"
        docker exec "$name" resolvectl status 2>&1 | tail -20 || true
        echo "  --- daemon log tail ---"
        docker exec "$name" tail -30 /var/log/fips.log 2>&1 || true
    fi

    # Verify fips-gateway's DNS upstream reachability check passes
    # against the daemon's new ::1 default. This locks the regression
    # class where the gateway default (was 127.0.0.1:5354) and the
    # daemon default (now [::1]:5354) drift apart on Linux IPv6
    # sockets that don't accept v4-mapped traffic.
    docker exec "$name" bash -c 'cat > /tmp/gateway-test.yaml <<EOF
node:
  identity:
    persistent: true
gateway:
  enabled: true
  pool: "fd01::/112"
  lan_interface: "eth0"
EOF'
    # fips-gateway checks IPv6 forwarding before the DNS upstream
    # reachability check; enable forwarding so we get to the check we
    # actually want to test.
    docker exec "$name" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
    docker exec -d "$name" bash -c '/usr/bin/fips-gateway --config /tmp/gateway-test.yaml >/var/log/fips-gateway.log 2>&1 || true'

    # Wait briefly for the upstream-reachability log line to appear
    # one way or the other.
    local gw_ok=0
    for _i in $(seq 1 5); do
        if docker exec "$name" grep -q "DNS upstream is reachable" /var/log/fips-gateway.log 2>/dev/null; then
            gw_ok=1
            break
        fi
        if docker exec "$name" grep -qE "DNS upstream did not respond|Failed to send DNS probe|DNS upstream recv failed" /var/log/fips-gateway.log 2>/dev/null; then
            break
        fi
        sleep 1
    done
    if [ "$gw_ok" = "1" ]; then
        pass "fips-gateway reaches DNS upstream at [::1]:5354 (gateway/daemon default parity)"
    else
        fail "fips-gateway DNS upstream check failed — defaults drifted?"
        echo "  --- fips-gateway log ---"
        docker exec "$name" tail -20 /var/log/fips-gateway.log 2>&1 || true
    fi
    # Stop the gateway (it will likely have failed past the upstream
    # check on something unrelated in this minimal container — we only
    # care that the upstream reachability step succeeded).
    docker exec "$name" pkill -f fips-gateway 2>/dev/null || true

    # Teardown via the script: backend config file must be removed
    # (path varies by backend selected above).
    local teardown_path
    if [ "$expected_backend" = "dns-delegate" ]; then
        teardown_path="/etc/systemd/dns-delegate.d/fips.dns-delegate"
    else
        teardown_path="/etc/systemd/resolved.conf.d/fips.conf"
    fi
    run_teardown "$name" >/dev/null 2>&1
    if ! file_exists "$name" "$teardown_path"; then
        pass "teardown removed $expected_backend config at $teardown_path"
    else
        fail "$expected_backend config still present after teardown at $teardown_path"
    fi

    cleanup_container "$name"
}

# Per-distro wrappers
_pkgs_with_resolved="systemd systemd-resolved iproute2 dbus dnsutils libdbus-1-3 procps"
_pkgs_ubuntu22="systemd iproute2 dbus dnsutils libdbus-1-3 procps"

test_e2e_debian12() { _run_e2e_scenario debian12 debian:12       "$_pkgs_with_resolved"; }
test_e2e_debian13() { _run_e2e_scenario debian13 debian:trixie   "$_pkgs_with_resolved"; }
test_e2e_ubuntu22() { _run_e2e_scenario ubuntu22 ubuntu:22.04    "$_pkgs_ubuntu22"; }
test_e2e_ubuntu24() { _run_e2e_scenario ubuntu24 ubuntu:24.04    "$_pkgs_with_resolved"; }
test_e2e_ubuntu26() { _run_e2e_scenario ubuntu26 ubuntu:26.04    "$_pkgs_with_resolved"; }

# ─────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────

ALL_SCENARIOS="debian12-resolved debian13-resolved ubuntu22-resolved ubuntu24-resolved ubuntu26-resolved dnsmasq nm-dnsmasq no-resolver e2e-debian12 e2e-debian13 e2e-ubuntu22 e2e-ubuntu24 e2e-ubuntu26"

if [ $# -eq 0 ]; then
    scenarios="$ALL_SCENARIOS"
else
    scenarios="$*"
fi

for scenario in $scenarios; do
    case "$scenario" in
        debian12-resolved) test_debian12_resolved ;;
        debian13-resolved) test_debian13_resolved ;;
        ubuntu22-resolved) test_ubuntu22_resolved ;;
        ubuntu24-resolved) test_ubuntu24_resolved ;;
        ubuntu26-resolved) test_ubuntu26_resolved ;;
        dnsmasq)           test_dnsmasq ;;
        nm-dnsmasq)        test_nm_dnsmasq ;;
        no-resolver)       test_no_resolver ;;
        e2e-debian12)      test_e2e_debian12 ;;
        e2e-debian13)      test_e2e_debian13 ;;
        e2e-ubuntu22)      test_e2e_ubuntu22 ;;
        e2e-ubuntu24)      test_e2e_ubuntu24 ;;
        e2e-ubuntu26)      test_e2e_ubuntu26 ;;
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
