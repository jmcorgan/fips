#!/bin/bash
# Test the fips Debian package install path across target distros.
#
# Each scenario builds (or reuses) the .deb in a Debian 12 cargo-deb
# builder image (cached), boots a privileged systemd container with
# TUN access for the target distro, installs the .deb via `apt
# install ./fips_*.deb`, waits for fips.service + fips-dns.service
# to come up, and verifies that `dig @127.0.0.53 AAAA <npub>.fips`
# returns a non-empty AAAA answer through the resolver backend that
# fips-dns-setup configured. Then exercises fips-gateway against the
# same daemon to verify the gateway/daemon default-pairing.
#
# This is the most thorough test surface — it exercises:
#   - cargo deb packaging (binary stripping, dependency declaration)
#   - dpkg conffile placement (/etc/fips/fips.yaml)
#   - postinst maintainer scripts (systemd unit enablement,
#     fips-dns.service running fips-dns-setup)
#   - The fips, fips-dns, and (optionally) fips-gateway systemd units
#   - End-to-end .fips resolution as a real user would experience it
#
# Usage: ./test.sh [scenario ...]
#   No args = run all scenarios.
#   Named args = run only those (e.g., ./test.sh ubuntu26 debian12)
#
# Requirements: Docker with privileged container support, /dev/net/tun
# on the host (standard).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CACHE_DIR="$SCRIPT_DIR/.cache"
DEB_CACHE_DIR="$CACHE_DIR/deb"

# Timeouts
BOOT_TIMEOUT=30
SERVICE_TIMEOUT=20
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

build_image() {
    local tag="$1"
    shift
    echo "$@" | docker build -t "$tag" -f - "$REPO_ROOT" >/dev/null 2>&1
}

start_systemd_container_with_tun() {
    local name="$1" image="$2"
    cleanup_container "$name"
    docker run -d --name "$name" \
        --privileged \
        --cgroupns=host \
        --device /dev/net/tun \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock \
        "$image" >/dev/null 2>&1
}

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

wait_for_service_active() {
    local name="$1" service="$2" timeout="${3:-$SERVICE_TIMEOUT}"
    for _i in $(seq 1 "$timeout"); do
        if docker exec "$name" systemctl is-active --quiet "$service" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

container_systemd_version() {
    local name="$1"
    docker exec "$name" systemctl --version 2>/dev/null | head -1 \
        | grep -oE '[0-9]+' | head -1
}

# ─────────────────────────────────────────────────────────────────────
# Build the .deb once in a Debian 12 cargo-deb builder image (cached
# between runs). Output cached at testing/deb-install/.cache/deb/.
# Rebuilt if any source/Cargo/packaging file is newer than the cached
# .deb, or if the .deb is missing.
# ─────────────────────────────────────────────────────────────────────

build_deb() {
    mkdir -p "$DEB_CACHE_DIR"

    local cached_deb
    cached_deb=$(ls "$DEB_CACHE_DIR"/fips_*_amd64.deb 2>/dev/null | head -1)

    if [ -n "$cached_deb" ] && [ -f "$cached_deb" ]; then
        local newest_src
        newest_src=$(find "$REPO_ROOT/src" "$REPO_ROOT/Cargo.toml" \
            "$REPO_ROOT/Cargo.lock" "$REPO_ROOT/packaging" \
            -type f -printf '%T@\n' 2>/dev/null | sort -nr | head -1)
        local cached_age
        cached_age=$(stat -c '%Y' "$cached_deb" 2>/dev/null || echo 0)
        if awk "BEGIN { exit !($cached_age >= $newest_src) }"; then
            log "Using cached .deb at $cached_deb"
            return 0
        fi
        log "Cached .deb is stale, rebuilding"
    else
        log "No cached .deb, building"
    fi

    local builder_tag="fips-deb-test:builder"
    log "Building Debian 12 cargo-deb builder image (slow on first run)"
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
RUN cargo install cargo-deb --version 3.6.3 --locked
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs LICENSE README.md ./
COPY src ./src
COPY packaging ./packaging
RUN cargo build --release && cargo deb --no-build
DOCKERFILE

    if [ ! "$(docker images -q "$builder_tag" 2>/dev/null)" ]; then
        echo "  ERROR: builder image build failed"
        return 1
    fi

    log "Extracting .deb from builder image"
    rm -f "$DEB_CACHE_DIR"/*.deb
    local cid
    cid=$(docker create "$builder_tag")
    docker cp "$cid:/src/target/debian/." "$DEB_CACHE_DIR/" >/dev/null 2>&1
    docker rm "$cid" >/dev/null
    # Cargo-deb leaves intermediate artifacts; keep just the .deb.
    find "$DEB_CACHE_DIR" -mindepth 1 -not -name 'fips_*_amd64.deb' -delete 2>/dev/null || true
    cached_deb=$(ls "$DEB_CACHE_DIR"/fips_*_amd64.deb 2>/dev/null | head -1)
    if [ -n "$cached_deb" ]; then
        log "Cached at $cached_deb ($(stat -c %s "$cached_deb") bytes)"
    else
        echo "  ERROR: no .deb produced by cargo-deb"
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────
# Scenario runner
#
# Args: <distro_label> <docker_base_image>
# distro_label: short tag for container/image names (e.g. "debian12")
# docker_base_image: e.g. "debian:12", "ubuntu:26.04"
# ─────────────────────────────────────────────────────────────────────

_run_deb_install_scenario() {
    local distro_label="$1"
    local base_image="$2"

    local name="fips-deb-test-${distro_label}"
    local image="fips-deb-test:${distro_label}"
    log ".deb install: ${base_image}"

    build_deb || { fail ".deb build failed"; return; }

    local cached_deb
    cached_deb=$(ls "$DEB_CACHE_DIR"/fips_*_amd64.deb 2>/dev/null | head -1)
    if [ -z "$cached_deb" ] || [ ! -f "$cached_deb" ]; then
        fail "no .deb available at $DEB_CACHE_DIR"
        return
    fi
    local deb_basename
    deb_basename=$(basename "$cached_deb")

    # Ubuntu 22.04 bundles systemd-resolved into systemd; other
    # distros require it as a separate package. Compose the apt
    # package list accordingly.
    local apt_packages="systemd iproute2 dbus dnsutils procps"
    if [ "$base_image" != "ubuntu:22.04" ]; then
        apt_packages="systemd systemd-resolved iproute2 dbus dnsutils procps"
    fi

    log "Building ${base_image} runtime image"
    cp "$cached_deb" "$CACHE_DIR/deb-for-image"
    # Place the .deb under /opt — systemd remounts /tmp during boot
    # (PrivateTmp / tmpfs) which would wipe a .deb COPY'd to /tmp.
    build_image "$image" "$(cat <<DOCKERFILE
FROM ${base_image}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \\
    ${apt_packages} && \\
    apt-get clean && rm -rf /var/lib/apt/lists/* && \\
    systemctl enable systemd-resolved && \\
    mkdir -p /opt/fips-deb
COPY testing/deb-install/.cache/deb-for-image /opt/fips-deb/${deb_basename}
CMD ["/lib/systemd/systemd"]
DOCKERFILE
    )" || { fail "runtime build failed"; rm -f "$CACHE_DIR/deb-for-image"; return; }
    rm -f "$CACHE_DIR/deb-for-image"

    start_systemd_container_with_tun "$name" "$image"
    wait_for_systemd "$name"

    # Install the .deb. apt handles dependencies (libc6, systemd,
    # libdbus-1-3) and runs the maintainer scripts (postinst →
    # systemctl enable fips.service; fips-dns.service starts and
    # runs fips-dns-setup).
    log "Installing .deb (apt install /opt/fips-deb/${deb_basename})"
    local install_output
    install_output=$(docker exec "$name" bash -c "
        apt-get update >/dev/null 2>&1
        cd /opt/fips-deb && apt-get install -y --no-install-recommends ./${deb_basename} 2>&1
    ") || true
    if echo "$install_output" | grep -qE "^E:|errors? were encountered"; then
        fail "apt install reported errors"
        echo "$install_output" | tail -20
        cleanup_container "$name"
        return
    else
        pass "apt install completed"
    fi

    # Verify shipped files landed where expected.
    if docker exec "$name" test -x /usr/bin/fips; then
        pass "/usr/bin/fips installed"
    else
        fail "/usr/bin/fips missing"
    fi
    if docker exec "$name" test -x /usr/bin/fips-gateway; then
        pass "/usr/bin/fips-gateway installed"
    else
        fail "/usr/bin/fips-gateway missing"
    fi
    if docker exec "$name" test -f /etc/fips/fips.yaml; then
        pass "/etc/fips/fips.yaml conffile installed"
    else
        fail "/etc/fips/fips.yaml conffile missing"
    fi

    # Verify fips.service is enabled (postinst enables but does not
    # start on fresh install — standard Debian convention).
    if docker exec "$name" systemctl is-enabled --quiet fips.service; then
        pass "fips.service enabled by postinst"
    else
        fail "fips.service not enabled after install"
    fi
    if docker exec "$name" systemctl is-enabled --quiet fips-dns.service; then
        pass "fips-dns.service enabled by postinst"
    else
        fail "fips-dns.service not enabled after install"
    fi

    # Start the services as a simulated boot. (On a real system,
    # they'd come up on next reboot.)
    docker exec "$name" systemctl start fips.service 2>&1 || true
    docker exec "$name" systemctl start fips-dns.service 2>&1 || true

    if wait_for_service_active "$name" fips.service; then
        pass "fips.service active after explicit start"
    else
        fail "fips.service did not become active in ${SERVICE_TIMEOUT}s"
        echo "  --- fips.service status ---"
        docker exec "$name" systemctl status fips.service --no-pager 2>&1 | tail -20
        echo "  --- fips.service journal ---"
        docker exec "$name" journalctl -u fips.service --no-pager 2>&1 | tail -20
        cleanup_container "$name"
        return
    fi

    # Wait for the DNS responder to bind on the daemon's [::1]:5354.
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
        cleanup_container "$name"
        return
    fi

    # Wait for fips-dns.service. This should have run fips-dns-setup
    # which configures the resolver backend and writes
    # /run/fips/dns-backend.
    sleep 2
    local backend
    backend=$(docker exec "$name" cat /run/fips/dns-backend 2>/dev/null || echo "(missing)")
    local ver
    ver=$(container_systemd_version "$name")
    local expected_backend
    if [ -n "$ver" ] && [ "$ver" -ge 258 ]; then
        expected_backend="dns-delegate"
    else
        expected_backend="global-drop-in"
    fi
    if [ "$backend" = "$expected_backend" ]; then
        pass "fips-dns.service picked $expected_backend backend (systemd $ver)"
    else
        fail "expected $expected_backend (systemd $ver), got: $backend"
        echo "  --- fips-dns.service journal ---"
        docker exec "$name" journalctl -u fips-dns.service --no-pager 2>&1 | tail -20
    fi

    # Get the daemon's npub via fipsctl. Works for both ephemeral
    # and persistent identity (no need to override the conffile).
    local npub
    npub=$(docker exec "$name" fipsctl show status 2>/dev/null \
        | grep -oE 'npub1[a-z0-9]+' | head -1)
    if [ -z "$npub" ]; then
        fail "could not read npub from fipsctl show status"
        cleanup_container "$name"
        return
    fi
    echo "  daemon npub: $npub"

    # The actual end-to-end test: a stock dpkg-installed deployment
    # must successfully resolve a .fips query through the system
    # resolver. This covers the full path: maintainer scripts ran,
    # service started, DNS responder bound, resolver backend
    # configured, query routed and answered.
    sleep 1
    local stub_output
    stub_output=$(docker exec "$name" dig +tries=1 +time=3 @127.0.0.53 AAAA "${npub}.fips" 2>&1)
    if echo "$stub_output" | grep -qE '^[a-zA-Z0-9].*\sAAAA\s+[0-9a-f:]+'; then
        pass "end-to-end dig @127.0.0.53 returns AAAA on stock .deb install"
    else
        fail "end-to-end dig @127.0.0.53 did not return AAAA"
        echo "  --- dig output ---"
        echo "$stub_output" | tail -15
        echo "  --- resolved status ---"
        docker exec "$name" resolvectl status 2>&1 | tail -25 || true
        echo "  --- fips journal ---"
        docker exec "$name" journalctl -u fips.service --no-pager 2>&1 | tail -10
    fi

    # Verify fips-gateway can run against the installed daemon. Tests
    # the gateway/daemon default-pairing on a real .deb install (no
    # custom config). Requires enabling the unit (it's not in the
    # default preset) and ipv6 forwarding (gateway checks before
    # the DNS upstream check).
    docker exec "$name" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
    docker exec "$name" bash -c '
        systemctl unmask fips-gateway.service 2>/dev/null
        # Patch in a minimal gateway config since the shipped fips.yaml
        # has gateway disabled by default.
        cp /etc/fips/fips.yaml /etc/fips/fips.yaml.orig
        cat >> /etc/fips/fips.yaml <<EOF
gateway:
  enabled: true
  pool: "fd01::/112"
  lan_interface: "eth0"
EOF
        systemctl restart fips.service
    ' >/dev/null 2>&1

    sleep 3
    if wait_for_service_active "$name" fips.service 5; then
        :
    else
        fail "fips.service did not stay up after gateway-enable restart"
    fi

    docker exec "$name" systemctl start fips-gateway.service >/dev/null 2>&1 || true
    sleep 3
    if docker exec "$name" journalctl -u fips-gateway.service --no-pager 2>/dev/null \
            | grep -q "DNS upstream is reachable"; then
        pass "fips-gateway reaches DNS upstream at [::1]:5354 via .deb install"
    else
        fail "fips-gateway DNS upstream check failed against installed daemon"
        echo "  --- fips-gateway journal ---"
        docker exec "$name" journalctl -u fips-gateway.service --no-pager 2>&1 | tail -15
    fi

    cleanup_container "$name"
}

# Per-distro wrappers
test_debian12() { _run_deb_install_scenario debian12 debian:12;     }
test_debian13() { _run_deb_install_scenario debian13 debian:trixie; }
test_ubuntu22() { _run_deb_install_scenario ubuntu22 ubuntu:22.04;  }
test_ubuntu24() { _run_deb_install_scenario ubuntu24 ubuntu:24.04;  }
test_ubuntu26() { _run_deb_install_scenario ubuntu26 ubuntu:26.04;  }

# ─────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────

ALL_SCENARIOS="debian12 debian13 ubuntu22 ubuntu24 ubuntu26"

if [ $# -eq 0 ]; then
    scenarios="$ALL_SCENARIOS"
else
    scenarios="$*"
fi

for scenario in $scenarios; do
    case "$scenario" in
        debian12) test_debian12 ;;
        debian13) test_debian13 ;;
        ubuntu22) test_ubuntu22 ;;
        ubuntu24) test_ubuntu24 ;;
        ubuntu26) test_ubuntu26 ;;
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
