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
# The end-to-end scenarios take fips and fips-gateway from the Debian
# package, which is built in the pinned floor container and so runs on
# every target distro. Each starts the daemon, configures DNS via the
# script, and confirms `dig @127.0.0.53 AAAA <npub>.fips` returns a
# non-empty AAAA answer.
#
# Usage: ./test.sh [--deb PATH] [scenario ...]
#   --deb PATH = take the binaries from this package. Without it the
#                e2e scenarios build the package through
#                packaging/debian/build-deb-container.sh.
#   No scenarios = run all scenarios.
#   Named scenarios = run only those (e.g., ./test.sh debian12-resolved e2e-debian12)
#
# Requirements: Docker able to grant SYS_ADMIN and NET_ADMIN and an
# unconfined AppArmor profile (the containers are not privileged; see
# testing/lib/systemd-container.sh). The e2e scenarios also need
# /dev/net/tun on the host (standard) and dpkg-deb to read the package.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=SCRIPTDIR/../lib/systemd-container.sh
source "$SCRIPT_DIR/../lib/systemd-container.sh"
# shellcheck source=SCRIPTDIR/../lib/image-build.sh
source "$SCRIPT_DIR/../lib/image-build.sh"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SETUP_SCRIPT="$REPO_ROOT/packaging/common/fips-dns-setup"
TEARDOWN_SCRIPT="$REPO_ROOT/packaging/common/fips-dns-teardown"
CACHE_DIR="$SCRIPT_DIR/.cache"
FIPS_BIN_CACHE="$CACHE_DIR/fips"
FIPS_GATEWAY_BIN_CACHE="$CACHE_DIR/fips-gateway"

# Set by --deb. BINARIES_READY keeps the package unpack to a single
# operation however many e2e scenarios run in one process.
SUPPLIED_DEB=""
BINARIES_READY=0

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
    local dockerfile="$*"
    retry_build "docker build -t $tag" build_inline "$tag" "$dockerfile" "$REPO_ROOT" || return
    return 0
}

# Start a systemd container in the background. Not privileged: see
# testing/lib/systemd-container.sh for the flags and why.
start_systemd_container() {
    local name="$1" image="$2"
    cleanup_container "$name"
    run_quiet "docker run $name" \
        docker run -d --name "$name" \
        --label com.corganlabs.fips-ci=1 \
        "${SYSTEMD_CAPS[@]}" \
        --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock \
        "$image" || return
    check_isolation "$name"
    return
}

# Same, but with TUN device for the e2e scenario.
#
# IPv6 forwarding is set here rather than inside the container because
# /proc/sys is read-only there. fips-gateway checks it before its DNS upstream
# check, so the gateway parity check needs it; the cost is that forwarding is
# on for every check in the scenario, including the daemon, setup and dig
# checks that run before the gateway.
start_systemd_container_with_tun() {
    local name="$1" image="$2"
    cleanup_container "$name"
    run_quiet "docker run $name (with tun)" \
        docker run -d --name "$name" \
        --label com.corganlabs.fips-ci=1 \
        "${SYSTEMD_CAPS[@]}" \
        --cgroupns=host \
        --device /dev/net/tun \
        --sysctl net.ipv6.conf.all.forwarding=1 \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock \
        "$image" || return
    check_isolation "$name"
    return
}

# Report why systemd never reached a running state. Every probe is
# best-effort and captured with its own stderr: the container may have
# exited, or never have been created at all, and the docker error text
# saying so is itself the diagnosis.
dump_systemd_state() {
    local name="$1" out
    out=$(mktemp)
    {
        echo "== docker ps -a"
        docker ps -a --filter "name=^${name}$" 2>&1
        echo "== systemctl is-system-running"
        docker exec "$name" systemctl is-system-running 2>&1
        echo "== systemctl list-units --failed"
        docker exec "$name" systemctl list-units --failed --no-pager 2>&1
        echo "== journalctl -b (last 100 lines)"
        docker exec "$name" journalctl -b --no-pager -n 100 2>&1
        echo "== docker logs (last 100 lines)"
        docker logs --tail 100 "$name" 2>&1
    } >"$out" 2>&1
    dump_output "systemd boot of $name" "$out"
    rm -f "$out"
}

# Wait for systemd to reach a bootable state inside the container.
wait_for_systemd() {
    local name="$1"
    local state
    for _i in $(seq 1 "$BOOT_TIMEOUT"); do
        # Read the state rather than piping it into grep. systemctl exits
        # non-zero for "degraded", and pipefail turns that into a failed
        # pipeline even when grep matched, so the piped form could never
        # accept a degraded boot: in a container systemd-modules-load
        # always fails, so every scenario burned the full timeout and
        # warned about a container that had in fact booted.
        state=$(docker exec "$name" systemctl is-system-running --wait 2>/dev/null)
        case "$state" in
            *running*|*degraded*) return 0 ;;
        esac
        sleep 1
    done
    echo "  WARNING: systemd did not reach running state in ${BOOT_TIMEOUT}s (may still work)"
    dump_systemd_state "$name"
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
    # Most cases test detection and config generation, not service
    # operation; the dnsmasq case also checks that dnsmasq took the config.
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

# Pass only when the file is confirmed absent after teardown. Negating
# file_exists fails open: `docker exec` exits non-zero for a container
# that is gone just as `test -f` does for a missing file, so a teardown
# that took the container down would read as clean. When the check
# cannot run, name the unreachable container rather than the file.
check_removed() {
    local name="$1" path="$2" okmsg="$3" badmsg="$4"
    if docker exec "$name" test ! -f "$path" 2>/dev/null; then
        pass "$okmsg"
    elif [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" != true ]; then
        fail "could not check $path after teardown: container $name is not running"
    else
        fail "$badmsg"
    fi
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
    check_removed "$name" "$expected_path" \
        "teardown removed config file" \
        "config file still exists after teardown"
    check_removed "$name" /run/fips/dns-backend \
        "teardown cleaned state file" \
        "state file still exists after teardown"
}

# ─────────────────────────────────────────────────────────────────────
# Take fips and fips-gateway from the Debian package rather than
# compiling them here. The package is built in the pinned floor
# container (packaging/build-floor.env), whose glibc is the lowest of
# every target distro, so its binaries run in all five e2e images. The
# suite used to compile its own copy in a Debian 12 image with whatever
# Rust was current, which was a second, uncached release build per run
# and was not the toolchain or the build that ships.
#
# With --deb the caller's package is used, which is how CI runs it:
# one package build serves this suite and the install suite. Without
# it, the package is built through the same container script the
# release uses. Done once per process however many e2e scenarios run.
# ─────────────────────────────────────────────────────────────────────

prepare_binaries() {
    if [ "$BINARIES_READY" -eq 1 ]; then
        return 0
    fi

    if ! command -v dpkg-deb >/dev/null 2>&1; then
        echo "  ERROR: dpkg-deb is required to read the package and was not found" >&2
        return 1
    fi

    mkdir -p "$CACHE_DIR"
    local deb
    if [ -n "$SUPPLIED_DEB" ]; then
        deb="$SUPPLIED_DEB"
        log "Using the supplied package $(basename "$deb")"
    else
        # The cache holds one package at a time, and the package used is
        # the one the build names on the last line of its stdout, never one
        # found by listing the directory (as in deb-install/test.sh).
        log "Building the .deb in the pinned build container (slow on first run)"
        mkdir -p "$CACHE_DIR/deb"
        rm -f "$CACHE_DIR"/deb/*.deb
        local build_out
        if ! build_out=$(bash "$REPO_ROOT/packaging/debian/build-deb-container.sh" \
                --output-dir "$CACHE_DIR/deb"); then
            echo "  ERROR: container build failed" >&2
            return 1
        fi
        deb=$(printf '%s\n' "$build_out" | tail -n 1)
        if [ -z "$deb" ] || [ ! -f "$deb" ]; then
            echo "  ERROR: the container build did not report a package path: '$deb'" >&2
            return 1
        fi
    fi

    # Drop the previous run's binaries before extracting. Without this, a
    # failed extraction below leaves them in place and the e2e scenarios
    # silently exercise the previous commit's code.
    rm -f "$FIPS_BIN_CACHE" "$FIPS_GATEWAY_BIN_CACHE"

    local tmp err
    tmp=$(mktemp -d)
    if ! err=$(dpkg-deb -x "$deb" "$tmp" 2>&1); then
        echo "  ERROR: dpkg-deb could not unpack $deb: $err" >&2
        rm -rf "$tmp"
        return 1
    fi

    local spec bin dest
    for spec in "fips:$FIPS_BIN_CACHE" "fips-gateway:$FIPS_GATEWAY_BIN_CACHE"; do
        bin="${spec%%:*}"
        dest="${spec#*:}"
        if [ ! -f "$tmp/usr/bin/$bin" ] || [ ! -s "$tmp/usr/bin/$bin" ]; then
            echo "  ERROR: $(basename "$deb") has no usable /usr/bin/$bin" >&2
            rm -rf "$tmp"
            return 1
        fi
        if ! install -m 0755 "$tmp/usr/bin/$bin" "$dest"; then
            echo "  ERROR: could not install $bin to $dest" >&2
            rm -rf "$tmp"
            return 1
        fi
    done
    rm -rf "$tmp"

    for dest in "$FIPS_BIN_CACHE" "$FIPS_GATEWAY_BIN_CACHE"; do
        log "$(basename "$dest"): $(stat -c %s "$dest") bytes, sha256 $(sha256sum "$dest" | cut -d' ' -f1)"
    done
    BINARIES_READY=1
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
    # build_inline writes this tag with no run suffix, so change the tag
    # whenever this Dockerfile changes. Otherwise a concurrent run of the
    # previous Dockerfile can overwrite the image between this run's build
    # and its docker run.
    local image="fips-dns-test:dnsmasq-fwd"
    log "Debian 12 + dnsmasq standalone"

    # procps provides /bin/kill, which dnsmasq.service's ExecReload runs, so
    # the container behaves as a real Debian host does. dnsutils provides
    # dig. 00-test.conf leaves dnsmasq with no upstream, so a .fips query it
    # has no server for is answered locally rather than sent to the host's
    # resolver.
    build_image "$image" "$(cat <<'DOCKERFILE'
FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd dnsmasq iproute2 dbus procps dnsutils && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    systemctl enable dnsmasq && \
    mkdir -p /etc/dnsmasq.d && \
    echo no-resolv > /etc/dnsmasq.d/00-test.conf
CMD ["/lib/systemd/systemd"]
DOCKERFILE
    )" || { fail "build failed"; return; }

    start_systemd_container "$name" "$image"
    wait_for_systemd "$name"
    create_fips0 "$name"

    # A stand-in for the fips DNS responder on the daemon's bind, ::1#5354,
    # answering every .fips AAAA query with a fixed address. If it does not
    # answer directly, the forwarding checks below would pass or fail for
    # the wrong reason, so the case stops here.
    docker exec "$name" dnsmasq --port=5354 --listen-address=::1 \
        --bind-interfaces --no-resolv --no-hosts --conf-file=/dev/null \
        --address=/fips/fd00::5354 --pid-file=/run/fips-standin.pid 2>&1
    if [ "$(dnsmasq_query "$name" ::1 5354)" = "fd00::5354" ]; then
        pass "stand-in .fips responder answers on ::1#5354"
    else
        fail "stand-in .fips responder does not answer on ::1#5354"
        cleanup_container "$name"
        return
    fi

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

    if grep -q 'WARNING: dnsmasq' <<<"$output"; then
        fail "setup warned about dnsmasq"
    else
        pass "setup did not warn about dnsmasq"
    fi

    # A written file proves nothing until dnsmasq has loaded it: the query
    # must come back with the stand-in's address through dnsmasq itself.
    local answer forwarded=0
    answer=$(dnsmasq_query "$name" 127.0.0.1 53)
    if [ "$answer" = "fd00::5354" ]; then
        pass "dnsmasq forwards .fips to ::1#5354 after setup"
        forwarded=1
    else
        fail "dnsmasq forwards .fips: expected fd00::5354 through 127.0.0.1, got: ${answer:-(empty)}"
        dnsmasq_dump "$name"
    fi

    # Teardown
    run_teardown "$name" >/dev/null 2>&1
    check_removed "$name" /etc/dnsmasq.d/fips.conf \
        "teardown removed dnsmasq config" \
        "dnsmasq config still exists after teardown"
    check_removed "$name" /run/fips/dns-backend \
        "teardown cleaned state file" \
        "state file still exists after teardown"

    if docker exec "$name" systemctl is-active --quiet dnsmasq.service; then
        pass "dnsmasq still active after teardown"
    else
        fail "dnsmasq not active after teardown"
    fi

    # A missing fd00::5354 shows the forward was unloaded only if the
    # forward had been loaded and the stand-in would still answer it.
    # Otherwise the check below would pass without testing anything.
    local reply
    if [ "$forwarded" -ne 1 ]; then
        skip "dnsmasq stops forwarding .fips after teardown: setup never loaded the forward"
        cleanup_container "$name"
        return
    fi
    if [ "$(dnsmasq_query "$name" ::1 5354)" != "fd00::5354" ]; then
        fail "dnsmasq stops forwarding .fips after teardown: stand-in no longer answers on ::1#5354"
        cleanup_container "$name"
        return
    fi
    # dnsmasq must answer (a status header, so a dead dnsmasq cannot pass)
    # and must no longer return the stand-in's address.
    reply=$(dnsmasq_reply "$name")
    if ! grep -q 'status:' <<<"$reply"; then
        fail "dnsmasq stops forwarding .fips after teardown: no response from 127.0.0.1"
        dnsmasq_dump "$name"
    elif grep -qF 'fd00::5354' <<<"$reply"; then
        fail "dnsmasq stops forwarding .fips after teardown: still answers fd00::5354"
        dnsmasq_dump "$name"
    else
        pass "dnsmasq stops forwarding .fips after teardown"
    fi

    cleanup_container "$name"
}

# Print the AAAA answer for probe.fips from the server at ADDR#PORT inside
# the container, or nothing. Up to three tries a second apart, because a
# dnsmasq that systemd has just restarted or that has just forked may not
# be answering on the first query. dig reports a timeout on stdout as a
# line starting ";;", which is not an answer, so it does not end the tries.
dnsmasq_query() {
    local name="$1" addr="$2" port="$3" answer=""
    for _i in 1 2 3; do
        answer=$(docker exec "$name" dig +short +time=2 +tries=1 \
            -p "$port" "@$addr" AAAA probe.fips 2>/dev/null)
        [ -n "$answer" ] && [ "${answer#;;}" = "$answer" ] && break
        sleep 1
    done
    echo "$answer"
    return 0
}

# Print dig's full reply for probe.fips from the container's dnsmasq on
# 127.0.0.1, retrying up to three times until one carries a status header.
dnsmasq_reply() {
    local name="$1" reply=""
    for _i in 1 2 3; do
        reply=$(docker exec "$name" dig +time=2 +tries=1 \
            @127.0.0.1 AAAA probe.fips 2>&1)
        grep -q 'status:' <<<"$reply" && break
        sleep 1
    done
    echo "$reply"
    return 0
}

# Dump dnsmasq's unit status and journal, so a forwarding failure shows
# whether dnsmasq rejected the config, never re-read it, or was down.
dnsmasq_dump() {
    local name="$1" out
    out=$(mktemp)
    {
        echo "== systemctl status dnsmasq"
        docker exec "$name" systemctl status dnsmasq --no-pager 2>&1
        echo "== journalctl -u dnsmasq"
        docker exec "$name" journalctl -u dnsmasq --no-pager 2>&1
    } >"$out" 2>&1
    dump_output "dnsmasq forwarding in $name" "$out"
    rm -f "$out"
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
    check_removed "$name" /etc/NetworkManager/dnsmasq.d/fips.conf \
        "teardown removed NM dnsmasq config" \
        "NM dnsmasq config still exists after teardown"
    check_removed "$name" /run/fips/dns-backend \
        "teardown cleaned state file" \
        "state file still exists after teardown"

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

    # The script ships beyond Debian, so the hint must not name one
    # distribution's package manager.
    if echo "$output" | grep -qE '(apt|apt-get|dnf|yum|zypper) install|pacman -S'; then
        fail "manual instructions name a package manager"
    else
        pass "manual instructions name no package manager"
    fi

    # Setup uses systemd-resolved only when it is active, so the hint
    # must say to start it, not only to install or enable it.
    if echo "$output" | grep -qF 'enable --now systemd-resolved'; then
        pass "manual instructions start systemd-resolved"
    else
        fail "manual instructions do not start systemd-resolved"
    fi

    run_teardown "$name" >/dev/null 2>&1
    check_removed "$name" /run/fips/dns-backend \
        "teardown cleaned state file" \
        "state file still exists after teardown"

    cleanup_container "$name"
}

# ─────────────────────────────────────────────────────────────────────
# End-to-end scenarios — run a real fips + fips-gateway, configure
# DNS via the script, dig through systemd-resolved.
#
# Parameterized across Debian 12/13 and Ubuntu 22/24/26. The fips
# and fips-gateway binaries come from the package once per run (see
# prepare_binaries) and are copied into each per-distro runtime image.
# ─────────────────────────────────────────────────────────────────────

# Print a fips-gateway log from the container with terminal colour codes
# removed, so structured fields can be matched as plain "key=value" text.
# Fails when the log cannot be read.
read_gateway_log() {
    local name="$1" log="$2"
    local text
    text=$(docker exec "$name" cat "$log" 2>/dev/null) || return 1
    printf '%s\n' "$text" | sed 's/\x1b\[[0-9;]*m//g'
    return 0
}

# The gateway on its default config binds [::1]:5365 and gets past the
# bind to the NAT step, logging one of the two NAT lines whichever way NAT
# goes in this container. Those are the lines the held-port check requires
# to be absent, so this shows the gateway still emits them in that text.
check_gateway_default_bind() {
    local name="$1"
    local log=/var/log/fips-gateway.log
    local text="" read_ok=0 listening=0 nat_step=0 _i
    for _i in $(seq 1 5); do
        if text=$(read_gateway_log "$name" "$log"); then
            read_ok=1
            if printf '%s\n' "$text" | grep -q 'Gateway DNS resolver listening.*addr=\[::1\]:5365'; then
                listening=1
            fi
            if printf '%s\n' "$text" | grep -qE 'Created nftables table|Failed to create nftables table'; then
                nat_step=1
                break
            fi
        fi
        sleep 1
    done
    if [ "$read_ok" = "0" ]; then
        fail "could not read $log, so the gateway's default bind was not observed"
        return
    fi
    if [ "$listening" = "1" ]; then
        pass "fips-gateway listens on its default [::1]:5365"
    else
        fail "fips-gateway did not log listening on [::1]:5365"
    fi
    if [ "$nat_step" = "1" ]; then
        pass "fips-gateway gets past the DNS bind to the NAT step"
    else
        fail "fips-gateway logged neither NAT-step line after the DNS bind"
    fi
    if [ "$listening" = "0" ] || [ "$nat_step" = "0" ]; then
        echo "  --- $log ---"
        printf '%s\n' "$text" | tail -20
    fi
}

# Source-port screening: a DNS listener answers a query from an ordinary
# port and ignores one from chargen's port 19, which no resolver sends
# from. dig runs as root here, so it can bind the low port. A drop must
# show as a timeout, not as a failed bind, so a dig that never sent
# cannot pass as a dropped query. The control comes first, so a listener
# that is not up fails the control rather than passing the drop.
# Args: <container> <label> <listen port on ::1> <npub>
check_source_port_screen() {
    local name="$1" who="$2" port="$3" npub="$4"
    local out
    out=$(docker exec "$name" dig -b '::1#53000' +tries=1 +time=2 @::1 -p "$port" AAAA "${npub}.fips" 2>&1)
    if echo "$out" | grep -qE '^[a-zA-Z0-9].*\sAAAA\s+[0-9a-f:]+'; then
        pass "$who: dig from source port 53000 returns AAAA"
    else
        fail "$who: dig from source port 53000 did not return AAAA"
        echo "  --- dig output ---"
        echo "$out" | tail -15
        return
    fi
    out=$(docker exec "$name" dig -b '::1#19' +tries=1 +time=2 @::1 -p "$port" AAAA "${npub}.fips" 2>&1)
    if echo "$out" | grep -qE '^[a-zA-Z0-9].*\sAAAA\s+[0-9a-f:]+'; then
        fail "$who: dig from source port 19 was answered"
        echo "  --- dig output ---"
        echo "$out" | tail -15
    elif echo "$out" | grep -qiE 'failed|bind'; then
        fail "$who: dig from source port 19 did not send (bind or send failed)"
        echo "  --- dig output ---"
        echo "$out" | tail -15
    elif echo "$out" | grep -q 'timed out'; then
        pass "$who: dig from source port 19 gets no reply"
    else
        fail "$who: dig from source port 19: neither an answer nor a timeout"
        echo "  --- dig output ---"
        echo "$out" | tail -15
    fi
}

# The gateway exits at the DNS bind when its listen port is held. The
# daemon in this container holds [::1]:5354, so a gateway configured to
# listen there must exit non-zero with the hint naming the daemon, before
# it creates the address pool or the NAT table. Any build that gets past
# the bind logs one of the pool or NAT lines below, whichever way NAT goes
# in this container, so their absence shows the exit came first.
check_gateway_exits_on_held_port() {
    local name="$1"
    local log=/var/log/fips-gateway-held.log
    local fail_before=$FAIL
    docker exec "$name" bash -c 'cat > /tmp/gateway-held.yaml <<EOF
node:
  identity:
    persistent: true
gateway:
  enabled: true
  pool: "fd01::/112"
  lan_interface: "eth0"
  dns:
    listen: "[::1]:5354"
EOF'
    docker exec "$name" bash -c "timeout 30 /usr/bin/fips-gateway --config /tmp/gateway-held.yaml >$log 2>&1; echo \"EXIT=\$?\" >>$log"

    local text
    if ! text=$(read_gateway_log "$name" "$log"); then
        fail "could not read $log, so the held-port exit was not observed"
        return
    fi
    local rc
    rc=$(printf '%s\n' "$text" | sed -n 's/^EXIT=//p' | tail -n 1)
    if [ -z "$rc" ]; then
        fail "the held-port gateway run left no exit status in $log"
    elif [ "$rc" = "0" ] || [ "$rc" = "124" ]; then
        fail "fips-gateway on a held DNS port exited $rc (expected non-zero, not the timeout)"
    else
        pass "fips-gateway on a held DNS port exits $rc"
    fi
    if printf '%s\n' "$text" | grep -qF "the fips daemon's own DNS responder listens on 5354"; then
        pass "the bind error names the daemon as the likely holder of 5354"
    else
        fail "the bind error does not carry the 5354 hint"
    fi
    local line
    for line in "Failed to create virtual IP pool" "Failed to create nftables table" "Created nftables table"; do
        if printf '%s\n' "$text" | grep -qF "$line"; then
            fail "fips-gateway reached a step after the DNS bind: '$line'"
        else
            pass "fips-gateway stopped before '$line'"
        fi
    done
    if [ "$FAIL" -gt "$fail_before" ]; then
        echo "  --- $log ---"
        printf '%s\n' "$text" | tail -20
    fi
}

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

    prepare_binaries || { fail "could not prepare the fips binaries"; return; }

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
    # A UDP transport is configured so at least one transport comes up:
    # a node with zero operational transports is Failed and refuses to
    # start. This test exercises the .fips DNS responder, not mesh
    # connectivity, so any bound transport suffices.
    docker exec "$name" bash -c 'cat > /etc/fips/fips.yaml <<EOF
node:
  identity:
    persistent: true
  log_level: debug
transports:
  udp:
    bind_addr: "0.0.0.0:2121"
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

    check_source_port_screen "$name" daemon 5354 "$npub"

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
    # reachability check; the container is started with forwarding on
    # (see start_systemd_container_with_tun) so we get to the check we
    # actually want to test.
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
    check_gateway_default_bind "$name"

    # Stop the gateway (it may have failed after the DNS bind on something
    # unrelated in this minimal container).
    docker exec "$name" pkill -f fips-gateway 2>/dev/null || true

    check_gateway_exits_on_held_port "$name"

    # Teardown via the script: backend config file must be removed
    # (path varies by backend selected above).
    local teardown_path
    if [ "$expected_backend" = "dns-delegate" ]; then
        teardown_path="/etc/systemd/dns-delegate.d/fips.dns-delegate"
    else
        teardown_path="/etc/systemd/resolved.conf.d/fips.conf"
    fi
    run_teardown "$name" >/dev/null 2>&1
    check_removed "$name" "$teardown_path" \
        "teardown removed $expected_backend config at $teardown_path" \
        "$expected_backend config still present after teardown at $teardown_path"

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

# A missing package is refused here, before any scenario runs, rather
# than surfacing as a failure of the first e2e scenario.
_args=()
while [ $# -gt 0 ]; do
    case "$1" in
        --deb)
            SUPPLIED_DEB="${2:?--deb requires a path}"
            if [ ! -f "$SUPPLIED_DEB" ]; then
                echo "--deb $SUPPLIED_DEB does not exist" >&2
                exit 2
            fi
            shift 2
            ;;
        -h|--help)
            echo "usage: test.sh [--deb PATH] [scenario ...]"
            echo "scenarios: $ALL_SCENARIOS"
            exit 0
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
        *)
            _args+=("$1")
            shift
            ;;
    esac
done
set -- ${_args[@]+"${_args[@]}"}

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
