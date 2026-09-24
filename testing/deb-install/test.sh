#!/bin/bash
# Test the fips Debian package install path across target distros.
#
# Each scenario takes the .deb from --deb, or builds (or reuses) it
# through packaging/debian/build-deb-container.sh, boots a systemd
# container with TUN access for the target distro, installs the .deb
# via `apt install ./fips_*.deb`, waits for fips.service + fips-dns.service
# to come up, and verifies that `dig @127.0.0.53 AAAA <npub>.fips`
# returns a non-empty AAAA answer through the resolver backend that
# fips-dns-setup configured. Then exercises fips-gateway against the
# same daemon to verify the gateway/daemon default-pairing. Finally it
# purges the package with the DNS routing file planted and fips-dns
# stopped, and checks the file is removed and systemd-resolved restarted.
#
# This is the most thorough test surface — it exercises:
#   - cargo deb packaging (binary stripping, dependency declaration)
#   - dpkg conffile placement (/etc/fips/fips.yaml)
#   - postinst maintainer scripts (systemd unit enablement,
#     fips-dns.service running fips-dns-setup)
#   - postrm purge (removing the DNS routing fips-dns-setup wrote)
#   - The fips, fips-dns, and (optionally) fips-gateway systemd units
#   - End-to-end .fips resolution as a real user would experience it
#
# Usage: ./test.sh [scenario ...]
#   No args = run all scenarios.
#   Named args = run only those (e.g., ./test.sh ubuntu26 debian12)
#
# Requirements: Docker able to grant SYS_ADMIN and NET_ADMIN and an
# unconfined AppArmor profile (the containers are not privileged; see
# testing/lib/systemd-container.sh), /dev/net/tun on the host (standard).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=SCRIPTDIR/../lib/systemd-container.sh
source "$SCRIPT_DIR/../lib/systemd-container.sh"
# shellcheck source=SCRIPTDIR/../lib/image-build.sh
source "$SCRIPT_DIR/../lib/image-build.sh"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CACHE_DIR="$SCRIPT_DIR/.cache"
DEB_CACHE_DIR="$CACHE_DIR/deb"

# Timeouts. Each wait loop below exits as soon as its condition is met.
BOOT_TIMEOUT=30
SERVICE_TIMEOUT=20
DAEMON_TIMEOUT=15
# Bounds on a single `systemctl start`, which is not a wait loop and needs its
# own limit. See start_unit() for why an unbounded one can never return.
UNIT_START_TIMEOUT=30
# fips-gateway.service's ExecStartPre waits up to 30s for fips0 to appear, by
# design, so its start legitimately takes longer than any other.
GATEWAY_START_TIMEOUT=60
# The gateway-enable block restarts fips.service inside the container. Above
# systemd's default TimeoutStopSec of 90s, so a wedged stop trips this rather
# than this cutting a healthy stop short.
CONFIG_RESTART_TIMEOUT=120

PASS=0
FAIL=0
SKIP=0

# Set by --deb. DEB_PREPARED keeps the copy-into-cache to a single operation
# however many scenarios run in one process.
SUPPLIED_DEB=""
DEB_PREPARED=0
# The package the scenarios install, set by build_deb() on every path that
# succeeds. Scenarios use it rather than listing the cache directory, so which
# file they install never depends on what else happens to be in there.
DEB_PATH=""

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

# Start the scenario's systemd container. Not privileged: see
# testing/lib/systemd-container.sh for the flags and why.
#
# IPv6 forwarding is set here rather than inside the container because
# /proc/sys is read-only there. fips-gateway checks it before its DNS upstream
# check, so the gateway block needs it; the cost is that forwarding is on for
# every check in the scenario, including the install and resolver checks that
# run before the gateway block.
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

wait_for_systemd() {
    local name="$1" state
    for _i in $(seq 1 "$BOOT_TIMEOUT"); do
        # `is-system-running` exits non-zero for `degraded` (a unit failed to
        # start -- e.g. systemd-modules-load, which cannot load kernel modules
        # inside a container -- even though the system did finish booting). This
        # script runs `set -o pipefail`, so a piped `grep` would inherit that
        # non-zero exit and reject an acceptable state, which timed out the
        # newest distros (they reach `degraded`, older ones reach `running`).
        # Capture the state string and test it directly instead of the pipe.
        state=$(docker exec "$name" systemctl is-system-running --wait 2>/dev/null || true)
        case "$state" in
            running | degraded) return 0 ;;
        esac
        sleep 1
    done
    # A boot that never reached `running` or `degraded` is not a warning: every
    # check after this point reads a system that may not have started its units,
    # and returning 0 here made the timeout indistinguishable from a clean boot.
    echo "  ERROR: systemd did not reach running state in ${BOOT_TIMEOUT}s" >&2
    return 1
}

# Start a unit without waiting for its start job to finish.
#
# Start a unit and wait for its start job, under a bound.
#
# Blocking is the right default and the call returning is what synchronises the
# checks after it: `fips-gateway.service` in particular has an ExecStartPre that
# waits up to 30s for fips0, so a caller that does not wait races it. What the
# old code lacked was the bound, not the wait.
start_unit() {
    local name="$1" unit="$2" limit="${3:-$UNIT_START_TIMEOUT}"
    timeout "$limit" docker exec "$name" systemctl start "$unit" 2>&1
}

# Queue a unit's start job and return without waiting for it.
#
# For `fips-dns.service` only, and the reason is specific rather than general.
# It is Type=oneshot with Requires=fips.service, so its start job waits on a
# dependency that a broken daemon never satisfies: fips.service restarts every
# 5s for ever and the oneshot's job is never dispatched. `systemctl start` then
# never returns. That is the whole class of fault this suite exists to find, and
# the suite answered it by hanging -- no FAIL, no Results line, no exit status,
# observed at 21 minutes against a package whose binaries could not load.
#
# Queueing moves the verdict onto the wait_for_service_active call that follows,
# which carries a timeout and dumps the journal when it fails. RemainAfterExit=yes
# on that unit makes `is-active` a correct readiness test for a oneshot.
#
# This bounds these call sites, not every `docker exec` in the file. The backstop
# for the rest is the caller's own limit: ci-local.sh bounds the whole suite, and
# the GitHub leg carries timeout-minutes.
start_unit_queued() {
    local name="$1" unit="$2"
    timeout "$UNIT_START_TIMEOUT" docker exec "$name" systemctl start --no-block "$unit" 2>&1
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

    # A supplied package wins outright and bypasses the staleness check below.
    # That check compares mtimes, so a cached package could otherwise beat the
    # artifact the caller explicitly handed over, which is exactly the silent
    # substitution this suite exists to stop making.
    if [ -n "$SUPPLIED_DEB" ]; then
        if [ "$DEB_PREPARED" -eq 1 ]; then
            return 0
        fi
        if [ ! -f "$SUPPLIED_DEB" ]; then
            echo "  ERROR: --deb $SUPPLIED_DEB does not exist" >&2
            return 1
        fi
        rm -f "$DEB_CACHE_DIR"/*.deb
        cp "$SUPPLIED_DEB" "$DEB_CACHE_DIR/"
        DEB_PATH="$DEB_CACHE_DIR/$(basename "$SUPPLIED_DEB")"
        DEB_PREPARED=1
        log "Installing the supplied package $(basename "$SUPPLIED_DEB")"
        return 0
    fi

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
            DEB_PATH="$cached_deb"
            log "Using cached .deb at $cached_deb"
            return 0
        fi
        log "Cached .deb is stale, rebuilding"
    else
        log "No cached .deb, building"
    fi

    # Build through the shared container script rather than a builder defined
    # here. This suite used to compile its own package inside a Debian 12 image
    # while the release compiled on the newest GitHub runner, so the package it
    # tested had a lower glibc floor than the package users received and could
    # not exhibit a defect that only the release environment produced. It stayed
    # green through five releases that could not start on two of the five
    # distributions in its own matrix.
    #
    # The cache holds one package at a time. Clearing it first is what keeps the
    # reuse check above honest, since that check looks at whichever package it
    # finds; and the package installed is the one the build names on the last
    # line of its stdout, never one found by listing the directory.
    log "Building the .deb in the pinned build container (slow on first run)"
    rm -f "$DEB_CACHE_DIR"/*.deb
    local build_out
    if ! build_out=$(bash "$REPO_ROOT/packaging/debian/build-deb-container.sh" \
            --output-dir "$DEB_CACHE_DIR"); then
        echo "  ERROR: container build failed" >&2
        return 1
    fi

    cached_deb=$(printf '%s\n' "$build_out" | tail -n 1)
    if [ -z "$cached_deb" ] || [ ! -f "$cached_deb" ]; then
        echo "  ERROR: the container build did not report a package path: '$cached_deb'" >&2
        return 1
    fi
    DEB_PATH="$cached_deb"
    log "Cached at $cached_deb ($(stat -c %s "$cached_deb") bytes)"
    return 0
}

# The packages a runtime image installs on top of the distro base image.
# Ubuntu 22.04 bundles systemd-resolved into systemd; other distros require it
# as a separate package.
runtime_packages() {
    local base_image="$1"
    if [ "$base_image" = "ubuntu:22.04" ]; then
        echo "systemd iproute2 dbus dnsutils procps"
    else
        echo "systemd systemd-resolved iproute2 dbus dnsutils procps"
    fi
    return 0
}

# Patch a minimal gateway config into the container's fips.yaml, since the
# shipped one has the gateway disabled, and restart fips.service to load it.
# The caller checks that the daemon came back.
apply_gateway_config() {
    local name="$1"
    timeout "$CONFIG_RESTART_TIMEOUT" docker exec "$name" bash -c '
        systemctl unmask fips-gateway.service 2>/dev/null
        cp /etc/fips/fips.yaml /etc/fips/fips.yaml.orig
        cat >> /etc/fips/fips.yaml <<EOF
gateway:
  enabled: true
  pool: "fd01::/112"
  lan_interface: "eth0"
EOF
        systemctl restart fips.service
    ' >/dev/null 2>&1
    return
}

# Purge the package with the DNS routing file planted and fips-dns stopped, and
# check that postrm removes the file and restarts systemd-resolved.
#
# Stopping fips-dns runs fips-dns-teardown, which removes the file; putting it
# back gives the state in which removal leaves it behind: a live delegation and
# an inactive fips-dns, so prerm's stop runs no teardown. Only postrm purge is
# left to clean up, and a file it misses keeps the resolver sending .fips to
# [::1]:5354 after nothing listens there.
#
# Args: <name> <expected_backend>, the backend the scenario expects
# fips-dns-setup to pick (dns-delegate or global-drop-in).
check_purge_clears_dns() {
    local name="$1" backend="$2" file
    case "$backend" in
        dns-delegate) file=/etc/systemd/dns-delegate.d/fips.dns-delegate ;;
        global-drop-in) file=/etc/systemd/resolved.conf.d/fips.conf ;;
        *)
            fail "purge: no DNS routing file known for backend '$backend'"
            return
            ;;
    esac

    # The gateway-enable restart of fips.service is passed on to fips-dns
    # (Requires=fips.service), whose setup waits for fips0 before it writes the
    # file, and nothing since has waited for it. After=fips.service stops the
    # old instance before the daemon, so active here means the new setup ran.
    if ! wait_for_service_active "$name" fips-dns.service; then
        fail "purge: fips-dns.service not active again after the gateway-enable restart"
        echo "  --- fips-dns.service journal ---"
        docker exec "$name" journalctl -u fips-dns.service --no-pager 2>&1 | tail -20
        return
    fi
    if ! cexec "$name" test -f "$file"; then
        fail "purge: $file not written by fips-dns-setup before the purge"
        return
    fi
    # Saved inside the container: cexec runs docker exec without -i, so a
    # copy piped back from the host would arrive empty.
    if ! cexec "$name" cp "$file" /root/fips-dns.saved; then
        fail "purge: could not save $file"
        return
    fi

    cexec "$name" systemctl stop fips-dns.service >/dev/null 2>&1
    cexec "$name" cp /root/fips-dns.saved "$file"
    cexec "$name" systemctl restart systemd-resolved >/dev/null 2>&1

    local ok=1 status
    if ! cexec "$name" sh -c "test -s '$file' && cmp -s '$file' /root/fips-dns.saved"; then
        fail "purge: $file not restored before the purge"
        ok=0
    fi
    if cexec "$name" systemctl is-active --quiet fips-dns.service; then
        fail "purge: fips-dns.service still active before the purge"
        ok=0
    fi
    # Captured rather than piped into grep -q: under pipefail, grep closing the
    # pipe early can fail the pipeline on a match.
    if ! status=$(cexec "$name" resolvectl status 2>&1); then
        fail "purge: resolvectl status failed before the purge"
        echo "$status" | tail -10
        ok=0
    elif ! grep -q ':5354' <<<"$status"; then
        fail "purge: resolvectl status does not show $file in effect before the purge"
        echo "$status" | tail -25
        ok=0
    fi
    [ "$ok" = 1 ] || return
    local before after
    before=$(cexec "$name" systemctl show -p InvocationID --value systemd-resolved)

    run_apt "$name" "$UPGRADE_APT_TIMEOUT" purge -y fips
    echo "  purge took ${APT_SECS}s"
    if [ "$APT_RC" -ne 0 ]; then
        fail "purge: apt-get purge exited $APT_RC"
        echo "$APT_OUT" | tail -20
        return
    fi

    # test exits 1 for a missing file; any other failure is docker exec's.
    local rc=0
    cexec "$name" test -e "$file" || rc=$?
    case "$rc" in
        1) pass "purge removed $file" ;;
        0) fail "purge left $file behind" ;;
        *) fail "purge: could not check for $file (exit $rc)" ;;
    esac
    after=$(cexec "$name" systemctl show -p InvocationID --value systemd-resolved)
    if [ -n "$before" ] && [ -n "$after" ] && [ "$before" != "$after" ]; then
        pass "purge restarted systemd-resolved"
    else
        fail "purge did not restart systemd-resolved (InvocationID '$before' -> '$after')"
    fi
    if ! status=$(cexec "$name" resolvectl status 2>&1); then
        fail "purge: resolvectl status failed after the purge"
        echo "$status" | tail -10
    elif grep -q ':5354' <<<"$status"; then
        fail "purge: resolvectl status still routes to port 5354"
        echo "$status" | tail -25
    else
        pass "purge: resolvectl status no longer routes to port 5354"
    fi
    return
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

    local name="fips-deb-test-${distro_label}${FIPS_CI_NAME_SUFFIX:-}"
    local image="fips-deb-test:${distro_label}"
    log ".deb install: ${base_image}"

    build_deb || { fail ".deb build failed"; return; }

    local cached_deb="$DEB_PATH"
    if [ -z "$cached_deb" ] || [ ! -f "$cached_deb" ]; then
        fail "no .deb available at $DEB_CACHE_DIR"
        return
    fi
    local deb_basename
    deb_basename=$(basename "$cached_deb")

    local apt_packages
    apt_packages=$(runtime_packages "$base_image")

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
    wait_for_systemd "$name" || {
        fail "systemd did not boot in $name; the install checks below would read an unstarted system"
        cleanup_container "$name"
        return
    }

    # Install the .deb. apt handles dependencies (libc6, systemd,
    # libdbus-1-3) and runs the maintainer scripts (postinst →
    # systemctl enable fips.service; fips-dns.service starts and
    # runs fips-dns-setup).
    log "Installing .deb (apt install /opt/fips-deb/${deb_basename})"
    # `|| true` here used to discard apt's exit status, and an empty capture (a
    # failed `docker exec`) matches neither error pattern below, so a install
    # that never ran reached `pass "apt install completed"`. Keep the capture on
    # failure so the diagnostics below can print it, but remember the status.
    local install_output install_rc=0
    install_output=$(docker exec "$name" bash -c "
        apt-get update >/dev/null 2>&1
        cd /opt/fips-deb && apt-get install -y --no-install-recommends ./${deb_basename} 2>&1
    ") || install_rc=$?
    if [ "$install_rc" -ne 0 ]; then
        fail "apt install exited $install_rc"
        echo "$install_output" | tail -20
        cleanup_container "$name"
        return
    fi
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

    # ── nftables firewall baseline (v0.3.0) ──────────────────────────
    # The fips-firewall.service unit ships installed but DISABLED by
    # default; operators opt in explicitly. The fips.nft ruleset is a
    # dpkg conffile, and /etc/fips/fips.d/ is a drop-in directory the
    # ruleset includes via a glob. None of these are exercised by the
    # service-start path below — verify them as static install state.
    if docker exec "$name" test -f /lib/systemd/system/fips-firewall.service; then
        pass "fips-firewall.service unit installed at /lib/systemd/system/"
    else
        fail "fips-firewall.service unit missing from /lib/systemd/system/"
    fi
    # is-enabled prints 'disabled' (and exits non-zero) for an
    # installed-but-not-enabled unit; capture stdout, don't gate on rc.
    fw_state=$(docker exec "$name" systemctl is-enabled fips-firewall.service 2>/dev/null || true)
    if [ "$fw_state" = "disabled" ]; then
        pass "fips-firewall.service disabled by default (opt-in)"
    else
        fail "fips-firewall.service unexpected state: '$fw_state' (expected 'disabled')"
    fi
    if docker exec "$name" test -f /etc/fips/fips.nft && \
       docker exec "$name" dpkg-query -W -f='${Conffiles}\n' fips 2>/dev/null \
            | grep -q '/etc/fips/fips.nft'; then
        pass "/etc/fips/fips.nft installed and registered as dpkg conffile"
    else
        fail "/etc/fips/fips.nft missing or not a registered conffile"
    fi
    if docker exec "$name" test -d /etc/fips/fips.d; then
        fwd_mode=$(docker exec "$name" stat -c '%a %U:%G' /etc/fips/fips.d 2>/dev/null)
        if [ "$fwd_mode" = "755 root:root" ]; then
            pass "/etc/fips/fips.d/ drop-in dir present (755 root:root)"
        else
            fail "/etc/fips/fips.d/ wrong mode/owner: '$fwd_mode' (expected '755 root:root')"
        fi
    else
        fail "/etc/fips/fips.d/ drop-in directory missing"
    fi
    if docker exec "$name" grep -qF 'include "/etc/fips/fips.d/*.nft"' /etc/fips/fips.nft; then
        pass "fips.nft includes drop-in glob /etc/fips/fips.d/*.nft"
    else
        fail "fips.nft missing drop-in include for /etc/fips/fips.d/*.nft"
    fi

    # Start the services as a simulated boot. (On a real system,
    # they'd come up on next reboot.)
    start_unit "$name" fips.service || true
    start_unit_queued "$name" fips-dns.service || true

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

    # Wait for fips-dns.service to finish. Its start job is queued rather than
    # waited on above, so this is what makes /run/fips/dns-backend safe to read:
    # fips-dns-setup waits up to 30s for fips0 and restarts systemd-resolved
    # before it writes that file, so reading it on a timer races the setup.
    # RemainAfterExit=yes makes is-active correct for this oneshot.
    if wait_for_service_active "$name" fips-dns.service; then
        pass "fips-dns.service completed"
    else
        fail "fips-dns.service did not complete in ${SERVICE_TIMEOUT}s"
        echo "  --- fips-dns.service journal ---"
        docker exec "$name" journalctl -u fips-dns.service --no-pager 2>&1 | tail -20
        cleanup_container "$name"
        return
    fi

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
    # the DNS upstream check), which the container is started with;
    # see start_systemd_container_with_tun.
    apply_gateway_config "$name"

    sleep 3
    if wait_for_service_active "$name" fips.service 5; then
        :
    else
        fail "fips.service did not stay up after gateway-enable restart"
    fi

    # systemd removes and recreates RuntimeDirectory=fips across this restart
    # as root:root 0750. The daemon must restore the fips group on every start,
    # not only when it created the directory itself.
    local runtime_access
    runtime_access=$(docker exec "$name" stat -c '%a %U:%G' /run/fips 2>/dev/null || true)
    if [ "$runtime_access" = "750 root:fips" ]; then
        pass "/run/fips ownership restored after service restart"
    else
        fail "/run/fips wrong after service restart: '$runtime_access' (expected '750 root:fips')"
    fi

    if docker exec "$name" bash -c '
        useradd --system --no-create-home --user-group --groups fips fips-test-client
        runuser -u fips-test-client -- fipsctl show status >/dev/null
    '; then
        pass "non-root fips group member reaches control socket after restart"
    else
        fail "non-root fips group member cannot reach control socket after restart"
    fi

    start_unit "$name" fips-gateway.service "$GATEWAY_START_TIMEOUT" >/dev/null 2>&1 || true
    sleep 3
    if docker exec "$name" journalctl -u fips-gateway.service --no-pager 2>/dev/null \
            | grep -q "DNS upstream is reachable"; then
        pass "fips-gateway reaches DNS upstream at [::1]:5354 via .deb install"
    else
        fail "fips-gateway DNS upstream check failed against installed daemon"
        echo "  --- fips-gateway journal ---"
        docker exec "$name" journalctl -u fips-gateway.service --no-pager 2>&1 | tail -15
    fi

    check_purge_clears_dns "$name" "$expected_backend"

    cleanup_container "$name"
}

# ─────────────────────────────────────────────────────────────────────
# Upgrade scenario
#
# Upgrades an installed package to a newer one and checks what the
# maintainer scripts do to the running services on the way. The newer
# package is made from the one under test inside the container: unpacked,
# given a higher Version and repacked, so the upgrade runs this tree's prerm
# and postinst without a second build.
#
# Its runtime image holds no package. The install scenario's image does, but
# under a tag every run shares and a file name every build of one version
# shares, so another run could retag it in the minutes between the two
# scenarios and this one would upgrade from that run's package. Instead the
# package this run built is copied into each container, and its checksum is
# compared there before anything is installed.
# ─────────────────────────────────────────────────────────────────────

# Every apt run here is bounded: an upgrade that blocks in postinst is one of
# the defects this scenario exists to catch, and an unbounded one would hang
# the suite instead of failing it.
# The package's own worst case on a healthy daemon is its three bounded starts,
# 60s + 60s + 90s, so an upgrade bound above that reports the package's
# diagnosis rather than this one.
UPGRADE_APT_TIMEOUT=300
# The dead-daemon reinstall skips the units behind the daemon, so its worst
# case is one 60s bound.
DEAD_DAEMON_APT_TIMEOUT=150
# postinst waits up to 60s for a unit that does not start. When the daemon
# cannot start, apt has to return a failure well inside this.
DEAD_DAEMON_LIMIT=120
# Bound on a single short command inside a container.
EXEC_TIMEOUT=60

# Run a short command in a container under EXEC_TIMEOUT.
cexec() {
    local name="$1"
    shift
    timeout "$EXEC_TIMEOUT" docker exec "$name" "$@"
    return
}

# Run apt-get in /opt/fips-deb inside the container, bounded by the given
# number of seconds, keeping the existing configuration files. Sets APT_RC,
# APT_SECS and APT_OUT rather than returning a status, because every caller
# needs all three.
run_apt() {
    local name="$1" limit="$2"
    shift 2
    local start=$SECONDS
    APT_RC=0
    APT_OUT=$(timeout "$limit" docker exec -w /opt/fips-deb "$name" \
        apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
        "$@" 2>&1) || APT_RC=$?
    APT_SECS=$((SECONDS - start))
    return 0
}

# Boot an upgrade container, copy this run's package into it and install it.
# Returns 1, having recorded why, when any step fails.
upgrade_boot() {
    local name="$1" image="$2" deb="$3"
    if ! start_systemd_container_with_tun "$name" "$image"; then
        fail "$name: container did not start"
        return 1
    fi
    if ! wait_for_systemd "$name"; then
        fail "systemd did not boot in $name"
        return 1
    fi
    # /opt rather than /tmp: systemd mounts a fresh /tmp during boot.
    if ! timeout "$EXEC_TIMEOUT" docker cp "$DEB_PATH" "$name:/opt/fips-deb/$deb"; then
        fail "$name: could not copy $deb into the container"
        return 1
    fi
    local want have
    want=$(sha256sum "$DEB_PATH" | cut -d' ' -f1)
    have=$(cexec "$name" sha256sum "/opt/fips-deb/$deb" 2>/dev/null | cut -d' ' -f1)
    if [ -z "$want" ] || [ "$want" != "$have" ]; then
        fail "$name: the package in the container is not the one under test ('$have', want '$want')"
        return 1
    fi
    local start=$SECONDS rc=0 out
    out=$(timeout "$UPGRADE_APT_TIMEOUT" docker exec -w /opt/fips-deb "$name" bash -c "
        apt-get update >/dev/null 2>&1
        apt-get install -y --no-install-recommends ./${deb} 2>&1
    ") || rc=$?
    echo "  install took $((SECONDS - start))s"
    if [ "$rc" -ne 0 ]; then
        fail "$name: installing $deb exited $rc"
        echo "$out" | tail -20
        return 1
    fi
    return 0
}

# Make /opt/fips-deb/next.deb from the package under test, inside the
# container so the host needs no dpkg tooling. Its Version is the original's
# with "+upgrade1" appended, which must compare higher, and its fips.nft gains
# a named counter inside the fips table, so a check can tell whether the
# ruleset loaded after the upgrade is the new one. Any step failing is a
# failure of the scenario, never a skip.
make_next_package() {
    local name="$1" deb="$2" out rc=0
    # shellcheck disable=SC2016  # the script expands inside the container
    out=$(timeout "$EXEC_TIMEOUT" docker exec -w /opt/fips-deb -e DEB="$deb" "$name" \
        bash -euo pipefail -c '
        rm -rf /root/next
        dpkg-deb -R "./$DEB" /root/next
        old=$(dpkg-deb -f "./$DEB" Version)
        new="${old}+upgrade1"
        sed -i "s/^Version: .*/Version: ${new}/" /root/next/DEBIAN/control
        dpkg --compare-versions "$new" gt "$old"
        nft_file=/root/next/etc/fips/fips.nft
        grep -q "^table inet fips {\$" "$nft_file"
        sed -i "/^table inet fips {\$/a\\    counter fips_upgrade_probe { packets 0 bytes 0 }" "$nft_file"
        grep -q "counter fips_upgrade_probe" "$nft_file"
        nft -c -f "$nft_file"
        if grep -q "  etc/fips/fips.nft\$" /root/next/DEBIAN/md5sums 2>/dev/null; then
            sum=$(md5sum "$nft_file" | cut -d" " -f1)
            sed -i "s|^[0-9a-f]*  etc/fips/fips.nft\$|${sum}  etc/fips/fips.nft|" /root/next/DEBIAN/md5sums
            grep -q "^${sum}  etc/fips/fips.nft\$" /root/next/DEBIAN/md5sums
        fi
        dpkg-deb -b /root/next /opt/fips-deb/next.deb >/dev/null
        echo "made next.deb at Version $new"
    ' 2>&1) || rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "$name: could not make the newer package (exit $rc)"
        echo "$out" | tail -20
        return 1
    fi
    echo "  $out"
    return 0
}

# Start fips.service and fips-dns.service the way the install scenario does
# and require both to be active.
start_daemon_units() {
    local name="$1"
    start_unit "$name" fips.service >/dev/null || true
    start_unit_queued "$name" fips-dns.service >/dev/null || true
    if wait_for_service_active "$name" fips.service &&
        wait_for_service_active "$name" fips-dns.service; then
        return 0
    fi
    cexec "$name" systemctl status --no-pager fips.service fips-dns.service 2>&1 | tail -20
    return 1
}

# Pass or fail on whether a unit is active.
check_active() {
    local name="$1" unit="$2" what="$3"
    if cexec "$name" systemctl is-active --quiet "$unit"; then
        pass "$what: $unit active"
    else
        fail "$what: $unit not active"
        cexec "$name" systemctl status --no-pager "$unit" 2>&1 | tail -15
    fi
    return 0
}

# Pass or fail on whether a unit the host never enabled is still neither
# running nor enabled.
check_left_off() {
    local name="$1" unit="$2" what="$3" state
    state=$(cexec "$name" systemctl is-enabled "$unit" 2>/dev/null || true)
    if ! cexec "$name" systemctl is-active --quiet "$unit" && [ "$state" = "disabled" ]; then
        pass "$what: $unit inactive and disabled"
    else
        fail "$what: $unit is $(cexec "$name" systemctl is-active "$unit" 2>/dev/null) and '$state' (want inactive and disabled)"
    fi
    return 0
}

# Start `nft monitor tables` in the background, writing to
# /root/nft-monitor.log, and prove it is recording by adding and deleting a
# table of its own. An empty log from a monitor that never ran would otherwise
# read as a ruleset that was never removed. The probe table's name does not
# begin with "fips", so it cannot match a check on the fips table.
start_nft_monitor() {
    local name="$1"
    if ! timeout "$EXEC_TIMEOUT" docker exec -d "$name" \
            sh -c 'exec nft monitor tables > /root/nft-monitor.log 2>&1'; then
        return 1
    fi
    sleep 1
    cexec "$name" sh -c 'nft add table inet monprobe && nft delete table inet monprobe' || return 1
    local _i
    for _i in 1 2 3 4 5; do
        if cexec "$name" grep -Eq '^delete table inet monprobe( |$)' /root/nft-monitor.log; then
            return 0
        fi
        sleep 1
    done
    cexec "$name" cat /root/nft-monitor.log 2>&1 | tail -10
    return 1
}

# Apply the gateway config and start fips-gateway.service, bounded, requiring
# it to be active. Leaves it enabled or not as the caller already set it.
start_gateway() {
    local name="$1"
    apply_gateway_config "$name"
    if ! wait_for_service_active "$name" fips.service 10; then
        return 1
    fi
    start_unit "$name" fips-gateway.service "$GATEWAY_START_TIMEOUT" >/dev/null 2>&1 || true
    if wait_for_service_active "$name" fips-gateway.service 10; then
        return 0
    fi
    cexec "$name" systemctl status --no-pager fips-gateway.service 2>&1 | tail -15
    return 1
}

# Print a unit's MainPID; 0 when it has no main process.
main_pid() {
    local name="$1" unit="$2"
    cexec "$name" systemctl show -p MainPID --value "$unit" 2>/dev/null || echo 0
    return 0
}

# Pass or fail on whether a unit runs a new process of the installed binary
# after the upgrade: active, a MainPID other than the one before, and an
# executable that is the installed file rather than one the upgrade replaced,
# which the kernel reports with a " (deleted)" suffix.
check_new_binary() {
    local name="$1" unit="$2" binary="$3" before="$4" what="$5" pid exe
    pid=$(main_pid "$name" "$unit")
    exe=$(cexec "$name" readlink "/proc/$pid/exe" 2>/dev/null || true)
    if cexec "$name" systemctl is-active --quiet "$unit" && [ "$pid" != 0 ] &&
        [ "$pid" != "$before" ] && [ "$exe" = "$binary" ]; then
        pass "$what: $unit runs the upgraded $binary"
    else
        fail "$what: $unit is $(cexec "$name" systemctl is-active "$unit" 2>/dev/null), MainPID $before -> $pid, exe '$exe' (want active, a new process, $binary)"
    fi
    return 0
}

# Host that opted in to the firewall and enabled the gateway: the upgrade must
# apply the new ruleset in place, with no moment at which the fips table is
# absent, and bring the gateway back on the new binary. Purging the package
# must then leave no enablement behind for the gateway.
_upgrade_opted_in() {
    local name="$1" image="$2" deb="$3"
    log "upgrade on a host that opted in ($name)"
    upgrade_boot "$name" "$image" "$deb" || { cleanup_container "$name"; return 0; }
    make_next_package "$name" "$deb" || { cleanup_container "$name"; return 0; }
    if ! cexec "$name" systemctl enable --now fips-firewall.service >/dev/null 2>&1 ||
        ! start_daemon_units "$name"; then
        fail "opted in: the firewall, fips and fips-dns did not all start before the upgrade"
        cexec "$name" systemctl status --no-pager fips-firewall.service 2>&1 | tail -15
        cleanup_container "$name"
        return 0
    fi
    cexec "$name" systemctl enable fips-gateway.service >/dev/null 2>&1
    if ! start_gateway "$name"; then
        fail "opted in: fips-gateway did not start before the upgrade"
        cleanup_container "$name"
        return 0
    fi
    if ! start_nft_monitor "$name"; then
        fail "opted in: nft monitor is not observing table changes"
        cleanup_container "$name"
        return 0
    fi
    local fips_pid gw_pid
    fips_pid=$(main_pid "$name" fips.service)
    gw_pid=$(main_pid "$name" fips-gateway.service)

    run_apt "$name" "$UPGRADE_APT_TIMEOUT" install -y ./next.deb
    echo "  upgrade took ${APT_SECS}s"
    if [ "$APT_RC" -eq 0 ]; then
        pass "opted in: upgrade exits 0"
    else
        fail "opted in: upgrade exited $APT_RC"
        echo "$APT_OUT" | tail -20
    fi
    check_active "$name" fips.service "opted in, after upgrade"
    check_active "$name" fips-dns.service "opted in, after upgrade"
    check_active "$name" fips-firewall.service "opted in, after upgrade"
    if cexec "$name" nft list counter inet fips fips_upgrade_probe >/dev/null 2>&1; then
        pass "opted in: the upgraded ruleset is loaded"
    else
        fail "opted in: the upgraded ruleset is not loaded (no fips_upgrade_probe counter)"
    fi
    if cexec "$name" grep -Eq '^delete table inet fips( |$)' /root/nft-monitor.log; then
        fail "opted in: the fips table was deleted during the upgrade"
        cexec "$name" cat /root/nft-monitor.log 2>&1 | tail -10
    else
        pass "opted in: the fips table was never deleted during the upgrade"
    fi
    check_new_binary "$name" fips.service /usr/bin/fips "$fips_pid" "opted in, after upgrade"
    check_new_binary "$name" fips-gateway.service /usr/bin/fips-gateway "$gw_pid" "opted in, after upgrade"

    run_apt "$name" "$UPGRADE_APT_TIMEOUT" purge -y fips
    echo "  purge took ${APT_SECS}s"
    if [ "$APT_RC" -ne 0 ]; then
        fail "opted in: purge exited $APT_RC"
        echo "$APT_OUT" | tail -20
    fi
    local link=/etc/systemd/system/multi-user.target.wants/fips-gateway.service state
    state=$(cexec "$name" systemctl is-enabled fips-gateway.service 2>/dev/null || true)
    if ! cexec "$name" test -e "$link" && ! cexec "$name" test -L "$link" &&
        [ "$state" != "enabled" ]; then
        pass "opted in, after purge: no fips-gateway enablement left behind"
    else
        fail "opted in, after purge: fips-gateway still enabled ('$state', $(cexec "$name" ls -l "$link" 2>&1))"
    fi

    cleanup_container "$name"
    return 0
}

# Host that never opted in to the firewall and ran the gateway without enabling
# it: the upgrade must leave neither running nor enabled. Then the package is
# reinstalled three times: with the daemon masked, when apt must succeed and
# start nothing; with an enabled gateway that cannot start, when apt must
# succeed, say so, and leave the daemon running; and with a daemon that cannot
# start, when apt must fail, promptly, naming the unit, rather than wait for
# ever on a unit that requires a daemon which never comes up.
_upgrade_not_opted_in() {
    local name="$1" image="$2" deb="$3"
    log "upgrade on a host that never opted in ($name)"
    upgrade_boot "$name" "$image" "$deb" || { cleanup_container "$name"; return 0; }
    make_next_package "$name" "$deb" || { cleanup_container "$name"; return 0; }
    if ! start_daemon_units "$name" || ! start_gateway "$name"; then
        fail "not opted in: fips, fips-dns and fips-gateway did not start before the upgrade"
        cleanup_container "$name"
        return 0
    fi

    run_apt "$name" "$UPGRADE_APT_TIMEOUT" install -y ./next.deb
    echo "  upgrade took ${APT_SECS}s"
    if [ "$APT_RC" -eq 0 ]; then
        pass "not opted in: upgrade exits 0"
    else
        fail "not opted in: upgrade exited $APT_RC"
        echo "$APT_OUT" | tail -20
    fi
    check_active "$name" fips.service "not opted in, after upgrade"
    check_active "$name" fips-dns.service "not opted in, after upgrade"
    check_left_off "$name" fips-firewall.service "not opted in, after upgrade"
    check_left_off "$name" fips-gateway.service "not opted in, after upgrade"
    if cexec "$name" nft list table inet fips >/dev/null 2>&1; then
        fail "not opted in, after upgrade: the fips firewall table is loaded"
    else
        pass "not opted in, after upgrade: no fips firewall table"
    fi

    # A host that masked the daemon on purpose: the upgrade must skip it with a
    # message, not fail. The package before this change printed nothing for a
    # masked unit, so the message is what tells the two apart.
    cexec "$name" bash -c 'systemctl stop fips-dns.service fips.service; systemctl mask fips.service' \
        >/dev/null 2>&1
    run_apt "$name" "$UPGRADE_APT_TIMEOUT" install --reinstall -y ./next.deb
    echo "  reinstall with the daemon masked took ${APT_SECS}s (exit $APT_RC)"
    if [ "$APT_RC" -eq 0 ] && grep -q "fips.service is masked" <<<"$APT_OUT" &&
        ! cexec "$name" systemctl is-active --quiet fips.service &&
        ! cexec "$name" systemctl is-active --quiet fips-dns.service; then
        pass "masked daemon: apt succeeds, says the unit was skipped and starts nothing"
    else
        fail "masked daemon: apt exited $APT_RC (want 0, a message that fips.service is masked, and fips and fips-dns inactive)"
        echo "$APT_OUT" | tail -20
    fi
    cexec "$name" bash -c 'systemctl unmask fips.service; systemctl daemon-reload' >/dev/null 2>&1
    if ! start_daemon_units "$name"; then
        fail "dead daemon: fips and fips-dns did not start again after unmasking"
        cleanup_container "$name"
        return 0
    fi

    # An enabled gateway that fails on start, behind a daemon that is healthy:
    # the gateway is an opt-in addition, so apt must report it and succeed.
    # Restart=no so it reaches failed at once rather than looping.
    cexec "$name" bash -c '
        mkdir -p /etc/systemd/system/fips-gateway.service.d
        printf "[Service]\nExecStart=\nExecStart=/bin/false\nRestart=no\n" \
            > /etc/systemd/system/fips-gateway.service.d/broken.conf
        systemctl daemon-reload
        systemctl enable fips-gateway.service
    ' >/dev/null 2>&1
    run_apt "$name" "$UPGRADE_APT_TIMEOUT" install --reinstall -y ./next.deb
    echo "  reinstall with a broken gateway took ${APT_SECS}s (exit $APT_RC)"
    if [ "$APT_RC" -eq 0 ] &&
        grep -q "fips-gateway.service did not come back" <<<"$APT_OUT" &&
        cexec "$name" systemctl is-active --quiet fips.service; then
        pass "broken gateway: apt succeeds, reports the gateway and leaves the daemon running"
    else
        fail "broken gateway: apt exited $APT_RC (want 0, a message that fips-gateway.service did not come back, and fips active)"
        echo "$APT_OUT" | tail -20
    fi
    cexec "$name" bash -c '
        systemctl disable fips-gateway.service
        rm -rf /etc/systemd/system/fips-gateway.service.d
        systemctl daemon-reload
        systemctl reset-failed fips-gateway.service
    ' >/dev/null 2>&1

    # A daemon that fails on every start: exit 1, so Restart=on-failure loops,
    # and the start job of fips-dns, which requires it, is never dispatched.
    cexec "$name" bash -c '
        mkdir -p /etc/systemd/system/fips.service.d
        printf "[Service]\nExecStart=\nExecStart=/bin/false\n" \
            > /etc/systemd/system/fips.service.d/broken.conf
        systemctl daemon-reload
    '
    run_apt "$name" "$DEAD_DAEMON_APT_TIMEOUT" install --reinstall -y ./next.deb
    echo "  reinstall with a dead daemon took ${APT_SECS}s (exit $APT_RC)"
    if [ "$APT_RC" -ne 0 ] && [ "$APT_RC" -ne 124 ] &&
        [ "$APT_SECS" -lt "$DEAD_DAEMON_LIMIT" ] &&
        grep -q "fips.service did not become active" <<<"$APT_OUT"; then
        pass "dead daemon: apt fails in ${APT_SECS}s and names fips.service"
    else
        fail "dead daemon: apt exited $APT_RC after ${APT_SECS}s (want a failure under ${DEAD_DAEMON_LIMIT}s naming fips.service; 124 is the harness bound)"
        echo "$APT_OUT" | tail -20
    fi

    cleanup_container "$name"
    return 0
}

_run_deb_upgrade_scenario() {
    local distro_label="$1"
    local base_image="$2"
    # Scoped to the run like the container names, although it holds no
    # package, so concurrent runs never rebuild an image under each other.
    local image="fips-deb-upgrade:${distro_label}${FIPS_CI_NAME_SUFFIX:-}"
    log ".deb upgrade: ${base_image}"

    if [ -z "$DEB_PATH" ] || [ ! -f "$DEB_PATH" ]; then
        fail "no package to upgrade from"
        return
    fi
    local deb
    deb=$(basename "$DEB_PATH")

    log "Building $image (runtime packages and nftables, no fips package)"
    build_image "$image" "$(cat <<DOCKERFILE
FROM ${base_image}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \\
    $(runtime_packages "$base_image") nftables && \\
    apt-get clean && rm -rf /var/lib/apt/lists/* && \\
    systemctl enable systemd-resolved && \\
    mkdir -p /opt/fips-deb
CMD ["/lib/systemd/systemd"]
DOCKERFILE
    )" || {
        fail "upgrade image build failed"
        return
    }

    # Named under the install scenario's prefix, so a CI step that collects
    # that scenario's container logs on failure collects these too.
    _upgrade_opted_in "fips-deb-test-${distro_label}-upg-a${FIPS_CI_NAME_SUFFIX:-}" "$image" "$deb"
    _upgrade_not_opted_in "fips-deb-test-${distro_label}-upg-b${FIPS_CI_NAME_SUFFIX:-}" "$image" "$deb"
    docker rmi "$image" >/dev/null 2>&1 || true
    return 0
}

# Per-distro wrappers
# debian12 also runs the upgrade scenario. One distro keeps the suite's cost
# down; this one because a oneshot start behind a daemon in its restart loop
# waits for ever on its systemd (252), while on Ubuntu 22.04's (249) the start
# returns with an error, so only here does the upgrade scenario see the hang.
test_debian12() {
    _run_deb_install_scenario debian12 debian:12
    _run_deb_upgrade_scenario debian12 debian:12
}
test_debian13() { _run_deb_install_scenario debian13 debian:trixie; }
test_ubuntu22() { _run_deb_install_scenario ubuntu22 ubuntu:22.04;  }
test_ubuntu24() { _run_deb_install_scenario ubuntu24 ubuntu:24.04;  }
test_ubuntu26() { _run_deb_install_scenario ubuntu26 ubuntu:26.04;  }

# ─────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────

ALL_SCENARIOS="debian12 debian13 ubuntu22 ubuntu24 ubuntu26"

# `--deb PATH` installs a package the caller already built, which is how one
# build serves all five distributions and how GitHub CI and a local run come to
# do the same work: both build once through the container script and hand the
# result here. Keep ALL_SCENARIOS above on its own line at column zero;
# check-ci-parity.sh reads it to compare this matrix against the GitHub one.
_args=()
while [ $# -gt 0 ]; do
    case "$1" in
        --deb)
            SUPPLIED_DEB="${2:?--deb requires a path}"
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

# A skip must not read as a pass. Nothing calls skip() today, so SKIP is
# always 0 and this changes no current outcome -- which is exactly why it is
# worth adding now: the helper and the counter already existed and were
# reported, so a later skip path would have printed "N skipped" next to a
# zero exit and looked like coverage. Gate on it before that happens.
if [ "$SKIP" -ne 0 ]; then
    echo "FAIL: $SKIP check(s) skipped; a skipped check is not a passed one." >&2
    echo "      Either make the check run here, or remove it and record the" >&2
    echo "      gap deliberately rather than skipping it at runtime." >&2
fi

[ "$FAIL" -eq 0 ] && [ "$SKIP" -eq 0 ]
