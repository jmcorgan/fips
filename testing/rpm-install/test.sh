#!/bin/bash
# Test the fips-mesh RPM install path across the RPM-family distributions.
#
# The artifact under test is the one a release publishes: the .deb is built in
# the pinned container, its binaries are recovered, and
# packaging/rpm/build-rpm-container.sh --no-build packages those. That is the
# path only the release workflow takes -- `make rpm` and `make rpm-host` both
# reach the other branch -- so a defect on it is invisible to anything a
# developer runs by hand, which is how one shipped once already.
#
# Each scenario boots a systemd container with TUN access, installs the
# package with dnf, and checks what an operator would meet:
#
#   almalinux9   install, unit state, file placement, end-to-end .fips
#                resolution, then erase
#   fedora       the same, on a systemd new enough for the dns-delegate
#                backend
#   no-resolver  a stock EL9 host, where no resolver backend applies: the
#                daemon runs and `.fips` does not resolve, which is a
#                documented outcome rather than a failure
#   upgrade      a running daemon upgraded in place: the transaction must not
#                wait on the restart, the daemon must come back, and a host
#                that never enabled the gateway must not acquire it
#
# Usage: ./test.sh [--deb PATH | --rpm PATH] [scenario ...]
#   --deb  package the binaries from this container-built .deb, instead of
#          building one (ci-local.sh passes the .deb it shares with
#          deb-install and dns-resolver)
#   --rpm  test this package as given, skipping the build
#   No scenario args = run all scenarios.
#
# Requirements: Docker able to grant SYS_ADMIN and NET_ADMIN and an
# unconfined AppArmor profile (see testing/lib/systemd-container.sh),
# /dev/net/tun on the host.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=SCRIPTDIR/../lib/systemd-container.sh
source "$SCRIPT_DIR/../lib/systemd-container.sh"
# shellcheck source=SCRIPTDIR/../lib/image-build.sh
source "$SCRIPT_DIR/../lib/image-build.sh"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=../../packaging/build-floor.env
source "$REPO_ROOT/packaging/build-floor.env"

CACHE_DIR="$SCRIPT_DIR/.cache"
RPM_PATH=""
DEB_PATH=""

PASS=0
FAIL=0
SKIP=0

# Bounds. Every dnf call is bounded because an install or an upgrade that
# blocks in a scriptlet is one of the defects this suite exists to catch, and
# an unbounded one would hang the run instead of failing it. The upgrade bound
# is the tighter of the two on purpose: %postun queues the restart with
# --no-block, so the transaction should return in seconds, and a transaction
# that waits on fips-dns-setup's 30 s interface wait would exceed this.
EXEC_TIMEOUT=${EXEC_TIMEOUT:-120}
DNF_TIMEOUT=${DNF_TIMEOUT:-600}
UPGRADE_DNF_TIMEOUT=${UPGRADE_DNF_TIMEOUT:-120}
UPGRADE_TRANSACTION_CEILING=${UPGRADE_TRANSACTION_CEILING:-45}

ALL_SCENARIOS="almalinux9 fedora no-resolver upgrade"

EL9_IMAGE="almalinux:9"
FEDORA_IMAGE="fedora:44"

log()  { echo "=== $*"; }
pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP: $*"; SKIP=$((SKIP + 1)); }

# The container plumbing below is deb-install's, unchanged, so the two suites
# boot, start and time out the same way. If it moves into testing/lib/, both
# should take it from there.
BOOT_TIMEOUT=30
SERVICE_TIMEOUT=20
DAEMON_TIMEOUT=15
UNIT_START_TIMEOUT=30

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

cexec() {
    local name="$1"
    shift
    timeout "$EXEC_TIMEOUT" docker exec "$name" "$@"
    return
}

# Build the artifact the release publishes, or take one from --rpm.
#
# Not `make rpm`: that path builds the .deb and packages it in one call, and
# the release workflow instead recovers the binaries from a .deb it already
# has and calls build-rpm-container.sh --no-build over them. This reproduces
# the second, and asserts the script's own exit status, because a package that
# builds and then reports failure is exactly what that path shipped before.
build_rpm() {
    if [ -n "$RPM_PATH" ]; then
        [ -f "$RPM_PATH" ] || { fail "no package at $RPM_PATH"; return 1; }
        log "Using the package given on the command line: $(basename "$RPM_PATH")"
        return 0
    fi

    mkdir -p "$CACHE_DIR"
    local deb_dir="$CACHE_DIR/deb" bin_dir="$CACHE_DIR/bin" rpm_dir="$CACHE_DIR/rpm"

    # Take the given .deb aside before the cache is cleared, in case the
    # caller pointed at one inside it.
    local given=""
    if [ -n "$DEB_PATH" ]; then
        [ -f "$DEB_PATH" ] || { fail "no .deb at $DEB_PATH"; return 1; }
        given=$(mktemp "$CACHE_DIR/given.XXXXXX.deb")
        cp "$DEB_PATH" "$given"
    fi

    rm -rf "$deb_dir" "$bin_dir" "$rpm_dir"
    mkdir -p "$deb_dir" "$bin_dir" "$rpm_dir"

    local deb
    if [ -n "$given" ]; then
        log "Packaging the binaries from the given .deb: $(basename "$DEB_PATH")"
        mv "$given" "$deb_dir/$(basename "$DEB_PATH")"
        deb="$deb_dir/$(basename "$DEB_PATH")"
    else
        log "Building the .deb in the pinned container (its binaries are what the RPM packages)"
        deb=$("$REPO_ROOT/packaging/debian/build-deb-container.sh" --output-dir "$deb_dir" | tail -n 1)
        if [ -z "$deb" ] || [ ! -f "$deb" ]; then
            fail "the Debian container build did not produce a package"
            return 1
        fi
    fi

    # dpkg-deb is not necessarily on the host, so unpack in a container. Not
    # the Debian *builder* image: that one is built locally and never pushed,
    # so it exists only on the runner that built the package, and a CI leg that
    # was handed the .deb as an artifact cannot pull it. Every Debian-family
    # base image carries dpkg-deb, and FIPS_BUILD_IMAGE is one that any runner
    # can pull.
    if ! docker run --rm \
        -v "$deb_dir":/deb:ro -v "$bin_dir":/bin-out \
        -e "HOST_UID=$(id -u)" -e "HOST_GID=$(id -g)" \
        "$FIPS_BUILD_IMAGE" bash -euo pipefail -c '
            unpack=$(mktemp -d)
            dpkg-deb -x /deb/*.deb "$unpack"
            for binary in fips fipsctl fipstop fips-gateway; do
                install -m 0755 "$unpack/usr/bin/$binary" "/bin-out/$binary"
            done
            chown "$HOST_UID:$HOST_GID" /bin-out/*
        ' >&2; then
        fail "could not recover the binaries from the .deb"
        return 1
    fi

    log "Packaging them with --no-build, the path the release workflow takes"
    local rc=0 out
    out=$("$REPO_ROOT/packaging/rpm/build-rpm-container.sh" \
        --no-build --bin-dir "$bin_dir" --output-dir "$rpm_dir") || rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "build-rpm-container.sh --no-build exited $rc"
        return 1
    fi
    pass "build-rpm-container.sh --no-build exited 0"

    RPM_PATH=$(echo "$out" | tail -n 1)
    if [ -z "$RPM_PATH" ] || [ ! -f "$RPM_PATH" ]; then
        fail "the build did not name a package it produced ('$RPM_PATH')"
        return 1
    fi
    pass "release path produced $(basename "$RPM_PATH")"

    # --features has to reach cargo, and on this path nothing compiles, so the
    # script must refuse rather than mark a Release it cannot back up.
    if "$REPO_ROOT/packaging/rpm/build-rpm-container.sh" \
        --no-build --bin-dir "$bin_dir" --features profiling \
        --output-dir "$rpm_dir" >/dev/null 2>&1; then
        fail "--features was accepted with --no-build"
    else
        pass "--features refused with --no-build"
    fi
    return 0
}

# The packages a runtime image needs on top of the distro base image.
#
# `resolver` adds systemd-resolved, which neither family installs by default
# outside Ubuntu 22.04's bundled one: the Debian legs of deb-install install it
# the same way. Without it no backend applies, which is what the no-resolver
# scenario is for.
runtime_packages() {
    local with_resolver="$1"
    local packages="systemd iproute dbus-daemon bind-utils procps-ng"
    if [ "$with_resolver" = "resolver" ]; then
        packages="$packages systemd-resolved"
    fi
    echo "$packages"
    return 0
}

# Build a runtime image for a scenario, with the package staged under /opt --
# systemd mounts a fresh /tmp during boot, which would wipe a package copied
# there.
build_runtime_image() {
    local image="$1" base_image="$2" with_resolver="$3"
    local rpm_basename
    rpm_basename=$(basename "$RPM_PATH")

    local packages enable_resolved=""
    packages=$(runtime_packages "$with_resolver")
    if [ "$with_resolver" = "resolver" ]; then
        enable_resolved="systemctl enable systemd-resolved && \\"
    fi

    mkdir -p "$CACHE_DIR"
    cp "$RPM_PATH" "$CACHE_DIR/rpm-for-image"
    build_image "$image" "$(cat <<DOCKERFILE
FROM ${base_image}
RUN dnf install -y --setopt=install_weak_deps=False ${packages} && \\
    dnf clean all && \\
    ${enable_resolved}
    mkdir -p /opt/fips-rpm
COPY testing/rpm-install/.cache/rpm-for-image /opt/fips-rpm/${rpm_basename}
CMD ["/usr/sbin/init"]
DOCKERFILE
    )"
    local rc=$?
    rm -f "$CACHE_DIR/rpm-for-image"
    return $rc
}

# Boot a scenario's container with the package staged inside it.
boot_scenario() {
    local name="$1" image="$2" base_image="$3" with_resolver="$4"

    log "Building ${base_image} runtime image"
    if ! build_runtime_image "$image" "$base_image" "$with_resolver"; then
        fail "runtime image build failed for $base_image"
        return 1
    fi

    start_systemd_container_with_tun "$name" "$image"
    if ! wait_for_systemd "$name"; then
        fail "systemd did not boot in $name; the checks below would read an unstarted system"
        cleanup_container "$name"
        return 1
    fi
    return 0
}

# Install the staged package. Bounded: an install that blocks in a scriptlet is
# one of the things this suite is here to catch.
install_package() {
    local name="$1"
    local rpm_basename
    rpm_basename=$(basename "$RPM_PATH")

    log "Installing (dnf install /opt/fips-rpm/${rpm_basename})"
    local rc=0 out start=$SECONDS
    out=$(timeout "$DNF_TIMEOUT" docker exec -w /opt/fips-rpm "$name" \
        dnf install -y --setopt=install_weak_deps=False "./${rpm_basename}" 2>&1) || rc=$?
    echo "  install took $((SECONDS - start))s"
    if [ "$rc" -ne 0 ]; then
        fail "dnf install exited $rc"
        echo "$out" | tail -20
        return 1
    fi
    pass "dnf install completed"
    return 0
}

# What the package put on disk, and in what state, before anything is started.
check_installed_state() {
    local name="$1"

    local installed
    installed=$(cexec "$name" rpm -q fips-mesh 2>/dev/null)
    if [ -n "$installed" ]; then
        pass "package installed: $installed"
    else
        fail "rpm -q fips-mesh found nothing"
        return 1
    fi

    if cexec "$name" getent group fips >/dev/null 2>&1; then
        pass "fips group created by %post"
    else
        fail "fips group missing"
    fi

    local config_mode
    config_mode=$(cexec "$name" stat -c '%a %U:%G' /etc/fips/fips.yaml 2>/dev/null)
    if [ "$config_mode" = "600 root:root" ]; then
        pass "/etc/fips/fips.yaml seeded (600 root:root)"
    else
        fail "/etc/fips/fips.yaml wrong or missing: '$config_mode' (expected '600 root:root')"
    fi

    # Seeded, not shipped: rpm must not own it, or an erase would take the
    # operator's configuration -- and their identity keys sit beside it.
    if cexec "$name" rpm -qf /etc/fips/fips.yaml >/dev/null 2>&1; then
        fail "/etc/fips/fips.yaml is owned by the package"
    else
        pass "/etc/fips/fips.yaml is seeded, not owned by the package"
    fi

    # hosts and fips.nft are the opposite: owned, and %config(noreplace).
    local marked=0 f
    for f in /etc/fips/hosts /etc/fips/fips.nft; do
        if cexec "$name" rpm -qc fips-mesh 2>/dev/null | grep -qx "$f"; then
            marked=$((marked + 1))
        else
            fail "$f is not a config file of the package"
        fi
    done
    [ "$marked" -eq 2 ] && pass "hosts and fips.nft are %config(noreplace)"

    if cexec "$name" test -d /etc/fips/fips.d; then
        local dropin_mode
        dropin_mode=$(cexec "$name" stat -c '%a %U:%G' /etc/fips/fips.d 2>/dev/null)
        if [ "$dropin_mode" = "755 root:root" ]; then
            pass "/etc/fips/fips.d/ drop-in dir present (755 root:root)"
        else
            fail "/etc/fips/fips.d/ wrong mode/owner: '$dropin_mode'"
        fi
    else
        fail "/etc/fips/fips.d/ missing"
    fi

    # Enabled and not started, which is where the RPM follows the .deb: the
    # install transaction must not bring a resolver rewrite with it.
    local unit state active
    for unit in fips.service fips-dns.service; do
        state=$(cexec "$name" systemctl is-enabled "$unit" 2>/dev/null || true)
        active=$(cexec "$name" systemctl is-active "$unit" 2>/dev/null || true)
        if [ "$state" = "enabled" ] && [ "$active" = "inactive" ]; then
            pass "$unit enabled and not started by the install"
        else
            fail "$unit is '$state'/'$active' (expected 'enabled'/'inactive')"
        fi
    done

    for unit in fips-firewall.service fips-gateway.service; do
        state=$(cexec "$name" systemctl is-enabled "$unit" 2>/dev/null || true)
        if [ "$state" = "disabled" ]; then
            pass "$unit disabled by default (opt-in)"
        else
            fail "$unit is '$state' (expected 'disabled')"
        fi
    done
    return 0
}

# Start the units the way an operator would, and report the daemon's npub.
start_and_identify() {
    local name="$1"

    start_unit "$name" fips.service || true
    start_unit_queued "$name" fips-dns.service || true

    if wait_for_service_active "$name" fips.service; then
        pass "fips.service active after explicit start"
    else
        fail "fips.service did not become active in ${SERVICE_TIMEOUT}s"
        echo "  --- fips.service status ---"
        cexec "$name" systemctl status fips.service --no-pager 2>&1 | tail -20
        return 1
    fi

    # The daemon hands /run/fips to the fips group once its control socket is
    # up, which is after the unit reports active, so poll rather than read it
    # once -- deb-install checks it only after the DNS listener has appeared,
    # for the same reason.
    local runtime_access="" _
    for _ in $(seq 1 "$DAEMON_TIMEOUT"); do
        runtime_access=$(cexec "$name" stat -c '%a %U:%G' /run/fips 2>/dev/null || true)
        [ "$runtime_access" = "750 root:fips" ] && break
        sleep 1
    done
    if [ "$runtime_access" = "750 root:fips" ]; then
        pass "/run/fips is 750 root:fips, so group members can reach the control socket"
    else
        fail "/run/fips wrong: '$runtime_access' (expected '750 root:fips')"
    fi

    NPUB=$(cexec "$name" fipsctl show status 2>/dev/null | grep -oE 'npub1[a-z0-9]+' | head -1)
    if [ -z "$NPUB" ]; then
        fail "could not read an npub from fipsctl show status"
        return 1
    fi
    echo "  daemon npub: $NPUB"
    return 0
}

# The end a user meets: a .fips name resolving through whichever backend
# fips-dns-setup picked.
check_resolution() {
    local name="$1"

    # fips-dns.service was queued, not waited on, and fips-dns-setup writes the
    # backend file only after up to 30 s for fips0 and a resolver restart, so
    # reading it before the oneshot finishes races the setup. RemainAfterExit
    # makes is-active the right test.
    if wait_for_service_active "$name" fips-dns.service; then
        pass "fips-dns.service completed"
    else
        fail "fips-dns.service did not complete in ${SERVICE_TIMEOUT}s"
        cexec "$name" journalctl -u fips-dns.service --no-pager 2>&1 | tail -20
        return
    fi

    local backend ver expected
    backend=$(cexec "$name" cat /run/fips/dns-backend 2>/dev/null || echo "(missing)")
    ver=$(container_systemd_version "$name")
    if [ -n "$ver" ] && [ "$ver" -ge 258 ]; then
        expected="dns-delegate"
    else
        expected="global-drop-in"
    fi
    if [ "$backend" = "$expected" ]; then
        pass "fips-dns.service picked $expected (systemd $ver)"
    else
        fail "expected $expected (systemd $ver), got: $backend"
        cexec "$name" journalctl -u fips-dns.service --no-pager 2>&1 | tail -20
    fi

    sleep 1
    local dig_output
    dig_output=$(cexec "$name" dig +tries=1 +time=3 @127.0.0.53 AAAA "${NPUB}.fips" 2>&1)
    if echo "$dig_output" | grep -qE '^[a-zA-Z0-9].*\sAAAA\s+[0-9a-f:]+'; then
        pass "end-to-end dig @127.0.0.53 returns AAAA"
    else
        fail "end-to-end dig @127.0.0.53 returned no AAAA"
        echo "  --- dig ---"
        echo "$dig_output" | tail -12
        echo "  --- resolved ---"
        cexec "$name" resolvectl status 2>&1 | tail -20 || true
    fi
}

# Erase, which on rpm is the only cleanup there is: there is no purge, so
# whatever survives here survives for ever.
check_erase() {
    local name="$1"

    # Stand in for a host where fips-dns.service never ran, which is the case
    # the erase branch exists for: the teardown removes these on ExecStop.
    cexec "$name" mkdir -p /etc/systemd/resolved.conf.d /etc/systemd/dns-delegate.d \
        /etc/dnsmasq.d /etc/NetworkManager/dnsmasq.d >/dev/null 2>&1
    cexec "$name" touch /etc/systemd/resolved.conf.d/fips.conf \
        /etc/systemd/dns-delegate.d/fips.dns-delegate \
        /etc/dnsmasq.d/fips.conf /etc/NetworkManager/dnsmasq.d/fips.conf >/dev/null 2>&1

    local rc=0 out
    out=$(timeout "$DNF_TIMEOUT" docker exec "$name" dnf remove -y fips-mesh 2>&1) || rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "dnf remove exited $rc"
        echo "$out" | tail -15
        return 1
    fi
    pass "dnf remove completed"

    if cexec "$name" test -f /usr/bin/fips; then
        fail "/usr/bin/fips survived the erase"
    else
        pass "binaries removed"
    fi

    local unit
    for unit in fips.service fips-dns.service; do
        if cexec "$name" test -f "/usr/lib/systemd/system/$unit"; then
            fail "$unit survived the erase"
        else
            pass "$unit removed"
        fi
    done

    local leftover=0 f
    for f in /etc/systemd/resolved.conf.d/fips.conf \
             /etc/systemd/dns-delegate.d/fips.dns-delegate \
             /etc/dnsmasq.d/fips.conf \
             /etc/NetworkManager/dnsmasq.d/fips.conf; do
        if cexec "$name" test -f "$f"; then
            fail "$f survived the erase"
            leftover=$((leftover + 1))
        fi
    done
    [ "$leftover" -eq 0 ] && pass "all four DNS drop-ins removed on erase"

    # The other half of having no purge: what must NOT be removed.
    if cexec "$name" test -f /etc/fips/fips.yaml; then
        pass "/etc/fips/fips.yaml kept (an erase must not take the node's identity)"
    else
        fail "/etc/fips/fips.yaml removed by the erase"
    fi
    return 0
}

# --- Scenarios ------------------------------------------------------------

# A distribution with a resolver, which is every install-suite leg on the
# Debian side too: they install systemd-resolved into the runtime image.
_run_install_scenario() {
    local label="$1" base_image="$2"
    local name="fips-rpm-test-${label}${FIPS_CI_NAME_SUFFIX:-}"
    local image="fips-rpm-test:${label}"

    log "RPM install: ${base_image}"
    boot_scenario "$name" "$image" "$base_image" resolver || return

    if install_package "$name"; then
        check_installed_state "$name"
        if start_and_identify "$name"; then
            check_resolution "$name"
        fi
        check_erase "$name"
    fi
    cleanup_container "$name"
}

test_almalinux9() { _run_install_scenario almalinux9 "$EL9_IMAGE"; }
test_fedora()     { _run_install_scenario fedora "$FEDORA_IMAGE"; }

# A stock EL9 host: no systemd-resolved, no dnsmasq, NetworkManager not
# configured for dnsmasq. No backend applies, and the documented outcome is a
# node that runs with .fips resolution absent -- not a failed unit. This pins
# that, because it is what an operator meets on a default install and nothing
# else in the tree asserts it.
test_no_resolver() {
    local name="fips-rpm-test-no-resolver${FIPS_CI_NAME_SUFFIX:-}"
    local image="fips-rpm-test:no-resolver"

    log "RPM install: ${EL9_IMAGE} with no resolver backend available"
    boot_scenario "$name" "$image" "$EL9_IMAGE" bare || return

    if install_package "$name"; then
        start_unit "$name" fips.service || true
        start_unit_queued "$name" fips-dns.service || true

        if wait_for_service_active "$name" fips.service; then
            pass "fips.service active without any resolver backend"
        else
            fail "fips.service did not start"
        fi

        # Type=oneshot + RemainAfterExit=yes + `exit 0` on the last branch, so
        # the unit settles active even though it configured nothing.
        if wait_for_service_active "$name" fips-dns.service; then
            pass "fips-dns.service reports active (exited) with nothing configured"
        else
            fail "fips-dns.service is '$(cexec "$name" systemctl is-active fips-dns.service 2>/dev/null)' (expected 'active')"
        fi

        local backend
        backend=$(cexec "$name" cat /run/fips/dns-backend 2>/dev/null || echo "(missing)")
        if [ "$backend" = "none" ]; then
            pass "saved backend is 'none'"
        else
            fail "saved backend is '$backend' (expected 'none')"
        fi

        if cexec "$name" journalctl -u fips-dns.service --no-pager 2>&1 \
            | grep -q "No supported DNS resolver detected"; then
            pass "journal carries the no-resolver warning"
        else
            fail "no-resolver warning missing from the journal"
        fi

        # Nothing configured means nothing written.
        local wrote=0 f
        for f in /etc/systemd/resolved.conf.d/fips.conf \
                 /etc/systemd/dns-delegate.d/fips.dns-delegate \
                 /etc/dnsmasq.d/fips.conf \
                 /etc/NetworkManager/dnsmasq.d/fips.conf; do
            if cexec "$name" test -f "$f"; then
                fail "$f was written with no backend detected"
                wrote=$((wrote + 1))
            fi
        done
        [ "$wrote" -eq 0 ] && pass "no resolver configuration written"

        # The mesh itself is unaffected, which is the point of calling this
        # documented rather than broken.
        if cexec "$name" ip link show fips0 >/dev/null 2>&1; then
            pass "fips0 is up: the node works, only .fips names do not resolve"
        else
            fail "fips0 missing"
        fi
    fi
    cleanup_container "$name"
}

# The package this run built, repacked at a higher Release from the same
# binaries, so the upgrade runs this tree's scriptlets without a second
# compile. With --rpm, the binaries are taken back out of the given package.
make_next_package() {
    local bin_dir="$CACHE_DIR/bin" next_dir="$CACHE_DIR/next"
    rm -rf "$next_dir"
    mkdir -p "$next_dir" "$bin_dir"

    if [ ! -x "$bin_dir/fips" ]; then
        if ! docker run --rm \
            -v "$(dirname "$RPM_PATH")":/rpm:ro -v "$bin_dir":/bin-out \
            -e "HOST_UID=$(id -u)" -e "HOST_GID=$(id -g)" \
            "$FIPS_RPM_BUILD_IMAGE" bash -euo pipefail -c "
                dnf install -y -q --setopt=install_weak_deps=False cpio >/dev/null
                cd \$(mktemp -d)
                rpm2cpio /rpm/$(basename "$RPM_PATH") | cpio -idm --quiet
                for binary in fips fipsctl fipstop fips-gateway; do
                    install -m 0755 usr/bin/\$binary /bin-out/\$binary
                done
                chown \"\$HOST_UID:\$HOST_GID\" /bin-out/*
            " >&2; then
            return 1
        fi
    fi

    # Release 999 sorts above any dev Release (0.dev...) and any tag's 1.
    local version
    version=$(rpm -qp --queryformat '%{VERSION}' "$RPM_PATH" 2>/dev/null \
        || awk -F'"' '/^version = /{print $2; exit}' "$REPO_ROOT/Cargo.toml" | sed 's/-dev$//')
    NEXT_RPM=$("$REPO_ROOT/packaging/rpm/build-rpm-container.sh" \
        --no-build --bin-dir "$bin_dir" --version "${version}-999" \
        --output-dir "$next_dir" | tail -n 1)
    [ -n "$NEXT_RPM" ] && [ -f "$NEXT_RPM" ]
}

# A running daemon upgraded in place. %postun of the *old* package is what
# restarts it, so this is also the check that the first published RPM gets it
# right: an upgrade is only as good as the scriptlet it upgrades away from.
test_upgrade() {
    local name="fips-rpm-test-upgrade${FIPS_CI_NAME_SUFFIX:-}"
    local image="fips-rpm-test:upgrade"

    log "RPM upgrade: ${EL9_IMAGE}"
    if ! make_next_package; then
        fail "could not build the higher-Release package for the upgrade"
        return
    fi
    boot_scenario "$name" "$image" "$EL9_IMAGE" resolver || return
    install_package "$name" || { cleanup_container "$name"; return; }

    start_unit "$name" fips.service || true
    if ! wait_for_service_active "$name" fips.service; then
        fail "fips.service did not start before the upgrade"
        cleanup_container "$name"
        return
    fi
    local pid_before
    pid_before=$(cexec "$name" systemctl show fips.service -p MainPID --value)

    # The timing check below only bites when the restart is slow, which a
    # healthy daemon's is not: a blocking try-restart of a daemon that comes
    # straight back finishes in seconds too. What makes the transaction safe
    # is the --no-block in the scriptlet that runs on upgrade -- the installed
    # package's %postun -- so assert that directly.
    if cexec "$name" rpm -q --scripts fips-mesh 2>/dev/null \
        | grep -q 'systemctl --no-block try-restart'; then
        pass "installed %postun queues the restart (--no-block)"
    else
        fail "installed %postun does not queue the restart with --no-block"
    fi

    # An operator's edit, which must survive.
    cexec "$name" sh -c 'echo "# operator edit" >> /etc/fips/fips.yaml'

    local next_basename
    next_basename=$(basename "$NEXT_RPM")
    timeout "$EXEC_TIMEOUT" docker cp "$NEXT_RPM" "$name:/opt/fips-rpm/$next_basename"

    local rc=0 out start=$SECONDS secs
    out=$(timeout "$UPGRADE_DNF_TIMEOUT" docker exec -w /opt/fips-rpm "$name" \
        dnf upgrade -y --setopt=install_weak_deps=False "./$next_basename" 2>&1) || rc=$?
    secs=$((SECONDS - start))
    echo "  upgrade took ${secs}s"
    if [ "$rc" -ne 0 ]; then
        fail "dnf upgrade exited $rc"
        echo "$out" | tail -15
        cleanup_container "$name"
        return
    fi
    pass "dnf upgrade completed"

    # The restart is queued with --no-block; a transaction that waits on it
    # would take at least fips-dns-setup's interface wait.
    if [ "$secs" -le "$UPGRADE_TRANSACTION_CEILING" ]; then
        pass "upgrade transaction did not wait on the restart (${secs}s)"
    else
        fail "upgrade transaction took ${secs}s (ceiling ${UPGRADE_TRANSACTION_CEILING}s)"
    fi

    # The queued restart lands after dnf returns.
    local pid_after="" _
    for _ in $(seq 1 30); do
        pid_after=$(cexec "$name" systemctl show fips.service -p MainPID --value 2>/dev/null)
        if [ -n "$pid_after" ] && [ "$pid_after" != "0" ] && [ "$pid_after" != "$pid_before" ]; then
            break
        fi
        sleep 1
    done
    if [ "$pid_after" != "$pid_before" ] && [ "$pid_after" != "0" ]; then
        pass "daemon restarted onto the new package (MainPID $pid_before -> $pid_after)"
    else
        fail "daemon was not restarted (MainPID $pid_before -> $pid_after)"
    fi

    local gw
    gw=$(cexec "$name" systemctl is-enabled fips-gateway.service 2>/dev/null || true)
    if [ "$gw" = "disabled" ]; then
        pass "fips-gateway not opted in by the upgrade"
    else
        fail "fips-gateway is '$gw' after the upgrade (expected 'disabled')"
    fi

    if cexec "$name" grep -q "^# operator edit" /etc/fips/fips.yaml; then
        pass "operator edit to fips.yaml survived the upgrade"
    else
        fail "operator edit to fips.yaml lost in the upgrade"
    fi

    if cexec "$name" sh -c 'ls /etc/fips/*.rpmnew /etc/fips/*.rpmsave' >/dev/null 2>&1; then
        fail "the upgrade left .rpmnew or .rpmsave files in /etc/fips"
    else
        pass "no .rpmnew or .rpmsave left in /etc/fips"
    fi
    cleanup_container "$name"
}

# --- Main -----------------------------------------------------------------

SCENARIOS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --rpm) RPM_PATH="$(cd "$(dirname "${2:?missing value for --rpm}")" && pwd)/$(basename "$2")"; shift 2 ;;
        --deb) DEB_PATH="$(cd "$(dirname "${2:?missing value for --deb}")" && pwd)/$(basename "$2")"; shift 2 ;;
        -h | --help) sed -n '2,35p' "$0"; exit 0 ;;
        *) SCENARIOS+=("$1"); shift ;;
    esac
done
[ ${#SCENARIOS[@]} -eq 0 ] && read -ra SCENARIOS <<<"$ALL_SCENARIOS"

build_rpm || { echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"; exit 1; }

for scenario in "${SCENARIOS[@]}"; do
    case "$scenario" in
        almalinux9) test_almalinux9 ;;
        fedora) test_fedora ;;
        no-resolver) test_no_resolver ;;
        upgrade) test_upgrade ;;
        *) fail "unknown scenario: $scenario (have: $ALL_SCENARIOS)" ;;
    esac
done

echo ""
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
