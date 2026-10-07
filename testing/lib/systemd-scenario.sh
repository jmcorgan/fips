#!/bin/bash
# Container plumbing for the package install suites (deb-install, rpm-install):
# start a systemd container with TUN access, wait for it to boot, start units
# under a bound, and run short commands in it under a bound.
#
# Source this after systemd-container.sh and image-build.sh, from a harness one
# level under testing/:
#   source "$SCRIPT_DIR/../lib/systemd-container.sh"
#   source "$SCRIPT_DIR/../lib/systemd-scenario.sh"
#   source "$SCRIPT_DIR/../lib/image-build.sh"
#
# The caller defines the bounds these read, so each suite keeps its own:
#   REPO_ROOT           build context for build_image
#   BOOT_TIMEOUT        seconds wait_for_systemd waits for running/degraded
#   SERVICE_TIMEOUT     default seconds wait_for_service_active waits
#   UNIT_START_TIMEOUT  bound on start_unit and start_unit_queued
#   EXEC_TIMEOUT        bound on cexec
#
# Kept out of systemd-container.sh on purpose. dns-resolver and tarball-install
# source that file and define their own cleanup_container, build_image,
# wait_for_systemd and start_unit after it, several of which differ from these.
# Defined there, these would be silently shadowed in those suites and read as
# shared when they are not.

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

# Run a short command in a container under EXEC_TIMEOUT.
cexec() {
    local name="$1"
    shift
    timeout "$EXEC_TIMEOUT" docker exec "$name" "$@"
    return
}
