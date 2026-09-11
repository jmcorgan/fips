#!/bin/bash
# Shared flags and isolation check for test containers that boot systemd.
#
# Source this file from a harness one level under testing/:
#   source "$SCRIPT_DIR/../lib/systemd-container.sh"
#   docker run -d ... "${SYSTEMD_CAPS[@]}" ... "$image"
#   check_isolation "$name"
#
# check_isolation reports through the harness's own pass() and fail(), so
# those must be defined before it is called.
#
# Why these containers are not started with --privileged: a privileged
# container sees the host's real VT and serial devices (/dev/tty0, /dev/tty1,
# /dev/ttyS0, ...) and a writable /proc/sys and /sys. The systemd inside the
# image treats them as its own, so it starts a getty on the host's console,
# where each side's hangup kills the other's getty until the host's unit hits
# its start limit and the machine is left with no console login; logind holds
# a host VT open; and systemd-sysctl applies the image's sysctl.d to the host's
# kernel parameters. Some images also set up the host's virtual consoles and
# run a udev coldplug against the host's /sys.
#
# Without --privileged, docker gives the container only its default /dev and
# mounts /proc/sys and /sys read-only, so those units skip on their own
# conditions. That removes the console and kernel-parameter reach; it does not
# seal the container off from the host. systemd still mounts the host's fusectl
# and a hugetlbfs, and SYS_ADMIN would let a process inside remount /proc/sys
# read-write, which nothing in these images does.
#
# What each flag is for:
#   --cap-add SYS_ADMIN   mount namespaces for unit sandboxing (PrivateTmp,
#                         ProtectHome, ProtectKernelModules in the fips units,
#                         and the sandboxing resolved and logind carry)
#   --cap-add NET_ADMIN   TUN and dummy fips0 links, and nftables and neighbour
#                         proxy entries in the container's own network namespace
#   --security-opt apparmor=unconfined
#                         the default AppArmor profile denies the mounts systemd
#                         makes for that sandboxing; without it boot ends
#                         degraded with logind and resolved failed. Needed on
#                         AppArmor hosts, which include Ubuntu hosts and
#                         GitHub's ubuntu-latest runners.
# shellcheck disable=SC2034  # read by the sourcing harness, not within this file
SYSTEMD_CAPS=(
    --cap-add SYS_ADMIN
    --cap-add NET_ADMIN
    --security-opt apparmor=unconfined
)

# Fail the suite if a running container can reach the host console or write
# the host's kernel parameters.
#
# Device nodes and mount modes are fixed when the container is created, so one
# look straight after `docker run` is enough; a remount made later from inside
# is out of its reach. The probe prints a marker first and exits 0, so the
# exec's status says only whether the probe ran: a container that could not be
# inspected is a failure, never a pass. On any failure the container is
# removed at once, so a privileged container does not live on to reach the
# host's console.
#
# Returns 0 when the container is isolated, 1 otherwise.
check_isolation() {
    local name="$1" out findings
    if ! out=$(docker exec "$name" sh -c '
        echo ISOLATION-PROBE
        for d in /dev/tty[0-9]* /dev/ttyS[0-9]* /dev/console; do
            [ -e "$d" ] && echo "device $d"
        done
        [ -w /proc/sys/kernel/core_pattern ] && echo "writable /proc/sys"
        [ -w /sys/kernel ] && echo "writable /sys"
        exit 0' 2>&1); then
        fail "isolation: could not inspect $name: ${out:-no output}"
        docker rm -f "$name" >/dev/null 2>&1 || true
        return 1
    fi
    case $'\n'"$out" in
        *$'\n'ISOLATION-PROBE*) ;;
        *)
            fail "isolation: probe of $name printed no marker: ${out:-no output}"
            docker rm -f "$name" >/dev/null 2>&1 || true
            return 1
            ;;
    esac
    findings=${out#*ISOLATION-PROBE}
    findings=${findings#$'\n'}
    if [ -n "$findings" ]; then
        fail "isolation: $name reaches the host: ${findings//$'\n'/, }"
        docker rm -f "$name" >/dev/null 2>&1 || true
        return 1
    fi
    pass "isolation: $name has no host console devices and read-only /proc/sys and /sys"
    return 0
}
