#!/bin/bash
# Test the systemd tarball's install.sh as an upgrade, under real systemd.
#
# fips-dns.service and fips-gateway.service carry Requires=fips.service, so
# stopping fips stops both. An upgrade that checks which units are running
# only after stopping fips sees the other two as already stopped, and starts
# fips alone again. This suite installs the tarball once, puts the units in a
# known state, runs install.sh a second time (the upgrade), and checks that
# exactly the units that were running before are running after.
#
# The tarball is staged from the real packaging/systemd/install.sh and unit
# files, and the real packaging/common configuration, the same file set
# build-tarball.sh ships. The binaries and DNS helpers are stubs: the fips and
# fips-gateway stubs sleep, so their units stay active, and the DNS helpers
# exit 0. What is under test is install.sh against real units and a real
# systemd, which carries the Requires= stop propagation; nothing here depends
# on what the binaries do.
#
# Scenarios, each on a fresh container:
#   all-active  fips, fips-dns and fips-gateway running before the upgrade.
#               All three must be running after it, and fips must have been
#               restarted (its InvocationID changes).
#   fips-only   only fips running. fips must be running after, and the other
#               two must still be stopped.
#   none-active nothing running. Nothing may be running after.
#
# Usage: ./test.sh [--install-sh PATH] [scenario ...]
#   No scenarios = run all of them.
#   --install-sh PATH runs another install.sh in place of the tree's, so the
#   suite can be pointed at an older script without editing the tree.
#
# Requirements: Docker able to grant SYS_ADMIN and NET_ADMIN and an unconfined
# AppArmor profile (the container is not privileged; see
# testing/lib/systemd-container.sh), and /dev/net/tun on the host.
#
# Exit 0 only when every check passed. A container that cannot boot or be
# inspected is a FAIL, never a skip.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=SCRIPTDIR/../lib/systemd-container.sh
source "$SCRIPT_DIR/../lib/systemd-container.sh"
# shellcheck source=SCRIPTDIR/../lib/image-build.sh
source "$SCRIPT_DIR/../lib/image-build.sh"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

IMAGE="fips-tarball-test:debian12"
BOOT_TIMEOUT=60
# Bounds one install.sh run. It starts at most three units, whose programs here
# are stubs, so none of them waits for anything before it is started.
INSTALL_TIMEOUT=120
UNIT_START_TIMEOUT=60
TARBALL_DIR=/opt/fips-tarball

PASS=0
FAIL=0

INSTALL_SH="$REPO_ROOT/packaging/systemd/install.sh"
STAGE=""

log()  { echo "=== $*"; }
pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }

# Remove a container, ignoring one that does not exist.
cleanup_container() {
    local name="$1"
    docker rm -f "$name" >/dev/null 2>&1 || true
}

# Remove every scenario's container and the staged tarball.
cleanup_all() {
    local s
    for s in $ALL_SCENARIOS; do
        cleanup_container "$(container_name "$s")"
    done
    [ -n "$STAGE" ] && rm -rf "$STAGE"
}

# The container name for a scenario, scoped to this CI run.
container_name() {
    echo "fips-tarball-test-$1${FIPS_CI_NAME_SUFFIX:-}"
    return 0
}

# Build the systemd image. The build context is an empty directory: the
# tarball is copied into the container after it starts, not baked in.
build_image() {
    local ctx rc=0
    ctx=$(mktemp -d)
    retry_build "docker build -t $IMAGE" build_inline "$IMAGE" "$(cat <<'DOCKERFILE'
FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd iproute2 procps && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
CMD ["/lib/systemd/systemd"]
DOCKERFILE
    )" "$ctx" || rc=$?
    rm -rf "$ctx"
    return "$rc"
}

# Stage a tarball directory: the real install script, units and configuration,
# with stub binaries and DNS helpers.
stage_tarball() {
    local f
    STAGE=$(mktemp -d)
    cp "$INSTALL_SH" "$STAGE/install.sh" || return 1
    for f in fips.service fips-dns.service fips-gateway.service fips-firewall.service; do
        cp "$REPO_ROOT/packaging/systemd/$f" "$STAGE/" || return 1
    done
    for f in fips.yaml hosts fips.nft; do
        cp "$REPO_ROOT/packaging/common/$f" "$STAGE/" || return 1
    done
    printf '#!/bin/sh\nexec sleep infinity\n' > "$STAGE/fips"
    printf '#!/bin/sh\nexec sleep infinity\n' > "$STAGE/fips-gateway"
    printf '#!/bin/sh\nexit 0\n' > "$STAGE/fipsctl"
    printf '#!/bin/sh\nexit 0\n' > "$STAGE/fips-dns-setup"
    printf '#!/bin/sh\nexit 0\n' > "$STAGE/fips-dns-teardown"
    chmod 0755 "$STAGE"/install.sh "$STAGE"/fips "$STAGE"/fips-gateway \
        "$STAGE"/fipsctl "$STAGE"/fips-dns-setup "$STAGE"/fips-dns-teardown
    return 0
}

# Start the scenario's systemd container. Not privileged: see
# testing/lib/systemd-container.sh for the flags and why. The TUN device is
# passed so the scenario can create a fips0. fips-gateway.service no longer
# needs it, since the gateway here is a stub that does not look for the TUN; it
# is kept because it is harmless and matches a host the daemon has started on.
start_container() {
    local name="$1"
    cleanup_container "$name"
    run_quiet "docker run $name" \
        docker run -d --name "$name" \
        "${CI_LABELS[@]}" \
        "${SYSTEMD_CAPS[@]}" \
        --cgroupns=host \
        --device /dev/net/tun \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock \
        "$IMAGE" || return
    check_isolation "$name"
    return
}

# Wait for systemd to finish booting. `degraded` counts as booted: units such
# as systemd-modules-load cannot succeed in a container, and the system still
# finished starting. The state string is tested directly rather than piped, so
# pipefail cannot turn a degraded boot into a failure.
wait_for_systemd() {
    local name="$1" state
    for _i in $(seq 1 "$BOOT_TIMEOUT"); do
        state=$(systemd_state "$name")
        case "$state" in
            running | degraded) return 0 ;;
        esac
        sleep 1
    done
    echo "  ERROR: systemd did not reach running state in ${BOOT_TIMEOUT}s" >&2
    return 1
}

# Run the staged install.sh in the container, under a bound.
run_install() {
    local name="$1" label="$2" out rc=0
    out=$(timeout "$INSTALL_TIMEOUT" docker exec "$name" "$TARBALL_DIR/install.sh" 2>&1) || rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "$label: install.sh exited $rc"
        echo "$out" | sed 's/^/    /'
        return 1
    fi
    pass "$label: install.sh exits 0"
    return 0
}

# Print a unit's active state ("unknown" when the container cannot be asked).
unit_state() {
    local name="$1" unit="$2" state
    state=$(docker exec "$name" systemctl is-active "$unit" 2>/dev/null)
    echo "${state:-unknown}"
    return 0
}

# Print a unit's InvocationID, which changes on every start.
invocation_id() {
    docker exec "$1" systemctl show -p InvocationID --value "$2" 2>/dev/null
    return
}

# Record a PASS when a unit is in the wanted state, a FAIL otherwise.
expect_state() {
    local name="$1" label="$2" unit="$3" want="$4" got
    got=$(unit_state "$name" "$unit")
    if [ "$got" = "$want" ]; then
        pass "$label: $unit is $got"
    else
        fail "$label: $unit is $got (want $want)"
    fi
    return 0
}

# Start a unit under a bound, recording a FAIL when it does not start.
start_unit() {
    local name="$1" unit="$2" out
    if ! out=$(timeout "$UNIT_START_TIMEOUT" docker exec "$name" systemctl start "$unit" 2>&1); then
        fail "setup: could not start $unit: ${out:-no output}"
        return 1
    fi
    return 0
}

# Boot a fresh container, copy the tarball in and run the first install.
# Returns 1, having recorded a FAIL, when any of that does not happen.
prepare() {
    local name="$1" label="$2"
    start_container "$name" || { fail "$label: container did not start"; return 1; }
    wait_for_systemd "$name" || {
        fail "$label: systemd did not boot; the checks would read an unstarted system"
        return 1
    }
    if ! docker cp "$STAGE/." "$name:$TARBALL_DIR" >/dev/null; then
        fail "$label: could not copy the tarball into $name"
        return 1
    fi
    if ! docker exec "$name" ip tuntap add fips0 mode tun >/dev/null 2>&1; then
        fail "$label: could not create fips0 in $name"
        return 1
    fi
    run_install "$name" "$label: first install" || return 1
    return 0
}

scenario_all_active() {
    local label="all-active" name before after
    name=$(container_name "$label")
    log "$label: fips, fips-dns and fips-gateway running before the upgrade"
    if prepare "$name" "$label" \
        && start_unit "$name" fips.service \
        && start_unit "$name" fips-dns.service \
        && start_unit "$name" fips-gateway.service; then
        expect_state "$name" "$label: before" fips.service active
        expect_state "$name" "$label: before" fips-dns.service active
        expect_state "$name" "$label: before" fips-gateway.service active
        before=$(invocation_id "$name" fips.service)
        if run_install "$name" "$label: upgrade"; then
            expect_state "$name" "$label: after" fips.service active
            expect_state "$name" "$label: after" fips-dns.service active
            expect_state "$name" "$label: after" fips-gateway.service active
            after=$(invocation_id "$name" fips.service)
            if [ -z "$before" ] || [ -z "$after" ]; then
                fail "$label: could not read fips.service's InvocationID (before '${before}', after '${after}')"
            elif [ "$before" != "$after" ]; then
                pass "$label: the upgrade restarted fips.service"
            else
                fail "$label: fips.service kept InvocationID $before, so the upgrade did not stop and restart it"
            fi
        fi
    fi
    cleanup_container "$name"
    return 0
}

scenario_fips_only() {
    local label="fips-only" name
    name=$(container_name "$label")
    log "$label: only fips running before the upgrade"
    if prepare "$name" "$label" && start_unit "$name" fips.service; then
        expect_state "$name" "$label: before" fips.service active
        expect_state "$name" "$label: before" fips-dns.service inactive
        expect_state "$name" "$label: before" fips-gateway.service inactive
        if run_install "$name" "$label: upgrade"; then
            expect_state "$name" "$label: after" fips.service active
            expect_state "$name" "$label: after" fips-dns.service inactive
            expect_state "$name" "$label: after" fips-gateway.service inactive
        fi
    fi
    cleanup_container "$name"
    return 0
}

scenario_none_active() {
    local label="none-active" name
    name=$(container_name "$label")
    log "$label: nothing running before the upgrade"
    if prepare "$name" "$label"; then
        expect_state "$name" "$label: before" fips.service inactive
        if run_install "$name" "$label: upgrade"; then
            expect_state "$name" "$label: after" fips.service inactive
            expect_state "$name" "$label: after" fips-dns.service inactive
            expect_state "$name" "$label: after" fips-gateway.service inactive
        fi
    fi
    cleanup_container "$name"
    return 0
}

ALL_SCENARIOS="all-active fips-only none-active"

_args=()
while [ $# -gt 0 ]; do
    case "$1" in
        --install-sh)
            INSTALL_SH="${2:?--install-sh requires a path}"
            shift 2
            ;;
        -h|--help)
            echo "usage: test.sh [--install-sh PATH] [scenario ...]"
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
    case " $ALL_SCENARIOS " in
        *" $scenario "*) ;;
        *)
            echo "Unknown scenario: $scenario (available: $ALL_SCENARIOS)" >&2
            exit 1
            ;;
    esac
done

if [ ! -f "$INSTALL_SH" ]; then
    echo "install script not found: $INSTALL_SH" >&2
    exit 1
fi

trap cleanup_all EXIT

log "Building $IMAGE"
if ! build_image; then
    fail "image build failed"
elif ! stage_tarball; then
    fail "could not stage the tarball"
else
    for scenario in $scenarios; do
        case "$scenario" in
            all-active) scenario_all_active ;;
            fips-only) scenario_fips_only ;;
            none-active) scenario_none_active ;;
        esac
        echo
    done
fi

echo "═══════════════════════════════════════"
echo "Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════"

[ "$FAIL" -eq 0 ] && [ "$PASS" -gt 0 ]
