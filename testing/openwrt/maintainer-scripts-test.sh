#!/bin/bash
# ── OpenWrt maintainer-script scenarios ─────────────────────────────────────
# Runs testing/openwrt/scenarios.sh inside a busybox container, so the package
# scripts and the fips-gateway init script are interpreted by ash rather than
# by the host's bash or dash. The scripts ship to routers and are only ever run
# under ash there; a construct bash accepts and ash does not would otherwise
# surface on a router.
#
# Then runs testing/openwrt/firewall-scenarios.sh in four pinned OpenWrt
# rootfs images, which carry the real uci, fw4 and nft, so 90-fips-setup's
# firewall zone and upgrade migration run against the firewall they configure.
# Those containers get NET_ADMIN so fw4 can load its table, into the
# container's own network namespace; they have no network otherwise. Each also
# gets a small tmpfs, where the cases that save onto a full overlay put
# /etc/config.
#
# No FIPS binary and no shared test image are used.
#
# Exit 0 = every scenario passed. Exit 1 = at least one failed. Exit 2 = the
# harness could not run; never treated as a pass. The firewall runs go ahead
# when the busybox run failed, and the worst code of all the runs is returned.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Pinned by digest so the shell under test does not change under a run: the
# 1.37 tag moves with every 1.37.x rebuild. This is the multi-arch index digest
# of busybox:1.37.0 as of 2026-10-01. Bump it deliberately, reading the new
# digest with `docker buildx imagetools inspect busybox:<version>`.
# Overridable for trying another ash build.
IMAGE="${OPENWRT_ASH_IMAGE:-busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e}"

# The OpenWrt releases the package supports, each pinned by digest as of
# 2026-10-10 and read the same way (25.12.5 is published as a single manifest,
# the others as multi-arch indexes). The two older releases run a subset of the
# cases to keep the job's time: an upgrade, a fresh install, port-forward
# scoping, a failed reload and its recovery, an unloaded firewall, and a save
# onto a full overlay, which matters most on 22.03, whose default input policy
# is ACCEPT.
FW_OLDER_CASES="fw_upgrade_moves_fips0_into_its_own_zone fw_fresh_install_creates_live_zone fw_operator_scoping_renders_before_port_forwards fw_failed_reload_blocks_new_fips0_connections fw_recovery_after_failed_reload_clears_block fw_unloaded_firewall_is_reported fw_full_overlay_save_blocks_and_keeps_setup"
FW_IMAGES=(
    "openwrt/rootfs:x86-64-25.12.5@sha256:c5d5f05bab4ce06a4e840b3573671a06ec8ae9842273188ffc53f7021836b8e2|"
    "openwrt/rootfs:x86-64-24.10.8@sha256:9972a4b4747cd136abd597475d7b88c51a49fd849d0d53f069a2f4bf446061b9|"
    "openwrt/rootfs:x86-64-23.05.6@sha256:f53afb386d05651ada9a4a964e0779930f30962a2abc2fadf1b03bfcbcbabb14|$FW_OLDER_CASES"
    "openwrt/rootfs:x86-64-22.03.7@sha256:f6e5b98399ae4ff89fc1a2de2da5b94c520c8f82aa1e5c717fb190da8b3313ed|$FW_OLDER_CASES"
)

if ! command -v docker >/dev/null 2>&1; then
    echo "openwrt-scripts: docker not found; cannot run the ash scenarios" >&2
    exit 2
fi

for f in scenarios.sh firewall-scenarios.sh; do
    if [[ ! -f "$SCRIPT_DIR/$f" ]]; then
        echo "openwrt-scripts: missing $SCRIPT_DIR/$f" >&2
        exit 2
    fi
done

# Each image is pulled once, with a few attempts, so a registry outage reads as
# the harness not running rather than as a failed case.
pull() {
    local attempt
    for attempt in 1 2 3; do
        docker pull -q "$1" >/dev/null && return 0
        echo "openwrt-scripts: pulling $1 failed (attempt $attempt)" >&2
        [[ $attempt -lt 3 ]] && sleep 5
    done
    return 1
}
pull_started=$SECONDS
for spec in "$IMAGE" "${FW_IMAGES[@]}"; do
    image="${spec%%|*}"
    if ! pull "$image"; then
        echo "openwrt-scripts: could not pull $image" >&2
        exit 2
    fi
done
echo "openwrt-scripts: images ready in $((SECONDS - pull_started))s"

# The .apk wraps the shared bodies for its upgrade path. package-test.sh builds
# the package on the host with the real build-apk.sh, checks what it registers,
# and leaves the four scripts here so the scenarios run exactly what ships.
# The directory is bind-mounted into the container, so it is made by
# shared_tmpdir under the checkout, not /tmp; testing/lib/image-build.sh says
# why. --sweep clears what a killed run left behind.
# shellcheck source=SCRIPTDIR/../lib/image-build.sh
. "$SCRIPT_DIR/../lib/image-build.sh"
APK_DIR="$(shared_tmpdir --sweep "$PROJECT_ROOT/target" openwrt-apk)" || {
    echo "openwrt-scripts: could not create a temporary directory under $PROJECT_ROOT/target" >&2
    exit 2
}
trap 'rm -rf "$APK_DIR"' EXIT
bash "$SCRIPT_DIR/package-test.sh" --keep "$APK_DIR"
rc=$?
if [[ $rc -ne 0 ]]; then
    echo "openwrt-scripts: package-test.sh exited $rc" >&2
    exit $rc
fi

docker run --rm --network none \
    -v "$PROJECT_ROOT:/src:ro" \
    -v "$APK_DIR:/apk:ro" \
    -e REPO=/src \
    -e APK_SCRIPTS=/apk \
    -e "POSTINST=${POSTINST:-}" \
    -e "PRERM=${PRERM:-}" \
    -e "PREINST=${PREINST:-}" \
    -e "INIT_GATEWAY=${INIT_GATEWAY:-}" \
    "$IMAGE" sh /src/testing/openwrt/scenarios.sh
rc=$?

if [[ $rc -ne 0 && $rc -ne 1 ]]; then
    echo "openwrt-scripts: the container exited $rc, so the scenarios did not report" >&2
    rc=2
fi
worst=$rc

# FW_SETUP and FW_SNIPPETS pass through from the caller when set, to run the
# firewall scenarios against another setup script or without the snippets.
for spec in "${FW_IMAGES[@]}"; do
    image="${spec%%|*}"
    cases="${spec#*|}"
    fw_env=(-e FW_SETUP -e FW_SNIPPETS)
    if [[ -n "$cases" ]]; then
        fw_env+=(-e "FW_CASES=$cases")
    else
        fw_env+=(-e FW_CASES)
    fi
    echo "==> firewall scenarios in $image"
    docker run --rm --network none --cap-add NET_ADMIN \
        --tmpfs /fw-small:size=128k \
        -v "$PROJECT_ROOT:/src:ro" \
        -v "$APK_DIR:/apk:ro" \
        "${fw_env[@]}" \
        "$image" sh /src/testing/openwrt/firewall-scenarios.sh
    rc=$?
    if [[ $rc -ne 0 && $rc -ne 1 ]]; then
        echo "openwrt-scripts: the $image container exited $rc, so its firewall scenarios did not report" >&2
        rc=2
    fi
    [[ $rc -gt $worst ]] && worst=$rc
done

echo "openwrt-scripts: finished in ${SECONDS}s, exit $worst"
exit $worst
