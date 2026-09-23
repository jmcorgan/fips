#!/bin/bash
# ── OpenWrt maintainer-script scenarios ─────────────────────────────────────
# Runs testing/openwrt/scenarios.sh inside a busybox container, so the package
# scripts and the fips-gateway init script are interpreted by ash rather than
# by the host's bash or dash. The scripts ship to routers and are only ever run
# under ash there; a construct bash accepts and ash does not would otherwise
# surface on a router.
#
# The container is the only reason docker is needed: the scenarios touch no
# network and no FIPS binary, and they do not use the shared test image.
#
# Exit 0 = every scenario passed. Exit 1 = at least one failed. Exit 2 = the
# harness could not run; never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Pinned rather than :latest so the shell under test does not change under a
# run. Overridable for trying another ash build.
IMAGE="${OPENWRT_ASH_IMAGE:-busybox:1.37}"

if ! command -v docker >/dev/null 2>&1; then
    echo "openwrt-scripts: docker not found; cannot run the ash scenarios" >&2
    exit 2
fi

if [[ ! -f "$SCRIPT_DIR/scenarios.sh" ]]; then
    echo "openwrt-scripts: missing $SCRIPT_DIR/scenarios.sh" >&2
    exit 2
fi

# The .apk wraps the shared bodies for its upgrade path. package-test.sh builds
# the package on the host with the real build-apk.sh, checks what it registers,
# and leaves the four scripts here so the scenarios run exactly what ships.
APK_DIR="$(mktemp -d)" || { echo "openwrt-scripts: mktemp failed" >&2; exit 2; }
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
    "$IMAGE" sh /src/testing/openwrt/scenarios.sh
rc=$?

if [[ $rc -ne 0 && $rc -ne 1 ]]; then
    echo "openwrt-scripts: the container exited $rc, so the scenarios did not report" >&2
    exit 2
fi
exit $rc
