#!/bin/bash
# Reap FIPS CI docker resources: containers, networks, volumes, images.
#
# Force-removes everything created by ci-local.sh that is still around —
# whether a run finished cleanly, was preempted (SIGTERM/SIGKILL), OOM-killed,
# or crashed. Two complementary selectors make this robust no matter how a
# prior run died:
#
#   1. The CI label  com.corganlabs.fips-ci=1  (attached to every direct
#      `docker run`/network/volume ci-local drives).
#   2. The compose project-name prefix  fipsci_  (every compose project ci-local
#      starts is named  fipsci_<run-id>_<suite>, so its containers/networks/
#      volumes all carry  com.docker.compose.project=fipsci_...  and are named
#      with that prefix).
#
# Usage:
#   ci-cleanup.sh                       Reap ALL fips-ci resources (any run)
#   ci-cleanup.sh --project-prefix P    Restrict the compose-project sweep to
#                                       names starting with P (scopes the reap
#                                       to a single run; the label sweep still
#                                       runs)
#   ci-cleanup.sh --label L             Override the CI label (default above)
#   ci-cleanup.sh --images "a b,c"      Also `docker rmi -f` these image tags
#                                       (space- or comma-separated)
#
# Safe to run when there is nothing to reap, and safe to run repeatedly.
# Also reachable as `ci-local.sh --reap`.
set -uo pipefail

LABEL="com.corganlabs.fips-ci=1"
PROJECT_PREFIX="fipsci_"   # broad default: every CI run
IMAGES=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --label)          LABEL="$2"; shift 2 ;;
        --project-prefix) PROJECT_PREFIX="$2"; shift 2 ;;
        --images)         IMAGES="$2"; shift 2 ;;
        -h|--help)        sed -n '2,/^set /{ /^set /d; s/^# \?//; p }' "$0"; exit 0 ;;
        *)                echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    # No docker, nothing to reap.
    exit 0
fi
if ! docker info >/dev/null 2>&1; then
    # Daemon unreachable; treat as nothing to reap rather than wedging a caller.
    exit 0
fi

# Each docker mutation is wrapped in `timeout` so a stuck daemon/resource can
# never wedge a caller (ci-local's signal trap relies on this being bounded).
TMO=30

# Distinct compose project names (read off container labels) that start with
# the configured prefix.
ci_projects() {
    docker ps -a --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null \
        | grep -E "^${PROJECT_PREFIX}" | sort -u
}

reap_containers() {
    # By CI label.
    docker ps -aq --filter "label=${LABEL}" 2>/dev/null \
        | xargs -r timeout "$TMO" docker rm -f >/dev/null 2>&1 || true
    # By compose project (carried even when container_name is explicit).
    local p
    for p in $(ci_projects); do
        docker ps -aq --filter "label=com.docker.compose.project=${p}" 2>/dev/null \
            | xargs -r timeout "$TMO" docker rm -f >/dev/null 2>&1 || true
    done
}

reap_networks() {
    docker network ls -q --filter "label=${LABEL}" 2>/dev/null \
        | xargs -r timeout "$TMO" docker network rm >/dev/null 2>&1 || true
    # Compose networks are named  <project>_<net>  → match by name prefix so
    # orphaned networks (whose containers are already gone) are still caught.
    docker network ls --format '{{.Name}}' 2>/dev/null | grep -E "^${PROJECT_PREFIX}" \
        | xargs -r timeout "$TMO" docker network rm >/dev/null 2>&1 || true
}

reap_volumes() {
    docker volume ls -q --filter "label=${LABEL}" 2>/dev/null \
        | xargs -r timeout "$TMO" docker volume rm >/dev/null 2>&1 || true
    docker volume ls --format '{{.Name}}' 2>/dev/null | grep -E "^${PROJECT_PREFIX}" \
        | xargs -r timeout "$TMO" docker volume rm >/dev/null 2>&1 || true
}

reap_images() {
    [[ -z "$IMAGES" ]] && return 0
    local imgs
    read -ra imgs <<< "${IMAGES//,/ }"
    [[ ${#imgs[@]} -eq 0 ]] && return 0
    timeout "$TMO" docker rmi -f "${imgs[@]}" >/dev/null 2>&1 || true
}

# Order matters: containers reference networks/volumes, so drop them first.
reap_containers
reap_networks
reap_volumes
reap_images

exit 0
