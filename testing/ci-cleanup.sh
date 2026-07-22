#!/bin/bash
# Reap FIPS CI resources: containers, networks, volumes, images, veth pairs.
#
# Force-removes everything created by ci-local.sh that is still around —
# whether a run finished cleanly, was preempted (SIGTERM/SIGKILL), OOM-killed,
# or crashed. Two complementary selectors make this robust no matter how a
# prior run died:
#
#   1. The CI label  com.corganlabs.fips-ci=1  (attached to every direct
#      `docker run`/network/volume ci-local drives). Every run additionally
#      stamps  com.corganlabs.fips-ci.run=<run-id>  on the same resources.
#   2. The compose project-name prefix  fipsci_  (every compose project ci-local
#      starts is named  fipsci_<run-id>_<suite>, so its containers/networks/
#      volumes all carry  com.docker.compose.project=fipsci_...  and are named
#      with that prefix).
#
# The generic CI label is shared by every run on the host, so an unscoped label
# sweep would tear down a CONCURRENT run's resources. Pass --run-id to narrow
# the label sweep to one run; a run's own teardown always does. Without it the
# label sweep stays broad, which is what a manual "reap everything" wants.
#
# Host-namespace veth interfaces are the one non-docker resource reaped here.
# The chaos simulation creates each pair in the host namespace and then moves
# the two ends into container namespaces, so a run killed in between leaves the
# pair behind, and nothing else on the box removes it. Their names carry a
# short token derived from the scenario's name suffix, so --veth-suffixes takes
# the suffixes a run used and reaps only the tokens those could produce. Only a
# reap with neither --run-id nor --veth-suffixes matches every simulation veth
# name, in step with the broad label sweep. --project-prefix does not scope the
# veth sweep at all: a host interface carries no compose project.
#
# These interfaces are also the one resource reaped WITHOUT regard to the CI
# label — they cannot carry one — so an unscoped reap takes the host ends of a
# bare `chaos.sh` simulation's veth pairs too, even though it leaves that
# simulation's unlabelled containers running. Scope with --veth-suffixes (or
# just don't reap) while a bare simulation is up.
#
# Usage:
#   ci-cleanup.sh                       Reap ALL fips-ci resources (any run)
#   ci-cleanup.sh --project-prefix P    Restrict the compose-project sweep to
#                                       names starting with P (scopes the reap
#                                       to a single run). Does NOT scope the
#                                       host veth sweep — see --veth-suffixes
#   ci-cleanup.sh --run-id ID           Restrict the label sweep to the run
#                                       labelled ID (leaves other runs alone)
#   ci-cleanup.sh --label L             Override the CI label (default above)
#   ci-cleanup.sh --images "a b,c"      Also `docker rmi -f` these image tags
#                                       (space- or comma-separated)
#   ci-cleanup.sh --veth-suffixes "a b" Restrict the host veth sweep to the
#                                       name suffixes a single run used
#                                       (space- or comma-separated). Without
#                                       it the sweep reaches every simulation
#                                       veth name on the host, including a
#                                       bare `chaos.sh` run's live ones
#
# Safe to run when there is nothing to reap, and safe to run repeatedly.
# Also reachable as `ci-local.sh --reap`.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

LABEL="com.corganlabs.fips-ci=1"
RUN_LABEL_KEY="com.corganlabs.fips-ci.run"
PROJECT_PREFIX="fipsci_"   # broad default: every CI run
RUN_ID=""                  # broad default: every CI run
IMAGES=""
VETH_SUFFIXES=""           # empty AND no --run-id: every simulation veth name
# ip(8) runs inside this image, the same way the simulation creates the
# interfaces, so the reap works wherever the simulation does. The chaos
# simulation builds it, and it carries iproute2.
VETH_IMAGE="fips-test:latest"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --label)          LABEL="$2"; shift 2 ;;
        --project-prefix) PROJECT_PREFIX="$2"; shift 2 ;;
        --run-id)         RUN_ID="$2"; shift 2 ;;
        --images)         IMAGES="$2"; shift 2 ;;
        --veth-suffixes)  VETH_SUFFIXES="$2"; shift 2 ;;
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

# Selector for the label sweep. With --run-id it matches only the named run, so
# a concurrent run's resources are left alone; without it, every CI run.
if [[ -n "$RUN_ID" ]]; then
    SWEEP_LABEL="${RUN_LABEL_KEY}=${RUN_ID}"
else
    SWEEP_LABEL="$LABEL"
fi

# Distinct compose project names (read off container labels) that start with
# the configured prefix.
ci_projects() {
    docker ps -a --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null \
        | grep -E "^${PROJECT_PREFIX}" | sort -u
}

reap_containers() {
    # By CI label.
    docker ps -aq --filter "label=${SWEEP_LABEL}" 2>/dev/null \
        | xargs -r timeout "$TMO" docker rm -f >/dev/null 2>&1 || true
    # By compose project (carried even when container_name is explicit).
    local p
    for p in $(ci_projects); do
        docker ps -aq --filter "label=com.docker.compose.project=${p}" 2>/dev/null \
            | xargs -r timeout "$TMO" docker rm -f >/dev/null 2>&1 || true
    done
}

reap_networks() {
    docker network ls -q --filter "label=${SWEEP_LABEL}" 2>/dev/null \
        | xargs -r timeout "$TMO" docker network rm >/dev/null 2>&1 || true
    # Compose networks are named  <project>_<net>  → match by name prefix so
    # orphaned networks (whose containers are already gone) are still caught.
    docker network ls --format '{{.Name}}' 2>/dev/null | grep -E "^${PROJECT_PREFIX}" \
        | xargs -r timeout "$TMO" docker network rm >/dev/null 2>&1 || true
}

reap_volumes() {
    docker volume ls -q --filter "label=${SWEEP_LABEL}" 2>/dev/null \
        | xargs -r timeout "$TMO" docker volume rm >/dev/null 2>&1 || true
    docker volume ls --format '{{.Name}}' 2>/dev/null | grep -E "^${PROJECT_PREFIX}" \
        | xargs -r timeout "$TMO" docker volume rm >/dev/null 2>&1 || true
}

# Every failure below leaves interfaces behind rather than widening the sweep,
# so each one is silent by construction. Say so on stderr instead, or a reap
# that reclaimed nothing looks exactly like a reap that had nothing to reclaim.
veth_warn() { echo "ci-cleanup: host veth sweep skipped: $*" >&2; }

# One node id, exactly as chaos/sim/topology.py renders it (f"n{i+1:02d}"):
# zero-padded to two digits, and never zero-padded beyond that. Spelling it out
# keeps shapes the simulation cannot emit (vh01020a) out of the sweep.
VETH_NODE_ID='(0[0-9]|[1-9][0-9]+)'

# Regex matching the host veth names to remove. With --veth-suffixes it covers
# only the tokens those suffixes hash to, so a concurrent run's interfaces —
# which carry a different token — cannot match. The token derivation is read
# from the simulation itself rather than repeated here, so widening it cannot
# leave this matching the old width. Empty output means "reap nothing".
veth_pattern() {
    # vh{token}{NN}{MM}{a,b}: the token is 4 hex or wholly absent — never a
    # part of one — and the two node ids follow. Anchored and shaped this
    # tightly so the unscoped sweep cannot reach an interface the simulation
    # never made. Broad only for an unscoped reap: once --run-id names a
    # single run, no missing or empty suffix list may widen this back out to
    # every run.
    if [[ -z "$RUN_ID" && -z "$VETH_SUFFIXES" ]]; then
        printf '^vh([0-9a-f]{4})?%s%s[ab]$' "$VETH_NODE_ID" "$VETH_NODE_ID"
        return 0
    fi
    if [[ -z "$VETH_SUFFIXES" ]]; then
        veth_warn "--run-id given with no --veth-suffixes"
        return 0
    fi
    local sfx=() tok alt="" out rc
    read -ra sfx <<< "${VETH_SUFFIXES//,/ }"
    if [[ ${#sfx[@]} -eq 0 ]]; then
        veth_warn "--veth-suffixes is empty"
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        veth_warn "python3 not found, cannot derive interface tokens"
        return 0
    fi
    # SCRIPT_DIR comes from $0, so invoking this script through a symlink or a
    # copy on $PATH points PYTHONPATH at a tree with no simulation in it. Say
    # which tree was tried when the derivation fails, rather than no-opping.
    out="$(PYTHONPATH="$SCRIPT_DIR/chaos" python3 -m sim.naming "${sfx[@]}" 2>&1)"
    rc=$?
    if [[ $rc -ne 0 ]]; then
        veth_warn "token derivation failed under $SCRIPT_DIR/chaos: $out"
        return 0
    fi
    for tok in $out; do
        [[ "$tok" =~ ^[0-9a-f]{4}$ ]] && alt="${alt:+$alt|}$tok"
    done
    if [[ -z "$alt" ]]; then
        veth_warn "no interface tokens derived from: ${sfx[*]}"
        return 0
    fi
    printf '^vh(%s)%s%s[ab]$' "$alt" "$VETH_NODE_ID" "$VETH_NODE_ID"
}

# ip(8) in a privileged --net=host container, matching how the simulation
# creates these interfaces (see chaos/sim/veth.py).
veth_ip() {
    timeout "$TMO" docker run --rm --privileged --net=host \
        --entrypoint ip "$VETH_IMAGE" "$@" 2>/dev/null
}

# The same, taking `ip -batch` commands on stdin so any number of deletes costs
# one container. -force keeps ip going past an interface that vanished under us.
veth_ip_batch() {
    timeout "$TMO" docker run --rm -i --privileged --net=host \
        --entrypoint ip "$VETH_IMAGE" -force -batch - >/dev/null 2>&1 || true
}

reap_veths() {
    local pattern
    pattern="$(veth_pattern)"
    [[ -z "$pattern" ]] && return 0
    # Without the image there is no way to run ip(8). Orphans can outlive it —
    # `docker image prune -a`, a build host that prunes between runs, or a run
    # aborted before ci-local.sh retags :latest all remove it while interfaces
    # are still up — so this is a real skip, not "nothing was ever run here".
    if ! docker image inspect "$VETH_IMAGE" >/dev/null 2>&1; then
        veth_warn "image $VETH_IMAGE not present, cannot run ip(8)"
        return 0
    fi
    # Both ends of a pair match, but deleting either removes both, so collapse
    # each pair to one delete and issue the lot in a single container. The
    # whole script runs under a caller-imposed timeout, and a container spawn
    # per name would put a large orphan set at risk of exhausting it. `sort -u`
    # orders `...a` before `...b`, so the surviving end of a pair the
    # simulation was killed part-way through moving is still the one picked.
    local names
    names="$(veth_ip -o link show \
        | sed -E 's/^[0-9]+: ([^:@]+).*/\1/' \
        | grep -E "$pattern" | sort -u \
        | awk '{ k = substr($0, 1, length($0) - 1)
                 if (!(k in seen)) { seen[k] = 1; print } }')"
    [[ -z "$names" ]] && return 0
    sed 's/^/link delete /' <<< "$names" | veth_ip_batch
}

reap_images() {
    [[ -z "$IMAGES" ]] && return 0
    local imgs
    read -ra imgs <<< "${IMAGES//,/ }"
    [[ ${#imgs[@]} -eq 0 ]] && return 0
    timeout "$TMO" docker rmi -f "${imgs[@]}" >/dev/null 2>&1 || true
}

# Order matters: containers reference networks/volumes, so drop them first, and
# the veth sweep needs an image to run ip(8) in, so it precedes the image reap.
reap_containers
reap_networks
reap_volumes
reap_veths
reap_images

exit 0
