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
#      with that prefix, and every image compose builds for a service with no
#      image: key is named  <project>-<service>).
#
# For images, "everything" means the run's labelled images and its compose-built
# fipsci_ images, which is what a run killed with SIGKILL leaves behind. The
# labelled ones include the install suites' per-run images (fips-deb-test,
# fips-deb-upgrade, and fips-dns-test's e2e tags), which bake in the run's
# package or binaries and so carry the run's suffix in their tag and the run
# label. The suites' fixed tags (fips-dns-test's other tags,
# fips-tarball-test, fips-interop) are outside it by design: those images hold
# nothing of a run, and each overwrites one tag rather than adding an image
# per run.
#
# The generic CI label is shared by every run on the host, so an unscoped label
# sweep would tear down a CONCURRENT run's resources. So would an unscoped
# compose-project sweep, and reap_containers runs BOTH. Neither flag alone is
# therefore enough to spare a concurrent run: --run-id narrows only the label
# sweep, --project-prefix only the project sweep, and whichever is left broad
# reaps everything by itself. This cost three concurrent runs on 2026-07-29,
# via a caller that passed --run-id alone and reasonably believed that scoped
# it. --run-id now implies the matching project prefix, and --project-prefix
# without --run-id is refused, so the dangerous half-scoped states are no
# longer reachable. Passing neither is still the broad "reap everything" form.
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
#   ci-cleanup.sh --run-id ID           Scope the reap to one run: narrows the
#                                       label sweep to ID and, unless
#                                       --project-prefix says otherwise,
#                                       narrows the project sweep to that run
#                                       too. Does NOT scope the host veth
#                                       sweep — see --veth-suffixes
#   ci-cleanup.sh --project-prefix P    Restrict the compose-project sweep to
#                                       names starting with P. Requires
#                                       --run-id: on its own it leaves the
#                                       label sweep broad, which reaps every
#                                       concurrent run regardless of P
#   ci-cleanup.sh --label L             Override the CI label (default above)
#   ci-cleanup.sh --images "a b,c"      Also `docker rmi -f` these image tags
#                                       (space- or comma-separated), in
#                                       addition to the images the label and
#                                       project sweeps find
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
# interfaces, so the reap works wherever the simulation does. Any fips test
# image will do; it is wanted only for its iproute2.
#
# Empty here and resolved after the argument loop, because the resolution has
# to consider --veth-image. The old default of fips-test:latest is no longer
# safe on its own: ci-local.sh does not write that tag, so on a host that has
# only ever run the harness it need not exist at all, and the reap this script
# advertises as the remedy for orphaned interfaces would be a permanent no-op.
VETH_IMAGE=""
PROJECT_PREFIX_GIVEN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --label)          LABEL="$2"; shift 2 ;;
        --project-prefix) PROJECT_PREFIX="$2"; PROJECT_PREFIX_GIVEN=1; shift 2 ;;
        --run-id)         RUN_ID="$2"; shift 2 ;;
        --images)         IMAGES="$2"; shift 2 ;;
        --veth-suffixes)  VETH_SUFFIXES="$2"; shift 2 ;;
        --veth-image)     VETH_IMAGE="$2"; shift 2 ;;
        -h|--help)        sed -n '2,/^set /{ /^set /d; s/^# \?//; p }' "$0"; exit 0 ;;
        *)                echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

# A reap scoped on one axis and broad on the other still destroys every
# concurrent run, because both selectors run. Close both half-scoped states
# here rather than trusting each caller to pass the pair.
if [[ -n "$RUN_ID" && "$PROJECT_PREFIX_GIVEN" -eq 0 ]]; then
    # Every run's projects are named "<base prefix><run id>_<suite>", so the
    # run id is all that is needed. Derived from the base rather than a second
    # copy of the literal, so the two cannot drift.
    PROJECT_PREFIX="${PROJECT_PREFIX}${RUN_ID}"
fi
if [[ -z "$RUN_ID" && "$PROJECT_PREFIX_GIVEN" -eq 1 ]]; then
    echo "ci-cleanup.sh: --project-prefix requires --run-id." >&2
    echo "  Without it the label sweep stays broad and reaps every concurrent" >&2
    echo "  run regardless of the prefix. Pass both, or neither for a full reap." >&2
    exit 2
fi

# Resolve the image to run ip(8) in: the caller's choice, then the run's own
# image, then any surviving fips test image. That last fallback is what keeps
# an unscoped `ci-local.sh --reap` working — it execs this script from inside
# its own argument loop, before the run identity is exported, so it can pass
# neither. The empty case is handled at the point of use, which already warns
# and skips rather than failing the sweep.
if [[ -z "$VETH_IMAGE" ]]; then
    VETH_IMAGE="${FIPS_TEST_IMAGE:-}"
fi
if [[ -z "$VETH_IMAGE" ]] && command -v docker >/dev/null 2>&1; then
    VETH_IMAGE="$(timeout 10 docker image ls --format '{{.Repository}}:{{.Tag}}' fips-test 2>/dev/null | head -n1)"
fi
[[ -z "$VETH_IMAGE" ]] && VETH_IMAGE="fips-test:latest"

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

# Selector for the label sweep. With --run-id it matches only the named run;
# without it, every CI run. Note this is only half of what scopes a reap — the
# compose-project sweep below is the other half, and both must be narrow.
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
#
# Three producers, three shapes. The chaos simulation makes
# vh{token}{NN}{MM}{a,b}; the NAT lab (nat/scripts/setup-topology.sh) makes
# vn{a,b}{token}{0,1}; the interface-binding suite
# (iface-binding/test.sh) makes vhifb{token}{a,b,c,d}. The last two use the
# RUN-wide suffix rather than any chaos scenario's. Widening this regex is
# only half the fix: the token set is derived separately below, so a suffix
# list carrying no run-wide suffix leaves those halves matching nothing while
# looking correct. ci-local.sh's ci_teardown therefore appends the run-wide
# suffix to --veth-suffixes.
#
# vhifb is listed before the bare vh shape in each alternation only for
# readability; the shapes are anchored and cannot overlap, because a node id
# is digits and `ifb` is not.
veth_pattern() {
    # vh{token}{NN}{MM}{a,b}: the token is 4 hex or wholly absent — never a
    # part of one — and the two node ids follow. Anchored and shaped this
    # tightly so the unscoped sweep cannot reach an interface the simulation
    # never made. Broad only for an unscoped reap: once --run-id names a
    # single run, no missing or empty suffix list may widen this back out to
    # every run.
    if [[ -z "$RUN_ID" && -z "$VETH_SUFFIXES" ]]; then
        printf '^vhifb([0-9a-f]{4})?[a-d]$|^vh([0-9a-f]{4})?%s%s[ab]$|^vn[ab]([0-9a-f]{4})?[01]$' \
            "$VETH_NODE_ID" "$VETH_NODE_ID"
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
    printf '^vhifb(%s)[a-d]$|^vh(%s)%s%s[ab]$|^vn[ab](%s)[01]$' \
        "$alt" "$alt" "$VETH_NODE_ID" "$VETH_NODE_ID" "$alt"
}

# ip(8) in a privileged --net=host container, matching how the simulation
# creates these interfaces (see chaos/sim/veth.py).
#
# Neither helper carries the CI labels: the builder skips its orphan sweep
# while any generic-labelled container is up, so a labelled helper would let
# one run's teardown hold off that sweep. The `# ci-labels:` comment exempts
# each from testing/check-ci-labels.py, and sits on the command's last line
# because a comment after a backslash would end the command there.
veth_ip() {
    timeout "$TMO" docker run --rm --privileged --net=host \
        --entrypoint ip "$VETH_IMAGE" "$@" 2>/dev/null  # ci-labels: the reaper's ip(8) helper
}

# The same, taking `ip -batch` commands on stdin so any number of deletes costs
# one container. -force keeps ip going past an interface that vanished under us.
veth_ip_batch() {
    timeout "$TMO" docker run --rm -i --privileged --net=host \
        --entrypoint ip "$VETH_IMAGE" -force -batch - >/dev/null 2>&1 || true  # ci-labels: the reaper's ip(8) helper
}

reap_veths() {
    local pattern
    pattern="$(veth_pattern)"
    [[ -z "$pattern" ]] && return 0
    # Without the image there is no way to run ip(8). Orphans can outlive it —
    # `docker image prune -a`, a build host that prunes between runs, or a run
    # whose per-run image was already reaped all remove it while interfaces are
    # still up — so this is a real skip, not "nothing was ever run here".
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

image_warn() { echo "ci-cleanup: $*" >&2; }

# Tagged images as repository:tag, optionally narrowed by `docker image ls`
# arguments. Untagged entries are dropped: removal goes by name and never by
# ID, because removing an ID takes every tag it carries, including one that
# somebody else gave the same image. Fails only when the listing itself does.
image_names() {
    local out
    out="$(timeout "$TMO" docker image ls "$@" --format '{{.Repository}}:{{.Tag}}' 2>/dev/null)" \
        || return 1
    grep -v -e '<none>' -e '^$' <<< "$out" || true
}

# Every image name this reap owns, one per line: the --images list, every image
# carrying the sweep label, and every compose-built image of a matched project.
# Compose names an image it builds <project>-<service>, and `docker image ls
# --format` cannot read image labels, so the project images are matched by name
# the way reap_networks matches networks. The prefix is anchored on the `_` that
# ends the run id: run abc-12 must not reach run abc-123's images, and run ids
# vary in length, so concurrent runs on one commit can stand in that relation.
image_targets() {
    local anchor all labelled img imgs=()
    anchor="$PROJECT_PREFIX"
    [[ "$anchor" == *_ ]] || anchor="${anchor}_"
    read -ra imgs <<< "${IMAGES//,/ }"
    labelled="$(image_names --filter "label=${SWEEP_LABEL}")" \
        || image_warn "image listing by label failed, label sweep skipped"
    all="$(image_names)" \
        || image_warn "image listing failed, compose image sweep skipped"
    {
        for img in "${imgs[@]}"; do
            # A bare name means :latest, which is how the listing spells it.
            [[ "${img##*/}" == *:* ]] || img="${img}:latest"
            printf '%s\n' "$img"
        done
        printf '%s\n' "$labelled"
        grep -E "^${anchor}" <<< "$all" || true
    } | grep -v '^$' | sort -u
}

# Remove this reap's images, then list again and report on stderr whatever is
# still there. The reap stays best-effort and exits 0 regardless, so without
# the report a teardown that stopped removing images would look exactly like
# one that had nothing to remove.
reap_images() {
    local targets left
    targets="$(image_targets)"
    [[ -z "$targets" ]] && return 0
    xargs -r timeout "$TMO" docker rmi -f <<< "$targets" >/dev/null 2>&1 || true
    if ! left="$(image_names)"; then
        image_warn "image listing failed, cannot confirm image removal"
        return 0
    fi
    left="$(grep -Fx -f <(printf '%s\n' "$targets") <<< "$left" || true)"
    [[ -z "$left" ]] && return 0
    image_warn "$(grep -c . <<< "$left") image(s) not removed: $(paste -sd' ' <<< "$left")"
}

# Per-run build contexts left in the working tree. ci-local.sh removes its own
# from the EXIT trap, but the CI worker sends SIGKILL after SIGTERM and a
# SIGKILL runs no trap, so a preempted run can leave an 18 MB directory behind
# with nothing else that would ever notice it.
#
# Scoped mode takes only the named run's. Broad mode cannot tell a live run's
# context from an abandoned one by name, so it goes by age instead: a run lasts
# well under an hour, and a day is far outside that.
reap_build_contexts() {
    local dir
    if [[ -n "$RUN_ID" ]]; then
        dir="$SCRIPT_DIR/docker-$RUN_ID"
        [[ -d "$dir" ]] && rm -rf "$dir"
        return 0
    fi
    while IFS= read -r dir; do
        [[ -n "$dir" ]] && rm -rf "$dir"
    done < <(find "$SCRIPT_DIR" -maxdepth 1 -type d -name 'docker-*' -mtime +0 2>/dev/null)
    return 0
}

# Order matters: containers reference networks/volumes, so drop them first, and
# the veth sweep needs an image to run ip(8) in, so it precedes the image reap.
reap_containers
reap_networks
reap_volumes
reap_veths
reap_images
reap_build_contexts

exit 0
