#!/bin/bash
# Mixed-version interop test driver.
#
# Brings up an N-node full mesh from a NODE-SPEC (a multiset of image
# slots), verifies every pair interoperates — FMP link, FSP session,
# connectivity, rekey survival — and runs a per-node, per-pair log
# analysis tuned to surface INTEROP problems: handshake failures,
# FSP/FMP decrypt failures, `unknown FMP version`, replay storms,
# link/session teardowns.
#
# The harness's job is NOT to test a single version. It is to find any
# place where two DIFFERENT versions fail to interoperate in a way a
# same-version pair would not. Every failure is attributed to a specific
# (version-X <-> version-Y) pair, classified same-version vs MIXED.
#
# A node-spec like `a a b c` produces a same-version pair (a1<->a2) — the
# CONTROL ARM — alongside the mixed pairs. The control pair is what makes
# a netem run interpretable: a failure on a mixed pair that the control
# pair does not share is an interop regression; a failure both share is
# loss noise, not version-specific.
#
# Prerequisites:
#   1. bash build-images.sh <ref-a> <ref-b> <ref-c>   (builds fips-interop:a/b/c)
#   2. configs are (re)generated automatically below for the given spec.
#
# Usage:
#   ./interop-test.sh [--topology <name>] [node-spec...]
#   ./interop-test.sh --multipath[=request|config] a c
#   ./interop-test.sh --probe-hour a c
#
#   --topology  built-in multi-hop topology selecting a node-spec + edge
#               set + default data-plane streams. Known: multihop-3v-cycle
#               (6 nodes, 2 of each version, one cycle, two leaves —
#               exercises cross-version forwarding + mesh-size). Without
#               it the mesh is a full mesh from the positional node-spec.
#   --multipath a multipath-enabled node (slot a) against a release node
#               (slot c), joined on a second network as well as the first:
#               the new node is given the old node's second-network address
#               as a path candidate, by `fipsctl connect` once the link is
#               up (request, the default) or as a configured address of a
#               peer it does not dial (config), and the run checks what the
#               multipath draft promises the old node (phases M0 to M5,
#               below). Needs the spec `a c` and an `a` image that knows
#               node.path. Run by hand; not part of local CI.
#   --probe-hour  --multipath=request, with the re-dial replaced by an hour
#               from link-up that counts the capability probes, their gaps
#               and their bytes at the old node.
#   node-spec   space-separated slot letters (a/b/c), default `a b c`.
#               e.g. `a a b c` (4-node, one same-version control pair),
#                    `a a a`   (3-node same-version flake rig).
#
# Beyond FMP/FSP rekey survival, a --topology run also verifies multi-hop
# FORWARDING (all-pairs ping over non-adjacent pairs), DATA-PLANE
# CONTINUITY across rekey (control-differential ping-loss stream,
# Phase 5b), and MESH-SIZE estimate convergence across versions
# (Phase 7).
#
# A link lost at any point of a run turns it red: the ping phases cover
# Phases 1 to 5, Phase 7 checks every node's direct peers on each poll
# round of its warmup and settle loops, and Phase 8 scans the whole run's
# logs for peer removals and the other global failure signatures.
#
# Environment:
#   FIPS_INTEROP_NETEM     tc-netem arg string applied to every container's
#                          eth0, e.g. "delay 10ms 5ms 25% loss 1%". Unset =
#                          no impairment.
#   FIPS_INTEROP_EDGES     explicit undirected edge list (overrides the
#                          full mesh) — see generate-configs.sh. Usually
#                          set for you by --topology.
#   FIPS_INTEROP_STREAMS   data-plane stream pairs (`nid-nid` tokens, both
#                          directions streamed). Enables Phase 1b/5b. Set
#                          by --topology; empty = streams off.
#   STREAM_LOSS_MARGIN_PCT rekey-vs-control loss margin (default 5).
#   CONTROL_STREAM_SECS    quiet control-window length (default 12).
#   CONTROL_MAX_ATTEMPTS   control windows measured before Phase 5b
#                          abstains because every one saw a rekey
#                          cutover or could not be checked (default 3).
#   MESH_SIZE_WARMUP       Phase 7 bloom warmup, from mesh start, before
#                          any estimate counts (default 300).
#   MESH_SIZE_SETTLE       Phase 7 unbroken in-band window a node must
#                          hold to be credited (default 60).
#   MESH_SIZE_TIMEOUT      Phase 7 poll budget beyond warmup+settle
#                          (default 180).
#   FIPS_INTEROP_KEEP_UP   1 = leave containers running after the test (debug).
#   REKEY_AFTER_SECS       rekey interval to generate configs with (default
#                          35; multihop-3v-cycle defaults it to 50).
#   FIPS_INTEROP_RUNS_DIR  Root for harness scratch dirs (.build/,
#                          .stress-runs/, generated-configs/). When
#                          unset, falls back to in-tree paths under
#                          testing/interop/ and prints a warning to
#                          stderr; set it to a path outside the source
#                          tree to keep generated artefacts out of the
#                          checkout.
#   FIPS_INTEROP_NAME      run name (default fips-interop): container
#                          prefix, compose project, per-run directory.
#   FIPS_INTEROP_IMAGE     image repository (default: the run name); point
#                          several named runs at one build with it.
#   FIPS_INTEROP_SUBNET    first three octets of the mesh /24 (default
#                          172.30.0); checked free before the mesh starts.
#                          See names.sh.
#   FIPS_INTEROP_SUBNET2   the multipath mode's second /24 (default 172.30.1).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib/wait-converge.sh"
# shellcheck source=../lib/image-build.sh
source "$SCRIPT_DIR/../lib/image-build.sh"

# ── Scratch-dir root ─────────────────────────────────────────────────
#
# FIPS_INTEROP_RUNS_DIR controls where the harness writes its scratch
# directories (.build/, .stress-runs/, generated-configs/). When unset
# we fall back to in-tree paths under testing/interop/ and warn the
# operator, so the warning fires exactly once per invocation. When a
# parent script has already warned it exports _FIPS_INTEROP_WARNED=1
# to suppress duplicate warnings in child scripts.
if [[ -n "${FIPS_INTEROP_RUNS_DIR:-}" ]]; then
    RUNS_BASE="$FIPS_INTEROP_RUNS_DIR"
    mkdir -p "$RUNS_BASE"
else
    RUNS_BASE="$SCRIPT_DIR"
    if [[ -z "${_FIPS_INTEROP_WARNED:-}" ]]; then
        echo >&2 "WARNING: FIPS_INTEROP_RUNS_DIR not set; harness output will be written under the source tree at $RUNS_BASE. Set FIPS_INTEROP_RUNS_DIR to a path outside the source tree to avoid this."
        export _FIPS_INTEROP_WARNED=1
    fi
fi

# shellcheck source=names.sh
source "$SCRIPT_DIR/names.sh"
interop_names
COMPOSE_FILE="$GEN_DIR/docker-compose.generated.yml"
NODES_ENV="$GEN_DIR/nodes.env"
# The log readers and the multipath checks.
# shellcheck source=checks.sh
source "$SCRIPT_DIR/checks.sh"

# ── Built-in topology selection ──────────────────────────────────────
#
# --topology <name> selects a node-spec + an explicit edge set (a
# multi-hop, mixed-version, leaf-bearing graph) + a default data-plane
# stream set, exercising forwarding / routing / mesh-size convergence
# across versions. Without it, positional args are the node-spec and the
# mesh is a full mesh (historical behavior).
TOPOLOGY_NAME=""
MULTIPATH=""
PROBE_HOUR=0
_ARGS=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --topology)    TOPOLOGY_NAME="${2:-}"; shift 2 ;;
        --topology=*)  TOPOLOGY_NAME="${1#--topology=}"; shift ;;
        --multipath)   MULTIPATH="request"; shift ;;
        --multipath=*) MULTIPATH="${1#--multipath=}"; shift ;;
        --probe-hour)  PROBE_HOUR=1; shift ;;
        *)             _ARGS+=("$1"); shift ;;
    esac
done
if [ "$PROBE_HOUR" -eq 1 ]; then
    if [ -n "$MULTIPATH" ] && [ "$MULTIPATH" != "request" ]; then
        echo "ERROR: --probe-hour runs the request source only" >&2
        exit 2
    fi
    MULTIPATH="request"
fi
case "$MULTIPATH" in
    ""|request|config) ;;
    *) echo "ERROR: --multipath takes request or config (got '$MULTIPATH')" >&2; exit 2 ;;
esac
set -- ${_ARGS[@]+"${_ARGS[@]}"}

if [ -n "$TOPOLOGY_NAME" ]; then
    case "$TOPOLOGY_NAME" in
        multihop-3v-cycle)
            # 6 nodes (2 of each version), one cycle, two leaves.
            #         a1
            #        /  \         leaves: a2, c2
            #      b1    c1       cycle:  b1-a1-c1-b2-b1
            #     / \      \
            #   a2  b2------c2-edge(b2-c1)
            set -- a a b b c c
            export FIPS_INTEROP_EDGES="a1-b1 a1-c1 b1-a2 b1-b2 c1-c2 b2-c1"
            : "${FIPS_INTEROP_STREAMS:=a2-c2 a1-b1}"
            export FIPS_INTEROP_STREAMS
            # Multi-hop convergence + a clean pre-rekey control window
            # want more headroom than the 35s full-mesh default.
            : "${REKEY_AFTER_SECS:=50}"
            ;;
        *)
            echo "ERROR: unknown --topology '$TOPOLOGY_NAME' (known: multihop-3v-cycle)" >&2
            exit 2
            ;;
    esac
fi

REKEY_AFTER_SECS="${REKEY_AFTER_SECS:-35}"

# ── Node-spec ────────────────────────────────────────────────────────

SPEC=("$@")
if [ "${#SPEC[@]}" -eq 0 ]; then
    SPEC=(a b c)
fi
SPEC_STR="${SPEC[*]}"

# The multipath mode's old node logs its discards with no peer field, so
# a count there is attributable only when the old node has one peer.
INTEROP_SUBNET2=""
if [ -n "$MULTIPATH" ]; then
    if [ "$SPEC_STR" != "a c" ] || [ -n "$TOPOLOGY_NAME" ]; then
        echo "ERROR: --multipath and --probe-hour need the spec 'a c' and no --topology (got '$SPEC_STR')" >&2
        exit 2
    fi
    INTEROP_SUBNET2="${FIPS_INTEROP_SUBNET2:-172.30.1}"
    interop_check_subnet FIPS_INTEROP_SUBNET2 "$INTEROP_SUBNET2"
    export FIPS_INTEROP_MULTIPATH="$MULTIPATH"
else
    unset FIPS_INTEROP_MULTIPATH
fi

# ── Timing ───────────────────────────────────────────────────────────

CONVERGENCE_TIMEOUT="${CONVERGENCE_TIMEOUT:-90}"  # detector settle budget (env-overridable; larger meshes under loss converge slower)
PING_TIMEOUT=5
MAX_PING_ATTEMPTS=4             # strict-ping retry (mirrors rekey-test.sh)
PING_RETRY_DELAY=1
# First rekey should follow shortly after the interval once converged.
FIRST_REKEY_TIMEOUT=$((REKEY_AFTER_SECS + 20))
SECOND_REKEY_WAIT=$((REKEY_AFTER_SECS + 5))
REKEY_SETTLE=12                 # FSP-cutover settle budget (Phase 6)
# Post-rekey reconvergence is polled, not fixed-slept: the mesh is given
# up to this long to restore full connectivity after a rekey before the
# strict assertion sweep runs. A genuinely stuck pair still fails — the
# poll times out and the recording sweep captures it.
POST_REKEY_TIMEOUT=45
# Progress-aware stall budget for the convergence detector
# (wait_for_full_baseline → wait_until_connected). If no additional pair
# becomes reachable for this long while more than the near-converged
# slack of pairs is still down, the detector gives up early instead of
# burning the whole convergence/post-rekey window; any progress resets
# the clock, so a slow-but-converging mesh under netem keeps polling.
RECONVERGE_STALL=15
LOG_POLL_INTERVAL=2

# Data-plane continuity stream (control-differential). Streams run a
# sustained ping6 over the overlay across the rekey window vs a quiet
# control window; loss is compared to prove rekey is hitless.
# The control window cannot be lengthened much: it has to fit inside one
# rekey interval (REKEY_AFTER_SECS, 35s by default) to stand a chance of
# being cutover-free, and it already gets contaminated sometimes at 12s.
# So the sample is raised by rate instead. At 20 Hz the control window is
# 240 packets and the rekey window ~3100, where at 5 Hz they were 60 and
# ~775 and a 1% margin came to 0.6 of a control packet — below the
# quantisation of its own measurement, so a one-packet difference decided
# the verdict and the netem arm failed on same-version pairs as readily
# as on mixed ones.
STREAM_RATE_HZ=20
CONTROL_STREAM_SECS="${CONTROL_STREAM_SECS:-12}" # quiet pre-rekey window
# A control window that saw a rekey cutover, or whose cutover count could
# not be read, is no baseline. Phase 1b re-measures it, after waiting for
# the cutover count to hold still for CONTROL_QUIET_SECS (at most
# CONTROL_QUIET_MAX) so the retry does not land in the same cluster of
# cutovers, and Phase 5b abstains when no attempt comes out clean.
CONTROL_MAX_ATTEMPTS="${CONTROL_MAX_ATTEMPTS:-3}"
CONTROL_QUIET_SECS=5
CONTROL_QUIET_MAX=30
# 5% is 12 packets of the 240-packet control window and ~155 of the
# ~3100-packet rekey window. On a path losing up to 6% (the range the
# v0.4.2 netem runs baselined at, under `loss 2%` over several hops) the
# difference of the two windows has a standard deviation below 1.6%, so
# 5% is past three sigma and sampling spread can no longer produce a red.
# It still catches what this check exists for: a rekey that is not
# hitless blackholes until the session reconverges, which the harness
# budgets 45s for, against the ~8s of traffic 5% of the rekey window is.
STREAM_LOSS_MARGIN_PCT="${STREAM_LOSS_MARGIN_PCT:-5}"
# The rekey-window stream must span Phases 2-5 (both cutovers + reconverge).
REKEY_STREAM_SECS=$(( FIRST_REKEY_TIMEOUT + SECOND_REKEY_WAIT + POST_REKEY_TIMEOUT + 15 ))

# Mesh-size estimate convergence (strict ±25% of true N). The archived
# design note puts bloom-filter warmup at ~5 minutes from node start and
# calls the estimate unreliable before that, so nothing sampled inside
# MESH_SIZE_WARMUP is evidence of convergence, and a node is credited
# only after holding the band unbroken for MESH_SIZE_SETTLE afterwards.
# MESH_SIZE_TIMEOUT is the extra budget for reaching that state, on top
# of the warmup and settle windows rather than covering them.
MESH_SIZE_WARMUP="${MESH_SIZE_WARMUP:-300}"
MESH_SIZE_SETTLE="${MESH_SIZE_SETTLE:-60}"
MESH_SIZE_TIMEOUT="${MESH_SIZE_TIMEOUT:-180}"
MESH_SIZE_POLL=5

# ── Counters ─────────────────────────────────────────────────────────

PASSED=0
FAILED=0
TOTAL_PASSED=0
TOTAL_FAILED=0
# INTEROP_FAILURES collects human-readable, pair-attributed failure lines.
INTEROP_FAILURES=()

# ── Preflight: docker + images ───────────────────────────────────────

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker daemon is not reachable" >&2
    exit 2
fi

# A node-spec only ever references the three image slots, regardless of
# how many nodes it has. Check the slots actually present in the spec.
for slot in $(printf '%s\n' "${SPEC[@]}" | sort -u); do
    case "$slot" in
        a|b|c) ;;
        *) echo "ERROR: invalid slot '$slot' in node-spec" >&2; exit 2 ;;
    esac
    if ! docker image inspect "$INTEROP_IMAGE:$slot" >/dev/null 2>&1; then
        echo "ERROR: image $INTEROP_IMAGE:$slot not present." >&2
        echo "Build the three images first:" >&2
        echo "  bash $SCRIPT_DIR/build-images.sh <ref-a> <ref-b> <ref-c>" >&2
        exit 2
    fi
done

# ── (Re)generate configs for this node-spec ──────────────────────────
#
# Always regenerate when the spec, edges, run name, image repository or
# subnet on disk do not match the requested ones (or no manifest exists).
# Generation is deterministic and cheap.

# manifest_value <VAR>: the value nodes.env records for VAR, empty if none.
manifest_value() {
    sed -n "s/^$1=\"\(.*\)\"\$/\1/p" "$NODES_ENV"
}

need_regen=1
if [ -f "$NODES_ENV" ]; then
    if [ "$(manifest_value INTEROP_SPEC)" = "$SPEC_STR" ] \
        && [ "$(manifest_value INTEROP_TOPOLOGY_EDGES)" = "${FIPS_INTEROP_EDGES:-}" ] \
        && [ "$(manifest_value INTEROP_NAME)" = "$INTEROP_NAME" ] \
        && [ "$(manifest_value INTEROP_IMAGE)" = "$INTEROP_IMAGE" ] \
        && [ "$(manifest_value INTEROP_SUBNET)" = "$INTEROP_SUBNET" ] \
        && [ "$(manifest_value INTEROP_MULTIPATH)" = "$MULTIPATH" ] \
        && [ "$(manifest_value INTEROP_SUBNET2)" = "$INTEROP_SUBNET2" ]; then
        need_regen=0
    fi
fi
if [ "$need_regen" -eq 1 ]; then
    echo "Generating mesh configs for spec '$SPEC_STR' (rekey.after_secs=$REKEY_AFTER_SECS)..."
    REKEY_AFTER_SECS="$REKEY_AFTER_SECS" bash "$SCRIPT_DIR/generate-configs.sh" \
        "${SPEC[@]}"
    echo ""
fi

# ── Load the manifest ────────────────────────────────────────────────
#
# nodes.env gives the ordered node list and the per-node slot/container/
# ip/npub maps. npubs.env gives NPUB_<NODEID> vars used by ping_one.

# shellcheck disable=SC1090
source "$NODES_ENV"
# shellcheck disable=SC1091
source "$GEN_DIR/npubs.env"

read -r -a NODES <<< "$INTEROP_NODE_IDS"

declare -A SLOT_OF CONTAINER NODE_IP_OF NPUB_OF
parse_map() {
    # parse_map <assoc-array-name> <space-separated nodeid:value tokens>
    local -n _dst="$1"
    local tok nid val
    for tok in $2; do
        nid="${tok%%:*}"
        val="${tok#*:}"
        _dst["$nid"]="$val"
    done
}
parse_map SLOT_OF       "$INTEROP_NODE_SLOTS"
parse_map CONTAINER     "$INTEROP_NODE_CONTAINERS"
parse_map NODE_IP_OF    "$INTEROP_NODE_IPS"
parse_map NPUB_OF       "$INTEROP_NODE_NPUBS"
declare -A NODE_IP2_OF
parse_map NODE_IP2_OF   "${INTEROP_NODE_IPS2:-}"
INTEROP_MULTIPATH="${INTEROP_MULTIPATH:-}"
INTEROP_CAPTURES="${INTEROP_CAPTURES:-}"
INTEROP_MP_TRANSPORT="${INTEROP_MP_TRANSPORT:-}"
MP_DIR="$RUN_BASE/multipath"
MP_A1_START=1
MP_C1_START=1
MP_MACS=""

# Topology metadata: per-node expected direct-peer degree, and the
# undirected direct-edge set (for direct-vs-routed pair labeling).
TOPOLOGY_KIND="${INTEROP_TOPOLOGY:-full-mesh}"
declare -A DEGREE_OF
parse_map DEGREE_OF     "${INTEROP_NODE_DEGREE:-}"

declare -A IS_DIRECT_EDGE
if [ -n "${INTEROP_TOPOLOGY_EDGES:-}" ]; then
    for _e in $INTEROP_TOPOLOGY_EDGES; do
        _x="${_e%%-*}"; _y="${_e#*-}"
        IS_DIRECT_EDGE["$_x|$_y"]=1
        IS_DIRECT_EDGE["$_y|$_x"]=1
    done
else
    # Full mesh: every ordered pair is a direct edge.
    for _a in "${NODES[@]}"; do
        for _b in "${NODES[@]}"; do
            [ "$_a" = "$_b" ] && continue
            IS_DIRECT_EDGE["$_a|$_b"]=1
        done
    done
fi

pair_is_direct() { [ -n "${IS_DIRECT_EDGE[$1|$2]:-}" ]; }
hop_label()      { if pair_is_direct "$1" "$2"; then echo "direct"; else echo "routed"; fi; }

# Data-plane stream directed pairs (both directions of each token).
STREAM_PAIRS=()
if [ -n "${FIPS_INTEROP_STREAMS:-}" ]; then
    for _tok in ${FIPS_INTEROP_STREAMS//,/ }; do
        _x="${_tok%%-*}"; _y="${_tok#*-}"
        STREAM_PAIRS+=("$_x $_y" "$_y $_x")
    done
fi

# Unordered pairs of the mesh.
PAIRS=()
for ((i = 0; i < ${#NODES[@]}; i++)); do
    for ((j = i + 1; j < ${#NODES[@]}; j++)); do
        PAIRS+=("${NODES[$i]} ${NODES[$j]}")
    done
done

NUM_NODES="${#NODES[@]}"
NUM_PAIRS="${#PAIRS[@]}"
NUM_DIRECTED=$((NUM_PAIRS * 2))
PEERS_EXPECTED=$((NUM_NODES - 1))

# ── Ref / version metadata ───────────────────────────────────────────
#
# refs.env (written by build-images.sh) records what each SLOT was built
# from. If absent, fall back to the image labels, then to "unknown".
# These maps are keyed by SLOT (a/b/c), not by node id.

declare -A SLOT_REF SLOT_SHA

load_slot_metadata() {
    local slot upper
    for slot in a b c; do
        SLOT_REF[$slot]="unknown"
        SLOT_SHA[$slot]="unknown"
    done
    if [ -f "$REFS_ENV" ]; then
        # shellcheck disable=SC1090
        source "$REFS_ENV"
    fi
    for slot in a b c; do
        upper="$(echo "$slot" | tr '[:lower:]' '[:upper:]')"
        local ref_var="INTEROP_REF_${upper}"
        local sha_var="INTEROP_SHA_${upper}"
        if [ -n "${!ref_var:-}" ]; then
            SLOT_REF[$slot]="${!ref_var}"
            SLOT_SHA[$slot]="${!sha_var:-unknown}"
            continue
        fi
        local lbl_ref lbl_sha
        lbl_ref="$(docker image inspect "$INTEROP_IMAGE:$slot" \
            --format '{{ index .Config.Labels "fips.interop.ref" }}' 2>/dev/null || true)"
        lbl_sha="$(docker image inspect "$INTEROP_IMAGE:$slot" \
            --format '{{ index .Config.Labels "fips.interop.sha" }}' 2>/dev/null || true)"
        [ -n "$lbl_ref" ] && SLOT_REF[$slot]="$lbl_ref"
        [ -n "$lbl_sha" ] && SLOT_SHA[$slot]="$lbl_sha"
    done
}

# A pair is "mixed-version" iff the two nodes' image slots resolve to
# different built SHAs. SHA is the precise discriminator; ref names can
# differ yet point at the same commit.
pair_is_mixed() {
    local n1="$1" n2="$2"
    local s1="${SLOT_OF[$n1]}" s2="${SLOT_OF[$n2]}"
    if [ "${SLOT_SHA[$s1]}" = "${SLOT_SHA[$s2]}" ] \
        && [ "${SLOT_SHA[$s1]}" != "unknown" ]; then
        return 1   # same version
    fi
    return 0       # mixed (or unknown — treat as mixed for scrutiny)
}

pair_kind() {
    if pair_is_mixed "$1" "$2"; then
        echo "MIXED"
    else
        echo "same"
    fi
}

pair_label() {
    # e.g. "a1[A fix/...@3045212] <-> c1[C v0.3.0@b11b639]"
    local n1="$1" n2="$2"
    local s1="${SLOT_OF[$n1]}" s2="${SLOT_OF[$n2]}"
    local u1 u2
    u1="$(echo "$s1" | tr '[:lower:]' '[:upper:]')"
    u2="$(echo "$s2" | tr '[:lower:]' '[:upper:]')"
    echo "${n1}[$u1 ${SLOT_REF[$s1]}@${SLOT_SHA[$s1]}] <-> ${n2}[$u2 ${SLOT_REF[$s2]}@${SLOT_SHA[$s2]}]"
}

# ── Helpers ──────────────────────────────────────────────────────────

# ping6 from one container to another node's mesh address (npub.fips).
ping_one() {
    local from_node="$1" to_node="$2" quiet="${3:-}"
    local max_attempts="${4:-1}"
    local from_ctr="${CONTAINER[$from_node]}"
    local to_npub="${NPUB_OF[$to_node]}"
    local label="$from_node -> $to_node"

    local attempt=1 output rtt
    while (( attempt <= max_attempts )); do
        (( attempt > 1 )) && sleep "$PING_RETRY_DELAY"
        if output=$(docker exec "$from_ctr" ping6 -c 1 -W "$PING_TIMEOUT" \
            "${to_npub}.fips" 2>&1); then
            rtt=$(echo "$output" | grep -oE 'time=[0-9.]+' | cut -d= -f2)
            if [ -z "$quiet" ]; then
                echo "  $label ... OK (${rtt:-?}ms${attempt:+, attempt $attempt})"
            fi
            PASSED=$((PASSED + 1))
            return 0
        fi
        attempt=$((attempt + 1))
    done
    if [ -z "$quiet" ]; then
        echo "  $label ... FAIL (after $max_attempts attempt(s))"
    fi
    FAILED=$((FAILED + 1))
    return 1
}

# All directed pairs of the mesh. Records pair-attributed failures into
# INTEROP_FAILURES, with the mixed/same classification.
ping_all_pairs() {
    local quiet="${1:-}" max_attempts="${2:-1}" context="${3:-connectivity}"
    PASSED=0
    FAILED=0
    local i j
    for i in "${NODES[@]}"; do
        for j in "${NODES[@]}"; do
            [ "$i" = "$j" ] && continue
            if ! ping_one "$i" "$j" "$quiet" "$max_attempts"; then
                # The `convergence` context is the wait_for_full_baseline
                # detector poll, NOT an assertion: a miss there only means
                # "not converged yet, keep polling". Recording detector
                # misses as interop failures is wrong — it false-fails
                # every rep that takes a moment to converge. Only the
                # strict assertion sweeps (baseline / post-rekey-*) record.
                if [ "$context" != "convergence" ]; then
                    local kind hop
                    kind="$(pair_kind "$i" "$j")"
                    hop="$(hop_label "$i" "$j")"
                    # NOTE: keep "$kind pair" contiguous — interop-stress.sh
                    # greps "MIXED pair"/"same pair". The [hop] tag is additive.
                    INTEROP_FAILURES+=("[$context] $kind pair $(pair_label "$i" "$j") [$hop]: ping $i->$j FAILED")
                fi
            fi
        done
    done
}

# Convergence detector probe: one full all-pairs ping sweep in the
# "convergence" context (which ping_all_pairs deliberately does NOT
# record as a failure), setting PASSED/FAILED for wait_until_connected.
_baseline_probe() {
    ping_all_pairs quiet 1 "convergence"
}

# Poll until every directed pair pings clean, or until timeout. This is a
# convergence DETECTOR — used at establishment (Phase 1) and after each
# rekey (Phases 3/5). It pings with the "convergence" context, which
# ping_all_pairs deliberately does not record as a failure; the caller
# runs a separate strict assertion sweep afterwards.
#
# Delegates to the shared progress-aware wait_until_connected so the
# deadline extends while more pairs are still coming up and gives up fast
# on a genuine stall, instead of the prior fixed-deadline poll that could
# false-time-out under heavy CI contention even while still converging.
# Returns 0 once every pair is reachable, 1 on stall/timeout.
wait_for_full_baseline() {
    local timeout="$1"
    wait_until_connected _baseline_probe "$timeout" "$RECONVERGE_STALL"
}

phase_result() {
    local phase="$1"
    TOTAL_PASSED=$((TOTAL_PASSED + PASSED))
    TOTAL_FAILED=$((TOTAL_FAILED + FAILED))
    if [ "$FAILED" -eq 0 ]; then
        echo "  PASS  $phase: $PASSED/$((PASSED + FAILED))"
    else
        echo "  FAIL  $phase: $PASSED passed, $FAILED FAILED"
    fi
}

# count_log_pattern <pattern> [node...] is in checks.sh, with the other
# log readers.

# Count completed FMP rekey cutovers across all node logs.
#
# The line says "(initiator)", but it does not show direction in a mixed
# mesh: builds before v0.5.2 also log it as a responder, on the self-cutover
# one tick after sending msg2. So this counts cutovers of either role, and
# every caller reports it as a role-blind count. None needs direction: the
# control window wants any cutover, and the rekey phases want proof that
# rekeys completed.
#
# The pattern is a literal argument so the log-string guard can check it
# against the daemon source. Prints the count, or `unreadable:<ctr>` with
# status 1 when a node's logs cannot be read.
fmp_cutover_count() {
    count_log_pattern 'Rekey cutover complete \(initiator\), K-bit flipped'
    return $?
}

# Wait until the FMP cutover count has held unchanged for
# CONTROL_QUIET_SECS, giving up after CONTROL_QUIET_MAX. An unreadable
# count is treated as a change, so it never counts as quiet.
wait_cutover_quiet() {
    local start=$SECONDS still=$SECONDS last cur
    last="$(fmp_cutover_count)" || last="unreadable"
    while (( SECONDS - still < CONTROL_QUIET_SECS )); do
        if (( SECONDS - start >= CONTROL_QUIET_MAX )); then
            echo "    cutover count still moving after ${CONTROL_QUIET_MAX}s; measuring anyway"
            return 1
        fi
        sleep 1
        cur="$(fmp_cutover_count)" || cur="unreadable"
        if [ "$cur" != "$last" ] || [ "$cur" = "unreadable" ]; then
            last="$cur"
            still=$SECONDS
        fi
    done
    return 0
}

# Per-node count of a pattern.
count_node_pattern() {
    local node="$1" pattern="$2"
    docker logs "${CONTAINER[$node]}" 2>&1 | grep -cE "$pattern" || true
}

# Wait until the count of a pattern across all node logs reaches
# min_count. Returns 0 when it does, 1 on timeout, and 2 at once when a
# node's logs cannot be read, since no count is established then; the
# caller reports that when it takes its own count.
wait_for_log_pattern_count() {
    local pattern="$1" min_count="$2" timeout="$3"
    local start=$SECONDS count
    while :; do
        count="$(count_log_pattern "$pattern")" || return 2
        [ "$count" -ge "$min_count" ] && return 0
        (( SECONDS - start < timeout )) || return 1
        sleep "$LOG_POLL_INTERVAL"
    done
}

# One node's bloom-union mesh-size estimate, or "null" when the daemon
# has no estimate yet or cannot be reached.
mesh_estimate() {
    docker exec "${CONTAINER[$1]}" fipsctl show status 2>/dev/null \
        | python3 -c "import sys,json; v=json.load(sys.stdin).get('estimated_mesh_size'); print(v if v is not None else 'null')" 2>/dev/null \
        || echo null
}

# The direct neighbours <node> does not list in `fipsctl show peers`, as
# space-separated node ids (empty when all are listed). Prints `unreadable`
# with status 1 when the node cannot be asked or its answer cannot be
# parsed, so a dead reader is never taken for a full peer list.
missing_peers() {
    local n="$1" out listed m missing=""
    if ! out="$(docker exec "${CONTAINER[$n]}" fipsctl show peers 2>/dev/null)" \
        || ! listed="$(python3 -c 'import sys,json; print(" ".join(p["npub"] for p in json.load(sys.stdin)["peers"]))' <<<"$out" 2>/dev/null)"; then
        echo "unreadable"
        return 1
    fi
    for m in "${NODES[@]}"; do
        pair_is_direct "$n" "$m" || continue
        case " $listed " in
            *" ${NPUB_OF[$m]} "*) ;;
            *) missing+=" $m" ;;
        esac
    done
    echo "${missing# }"
    return 0
}

# One link-continuity round over every node: record each direct neighbour
# a node has stopped listing, and each node that could not be asked. A
# peer drops out of `show peers` only when its link is removed (a stale
# but live link stays listed), so a miss here is a lost link, not loss
# noise. Phase 7 runs no pings, so without this a link lost during its
# warmup would pass the run.
#
# A node that cannot be asked is a different matter: one failed
# `docker exec` says nothing about its links. An isolated unreadable round
# is counted and reported but tolerated; two in a row, or an unreadable
# final round, fail the node, because then the harness has stopped
# observing it. A link lost and re-established inside the unread gap
# still leaves an "MMP link teardown" line for Phase 8 to find.
declare -A LINK_LOST_AT LINK_LOST_ROUNDS LINK_UNREADABLE LINK_UNREAD_RUN LINK_UNREAD_WORST
LINK_ROUNDS=0
check_links_round() {
    local n m missing at=$(( SECONDS - MESH_UP_AT ))
    LINK_ROUNDS=$((LINK_ROUNDS + 1))
    for n in "${NODES[@]}"; do
        if ! missing="$(missing_peers "$n")"; then
            LINK_UNREADABLE[$n]=$(( ${LINK_UNREADABLE[$n]:-0} + 1 ))
            LINK_UNREAD_RUN[$n]=$(( ${LINK_UNREAD_RUN[$n]:-0} + 1 ))
            if [ "${LINK_UNREAD_RUN[$n]}" -gt "${LINK_UNREAD_WORST[$n]:-0}" ]; then
                LINK_UNREAD_WORST[$n]="${LINK_UNREAD_RUN[$n]}"
            fi
            echo "    UNREADABLE  $n: show peers could not be read (${at}s after mesh start)"
            continue
        fi
        LINK_UNREAD_RUN[$n]=0
        for m in $missing; do
            if [ -z "${LINK_LOST_AT[$n|$m]:-}" ]; then
                LINK_LOST_AT[$n|$m]="$at"
                echo "    LINK LOST  $n no longer lists direct peer $m (${at}s after mesh start)"
            fi
            LINK_LOST_ROUNDS[$n|$m]=$(( ${LINK_LOST_ROUNDS[$n|$m]:-0} + 1 ))
        done
    done
    return 0
}

# Global negative checks — these must be zero on EVERY node regardless
# of version pairing. A non-zero count is attributed to the node and,
# where the count is asymmetric across versions, flagged as interop.
# Every pattern must be live at the level generate-configs.sh sets.
declare -A GLOBAL_PATTERNS=(
    ["PANIC|panicked"]="panics"
    ["ERROR"]="error-level log lines"
    ["unknown FMP version|Unknown FMP version"]="unknown-FMP-version drops"
    ["MMP link teardown"]="MMP link teardowns (a peer removed)"
    ["Excessive decryption failures"]="decryption-failure threshold crossings"
    ["Session AEAD decryption failed"]="FSP AEAD decrypt failures"
    ["Rekey msg2 processing failed"]="rekey msg2 failures"
    ["Handshake failed|handshake failed"]="handshake failures"
)

scan_global_patterns() {
    local pat desc total n c s u
    for pat in "${!GLOBAL_PATTERNS[@]}"; do
        desc="${GLOBAL_PATTERNS[$pat]}"
        if ! total="$(count_log_pattern "$pat")"; then
            echo "    FAIL  $desc: node logs unreadable ($total), zero not established"
            FAILED=$((FAILED + 1))
            INTEROP_FAILURES+=("[log] $desc: node logs unreadable ($total)")
            continue
        fi
        if [ "$total" -eq 0 ]; then
            echo "    PASS  $desc: 0"
            PASSED=$((PASSED + 1))
        else
            echo "    FAIL  $desc: $total (expected 0)"
            FAILED=$((FAILED + 1))
            # Per-node breakdown so the count can be attributed to a build.
            for n in "${NODES[@]}"; do
                c="$(count_node_pattern "$n" "$pat")"
                if [ "$c" -gt 0 ]; then
                    s="${SLOT_OF[$n]}"
                    u="$(echo "$s" | tr '[:lower:]' '[:upper:]')"
                    echo "          $n [$u ${SLOT_REF[$s]}@${SLOT_SHA[$s]}]: $c"
                    INTEROP_FAILURES+=("[log] node $n ($u ${SLOT_REF[$s]}@${SLOT_SHA[$s]}): $c x '$desc'")
                fi
            done
        fi
    done
    return 0
}

# ── Data-plane continuity streams ────────────────────────────────────
#
# A sustained ping6 stream over the overlay (<npub>.fips) is data-plane
# traffic: it traverses TUN → FSP session → FMP link → forwarding, the
# same path application packets take. We run streams across the rekey
# window and across a quiet control window, then compare loss — a rekey
# that drops data shows up as rekey-window loss above the control.

declare -A STREAM_TX STREAM_RX
_STREAM_PIDS=()
_STREAM_FILES=()        # "label:from->to:resultfile"
_STREAM_TMP=""

# One directed ping6 stream of <dur>s at STREAM_RATE_HZ; writes "tx rx".
_stream_one() {
    local from="$1" to="$2" dur="$3" outfile="$4"
    local from_ctr="${CONTAINER[$from]}" to_npub="${NPUB_OF[$to]}"
    local count=$(( dur * STREAM_RATE_HZ ))
    local out tx rx interval
    # Interval and count both derive from STREAM_RATE_HZ, so the packet
    # count the margin is reasoned about cannot drift from the rate sent.
    interval=$(awk -v hz="$STREAM_RATE_HZ" 'BEGIN{ printf "%.3f", 1/hz }')
    out=$(docker exec "$from_ctr" ping6 -i "$interval" -c "$count" -W "$PING_TIMEOUT" \
        "${to_npub}.fips" 2>&1)
    tx=$(echo "$out" | grep -oE '[0-9]+ packets transmitted' | grep -oE '^[0-9]+')
    rx=$(echo "$out" | grep -oE '[0-9]+ received' | grep -oE '^[0-9]+')
    echo "${tx:-0} ${rx:-0}" > "$outfile"
}

# Launch all stream pairs in the background for <label> over <dur>s.
launch_streams() {
    local label="$1" dur="$2"
    _STREAM_TMP="$(mktemp -d)"  # mount-tmpdir: ping counts this shell writes and reads, never mounted
    _STREAM_PIDS=(); _STREAM_FILES=()
    local sp from to
    for sp in "${STREAM_PAIRS[@]}"; do
        read -r from to <<< "$sp"
        _stream_one "$from" "$to" "$dur" "$_STREAM_TMP/$label-$from-$to" &
        _STREAM_PIDS+=("$!")
        _STREAM_FILES+=("$label:$from->$to:$_STREAM_TMP/$label-$from-$to")
    done
}

# Wait for the launched streams and read tx/rx into STREAM_TX/STREAM_RX.
collect_streams() {
    [ "${#_STREAM_PIDS[@]}" -gt 0 ] && wait "${_STREAM_PIDS[@]}" 2>/dev/null || true
    local entry label rest key f tx rx
    for entry in "${_STREAM_FILES[@]}"; do
        label="${entry%%:*}"; rest="${entry#*:}"; key="${rest%%:*}"; f="${rest#*:}"
        if read -r tx rx < "$f" 2>/dev/null; then :; else tx=0; rx=0; fi
        STREAM_TX["$label:$key"]="${tx:-0}"
        STREAM_RX["$label:$key"]="${rx:-0}"
    done
    [ -n "$_STREAM_TMP" ] && rm -rf "$_STREAM_TMP"
    _STREAM_TMP=""
}

# loss% from tx/rx (one decimal), or "NA" when tx==0.
_loss_pct() {
    awk -v t="${1:-0}" -v r="${2:-0}" \
        'BEGIN{ if (t>0) printf "%.1f", (t-r)*100/t; else print "NA" }'
}

dump_diagnostics() {
    echo ""
    echo "=== Peer / link snapshot ==="
    local n s
    for n in "${NODES[@]}"; do
        s="${SLOT_OF[$n]}"
        echo "--- $n (slot $s, ${SLOT_REF[$s]}@${SLOT_SHA[$s]}) ---"
        docker exec "${CONTAINER[$n]}" fipsctl show peers 2>/dev/null || true
        docker exec "${CONTAINER[$n]}" fipsctl show links 2>/dev/null || true
        echo ""
    done
    echo "=== Recent node logs (interop-relevant lines) ==="
    for n in "${NODES[@]}"; do
        echo "--- $n ---"
        docker logs "${CONTAINER[$n]}" 2>&1 \
            | grep -E "(ERROR|PANIC|panicked|FMP version|handshake|Handshake|decrypt|Decrypt|teardown|rekey|Rekey|K-bit|established|Established)" \
            | tail -40
        echo ""
    done
}

# ── Multipath mode (--multipath, --probe-hour) ───────────────────────
#
# A node with multipath enabled (a1, slot a) against a release that does
# not implement it (c1, slot c), joined on a second network as well as
# the first. What the multipath draft promises such a peer, and what the
# phases below check:
#
#   M0  every check below fails or abstains on planted input (checks.sh)
#   Pre each capture runs before its daemon; addresses; mp2 is up
#   M1  no capability probe before a candidate is held (request mode);
#       the candidate is given by `fipsctl connect` and not dialled
#   C1  a marked datagram shows each second-interface capture live, and
#       the ARP request before it shows no neighbour entry existed
#   M2  1 to capability_bound(310) probes discarded at the old node, no
#       PathAck or PathClose, nothing else unknown; every probe sent on
#       the original path at 27 bytes and seen at the wire; the gaps at
#       or above the draft's floors; smoothed_loss present and 0; one
#       path; no frame on either second interface; no send or dial line
#       to the second network (W)
#   M3  short runs: the old node killed past link-dead is removed and
#       dialled again (C2 first), nothing on the second interfaces in the
#       outage, and the new link's probes within its bound (0 in request
#       mode, whose candidate went with the old link)
#   M4  --probe-hour: the count at 3610 s against capability_bound(3610),
#       the gaps, and the bytes the old node received
#   M5  a last marked datagram on every capture whose zero was reported
#
# A zero read from a log line counts only once that line is shown live in
# this run at that node (checks.sh, mp_gates and dial_gate); otherwise it
# is "not established", which fails the run as any other check does.

# mp_record <label> [nofail]: record the last check's verdict in this
# phase's PASSED/FAILED and the failure list. NE fails like FAIL.
mp_record() {
    local label="$1"
    case "$V" in
        PASS)
            echo "    PASS  $label: $VD"
            PASSED=$((PASSED + 1))
            ;;
        FAIL|NE)
            echo "    $V  $label: $VD"
            FAILED=$((FAILED + 1))
            INTEROP_FAILURES+=("[multipath] $label: $V ($VD)")
            ;;
        *)
            echo "    FAIL  $label: no verdict"
            FAILED=$((FAILED + 1))
            INTEROP_FAILURES+=("[multipath] $label: no verdict")
            ;;
    esac
    V=""
    VD=""
}

# mp_note <text>: a line the record reads that decides nothing.
mp_note() { echo "    NOTE  $*"; }

# mp_stop <why>: a stop condition. Record it and end the run red.
mp_stop() {
    echo "    STOP  $*"
    INTEROP_FAILURES+=("[multipath] STOP: $*")
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
    dump_diagnostics
    echo ""
    echo "FAIL: multipath stop condition: $*"
    exit 1
}

# mp_now: the host's clock as epoch seconds with microseconds; the
# containers share it, so it compares with their log stamps.
mp_now() { date +%s.%6N; }

# mp_wait_until <epoch>: sleep until the host clock passes <epoch>.
mp_wait_until() {
    local left
    left="$(awk -v t="$1" -v n="$(mp_now)" 'BEGIN{d=t-n; if (d<0) d=0; printf "%.1f", d}')"
    sleep "$left"
}

# mp_capfile <node> <iface> <start>: the capture file of that start
# (1 for the first), from the wrapper's `captures running` lines.
mp_capfile() {
    local n="$1" ifc="$2" k="$3" lines tag
    lines="$(matching_lines 'capture-entry: ' "$n")" || return 1
    tag="$(grep -F 'capture-entry: captures running' <<<"$lines" | sed -n "${k}p" | awk '{print $NF}')"
    [ -n "$tag" ] || return 1
    echo "$INTEROP_CAPTURES/$n-$ifc-$tag.pcap"
}

# mp_pre <node> <start>: the checks after a container's <start>-th start:
# its wrapper printed `captures running` with no FATAL, before the
# daemon's first line; every capture file exists and its tcpdump runs;
# eth0 and eth1 carry the node's two addresses.
mp_pre() {
    local n="$1" k="$2" ifaces="eth1" lines seq want ifc f t0 procs addr mac
    [ "${SLOT_OF[$n]}" = "c" ] && ifaces="eth1 eth0"
    t0=$SECONDS
    while :; do
        lines="$(matching_lines 'capture-entry: |starting' "$n")" || lines=""
        if grep -qF 'capture-entry: FATAL' <<<"$lines"; then
            verdict FAIL "$(grep -F 'capture-entry: FATAL' <<<"$lines" | tail -1)"
            mp_record "Pre $n start $k: capture wrapper"
            mp_stop "capture wrapper failed on $n"
        fi
        [ "$(grep_count 'capture-entry: captures running' "$lines")" -ge "$k" ] && break
        if (( SECONDS - t0 > 45 )); then
            verdict FAIL "no 'captures running' line for start $k within 45 s"
            mp_record "Pre $n start $k: capture wrapper"
            mp_stop "captures did not start on $n"
        fi
        sleep 1
    done
    # The order of the wrapper's line and the daemon's first line, one
    # letter per line: R for `captures running`, S for the daemon's
    # `FIPS <version> ... starting`. Each start must read RS.
    sleep 2
    lines="$(matching_lines 'capture-entry: |starting' "$n")" || lines=""
    seq="$(awk '/capture-entry: captures running/ {printf "R"} / fips: FIPS .* starting/ {printf "S"}' <<<"$lines")"
    want="$(printf 'RS%.0s' $(seq 1 "$k"))"
    if [ "$seq" = "$want" ]; then
        verdict PASS "wrapper line before the daemon's first line on each start ($seq)"
    else
        verdict FAIL "wrapper and daemon lines in the order $seq, expected $want"
    fi
    mp_record "Pre $n start $k: captures before the daemon"
    procs="$(docker exec "${CONTAINER[$n]}" pgrep -c tcpdump 2>/dev/null || echo unreadable)"
    for ifc in $ifaces; do
        f="$(mp_capfile "$n" "$ifc" "$k")" || f=""
        if [ -n "$f" ] && [ -s "$f" ]; then
            verdict PASS "$(basename "$f") ($(stat -c %s "$f") bytes)"
        else
            verdict FAIL "no capture file for start $k (${f:-unnamed})"
        fi
        mp_record "Pre $n start $k: $ifc capture file"
    done
    chk_range "$procs" "$(wc -w <<<"$ifaces")" "$(wc -w <<<"$ifaces")"
    mp_record "Pre $n start $k: tcpdump processes running"
    addr="$(docker exec "${CONTAINER[$n]}" ip -o -4 addr show dev eth0 2>/dev/null)"
    if [[ "$addr" == *" ${NODE_IP_OF[$n]}/24 "* ]]; then verdict PASS "eth0 ${NODE_IP_OF[$n]}"; else verdict FAIL "eth0: ${addr:-unreadable}"; fi
    mp_record "Pre $n start $k: first-network address on eth0"
    addr="$(docker exec "${CONTAINER[$n]}" ip -o -4 addr show dev eth1 2>/dev/null)"
    if [[ "$addr" == *" ${NODE_IP2_OF[$n]}/24 "* ]]; then verdict PASS "eth1 ${NODE_IP2_OF[$n]}"; else verdict FAIL "eth1: ${addr:-unreadable}"; fi
    mp_record "Pre $n start $k: second-network address on eth1"
    # The node's MACs: a UDP datagram on a second interface is the node's
    # only when it comes from one of them (checks.sh, pcap).
    for ifc in eth0 eth1; do
        mac="$(docker exec "${CONTAINER[$n]}" cat "/sys/class/net/$ifc/address" 2>/dev/null)" || mac=""
        if [[ "$mac" =~ ^[0-9a-f]{2}(:[0-9a-f]{2}){5}$ ]]; then
            verdict PASS "$mac"
            MP_MACS="${MP_MACS:+$MP_MACS,}$mac"
        else
            verdict FAIL "unreadable (${mac:-none})"
        fi
        mp_record "Pre $n start $k: $ifc MAC"
    done
}

# mp_transport_check: a1's second UDP transport is up on eth1. Without
# it the connect request's candidate resolves to no pair and the reply
# is the same "peer live, not dialled", so M2's lower bound would fail
# with no cause stated.
mp_transport_check() {
    local out
    out="$(docker exec "${CONTAINER[a1]}" fipsctl show transports 2>/dev/null)" || out=""
    py_verdict "$(mp_py transports "${INTEROP_MP_TRANSPORT#udp/}" "$INTEROP_MP_PORT" <<<"$out")"
    mp_record "Pre a1: transport ${INTEROP_MP_TRANSPORT#udp/} up on port $INTEROP_MP_PORT"
    # The device binding, as the kernel holds it: ss prints a socket
    # bound to a device as <addr>%<device>:<port>.
    out="$(docker exec "${CONTAINER[a1]}" ss -Hlun 2>/dev/null)" || out=""
    if grep -qF -- "%eth1:$INTEROP_MP_PORT " <<<"$out"; then
        verdict PASS "$(grep -F -- "%eth1:$INTEROP_MP_PORT " <<<"$out" | awk '{print $4}')"
    else
        verdict FAIL "no UDP socket bound to eth1 on port $INTEROP_MP_PORT (ss: $(tr -s ' \n' ' ' <<<"${out:-unreadable}"))"
    fi
    mp_record "Pre a1: the $INTEROP_MP_PORT socket is bound to eth1"
}

# mp_control <label> [need-arp]: one marked datagram from a1's second
# address to c1's, port 40999 to 40999, which nothing listens on. Every
# current second-interface capture must count it once more; with
# need-arp, a1's must show an ARP request for c1's address before it.
MP_CTL_TIMES="-"
mp_control() {
    local label="$1" need="${2:-}" fa fc ba bc t
    fa="$(mp_capfile a1 eth1 "$MP_A1_START")" || fa=""
    fc="$(mp_capfile c1 eth1 "$MP_C1_START")" || fc=""
    ba="unreadable"
    bc="unreadable"
    if pcap_read "$fa" - - - - -; then ba="$PC_CTL"; fi
    if pcap_read "$fc" - - - - -; then bc="$PC_CTL"; fi
    t="$(mp_now)"
    MP_CTL_TIMES="$MP_CTL_TIMES,$t"
    if ! docker exec "${CONTAINER[a1]}" python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('${NODE_IP2_OF[a1]}', 40999)); s.sendto(b'fips-multipath-control', ('${NODE_IP2_OF[c1]}', 40999))"; then
        verdict FAIL "the control datagram could not be sent"
        mp_record "$label: send"
        return
    fi
    sleep 2
    if [ "$need" = "need-arp" ]; then
        chk_control "$ba" "$fa" "$MP_CTL_TIMES" need-arp "${NODE_IP2_OF[a1]}" "${NODE_IP2_OF[c1]}"
    else
        chk_control "$ba" "$fa" "$MP_CTL_TIMES"
    fi
    mp_record "$label: a1 eth1 capture $(basename "${fa:-none}")"
    chk_control "$bc" "$fc" "$MP_CTL_TIMES"
    mp_record "$label: c1 eth1 capture $(basename "${fc:-none}")"
}

# mp_quiet <label> [from] [to]: no FIPS frame on either second interface
# in every capture file so far (a1's with the ARP rule).
mp_quiet() {
    local label="$1" from="${2:--}" to="${3:--}" f
    for f in "$INTEROP_CAPTURES"/a1-eth1-*.pcap; do
        chk_quiet "$f" "$from" "$to" "${NODE_IP2_OF[a1]}" "${NODE_IP2_OF[c1]}" "$MP_CTL_TIMES" "$MP_MACS"
        mp_record "$label: no FIPS frame, $(basename "$f")"
    done
    for f in "$INTEROP_CAPTURES"/c1-eth1-*.pcap; do
        chk_quiet "$f" "$from" "$to" - - "$MP_CTL_TIMES" "$MP_MACS"
        mp_record "$label: no FIPS frame, $(basename "$f")"
    done
}

# mp_witness <label>: W, the log witness that needs no neighbour table:
# no send line and no dial line at a1, and no dial line at c1, to a
# second-network address. Each zero is gated on its line being live.
mp_witness() {
    local label="$1" net2="${INTEROP_SUBNET2}."
    if counted_lines 'Path message sent' a1; then
        chk_absent "$CL_LINES" " remote_addr=$net2" "send lines to the second network"
        [ "$A1_LIVE" = 1 ] || verdict NE "not established: $A1_WHY"
    else
        verdict NE "not established: $CL_WHY"
    fi
    mp_record "$label: W, a1 Path message sent"
    if counted_lines 'Path message not sent' a1; then
        chk_absent "$CL_LINES" " remote_addr=$net2" "failed sends to the second network"
        [ "$A1_LIVE" = 1 ] || verdict NE "not established: $A1_WHY"
        [ "$CL_N" -eq 0 ] || mp_note "a1 logged $CL_N 'Path message not sent' line(s)"
    else
        verdict NE "not established: $CL_WHY"
    fi
    mp_record "$label: W, a1 Path message not sent"
    if [ "$INTEROP_MULTIPATH" = "config" ]; then
        mp_note "$label: a1 does not dial c1 in the configured run (manual); a1's eth1 capture alone carries its dial half of W"
    else
        dial_gate a1 "${NODE_IP_OF[c1]}"
        if counted_lines 'Connection initiated' a1; then
            chk_absent "$CL_LINES" " remote_addr=$net2" "dials to the second network"
            [ "$DIAL_LIVE" = 1 ] || verdict NE "not established: $DIAL_WHY"
        else
            verdict NE "not established: $CL_WHY"
        fi
        mp_record "$label: W, a1 Connection initiated"
    fi
    dial_gate c1 "${NODE_IP_OF[a1]}"
    if counted_lines 'Connection initiated' c1; then
        chk_absent "$CL_LINES" " remote_addr=$net2" "dials to the second network"
        [ "$DIAL_LIVE" = 1 ] || verdict NE "not established: $DIAL_WHY"
    else
        verdict NE "not established: $CL_WHY"
    fi
    mp_record "$label: W, c1 Connection initiated"
}

# mp_link_checks <label>: one path, the peer not capable; smoothed_loss
# present and 0, polled up to 60 s for the first ReceiverReport interval.
mp_link_checks() {
    local label="$1" out t0=$SECONDS
    out="$(docker exec "${CONTAINER[a1]}" fipsctl path show "${NPUB_OF[c1]}" 2>/dev/null)" || out=""
    chk_paths "$out" "${NODE_IP_OF[c1]}:2121"
    mp_record "$label: path show lists one path"
    while :; do
        out="$(docker exec "${CONTAINER[a1]}" fipsctl show mmp 2>/dev/null)" || out=""
        chk_loss "$out" c1
        if [ "$V" != "NE" ] || (( SECONDS - t0 >= 60 )); then
            break
        fi
        sleep 5
    done
    mp_record "$label: c1's receiver reports show no loss"
}

# mp_loss_sample <when>: report smoothed_loss and loss_rate (no verdict).
MP_LOSS_SAMPLES=0
mp_loss_sample() {
    local out
    out="$(docker exec "${CONTAINER[a1]}" fipsctl show mmp 2>/dev/null)" || out=""
    MP_LOSS_SAMPLES=$((MP_LOSS_SAMPLES + 1))
    echo "    loss sample $1: $(mp_py mmp c1 <<<"$out")"
}

# mp_sends_since <epoch>: SS_LINES, the probe send lines to c1's first
# address stamped at or after <epoch>, from counted lines.
mp_sends_since() {
    SS_LINES=""
    if ! counted_lines 'Path message sent' a1; then
        SS_WHY="$CL_WHY"
        return 1
    fi
    SS_LINES="$(grep -F -- " msg_type=82 " <<<"$CL_LINES" | mp_py since "$1")"
    return 0
}

# mp_offsets <lines> <epoch>: each line's offset from <epoch>, in s.
mp_offsets() {
    [ -n "$1" ] || { echo "-"; return; }
    mp_py stamps <<<"$1" | awk -v u="$2" '{printf "%s%.1f", (NR>1?" ":""), $1-u}'
}

# mp_probe_checks <label> <from-epoch>: the send lines since <from-epoch>
# against the original path and size, the wire, and the gap floors.
mp_probe_checks() {
    local label="$1" from="$2" eth0s f
    if ! mp_sends_since "$from"; then
        verdict NE "not established: $SS_WHY"
        mp_record "$label: probe sends on the original path at 27 bytes"
        return
    fi
    if [ "$A1_LIVE" = 1 ]; then
        if counted_lines 'Path message sent' a1; then
            chk_sends "$(mp_py since "$from" <<<"$CL_LINES")" "${NODE_IP_OF[c1]}:2121" 27
        else
            verdict NE "not established: $CL_WHY"
        fi
    else
        verdict NE "not established: $A1_WHY"
    fi
    mp_record "$label: probe sends on the original path at 27 bytes"
    eth0s=()
    for f in "$INTEROP_CAPTURES"/c1-eth0-*.pcap; do eth0s+=("$f"); done
    if [ "$A1_LIVE" = 1 ]; then
        py_verdict "$(mp_py wire "${eth0s[@]}" -- "${NODE_IP_OF[a1]}" "${NODE_IP_OF[c1]}" "$MP_PROBE_WIRE" <<<"$SS_LINES")"
        [ "$V" = PASS ] && VD="$VD (consistent with a 27-byte probe; the size is not unique to it)"
    else
        verdict NE "not established: $A1_WHY"
    fi
    mp_record "$label: each probe seen at c1's eth0 as a $MP_PROBE_WIRE-byte datagram"
    if [ "$A1_LIVE" = 1 ]; then chk_gaps "$SS_LINES"; else verdict NE "not established: $A1_WHY"; fi
    mp_record "$label: gaps between probes at or above the draft's floors"
}

# The UDP payload of a 27-byte link message: the 16-byte established
# header, the 4-byte inner timestamp, the message and the 16-byte AEAD
# tag (src/node/mod.rs, ESTABLISHED_HEADER_SIZE + inner_len + TAG_SIZE).
MP_PROBE_WIRE=63

# mp_sampler <at-epoch> <file>: in the background, at <at-epoch> count
# c1's probe discards, then a1's probe sends to c1's first address (in
# that order, so a probe sent between the reads can only raise a1's),
# and write both to <file>. A sampler that dies leaves no file, which
# the reader reports as not established.
mp_sampler() {
    local at="$1" file="$2"
    (
        mp_wait_until "$at"
        c="$(count_log_pattern 'Unknown link message type.*msg_type=82' c1)"
        if counted_lines 'Path message sent' a1; then
            a="$(probe_sends "$CL_LINES" "${NODE_IP_OF[c1]}:2121")"
        else
            a="unreadable"
        fi
        printf 'c1=%s\na1=%s\nat=%s\n' "$c" "$a" "$(mp_now)" > "$file.tmp" && mv "$file.tmp" "$file"
    ) &
    MP_SAMPLER_PID=$!
}

# mp_delta_patterns: GLOBAL_PATTERNS counts at every node, as
# `pattern<TAB>count` lines, for the deltas over a window. MMP link
# teardown is left out: the kill makes one by design.
mp_delta_patterns() {
    local pat
    for pat in "${!GLOBAL_PATTERNS[@]}"; do
        [ "$pat" = "MMP link teardown" ] && continue
        printf '%s\t%s\n' "$pat" "$(count_log_pattern "$pat")"
    done
}

# mp_delta_check <label> <before>: every pattern's count unchanged.
mp_delta_check() {
    local label="$1" before="$2" pat was now
    while IFS=$'\t' read -r pat was; do
        [ -n "$pat" ] || continue
        now="$(count_log_pattern "$pat")"
        if is_count "$was" && is_count "$now"; then
            chk_range "$((now - was))" 0 0
        else
            verdict NE "not established: $was -> $now"
        fi
        mp_record "$label: ${GLOBAL_PATTERNS[$pat]} delta"
    done <<<"$before"
}

# ── M1: no probe before a candidate; the connect request ─────────────

mp_m1() {
    echo "Phase M1: No capability probe before a candidate is held; the candidate"
    if [ "$INTEROP_MULTIPATH" = "request" ]; then
        mp_wait_until "$(awk -v u="$MP_LINK_UP" 'BEGIN{printf "%.6f", u + 40}')"
        MP_M1_C1="$(count_log_pattern 'Unknown link message type.*msg_type=82' c1)"
        if counted_lines 'Path message sent' a1; then
            MP_M1_A1="$(line_count "$CL_LINES")"
        else
            MP_M1_A1="unreadable"
        fi
        echo "    40 s after link-up: c1 probe discards $MP_M1_C1, a1 send lines $MP_M1_A1 (verdicts after M2's lower bounds)"
        ping_one a1 c1 quiet 4 || true
        local reply
        reply="$(docker exec "${CONTAINER[a1]}" fipsctl connect "${NPUB_OF[c1]}" "${NODE_IP2_OF[c1]}:2121" "$INTEROP_MP_TRANSPORT" 2>&1)" || true
        MP_CANDIDATE_AT="$(mp_now)"
        echo "    fipsctl connect reply: $(tr -s ' \n' ' ' <<<"$reply")"
        py_verdict "$(mp_py connect <<<"$reply")"
        local v="$V"
        mp_record "M1: connect request held the candidate without a dial"
        [ "$v" = PASS ] || mp_stop "the connect request's reply shows a dial or an error"
    else
        MP_CANDIDATE_AT="$MP_LINK_UP"
        mp_note "configured run: the candidate is the configured second address, held from link-up"
    fi
    MP_SAMPLE_FILE="$MP_DIR/sample-310"
    rm -f "$MP_SAMPLE_FILE"
    mp_sampler "$(awk -v u="$MP_LINK_UP" 'BEGIN{printf "%.6f", u + 310}')" "$MP_SAMPLE_FILE"
    echo "    310 s sampler started (pid $MP_SAMPLER_PID)"
    echo ""
}

# ── M2: the old node, the wire and the captures ──────────────────────

mp_m2() {
    local b out c total
    echo "Phase M2: The old node at 310 s, the probes, the wire, the captures"
    PASSED=0; FAILED=0
    mp_control "C1 (capture control, first)" need-arp
    if [ -n "${MP_SAMPLER_PID:-}" ]; then
        wait "$MP_SAMPLER_PID" 2>/dev/null || true
    fi
    sampler_read "$MP_SAMPLE_FILE" || true
    b="$(capability_bound 310)"
    echo "    capability_bound 310 = $b (budget $CAPABILITY_PROBE_BUDGET, span ${CAPABILITY_PROBE_SPAN}s, interval max ${CAPABILITY_PROBE_INTERVAL_MAX}s)"
    chk_range "$SAMPLE_C1" 1 "$b"
    mp_record "M2: c1 discarded 1 to $b capability probes in the first 310 s"
    # The gates: the old node's discard line is live once it is counted
    # at least once; the new node's send line once it counts at least as
    # many probe sends as the old node counted discards.
    if is_count "$SAMPLE_C1" && [ "$SAMPLE_C1" -ge 1 ]; then C1_LIVE=1; C1_WHY=""; else C1_LIVE=0; C1_WHY="no discard line at c1 at 310 s ($SAMPLE_C1)"; fi
    send_gate "$SAMPLE_C1" "$SAMPLE_A1" "${NODE_IP_OF[c1]}:2121"
    if [ "$A1_LIVE" = 1 ]; then verdict PASS "a1 $SAMPLE_A1 probe sends, c1 $SAMPLE_C1 discards"; else verdict NE "not established: $A1_WHY"; fi
    mp_record "M2: a1's probe sends at 310 s at least 1 and at least c1's discards"
    if [ "$INTEROP_MULTIPATH" = "request" ]; then
        chk_gated "$C1_LIVE" "$C1_WHY" "$MP_M1_C1" 0 0
        mp_record "M1: c1 discarded no probe before the candidate (40 s after link-up)"
        chk_gated "$A1_LIVE" "$A1_WHY" "$MP_M1_A1" 0 0
        mp_record "M1: a1 sent no path message before the candidate (40 s after link-up)"
    fi
    c="$(count_log_pattern 'Unknown link message type.*msg_type=8[34]' c1)"
    chk_gated "$C1_LIVE" "$C1_WHY" "$c" 0 0
    mp_record "M2: no PathAck or PathClose reached c1"
    # One read, so a probe arriving between two counts cannot split them.
    if counted_lines 'Unknown link message type' c1; then
        total="$CL_N"
        c="$(grep_count " msg_type=82" "$CL_LINES")"
        chk_gated "$C1_LIVE" "$C1_WHY" "$((total - c))" 0 0
    else
        total="?"; c="?"
        verdict NE "not established: $CL_WHY"
    fi
    mp_record "M2: every unknown-type discard at c1 is a capability probe ($c of $total)"
    if [ "$INTEROP_MULTIPATH" = "config" ]; then
        mp_moves a1 "$MP_LINK_UP"
        chk_gated "$MOVE_OK" "$MOVE_WHY" 0 0 0
        mp_record "M2: no session move after link-up (the bound counts from link-up)"
    else
        mp_moves a1 "$MP_LINK_UP"
        [ "$MOVE_OK" = 1 ] || mp_note "$MOVE_WHY (request run: a move drops the request candidate, which only lowers the count)"
    fi
    # From the mesh start, not the driver's link-up: the configured run's
    # first probes go at the true link-up, before the driver sees it.
    mp_probe_checks "M2" "$MP_MESH_EPOCH"
    echo "    probe offsets from link-up, s: $(mp_offsets "$SS_LINES" "$MP_LINK_UP")"
    if [ "$INTEROP_MULTIPATH" = "request" ]; then
        echo "    predicted (draft schedule from the connect request at $(awk -v a="$MP_CANDIDATE_AT" -v u="$MP_LINK_UP" 'BEGIN{printf "%.1f", a-u}') s): +0 +10 +20 +50 +110 +230 +470 +950 +1550 +2150 +2750 +3350"
    else
        echo "    predicted (candidate held from link-up): 0 10 20 50 110 230 470 950 1550 2150 2750 3350"
    fi
    mp_link_checks "M2"
    mp_quiet "M2"
    mp_witness "M2"
    phase_result "Multipath M2: old node, wire and captures"
    echo ""
}

# ── M3: the old node killed past link-dead, and the re-dial ──────────

mp_m3() {
    local rm0 dial0 cdial0 d0 p8 t0 rm dial new bad kill_at start_at up2 d sends b f
    echo "Phase M3: Re-dial after the old node is killed past link-dead"
    PASSED=0; FAILED=0
    mp_control "C2 (capture control, before the kill)"
    docker kill --signal KILL "${CONTAINER[c1]}" >/dev/null
    kill_at="$(mp_now)"
    echo "    c1 killed (SIGKILL) at $kill_at"
    # Counts after the kill, so the killed process adds nothing after them.
    rm0="$(count_log_pattern 'Removing peer: link dead timeout' a1)"
    dial0="$(count_log_pattern 'Connection initiated' a1)"
    cdial0="$(count_log_pattern 'Connection initiated' c1)"
    d0="$(count_log_pattern 'Unknown link message type.*msg_type=82' c1)"
    p8="$(mp_delta_patterns)"
    t0=$SECONDS
    while (( SECONDS - t0 < 120 )); do
        rm="$(count_log_pattern 'Removing peer: link dead timeout' a1)"
        dial="$(count_log_pattern 'Connection initiated' a1)"
        if is_count "$rm" && is_count "$rm0" && [ "$rm" -gt "$rm0" ]; then
            if [ "$INTEROP_MULTIPATH" = "config" ]; then break; fi
            if is_count "$dial" && is_count "$dial0" && [ "$dial" -gt "$dial0" ]; then break; fi
        fi
        sleep 2
    done
    echo "    after $(( SECONDS - t0 ))s: removals $rm0 -> $rm, a1 dials $dial0 -> $dial"
    if is_count "$rm" && is_count "$rm0"; then chk_range "$((rm - rm0))" 1 1; else verdict NE "not established: $rm0 -> $rm"; fi
    mp_record "M3: a1 removed c1 at link-dead (one removal)"
    if [ "$INTEROP_MULTIPATH" = "request" ]; then
        if is_count "$dial" && is_count "$dial0"; then chk_range "$((dial - dial0))" 1 99999; else verdict NE "not established: $dial0 -> $dial"; fi
        mp_record "M3: a1 dialled c1 again after the removal"
    fi
    start_at="$(mp_now)"
    docker start "${CONTAINER[c1]}" >/dev/null
    MP_C1_START=2
    mp_pre c1 2
    if wait_for_peers "${CONTAINER[a1]}" 1 120; then
        up2="$(mp_now)"
        verdict PASS "a1 lists c1 again"
    else
        up2="$(mp_now)"
        verdict FAIL "a1 did not list c1 within 120 s of the restart"
    fi
    mp_record "M3: link back within 120 s"
    if [ "$INTEROP_MULTIPATH" = "request" ]; then
        if counted_lines 'Connection initiated' a1; then
            new="$(mp_py since "$kill_at" <<<"$CL_LINES")"
            bad="$(grep -vcF -- " remote_addr=${NODE_IP_OF[c1]}:2121 " <<<"$new" || true)"
            [ -n "$new" ] || bad="no line"
            if [ "$bad" = 0 ]; then verdict PASS "$(line_count "$new") dial(s) since the kill, all to ${NODE_IP_OF[c1]}:2121"; else verdict FAIL "dials since the kill not all to the first network ($bad)"; fi
        else
            verdict NE "not established: $CL_WHY"
        fi
        mp_record "M3: every re-dial went to c1's first-network address"
    else
        d="$(count_log_pattern 'Connection initiated' c1)"
        if is_count "$d" && is_count "$cdial0"; then chk_range "$((d - cdial0))" 1 99999; else verdict NE "not established: $cdial0 -> $d"; fi
        mp_record "M3: c1 dialled a1 after its restart"
    fi
    # The outage: from the kill to the restart, a1's second interface
    # carried nothing, and W did not move.
    for f in "$INTEROP_CAPTURES"/a1-eth1-*.pcap; do
        chk_quiet "$f" "$kill_at" "$start_at" "${NODE_IP2_OF[a1]}" "${NODE_IP2_OF[c1]}" "$MP_CTL_TIMES" "$MP_MACS"
        mp_record "M3: no FIPS frame on a1's eth1 during the outage, $(basename "$f")"
    done
    # The new link's first 60 s, then its probes.
    mp_wait_until "$(awk -v u="$up2" 'BEGIN{printf "%.6f", u + 60}')"
    d="$(count_log_pattern 'Unknown link message type.*msg_type=82' c1)"
    # a1's sends since c1's restart: the old link was removed before it,
    # so each is on the new link.
    if counted_lines 'Path message sent' a1; then
        sends="$(line_count "$(mp_py since "$start_at" <<<"$CL_LINES")")"
    else
        sends="unreadable"
    fi
    sleep 5
    mp_gates c1 a1 "${NODE_IP_OF[c1]}:2121"
    if [ "$INTEROP_MULTIPATH" = "request" ]; then
        # The request candidate belonged to the old link, and a new link
        # re-offers only the configured and advertised feeds, so no
        # candidate is held: no probe from link-up to the end of the run.
        if is_count "$d" && is_count "$d0"; then chk_gated "$C1_LIVE" "$C1_WHY" "$((d - d0))" 0 0; else verdict NE "not established: $d0 -> $d"; fi
        mp_record "M3: c1 discarded no probe on the new link (no candidate held)"
        chk_gated "$A1_LIVE" "$A1_WHY" "$sends" 0 0
        mp_record "M3: a1 sent no path message on the new link"
    else
        b="$(capability_bound 60)"
        if is_count "$d" && is_count "$d0"; then chk_range "$((d - d0))" 0 "$b"; else verdict NE "not established: $d0 -> $d"; fi
        mp_record "M3: c1 discarded at most capability_bound 60 = $b probes in the new link's first 60 s"
        mp_probe_checks "M3 new link" "$start_at"
        echo "    new-link probe offsets from link-up, s: $(mp_offsets "$SS_LINES" "$up2") (predicted 0 10 20 50)"
    fi
    mp_link_checks "M3"
    mp_quiet "M3"
    mp_witness "M3"
    mp_delta_check "M3" "$p8"
    phase_result "Multipath M3: re-dial"
    echo ""
}

# ── M4: the first hour's capability probes ───────────────────────────

mp_m4() {
    local b c
    echo "Phase M4: Capability probes over the first hour"
    PASSED=0; FAILED=0
    local p8
    p8="$(mp_delta_patterns)"
    local end
    end="$(awk -v u="$MP_LINK_UP" 'BEGIN{printf "%.6f", u + 3610}')"
    while awk -v e="$end" -v n="$(mp_now)" 'BEGIN{exit !(n < e)}'; do
        check_links_round
        sleep 30
    done
    for m in a1 c1; do
        for n in a1 c1; do
            [ "$m" = "$n" ] && continue
            if [ -n "${LINK_LOST_AT[$m|$n]:-}" ]; then
                verdict FAIL "$m lost $n (first ${LINK_LOST_AT[$m|$n]}s after mesh start)"
            else
                verdict PASS "$m listed $n in every readable round"
            fi
            mp_record "M4: link continuity $m -> $n"
        done
    done
    b="$(capability_bound 3610)"
    c="$(count_log_pattern 'Unknown link message type.*msg_type=82' c1)"
    chk_range "$c" 1 "$b"
    mp_record "M4: c1 discarded 1 to $b capability probes in the first 3610 s"
    mp_gates c1 a1 "${NODE_IP_OF[c1]}:2121"
    mp_probe_checks "M4" "$MP_MESH_EPOCH"
    echo "    probe offsets from link-up, s: $(mp_offsets "$SS_LINES" "$MP_LINK_UP")"
    echo "    predicted: see M2"
    if is_count "$c"; then
        echo "    bytes at c1: $c probes x (27 link message, $MP_PROBE_WIRE UDP payload, $((MP_PROBE_WIRE + 28)) IPv4 packet) = $((c * MP_PROBE_WIRE)) UDP payload bytes, $((c * (MP_PROBE_WIRE + 28))) IP bytes in the hour"
        echo "    steady state at the cap: $((3600 / CAPABILITY_PROBE_INTERVAL_MAX)) probes an hour, $((3600 * (MP_PROBE_WIRE + 28) / CAPABILITY_PROBE_INTERVAL_MAX)) IP bytes an hour"
    fi
    mp_link_checks "M4"
    mp_quiet "M4"
    mp_witness "M4"
    mp_delta_check "M4" "$p8"
    phase_result "Multipath M4: the first hour"
    echo ""
}

# ── M5: the last capture control ─────────────────────────────────────

mp_m5() {
    echo "Phase M5: Capture control, last"
    PASSED=0; FAILED=0
    mp_control "M5 (capture control, last)"
    phase_result "Multipath M5: last capture control"
    echo ""
}

# mp_handback: give the captures written as root back to this user.
mp_handback() {
    [ -n "${INTEROP_CAPTURES:-}" ] && [ -d "$INTEROP_CAPTURES" ] || return 0
    docker run --rm "${CI_LABELS[@]}" -v "$INTEROP_CAPTURES:/c" \
        --entrypoint chown "$INTEROP_IMAGE:c" \
        -R "$(id -u):$(id -g)" /c >/dev/null 2>&1 \
        || echo "WARN: could not hand $INTEROP_CAPTURES back to $(id -u):$(id -g)" >&2
}

compose() {
    docker compose -f "$COMPOSE_FILE" "$@"
}

cleanup() {
    # Reap any in-flight stream tmpdir (e.g. on interrupt mid-window).
    [ -n "${_STREAM_TMP:-}" ] && rm -rf "$_STREAM_TMP" 2>/dev/null
    if [ "${FIPS_INTEROP_KEEP_UP:-}" = "1" ]; then
        echo ""
        echo "FIPS_INTEROP_KEEP_UP=1 — leaving mesh running. Tear down with:"
        echo "  docker compose -f $COMPOSE_FILE down --volumes --remove-orphans"
        return
    fi
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    [ -n "$INTEROP_MULTIPATH" ] && mp_handback
    return 0
}
trap cleanup EXIT
trap 'echo ""; echo "Interrupted"; exit 130' INT

load_slot_metadata

# ── Banner ───────────────────────────────────────────────────────────

echo "=============================================================="
echo " FIPS Mixed-Version Interop Test"
echo "=============================================================="
echo ""
echo "Node-spec: $SPEC_STR   ($NUM_NODES nodes, $NUM_PAIRS pairs, $NUM_DIRECTED directed)"
echo "Topology : $TOPOLOGY_KIND${TOPOLOGY_NAME:+ ($TOPOLOGY_NAME)}"
if [ "$TOPOLOGY_KIND" != "full-mesh" ]; then
    echo "  edges: ${INTEROP_TOPOLOGY_EDGES:-}"
fi
echo ""
echo "Mesh nodes:"
for n in "${NODES[@]}"; do
    s="${SLOT_OF[$n]}"
    u="$(echo "$s" | tr '[:lower:]' '[:upper:]')"
    echo "  $n  slot $u  ${SLOT_REF[$s]} @ ${SLOT_SHA[$s]}  deg=${DEGREE_OF[$n]:-?}  (${NODE_IP_OF[$n]})"
done
echo ""
echo "Mesh pairs:"
for p in "${PAIRS[@]}"; do
    read -r n1 n2 <<< "$p"
    echo "  $(pair_kind "$n1" "$n2")  $(pair_label "$n1" "$n2")  [$(hop_label "$n1" "$n2")]"
done
if [ "${#STREAM_PAIRS[@]}" -gt 0 ]; then
    echo ""
    echo "Data-plane streams (continuity across rekey):"
    for sp in "${STREAM_PAIRS[@]}"; do
        read -r sf st <<< "$sp"
        echo "  $sf -> $st  [$(hop_label "$sf" "$st")]"
    done
fi
echo ""
if [ -n "${FIPS_INTEROP_NETEM:-}" ]; then
    echo "Netem impairment: $FIPS_INTEROP_NETEM"
    echo ""
fi
echo "rekey.after_secs=$REKEY_AFTER_SECS"
echo ""
if [ -n "$INTEROP_MULTIPATH" ]; then
    echo "Multipath mode: candidate from $INTEROP_MULTIPATH$([ "$PROBE_HOUR" -eq 1 ] && echo ', the first hour'); second network $INTEROP_SUBNET2.0/24"
    echo "  a1 ${NODE_IP_OF[a1]} / ${NODE_IP2_OF[a1]} (udp/main 2121, $INTEROP_MP_TRANSPORT ${INTEROP_MP_PORT:-} on eth1, node.path.enabled)"
    echo "  c1 ${NODE_IP_OF[c1]} / ${NODE_IP2_OF[c1]} (one UDP transport on 2121)"
    echo "  captures: $INTEROP_CAPTURES"
    echo "  host: $(uptime), $(nproc) CPUs, $(docker ps -q | wc -l) containers running"
    echo ""
    echo "Phase M0: Every multipath check on planted input"
    if ! mp_controls "$INTEROP_IMAGE:c" "$MP_DIR/controls"; then
        echo "FAIL: a control gave the wrong verdict; the harness is fixed before any run is recorded"
        exit 1
    fi
    echo ""
fi

# ── Phase 0: bring up the mesh ───────────────────────────────────────

echo "Phase 0: Starting mesh"
compose down --volumes --remove-orphans >/dev/null 2>&1 || true
# Another run's network on the same /24 makes `compose up` fail anyway;
# checking first says which one, and catches a host route compose would
# not refuse.
# A previous run's captures would be read as this run's: clear them,
# after handing back any a killed run left owned by root.
if [ -n "$INTEROP_MULTIPATH" ] && [ -n "$INTEROP_CAPTURES" ] && [ -d "$INTEROP_CAPTURES" ]; then
    mp_handback
    rm -f -- "$INTEROP_CAPTURES"/*.pcap "$INTEROP_CAPTURES"/*.err
fi
for _net in "$INTEROP_SUBNET" ${INTEROP_SUBNET2:+"$INTEROP_SUBNET2"}; do
    if ! subnet_why="$(interop_subnet_free "$_net.0/24")"; then
        echo "  FAIL  subnet $_net.0/24 is not free: ${subnet_why:-networks or routes unreadable}"
        exit 1
    fi
done
MP_MESH_EPOCH="$(date +%s.%6N)"
if ! compose up -d; then
    echo "  FAIL  compose up failed"
    exit 1
fi
# Phase 7 measures bloom-filter warmup from node start, not from its own
# start, so the clock has to be taken here.
MESH_UP_AT=$SECONDS

# Optional netem: applied via `docker exec ... tc qdisc` on each
# container's eth0 — host bridge qdisc does NOT shape inter-container
# port-to-port traffic, so the impairment must live inside each
# container. Same mechanism as testing/flake-lab/run-loop.sh.
if [ -n "${FIPS_INTEROP_NETEM:-}" ]; then
    echo "  Applying netem to each container eth0: $FIPS_INTEROP_NETEM"
    for n in "${NODES[@]}"; do
        if docker exec "${CONTAINER[$n]}" tc qdisc add dev eth0 root \
            netem ${FIPS_INTEROP_NETEM} >/dev/null 2>&1; then
            echo "    $n: netem applied"
        else
            echo "    $n: WARN netem apply failed"
        fi
    done
fi
echo ""

if [ -n "$INTEROP_MULTIPATH" ]; then
    echo "Phase Pre: Captures, addresses"
    PASSED=0; FAILED=0
    mp_pre a1 1
    mp_pre c1 1
    phase_result "Multipath Pre"
    [ "$FAILED" -eq 0 ] || mp_stop "a capture or an address is not as the checks need"
    echo ""
fi

# ── Phase 1: FMP link + FSP session establishment ────────────────────

echo "Phase 1: Link/session establishment + connectivity baseline"
PASSED=0; FAILED=0

# Every node must reach its DIRECT-peer degree of authenticated peers (a
# peer in `show peers` is an authenticated FMP-link peer). In a full mesh
# that degree is N-1; in a multi-hop topology it is the node's adjacency.
for n in "${NODES[@]}"; do
    exp="${DEGREE_OF[$n]:-$PEERS_EXPECTED}"
    if ! wait_for_peers "${CONTAINER[$n]}" "$exp" "$CONVERGENCE_TIMEOUT"; then
        echo "  $n did not reach $exp authenticated direct peer(s)"
    fi
done
# The multipath bounds count from link-up, which is taken here: once
# every node lists its peers. It lags the true link-up by the poll.
MP_LINK_UP="$(date +%s.%6N)"

# The all-pairs ping over fips0 is the definitive reachability check.
# Direct-neighbor pairs prove their FSP session; NON-adjacent pairs in a
# multi-hop topology can only succeed via forwarding, so all-pairs ping
# is also the cross-version FORWARDING test (we keep pinging every pair).
# The convergence detector is an ADVISORY settle-wait, not the assertion.
# It needs one fully-clean, no-retry sweep of every directed pair; under
# packet loss that is statistically unlikely on a large mesh even when the
# mesh is perfectly healthy (e.g. 30 pairs at 2% loss => ~55% of sweeps
# are clean), so its timeout must NOT be fatal. The strict, retrying ping
# below is the real baseline assertion — it decides pass/fail.
if ! wait_for_full_baseline "$CONVERGENCE_TIMEOUT"; then
    echo "  detector saw no fully-clean sweep within ${CONVERGENCE_TIMEOUT}s (best $PASSED/$NUM_DIRECTED); strict re-ping decides"
fi
ping_all_pairs "" "$MAX_PING_ATTEMPTS" "baseline"
phase_result "Establishment baseline (all $NUM_DIRECTED directed pairs)"
if [ "$FAILED" -ne 0 ]; then
    dump_diagnostics
    echo ""
    echo "=== Results: $TOTAL_PASSED passed, $TOTAL_FAILED failed ==="
    echo "FAIL: mesh did not converge — see pair attribution above."
    exit 1
fi
echo ""

if [ -n "$INTEROP_MULTIPATH" ]; then
    PASSED=0; FAILED=0
    mp_transport_check
    phase_result "Multipath second transport"
    [ "$FAILED" -eq 0 ] || mp_stop "a1's second transport is not up on eth1"
    echo ""
    mp_m1
fi

# ── Phase 1b: data-plane control window (quiet, pre-rekey) ───────────
#
# Measure stream loss over a window with NO rekey cutover, as the control
# baseline for the differential. A window counts only when the FMP cutover
# count was read before and after it and did not advance. A window that
# saw a cutover, or could not be checked, is re-measured up to
# CONTROL_MAX_ATTEMPTS times; if none is clean, Phase 5b abstains rather
# than computing a verdict from a contaminated baseline. Then launch the
# rekey-window streams, which run in the background across Phases 2-5 and
# are collected/asserted in Phase 5b.
control_abstain=0
if [ "${#STREAM_PAIRS[@]}" -gt 0 ]; then
    echo "Phase 1b: Data-plane control stream (${CONTROL_STREAM_SECS}s quiet window, up to ${CONTROL_MAX_ATTEMPTS} attempts)"
    control_ok=0
    for ((attempt = 1; attempt <= CONTROL_MAX_ATTEMPTS; attempt++)); do
        pre_rc=0
        post_rc=0
        pre_cut="$(fmp_cutover_count)" || pre_rc=$?
        launch_streams CONTROL "$CONTROL_STREAM_SECS"
        collect_streams
        post_cut="$(fmp_cutover_count)" || post_rc=$?
        if [ "$pre_rc" -ne 0 ] || ! [[ "$pre_cut" =~ ^[0-9]+$ ]]; then
            why="cutover count unreadable ($pre_cut)"
        elif [ "$post_rc" -ne 0 ] || ! [[ "$post_cut" =~ ^[0-9]+$ ]]; then
            why="cutover count unreadable ($post_cut)"
        elif [ "$post_cut" -ne "$pre_cut" ]; then
            why="a rekey cutover occurred (+$((post_cut - pre_cut)))"
        else
            control_ok=1
            echo "  control window accepted on attempt $attempt/$CONTROL_MAX_ATTEMPTS"
            break
        fi
        if [ "$attempt" -lt "$CONTROL_MAX_ATTEMPTS" ]; then
            echo "  control window attempt $attempt/$CONTROL_MAX_ATTEMPTS: $why; re-measuring"
            wait_cutover_quiet || true
        else
            echo "  control window attempt $attempt/$CONTROL_MAX_ATTEMPTS: $why"
        fi
    done
    if [ "$control_ok" -eq 0 ]; then
        control_abstain=1
        echo "  ABSTAIN  control window contaminated on all $CONTROL_MAX_ATTEMPTS attempts; Phase 5b will not return a verdict"
    fi
    ctl_note=""
    [ "$control_abstain" -eq 1 ] && ctl_note=" (last attempt, contaminated)"
    for sp in "${STREAM_PAIRS[@]}"; do
        read -r sf st <<< "$sp"
        key="$sf->$st"
        echo "    control $key: tx=${STREAM_TX[CONTROL:$key]:-0} rx=${STREAM_RX[CONTROL:$key]:-0} loss=$(_loss_pct "${STREAM_TX[CONTROL:$key]:-0}" "${STREAM_RX[CONTROL:$key]:-0}")%$ctl_note"
    done
    echo "  Launching rekey-window streams (${REKEY_STREAM_SECS}s, spanning Phases 2-5)"
    launch_streams REKEY "$REKEY_STREAM_SECS"
    echo ""
fi

# ── Phase 2: first rekey cycle ───────────────────────────────────────

echo "Phase 2: First rekey cycle (waiting up to ${FIRST_REKEY_TIMEOUT}s)"
PASSED=0; FAILED=0
wait_for_log_pattern_count \
    "Rekey cutover complete \(initiator\), K-bit flipped" 1 \
    "$FIRST_REKEY_TIMEOUT" || true
if ! fmp_cutovers="$(count_log_pattern 'Rekey cutover complete \(initiator\), K-bit flipped')"; then
    echo "  FAIL  FMP rekey cutovers: node logs unreadable ($fmp_cutovers), not established"
    FAILED=$((FAILED + 1))
    INTEROP_FAILURES+=("[log] FMP rekey cutovers: node logs unreadable ($fmp_cutovers)")
elif [ "$fmp_cutovers" -ge 1 ]; then
    echo "  PASS  FMP rekey cutovers (either role; see fmp_cutover_count): $fmp_cutovers"
    PASSED=$((PASSED + 1))
else
    echo "  FAIL  no FMP rekey cutover observed within ${FIRST_REKEY_TIMEOUT}s"
    FAILED=$((FAILED + 1))
    INTEROP_FAILURES+=("[rekey] no FMP rekey cutover completed across the mesh")
fi
phase_result "First rekey cycle"
echo ""

# ── Phase 3: post-first-rekey connectivity ───────────────────────────

echo "Phase 3: Post-first-rekey connectivity (reconverge within ${POST_REKEY_TIMEOUT}s)"
PASSED=0; FAILED=0
# Poll until the mesh has reconverged after the rekey, then assert once.
# The detector poll records nothing (see ping_all_pairs); only the strict
# sweep below records, so a brief rekey-induced disruption is not a fail.
wait_for_full_baseline "$POST_REKEY_TIMEOUT" || true
ping_all_pairs "" "$MAX_PING_ATTEMPTS" "post-rekey-1"
phase_result "Post-first-rekey (all $NUM_DIRECTED directed pairs)"
echo ""

# ── Phase 4: second rekey cycle ──────────────────────────────────────

echo "Phase 4: Second rekey cycle (waiting up to ${SECOND_REKEY_WAIT}s for the next cutover)"
# Poll for the next FMP cutover beyond what Phases 2/3 already saw, using
# the same pre/post cutover-count delta convention as the control window
# (Phase 1b), instead of a blind sleep. Bounded by SECOND_REKEY_WAIT so a
# stalled rekey falls through to the strict Phase 5/6 assertions.
# An unreadable baseline gives nothing to wait beyond, so do not wait.
# Phase 4 keeps no PASSED/FAILED of its own; the INTEROP_FAILURES entry
# is what turns the run red.
if fmp_cutovers_before="$(count_log_pattern 'Rekey cutover complete \(initiator\), K-bit flipped')"; then
    wait_for_log_pattern_count \
        "Rekey cutover complete \(initiator\), K-bit flipped" \
        "$((fmp_cutovers_before + 1))" "$SECOND_REKEY_WAIT" || true
else
    echo "  FAIL  second rekey cycle: node logs unreadable ($fmp_cutovers_before), baseline not established"
    INTEROP_FAILURES+=("[log] second rekey cycle: node logs unreadable ($fmp_cutovers_before)")
fi
echo ""

echo "Phase 5: Post-second-rekey connectivity (reconverge within ${POST_REKEY_TIMEOUT}s)"
PASSED=0; FAILED=0
wait_for_full_baseline "$POST_REKEY_TIMEOUT" || true
ping_all_pairs "" "$MAX_PING_ATTEMPTS" "post-rekey-2"
phase_result "Post-second-rekey (all $NUM_DIRECTED directed pairs)"
echo ""

# ── Phase 5b: data-plane continuity across rekey (control-differential)
#
# Collect the rekey-window streams launched in Phase 1b and compare their
# loss to the control window. A hitless rekey keeps rekey-window loss at
# or below the control (plus a small margin); excess loss is data the
# rekey dropped — the failure the cutover fixes (4af3730/6e5cb89) and the
# pipelined wire layout are supposed to prevent.
if [ "${#STREAM_PAIRS[@]}" -gt 0 ]; then
    echo "Phase 5b: Data-plane continuity across rekey (control-differential, margin ${STREAM_LOSS_MARGIN_PCT}%)"
    PASSED=0; FAILED=0
    collect_streams
    printf '    %-16s %11s %11s %8s  %s\n' "stream" "ctrl-loss%" "rekey-loss%" "delta" "verdict"
    for sp in "${STREAM_PAIRS[@]}"; do
        read -r sf st <<< "$sp"
        key="$sf->$st"
        cpct="$(_loss_pct "${STREAM_TX[CONTROL:$key]:-0}" "${STREAM_RX[CONTROL:$key]:-0}")"
        rpct="$(_loss_pct "${STREAM_TX[REKEY:$key]:-0}" "${STREAM_RX[REKEY:$key]:-0}")"
        verdict="$(awk -v c="$cpct" -v k="$rpct" -v m="$STREAM_LOSS_MARGIN_PCT" 'BEGIN{
            if (c=="NA" || k=="NA") { print "NODATA"; exit }
            if (k <= c + m) print "PASS"; else print "FAIL"
        }')"
        delta="$(awk -v c="$cpct" -v k="$rpct" 'BEGIN{ if(c=="NA"||k=="NA") print "NA"; else printf "%+.1f", k-c }')"
        # No clean control window: report the losses for reading, but
        # compute no verdict from a contaminated baseline.
        if [ "$control_abstain" -eq 1 ]; then
            printf '    %-16s %11s %11s %8s  %s\n' "$key" "$cpct" "$rpct" "$delta" "ABSTAIN"
            continue
        fi
        printf '    %-16s %11s %11s %8s  %s\n' "$key" "$cpct" "$rpct" "$delta" "$verdict"
        if [ "$verdict" = "PASS" ]; then
            PASSED=$((PASSED + 1))
        else
            FAILED=$((FAILED + 1))
            INTEROP_FAILURES+=("[stream] $key ($(hop_label "$sf" "$st")): rekey-window loss ${rpct}% vs control ${cpct}% (+${STREAM_LOSS_MARGIN_PCT}% margin) -> $verdict")
        fi
    done
    if [ "$control_abstain" -eq 1 ]; then
        echo "  ABSTAIN  Data-plane continuity across rekey: no uncontaminated control window in $CONTROL_MAX_ATTEMPTS attempts"
    else
        phase_result "Data-plane continuity across rekey"
    fi
    echo ""
fi

# ── Phase 6: per-node, per-pair interop log analysis ─────────────────
#
# This is the interop-specific analysis. For each unordered pair it
# reports same vs mixed-version, then scans BOTH endpoints' logs for
# interop failure signatures. A signature firing on a mixed pair that
# does not fire on a same-version pair is the harness's primary signal.

echo "Phase 6: Interop log analysis"
PASSED=0; FAILED=0

# Give FSP rekey (which trails FMP rekey) a bounded chance to complete
# at least one cutover before the final assertions.
wait_for_log_pattern_count "FSP rekey cutover complete" 1 "$REKEY_SETTLE" || true

# The global negative checks (panics, errors, link teardowns, ...) run
# after Phase 7 instead, so they cover the whole run including the
# mesh-size warmup; see Phase 8.

# Positive checks — the rekey machinery actually exercised both layers.
echo ""
echo "  -- Rekey machinery exercised --"
# An unreadable log means the harness observed nothing, so it is a FAIL
# on either layer; the FSP WARN below is for a readable zero only.
if ! fmp_total="$(count_log_pattern 'Rekey cutover complete \(initiator\), K-bit flipped')"; then
    echo "    FAIL  FMP rekey cutovers: node logs unreadable ($fmp_total), not established"
    FAILED=$((FAILED + 1))
elif [ "$fmp_total" -ge 1 ]; then
    echo "    PASS  FMP rekey cutovers across mesh (either role): $fmp_total"
    PASSED=$((PASSED + 1))
else
    echo "    FAIL  FMP rekey cutovers: $fmp_total (expected >= 1)"
    FAILED=$((FAILED + 1))
fi
if ! fsp_total="$(count_log_pattern 'FSP rekey cutover complete')"; then
    echo "    FAIL  FSP rekey cutovers: node logs unreadable ($fsp_total), not established"
    FAILED=$((FAILED + 1))
elif [ "$fsp_total" -ge 1 ]; then
    echo "    PASS  FSP rekey cutovers across mesh: $fsp_total"
    PASSED=$((PASSED + 1))
else
    # FSP rekey not completing is a soft signal: report it but only
    # hard-fail if a pair also lost connectivity. The connectivity
    # phases already cover the user-visible impact.
    echo "    WARN  FSP rekey cutovers: $fsp_total (expected >= 1)"
fi

# Per-pair summary: classify each unordered pair and report whether it
# stayed healthy through Phases 1 to 6. "Healthy" = no connectivity
# failure recorded for either direction of the pair. Phase 7's link
# checks and Phase 8's log scan run later and record their own failures.
echo ""
echo "  -- Per-pair interop summary --"
for p in "${PAIRS[@]}"; do
    read -r n1 n2 <<< "$p"
    kind="$(pair_kind "$n1" "$n2")"
    label="$(pair_label "$n1" "$n2") [$(hop_label "$n1" "$n2")]"
    pair_failed=0
    if [ "${#INTEROP_FAILURES[@]}" -gt 0 ]; then
        for f in "${INTEROP_FAILURES[@]}"; do
            case "$f" in
                *"ping $n1->$n2 FAILED"*|*"ping $n2->$n1 FAILED"*)
                    pair_failed=1 ;;
            esac
        done
    fi
    if [ "$pair_failed" -eq 0 ]; then
        echo "    PASS  $kind pair $label: healthy through Phase 6"
        PASSED=$((PASSED + 1))
    else
        echo "    FAIL  $kind pair $label: connectivity failed by Phase 6"
        FAILED=$((FAILED + 1))
    fi
done

phase_result "Interop log analysis"
echo ""

# ── Phase 7: mesh-size estimate convergence (strict ±25%) ────────────
#
# Each node's bloom-union mesh-size estimate (fipsctl show status
# .estimated_mesh_size) should converge to the true node count across
# versions. A mixed-version bloom/tree-encoding divergence shows up as a
# node that never produces an in-band estimate (or returns null). Strict
# band = [0.75N, 1.25N].
#
# The verdict is taken on a settled estimate rather than on a node's
# first tolerable reading. Two windows enforce that. Nothing sampled
# before MESH_SIZE_WARMUP has elapsed since the mesh came up counts at
# all, because the estimate is documented as unreliable during warmup;
# after it, a node is credited only once it has held the band unbroken
# for MESH_SIZE_SETTLE. Every node is re-polled every round and any
# out-of-band reading restarts that node's settle clock, so a node
# cannot be credited for a sample it has since contradicted.
echo "Phase 7: Mesh-size estimate convergence (strict ±25% of true N=$NUM_NODES)"
PASSED=0; FAILED=0
ms_lo="$(awk -v n="$NUM_NODES" 'BEGIN{printf "%.2f", 0.75*n}')"
ms_hi="$(awk -v n="$NUM_NODES" 'BEGIN{printf "%.2f", 1.25*n}')"
declare -A MS_EST MS_OK MS_INBAND_SINCE
ms_accept_after=$(( MESH_UP_AT + MESH_SIZE_WARMUP ))
echo "  band [$ms_lo, $ms_hi], warmup ends $(( ms_accept_after - SECONDS ))s from now, then ${MESH_SIZE_SETTLE}s settled, poll up to ${MESH_SIZE_TIMEOUT}s beyond that"

# Poll through the warmup as well. The estimates are not asserted on here —
# they are the trajectory the phase has never recorded, and what an
# undercount that never recovers would show up in — but every round
# checks that each node still lists all its direct peers.
ms_next_print=$SECONDS
while [ "$SECONDS" -lt "$ms_accept_after" ]; do
    check_links_round
    if [ "$SECONDS" -ge "$ms_next_print" ]; then
        ms_line=""
        for n in "${NODES[@]}"; do
            MS_EST[$n]="$(mesh_estimate "$n")"
            ms_line+=" $n=${MS_EST[$n]}"
        done
        echo "    warmup, $(( ms_accept_after - SECONDS ))s to go:$ms_line"
        [ -n "$INTEROP_MULTIPATH" ] && mp_loss_sample "at $(( SECONDS - MESH_UP_AT ))s"
        ms_next_print=$(( SECONDS + 30 ))
    fi
    sleep "$MESH_SIZE_POLL"
done

ms_deadline=$(( SECONDS + MESH_SIZE_SETTLE + MESH_SIZE_TIMEOUT ))
while :; do
    check_links_round
    all_ok=1
    for n in "${NODES[@]}"; do
        est="$(mesh_estimate "$n")"
        MS_EST[$n]="$est"
        if [ "$est" != "null" ] && awk "BEGIN{exit !($est>=$ms_lo && $est<=$ms_hi)}"; then
            [ -z "${MS_INBAND_SINCE[$n]:-}" ] && MS_INBAND_SINCE[$n]="$SECONDS"
        else
            unset "MS_INBAND_SINCE[$n]"
        fi
        if [ -n "${MS_INBAND_SINCE[$n]:-}" ] \
           && [ $(( SECONDS - ${MS_INBAND_SINCE[$n]} )) -ge "$MESH_SIZE_SETTLE" ]; then
            MS_OK[$n]=1
        else
            MS_OK[$n]=0
            all_ok=0
        fi
    done
    [ "$all_ok" = "1" ] && break
    [ "$SECONDS" -ge "$ms_deadline" ] && break
    sleep "$MESH_SIZE_POLL"
done
for n in "${NODES[@]}"; do
    s="${SLOT_OF[$n]}"; u="$(echo "$s" | tr '[:lower:]' '[:upper:]')"
    if [ "${MS_OK[$n]:-0}" = "1" ]; then
        echo "    PASS  $n [$u]: estimated_mesh_size=${MS_EST[$n]} (held band ${MESH_SIZE_SETTLE}s+ after warmup)"
        PASSED=$((PASSED + 1))
    else
        if [ -n "${MS_INBAND_SINCE[$n]:-}" ]; then
            ms_why="held band only $(( SECONDS - ${MS_INBAND_SINCE[$n]} ))s of the ${MESH_SIZE_SETTLE}s settle window"
        else
            ms_why="outside [$ms_lo,$ms_hi]"
        fi
        echo "    FAIL  $n [$u]: estimated_mesh_size=${MS_EST[$n]:-null} ($ms_why)"
        FAILED=$((FAILED + 1))
        INTEROP_FAILURES+=("[mesh-size] node $n ($u ${SLOT_REF[$s]}@${SLOT_SHA[$s]}): estimate=${MS_EST[$n]:-null} $ms_why")
    fi
done
# The band is per-node, so a green says every node was plausible, not
# that the nodes agreed. Print the spread so nobody has to infer it.
ms_spread="$(printf '%s\n' "${MS_EST[@]}" | sort -n | awk '/^[0-9]+$/{ if (lo=="") lo=$1; hi=$1 } END{ if (lo=="") print "no numeric estimates"; else if (lo==hi) print "all nodes agree on " lo; else print "nodes disagree: " lo " to " hi }')"
echo "    NOTE: final estimates — $ms_spread (agreement is reported, not asserted)"

# Link continuity across Phase 7, one check per node.
for n in "${NODES[@]}"; do
    s="${SLOT_OF[$n]}"; u="$(echo "$s" | tr '[:lower:]' '[:upper:]')"
    node_ok=1
    if [ "${LINK_UNREAD_WORST[$n]:-0}" -ge 2 ] || [ "${LINK_UNREAD_RUN[$n]:-0}" -ge 1 ]; then
        node_ok=0
        echo "    FAIL  $n [$u]: show peers unreadable in ${LINK_UNREADABLE[$n]} of $LINK_ROUNDS rounds (longest run ${LINK_UNREAD_WORST[$n]}, final round $([ "${LINK_UNREAD_RUN[$n]:-0}" -ge 1 ] && echo unreadable || echo read)); link continuity not established"
        INTEROP_FAILURES+=("[link] node $n ($u ${SLOT_REF[$s]}@${SLOT_SHA[$s]}): show peers unreadable in ${LINK_UNREADABLE[$n]} of $LINK_ROUNDS Phase 7 rounds")
    elif [ -n "${LINK_UNREADABLE[$n]:-}" ]; then
        echo "    NOTE  $n [$u]: show peers unreadable in ${LINK_UNREADABLE[$n]} isolated round(s) of $LINK_ROUNDS; tolerated"
    fi
    for m in "${NODES[@]}"; do
        [ -n "${LINK_LOST_AT[$n|$m]:-}" ] || continue
        node_ok=0
        echo "    FAIL  $n [$u]: lost direct peer $m (first ${LINK_LOST_AT[$n|$m]}s after mesh start, missing in ${LINK_LOST_ROUNDS[$n|$m]} of $LINK_ROUNDS rounds)"
        # NOTE: keep "$kind pair" contiguous — interop-stress.sh greps it.
        INTEROP_FAILURES+=("[link] $(pair_kind "$n" "$m") pair $(pair_label "$n" "$m") [$(hop_label "$n" "$m")]: $n lost $m during Phase 7 (first ${LINK_LOST_AT[$n|$m]}s after mesh start)")
    done
    if [ "$node_ok" -eq 1 ]; then
        echo "    PASS  $n [$u]: listed every direct peer in every readable round of $LINK_ROUNDS Phase 7 rounds"
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
    fi
done
phase_result "Mesh-size estimate convergence and link continuity"
echo ""

# ── Phase 8: whole-run log health ────────────────────────────────────
#
# The global negative checks, run last so they cover every phase. A
# link lost and re-established inside the Phase 7 warmup leaves an
# "MMP link teardown" line even if no poll round caught it missing.
echo "Phase 8: Whole-run log health (all $NUM_NODES nodes)"
PASSED=0; FAILED=0
scan_global_patterns
phase_result "Whole-run log health"
echo ""

if [ -n "$INTEROP_MULTIPATH" ]; then
    mkdir -p "$MP_DIR"
    mp_m2
    if [ "$PROBE_HOUR" -eq 1 ]; then
        mp_m4
    else
        mp_m3
    fi
    mp_m5
fi

# ── Summary ──────────────────────────────────────────────────────────

echo "=============================================================="
echo " Results: $TOTAL_PASSED checks passed, $TOTAL_FAILED failed"
echo "=============================================================="

# `${#arr[@]}` cannot be combined with `:-`; count into a plain var.
INTEROP_FAILURE_COUNT="${#INTEROP_FAILURES[@]}"

# An abstaining Phase 5b adds no check, so say so: otherwise a green run
# reads as having covered data-plane continuity across rekey.
if [ "${control_abstain:-0}" -eq 1 ]; then
    echo ""
    echo "NOTE: Phase 5b abstained (control window contaminated); its rekey-loss check did not run."
fi

if [ "$TOTAL_FAILED" -eq 0 ] && [ "$INTEROP_FAILURE_COUNT" -eq 0 ]; then
    echo ""
    echo "PASS: all versions interoperate cleanly across the mesh (spec '$SPEC_STR')."
    exit 0
fi

echo ""
echo "INTEROP FAILURES (attributed to specific version pairs / builds):"
if [ "$INTEROP_FAILURE_COUNT" -gt 0 ]; then
    printf '%s\n' "${INTEROP_FAILURES[@]}" | sort -u | sed 's/^/  - /'
else
    echo "  (no per-pair failure recorded; see phase output above)"
fi
echo ""

# Highlight whether failures concentrate on mixed-version pairs — the
# defining interop signal.
mixed_hits=0
same_hits=0
if [ "$INTEROP_FAILURE_COUNT" -gt 0 ]; then
    for f in "${INTEROP_FAILURES[@]}"; do
        case "$f" in
            *"MIXED pair"*) mixed_hits=$((mixed_hits + 1)) ;;
            *"same pair"*)  same_hits=$((same_hits + 1)) ;;
        esac
    done
fi
echo "Connectivity-failure attribution: mixed-version=$mixed_hits  same-version=$same_hits"
if [ "$mixed_hits" -gt 0 ] && [ "$same_hits" -eq 0 ]; then
    echo "=> Failures are MIXED-VERSION ONLY: a genuine interop regression."
elif [ "$mixed_hits" -gt 0 ] && [ "$same_hits" -gt 0 ]; then
    echo "=> Failures hit both mixed and same-version pairs: likely a general"
    echo "   instability, not version-specific — investigate the common cause."
elif [ "$same_hits" -gt 0 ]; then
    echo "=> Failures are SAME-VERSION ONLY: not an interop issue per se;"
    echo "   a build is unstable even against itself."
fi

dump_diagnostics
exit 1
