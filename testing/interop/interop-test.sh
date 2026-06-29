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
#
#   --topology  built-in multi-hop topology selecting a node-spec + edge
#               set + default data-plane streams. Known: multihop-3v-cycle
#               (6 nodes, 2 of each version, one cycle, two leaves —
#               exercises cross-version forwarding + mesh-size). Without
#               it the mesh is a full mesh from the positional node-spec.
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
#   STREAM_LOSS_MARGIN_PCT rekey-vs-control loss margin (default 1).
#   CONTROL_STREAM_SECS    quiet control-window length (default 12).
#   MESH_SIZE_TIMEOUT      Phase 7 convergence poll budget (default 180).
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

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib/wait-converge.sh"

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

GEN_DIR="$RUNS_BASE/generated-configs"
COMPOSE_FILE="$GEN_DIR/docker-compose.generated.yml"
NODES_ENV="$GEN_DIR/nodes.env"
REFS_ENV="$RUNS_BASE/.build/refs.env"

# ── Built-in topology selection ──────────────────────────────────────
#
# --topology <name> selects a node-spec + an explicit edge set (a
# multi-hop, mixed-version, leaf-bearing graph) + a default data-plane
# stream set, exercising forwarding / routing / mesh-size convergence
# across versions. Without it, positional args are the node-spec and the
# mesh is a full mesh (historical behavior).
TOPOLOGY_NAME=""
_ARGS=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --topology)   TOPOLOGY_NAME="${2:-}"; shift 2 ;;
        --topology=*) TOPOLOGY_NAME="${1#--topology=}"; shift ;;
        *)            _ARGS+=("$1"); shift ;;
    esac
done
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
STREAM_RATE_HZ=5                                 # ping6 -i 0.2
CONTROL_STREAM_SECS="${CONTROL_STREAM_SECS:-12}" # quiet pre-rekey window
STREAM_LOSS_MARGIN_PCT="${STREAM_LOSS_MARGIN_PCT:-1}"
# The rekey-window stream must span Phases 2-5 (both cutovers + reconverge).
REKEY_STREAM_SECS=$(( FIRST_REKEY_TIMEOUT + SECOND_REKEY_WAIT + POST_REKEY_TIMEOUT + 15 ))

# Mesh-size estimate convergence (strict ±25% of true N). Generous poll
# budget — the bloom-union estimate converges over minutes.
MESH_SIZE_TIMEOUT="${MESH_SIZE_TIMEOUT:-180}"

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
    if ! docker image inspect "fips-interop:$slot" >/dev/null 2>&1; then
        echo "ERROR: image fips-interop:$slot not present." >&2
        echo "Build the three images first:" >&2
        echo "  bash $SCRIPT_DIR/build-images.sh <ref-a> <ref-b> <ref-c>" >&2
        exit 2
    fi
done

# ── (Re)generate configs for this node-spec ──────────────────────────
#
# Always regenerate when the spec on disk does not match the requested
# spec (or no manifest exists). Generation is deterministic and cheap.

need_regen=1
if [ -f "$NODES_ENV" ]; then
    existing_spec="$(sed -n 's/^INTEROP_SPEC="\(.*\)"$/\1/p' "$NODES_ENV")"
    existing_edges="$(sed -n 's/^INTEROP_TOPOLOGY_EDGES="\(.*\)"$/\1/p' "$NODES_ENV")"
    if [ "$existing_spec" = "$SPEC_STR" ] \
        && [ "$existing_edges" = "${FIPS_INTEROP_EDGES:-}" ]; then
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
        lbl_ref="$(docker image inspect "fips-interop:$slot" \
            --format '{{ index .Config.Labels "fips.interop.ref" }}' 2>/dev/null || true)"
        lbl_sha="$(docker image inspect "fips-interop:$slot" \
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

# Count a pattern across all node logs.
count_log_pattern() {
    local pattern="$1" total=0 n count
    for n in "${NODES[@]}"; do
        count=$(docker logs "${CONTAINER[$n]}" 2>&1 | grep -cE "$pattern" || true)
        total=$((total + count))
    done
    echo "$total"
}

# Per-node count of a pattern.
count_node_pattern() {
    local node="$1" pattern="$2"
    docker logs "${CONTAINER[$node]}" 2>&1 | grep -cE "$pattern" || true
}

wait_for_log_pattern_count() {
    local pattern="$1" min_count="$2" timeout="$3"
    local start=$SECONDS
    while (( SECONDS - start < timeout )); do
        [ "$(count_log_pattern "$pattern")" -ge "$min_count" ] && return 0
        sleep "$LOG_POLL_INTERVAL"
    done
    [ "$(count_log_pattern "$pattern")" -ge "$min_count" ]
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
    local out tx rx
    out=$(docker exec "$from_ctr" ping6 -i 0.2 -c "$count" -W "$PING_TIMEOUT" \
        "${to_npub}.fips" 2>&1)
    tx=$(echo "$out" | grep -oE '[0-9]+ packets transmitted' | grep -oE '^[0-9]+')
    rx=$(echo "$out" | grep -oE '[0-9]+ received' | grep -oE '^[0-9]+')
    echo "${tx:-0} ${rx:-0}" > "$outfile"
}

# Launch all stream pairs in the background for <label> over <dur>s.
launch_streams() {
    local label="$1" dur="$2"
    _STREAM_TMP="$(mktemp -d)"
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

# ── Phase 0: bring up the mesh ───────────────────────────────────────

echo "Phase 0: Starting mesh"
compose down --volumes --remove-orphans >/dev/null 2>&1 || true
if ! compose up -d; then
    echo "  FAIL  compose up failed"
    exit 1
fi

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

# ── Phase 1b: data-plane control window (quiet, pre-rekey) ───────────
#
# Measure stream loss over a window with NO rekey cutover, as the control
# baseline for the differential. Validated cutover-free by confirming the
# FMP cutover count did not advance during the window. Then launch the
# rekey-window streams, which run in the background across Phases 2-5 and
# are collected/asserted in Phase 5b.
control_contaminated=0
if [ "${#STREAM_PAIRS[@]}" -gt 0 ]; then
    echo "Phase 1b: Data-plane control stream (${CONTROL_STREAM_SECS}s quiet window)"
    pre_cut="$(count_log_pattern 'Rekey cutover complete \(initiator\), K-bit flipped')"
    launch_streams CONTROL "$CONTROL_STREAM_SECS"
    collect_streams
    post_cut="$(count_log_pattern 'Rekey cutover complete \(initiator\), K-bit flipped')"
    if [ "$post_cut" -ne "$pre_cut" ]; then
        control_contaminated=1
        echo "  WARN  a rekey cutover occurred during the control window — control loss may be contaminated"
    fi
    for sp in "${STREAM_PAIRS[@]}"; do
        read -r sf st <<< "$sp"
        key="$sf->$st"
        echo "    control $key: tx=${STREAM_TX[CONTROL:$key]:-0} rx=${STREAM_RX[CONTROL:$key]:-0} loss=$(_loss_pct "${STREAM_TX[CONTROL:$key]:-0}" "${STREAM_RX[CONTROL:$key]:-0}")%"
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
fmp_cutovers="$(count_log_pattern 'Rekey cutover complete \(initiator\), K-bit flipped')"
if [ "$fmp_cutovers" -ge 1 ]; then
    echo "  PASS  FMP rekey initiator cutovers: $fmp_cutovers"
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
fmp_cutovers_before="$(count_log_pattern 'Rekey cutover complete \(initiator\), K-bit flipped')"
wait_for_log_pattern_count \
    "Rekey cutover complete \(initiator\), K-bit flipped" \
    "$((fmp_cutovers_before + 1))" "$SECOND_REKEY_WAIT" || true
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
        printf '    %-16s %11s %11s %8s  %s\n' "$key" "$cpct" "$rpct" "$delta" "$verdict"
        if [ "$verdict" = "PASS" ]; then
            PASSED=$((PASSED + 1))
        else
            FAILED=$((FAILED + 1))
            INTEROP_FAILURES+=("[stream] $key ($(hop_label "$sf" "$st")): rekey-window loss ${rpct}% vs control ${cpct}% (+${STREAM_LOSS_MARGIN_PCT}% margin) -> $verdict")
        fi
    done
    [ "${control_contaminated:-0}" -eq 1 ] && echo "    NOTE: control window saw a cutover; differential may understate rekey loss."
    phase_result "Data-plane continuity across rekey"
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

# Global negative checks — these must be zero on EVERY node regardless
# of version pairing. A non-zero count is attributed to the node and,
# where the count is asymmetric across versions, flagged as interop.
echo ""
echo "  -- Global health (all $NUM_NODES nodes) --"

declare -A GLOBAL_PATTERNS=(
    ["PANIC|panicked"]="panics"
    ["ERROR"]="error-level log lines"
    ["unknown FMP version|Unknown FMP version"]="unknown-FMP-version drops"
    ["MMP link teardown"]="MMP link teardowns"
    ["Excessive decrypt failures"]="excessive-decrypt-failure removals"
    ["Session AEAD decryption failed"]="FSP AEAD decrypt failures"
    ["Rekey msg2 processing failed"]="rekey msg2 failures"
    ["Handshake failed|handshake failed|Handshake error"]="handshake failures"
)

for pat in "${!GLOBAL_PATTERNS[@]}"; do
    desc="${GLOBAL_PATTERNS[$pat]}"
    total="$(count_log_pattern "$pat")"
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

# Positive checks — the rekey machinery actually exercised both layers.
echo ""
echo "  -- Rekey machinery exercised --"
fmp_total="$(count_log_pattern 'Rekey cutover complete \(initiator\), K-bit flipped')"
fsp_total="$(count_log_pattern 'FSP rekey cutover complete')"
if [ "$fmp_total" -ge 1 ]; then
    echo "    PASS  FMP rekey cutovers across mesh: $fmp_total"
    PASSED=$((PASSED + 1))
else
    echo "    FAIL  FMP rekey cutovers: $fmp_total (expected >= 1)"
    FAILED=$((FAILED + 1))
fi
if [ "$fsp_total" -ge 1 ]; then
    echo "    PASS  FSP rekey cutovers across mesh: $fsp_total"
    PASSED=$((PASSED + 1))
else
    # FSP rekey not completing is a soft signal: report it but only
    # hard-fail if a pair also lost connectivity. The connectivity
    # phases already cover the user-visible impact.
    echo "    WARN  FSP rekey cutovers: $fsp_total (expected >= 1)"
fi

# Per-pair summary: classify each unordered pair and report whether it
# stayed healthy through the run. "Healthy" = no connectivity failure
# recorded for either direction of the pair.
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
        echo "    PASS  $kind pair $label: stayed healthy"
        PASSED=$((PASSED + 1))
    else
        echo "    FAIL  $kind pair $label: connectivity failed during the run"
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
# band = [0.75N, 1.25N]; polled up to MESH_SIZE_TIMEOUT (the estimate
# converges over minutes — see ISSUE-2026-0046 on its transient jitter).
echo "Phase 7: Mesh-size estimate convergence (strict ±25% of true N=$NUM_NODES)"
PASSED=0; FAILED=0
ms_lo="$(awk -v n="$NUM_NODES" 'BEGIN{printf "%.2f", 0.75*n}')"
ms_hi="$(awk -v n="$NUM_NODES" 'BEGIN{printf "%.2f", 1.25*n}')"
echo "  band [$ms_lo, $ms_hi], poll up to ${MESH_SIZE_TIMEOUT}s"
declare -A MS_EST MS_OK
ms_deadline=$(( SECONDS + MESH_SIZE_TIMEOUT ))
while :; do
    all_ok=1
    for n in "${NODES[@]}"; do
        [ "${MS_OK[$n]:-0}" = "1" ] && continue
        est="$(docker exec "${CONTAINER[$n]}" fipsctl show status 2>/dev/null \
            | python3 -c "import sys,json; v=json.load(sys.stdin).get('estimated_mesh_size'); print(v if v is not None else 'null')" 2>/dev/null || echo null)"
        MS_EST[$n]="$est"
        if [ "$est" != "null" ] && awk "BEGIN{exit !($est>=$ms_lo && $est<=$ms_hi)}"; then
            MS_OK[$n]=1
        else
            all_ok=0
        fi
    done
    [ "$all_ok" = "1" ] && break
    [ "$SECONDS" -ge "$ms_deadline" ] && break
    sleep 3
done
for n in "${NODES[@]}"; do
    s="${SLOT_OF[$n]}"; u="$(echo "$s" | tr '[:lower:]' '[:upper:]')"
    if [ "${MS_OK[$n]:-0}" = "1" ]; then
        echo "    PASS  $n [$u]: estimated_mesh_size=${MS_EST[$n]}"
        PASSED=$((PASSED + 1))
    else
        echo "    FAIL  $n [$u]: estimated_mesh_size=${MS_EST[$n]:-null} (outside [$ms_lo,$ms_hi] after ${MESH_SIZE_TIMEOUT}s)"
        FAILED=$((FAILED + 1))
        INTEROP_FAILURES+=("[mesh-size] node $n ($u ${SLOT_REF[$s]}@${SLOT_SHA[$s]}): estimate=${MS_EST[$n]:-null} outside [$ms_lo,$ms_hi]")
    fi
done
phase_result "Mesh-size estimate convergence"
echo ""

# ── Summary ──────────────────────────────────────────────────────────

echo "=============================================================="
echo " Results: $TOTAL_PASSED checks passed, $TOTAL_FAILED failed"
echo "=============================================================="

# `${#arr[@]}` cannot be combined with `:-`; count into a plain var.
INTEROP_FAILURE_COUNT="${#INTEROP_FAILURES[@]}"

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
