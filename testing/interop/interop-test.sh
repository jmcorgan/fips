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
#   ./interop-test.sh [node-spec...]
#
#   node-spec   space-separated slot letters (a/b/c), default `a b c`.
#               e.g. `a a b c` (4-node, one same-version control pair),
#                    `a a a`   (3-node same-version flake rig).
#
# Environment:
#   FIPS_INTEROP_NETEM     tc-netem arg string applied to every container's
#                          eth0, e.g. "delay 10ms 5ms 25% loss 1%". Unset =
#                          no impairment.
#   FIPS_INTEROP_KEEP_UP   1 = leave containers running after the test (debug).
#   REKEY_AFTER_SECS       rekey interval to generate configs with (default 35).
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

REKEY_AFTER_SECS="${REKEY_AFTER_SECS:-35}"

# ── Node-spec ────────────────────────────────────────────────────────

SPEC=("$@")
if [ "${#SPEC[@]}" -eq 0 ]; then
    SPEC=(a b c)
fi
SPEC_STR="${SPEC[*]}"

# ── Timing ───────────────────────────────────────────────────────────

CONVERGENCE_TIMEOUT=60          # wait for full mesh + clean ping baseline
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
LOG_POLL_INTERVAL=2

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
    if [ "$existing_spec" = "$SPEC_STR" ]; then
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
                    local kind
                    kind="$(pair_kind "$i" "$j")"
                    INTEROP_FAILURES+=("[$context] $kind pair $(pair_label "$i" "$j"): ping $i->$j FAILED")
                fi
            fi
        done
    done
}

# Poll until every directed pair pings clean, or until timeout. This is a
# convergence DETECTOR — used at establishment (Phase 1) and after each
# rekey (Phases 3/5). It pings with the "convergence" context, which
# ping_all_pairs deliberately does not record as a failure; the caller
# runs a separate strict assertion sweep afterwards.
wait_for_full_baseline() {
    local timeout="$1"
    local start=$SECONDS
    local best_passed=0 best_failed="$NUM_DIRECTED"
    while (( SECONDS - start < timeout )); do
        ping_all_pairs quiet 1 "convergence"
        if [ "$PASSED" -gt "$best_passed" ]; then
            best_passed="$PASSED"; best_failed="$FAILED"
        fi
        [ "$FAILED" -eq 0 ] && return 0
        sleep 1
    done
    PASSED="$best_passed"; FAILED="$best_failed"
    return 1
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
echo ""
echo "Mesh nodes:"
for n in "${NODES[@]}"; do
    s="${SLOT_OF[$n]}"
    u="$(echo "$s" | tr '[:lower:]' '[:upper:]')"
    echo "  $n  slot $u  ${SLOT_REF[$s]} @ ${SLOT_SHA[$s]}  (${NODE_IP_OF[$n]})"
done
echo ""
echo "Mesh pairs:"
for p in "${PAIRS[@]}"; do
    read -r n1 n2 <<< "$p"
    echo "  $(pair_kind "$n1" "$n2")  $(pair_label "$n1" "$n2")"
done
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

# Every node must reach N-1 authenticated peers. A peer in `show peers`
# is an authenticated FMP-link peer.
for n in "${NODES[@]}"; do
    if ! wait_for_peers "${CONTAINER[$n]}" "$PEERS_EXPECTED" "$CONVERGENCE_TIMEOUT"; then
        echo "  $n did not reach $PEERS_EXPECTED authenticated peers"
    fi
done

# The all-pairs ping over fips0 is the definitive FSP-session check: in
# a full mesh every pair is a direct neighbor, so a successful ping
# proves that pair's FSP session carries traffic in that direction.
if wait_for_full_baseline "$CONVERGENCE_TIMEOUT"; then
    ping_all_pairs "" "$MAX_PING_ATTEMPTS" "baseline"
    phase_result "Establishment baseline (all $NUM_DIRECTED directed pairs)"
else
    echo "  Best baseline before timeout: $PASSED/$((PASSED + FAILED))"
    ping_all_pairs "" "$MAX_PING_ATTEMPTS" "baseline"
    phase_result "Establishment baseline (all $NUM_DIRECTED directed pairs)"
    dump_diagnostics
    echo ""
    echo "=== Results: $TOTAL_PASSED passed, $TOTAL_FAILED failed ==="
    echo "FAIL: mesh did not converge — see pair attribution above."
    exit 1
fi
echo ""

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

echo "Phase 4: Second rekey cycle (waiting ${SECOND_REKEY_WAIT}s)"
sleep "$SECOND_REKEY_WAIT"
echo ""

echo "Phase 5: Post-second-rekey connectivity (reconverge within ${POST_REKEY_TIMEOUT}s)"
PASSED=0; FAILED=0
wait_for_full_baseline "$POST_REKEY_TIMEOUT" || true
ping_all_pairs "" "$MAX_PING_ATTEMPTS" "post-rekey-2"
phase_result "Post-second-rekey (all $NUM_DIRECTED directed pairs)"
echo ""

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
    label="$(pair_label "$n1" "$n2")"
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
