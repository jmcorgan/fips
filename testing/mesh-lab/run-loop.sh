#!/bin/bash
# FIPS mesh-reliability lab: run an integration suite N times under a
# configurable host-pressure profile, capture per-rep diagnostics, and
# produce a per-rep + aggregate summary.json compact enough for triage
# without holding gigabytes of raw log.
#
# See ./README.md for the full developer-facing description.
#
# Usage:
#   run-loop.sh <suite> [--reps N] [--profile NAME] [--out DIR]
#
#   suite     One of: rekey, rekey-accept-off, rekey-outbound-only,
#             nat-lan, bloom-storm.
#   --reps N  Number of repetitions (default 1).
#   --profile Pressure profile name from pressure-profiles.sh (default
#             idle). See pressure-profiles.sh for the full list.
#   --out DIR Output directory (default <runs-base>/runs/<ts>; see
#             FIPS_MESH_LAB_RUNS_DIR below for how the runs-base is
#             chosen).
#
# Environment:
#   FIPS_MESH_LAB_NETEM     netem argument string applied via tc qdisc
#                           inside each fips-node container's eth0.
#   FIPS_MESH_LAB_TRACE     when set, layers compose-trace.yml on top
#                           of the base + resource-limits stack to
#                           bump RUST_LOG to trace on rekey/handshake/
#                           forwarding/session/encrypted/mmp modules.
#   FIPS_MESH_LAB_RUNS_DIR  Root for harness output (runs/ and any
#                           other scratch). When unset, falls back to
#                           an in-tree path under testing/mesh-lab/
#                           and prints a warning to stderr; set it to
#                           a path outside the source tree to keep
#                           generated artefacts out of the checkout.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck disable=SC1091
source "$SCRIPT_DIR/pressure-profiles.sh"

# ── Scratch-dir root ─────────────────────────────────────────────────
#
# FIPS_MESH_LAB_RUNS_DIR controls where the harness writes its run
# output (runs/<timestamp>/...). When unset we fall back to an
# in-tree path under testing/mesh-lab/ and warn the operator, so the
# warning fires exactly once per invocation. When a parent script
# has already warned it exports _FIPS_MESH_LAB_WARNED=1 to suppress
# duplicate warnings in child scripts.
if [[ -n "${FIPS_MESH_LAB_RUNS_DIR:-}" ]]; then
    RUNS_BASE="$FIPS_MESH_LAB_RUNS_DIR"
    mkdir -p "$RUNS_BASE"
else
    RUNS_BASE="$SCRIPT_DIR"
    if [[ -z "${_FIPS_MESH_LAB_WARNED:-}" ]]; then
        echo >&2 "WARNING: FIPS_MESH_LAB_RUNS_DIR not set; harness output will be written under the source tree at $RUNS_BASE/runs/. Set FIPS_MESH_LAB_RUNS_DIR to a path outside the source tree to avoid this."
        export _FIPS_MESH_LAB_WARNED=1
    fi
fi

# ── Args ─────────────────────────────────────────────────────────────

SUITE=""
REPS=1
PROFILE="idle"
OUT_DIR=""

usage() {
    sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --reps) REPS="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        --) shift; break ;;
        -*) echo "unknown flag: $1" >&2; usage 1 ;;
        *)
            if [ -z "$SUITE" ]; then
                SUITE="$1"
            else
                echo "unexpected positional arg: $1" >&2
                usage 1
            fi
            shift ;;
    esac
done

if [ -z "$SUITE" ]; then
    echo "missing required <suite> argument" >&2
    usage 1
fi

if [ -z "$OUT_DIR" ]; then
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    OUT_DIR="$RUNS_BASE/runs/${ts}-${SUITE}-${PROFILE}"
fi

mkdir -p "$OUT_DIR"

# Mirror the harness's own stdout/stderr to a per-run log. The
# per-rep setup/test-output/teardown captures only the in-container
# test side; this captures the wrapper-level signal (pressure-profile
# start/stop, OOM-killed child notifications from bash job control,
# aggregate summary, any preflight error). Without this, host-side
# diagnostics are lost the moment the host reboots and the kernel
# ring buffer rolls.
exec > >(tee -a "$OUT_DIR/run-loop.log") 2>&1

# ── Preflight ────────────────────────────────────────────────────────

require_docker() {
    if ! docker info >/dev/null 2>&1; then
        echo "ERROR: Docker daemon is not reachable" >&2
        exit 2
    fi
}

require_test_image() {
    if ! docker image inspect fips-test:latest >/dev/null 2>&1; then
        echo "ERROR: fips-test:latest not present" >&2
        echo "Build it once with:  bash testing/ci-local.sh --build-only" >&2
        exit 2
    fi
}

require_docker
require_test_image

# ── Suite-specific drivers and signature parsers ─────────────────────
#
# Each driver runs ONE rep of the suite. It must:
#   - return 0 on suite-pass, non-zero on suite-fail
#   - write the test stdout/stderr to ${REP_DIR}/test-output.log
#   - capture container logs to ${REP_DIR}/docker-logs/ if relevant
#
# Each parser reads ${REP_DIR}/test-output.log and writes a JSON
# fragment (no enclosing braces) of suite-specific signature features
# into ${REP_DIR}/signature.json. Used by the aggregate summary to
# decide whether the failure matches the documented mechanism for the
# associated open issue.

run_rekey_family() {
    local variant="$1"   # rekey, rekey-accept-off, rekey-outbound-only
    local REP_DIR="$2"
    local compose_profile="$variant"
    local env_args=()

    case "$variant" in
        rekey-accept-off)
            env_args=(REKEY_TOPOLOGY=rekey-accept-off REKEY_ACCEPT_OFF_NODES=b) ;;
        rekey-outbound-only)
            env_args=(REKEY_TOPOLOGY=rekey-outbound-only REKEY_OUTBOUND_ONLY_NODES=b) ;;
    esac

    # Lab compose stack: base compose + mesh-lab resource-limits override.
    # The override pins each rekey-family daemon to roughly its GHA-runner
    # share (0.3 cpus / 1 GiB), mimicking the constraint a 2-core / 7-GiB
    # ubuntu-latest runner imposes. Base compose is unmodified so
    # ci-local.sh stays unconstrained for day-to-day developer runs.
    #
    # Trace-logging override: set FIPS_MESH_LAB_TRACE=1 in the environment
    # to bump RUST_LOG to trace level on the modules relevant to the
    # rekey-class flake (rekey, handshake, forwarding, session, encrypted,
    # mmp). Increases log volume substantially; use only when capturing
    # primary failure-moment evidence for mechanism investigation.
    local compose_args=(
        -f testing/static/docker-compose.yml
        -f testing/mesh-lab/compose-resource-limits.yml
        --profile "$compose_profile"
    )
    if [ -n "${FIPS_MESH_LAB_TRACE:-}" ]; then
        compose_args=(
            -f testing/static/docker-compose.yml
            -f testing/mesh-lab/compose-resource-limits.yml
            -f testing/mesh-lab/compose-trace.yml
            --profile "$compose_profile"
        )
    fi

    (
        cd "$REPO_ROOT" || exit 1
        env "${env_args[@]}" bash testing/static/scripts/generate-configs.sh "$variant" \
            >>"$REP_DIR/setup.log" 2>&1
        env "${env_args[@]}" bash testing/static/scripts/rekey-test.sh inject-config \
            >>"$REP_DIR/setup.log" 2>&1
        docker compose "${compose_args[@]}" up -d \
            >>"$REP_DIR/setup.log" 2>&1
    )

    # Optional: apply tc qdisc netem inside each fips-node container's
    # eth0. Set FIPS_MESH_LAB_NETEM to a netem argument string (e.g.
    # "delay 10ms 5ms 25% loss 1%") to enable. Applied via `docker
    # exec` because qdisc on the host-side docker bridge does NOT shape
    # port-to-port inter-container traffic on the bridge — only traffic
    # to/from the host's own IP. Egress qdisc on the container's own
    # eth0 reliably shapes that container's outbound packets to peer
    # containers. Containers already have NET_ADMIN cap (rekey needs
    # it for TUN); tc is in the fips-test image.
    local netem_applied=()
    if [ -n "${FIPS_MESH_LAB_NETEM:-}" ]; then
        for node in a b c d e; do
            if docker exec "fips-node-$node" tc qdisc add dev eth0 root \
                netem ${FIPS_MESH_LAB_NETEM} >>"$REP_DIR/setup.log" 2>&1; then
                netem_applied+=("fips-node-$node")
            else
                echo "WARN: netem apply failed on fips-node-$node" \
                    >>"$REP_DIR/setup.log"
            fi
        done
        if [ "${#netem_applied[@]}" -gt 0 ]; then
            echo "applied netem on ${#netem_applied[@]}/5 nodes: $FIPS_MESH_LAB_NETEM" \
                >>"$REP_DIR/setup.log"
        fi
    fi

    local rc=0
    (
        cd "$REPO_ROOT" || exit 1
        env "${env_args[@]}" bash testing/static/scripts/rekey-test.sh
    ) >"$REP_DIR/test-output.log" 2>&1 || rc=$?

    # Capture container logs before teardown
    mkdir -p "$REP_DIR/docker-logs"
    for node in a b c d e; do
        docker logs "fips-node-$node" >"$REP_DIR/docker-logs/node-$node.log" 2>&1 || true
    done

    # In-container netem disappears with the container itself on
    # compose down, so no explicit teardown needed.

    (
        cd "$REPO_ROOT" || exit 1
        docker compose "${compose_args[@]}" \
            down --volumes --remove-orphans \
            >>"$REP_DIR/teardown.log" 2>&1
    )

    return "$rc"
}

parse_rekey() {
    local REP_DIR="$1"
    local log="$REP_DIR/test-output.log"

    # Phase 5 per-pair failures (e.g., "B → D ... FAIL" or
    # "B → D ... FAIL (after 4 attempts)" when retries are enabled).
    local phase5_failures
    phase5_failures=$(awk '
        /^Phase 5:/ { in5=1; next }
        /^Phase 6:/ { in5=0 }
        in5 && /\.\.\. FAIL([[:space:]]|$)/ { print }
    ' "$log" | sed 's/^ *//' | tr '\n' ',' | sed 's/,$//')

    # Phase 6 log analysis result
    local phase6_status="unknown"
    if grep -q '"Log analysis: .* passed"\|✓ Log analysis: ' "$log"; then
        phase6_status="all-green"
    fi
    if grep -q 'ERROR\|PANIC\|panicked' "$log"; then
        phase6_status="errors-observed"
    fi

    # Late FSP K-bit cutover detection — scan node logs for cutover-
    # complete events occurring within or after the Phase 5 settle
    # window. The settle window is the 12 s before Phase 5's first
    # ping_all. Without precise timing parsing in this first pass, we
    # report the timestamps of all FSP K-bit-related events for the
    # rep so a reviewer can match against the documented mechanism.
    local late_fsp_events=""
    for nodelog in "$REP_DIR"/docker-logs/node-*.log; do
        [ -f "$nodelog" ] || continue
        # Strip ANSI escape codes that docker logs preserves from the
        # daemon's TTY-aware tracing-subscriber output; raw ESC bytes
        # are invalid JSON string contents.
        late_fsp_events+=$(grep -oE '[0-9-]+T[0-9:.]+Z.*(K-bit flip|FSP rekey cutover complete)' "$nodelog" \
            | sed -E 's/\x1b\[[0-9;]*[mK]//g' \
            | tail -5 \
            | tr '\n' ';')
        late_fsp_events+="|"
    done

    # Compose JSON via jq -n so embedded specials in any field are
    # safely escaped rather than splatted as raw bytes.
    jq -n \
        --arg pairs "$phase5_failures" \
        --arg phase6 "$phase6_status" \
        --arg events "$late_fsp_events" \
        '{phase5_failing_pairs: $pairs, phase6_log_analysis: $phase6, late_fsp_events_per_node_tail: $events}' \
        > "$REP_DIR/signature.json"
}

# Heuristic mechanism-match check for the rekey Phase 5 flake class.
# True iff:
#   - At least one Phase 5 ping fails
#   - Phase 6 log analysis is all-green (no ERROR/PANIC noise)
mechanism_match_rekey() {
    local REP_DIR="$1"
    local sig="$REP_DIR/signature.json"
    if [ ! -f "$sig" ]; then
        echo "  WARN: mechanism_match: $sig missing" >&2
        echo "false"
        return
    fi
    # Surface invalid JSON loudly — silent jq failure with `|| echo ""`
    # previously masked real mechanism matches when ANSI escapes leaked
    # into the events field.
    if ! jq -e . "$sig" >/dev/null 2>&1; then
        echo "  WARN: mechanism_match: $sig is invalid JSON" >&2
        echo "false"
        return
    fi
    local pairs phase6
    pairs=$(jq -r '.phase5_failing_pairs' "$sig")
    phase6=$(jq -r '.phase6_log_analysis' "$sig")
    if [ -n "$pairs" ] && [ "$phase6" = "all-green" ]; then
        echo "true"
    else
        echo "false"
    fi
}

run_nat_lan() {
    local REP_DIR="$1"
    local rc=0

    # Optional CPU-pinning sidecar. Mirrors the bloom-storm pattern at
    # run_bloom_storm above. nat-test.sh uses docker-compose, but the
    # mesh-lab compose-resource-limits.yml override is rekey-family
    # service-name specific (services rekey-* / rekey-accept-off-* /
    # rekey-outbound-only-*), so it does NOT constrain the nat-lan
    # containers (lan-a, lan-b). To pressure-match the GHA 2-core
    # constraint without adding nat-specific resource-limits files, the
    # sidecar polls for `fips-nat-lan-*` containers as compose spawns
    # them and applies `docker update --cpuset-cpus <set>` to each.
    # Pinning is idempotent — re-applying the same cpuset is a no-op.
    # Default `0,1` mimics a GHA 2-core runner; set FIPS_NAT_LAN_CPUSET
    # to a wider set (e.g. `0,1,2,3`) to relax, or to the empty string
    # to disable the sidecar.
    local cpuset="${FIPS_NAT_LAN_CPUSET-0,1}"
    local pinning_pid=""
    if [ -n "$cpuset" ]; then
        (
            while true; do
                for c in $(docker ps --filter "name=fips-nat-lan-" --format '{{.Names}}' 2>/dev/null); do
                    docker update --cpuset-cpus "$cpuset" "$c" >/dev/null 2>&1 || true
                done
                sleep 0.5
            done
        ) &
        pinning_pid=$!
        echo "nat-lan: cpu-pinning sidecar PID $pinning_pid (cpuset=$cpuset)" \
            >"$REP_DIR/setup.log"
    fi

    # Trace-logging override. When FIPS_MESH_LAB_TRACE is set, point
    # nat-test.sh at the nat-specific trace overlay via the
    # FIPS_NAT_EXTRA_COMPOSE env-var hook in nat-test.sh. The overlay
    # bumps RUST_LOG to trace on discovery::nostr, transport::udp,
    # node::lifecycle, handlers::handshake, handlers::forwarding —
    # the modules covering the cross-init / adoption / handshake
    # path that ISSUE-2026-0027 exhibits. Path is repo-relative.
    local -a env_args=(FIPS_NAT_SKIP_FINAL_CLEANUP=1)
    if [ -n "${FIPS_MESH_LAB_TRACE:-}" ]; then
        env_args+=(FIPS_NAT_EXTRA_COMPOSE=testing/mesh-lab/compose-trace-nat.yml)
        echo "nat-lan: FIPS_MESH_LAB_TRACE set, layering compose-trace-nat.yml" \
            >>"$REP_DIR/setup.log"
    fi

    # nat-test.sh's run_lan() tears containers down on the success
    # path (line 404 cleanup), which races with our docker-logs
    # capture below. FIPS_NAT_SKIP_FINAL_CLEANUP=1 disables that
    # final teardown; failure paths in run_lan already leave
    # containers up. We do the teardown explicitly after capture.
    (
        cd "$REPO_ROOT" || exit 1
        env "${env_args[@]}" bash testing/nat/scripts/nat-test.sh lan
    ) >"$REP_DIR/test-output.log" 2>&1 || rc=$?

    mkdir -p "$REP_DIR/docker-logs"
    for c in fips-nat-lan-a fips-nat-lan-b; do
        docker logs "$c" >"$REP_DIR/docker-logs/$c.log" 2>&1 || true
    done

    # Post-capture teardown. nat-test.sh skipped its final cleanup
    # (skipping is success-path only; failure paths return without
    # cleanup either way), so we tear down here. Mirrors nat-test.sh's
    # cleanup() shape: all three profiles + -v --remove-orphans.
    (
        cd "$REPO_ROOT" || exit 1
        docker compose -f testing/nat/docker-compose.yml \
            --profile cone --profile symmetric --profile lan \
            down -v --remove-orphans \
            >>"$REP_DIR/teardown.log" 2>&1 || true
    )

    if [ -n "$pinning_pid" ]; then
        kill "$pinning_pid" 2>/dev/null || true
        wait "$pinning_pid" 2>/dev/null || true
    fi

    return "$rc"
}

# Extract the timestamp of the last line in $log matching $pattern. The
# daemon's tracing-subscriber emits ISO 8601 UTC timestamps with sub-
# second precision as the first token on each line (after ANSI escapes
# are stripped). Returns the empty string if no line matches. Helper
# scoped to parse_nat_lan; relies on grep -E semantics.
_nat_lan_extract_last_ts() {
    local log="$1"
    local pattern="$2"
    [ -f "$log" ] || { echo ""; return; }
    grep -E "$pattern" "$log" 2>/dev/null \
        | sed -E 's/\x1b\[[0-9;]*[mK]//g' \
        | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z' \
        | tail -1
}

# Compute the per-node stall_signature events dict + derived fields by
# scanning the container's docker log for known event patterns. Echoes
# a JSON object suitable for inlining into the rep's signature.json.
_nat_lan_node_stall_signature() {
    local nodelog="$1"

    local startup_ts nostr_ts adoption_ts handshake_init_ts msg2_sent_ts
    local cross_init_progress_ts cross_init_connected_ts handshake_failed_ts
    local last_log_ts

    startup_ts=$(_nat_lan_extract_last_ts "$nodelog" 'Node started')
    nostr_ts=$(_nat_lan_extract_last_ts "$nodelog" 'Started Nostr UDP NAT traversal attempt|nostr notify loop entered')
    adoption_ts=$(_nat_lan_extract_last_ts "$nodelog" 'Adopted NAT traversal socket')
    handshake_init_ts=$(_nat_lan_extract_last_ts "$nodelog" 'Connection initiated')
    msg2_sent_ts=$(_nat_lan_extract_last_ts "$nodelog" 'Sent msg2 response')
    cross_init_progress_ts=$(_nat_lan_extract_last_ts "$nodelog" 'Ignoring established NAT traversal while peer handshake is already in progress')
    cross_init_connected_ts=$(_nat_lan_extract_last_ts "$nodelog" 'Ignoring established NAT traversal for already-connected peer')
    handshake_failed_ts=$(_nat_lan_extract_last_ts "$nodelog" 'Handshake completion failed')
    last_log_ts=$(_nat_lan_extract_last_ts "$nodelog" '.')

    # Derive last_meaningful_event_category and ts by string-max across
    # categories (ISO 8601 string compare == time compare). Empty
    # category timestamps don't contribute.
    local cat="" cat_ts=""
    local -a pairs=(
        "startup:$startup_ts"
        "discovery:$nostr_ts"
        "adoption:$adoption_ts"
        "handshake_init:$handshake_init_ts"
        "msg2_sent:$msg2_sent_ts"
        "cross_init_ignore_progress:$cross_init_progress_ts"
        "cross_init_ignore_connected:$cross_init_connected_ts"
        "handshake_failed:$handshake_failed_ts"
    )
    local p name ts
    for p in "${pairs[@]}"; do
        name="${p%%:*}"
        ts="${p#*:}"
        if [ -n "$ts" ] && [[ "$ts" > "$cat_ts" ]]; then
            cat_ts="$ts"
            cat="$name"
        fi
    done

    # silent_gap_s: seconds between last_meaningful_event_ts and
    # last_log_ts. Large gap → daemon stayed alive but stopped doing
    # meaningful work. Computed via Python (date math is fragile in
    # pure bash). Empty if either timestamp is missing.
    local silent_gap_s=""
    if [ -n "$last_log_ts" ] && [ -n "$cat_ts" ]; then
        silent_gap_s=$(python3 -c "
from datetime import datetime
def p(s):
    return datetime.strptime(s.rstrip('Z')[:26], '%Y-%m-%dT%H:%M:%S.%f' if '.' in s else '%Y-%m-%dT%H:%M:%S')
try:
    print(round((p('$last_log_ts') - p('$cat_ts')).total_seconds(), 3))
except Exception:
    print('')
" 2>/dev/null || echo "")
    fi

    jq -n \
        --arg last_log "$last_log_ts" \
        --arg last_meaningful "$cat_ts" \
        --arg last_cat "$cat" \
        --arg silent_gap "$silent_gap_s" \
        --arg startup "$startup_ts" \
        --arg discovery "$nostr_ts" \
        --arg adoption "$adoption_ts" \
        --arg handshake_init "$handshake_init_ts" \
        --arg msg2_sent "$msg2_sent_ts" \
        --arg ci_progress "$cross_init_progress_ts" \
        --arg ci_connected "$cross_init_connected_ts" \
        --arg hs_failed "$handshake_failed_ts" \
        '{
            last_log_ts: (if $last_log == "" then null else $last_log end),
            last_meaningful_event_ts: (if $last_meaningful == "" then null else $last_meaningful end),
            last_event_category: (if $last_cat == "" then null else $last_cat end),
            silent_gap_s: (if $silent_gap == "" then null else ($silent_gap | tonumber) end),
            events: {
                startup: (if $startup == "" then null else $startup end),
                discovery: (if $discovery == "" then null else $discovery end),
                adoption: (if $adoption == "" then null else $adoption end),
                handshake_init: (if $handshake_init == "" then null else $handshake_init end),
                msg2_sent: (if $msg2_sent == "" then null else $msg2_sent end),
                cross_init_ignore_progress: (if $ci_progress == "" then null else $ci_progress end),
                cross_init_ignore_connected: (if $ci_connected == "" then null else $ci_connected end),
                handshake_failed: (if $hs_failed == "" then null else $hs_failed end)
            }
        }'
}

parse_nat_lan() {
    local REP_DIR="$1"
    local log="$REP_DIR/test-output.log"

    local peer_adoption_timeout="false"
    if grep -q "TIMEOUT waiting for" "$log"; then
        peer_adoption_timeout="true"
    fi

    local cross_init_observed="false"
    if grep -E "Connection initiated.*node-(a|b)" "$REP_DIR"/docker-logs/*.log 2>/dev/null \
        | awk '{print $1}' | sort -u | head -2 | wc -l | grep -q '2'; then
        cross_init_observed="true"
    fi

    # Per-node stall_signature: scan each container's docker log for
    # known event patterns and extract last-occurrence timestamps. Used
    # by the aggregation phase to bin stalls into localized (both nodes
    # last at same category) / distributed (different categories) /
    # silent (daemon emitted nothing meaningful for >threshold s before
    # timeout) classes. See _nat_lan_node_stall_signature for the event
    # taxonomy.
    local sig_a sig_b
    sig_a=$(_nat_lan_node_stall_signature "$REP_DIR/docker-logs/fips-nat-lan-a.log")
    sig_b=$(_nat_lan_node_stall_signature "$REP_DIR/docker-logs/fips-nat-lan-b.log")

    # Top-level stall_class derived from per-node last_event_category:
    #   no_timeout — peer_adoption_timeout=false (success case)
    #   silent     — either node's silent_gap_s > 5
    #   localized  — both nodes' last_event_category is the same
    #   distributed — categories differ
    #   incomplete  — categories missing on one or both nodes
    local stall_class="no_timeout"
    if [ "$peer_adoption_timeout" = "true" ]; then
        local cat_a cat_b gap_a gap_b
        cat_a=$(echo "$sig_a" | jq -r '.last_event_category // ""')
        cat_b=$(echo "$sig_b" | jq -r '.last_event_category // ""')
        gap_a=$(echo "$sig_a" | jq -r '.silent_gap_s // 0')
        gap_b=$(echo "$sig_b" | jq -r '.silent_gap_s // 0')
        local silent_a silent_b
        silent_a=$(awk -v g="$gap_a" 'BEGIN{ print (g > 5) ? "1" : "0" }')
        silent_b=$(awk -v g="$gap_b" 'BEGIN{ print (g > 5) ? "1" : "0" }')
        if [ "$silent_a" = "1" ] || [ "$silent_b" = "1" ]; then
            stall_class="silent"
        elif [ -z "$cat_a" ] || [ -z "$cat_b" ]; then
            stall_class="incomplete"
        elif [ "$cat_a" = "$cat_b" ]; then
            stall_class="localized"
        else
            stall_class="distributed"
        fi
    fi

    jq -n \
        --argjson peer_adoption_timeout "$peer_adoption_timeout" \
        --argjson cross_init_observed "$cross_init_observed" \
        --argjson sig_a "$sig_a" \
        --argjson sig_b "$sig_b" \
        --arg stall_class "$stall_class" \
        '{
            peer_adoption_timeout: $peer_adoption_timeout,
            cross_init_observed: $cross_init_observed,
            stall_class: $stall_class,
            stall_signature: {
                "fips-nat-lan-a": $sig_a,
                "fips-nat-lan-b": $sig_b
            }
        }' >"$REP_DIR/signature.json"
}

mechanism_match_nat_lan() {
    local REP_DIR="$1"
    local sig="$REP_DIR/signature.json"
    [ -f "$sig" ] || return 1
    local timeout_seen
    timeout_seen=$(jq -r '.peer_adoption_timeout' "$sig" 2>/dev/null || echo "false")
    if [ "$timeout_seen" = "true" ]; then
        echo "true"
    else
        echo "false"
    fi
}

# ── bloom-storm ──────────────────────────────────────────────────────
# The bloom-storm chaos scenario (see
# testing/chaos/scenarios/bloom-storm.yaml) drives a six-node mesh
# with an induced n04 parent-flap and asserts a per-node ceiling
# on `stats.bloom.sent` deltas over the trailing 30s window of the
# 180s run. The flake class tracked here is a single node spiking
# above the ceiling while peers stay well under (asymmetric
# distribution), seen on master CI as ISSUE-2026-0026.
#
# Unlike rekey and nat-lan, chaos doesn't use docker-compose — the
# python sim runner under `python3 -m sim` owns the container
# lifecycle. So the dispatch is a thin wrapper: invoke chaos.sh,
# capture stdout/stderr, and parse the assertion outcomes from the
# captured log. Per-container docker logs aren't separately exposed
# by the sim, so the test-output.log is the primary evidence stream.

run_bloom_storm() {
    local REP_DIR="$1"
    local rc=0

    # Optional CPU-pinning sidecar. Chaos spawns containers under
    # `python3 -m sim`, not docker-compose, so the mesh-lab
    # `compose-resource-limits.yml` override does not apply. The
    # cheapest way to constrain the actual daemon containers' CPU
    # allocation is to poll for `fips-*` containers as the sim
    # spawns them and apply `docker update --cpuset-cpus <set>` to
    # each. Pinning is idempotent — re-applying the same cpuset to
    # a container that already has it is a no-op. The default
    # `0,1` mimics a GHA 2-core runner constraint; set the env var
    # to a wider set (e.g. `0,1,2,3`) to relax, or to the empty
    # string to disable the sidecar and run with the host's full
    # CPU set.
    local cpuset="${FIPS_BLOOM_STORM_CPUSET-0,1}"
    local pinning_pid=""
    if [ -n "$cpuset" ]; then
        (
            while true; do
                for c in $(docker ps --filter "name=fips-" --format '{{.Names}}' 2>/dev/null); do
                    docker update --cpuset-cpus "$cpuset" "$c" >/dev/null 2>&1 || true
                done
                sleep 0.5
            done
        ) &
        pinning_pid=$!
        echo "bloom-storm: cpu-pinning sidecar PID $pinning_pid (cpuset=$cpuset)" \
            >"$REP_DIR/setup.log"
    fi

    (
        cd "$REPO_ROOT" || exit 1
        bash testing/chaos/scripts/chaos.sh bloom-storm
    ) >"$REP_DIR/test-output.log" 2>&1 || rc=$?

    if [ -n "$pinning_pid" ]; then
        kill "$pinning_pid" 2>/dev/null || true
        wait "$pinning_pid" 2>/dev/null || true
    fi

    return "$rc"
}

parse_bloom_storm() {
    local REP_DIR="$1"
    local log="$REP_DIR/test-output.log"

    # bloom_send_rate assertion. The sim runner emits the assertion
    # in two forms — once through the python logger (prefixed with
    # `HH:MM:SS INFO  sim.runner: `) and once as a bare summary line
    # at end-of-run. Anchor on `^(PASS|FAIL)` so we always read the
    # bare line, not the timestamped logger line. Output shapes
    # (testing/chaos/sim/assertions.py):
    #   PASS  bloom_send_rate: max per-node delta N <= ceiling M over trailing Ss (per-node: n01=X, ...)
    #   FAIL  bloom_send_rate: K node(s) exceeded ceiling of M bloom_sent over trailing Ss — offenders: nXX=Y, ... (all per-node deltas: ...)
    local bsr_line
    bsr_line=$(grep -E '^(PASS|FAIL) bloom_send_rate:' "$log" | head -1 || true)

    local bsr_result="unknown"
    local bsr_offenders=""
    local bsr_deltas=""
    local bsr_ceiling=""
    local bsr_max_obs=""
    if [[ -n "$bsr_line" ]]; then
        if [[ "$bsr_line" == FAIL* ]]; then
            bsr_result="fail"
            bsr_offenders=$(echo "$bsr_line" \
                | sed -n 's/.*offenders: \(.*\) (all per-node.*/\1/p' \
                | sed 's/^ *//;s/ *$//')
            bsr_deltas=$(echo "$bsr_line" \
                | sed -n 's/.*all per-node deltas: \([^)]*\).*/\1/p' \
                | sed 's/^ *//;s/ *$//')
            bsr_ceiling=$(echo "$bsr_line" \
                | grep -oE 'ceiling of [0-9]+' | grep -oE '[0-9]+' | head -1)
        elif [[ "$bsr_line" == PASS* ]]; then
            bsr_result="pass"
            bsr_deltas=$(echo "$bsr_line" \
                | sed -n 's/.*(per-node: \([^)]*\)).*/\1/p' \
                | sed 's/^ *//;s/ *$//')
            bsr_ceiling=$(echo "$bsr_line" \
                | grep -oE 'ceiling [0-9]+' | grep -oE '[0-9]+' | head -1)
            bsr_max_obs=$(echo "$bsr_line" \
                | grep -oE 'max per-node delta [0-9]+' | grep -oE '[0-9]+' | head -1)
        fi
    fi

    # Companion assertion (always present in bloom-storm scenario).
    # Same `^(PASS|FAIL)` anchoring as bloom_send_rate above.
    local mps_line
    mps_line=$(grep -E '^(PASS|FAIL) min_parent_switches:' "$log" | head -1 || true)
    local mps_result="unknown"
    if [[ "$mps_line" == PASS* ]]; then
        mps_result="pass"
    elif [[ "$mps_line" == FAIL* ]]; then
        mps_result="fail"
    fi

    # Global negative checks. Use `grep | wc -l` instead of `grep -c`:
    # grep -c returns exit 1 on zero matches, which makes `|| echo 0`
    # fire alongside grep's own `0` stdout, emitting `0\n0` and
    # corrupting the JSON. `grep | wc -l` exits 0 either way and
    # emits exactly one number.
    local panics errors
    panics=$(grep -cE 'PANIC|panicked' "$log" 2>/dev/null; true)
    [[ -z "$panics" ]] && panics=0
    errors=$(grep -cE '\bERROR\b' "$log" 2>/dev/null; true)
    [[ -z "$errors" ]] && errors=0

    # JSON-safe: shell-quote any field that could embed special chars
    # by writing as JSON strings; the per-node delta string can have
    # commas but no quotes/backslashes (sim runner output).
    cat <<EOF >"$REP_DIR/signature.json"
{
  "suite": "bloom-storm",
  "bloom_send_rate": {
    "result": "$bsr_result",
    "ceiling": "$bsr_ceiling",
    "max_observed": "$bsr_max_obs",
    "offenders": "$bsr_offenders",
    "per_node_deltas": "$bsr_deltas"
  },
  "min_parent_switches": {
    "result": "$mps_result"
  },
  "panics": $panics,
  "errors": $errors
}
EOF
}

mechanism_match_bloom_storm() {
    local REP_DIR="$1"
    local log="$REP_DIR/test-output.log"
    # The ISSUE-2026-0026 mechanism is a bloom_send_rate FAIL with
    # at least one named offender (i.e., not the "failed to sample
    # window endpoints" sub-failure mode, which is harness rather
    # than mechanism). The asymmetric-distribution check (one node
    # spiking while peers stay under) is implicit in the FAIL
    # shape: the assertion only fires when at least one node is
    # over while at least one other is at or under the ceiling.
    if grep -qE '^FAIL bloom_send_rate:' "$log" 2>/dev/null \
        && grep -qE 'offenders: [a-z][0-9]+=[0-9]+' "$log" 2>/dev/null; then
        echo "true"
    else
        echo "false"
    fi
}

# Dispatch — returns rc of suite, side-effects signature.json
dispatch_suite() {
    local REP_DIR="$1"
    case "$SUITE" in
        rekey|rekey-accept-off|rekey-outbound-only)
            local rc=0
            run_rekey_family "$SUITE" "$REP_DIR" || rc=$?
            parse_rekey "$REP_DIR"
            return "$rc" ;;
        nat-lan)
            local rc=0
            run_nat_lan "$REP_DIR" || rc=$?
            parse_nat_lan "$REP_DIR"
            return "$rc" ;;
        bloom-storm)
            local rc=0
            run_bloom_storm "$REP_DIR" || rc=$?
            parse_bloom_storm "$REP_DIR"
            return "$rc" ;;
        *)
            echo "ERROR: unsupported suite '$SUITE' in this lab harness (initial scaffolding)" >&2
            echo "Supported: rekey, rekey-accept-off, rekey-outbound-only, nat-lan, bloom-storm" >&2
            return 99 ;;
    esac
}

# Mechanism-match heuristic per suite
dispatch_mechanism_match() {
    local REP_DIR="$1"
    case "$SUITE" in
        rekey|rekey-accept-off|rekey-outbound-only)
            mechanism_match_rekey "$REP_DIR" ;;
        nat-lan)
            mechanism_match_nat_lan "$REP_DIR" ;;
        bloom-storm)
            mechanism_match_bloom_storm "$REP_DIR" ;;
        *)
            echo "unknown" ;;
    esac
}

# ── Main loop ────────────────────────────────────────────────────────

echo "=== mesh-lab: suite=$SUITE reps=$REPS profile=$PROFILE ==="
echo "    out: $OUT_DIR"
echo ""

PASS_COUNT=0
FAIL_COUNT=0
MECH_MATCH_COUNT=0

# Trap to ensure pressure is always cleaned up even on Ctrl-C
trap 'pressure_stop; exit 130' INT TERM

for rep in $(seq 1 "$REPS"); do
    rep_padded=$(printf "%03d" "$rep")
    REP_DIR="$OUT_DIR/rep-$rep_padded"
    mkdir -p "$REP_DIR"

    started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "--- rep $rep/$REPS (started $started_at) ---"

    pressure_start "$PROFILE" || {
        echo "  ERROR: pressure_start failed for profile '$PROFILE'" >&2
        exit 2
    }

    rc=0
    dispatch_suite "$REP_DIR" || rc=$?

    pressure_stop

    ended_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    mechanism_match=$(dispatch_mechanism_match "$REP_DIR")

    if [ "$rc" -eq 0 ]; then
        result="pass"
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  rep $rep: PASS"
    else
        result="fail"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "  rep $rep: FAIL (exit $rc, mechanism_match=$mechanism_match)"
    fi

    if [ "$mechanism_match" = "true" ]; then
        MECH_MATCH_COUNT=$((MECH_MATCH_COUNT + 1))
    fi

    cat <<EOF >"$REP_DIR/summary.json"
{
  "rep": $rep,
  "suite": "$SUITE",
  "profile": "$PROFILE",
  "started_at": "$started_at",
  "ended_at": "$ended_at",
  "exit_code": $rc,
  "result": "$result",
  "mechanism_match": $mechanism_match,
  "signature_file": "signature.json"
}
EOF
done

# ── Aggregate summary ────────────────────────────────────────────────

cat <<EOF >"$OUT_DIR/summary.json"
{
  "suite": "$SUITE",
  "profile": "$PROFILE",
  "reps": $REPS,
  "pass_count": $PASS_COUNT,
  "fail_count": $FAIL_COUNT,
  "mechanism_match_count": $MECH_MATCH_COUNT,
  "pass_rate": $(awk -v p="$PASS_COUNT" -v r="$REPS" 'BEGIN{ printf "%.3f", p/r }'),
  "fail_rate": $(awk -v f="$FAIL_COUNT" -v r="$REPS" 'BEGIN{ printf "%.3f", f/r }'),
  "mechanism_match_rate": $(awk -v m="$MECH_MATCH_COUNT" -v r="$REPS" 'BEGIN{ printf "%.3f", m/r }')
}
EOF

echo ""
echo "=== summary ==="
cat "$OUT_DIR/summary.json"
echo ""
echo "raw artifacts: $OUT_DIR/"
