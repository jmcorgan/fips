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
    (
        cd "$REPO_ROOT" || exit 1
        bash testing/nat/scripts/nat-test.sh lan
    ) >"$REP_DIR/test-output.log" 2>&1 || rc=$?

    mkdir -p "$REP_DIR/docker-logs"
    for c in fips-nat-lan-a fips-nat-lan-b; do
        docker logs "$c" >"$REP_DIR/docker-logs/$c.log" 2>&1 || true
    done

    return "$rc"
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

    cat <<EOF >"$REP_DIR/signature.json"
{
  "peer_adoption_timeout": $peer_adoption_timeout,
  "cross_init_observed": $cross_init_observed
}
EOF
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
        *)
            echo "ERROR: unsupported suite '$SUITE' in this lab harness (initial scaffolding)" >&2
            echo "Supported: rekey, rekey-accept-off, rekey-outbound-only, nat-lan" >&2
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
