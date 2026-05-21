#!/bin/bash
# Multi-run iperf3 + ping bench for FIPS mesh. Repeats each test N times
# (default 3), reports median + min/max + flags outliers >20% from
# median. Adds round-trip latency (ping) and a TCP-retransmit count
# (proxy for packet loss across the FIPS overlay) per path.
#
# Usage:
#   ./bench-multirun.sh [mesh|chain]
#
# Environment:
#   FIPS_BENCH_RUNS=3        Number of iperf3 repetitions per path
#   FIPS_BENCH_DURATION=15   Seconds per iperf3 run
#   FIPS_BENCH_PARALLEL=1    Parallel TCP streams (1 = single-stream)
#   FIPS_BENCH_PING_COUNT=30 ICMP probes per path
#   FIPS_BENCH_OUTLIER_PCT=20  Flag run as outlier if Δ from median > N%
#   FIPS_BENCH_OUTPUT=json|text  (default text; json emits NDJSON)

set -e
trap 'echo ""; echo "Bench interrupted"; exit 130' INT

PROFILE="${1:-mesh}"
RUNS="${FIPS_BENCH_RUNS:-5}"
DURATION="${FIPS_BENCH_DURATION:-15}"
PARALLEL="${FIPS_BENCH_PARALLEL:-1}"
PING_COUNT="${FIPS_BENCH_PING_COUNT:-30}"
OUTLIER_PCT="${FIPS_BENCH_OUTLIER_PCT:-20}"
OUTPUT="${FIPS_BENCH_OUTPUT:-text}"

if ! [[ "$RUNS" =~ ^[1-9][0-9]*$ ]] || [ "$RUNS" -lt 1 ]; then
    echo "FIPS_BENCH_RUNS must be ≥ 1" >&2; exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/../generated-configs/npubs.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found. Run generate-configs.sh first." >&2
    exit 1
fi
# shellcheck source=../generated-configs/npubs.env
source "$ENV_FILE"

# ── Helpers ────────────────────────────────────────────────────────────────

# Run iperf3 once, print "<mbps> <retransmits>" on success or "FAIL" on
# failure. Uses JSON output so we don't have to scrape human-readable
# SI prefixes.
iperf_once() {
    local client="$1" dest_npub="$2"
    local out
    if ! out=$(docker exec "fips-$client" iperf3 -c "${dest_npub}.fips" \
        -t "$DURATION" -P "$PARALLEL" -J 2>&1); then
        echo FAIL
        return
    fi
    python3 - "$out" <<'PYEOF'
import json, sys
try:
    d = json.loads(sys.argv[1])
    bps = d['end']['sum_received']['bits_per_second']
    # iperf3 reports TCP retransmits in 'sum_sent.retransmits' on
    # the client side; missing on UDP or for the server-summary view.
    retr = d.get('end', {}).get('sum_sent', {}).get('retransmits', 0)
    print(f"{bps/1e6:.2f} {retr}")
except Exception as e:
    print("FAIL")
PYEOF
}

# Median + min + max + CoV% + outlier indices over a whitespace-
# separated list of floats. CoV% = (stddev / mean) * 100, i.e. the
# coefficient of variation in percent — directly comparable across
# paths regardless of absolute throughput. Single-value runs print
# CoV=0.
# Prints: "<median> <min> <max> <cov_pct> <outliers_csv>"
stats() {
    python3 - "$OUTLIER_PCT" "$@" <<'PYEOF'
import math
import sys
pct = float(sys.argv[1])
vals = [float(x) for x in sys.argv[2:]]
n = len(vals)
s = sorted(vals)
median = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2
lo, hi = s[0], s[-1]
mean = sum(vals) / n if n else 0.0
if n > 1 and mean > 0:
    variance = sum((v - mean) ** 2 for v in vals) / (n - 1)  # sample stddev
    cov_pct = math.sqrt(variance) / mean * 100
else:
    cov_pct = 0.0
outliers = []
if median > 0:
    for i, v in enumerate(vals):
        if abs(v - median) / median * 100 > pct:
            outliers.append(str(i + 1))
print(
    f"{median:.2f} {lo:.2f} {hi:.2f} {cov_pct:.1f}% "
    f"{','.join(outliers) if outliers else '-'}"
)
PYEOF
}

# Ping once, print "<min_ms> <avg_ms> <max_ms> <mdev_ms> <loss_pct>"
# or "FAIL".
ping_path() {
    local client="$1" dest_npub="$2"
    local out
    if ! out=$(docker exec "fips-$client" \
        ping -c "$PING_COUNT" -i 0.2 -w "$((PING_COUNT * 2))" \
        -q "${dest_npub}.fips" 2>&1); then
        echo FAIL
        return
    fi
    # "min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms"
    local rtt loss
    rtt=$(echo "$out" | awk -F' = ' '/min\/avg\/max\/mdev/ {print $2}' | awk '{print $1}')
    loss=$(echo "$out" | awk -F', ' '/packet loss/ {for (i=1;i<=NF;i++) if ($i ~ /packet loss/) print $i}' | awk '{print $1}')
    if [ -z "$rtt" ]; then
        echo FAIL
        return
    fi
    echo "${rtt//\// } ${loss:-N/A}"
}

# ── Path definitions ───────────────────────────────────────────────────────
#
# Each entry is `<client-container> <dest-npub> <label>`. Labels are
# plain `client→dest` — the bench measures iperf3 throughput between
# the two named nodes. The static topology is printed at start so the
# operator can see the configured routing context.
#
# IMPORTANT — labels DO NOT encode hop count. With peer discovery
# enabled and all nodes on the same docker-bridge subnet, every node
# pair establishes a direct UDP path within a few ticks regardless of
# the static `peers:` list. The bench measures the post-convergence
# steady state, which is what real-world FIPS deployments see. To
# force on-wire multihop, isolate nodes on distinct docker networks.
case "$PROFILE" in
    mesh|mesh-public)
        # Static-peer paths only — without mDNS / a Nostr relay in the
        # test container set, non-adjacent pairs (A↔B, A↔C) can't
        # establish direct UDP and the bench would either fail
        # convergence or measure multihop forwarding (apples-to-oranges
        # vs builds that do have mDNS). Stick to pairs that are in
        # each other's static `peers:` list so the measurement is
        # deterministic and the same on every build.
        PATHS=(
            "node-a $NPUB_D A→D"
            "node-a $NPUB_E A→E"
            "node-e $NPUB_A E→A"
        )
        TOPOLOGY_LINES=(
            "A peers with: D, E"
            "D peers with: A, C, E"
            "E peers with: A, C, D"
            "(Static-peer pairs A↔D, A↔E only — non-adjacent pairs"
            " are skipped because plain mesh.yaml has no discovery"
            " transport that converges them onto direct UDP.)"
        )
        ;;
    chain)
        # Chain topology forces intentional multihop forwarding for
        # non-adjacent pairs: A peers only with B, B peers with A+C,
        # etc. We bench just A→B (1 hop, direct static peer) so the
        # comparison is again apples-to-apples without discovery.
        PATHS=(
            "node-a $NPUB_B A→B"
        )
        TOPOLOGY_LINES=(
            "Static chain: A — B — C — D — E"
            "(A↔B is the only static-peer pair we benchmark; multi-hop"
            " forwarding to C/D/E needs reply-learned routing or mDNS"
            " to settle, which is not deterministic on a fresh mesh.)"
        )
        ;;
    *)
        echo "Unknown profile: $PROFILE" >&2; exit 1 ;;
esac

# ── Run ────────────────────────────────────────────────────────────────────

echo "=== FIPS multi-run bench ($PROFILE, ${RUNS}×${DURATION}s, P=${PARALLEL}) ==="
echo "Outlier flag: Δ from median > ${OUTLIER_PCT}%"
echo ""
echo "Topology (static \`peers:\` from $PROFILE.yaml):"
for line in "${TOPOLOGY_LINES[@]}"; do
    echo "  $line"
done
echo ""

# Wait for peer discovery to converge before measuring — otherwise
# the bench randomly measures either direct UDP (post-convergence
# steady state) or multihop forwarding through static peers (only
# until discovery converges). On the same docker-bridge subnet
# convergence should take seconds, not tens of seconds; this is the
# tight default. Bump FIPS_BENCH_CONVERGE_SECS for slower test setups
# (no Nostr relay, no mDNS, etc.).
#
# If any path hasn't converged by the deadline, the bench FAILS with
# a clear list of unconverged pairs — that's almost always a topology
# / discovery misconfiguration that would make the numbers noise.
CONVERGE_SECS="${FIPS_BENCH_CONVERGE_SECS:-15}"

peer_is_direct() {
    local client="$1" dest_npub="$2"
    docker exec "fips-$client" fipsctl show peers 2>/dev/null \
        | python3 -c '
import json, sys
target = sys.argv[1]
try:
    d = json.load(sys.stdin)
    for p in d.get("peers", []):
        if p.get("npub") == target:
            print("yes" if p.get("connectivity") == "connected" else "no")
            sys.exit(0)
    print("no")
except Exception:
    print("no")
' "$dest_npub" 2>/dev/null
}

# Per-peer `stats.bytes_sent` snapshot for the given client. Used to
# verify that the iperf3 traffic actually went out the intended next-
# hop (i.e. the routing protocol picked the static-peer link, not a
# multihop alternative).
peer_bytes_sent_snapshot() {
    local client="$1"
    docker exec "fips-$client" fipsctl show peers 2>/dev/null \
        | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    for p in d.get("peers", []):
        npub = p.get("npub") or "?"
        sent = (p.get("stats") or {}).get("bytes_sent", 0)
        print(f"{npub} {sent}")
except Exception:
    pass
'
}

# Compute deltas between two snapshots and identify which peer
# received the most bytes_sent growth, plus the absolute bytes for
# the requested target. Prints "<top_npub> <top_delta> <target_delta>".
peer_bytes_delta_winner() {
    local target="$1"; shift
    local before="$1"; shift
    local after="$1"; shift
    python3 - "$target" "$before" "$after" <<'PYEOF'
import sys
target, before, after = sys.argv[1], sys.argv[2], sys.argv[3]
b = {}
for line in before.splitlines():
    if not line.strip(): continue
    k, v = line.split()
    b[k] = int(v)
a = {}
for line in after.splitlines():
    if not line.strip(): continue
    k, v = line.split()
    a[k] = int(v)
deltas = {k: a.get(k, 0) - b.get(k, 0) for k in a}
target_delta = deltas.get(target, 0)
if deltas:
    top_npub = max(deltas, key=deltas.get)
    top_delta = deltas[top_npub]
else:
    top_npub, top_delta = "-", 0
print(f"{top_npub} {top_delta} {target_delta}")
PYEOF
}

declare -A PEER_STATE
echo "Waiting for peer convergence (up to ${CONVERGE_SECS}s)…"
WAIT_START=$(date +%s)
while :; do
    all_done=1
    for path in "${PATHS[@]}"; do
        read -r client npub label <<<"$path"
        if [ "${PEER_STATE[$label]:-}" = "direct" ]; then
            continue
        fi
        if [ "$(peer_is_direct "$client" "$npub")" = "yes" ]; then
            PEER_STATE[$label]=direct
        else
            all_done=0
        fi
    done
    if [ "$all_done" = 1 ]; then
        break
    fi
    elapsed=$(( $(date +%s) - WAIT_START ))
    if [ "$elapsed" -ge "$CONVERGE_SECS" ]; then
        break
    fi
    sleep 1
done

unconverged=()
for path in "${PATHS[@]}"; do
    read -r client npub label <<<"$path"
    state="${PEER_STATE[$label]:-via-forward}"
    PEER_STATE[$label]="$state"
    printf '  %-10s %s\n' "$label" "$state"
    if [ "$state" != "direct" ]; then
        unconverged+=("$label")
    fi
done
echo ""

if [ "${#unconverged[@]}" -gt 0 ]; then
    echo "ERROR: peer discovery did not converge for ${#unconverged[@]} of ${#PATHS[@]} paths within ${CONVERGE_SECS}s:" >&2
    for p in "${unconverged[@]}"; do
        echo "  - $p" >&2
    done
    echo "" >&2
    echo "On a single docker-bridge subnet convergence should take seconds." >&2
    echo "Check that: (a) all node IPs are reachable peer-to-peer, (b) the" >&2
    echo "test build includes a working discovery transport (Nostr relay /" >&2
    echo "mDNS / etc.), (c) FIPS_BENCH_CONVERGE_SECS is high enough for" >&2
    echo "this setup. Bench aborted to avoid reporting noisy mixed-state" >&2
    echo "measurements." >&2
    exit 2
fi

# Header for text output. All bandwidth columns are Mbits/sec
# (Mbps). CoV% = sample coefficient of variation (stddev/mean) over
# the N runs, in percent — directly comparable across paths.
if [ "$OUTPUT" = "text" ]; then
    printf '%-10s %-12s %12s %12s %12s %8s %10s | %10s %8s %10s\n' \
        path session 'median Mbps' 'min Mbps' 'max Mbps' 'CoV %' outliers \
        'avg RTT ms' 'loss %' 'TCP retr'
    printf '%-10s %-12s %12s %12s %12s %8s %10s | %10s %8s %10s\n' \
        '------' '------' '------' '------' '------' '------' '------' \
        '------' '------' '------'
fi

FAIL_COUNT=0

ROUTE_ERRORS=()

for path in "${PATHS[@]}"; do
    read -r client npub label <<<"$path"

    # Snapshot per-peer bytes_sent before iperf3 — used after the
    # runs to verify the routing protocol actually pushed the test
    # traffic out the intended static-peer link (and not, say,
    # via an alternative multihop route the cost-based router could
    # in principle pick). Same defensive check the iperf-test.sh
    # path measurement assumes implicitly.
    bytes_before=$(peer_bytes_sent_snapshot "$client")

    # iperf3 runs
    bw_runs=()
    retr_runs=()
    for i in $(seq 1 "$RUNS"); do
        result=$(iperf_once "$client" "$npub")
        if [ "$result" = "FAIL" ]; then
            FAIL_COUNT=$((FAIL_COUNT + 1))
            bw_runs+=("0")
            retr_runs+=("0")
        else
            bw=$(echo "$result" | awk '{print $1}')
            retr=$(echo "$result" | awk '{print $2}')
            bw_runs+=("$bw")
            retr_runs+=("$retr")
        fi
    done

    bytes_after=$(peer_bytes_sent_snapshot "$client")
    # `delta_winner` is "<npub_with_largest_bytes_sent_delta> <its_bytes> <target_dest_bytes>"
    delta_winner=$(peer_bytes_delta_winner "$npub" "$bytes_before" "$bytes_after")
    read -r winning_npub winning_delta target_delta <<<"$delta_winner"
    if [ "$winning_npub" != "$npub" ]; then
        ROUTE_ERRORS+=("$label: traffic exited via $winning_npub ($winning_delta B) instead of $npub ($target_delta B)")
    fi

    # Stats on bandwidth (median / min / max / coefficient-of-variation / outlier indices)
    bw_stats=$(stats "${bw_runs[@]}")
    read -r bw_median bw_min bw_max bw_cov bw_outliers <<<"$bw_stats"
    # Sum retransmits across runs (a proxy for packet loss volume).
    retr_sum=$(python3 -c "print(sum(int(x) for x in '${retr_runs[*]}'.split()))")

    # Ping (single run; ping gives its own internal stats already).
    ping_result=$(ping_path "$client" "$npub")
    if [ "$ping_result" = "FAIL" ]; then
        rtt_avg="N/A"
        loss="N/A"
    else
        # min avg max mdev loss
        read -r _rtt_min rtt_avg _rtt_max _rtt_mdev loss <<<"$ping_result"
    fi

    session_state="${PEER_STATE[$label]:-via-forward}"
    if [ "$OUTPUT" = "json" ]; then
        printf '{"path":"%s","client":"%s","dest_npub":"%s","session":"%s","mbps_runs":[%s],"mbps_median":%s,"mbps_min":%s,"mbps_max":%s,"mbps_cov_pct":"%s","outlier_runs":"%s","rtt_avg_ms":"%s","loss":"%s","tcp_retr_total":%s}\n' \
            "$label" "$client" "$npub" "$session_state" \
            "$(IFS=, ; echo "${bw_runs[*]}")" \
            "$bw_median" "$bw_min" "$bw_max" "$bw_cov" "$bw_outliers" \
            "$rtt_avg" "$loss" "$retr_sum"
    else
        printf '%-10s %-12s %12s %12s %12s %8s %10s | %10s %8s %10s\n' \
            "$label" "$session_state" "$bw_median" "$bw_min" "$bw_max" \
            "$bw_cov" "$bw_outliers" \
            "$rtt_avg" "$loss" "$retr_sum"
        if [ "$bw_outliers" != "-" ]; then
            printf '%-10s   runs (Mbps): %s\n' "  ↑outliers" "${bw_runs[*]}"
        fi
    fi
done

echo ""
if [ "${#ROUTE_ERRORS[@]}" -gt 0 ]; then
    echo "ERROR: traffic for ${#ROUTE_ERRORS[@]} of ${#PATHS[@]} paths did not exit via the intended static-peer link:" >&2
    for e in "${ROUTE_ERRORS[@]}"; do
        echo "  - $e" >&2
    done
    echo "" >&2
    echo "The numbers above measured a different route than the path label" >&2
    echo "claims. Inspect peer cost / tree topology before trusting them." >&2
    exit 3
fi
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "WARN: $FAIL_COUNT iperf3 runs failed"
    exit 1
fi
echo "OK"
