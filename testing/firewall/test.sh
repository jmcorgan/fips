#!/bin/bash
# Integration test for the fips0 nftables baseline (packaging/common/fips.nft).
#
# Asserts the four behaviors documented in the fips.nft header:
#   (a) unallowed inbound on fips0  → DROP
#   (b) outbound-initiated reply    → conntrack established/related ACCEPT
#   (c) ICMPv6 echo-request         → ACCEPT
#   (d) drop-in allowlisted port    → ACCEPT
# and one about the TUN name the file is scoped to:
#   (e) table scoped to an interface that is not the TUN → the TUN is
#       not policed, and the daemon's listener report says so; reloading
#       the real file restores (a)
#
# fips-firewall.service activation: the unit's ExecStart is
# `/usr/sbin/nft -f /etc/fips/fips.nft`. The test image does not run
# systemd, so this script invokes the same nft command directly inside
# the container after fips0 is up. The full deb-install harness covers
# the systemd unit-enablement path separately.
#
# Usage: ./test.sh [--skip-build] [--keep-up]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTING_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
GENERATE_CONFIGS="$SCRIPT_DIR/generate-configs.sh"

# shellcheck source=SCRIPTDIR/table-check.sh
source "$SCRIPT_DIR/table-check.sh"

CONTAINER_A="fips-fw-container-a${FIPS_CI_NAME_SUFFIX:-}"
CONTAINER_B="fips-fw-container-b${FIPS_CI_NAME_SUFFIX:-}"

NPUB_A="npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"
NPUB_B="npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le"

# Port not present in any drop-in. Used for case (a) to assert DROP.
UNALLOWED_PORT=8000
# Port present in node-b's fips.d drop-in. Used for case (d) to assert ACCEPT.
ALLOWED_PORT=22
# Port that node-a listens on for the conntrack reply test (case b).
OUTBOUND_TARGET_PORT=8000

SKIP_BUILD=false
KEEP_UP=false

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-build) SKIP_BUILD=true; shift ;;
        --keep-up) KEEP_UP=true; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

cleanup() {
    if [ "$KEEP_UP" = false ]; then
        docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT

log() {
    echo "=== $*"
}

pass() {
    echo "PASS: $*"
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# Wait for fips0 to exist and have a global IPv6 address inside container.
wait_for_fips0() {
    local container="$1"
    local timeout="${2:-30}"
    for _ in $(seq 1 "$timeout"); do
        # Captured before matching: under pipefail, grep -q exiting at its
        # match can kill the writer with SIGPIPE and turn the match into a
        # miss. Captured inside the condition so that set -e does not end
        # the script while fips0 is not up yet.
        if grep -qE 'inet6 fd[0-9a-f]+:' \
            <<<"$(docker exec "$container" ip -6 addr show fips0 2>/dev/null)"; then
            return 0
        fi
        sleep 1
    done
    fail "$container fips0 did not come up within ${timeout}s"
}

# Connected-peer count for a container, or the empty string if it did not
# answer.
#
# Empty is deliberately distinct from a real 0. An `|| echo 0` fallback here
# would make "the container is unreachable, or its daemon never came up" and
# "the daemon answered, and the answer was zero" the same value, so any caller
# expecting zero would be satisfied on the first iteration without the
# property it is checking ever being observed. No caller in this file expects
# zero today, which is exactly why the fallback has to go now rather than when
# one is added. Same shape as the acl-allowlist suite's read_connected_peers.
read_connected_peers() {
    local container="$1"
    docker exec "$container" fipsctl show peers 2>/dev/null \
        | python3 -c 'import json,sys; data=json.load(sys.stdin); print(sum(1 for p in data.get("peers", []) if p.get("connectivity") == "connected"))' 2>/dev/null \
        || true
}

# Wait for the peer count on a container to reach the expected value.
wait_for_peers_exact() {
    local container="$1"
    local expected_count="$2"
    local timeout="${3:-30}"

    local count="" answered=false
    for _ in $(seq 1 "$timeout"); do
        count=$(read_connected_peers "$container")
        if [ -n "$count" ]; then
            answered=true
            if [ "$count" -eq "$expected_count" ]; then
                return 0
            fi
        fi
        sleep 1
    done

    if [ "$answered" = false ]; then
        fail "$container never answered a peer query in ${timeout}s, so a count of $expected_count was never actually observed"
    fi
    docker exec "$container" fipsctl show peers >&2 || true
    fail "$container did not reach $expected_count connected peers in ${timeout}s (last answer: $count)"
}

# Resolve `<npub>.fips` inside a container and print the AAAA answer.
resolve_fips_addr() {
    local container="$1"
    local npub="$2"
    docker exec "$container" getent ahostsv6 "${npub}.fips" \
        | awk '{print $1; exit}'
}

# Activate the fips firewall baseline inside a container. Mirrors the
# fips-firewall.service ExecStart.
activate_firewall() {
    local container="$1"
    docker exec "$container" nft -f /etc/fips/fips.nft
    # Sanity: the table must now exist.
    if ! docker exec "$container" nft list table inet fips >/dev/null 2>&1; then
        fail "$container: inet fips table not present after nft -f"
    fi
}

# Print the `firewall_active` field of the IPv6 adapter's
# show_listening_sockets reply ("true" or "false"), or the empty string when
# the adapter's status socket did not answer. That socket sits beside the
# control socket, with -ipv6tun before its extension. Empty is distinct from
# both answers, so a caller expecting either value cannot be satisfied by an
# unreachable daemon.
read_firewall_active() {
    local container="$1"
    docker exec "$container" python3 -c '
import glob, json, socket, sys
paths = ["/run/fips/control-ipv6tun.sock", "/var/run/fips/control-ipv6tun.sock"] \
    + glob.glob("/run/user/*/fips/control-ipv6tun.sock") \
    + ["/tmp/fips-control-ipv6tun.sock"]
for path in paths:
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(path)
    except OSError:
        continue
    s.sendall(b"{\"command\":\"show_listening_sockets\"}\n")
    s.shutdown(socket.SHUT_WR)
    buf = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    reply = json.loads(buf.decode().splitlines()[0])
    active = reply.get("data", {}).get("firewall_active")
    if isinstance(active, bool):
        print("true" if active else "false")
    sys.exit(0)
' 2>/dev/null || true
}

# Verify default-policy and key chain rules look right.
assert_baseline_loaded() {
    local container="$1"
    local listing
    listing="$(docker exec "$container" nft list table inet fips)"
    # Default-deny is achieved via the trailing `counter drop` (chain
    # policy is `accept` for return-on-non-fips0 to work safely).
    # Require the verdict, not just the counter: `counter packets` alone
    # matches a counter rule with any verdict, including one that accepts.
    # nft renders the rule as `counter packets N bytes M drop`.
    #
    # This checks that a counted drop rule exists somewhere in the table,
    # not that it is the baseline's trailing one. A drop-in under
    # /etc/fips/fips.d/ contributing its own counted drop would satisfy
    # this even with the baseline rule removed. Asserting the rule's
    # position is a larger change than this finding calls for; the
    # drop-counter check at the end of the run is the one that reads the
    # trailing rule specifically.
    if ! printf '%s' "$listing" \
        | grep -qE 'counter packets [0-9]+ bytes [0-9]+ drop'; then
        fail "$container: trailing 'counter drop' rule missing from inet fips"
    fi
    if ! printf '%s' "$listing" | grep -q 'iifname != "fips0" return'; then
        fail "$container: non-fips0 early return rule missing"
    fi
    if ! printf '%s' "$listing" | grep -q 'ct state established,related accept'; then
        fail "$container: conntrack established,related rule missing"
    fi
    if ! printf '%s' "$listing" | grep -q 'icmpv6 type echo-request accept'; then
        fail "$container: ICMPv6 echo-request rule missing"
    fi
    if ! printf '%s' "$listing" | grep -q 'tcp dport 22 accept'; then
        fail "$container: drop-in tcp dport 22 rule missing (fips.d not included?)"
    fi
    pass "$container: fips.nft baseline + drop-in loaded"
}

# ────────────────────────────────────────────────────────────────────────

if [ "$SKIP_BUILD" = false ]; then
    log "Building Linux test binaries"
    "$TESTING_DIR/scripts/build.sh" --no-docker
fi

log "Generating firewall fixtures"
"$GENERATE_CONFIGS"

log "Starting firewall harness"
docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
# --build only on the hand path. Under a harness, --skip-build means the caller
# has already built the image this compose file names, and rebuilding it here
# would overwrite that image from whatever the shared build context happens to
# hold — which is how a suite ends up certifying binaries it was never given.
# With --skip-build a missing image is an error: compose may neither build it
# from the build: context nor pull a same-named image from a registry.
if [ "$SKIP_BUILD" = false ]; then
    docker compose -f "$COMPOSE_FILE" up -d --build
else
    docker compose -f "$COMPOSE_FILE" up -d --no-build --pull never
fi

log "Waiting for fips0 on both nodes"
wait_for_fips0 "$CONTAINER_A" 40
wait_for_fips0 "$CONTAINER_B" 40

log "Waiting for peer convergence"
wait_for_peers_exact "$CONTAINER_A" 1 40
wait_for_peers_exact "$CONTAINER_B" 1 40

log "Resolving fips0 addresses"
ADDR_A="$(resolve_fips_addr "$CONTAINER_A" "$NPUB_A")"
ADDR_B="$(resolve_fips_addr "$CONTAINER_B" "$NPUB_B")"
[ -z "$ADDR_A" ] && fail "could not resolve node-a fips0 address"
[ -z "$ADDR_B" ] && fail "could not resolve node-b fips0 address"
echo "  node-a: $ADDR_A"
echo "  node-b: $ADDR_B"

log "Activating fips-firewall on $CONTAINER_B"
activate_firewall "$CONTAINER_B"
assert_baseline_loaded "$CONTAINER_B"

# ── (c) Pre-firewall sanity: confirm both ports are reachable BEFORE ─
#       the firewall is up would be ideal, but we activated already to
#       keep the test deterministic. Instead we run case (c) ICMPv6
#       first, since it's the most basic reachability check.

log "Case (c): ICMPv6 echo-request to firewalled node"
if docker exec "$CONTAINER_A" ping6 -c 3 -W 5 "$ADDR_B" >/dev/null 2>&1; then
    pass "(c) ICMPv6 ping node-a → node-b accepted"
else
    fail "(c) ICMPv6 ping node-a → node-b should succeed but was dropped"
fi

# ── (a) Unallowed inbound is dropped ───────────────────────────────────
log "Case (a): unallowed inbound TCP/${UNALLOWED_PORT} from node-a → node-b"
# python3 http.server is already listening on :: per entrypoint default mode.
#
# The rule is a DROP, so the SYN is discarded with no RST and curl must
# hit --max-time and exit 28. Assert exactly that rather than "any
# non-zero rc": a REJECT, a closed port, an unroutable address or a
# missing listener all fail too, with rc 7 or similar, and accepting
# those would let the suite report a blocked connection when nothing was
# ever blocked. Only 28 distinguishes "silently dropped" from "failed for
# some other reason".
CURL_TIMEOUT_RC=28
set +e
docker exec "$CONTAINER_A" curl -6 --silent --output /dev/null \
    --max-time 5 "http://[${ADDR_B}]:${UNALLOWED_PORT}/"
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
    fail "(a) connection to ${UNALLOWED_PORT} succeeded but should have been DROP'd (rc=0)"
fi
if [ "$RC" -ne "$CURL_TIMEOUT_RC" ]; then
    fail "(a) connection to ${UNALLOWED_PORT} failed with curl rc=$RC, expected $CURL_TIMEOUT_RC (timeout). A DROP produces no RST, so anything else means the connection failed for a reason other than the firewall dropping it"
fi
pass "(a) inbound TCP/${UNALLOWED_PORT} dropped (curl rc=$RC, timed out as expected)"

# ── (b) Outbound-initiated flow + conntrack reply ──────────────────────
log "Case (b): node-b initiates outbound TCP, expects reply via conntrack"
# node-b → node-a:8000 on the fips overlay. node-a has http.server on
# [::]:8000 and is NOT firewalled, so this is purely a test of node-b's
# outbound + ct state established,related path on the way back.
#
# mktemp rather than a fixed /tmp name: two concurrent runs of this suite
# would otherwise share one host file, and either one's `rm` between the
# other's write and read leaves an empty read that fails the http_code check
# for a reason that has nothing to do with the firewall.
CURL_OUT="$(mktemp)"
set +e
docker exec "$CONTAINER_B" curl -6 --silent --max-time 5 \
    --output /dev/null --write-out '%{http_code}' \
    "http://[${ADDR_A}]:${OUTBOUND_TARGET_PORT}/" >"$CURL_OUT" 2>/dev/null
RC=$?
set -e
HTTP_CODE="$(cat "$CURL_OUT" 2>/dev/null || true)"
rm -f "$CURL_OUT"
if [ "$RC" -ne 0 ]; then
    fail "(b) outbound from node-b failed (curl rc=$RC, http=$HTTP_CODE) — conntrack reply path broken"
fi
if [ "$HTTP_CODE" != "200" ]; then
    fail "(b) outbound returned http=$HTTP_CODE (expected 200) — reply blocked?"
fi
pass "(b) outbound from node-b got HTTP $HTTP_CODE via conntrack reply path"

# ── (d) Drop-in allowlisted port accepted ──────────────────────────────
log "Case (d): drop-in allowlisted TCP/${ALLOWED_PORT} from node-a → node-b"
# nc -zv -w3: zero-I/O scan, verbose, 3-second timeout. Exit 0 = port
# open and reachable. The container's sshd is listening on [::]:22 by
# default per the test entrypoint.
if docker exec "$CONTAINER_A" nc -6 -z -v -w 3 "$ADDR_B" "$ALLOWED_PORT" 2>&1 \
    | grep -qE 'succeeded|open'; then
    pass "(d) drop-in allowlisted TCP/${ALLOWED_PORT} reachable"
else
    fail "(d) drop-in allowlisted TCP/${ALLOWED_PORT} should be reachable but was blocked"
fi

# ── Drop-counter sanity ────────────────────────────────────────────────
log "Drop counter incremented (case a should have ticked it)"
# Scope to a drop rule rather than any counter rule: `/counter packets/`
# alone takes the first counter rule of whatever verdict.
#
# Extract the count by position within the matched text, not by field
# number. `$3` assumes the line starts with `counter`, so on a rule like
# `tcp dport 9 counter packets 42 bytes 3000 drop` it prints the port,
# not the packet count -- a plausible shape, since fips.nft includes
# /etc/fips/fips.d/*.nft ahead of the trailing drop and a drop-in may
# legitimately add its own counted drop.
#
# Take the LAST match, not the first. Case (a) is an unallowed inbound
# that matches no accept rule and falls through to the baseline
# default-deny, which fips.nft emits as the final rule of the chain
# (packaging/common/fips.nft, `counter drop` after the drop-in include).
# A drop-in's own counted drop would otherwise be read instead, and it
# has nothing to do with what case (a) exercised.
DROP_PKTS="$(docker exec "$CONTAINER_B" nft list table inet fips \
    | awk 'match($0, /counter packets [0-9]+ bytes [0-9]+ drop/) {
             line = substr($0, RSTART); sub(/^counter packets /, "", line);
             split(line, f, " "); val = f[1]
           }
           END { if (val != "") print val }')"
if [ -z "${DROP_PKTS:-}" ] || [ "$DROP_PKTS" -lt 1 ]; then
    fail "drop counter is $DROP_PKTS — case (a) should have produced drops"
fi
pass "drop counter = $DROP_PKTS (case a was actually dropped, not just unrouted)"

# ── (e) Table scoped to an interface that is not the TUN ───────────────
# fips.nft scopes its chain with `iifname != $fips_if return`, so a table
# whose interface name differs from tun.name polices nothing on the TUN.
# Load the production file with its interface name rewritten (the sed
# matches the quoted literal on the define line and on the older inline
# form alike), and assert both halves: mesh traffic reaches the case-(a)
# port, and the daemon's listener report no longer claims an active
# firewall. Then reload the real file and assert case (a) drops again.
log "Case (e): fips.nft scoped to an interface that is not the TUN"

# Control first: with the real file loaded, the report must read "true".
# This proves the query path answers before its "false" is trusted below.
FW_ACTIVE="$(read_firewall_active "$CONTAINER_B")"
if [ "$FW_ACTIVE" != "true" ]; then
    fail "(e) control: with the real fips.nft loaded, the IPv6 adapter's" \
        "show_listening_sockets reply should report firewall_active true" \
        "(got '${FW_ACTIVE}'; empty means the adapter's socket did not answer)"
fi

OTHER_IF="notfips0"
docker exec "$CONTAINER_B" sh -c \
    "sed 's/\"fips0\"/\"${OTHER_IF}\"/g' /etc/fips/fips.nft > /tmp/fips-other-if.nft"
docker exec "$CONTAINER_B" nft -f /tmp/fips-other-if.nft
TABLE_RC=0
table_has "$CONTAINER_B" "iifname != \"${OTHER_IF}\" return" || TABLE_RC=$?
if [ "$TABLE_RC" -eq 2 ]; then
    fail "(e) could not list the rewritten table on $CONTAINER_B"
elif [ "$TABLE_RC" -ne 0 ]; then
    fail "(e) the rewritten table is not scoped to ${OTHER_IF}; the sed did not change the scoping rule"
fi

set +e
docker exec "$CONTAINER_A" curl -6 --silent --output /dev/null \
    --max-time 5 "http://[${ADDR_B}]:${UNALLOWED_PORT}/"
RC=$?
set -e
if [ "$RC" -ne 0 ]; then
    fail "(e) with the table scoped to ${OTHER_IF}, TCP/${UNALLOWED_PORT} on fips0 should be reachable (curl rc=$RC)"
fi
pass "(e) table scoped to ${OTHER_IF} does not police fips0: TCP/${UNALLOWED_PORT} reachable"

FW_ACTIVE="$(read_firewall_active "$CONTAINER_B")"
if [ "$FW_ACTIVE" != "false" ]; then
    fail "(e) table scoped to ${OTHER_IF} while the TUN is fips0: the IPv6 adapter's" \
        "show_listening_sockets reply should report firewall_active false" \
        "(got '${FW_ACTIVE}')"
fi
pass "(e) listener report shows the firewall as not policing the TUN"

activate_firewall "$CONTAINER_B"
assert_baseline_loaded "$CONTAINER_B"
set +e
docker exec "$CONTAINER_A" curl -6 --silent --output /dev/null \
    --max-time 5 "http://[${ADDR_B}]:${UNALLOWED_PORT}/"
RC=$?
set -e
if [ "$RC" -ne "$CURL_TIMEOUT_RC" ]; then
    fail "(e) after reloading the real fips.nft, TCP/${UNALLOWED_PORT} should be dropped again (curl rc=$RC, expected $CURL_TIMEOUT_RC)"
fi
FW_ACTIVE="$(read_firewall_active "$CONTAINER_B")"
if [ "$FW_ACTIVE" != "true" ]; then
    fail "(e) after reloading the real fips.nft, firewall_active should be true again (got '${FW_ACTIVE}')"
fi
pass "(e) real fips.nft reloaded: TCP/${UNALLOWED_PORT} dropped and the report shows the firewall active"

log "Firewall integration test passed"
