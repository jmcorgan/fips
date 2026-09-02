#!/bin/bash
# Integration test for dynamic interface binding.
#
# Asserts the five behaviors the presence machine exists to provide, against
# real daemons and a real veth pair:
#
#   (a) boot race        — a daemon whose interface does not exist yet starts,
#                          reports the transport ABSENT, and reports Degraded
#   (b) late attach      — the interface appears; the daemon binds it with no
#                          restart, clears Degraded, and peers over it
#   (c) flap             — the interface goes down and comes back; presence and
#                          health follow it in BOTH directions
#   (d) destroy/recreate — the interface is deleted outright and recreated; the
#                          daemon rebinds (the case the old ENXIO beacon hack
#                          half-covered)
#   (e) optional         — an interface that never appears logs at info and
#                          never moves node health
#
# plus the log-hygiene property the design is explicit about: absence is logged
# once on the edge, never once per retry.
#
# The daemons run under FIPS_TEST_MODE=default, NOT chaos: the chaos entrypoint
# waits for Ethernet interfaces before starting the daemon, which is exactly
# the workaround being retired. The daemon must wait for itself here.
#
# Usage: ./test.sh [--skip-build] [--keep-up]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTING_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

NODE_A="fips-ifb-node-a${FIPS_CI_NAME_SUFFIX:-}"
NODE_B="fips-ifb-node-b${FIPS_CI_NAME_SUFFIX:-}"
NODE_C="fips-ifb-node-c${FIPS_CI_NAME_SUFFIX:-}"

# The interface each node binds. Same name on both sides: they are in separate
# network namespaces, and using one name keeps the fixtures identical.
LAB_IFACE="ve-lab0"
# The interface that never exists. `optional: true` in both configs.
DOCK_IFACE="fips-dock0"
# node-c's interface, present before its daemon starts. See case (f).
BOOT_IFACE="ve-boot0"

# Host-side veth names, scoped per run: these live in the host (or Docker VM)
# namespace for the moment between creation and the move into the containers,
# where two concurrent runs would otherwise collide on one name.
HOST_VETH_A="vhifb${FIPS_CI_NAME_SUFFIX:-0}a"
HOST_VETH_B="vhifb${FIPS_CI_NAME_SUFFIX:-0}b"
HOST_VETH_C="vhifb${FIPS_CI_NAME_SUFFIX:-0}c"
HOST_VETH_D="vhifb${FIPS_CI_NAME_SUFFIX:-0}d"

SKIP_BUILD=false
KEEP_UP=false

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-build) SKIP_BUILD=true; shift ;;
        --keep-up) KEEP_UP=true; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

log()  { echo "=== $*"; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; dump_diagnostics; exit 1; }

dump_diagnostics() {
    echo "--- node-a transports ---" >&2
    docker exec "$NODE_A" fipsctl show transports >&2 2>&1 || true
    echo "--- node-a status ---" >&2
    docker exec "$NODE_A" fipsctl show status >&2 2>&1 || true
    echo "--- node-a log (tail) ---" >&2
    docker logs --tail 80 "$NODE_A" >&2 2>&1 || true
    echo "--- node-b log (tail) ---" >&2
    docker logs --tail 80 "$NODE_B" >&2 2>&1 || true
    return 0
}

cleanup() {
    # Remove the veth pair wherever it survived: inside a container if the move
    # succeeded, on the host if the run died between creation and the move.
    docker exec "$NODE_A" ip link del "$LAB_IFACE" >/dev/null 2>&1 || true
    ip_host "ip link del $HOST_VETH_A" >/dev/null 2>&1 || true
    docker exec "$NODE_C" ip link del "$BOOT_IFACE" >/dev/null 2>&1 || true
    ip_host "ip link del $HOST_VETH_C" >/dev/null 2>&1 || true
    if [ "$KEEP_UP" = false ]; then
        docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
    return 0
}

# ── Host-namespace ip(8) ─────────────────────────────────────────────────
#
# Every `ip link` operation that touches the host network stack runs inside a
# short-lived privileged container sharing the host network and PID namespaces,
# for the reason testing/chaos/sim/veth.py documents at length: on macOS the
# containers live in the Docker VM, so running ip(8) on the macOS host could
# never reach them, while on Linux the shared namespaces make it identical to
# running ip(8) directly.
ip_host() {
    docker run --rm --privileged --network host --pid host \
        --entrypoint /bin/sh "$IMAGE" -c "$1"
}

# Docker's own view of a container, so the gate case can wait for a netns
# without implying the daemon inside it has started.
container_state() {
    docker inspect -f '{{.State.Status}}' "$1" 2>/dev/null || true
}

container_pid() {
    docker inspect -f '{{.State.Pid}}' "$1"
}

# Create the veth pair and move one end into each container.
create_veth() {
    local pid_a pid_b
    pid_a="$(container_pid "$NODE_A")"
    pid_b="$(container_pid "$NODE_B")"

    # One invocation, not three. The host-side names exist only between the
    # `add` and the two `netns` moves, and ci-cleanup.sh's host-veth sweep is
    # deliberately shaped to the chaos simulation's names and does not cover
    # these — so the window in which a hard kill could strand them is kept to
    # a single command, with the EXIT trap covering the rest.
    ip_host "set -e
        ip link add $HOST_VETH_A type veth peer name $HOST_VETH_B
        ip link set $HOST_VETH_A netns $pid_a name $LAB_IFACE
        ip link set $HOST_VETH_B netns $pid_b name $LAB_IFACE" >/dev/null

    # A moved link arrives down. Presence is IFF_UP, so the daemon correctly
    # does not bind until this runs — which is also why (c) can flap it with
    # nothing but `ip link set down`.
    docker exec "$NODE_A" ip link set "$LAB_IFACE" up
    docker exec "$NODE_B" ip link set "$LAB_IFACE" up
    return 0
}

# ── Daemon introspection ─────────────────────────────────────────────────

# Field of a named transport's `interface` block, or "" if the transport, the
# block, or the daemon is not there.
iface_field() {
    docker exec "$1" fipsctl show transports 2>/dev/null | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    print(""); raise SystemExit
for t in data.get("transports", []):
    if t.get("name") == sys.argv[1]:
        print(t.get("interface", {}).get(sys.argv[2], ""))
        break
else:
    print("")
' "$2" "$3"
}

node_state() {
    docker exec "$1" fipsctl show status 2>/dev/null | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get("state", ""))
except Exception:
    print("")
'
}

peer_count() {
    docker exec "$1" fipsctl show peers 2>/dev/null | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    print(0); raise SystemExit
print(len(data.get("peers", [])))
'
}

# Count of a literal in a container log. Used for the log-hygiene assertion.
log_count() {
    docker logs "$1" 2>&1 | grep -c -- "$2" || true
}

# Poll `expr` until it prints `want`, up to `timeout` seconds.
# Usage: wait_for <timeout> <want> <command...>
wait_for() {
    local timeout="$1" want="$2"; shift 2
    local i got
    for i in $(seq 1 "$timeout"); do
        got="$("$@" || true)"
        if [ "$got" = "$want" ]; then
            return 0
        fi
        sleep 1
    done
    echo "  (last value: '${got:-}', wanted '$want')" >&2
    return 1
}

# Poll until the command prints a value no greater than `want`.
wait_for_at_most() {
    local timeout="$1" want="$2"; shift 2
    local i got
    for i in $(seq 1 "$timeout"); do
        got="$("$@" || true)"
        if [ -n "$got" ] && [ "$got" -le "$want" ] 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo "  (last value: '${got:-}', wanted <= '$want')" >&2
    return 1
}

# Poll until the command prints a value that is at least `want`.
wait_for_at_least() {
    local timeout="$1" want="$2"; shift 2
    local i got
    for i in $(seq 1 "$timeout"); do
        got="$("$@" || true)"
        if [ -n "$got" ] && [ "$got" -ge "$want" ] 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo "  (last value: '${got:-}', wanted >= '$want')" >&2
    return 1
}

# ── Run ──────────────────────────────────────────────────────────────────

IMAGE="${FIPS_TEST_IMAGE:-fips-test:latest}"

trap cleanup EXIT

if [ "$SKIP_BUILD" = false ]; then
    log "Building test image"
    bash "$TESTING_DIR/scripts/build.sh"
fi

log "Generating fixtures"
LAB_IFACE="$LAB_IFACE" DOCK_IFACE="$DOCK_IFACE" BOOT_IFACE="$BOOT_IFACE" \
    bash "$SCRIPT_DIR/generate-configs.sh"

log "Starting nodes with $LAB_IFACE absent"
docker compose -f "$COMPOSE_FILE" up -d

# The daemon must reach a serving state without the interface. Waiting on the
# control socket answering at all is the first half of assertion (a): a daemon
# that exited on `NoTransports` never answers.
if ! wait_for 40 "degraded" node_state "$NODE_A"; then
    fail "(a) node-a did not come up Degraded with $LAB_IFACE absent"
fi
pass "(a) daemon started and serves with its only interface absent"

# ── (a) presence and policy are visible to an operator ───────────────────

[ "$(iface_field "$NODE_A" lab presence)" = "absent" ] \
    || fail "(a) lab transport is not reported ABSENT"
[ "$(iface_field "$NODE_A" lab policy)" = "required" ] \
    || fail "(a) lab transport is not reported required"
[ "$(iface_field "$NODE_A" lab name)" = "$LAB_IFACE" ] \
    || fail "(a) lab transport does not name $LAB_IFACE"
[ "$(iface_field "$NODE_A" dock presence)" = "absent" ] \
    || fail "(e) dock transport is not reported ABSENT"
[ "$(iface_field "$NODE_A" dock policy)" = "optional" ] \
    || fail "(e) dock transport is not reported optional"
pass "(a) presence and policy are visible in show_transports"

# ── log hygiene, measured across the absence ─────────────────────────────
#
# The required interface's absence must be logged once, on the edge — not once
# per retry. Measured over an interval long enough for many retries (the binder
# polls every second). The 12 s also carries the next assertion past the 10 s
# bring-up window, so both the edge rule and the deadline are covered by one
# wait.

# Matched on the edge line specifically. The deadline error below is a
# different line by design, and counting both here would read the deadline
# firing during the sleep as a repeated edge.
EDGE_LINE="Ethernet interface absent; waiting"

absent_before="$(log_count "$NODE_A" "$EDGE_LINE")"
sleep 12
absent_after="$(log_count "$NODE_A" "$EDGE_LINE")"
if [ "$absent_after" -ne "$absent_before" ]; then
    fail "absence was logged $((absent_after - absent_before)) more times over 12s of retries; \
the edge must be logged once, not per attempt"
fi
# Two edges total: one for the required lab interface, one for the optional
# dock interface. More would mean the edge is not an edge.
[ "$absent_before" -eq 2 ] \
    || fail "expected exactly 2 absence edges at start, saw $absent_before"
pass "absence is logged once on the edge, not per retry"

# ── a sustained absence errors exactly once ──────────────────────────────
#
# The edge is not an error: an interface missing for a moment at boot and bound
# a moment later is the ordinary case this mechanism exists to absorb. Past the
# 10 s bring-up window it is no longer a race, and a *required* interface says
# so — once. The 12 s above put us on the far side of that window.
#
# Exactly one line, from lab. The optional dock interface has been absent just
# as long and must be silent, which is what `optional` means; two here would
# mean the policy is not being consulted.

startup_errors="$(log_count "$NODE_A" " ERROR ")"
if [ "$startup_errors" -ne 1 ]; then
    docker logs "$NODE_A" 2>&1 | grep -- " ERROR " >&2 || true
    fail "expected exactly 1 ERROR line for the required interface past the \
bring-up window, saw $startup_errors (an optional interface must contribute none)"
fi
[ "$(log_count "$NODE_A" "still missing past the bring-up window")" -eq 1 ] \
    || fail "the ERROR line is not the sustained-absence report"
pass "a required interface absent past the window errors, an optional one does not"

# ...and does not keep saying it. Duration is state, published as
# interface.since_secs and as Degraded; re-announcing it on a timer is what
# the old 1 m / 10 m / 1 h ladder did.
sleep 12
[ "$(log_count "$NODE_A" " ERROR ")" -eq 1 ] \
    || fail "the sustained-absence error repeated; it must be said once per episode"
pass "the sustained-absence error is said once, not on a schedule"

# ── (b) late attach ──────────────────────────────────────────────────────

log "Creating the veth pair"
create_veth

if ! wait_for 30 "present" iface_field "$NODE_A" lab presence; then
    fail "(b) node-a did not bind $LAB_IFACE after it appeared"
fi
if ! wait_for 30 "present" iface_field "$NODE_B" lab presence; then
    fail "(b) node-b did not bind $LAB_IFACE after it appeared"
fi
pass "(b) both daemons bound the interface with no restart"

# Health must clear. This is `Degraded` behaving as a level rather than a
# latch — the property that made the old monotonic failed-set wrong.
if ! wait_for 20 "running" node_state "$NODE_A"; then
    fail "(b) node-a stayed Degraded after its interface returned"
fi
pass "(b) Degraded cleared when the interface came back"

# The optional interface is still absent and must still not matter.
[ "$(iface_field "$NODE_A" dock presence)" = "absent" ] \
    || fail "(e) dock unexpectedly bound"
pass "(e) an absent optional interface does not degrade the node"

# Discovery and peering over the late-bound interface: the point of binding at
# all. Without this the suite would prove the daemon can open a socket, not
# that traffic flows over it.
if ! wait_for_at_least 45 1 peer_count "$NODE_A"; then
    fail "(b) node-a found no peer over the late-bound interface"
fi
if ! wait_for_at_least 45 1 peer_count "$NODE_B"; then
    fail "(b) node-b found no peer over the late-bound interface"
fi
pass "(b) nodes discovered and peered over the late-bound interface"

# ── (c) flap ─────────────────────────────────────────────────────────────

errors_before_detach="$(log_count "$NODE_A" " ERROR ")"

log "Taking $LAB_IFACE down on node-a"
docker exec "$NODE_A" ip link set "$LAB_IFACE" down

detach_start=$SECONDS
if ! wait_for 20 "absent" iface_field "$NODE_A" lab presence; then
    fail "(c) node-a did not notice the interface going down"
fi
detach_elapsed=$(( SECONDS - detach_start ))
if ! wait_for 20 "degraded" node_state "$NODE_A"; then
    fail "(c) node-a did not report Degraded while its interface was down"
fi
pass "(c) a link going down is observed as absence and degrades health"

# A detach is reported, at warn. The edge is not an error — a link coming and
# going is the weather in a mesh daemon, and the error is the 10 s deadline's
# to give, not the edge's.
if ! wait_for_at_least 10 1 log_count "$NODE_A" "Ethernet interface detached"; then
    fail "(c) a runtime detach was not reported"
fi

# Only meaningful while we are still inside the bring-up window. Detection is
# sub-second over netlink, so this is the ordinary path; if the runner was slow
# enough that the deadline could have fired, the check has nothing to say and
# says so rather than failing on the harness's own latency.
if [ "$detach_elapsed" -lt 8 ]; then
    detach_errors="$(log_count "$NODE_A" " ERROR ")"
    if [ "$detach_errors" -ne "$errors_before_detach" ]; then
        docker logs "$NODE_A" 2>&1 | grep -- " ERROR " >&2 || true
        fail "(c) the detach edge logged an ERROR after ${detach_elapsed}s; the \
edge is a warn and only outlasting the window earns an error"
    fi
    pass "(c) a detach is reported without crying error"
else
    echo "  (skipped the edge-not-an-error check: detach took ${detach_elapsed}s,"
    echo "   which is inside the deadline's reach)"
fi

# The peers that interface carried must go with it, and go *now*.
#
# `link_dead_timeout_secs` is at its 30 s default here, so a withdrawal inside
# 15 s can only have come from the detach edge and not from the liveness
# reaper. That gap is the whole point: until the edge drove the teardown, this
# node kept the peer, kept selecting routes through it, and kept advertising
# reachability it no longer had — dropping transit traffic in silence for the
# whole timeout, with alternative paths sitting unused.
if ! wait_for_at_most 15 0 peer_count "$NODE_A"; then
    fail "(c) node-a kept a peer that was only reachable over the downed \
interface; the detach edge did not withdraw it"
fi
pass "(c) the peers the interface carried were withdrawn on the detach edge"

log "Bringing $LAB_IFACE back up on node-a"
docker exec "$NODE_A" ip link set "$LAB_IFACE" up

if ! wait_for 30 "present" iface_field "$NODE_A" lab presence; then
    fail "(c) node-a did not rebind after the interface came back"
fi
if ! wait_for 20 "running" node_state "$NODE_A"; then
    fail "(c) node-a stayed Degraded after the interface came back"
fi
if ! wait_for_at_least 45 2 iface_field "$NODE_A" lab binds; then
    fail "(c) the rebind was not counted"
fi
pass "(c) the interface flapped and the daemon followed it both ways"

# And the withdrawal is not a one-way door: the peer comes back over the
# rebound interface on its own, by beacon, with no operator action.
if ! wait_for_at_least 60 1 peer_count "$NODE_A"; then
    fail "(c) node-a did not re-peer after its interface came back"
fi
pass "(c) peering re-established over the rebound interface"

# ── (d) destroy and recreate ─────────────────────────────────────────────
#
# Deleting the netdev outright is the case the old ENXIO beacon-socket reopen
# half-covered: the veth is gone, the socket underneath is stale, and the name
# comes back a moment later. One presence machine now covers it.

log "Deleting and recreating the veth pair"
docker exec "$NODE_A" ip link del "$LAB_IFACE"

if ! wait_for 20 "absent" iface_field "$NODE_A" lab presence; then
    fail "(d) node-a did not notice the interface being deleted"
fi
if ! wait_for 20 "absent" iface_field "$NODE_B" lab presence; then
    fail "(d) node-b did not notice its end of the pair disappearing"
fi

create_veth

if ! wait_for 30 "present" iface_field "$NODE_A" lab presence; then
    fail "(d) node-a did not rebind the recreated interface"
fi
if ! wait_for 30 "present" iface_field "$NODE_B" lab presence; then
    fail "(d) node-b did not rebind the recreated interface"
fi
if ! wait_for 20 "running" node_state "$NODE_A"; then
    fail "(d) node-a stayed Degraded after the interface was recreated"
fi
pass "(d) a destroyed and recreated interface is rebound"

# Peering must re-establish over the new hardware. A recreated veth has a new
# MAC, so this also exercises the "same name, different hardware" path that
# drops cached neighbors instead of resuming onto them.
if ! wait_for_at_least 60 1 peer_count "$NODE_A"; then
    fail "(d) node-a did not re-peer after the interface was recreated"
fi
pass "(d) peering re-established over the recreated interface"

# ── (f) an interface present before the daemon starts ────────────────────
#
# Everything above binds through the binder loop, because the interface does
# not exist until the harness makes it. The ordinary case on a booted router is
# the opposite one: the interface is already there and `start_async` binds it
# inline, before the loop is running.
#
# That path published its presence edge outside the churn guard, so the guard
# believed it had announced nothing and the *first* detach asked for no
# retraction. The node kept reporting Running with its only required interface
# gone, and stayed that way until a second detach happened to repair the guard.
# Nothing in cases (a)-(e) can reach it.
log "(f) starting node-c with its interface already present"

docker compose -f "$COMPOSE_FILE" up -d node-c

# The container parks on the gate, so this is the netns and not yet the daemon.
if ! wait_for 30 "running" container_state "$NODE_C"; then
    fail "(f) node-c container did not start"
fi

pid_c="$(container_pid "$NODE_C")"
ip_host "set -e
    ip link add $HOST_VETH_C type veth peer name $HOST_VETH_D
    ip link set $HOST_VETH_C netns $pid_c name $BOOT_IFACE
    ip link set $HOST_VETH_D netns $pid_c name ${BOOT_IFACE}p" >/dev/null
docker exec "$NODE_C" ip link set "$BOOT_IFACE" up
docker exec "$NODE_C" ip link set "${BOOT_IFACE}p" up

# Release the gate. The daemon now starts with the interface already up.
docker exec "$NODE_C" touch /tmp/fips-go

if ! wait_for 40 "running" node_state "$NODE_C"; then
    fail "(f) node-c did not come up Running with its interface present at start"
fi
[ "$(iface_field "$NODE_C" boot presence)" = "present" ] \
    || fail "(f) node-c did not bind $BOOT_IFACE inline at start"
pass "(f) an interface present at start is bound inline and reports Running"

# The assertion. One detach, on a binding this loop did not create.
docker exec "$NODE_C" ip link set "$BOOT_IFACE" down

if ! wait_for 30 "absent" iface_field "$NODE_C" boot presence; then
    fail "(f) node-c did not notice $BOOT_IFACE going down"
fi
if ! wait_for 30 "degraded" node_state "$NODE_C"; then
    fail "(f) node-c stayed Running after its only required interface went \
away — the start-time bind never reached node health"
fi
pass "(f) the first detach after a clean start degrades the node"

# And it is still a level, not a latch, on this path too.
docker exec "$NODE_C" ip link set "$BOOT_IFACE" up
if ! wait_for 30 "running" node_state "$NODE_C"; then
    fail "(f) node-c stayed Degraded after its interface returned"
fi
pass "(f) health clears again when the interface returns"

# ── (g) the link-event fast path is actually the one in use ──────────────
#
# The whole suite would pass with `open_link_socket()` hardcoded to Err: the
# 1 s poll is a complete fallback and covers every `wait_for` window here, so
# nothing else asserts that the netlink path exists, let alone that it is what
# detected anything. The binder says which backing it got at startup, so ask
# it directly rather than inferring from timing that the poll would also
# satisfy.
# `log_count`, not `grep -q`: under `set -o pipefail` a `grep -q` that exits on
# its first match closes the pipe, `docker logs` takes SIGPIPE, and the
# pipeline reports failure even though the line was found. `grep -c` reads the
# stream to the end.
if [ "$(log_count "$NODE_A" "event_driven=true")" -eq 0 ]; then
    docker logs "$NODE_A" 2>&1 | grep -i "binder started" >&2 || true
    fail "(g) the binder fell back to polling; the netlink link-event source \
did not open, and every timing assertion in this suite would still pass"
fi
pass "(g) detection is driven by netlink events, not by the poll fallback"

# ── (h) churn damping engages on a genuinely flapping interface ──────────
#
# This is load-bearing twice over. It is what stops a flapping interface
# logging a recovery per cycle, and — since the detach edge now withdraws the
# peers that interface carried — it is also the only thing bounding how often
# that withdrawal can fire. Nothing exercised it: every flap elsewhere in this
# suite is a single down/up with long settles either side, which is precisely
# the shape the damper ignores.
#
# Four bindings that each die well inside MIN_STABLE_BINDING (10 s). The
# streak crosses CHURN_THRESHOLD (3) on the third, which is the edge that
# announces itself.
log "(h) flapping $LAB_IFACE to drive the churn guard"
for _ in 1 2 3 4; do
    docker exec "$NODE_A" ip link set "$LAB_IFACE" down
    sleep 1
    docker exec "$NODE_A" ip link set "$LAB_IFACE" up
    sleep 2
done

if ! wait_for_at_least 30 1 log_count "$NODE_A" "keeps dying immediately after binding"; then
    docker logs "$NODE_A" 2>&1 | grep -i "ethernet" | tail -20 >&2
    fail "(h) four short-lived bindings did not engage the churn guard"
fi
pass "(h) a flapping interface engages churn damping"

# Having engaged, the guard must hold health rather than announcing each bind.
# The failure this catches is a damper that counts but does not damp.
recoveries_during_churn="$(log_count "$NODE_A" "Ethernet interface recovered")"
if [ "$recoveries_during_churn" -gt 6 ]; then
    fail "(h) node-a announced $recoveries_during_churn recoveries; the guard \
counted the churn but kept announcing through it"
fi
pass "(h) churn suppressed the per-cycle recovery announcements"

# And it is not a latch: once a binding lasts, the interface is announced
# again and the node returns to Running on its own.
log "(h) letting $LAB_IFACE settle"
docker exec "$NODE_A" ip link set "$LAB_IFACE" up >/dev/null 2>&1 || true
if ! wait_for 60 "present" iface_field "$NODE_A" lab presence; then
    fail "(h) node-a did not rebind after the flapping stopped"
fi
if ! wait_for 60 "running" node_state "$NODE_A"; then
    fail "(h) node-a stayed Degraded after the flapping stopped"
fi
pass "(h) a settled interface is announced again after churn"

# ── final log hygiene ────────────────────────────────────────────────────
#
# Four outages happened above (start, down, delete, and node-b's end of the
# delete). A generous ceiling still catches the failure mode that matters: a
# retry loop logging per attempt would be in the hundreds by now.
edges="$(log_count "$NODE_A" "Ethernet interface")"
[ "$edges" -lt 40 ] \
    || fail "node-a logged $edges interface lines; the edges are not edges"
pass "log volume stayed proportional to edges, not to retries"

echo
echo "ALL PASSED"
