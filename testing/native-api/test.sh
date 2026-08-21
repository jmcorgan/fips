#!/bin/bash
# Native datagram API checks (experimental feature).
#
# The client runs in its own container and reaches the daemon through a
# bind-mounted /run/fips. That is the real deployment shape: a separate process
# with its own filesystem opening the socket, rather than a test speaking to the
# daemon from inside its own container. It is also what makes the access policy
# observable — the host sees the socket file and can read its mode.
#
# The setup protocol is two commands and two descriptors. `connect` hands back
# a flow's SOCK_SEQPACKET half; `listen` hands back the listener's own, which is
# what makes a listener pollable and makes accepting a recvmsg on it rather than
# a round trip on the command socket. There are no events and no accept or
# reject command: an arriving flow is one message on the listener descriptor,
# carrying that flow's descriptor with it, and refusing a flow is close(2).
#
# Every check that receives a descriptor names it. The harness treats a
# descriptor nothing named as a failure rather than ignoring it, because an
# unnamed one is a flow or a held port dropped with nothing to say so.
#
# A peer is named by npub everywhere a client can see it, in a connect reply and
# in an arrival alike. The 16-byte node address is the wire's and appears only
# on the operator surface, which is why the control-socket check below asserts
# both and the client checks assert only the npub.
#
# The observability check reads the daemon's own view back out through the
# control socket. That needs nothing added to the image: the control socket is
# enabled by default and lands in the same bind-mounted /run/fips, and the image
# already carries python3 for the API client.
#
# inject, stats and arrive are debug commands, gated on
# node.native_api.debug_commands and off in a packaged node. node.yaml turns
# them on because nine checks here drive them; check_debug_commands_gated runs a
# second node that leaves the key alone and asserts all three are refused there.
#
# The echo check runs examples/native-echo.rs, which is built against the
# crate's own client module rather than against the line protocol. That makes it
# the only check here where both ends are programs a user could have written.
# examples/native-surface.rs is the second such program: it walks the client's
# whole public surface against a live daemon and asserts what each item reports,
# which is the coverage a check driven from the Python line-protocol client
# cannot give. Both image paths carry both binaries; see resolve_image and
# testing/docker/Dockerfile.
#
# Usage: ./test.sh
#
# Image: FIPS_TEST_IMAGE if set (this is what ci-local.sh passes, and there is
# deliberately no fips-test:latest to fall back on). Otherwise a minimal image
# is built from locally compiled binaries, which is the standalone path.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LABEL="com.corganlabs.fips-ci=1"
NODE_NAME="fips-native-api-node-$$"
GATED_NAME="fips-native-api-gated-$$"
SURFACE="fips-native-surface-$$"
SOCK_DIR="$(mktemp -d)"
IMAGE=""
BUILT_IMAGE=""

# Two valid npubs the checks use as peers. Nothing is ever sent to them: the
# wire is not connected, and the arrival command only names them. They must
# decode, because connect and arrive resolve an npub to a node address.
PEER="npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"
PEER2="npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl"

# How many assertions one run of examples/native-surface.rs records.
#
# Deliberately brittle. The binary prints the recorder's own counter rather than
# a literal, so comparing against this number catches an assertion block that
# stopped running as well as one that failed: a #[cfg] gate that no longer
# matches, or an early return, still exits 0 and still prints the completion
# line, and only the count betrays it. Adding an assertion there must therefore
# force an edit here, which is the friction that keeps the two from drifting
# apart in silence.
SURFACE_ASSERTIONS=31

PASS=0
FAIL=0

log()  { echo "=== $*"; }
pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }

cleanup() {
    teardown_two_nodes
    docker rm -f "$NODE_NAME" >/dev/null 2>&1
    docker rm -f "${NODE_NAME}-off" >/dev/null 2>&1
    docker rm -f "$GATED_NAME" >/dev/null 2>&1
    docker rm -f "$SURFACE" >/dev/null 2>&1
    [[ -n "$BUILT_IMAGE" ]] && docker rmi -f "$BUILT_IMAGE" >/dev/null 2>&1
    rm -rf "$SOCK_DIR"
    return 0
}
trap cleanup EXIT

# ─────────────────────────────────────────────────────────────────────
# Image
# ─────────────────────────────────────────────────────────────────────

# Print a source file newer than `built`, and nothing when none is. The second
# argument, when given, is the example source `built` was compiled from.
#
# Every binary this run depends on is built from src/ and Cargo.toml, and is
# read alongside the harness client in this directory. The Python is
# bind-mounted live rather than built into the image, so a redesigned harness
# would otherwise run against a stale daemon without complaint, which is
# exactly the verdict this guard exists to prevent.
#
# An example is probed against its OWN .rs and no other, which is what keeps
# the guard usable rather than merely correct. Cargo does not relink
# target/release/fips when only an example changes, so probing the daemon
# against all of examples/ leaves it permanently older than a just-edited
# example: the run refuses, and the `cargo build --release --bins --examples`
# the refusal prescribes does not clear the condition. Editing native-surface.rs
# is the routine case now, so that deadlock would be hit on nearly every
# iteration.
stale_source() {
    local built="$1" own="${2:-}"
    find "$REPO_ROOT/src" "$REPO_ROOT/Cargo.toml" -newer "$built" -print -quit 2>/dev/null
    find "$SCRIPT_DIR" -name '*.py' -newer "$built" -print -quit 2>/dev/null
    [[ -n "$own" && "$own" -nt "$built" ]] && echo "$own"
    return 0
}

resolve_image() {
    if [[ -n "${FIPS_TEST_IMAGE:-}" ]]; then
        IMAGE="$FIPS_TEST_IMAGE"
        log "Using FIPS_TEST_IMAGE=$IMAGE"
        return 0
    fi

    # All three binaries come from one profile directory. A release daemon
    # paired with a debug echo server would be two builds of two trees, which is
    # the mixture the staleness guard below exists to refuse.
    local profile=""
    for candidate in "$REPO_ROOT/target/release" "$REPO_ROOT/target/debug"; do
        [[ -x "$candidate/fips" && -x "$candidate/examples/native-echo" \
            && -x "$candidate/examples/native-surface" ]] \
            && { profile="$candidate"; break; }
    done
    if [[ -z "$profile" ]]; then
        echo "No FIPS_TEST_IMAGE, and no profile holds fips with the native-echo and native-surface examples." >&2
        echo "Build them first: cargo build --release --bins --examples" >&2
        return 1
    fi
    local binary="$profile/fips"
    local echo_binary="$profile/examples/native-echo"
    local walk_binary="$profile/examples/native-surface"

    # A stale binary is the worst outcome available here: the checks would run,
    # pass or fail against code that is not the working tree's, and report a
    # verdict about the wrong thing. Refuse rather than warn.
    local newest_source
    newest_source="$(stale_source "$binary"
        stale_source "$echo_binary" "$REPO_ROOT/examples/native-echo.rs"
        stale_source "$walk_binary" "$REPO_ROOT/examples/native-surface.rs")"
    # The probes can each name the same file; report it once.
    newest_source="${newest_source%%$'\n'*}"
    if [[ -n "$newest_source" ]]; then
        echo "$(basename "$profile") binaries are older than $newest_source" >&2
        echo "Rebuild before running: cargo build --release --bins --examples" >&2
        return 1
    fi

    BUILT_IMAGE="fips-native-api-test:$$"
    log "Building $BUILT_IMAGE from $(basename "$profile") binaries"
    local context
    context="$(mktemp -d)"
    cp "$binary" "$context/fips"
    cp "$echo_binary" "$context/native-echo"
    cp "$walk_binary" "$context/native-surface"
    cat > "$context/Dockerfile" <<'DOCKERFILE'
FROM debian:trixie-slim
# libdbus-1-3 and libsystemd0 are the daemon's dynamic dependencies (BLE and
# journal integration). Without them the binary does not start, and a check
# that only looks for a socket would read that as a feature failure.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 ca-certificates libdbus-1-3 libsystemd0 && \
    rm -rf /var/lib/apt/lists/*
COPY fips /usr/local/bin/fips
# The echo check runs native-echo as one end of a two-node exchange and the
# surface walk runs native-surface against a single node, so the standalone
# image needs both exactly as the CI image does.
COPY native-echo /usr/local/bin/native-echo
COPY native-surface /usr/local/bin/native-surface
RUN chmod +x /usr/local/bin/fips /usr/local/bin/native-echo /usr/local/bin/native-surface
DOCKERFILE
    docker build -t "$BUILT_IMAGE" --label "$LABEL" "$context" --quiet >/dev/null
    local status=$?
    rm -rf "$context"
    [[ $status -ne 0 ]] && return 1
    IMAGE="$BUILT_IMAGE"
    return 0
}

# ─────────────────────────────────────────────────────────────────────
# Daemon
# ─────────────────────────────────────────────────────────────────────

# Start a node with the given config, into the given container name.
start_node() {
    local name="$1" config="$2" sockdir="$3"
    docker rm -f "$name" >/dev/null 2>&1
    docker run -d --name "$name" --label "$LABEL" \
        -v "$sockdir:/run/fips" \
        -v "$SCRIPT_DIR/$config:/etc/fips/fips.yaml:ro" \
        --entrypoint /usr/local/bin/fips \
        "$IMAGE" --config /etc/fips/fips.yaml >/dev/null
}

# Wait up to `timeout` seconds for the socket file to appear.
wait_for_socket() {
    local path="$1" timeout="${2:-20}" waited=0
    while [[ $waited -lt $timeout ]]; do
        [[ -S "$path" ]] && return 0
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

# Wait up to `timeout` seconds for a node container to report itself running.
#
# "Running" means the daemon logged its startup line, not merely that the
# container is up: a container whose process is crash-looping is still "up" for
# a moment at a time.
wait_for_running() {
    local name="$1" timeout="${2:-20}" waited=0
    while [[ $waited -lt $timeout ]]; do
        if [[ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" == "true" ]] \
            && docker logs "$name" 2>&1 | grep -q "Node started"; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

# Run a client script in its own container against the socket.
run_client() {
    docker run --rm --label "$LABEL" \
        -v "$SOCK_DIR:/run/fips" \
        -v "$SCRIPT_DIR:/harness:ro" \
        --entrypoint python3 \
        "$IMAGE" -u /harness/client.py --socket /run/fips/api.sock --script "$1"
}

# ─────────────────────────────────────────────────────────────────────
# Checks
# ─────────────────────────────────────────────────────────────────────

check_socket_appears() {
    log "The socket appears when the API is enabled"
    start_node "$NODE_NAME" node.yaml "$SOCK_DIR"
    if wait_for_socket "$SOCK_DIR/api.sock"; then
        pass "socket bound at /run/fips/api.sock"
    else
        fail "socket never appeared"
        docker logs "$NODE_NAME" 2>&1 | tail -20
        return 1
    fi
}

check_socket_mode() {
    log "The socket carries the group-access mode"
    local mode
    mode="$(stat -c '%a' "$SOCK_DIR/api.sock" 2>/dev/null)"
    if [[ "$mode" == "770" ]]; then
        pass "mode is 0770"
    else
        # A failure here means the access policy did not run, which would leave
        # the socket readable by anyone who can reach the directory.
        fail "mode is $mode, wanted 770"
    fi
}

check_commands_answered() {
    log "Every command is answered on one connection, in command order"
    # Several commands travel over a single connection, which is the property
    # that separates this socket from the control socket's one-shot shape. Both
    # setup commands carry a descriptor, so this is also where the descriptor
    # association rule bites: two descriptor-bearing replies on one connection
    # is the shape that would let a reader hand one reply the other's flow.
    #
    # The daemon's own re-encode of the peer is asserted rather than an echo of
    # what was sent, because that is what makes a connect reply and an arrival
    # name one peer the same way.
    local script='[
      {"command":"listen","params":{"local_port":4242},"keep_listener":"L",
       "expect":{"status":"ok","data.local_port":4242,"data.backlog":16}},
      {"command":"connect","params":{"peer":"'"$PEER"'","remote_port":4242,"local_port":5000},
       "keep_fd":"a",
       "expect":{"status":"ok","data.local_port":5000,"data.remote_port":4242,
                 "data.peer":"'"$PEER"'"}},
      {"command":"teleport","expect":{"status":"error","data.errno":"EINVAL"}}
    ]'
    if run_client "$script"; then
        pass "both setup commands and a refusal answered over one connection"
    else
        fail "a command was not answered as expected"
    fi
}

check_ephemeral_allocation() {
    log "Port 0 and an absent port both ask for an ephemeral one"
    # One rule covers both commands, and a listener that asked for 0 has nowhere
    # but the reply to learn the port it got, which is getsockname after bind(2)
    # with port 0.
    #
    # The three ports asserted are the first three the node ever hands out: the
    # allocator is a cursor on the node that only moves forward, so this check
    # has to run before anything else that asks for an ephemeral port.
    local script='[
      {"command":"connect","params":{"peer":"'"$PEER"'","remote_port":4242},
       "keep_fd":"a","expect":{"status":"ok","data.local_port":49152}},
      {"command":"connect","params":{"peer":"'"$PEER"'","remote_port":4242,"local_port":0},
       "keep_fd":"b","expect":{"status":"ok","data.local_port":49153}},
      {"command":"listen","params":{"local_port":0},"keep_listener":"L",
       "expect":{"status":"ok","data.local_port":49154}}
    ]'
    if run_client "$script"; then
        pass "connect and listen both allocate from the ephemeral range"
    else
        fail "ephemeral allocation did not answer as expected"
    fi
}

check_reserved_ports_refused() {
    log "Reserved port tiers are refused"
    # Port 256 is the IPv6 shim. A client that could bind it, or name it on a
    # peer, would be injecting into an IPv6 plane it does not own.
    #
    # The errno is asserted, not merely the refusal: it is the contract a
    # binding turns into what bind(2) returns, and EADDRNOTAVAIL rather than
    # EACCES because no client, however privileged, may hold port 256.
    local script='[
      {"command":"listen","params":{"local_port":256},
       "expect":{"status":"error","data.errno":"EADDRNOTAVAIL"}},
      {"command":"listen","params":{"local_port":80},
       "expect":{"status":"error","data.errno":"EADDRNOTAVAIL"}},
      {"command":"listen","params":{"local_port":1023},
       "expect":{"status":"error","data.errno":"EADDRNOTAVAIL"}},
      {"command":"connect","params":{"peer":"'"$PEER"'","remote_port":256},
       "expect":{"status":"error","data.errno":"EADDRNOTAVAIL"}},
      {"command":"listen","params":{"local_port":1024},"keep_listener":"L",
       "expect":{"status":"ok"}}
    ]'
    if run_client "$script"; then
        pass "the reserved tiers are refused as EADDRNOTAVAIL and 1024 is not"
    else
        fail "port tier policy did not hold"
    fi
}

check_bad_input_survives() {
    log "A bad command does not end the connection"
    # The healthy path after each refusal is the point: a client that mistypes
    # one command must not lose the flows its connection holds.
    local script='[
      {"command":"teleport","expect":{"status":"error","data.errno":"EINVAL"}},
      {"command":"listen","expect":{"status":"error","data.errno":"EINVAL"}},
      {"command":"listen","params":{"local_port":4242},"keep_listener":"L",
       "expect":{"status":"ok"}}
    ]'
    if run_client "$script"; then
        pass "the connection survives an unknown command and missing params"
    else
        fail "the connection did not survive a bad command"
    fi
}

check_descriptor_carries_datagrams() {
    log "A descriptor arrives with the reply and carries datagrams to the daemon"
    # Three writes must reach the daemon as three datagrams. The byte count
    # matters as much as the datagram count: a boundary loss would show up as
    # one datagram of nine bytes rather than three of three.
    local script='[
      {"command":"connect","params":{"peer":"'"$PEER"'","remote_port":4242},
       "keep_fd":"a","keep_flow":"a","expect":{"status":"ok"}},
      {"fd":"a","write":"00ff10","repeat":3},
      {"command":"stats","params":{"flow_id":"@a"},
       "expect":{"status":"ok","data.rx_datagrams":3,"data.rx_bytes":9,"data.closed":false}}
    ]'
    if run_client "$script"; then
        pass "three datagrams crossed the descriptor and the daemon counted them"
    else
        fail "the daemon did not observe what the client wrote"
    fi
}

check_receive_direction() {
    log "The daemon can write datagrams the client receives whole"
    # 00ff10 includes a byte that is not valid UTF-8, so this also shows the
    # path carries arbitrary bytes rather than text.
    local script='[
      {"command":"connect","params":{"peer":"'"$PEER"'","remote_port":4242},
       "keep_fd":"a","keep_flow":"a","expect":{"status":"ok"}},
      {"fd":"a","readable":false},
      {"command":"inject","params":{"flow_id":"@a","data":"00ff10","repeat":3},
       "expect":{"status":"ok","data.datagrams":3,"data.bytes":9}},
      {"fd":"a","readable":true},
      {"fd":"a","read":3,"expect_bytes":"00ff10","sizes":[3,3,3]}
    ]'
    if run_client "$script"; then
        pass "poll reported readability and three datagrams arrived whole"
    else
        fail "the receive direction did not behave"
    fi
}

check_close_reaches_the_daemon() {
    log "Closing the descriptor releases the flow at the daemon"
    # Without this the daemon would hold a flow for a client that is gone, which
    # is the leak the whole close path exists to prevent. There is no close
    # command and never was: closing the descriptor is the signal.
    #
    # The node forgets a released flow, so `stats` answers for it the way it
    # answers for any name it does not hold. The step before the close is what
    # makes that discriminating: the same flow answered a moment earlier, so the
    # refusal afterwards can only be the release. The sleep is the task hop
    # between the daemon reading end of file and giving the entry back.
    local script='[
      {"command":"connect","params":{"peer":"'"$PEER"'","remote_port":4242},
       "keep_fd":"a","keep_flow":"a","expect":{"status":"ok"}},
      {"fd":"a","write":"aa"},
      {"command":"stats","params":{"flow_id":"@a"},
       "expect":{"status":"ok","data.closed":false,"data.rx_datagrams":1}},
      {"fd":"a","close":true},
      {"sleep":1},
      {"command":"stats","params":{"flow_id":"@a"},"expect":{"status":"error"}}
    ]'
    if run_client "$script"; then
        pass "the daemon saw the close and gave the flow back"
    else
        fail "the daemon did not release the closed flow"
    fi
}

check_flows_are_independent() {
    log "Two flows on one connection stay separate"
    local script='[
      {"command":"connect","params":{"peer":"'"$PEER"'","remote_port":4242},
       "keep_fd":"a","keep_flow":"a","expect":{"status":"ok"}},
      {"command":"connect","params":{"peer":"'"$PEER2"'","remote_port":4243},
       "keep_fd":"b","keep_flow":"b","expect":{"status":"ok"}},
      {"fd":"a","write":"11","repeat":2},
      {"command":"stats","params":{"flow_id":"@a"},"expect":{"data.rx_datagrams":2}},
      {"command":"stats","params":{"flow_id":"@b"},"expect":{"data.rx_datagrams":0}},
      {"command":"inject","params":{"flow_id":"@b","data":"22"},"expect":{"status":"ok"}},
      {"fd":"b","read":1,"expect_bytes":"22"},
      {"fd":"a","readable":false}
    ]'
    if run_client "$script"; then
        pass "each flow saw only its own traffic"
    else
        fail "traffic crossed between flows"
    fi
}

check_unknown_flow_refused() {
    log "A flow no node holds, and bad hex, are refused"
    # The debug commands are addressed node-wide rather than per connection,
    # because a flow belongs to the node and not to the connection that opened
    # it. So the refusal here is about a flow that does not exist, not about
    # ownership: any process that can open this socket can name any flow on the
    # node, which is why both commands are behind a gate that is off by default.
    local script='[
      {"command":"stats","params":{"flow_id":99},"expect":{"status":"error"}},
      {"command":"inject","params":{"flow_id":99,"data":"00"},"expect":{"status":"error"}},
      {"command":"inject","params":{"flow_id":1,"data":"zz"},"expect":{"status":"error"}}
    ]'
    if run_client "$script"; then
        pass "an absent flow and bad hex are refused"
    else
        fail "an absent flow or bad hex was accepted"
    fi
}

# A valid npub the checks use as a peer. Nothing is ever sent to it: the wire is
# not connected, and the arrival command only names it.

check_port_ownership() {
    log "A local port has one owner, and the descriptor is what holds it"
    # The registry lives on the node, so one port has one owner whichever client
    # asked. What releases it changed: the port is held by the listener's
    # descriptor, not by the connection, so closing that descriptor is the
    # unbind and closing the connection is not.
    local first='[
      {"command":"listen","params":{"local_port":4300},"keep_listener":"L",
       "expect":{"status":"ok"}},
      {"command":"listen","params":{"local_port":4300},
       "expect":{"status":"error","data.errno":"EADDRINUSE"}},
      {"command":"connect","params":{"peer":"'"$PEER"'","remote_port":9000,"local_port":4300},
       "expect":{"status":"error","data.errno":"EADDRINUSE"}},
      {"fd":"L","close":true},
      {"sleep":1},
      {"command":"listen","params":{"local_port":4300},"keep_listener":"M",
       "expect":{"status":"ok"}}
    ]'
    if run_client "$first"; then
        pass "a held port is refused twice, and closing the listener unbinds it"
    else
        fail "a port was handed out twice, or a closed listener kept it"
        return
    fi

    # That client's process is gone, so the kernel closed the descriptor it
    # still held and the same unbind path ran without its cooperation.
    local second='[
      {"command":"listen","params":{"local_port":4300},"keep_listener":"L",
       "expect":{"status":"ok"}}
    ]'
    if run_client "$second"; then
        pass "the port came back when its client exited"
    else
        fail "a client that exited left its port held"
    fi
}

check_listen_accept_deliver() {
    log "An arrival reaches the listener descriptor with its flow and what it held"
    # The arrival command drives the same dispatch the FSP receive path does, so
    # this exercises the rule before the wire is involved.
    #
    # Three things are asserted that the accept command used to answer for. The
    # arrival names the peer by npub, which is the address its session
    # authenticated and not a hash of it. It carries this node's own npub, so an
    # accepted flow can answer getsockname without consulting its listener. And
    # the datagram the node held before any descriptor existed is already on the
    # flow's descriptor when the client reads the arrival, which is the ordering
    # the hand-off guarantees: losing it drops a peer'"'"'s opening message.
    local script='[
      {"command":"listen","params":{"local_port":4301},"keep_listener":"L",
       "expect":{"status":"ok","data.local_port":4301}},
      {"command":"arrive","params":{"peer":"'"$PEER"'","src_port":5000,"dst_port":4301,"data":"00ff10"},
       "expect":{"status":"ok","data.outcome":"announced"}},
      {"accept":"L","keep_fd":"a","keep_flow":"a",
       "expect":{"local_port":4301,"remote_port":5000,"peer":"'"$PEER"'","held":1,
                 "max_payload":1362}},
      {"fd":"a","read":1,"expect_bytes":"00ff10"},
      {"command":"arrive","params":{"peer":"'"$PEER"'","src_port":5000,"dst_port":4301,"data":"aabb"},
       "expect":{"status":"ok","data.outcome":"delivered"}},
      {"fd":"a","read":1,"expect_bytes":"aabb"}
    ]'
    if run_client "$script"; then
        pass "the held datagram and the next one both reached the client"
    else
        fail "the listen and accept path did not deliver"
    fi
}

check_listener_is_pollable() {
    log "A listener descriptor is pollable, and reports a waiting arrival"
    # The point of the listener being a descriptor rather than a registration:
    # it joins a client'"'"'s existing poll, select or epoll loop with no new
    # mechanism, and accept is a recvmsg on it. Nothing else here proves that —
    # every other listener check discovers an arrival by blocking in accept,
    # which a registration could have offered too.
    #
    # The not-readable step before the arrival is what makes the readable one
    # mean something: without it, a descriptor that was readable from the moment
    # it was created would satisfy the check.
    local script='[
      {"command":"listen","params":{"local_port":4305},"keep_listener":"L",
       "expect":{"status":"ok"}},
      {"fd":"L","readable":false},
      {"command":"arrive","params":{"peer":"'"$PEER"'","src_port":5100,"dst_port":4305,"data":"aa"},
       "expect":{"status":"ok","data.outcome":"announced"}},
      {"fd":"L","readable":true},
      {"accept":"L","keep_fd":"a","expect":{"local_port":4305,"remote_port":5100}},
      {"fd":"L","readable":false},
      {"fd":"a","read":1,"expect_bytes":"aa"}
    ]'
    if run_client "$script"; then
        pass "poll reported the listener unreadable, then readable, then unreadable"
    else
        fail "the listener descriptor did not report readability"
    fi
}

check_dispatch_order() {
    log "Dispatch prefers an established flow, then a listener, then a drop"
    # The flow key is the peer and both ports, so the second arrival on one key
    # must reach the flow that key already names rather than announce a second
    # time; a third arrival differing only in source port is a different key and
    # must announce. The listener being unreadable in between is what says the
    # established flow won: without it, a daemon that announced everything would
    # satisfy every other step here.
    local script='[
      {"command":"arrive","params":{"peer":"'"$PEER"'","src_port":5000,"dst_port":4302,"data":"aa"},
       "expect":{"status":"ok","data.outcome":"dropped: no listener or flow on that port"}},
      {"command":"listen","params":{"local_port":4302},"keep_listener":"L",
       "expect":{"status":"ok"}},
      {"command":"arrive","params":{"peer":"'"$PEER"'","src_port":5000,"dst_port":4302,"data":"aa"},
       "expect":{"status":"ok","data.outcome":"announced"}},
      {"accept":"L","keep_fd":"a","expect":{"local_port":4302,"remote_port":5000}},
      {"fd":"a","read":1,"expect_bytes":"aa"},
      {"command":"arrive","params":{"peer":"'"$PEER"'","src_port":5000,"dst_port":4302,"data":"bb"},
       "expect":{"status":"ok","data.outcome":"delivered"}},
      {"fd":"a","read":1,"expect_bytes":"bb"},
      {"fd":"L","readable":false},
      {"command":"arrive","params":{"peer":"'"$PEER"'","src_port":5001,"dst_port":4302,"data":"cc"},
       "expect":{"status":"ok","data.outcome":"announced"}},
      {"accept":"L","keep_fd":"b","expect":{"local_port":4302,"remote_port":5001}},
      {"fd":"b","read":1,"expect_bytes":"cc"}
    ]'
    if run_client "$script"; then
        pass "an unheld port drops, a listener announces, then its flow receives"
    else
        fail "the dispatch order did not hold"
    fi
}

check_backlog_is_not_the_clients_bound() {
    log "A listener that never accepts is not bounded at its backlog"
    # This is what the backlog stopped meaning. It bounds flows the rx_loop has
    # announced and the daemon has not yet wired, and the daemon drains that
    # queue itself: a pending entry gives up its backlog claim as soon as the
    # listener task promotes it, which happens whether or not the client ever
    # calls recvmsg. So a client that binds a listener and reads nothing does
    # not stop at 16.
    #
    # What does bound it after that is the listener'"'"'s send buffer and the
    # node-wide max_flows, neither of which is a number a shell check can
    # produce deterministically; the drop paths for both are covered by the
    # daemon'"'"'s own tests. What is asserted here is the change: twenty
    # arrivals at an unread listener, on a backlog of sixteen, and every one
    # announced.
    #
    # The flow key is (peer, remote port, local port), so varying the source
    # port makes each arrival a separate flow without needing distinct npubs.
    local steps='[{"command":"listen","params":{"local_port":4303},"keep_listener":"L","expect":{"status":"ok"}}'
    local port
    for port in $(seq 6000 6019); do
        steps="$steps,{\"command\":\"arrive\",\"params\":{\"peer\":\"$PEER\",\"src_port\":$port,\"dst_port\":4303,\"data\":\"aa\"},\"expect\":{\"data.outcome\":\"announced\"}}"
    done
    steps="$steps]"

    if run_client "$steps" >/dev/null; then
        pass "20 arrivals announced at a listener that read none of them"
    else
        fail "an unread listener refused an arrival before its send buffer filled"
        run_client "$steps" 2>&1 | grep -A 3 FAILED | head -8
    fi
}

check_refusing_a_flow_frees_it() {
    log "Refusing an accepted flow is closing its descriptor, and that frees it"
    # There is no reject command: Berkeley has exactly one way to refuse a
    # connection and so does this. Keeping a second would let a client refuse a
    # flow two indistinguishable ways.
    #
    # Two things have to follow the close, and the second is what makes this
    # more than a repeat of the connected-flow close: the node forgets the flow,
    # and the registry entry and its key go with it, so the very same key
    # announces a new flow afterwards rather than delivering into the dead one.
    local script='[
      {"command":"listen","params":{"local_port":4304},"keep_listener":"L",
       "expect":{"status":"ok"}},
      {"command":"arrive","params":{"peer":"'"$PEER"'","src_port":5000,"dst_port":4304,"data":"aa"},
       "expect":{"status":"ok","data.outcome":"announced"}},
      {"accept":"L","keep_fd":"a","keep_flow":"a","expect":{"local_port":4304}},
      {"command":"stats","params":{"flow_id":"@a"},"expect":{"status":"ok"}},
      {"fd":"a","close":true},
      {"sleep":1},
      {"command":"stats","params":{"flow_id":"@a"},"expect":{"status":"error"}},
      {"command":"arrive","params":{"peer":"'"$PEER"'","src_port":5000,"dst_port":4304,"data":"bb"},
       "expect":{"status":"ok","data.outcome":"announced"}},
      {"accept":"L","keep_fd":"b","expect":{"local_port":4304,"remote_port":5000}},
      {"fd":"b","read":1,"expect_bytes":"bb"}
    ]'
    if run_client "$script"; then
        pass "a refused flow is gone and its key is free to arrive again"
    else
        fail "closing a refused flow did not release it"
    fi
}

# The refusal a gated debug command earns, one per command name.
gate_refusal() {
    printf "'%s' is a debug command and is disabled; set node.native_api.debug_commands to enable it" "$1"
}

check_debug_commands_gated() {
    log "The debug commands are refused where the gate is closed"
    local gated_dir
    gated_dir="$(mktemp -d)"
    start_node "$GATED_NAME" node-debug-off.yaml "$gated_dir"
    if ! wait_for_socket "$gated_dir/api.sock"; then
        fail "the gated node never bound its socket, so nothing here proves anything"
        docker logs "$GATED_NAME" 2>&1 | tail -20
        docker rm -f "$GATED_NAME" >/dev/null 2>&1
        rm -rf "$gated_dir"
        return 1
    fi

    # Every command below names a flow and a port this connection really holds,
    # opened one step earlier. That is what makes the refusals discriminating:
    # ungated, all three succeed, so an error here can only have come from the
    # gate. The message is asserted whole for the same reason — a refusal that
    # said "no such flow" would otherwise pass as a refusal.
    local gated_script
    gated_script="$(cat <<JSON
[
  {"command":"connect","params":{"peer":"$PEER","remote_port":4242,"local_port":5000},
   "keep_fd":"a","keep_flow":"a","expect":{"status":"ok"}},
  {"command":"inject","params":{"flow_id":"@a","data":"00ff10"},
   "expect":{"status":"error","message":"$(gate_refusal inject)"}},
  {"command":"stats","params":{"flow_id":"@a"},
   "expect":{"status":"error","message":"$(gate_refusal stats)"}},
  {"command":"arrive","params":{"peer":"$PEER","src_port":4242,"dst_port":5000,"data":"00"},
   "expect":{"status":"error","message":"$(gate_refusal arrive)"}},
  {"command":"listen","params":{"local_port":4243},"keep_listener":"L","expect":{"status":"ok"}}
]
JSON
)"
    if run_client_at "$gated_dir" 10 "$gated_script"; then
        pass "all three are refused by name, and the connection survives"
    else
        fail "a debug command was not refused as the gate says it should be"
        docker logs "$GATED_NAME" 2>&1 | tail -20
    fi

    docker rm -f "$GATED_NAME" >/dev/null 2>&1
    rm -rf "$gated_dir"

    # The other half of the guard: the same three commands, same shape, against
    # the node that has the key on. A gate that refused a legitimate run would
    # be no use, and nothing above would notice.
    local open_script
    open_script="$(cat <<JSON
[
  {"command":"connect","params":{"peer":"$PEER","remote_port":4242,"local_port":5000},
   "keep_fd":"a","keep_flow":"a","expect":{"status":"ok"}},
  {"command":"inject","params":{"flow_id":"@a","data":"00ff10"},"expect":{"status":"ok"}},
  {"command":"stats","params":{"flow_id":"@a"},"expect":{"status":"ok"}},
  {"command":"arrive","params":{"peer":"$PEER","src_port":4242,"dst_port":5000,"data":"00"},
   "expect":{"status":"ok","data.outcome":"delivered"}}
]
JSON
)"
    if run_client "$open_script"; then
        pass "the same three are answered where the key is on"
    else
        fail "the gate refused a run the key should have allowed"
    fi
}

# Every public item of fips::native::client, asserted against the live daemon.
#
# The other checks here drive the daemon through client.py, which speaks the
# line protocol by hand. That covers the wire and covers nothing of the Rust
# surface a caller actually links against: until this check, five public entry
# points (FipsStream::connect, connect_from, connect_at, FipsListener::bind and
# bind_at) had no coverage of any kind, and the rest were exercised only against
# the unit tests' hand-written stand-in daemon. A stand-in kinder than the real
# thing has already hidden a defect once, so the walk runs against the daemon.
#
# It runs last among the single-node checks. check_ephemeral_allocation asserts
# 49152, 49153 and 49154 as the first three ports this node ever hands out and
# the allocator is a forward-only cursor, so the walk goes after it and asserts
# only that its own ephemeral ports are >= 49152. Its named ports come from the
# otherwise unused 4800-4809 band.
check_surface_walk() {
    log "The client's whole public surface holds against a live daemon"

    local walk_log status=0
    walk_log="$(mktemp)"
    run_surface_at "$SOCK_DIR" "$SURFACE" walk /run/fips/api.sock "$PEER" \
        >"$walk_log" 2>&1 || status=$?

    if [[ $status -eq 124 ]]; then
        # The bound had to end it. The binary's own watchdog fires at 30s and
        # names the assertion it was in, so reaching this means the walk never
        # got far enough to arm it.
        fail "the surface walk did not finish inside its 60s bound, and its own watchdog never reported"
        tail -5 "$walk_log"
        rm -f "$walk_log"
        return 1
    fi
    if [[ $status -eq 125 ]]; then
        # The container did not start, or its exit code could not be read.
        # Nothing was observed, so nothing may be reported about the surface.
        fail "the surface walk did not run, so it says nothing about the surface"
        tail -5 "$walk_log"
        rm -f "$walk_log"
        return 1
    fi
    if [[ $status -ne 0 ]]; then
        # The binary prints one line naming the assertion that failed, or the
        # one the watchdog found in flight. Show it rather than the verdict
        # alone: the assertion name is the whole diagnostic.
        fail "the surface walk reported a failed assertion"
        tail -5 "$walk_log"
        rm -f "$walk_log"
        return 1
    fi

    # Three separate claims, not one. The exit status above says the binary
    # reported no failure; the completion line says it reached its own end
    # rather than exiting 0 from somewhere else; the count says every assertion
    # block ran. Only the count catches a block that stopped running, since a
    # #[cfg] gate that no longer matches or an early return still exits 0 and
    # still prints the line.
    local counted
    counted="$(sed -n 's/^native-surface: walk complete, \([0-9][0-9]*\) assertions passed$/\1/p' \
        "$walk_log")"
    if [[ -z "$counted" ]]; then
        fail "the surface walk exited 0 without printing its completion line"
        tail -5 "$walk_log"
    elif [[ "$counted" -ne "$SURFACE_ASSERTIONS" ]]; then
        fail "the surface walk passed $counted assertions, wanted $SURFACE_ASSERTIONS"
        tail -5 "$walk_log"
    else
        pass "all $SURFACE_ASSERTIONS assertions of the client surface hold against the daemon"
    fi
    rm -f "$walk_log"
}

# ─────────────────────────────────────────────────────────────────────
# Two nodes: the wire itself
# ─────────────────────────────────────────────────────────────────────

MESH="native-api-$$"
NET="fips-native-api-net-$$"
NODE_A="fips-native-a-$$"
NODE_B="fips-native-b-$$"
ECHO="fips-native-echo-$$"
DIR_A=""
DIR_B=""

# Write a node config peering with the other node.
#
# No debug_commands: the wire checks below drive real traffic between two nodes
# and need none of the three, which is the shape a packaged node runs in.
write_node_config() {
    local dir="$1" nsec="$2" peer_npub="$3" peer_host="$4"
    cat > "$dir/fips.yaml" <<YAML
node:
  identity:
    nsec: "$nsec"
  native_api:
    enabled: true
    socket_path: "/run/fips/api.sock"

tun:
  enabled: false

dns:
  enabled: false

transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    mtu: 1472

peers:
  - npub: "$peer_npub"
    alias: "$peer_host"
    addresses:
      - transport: udp
        addr: "$peer_host:2121"
YAML
}

# Wait up to `timeout` seconds for the two nodes to have a working link.
#
# Without this the clients race the handshake: connect still succeeds, the
# datagram is held in the native pending queue, and whether it arrives inside
# the listener's timeout depends on how long peering took. The first run of this
# check failed that way and passed on a rerun, which is the signature of a race
# rather than of a defect in what is being tested.
#
# The marker is the spanning tree forming, not a peer-promotion line: on this
# path — a configured peer, dialled outbound — the promotion message is never
# emitted, which cost a round of guessing. Exactly one of the two nodes adopts
# the other as its parent, so the check accepts the marker on either.
wait_for_link() {
    local timeout="${1:-45}" waited=0
    while [[ $waited -lt $timeout ]]; do
        if docker logs "$NODE_A" 2>&1 | grep -q "Parent switched" \
            || docker logs "$NODE_B" 2>&1 | grep -q "Parent switched"; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

# Wait up to `timeout` seconds for a client's log to report a step done.
#
# A client container having been launched is not the same as its step having
# taken effect, and the two ends here race each other: the sender's datagram
# would reach a port nothing held yet if it won. The client prints one line per
# completed step, so the log is the synchronisation point.
wait_for_step() {
    local log="$1" marker="$2" timeout="${3:-30}" waited=0
    while [[ $waited -lt $timeout ]]; do
        grep -qF "$marker" "$log" && return 0
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

# Run a client script against one node's socket directory.
run_client_at() {
    local sockdir="$1" timeout="$2" script="$3"
    docker run --rm --label "$LABEL" \
        -v "$sockdir:/run/fips" \
        -v "$SCRIPT_DIR:/harness:ro" \
        --entrypoint python3 \
        "$IMAGE" -u /harness/client.py --socket /run/fips/api.sock \
        --timeout "$timeout" --script "$script"
}

# Run the native-echo example against one node's socket, in its own container.
#
# The same container shape as the python client: the socket directory bind
# mounted, nothing else. The example is a compiled entrypoint rather than a
# script, so no harness mount is needed. It is named because it never exits on
# its own and the caller has to remove it.
run_echo_at() {
    local sockdir="$1" name="$2" port="$3"
    docker run --rm --name "$name" --label "$LABEL" \
        -v "$sockdir:/run/fips" \
        --entrypoint /usr/local/bin/native-echo \
        "$IMAGE" /run/fips/api.sock "$port"
}

# Run the native-surface example against one node's socket, in its own
# container, under a wall-clock bound. Prints what the container printed and
# returns its exit code, or 124 when the bound had to end it.
#
# The same container shape as native-echo: the socket directory bind mounted,
# nothing else. The bound is a backstop rather than the expected wait. The
# binary arms its own 30-second watchdog, which is what turns a blocked recv or
# accept into a red that names the assertion in flight; this catches only what
# the watchdog cannot reach, an image that never starts or a process that wedged
# before the thread was armed. Without a bound a wedged container never returns,
# the run never reaches its summary line, and in CI the step's own 15-minute
# timeout kills it with nothing said.
#
# `timeout 60 docker run` is NOT that bound, which a break-check measured rather
# than a reading of the manual: `timeout` sends SIGTERM to the docker client,
# the client proxies it to the container, and the walk is PID 1 there with no
# handler for it, so the kernel discards it. The container was still up five
# minutes after the bound passed and `docker run` never returned. Polling the
# container's own state and then removing it by force is what actually ends it,
# since `docker rm -f` is a SIGKILL and PID 1 cannot discard that.
#
# Detached rather than attached for the same reason: there is no client process
# left holding the run, so nothing to kill and nothing to wait on but the
# container itself. That also means `--rm` cannot be used — it would race the
# inspect that reads the exit code out — so the container is named and removed
# here on every path.
run_surface_at() {
    local sockdir="$1" name="$2"
    shift 2
    docker rm -f "$name" >/dev/null 2>&1
    if ! docker run -d --name "$name" --label "$LABEL" \
        -v "$sockdir:/run/fips" \
        --entrypoint /usr/local/bin/native-surface \
        "$IMAGE" "$@" >/dev/null; then
        echo "the surface container did not start"
        return 125
    fi

    local waited=0
    while [[ $waited -lt 60 ]]; do
        [[ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" != "true" ]] && break
        sleep 1
        waited=$((waited + 1))
    done

    local status
    if [[ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" == "true" ]]; then
        status=124
    else
        status="$(docker inspect -f '{{.State.ExitCode}}' "$name" 2>/dev/null)"
    fi
    docker logs "$name" 2>&1
    docker rm -f "$name" >/dev/null 2>&1

    # An inspect that could not read the container has observed nothing, and
    # must not be reported as the walk having succeeded.
    [[ "$status" =~ ^[0-9]+$ ]] || status=125
    return "$status"
}

# Query one node's control socket, printing the reply and failing when an
# expectation does not hold.
#
# This needs nothing added to the image. The control socket is enabled by
# default, its default path resolves to the same bind-mounted /run/fips the
# native API socket lands in, and the client image already carries python3, so
# the same container shape that reaches api.sock reaches control.sock.
query_control() {
    local sockdir="$1" command="$2"
    shift 2
    local expects=() expectation
    for expectation in "$@"; do
        expects+=(--expect "$expectation")
    done
    docker run --rm --label "$LABEL" \
        -v "$sockdir:/run/fips" \
        -v "$SCRIPT_DIR:/harness:ro" \
        --entrypoint python3 \
        "$IMAGE" -u /harness/control.py --socket /run/fips/control.sock \
        --command "$command" ${expects[@]+"${expects[@]}"}
}

# Poll one show_native_flows expectation until it holds or `timeout` passes.
#
# Everything asserted here is downstream of a datagram crossing the wire, so a
# single immediate query would be asserting against a state the node has not
# reached yet and would fail for timing rather than for substance.
wait_control() {
    local sockdir="$1" timeout="$2" expectation="$3" waited=0
    while [[ $waited -lt $timeout ]]; do
        query_control "$sockdir" show_native_flows "$expectation" >/dev/null 2>&1 && return 0
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

teardown_two_nodes() {
    docker rm -f "$ECHO" >/dev/null 2>&1
    docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
    [[ -n "$DIR_A" ]] && rm -rf "$DIR_A"
    [[ -n "$DIR_B" ]] && rm -rf "$DIR_B"
    return 0
}

check_end_to_end() {
    log "A datagram travels from one node's client to the other's"

    local keys_a keys_b nsec_a npub_a nsec_b npub_b
    keys_a="$(python3 "$REPO_ROOT/testing/lib/derive_keys.py" "$MESH" node-a)"
    keys_b="$(python3 "$REPO_ROOT/testing/lib/derive_keys.py" "$MESH" node-b)"
    nsec_a="$(sed -n 's/^nsec=//p' <<<"$keys_a")"
    npub_a="$(sed -n 's/^npub=//p' <<<"$keys_a")"
    nsec_b="$(sed -n 's/^nsec=//p' <<<"$keys_b")"
    npub_b="$(sed -n 's/^npub=//p' <<<"$keys_b")"
    if [[ -z "$nsec_a" || -z "$npub_b" ]]; then
        fail "could not derive node keys"
        return 1
    fi

    DIR_A="$(mktemp -d)"
    DIR_B="$(mktemp -d)"
    local cfg_a cfg_b
    cfg_a="$(mktemp -d)"
    cfg_b="$(mktemp -d)"
    write_node_config "$cfg_a" "$nsec_a" "$npub_b" "$NODE_B"
    write_node_config "$cfg_b" "$nsec_b" "$npub_a" "$NODE_A"

    docker network create --label "$LABEL" "$NET" >/dev/null 2>&1
    local name
    for name in "$NODE_A:$cfg_a:$DIR_A" "$NODE_B:$cfg_b:$DIR_B"; do
        local container="${name%%:*}" rest="${name#*:}"
        docker run -d --name "$container" --hostname "$container" \
            --label "$LABEL" --network "$NET" \
            -v "${rest%%:*}/fips.yaml:/etc/fips/fips.yaml:ro" \
            -v "${rest#*:}:/run/fips" \
            --entrypoint /usr/local/bin/fips \
            "$IMAGE" --config /etc/fips/fips.yaml >/dev/null
    done
    rm -rf "$cfg_a" "$cfg_b"

    if ! wait_for_running "$NODE_A" 20 || ! wait_for_running "$NODE_B" 20; then
        fail "the two nodes did not both start"
        docker logs "$NODE_A" 2>&1 | tail -10
        teardown_two_nodes
        return 1
    fi
    if ! wait_for_socket "$DIR_A/api.sock" 20 || ! wait_for_socket "$DIR_B/api.sock" 20; then
        fail "a native API socket did not appear"
        teardown_two_nodes
        return 1
    fi
    if ! wait_for_link 45; then
        fail "the two nodes did not form a link"
        docker logs "$NODE_A" 2>&1 | tail -10
        teardown_two_nodes
        return 1
    fi

    # B listens and waits. Its client blocks on the arrival, so it is started
    # first and in the background; A's send is what unblocks it.
    #
    # The payload is deliberately not a valid IPv6 packet. If a native datagram
    # were ever routed through the TUN pending queue it would be handed to the
    # IPv6 compressor, which would refuse it, and this check would fail — which
    # is the point: the trap is asserted rather than trusted.
    #
    # The arrival'"'"'s peer is asserted to be the sending node'"'"'s npub. That is the
    # whole point of the redesign at this end: the peer'"'"'s key is captured where
    # its session authenticated it, so an accepted flow reports a real address in
    # the same representation a connected one does, rather than a hash of it.
    local listener='[
      {"command":"listen","params":{"local_port":4400},"keep_listener":"L",
       "expect":{"status":"ok"}},
      {"accept":"L","keep_fd":"a",
       "expect":{"local_port":4400,"remote_port":4401,"peer":"'"$npub_a"'"}},
      {"fd":"a","read":1,"expect_bytes":"0011223344"}
    ]'
    local listener_log
    listener_log="$(mktemp)"
    run_client_at "$DIR_B" 90 "$listener" >"$listener_log" 2>&1 &
    local listener_pid=$!

    # Wait until the listener has actually bound its port. Launching it first is
    # not the same as it having registered: both clients start their own
    # container, and if the sender won that race its datagram would arrive at a
    # port nothing held and be dropped, with no listener left to tell.
    if ! wait_for_step "$listener_log" "step 0 (listen) ok" 30; then
        fail "the listener never bound its port"
        cat "$listener_log" | tail -5
        kill "$listener_pid" 2>/dev/null
        teardown_two_nodes
        return 1
    fi

    # A sends before any session exists, so the datagram is held in the native
    # pending queue and flushed when the session establishes.
    local sender='[
      {"command":"connect","params":{"peer":"'"$npub_b"'","remote_port":4400,"local_port":4401},
       "keep_fd":"a","expect":{"status":"ok","data.max_payload":1362}},
      {"fd":"a","write":"0011223344"},
      {"fd":"a","readable":false}
    ]'
    if run_client_at "$DIR_A" 30 "$sender" >/dev/null 2>&1; then
        pass "the sender opened a flow and reported the real payload limit"
    else
        fail "the sender could not open a flow"
        run_client_at "$DIR_A" 30 "$sender" 2>&1 | tail -5
    fi

    if wait "$listener_pid"; then
        pass "the datagram arrived intact on the other node"
    else
        fail "the datagram did not arrive"
        cat "$listener_log" | tail -10
        echo "--- sender node:"
        docker logs "$NODE_A" 2>&1 | grep -iE "native|session estab|pending" | tail -8
        echo "--- listener node:"
        docker logs "$NODE_B" 2>&1 | grep -iE "native|session estab|dropping" | tail -8
    fi
    rm -f "$listener_log"
    check_control_reports_the_flow "$npub_a" "$npub_b"
    check_echo_round_trip "$npub_b"
    teardown_two_nodes
}

# The example server answering a real client across the wire.
#
# This is the first check here where both ends are programs a user could have
# written: the echo server is `examples/native-echo.rs` built against
# `fips::native::client`, and the sender is the harness client speaking the line
# protocol by hand. Every other two-ended check has the daemon's own debug
# surface on one side, so nothing until now has exercised the client module
# outside its unit tests.
#
# One exchange, one flow, which is the server's model: it echoes the datagram
# and drops the flow rather than waiting for a far-end close a datagram API
# never sends.
check_echo_round_trip() {
    local npub_b="$1"
    log "A datagram sent to the example echo server comes back unchanged"

    local echo_log
    echo_log="$(mktemp)"
    run_echo_at "$DIR_B" "$ECHO" 4600 >"$echo_log" 2>&1 &
    local echo_pid=$!

    # The server having been launched is not the same as its port being held.
    # Sending first would put the datagram at a port nothing owned yet, and the
    # daemon would drop it with no server left to say so.
    if ! wait_for_step "$echo_log" "holding port 4600" 30; then
        fail "the echo server never bound its port"
        tail -5 "$echo_log"
        docker rm -f "$ECHO" >/dev/null 2>&1
        wait "$echo_pid" 2>/dev/null
        rm -f "$echo_log"
        return 1
    fi

    # Five bytes that are not a valid IPv6 packet, for the reason the
    # end-to-end check gives: anything routed through the TUN pending queue
    # would be refused by the compressor and this check would fail rather than
    # pass by a route it is not testing.
    local sender='[
      {"command":"connect","params":{"peer":"'"$npub_b"'","remote_port":4600,"local_port":4601},
       "keep_fd":"a","expect":{"status":"ok"}},
      {"fd":"a","write":"5a5b5c5d5e"},
      {"fd":"a","read":1,"expect_bytes":"5a5b5c5d5e"}
    ]'
    if run_client_at "$DIR_A" 30 "$sender" >/dev/null 2>&1; then
        pass "the echo server returned the same bytes on the same flow"
    else
        fail "the datagram did not come back from the echo server"
        run_client_at "$DIR_A" 30 "$sender" 2>&1 | tail -5
        echo "--- echo server:"
        tail -10 "$echo_log"
    fi

    docker rm -f "$ECHO" >/dev/null 2>&1
    wait "$echo_pid" 2>/dev/null
    rm -f "$echo_log"
    return 0
}

# What the daemon says about a flow that is still open, read the way an operator
# reads it: `show_native_flows` over the control socket.
#
# It runs on the two-node mesh because that is the only place a flow has a real
# peer to resolve, a real port at each end, and counters nothing but the wire can
# move. Both clients hold their *descriptors* open across the {"sleep":45} while
# the check looks, because a flow is gone from the registry the moment its last
# descriptor closes, and a query against an empty registry would agree with a
# publisher that dropped every field. The RPC connections are irrelevant to that:
# a flow outlives the connection that opened it, and closing one releases
# nothing.
check_control_reports_the_flow() {
    local npub_a="$1" npub_b="$2"
    log "The control socket reports a live flow, its peer and its counters"

    local listener='[
      {"command":"listen","params":{"local_port":4500},"keep_listener":"L",
       "expect":{"status":"ok"}},
      {"accept":"L","keep_fd":"a","expect":{"local_port":4500,"peer":"'"$npub_a"'"}},
      {"fd":"a","read":1,"expect_bytes":"a1b2c3"},
      {"sleep":45}
    ]'
    local listener_log
    listener_log="$(mktemp)"
    run_client_at "$DIR_B" 120 "$listener" >"$listener_log" 2>&1 &
    local listener_pid=$!

    if ! wait_for_step "$listener_log" "step 0 (listen) ok" 30; then
        fail "the listener never bound port 4500"
        tail -5 "$listener_log"
        kill "$listener_pid" 2>/dev/null
        rm -f "$listener_log"
        return 1
    fi

    local sender='[
      {"command":"connect","params":{"peer":"'"$npub_b"'","remote_port":4500,"local_port":4501},
       "keep_fd":"a","expect":{"status":"ok"}},
      {"fd":"a","write":"a1b2c3"},
      {"sleep":45}
    ]'
    local sender_log
    sender_log="$(mktemp)"
    run_client_at "$DIR_A" 120 "$sender" >"$sender_log" 2>&1 &
    local sender_pid=$!

    if ! wait_for_step "$sender_log" "step 1 (fd a) ok" 30; then
        fail "the sender never opened a flow on port 4501"
        tail -5 "$sender_log"
        kill "$sender_pid" "$listener_pid" 2>/dev/null
        rm -f "$sender_log" "$listener_log"
        return 1
    fi
    if ! wait_for_step "$listener_log" "step 2 (fd a) ok" 30; then
        fail "the datagram never reached the listener, so there is no live flow to report"
        tail -5 "$listener_log"
        kill "$sender_pid" "$listener_pid" 2>/dev/null
        rm -f "$sender_log" "$listener_log"
        return 1
    fi

    # `show_native_flows` renders from a snapshot the node publishes on its
    # maintenance tick, so a query fired the instant a flow opens can legitimately
    # answer from before it existed. Converge first, then assert the whole row:
    # otherwise this check would be measuring the tick interval.
    wait_control "$DIR_A" 15 "data.flows.0.local_port=4501"

    # The sending end: its own port, the far port, the peer as the npub the
    # config names it by, and the send counter moved. The npub is a field on the
    # flow now rather than something resolved when the row is rendered, and
    # `peer_addr` stays beside it because this is the operator surface and the
    # node address is what show_sessions and show_routing key on.
    if query_control "$DIR_A" show_native_flows \
        "data.flows.0.local_port=4501" \
        "data.flows.0.remote_port=4500" \
        "data.flows.0.peer=$npub_b" \
        "data.flows.0.state=established" \
        "data.stats.sent_datagrams>0" >/dev/null; then
        pass "the open flow is reported with both ports, its peer and a moved counter"
    else
        fail "the sending end's flow is not reported as opened"
        query_control "$DIR_A" show_native_flows 2>&1 | tail -3
    fi

    wait_control "$DIR_B" 15 "data.flows.0.local_port=4500"

    # The listening end: the ports are the mirror image, and the listener itself
    # is reported with an empty backlog now the flow has been accepted off it.
    if query_control "$DIR_B" show_native_flows \
        "data.flows.0.local_port=4500" \
        "data.flows.0.remote_port=4501" \
        "data.flows.0.peer=$npub_a" \
        "data.flows.0.state=established" \
        "data.listeners.0.local_port=4500" \
        "data.listeners.0.backlog=0" \
        "data.stats.received_datagrams>0" >/dev/null; then
        pass "the same flow and its listener are reported from the other side"
    else
        fail "the listening end's flow is not reported as accepted"
        query_control "$DIR_B" show_native_flows 2>&1 | tail -3
    fi

    # A datagram to a port nothing holds. The far node has neither a flow nor a
    # listener for 4599, so the registry drops it and says why. Pinning the other
    # drop counters at zero is what makes this a check about drop_no_port rather
    # than about some drop having happened.
    local probe='[
      {"command":"connect","params":{"peer":"'"$npub_b"'","remote_port":4599,"local_port":4502},
       "keep_fd":"a","expect":{"status":"ok"}},
      {"fd":"a","write":"deadbeef"}
    ]'
    if ! run_client_at "$DIR_A" 30 "$probe" >/dev/null 2>&1; then
        fail "the probe client could not send to an unheld port"
    elif ! wait_control "$DIR_B" 20 "data.stats.drop_no_port>0"; then
        fail "a datagram to an unheld port did not increment drop_no_port"
        query_control "$DIR_B" show_native_flows 2>&1 | tail -3
    elif query_control "$DIR_B" show_native_flows \
        "data.stats.drop_backlog_full=0" \
        "data.stats.drop_too_many_flows=0" \
        "data.stats.drop_pending_queue_full=0" \
        "data.stats.drop_flow_queue_full=0" \
        "data.stats.drop_arrival_queue_full=0" \
        "data.stats.drop_listener_gone=0" \
        "data.stats.drop_listener_not_reading=0" \
        "data.stats.drop_oversize=0" >/dev/null; then
        pass "an unheld port increments drop_no_port and no other drop counter"
    else
        fail "a drop counter other than drop_no_port moved"
        query_control "$DIR_B" show_native_flows 2>&1 | tail -3
    fi

    wait "$sender_pid" || { fail "the sender client did not exit cleanly"; tail -5 "$sender_log"; }
    wait "$listener_pid" || { fail "the listener client did not exit cleanly"; tail -5 "$listener_log"; }
    rm -f "$sender_log" "$listener_log"
}

check_disabled_by_default() {
    log "No socket appears when the API is not enabled"
    local off_dir
    off_dir="$(mktemp -d)"
    start_node "${NODE_NAME}-off" node-api-off.yaml "$off_dir"

    # The daemon must be proved alive before the absence of a socket means
    # anything. Without this, a daemon that fails to start at all satisfies
    # "no socket appeared" and the check passes for the wrong reason — which
    # is exactly what it did on its first run, when the image was missing a
    # shared library.
    if ! wait_for_running "${NODE_NAME}-off" 20; then
        fail "the daemon did not start, so the absence of a socket proves nothing"
        docker logs "${NODE_NAME}-off" 2>&1 | tail -20
        docker rm -f "${NODE_NAME}-off" >/dev/null 2>&1
        rm -rf "$off_dir"
        return 1
    fi

    if [[ -S "$off_dir/api.sock" ]]; then
        fail "a socket appeared with the API disabled"
    else
        pass "the daemon is up and no socket was bound"
    fi
    docker rm -f "${NODE_NAME}-off" >/dev/null 2>&1
    rm -rf "$off_dir"
}

# ─────────────────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────────────────

resolve_image || exit 1

if check_socket_appears; then
    check_socket_mode
    check_commands_answered
    check_ephemeral_allocation
    check_reserved_ports_refused
    check_bad_input_survives
    check_descriptor_carries_datagrams
    check_receive_direction
    check_close_reaches_the_daemon
    check_flows_are_independent
    check_unknown_flow_refused
    check_port_ownership
    check_listen_accept_deliver
    check_listener_is_pollable
    check_dispatch_order
    check_backlog_is_not_the_clients_bound
    check_refusing_a_flow_frees_it
    check_debug_commands_gated
    check_surface_walk
fi
check_end_to_end
check_disabled_by_default

echo ""
echo "=== native-api: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] || exit 1
