# Native Datagram API Harness

Checks for the experimental native datagram API: a client process opens a flow
to a remote pubkey over a Unix socket, receives a file descriptor, and sends and
receives datagrams on it with no IPv6 emulation and no TUN device.

Design of record: `design/native-api/v1-datagram-experiment.md` in the project
workspace, which is a separate tree from this repository. The feature is off by
default and Unix only.

## Shape

The client runs in **its own container**, reaching the daemon through a
bind-mounted `/run/fips`. That is the real deployment shape — a separate process
with its own filesystem opening the socket — rather than a test speaking to the
daemon from inside the daemon's container. It also makes the access policy
observable: the host sees the socket file and reads its mode directly.

The step scripts are Python rather than Rust so a check changes without
rebuilding the daemon, which is what keeps the outside-in loop fast. That buys
speed at the cost of covering nothing of the Rust surface a caller links
against, so two compiled programs run here as well, both built on
`fips::native::client`: `examples/native-echo.rs`, which arrived with A5 and
serves the echo check, and `examples/native-surface.rs`, which walks the whole
public surface against a live daemon.

The table covers this directory and the two example programs the driver runs.

| File | What it is |
| ---- | ---------- |
| `test.sh` | The driver. Holds the scenarios and the pass/fail accounting. |
| `client.py` | A thin RPC client. Runs a script of steps over one connection and checks the replies. |
| `control.py` | A thin control-socket client, used to read `show_native_flows` back while a flow is open. |
| `node.yaml` | One node with the API enabled, no TUN, no DNS, no peers. Turns the debug commands on. |
| `node-api-off.yaml` | The same node with the API disabled, for the default-off check. |
| `node-debug-off.yaml` | The API enabled and the debug commands left at their default, for the gate check. |
| `../../examples/native-echo.rs` | The echo server for `check_echo_round_trip`. A program shape to copy. |
| `../../examples/native-surface.rs` | The surface walk for `check_surface_walk`. An assertion harness, not a shape to copy. |

## Running

```bash
cargo build --release --bins --examples   # the driver refuses a stale binary
./testing/native-api/test.sh
```

`FIPS_TEST_IMAGE` is used when set, which is how `ci-local.sh` passes its
per-run image. There is deliberately no `fips-test:latest` to fall back on, so a
consumer that stops reading the variable fails loudly. Without it the driver
builds a minimal image from the locally compiled binary.

The driver **refuses to run against a stale binary**. Three binaries are built
or read from this tree, the daemon and the two examples, and each is probed
against what it is actually built from: `src/` plus `Cargo.toml` for all three,
this directory's `*.py` because the harness client is bind-mounted live rather
than built in, and, for an example, its own `.rs` and no other. A guard rooted
only at `src/` would let a stale example pass a check written about new code.
A stale binary is the worst outcome available here: the checks would run and
report a verdict about code that is not the working tree's.

An example is probed against its own source rather than all of `examples/`
because cargo does not relink `target/release/fips` when only an example
changes. Probing the daemon against every example would leave it permanently
older than a just-edited one, and the rebuild the refusal prescribes would not
clear the condition.

All three binaries must come from one profile directory. `resolve_image` refuses
a profile that holds only the daemon, which is what a bare
`cargo build --release` leaves behind.

## Increments

The API is built outside-in, and this harness grows with it. Each increment's
checks must pass before the next one starts.

| # | What it covers | State |
| - | -------------- | ----- |
| A1 | The socket, its access mode, the line framing, the command validation, the reserved-port refusals, and that the API is off by default | present |
| A2 | Descriptor passing over `SCM_RIGHTS`, message boundaries, `poll` readability, close reaching the daemon, flow isolation | present |
| A3 | Port ownership across clients, listening and accepting, the dispatch order, and reclaim when a descriptor closes | present |
| A4 | The end-to-end path between two nodes, and that a queued datagram is not IPv6-compressed | present |
| A5 | Counters, `show_native_flows` read back over the control socket, the Rust client module and echo example, and the debug-command gate | present |
| A6 | Every public item of `fips::native::client` walked against a live daemon: the five setup entry points, all eight `ToFipsAddr` spellings, the deadlines, non-blocking mode, the descriptor traits, and the payload limit | present |

**The `"stub": true` marker is gone.** It meant "this flow reaches no peer",
and after A4 every flow does. `max_payload` is now the real limit — the
transport MTU less the FIPS encapsulation and the port header, 1362 bytes on a
1472-byte transport — and the end-to-end check asserts that number rather than
accepting whatever is reported.

The tightening it existed for happened three times. A1's `connect` checks failed
the moment A2 began returning a descriptor, because `client.py` treats an
unannounced descriptor as a defect rather than ignoring it. A1's `accept` and
`reject` checks failed when A3 gave those commands a real registry, since a flow
no listener announced became a refusal. And the remaining `stub` assertions
failed at A4 when the field disappeared. Checks that had quietly kept passing
would have been worth nothing.

**The `accept` and `reject` commands are gone**, and so is the `incoming` event.
A listener now returns its own descriptor, so it is pollable, accepting is one
`recvmsg` on it that carries the arriving flow's descriptor, and refusing a flow
is closing that descriptor. The command socket carries replies only, in command
order. A step names a listener descriptor with `keep_listener` and takes flows
off it with an `accept` step; every descriptor a reply carries must be named, or
the run fails rather than dropping a flow silently.

**The backlog is no longer the bound a client sees.** It bounds arrivals the
daemon has announced and not yet wired, and the daemon drains that queue itself,
so a listener that never accepts is bounded by its send buffer and by
`node.native_api.max_flows` instead. `check_backlog_is_not_the_clients_bound`
asserts the change; the drop paths behind the new bound are covered by the
daemon's own tests, because neither is a number a shell check can produce.

**Flow identifiers are assigned by the node and keep counting up for its
lifetime.** A check must capture one with `keep_flow` rather than assume a
literal, or it holds only for the first flow the daemon ever made.

## The surface walk

`check_surface_walk` runs `examples/native-surface.rs` against the shared
single node, last among the single-node checks. Its subject is the Rust surface
rather than the wire: until it existed, `FipsStream::connect`, `connect_from`,
`connect_at`, `FipsListener::bind` and `bind_at` had no coverage of any kind,
and every other public item was exercised only against the hand-written stand-in
daemon in the crate's unit tests. That stand-in has already hidden a real defect
once, by being kinder than the daemon, which is why the walk talks to the real
one.

It runs last because `check_ephemeral_allocation` asserts 49152, 49153 and 49154
as the first three ports the node ever hands out and the allocator is a
forward-only cursor. The walk therefore asserts only that its own ephemeral
ports are `>= 49152`, and takes its named ports from the otherwise unused
4800-4809 band.

**The check asserts three things, not one:** that the container exited 0, that
its completion line is there, and that the count in that line equals
`SURFACE_ASSERTIONS` in `test.sh`. The third is the anti-silence measure. The
binary prints the recorder's own counter rather than a literal, so an assertion
block that stopped running — a `#[cfg]` gate that no longer matches, an early
return — still exits 0 and still prints the line, and only the count betrays it.
The number is deliberately brittle: adding an assertion must force an edit in
`test.sh`, so the two cannot drift apart quietly.

**A hang has to become a red, and has to name itself.** The walk's own subjects
fail by blocking forever: a read deadline never applied to the descriptor, a
`set_nonblocking` that did nothing. The binary arms a 30-second watchdog that
prints the assertion it was in and exits 1, and `run_surface_at` bounds the
container at 60 seconds as a backstop for a wedge before that thread is armed.

`timeout 60 docker run` is **not** that backstop, which a break-check measured
rather than a reading of the manual. `timeout` signals the docker client, the
client proxies SIGTERM to the container, and the walk is PID 1 there with no
handler for it, so the kernel discards the signal: the container was still up
five minutes after the bound passed and `docker run` never returned. The helper
runs the container detached, polls its state, and removes it by force, since
`docker rm -f` is a SIGKILL and PID 1 cannot discard that.

## The two-node check

`check_end_to_end` is the only check that runs more than one node. It derives
two identities with `testing/lib/derive_keys.py`, brings both up on their own
docker network peered by npub, and sends a datagram from a client on one to a
client on the other.

Three orderings are waited on explicitly rather than assumed, each because
assuming it produced an intermittent failure:

- **The link forms** before either client runs, watched for by the spanning tree
  adopting a parent. Not by a peer-promotion log line: on this path — a
  configured peer, dialled outbound — that line is never emitted.
- **The listener has bound its port** before the sender starts, watched for in
  the listener's own output. Launching it first is not the same as it having
  registered.
- **The client runs unbuffered** (`python3 -u`). Without it the marker above
  never reaches the log file, so the wait cannot see it and every run fails at
  the gate meant to make the check reliable.

The payload is deliberately not a valid IPv6 packet, and it is sent before any
session exists so it goes through the native pending queue. If a native datagram
were ever routed through the TUN pending queue it would be handed to the IPv6
compressor, which would refuse it, and this check would fail. The trap is
asserted rather than trusted.
