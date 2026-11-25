# src/nostr

Nostr rendezvous: overlay adverts published to relays, traversal offers and
answers carried as encrypted Nostr events, STUN for the reflexive address, UDP
hole punching, and the hand-over of a punched socket to the node as an
externally established link (`crate::node::handoff::EstablishedTraversal`),
which the node adopts as a UDP transport.

## Shell and machine

The directory is being split into a machine and a shell.

- `machine/` holds the decisions, with no I/O. It names no `std`, `tokio`,
  `tracing` or `nostr_sdk` path and nothing in the root crate outside itself;
  its README states the fence, and `testing/check-nostr-machine.py` holds it.
- Every other file here is the shell: it owns the relay client, the sockets,
  the clocks, the random draws and the logging, calls into the machine, and
  keeps the paths the rest of the crate uses by re-exporting the machine's
  names.

The shell builds every Nostr event it sends through the codecs in
`machine/event/`, passing in the time and the random bytes, and holds the
node key only in the `NodeSigner` there. The root `clippy.toml` bans the
`nostr` items that read the clock or the OS random source in all non-test
code; the test files that use them (`tests/mod.rs` and its children, and
`tests/signal_route.rs`) carry a file-level allow.

`relay.rs` is the shell's one view of the Nostr relay client: every call the
shell makes on the client (adding and connecting relays, the notification
channel, subscribing, fetching, sending, closing the connections at shutdown)
goes through its `RelayClient`, one method per call, and each caller maps the
client's error onto `BootstrapError`. Each of the machine's subscriptions is
opened under an id the pump draws once and reuses on every retry, so a relay
that already holds it is not given a second. The client answers a relay's
NIP-42 challenge through `PumpAuthenticator`, which asks the pump, so the node
key signs only in the machine.

## One task owning the machine

All of rendezvous (the peer advert cache, this node's advert and the
transports it is assembled from, the relay subscriptions and the inbox relay
list, and every traversal: the sessions, the dual-initiation election and seen
sessions, the signal gate, the offer admission and the per-peer failure state)
is owned by one task, the pump (`pump.rs`), which steps
`machine::rendezvous::Rendezvous`. The pump reads its inbox, the relay
client's notification stream, the signal router's channel (which only
traversal signals are put on, so an advert flood cannot drop one), its
sockets' datagrams and the machine's next deadline, with no preference among
them, hands each input to the machine with the step's two clock readings
(tokio's monotonic clock, so a test's paused clock moves the machine, and Unix
time), stores the status the node reads when it changed, and then carries out
the actions the step queued. The status is stored first because a reply
completes a `oneshot` another thread can read at once, so a reply never
arrives ahead of the status it describes. It never awaits I/O: each relay
call, host-name lookup and read of the host's interfaces runs in a task of its
own, held in a `JoinSet` that is aborted when the pump ends, and posts its
result back to the inbox. That is what lets a relay's NIP-42 challenge reach
the machine while a relay call is in flight. The machine signs with the only
copy of the node key; it seals and opens traversal signals itself. The
machine's log lines are rendered by `log.rs`, with the target, level, text and
fields each had before it moved (`fips::nostr::runtime`, `fips::nostr::driver`
for the two assembly warnings, `fips::nostr::stun`, `fips::nostr::traversal`
for the punch attempt's two lines, and the receive loop's target for the
protocol-mismatch warning), and so are the pump's three notify-loop lines.

`NostrRendezvous` (`runtime.rs`) is the node's handle: its methods post to
the pump, a command as a send, a query as a request carrying a `oneshot` for
its answer. A request the pump can no longer answer gets an empty answer
(`Disabled`, `Skipped`, nothing), never a hang. The failure record is a
request the node awaits, answered with the time its decision was computed
at; the cooldown and `show peers` read a `Status` the pump stores, so they
never wait; the version-mismatch note and the capacity are sends. A
connect's outcome, an adopted socket or a failure carrying the peer's
configuration as given, arrives on one event channel the node drains each
tick. `start` builds the client, the machine and the pump, takes the
client's stream before the pump can send the first subscribe, then connects
and sends `Start`; start-up waits for the first advert to be assembled, as it
always has. `shutdown` stops the pump (which aborts its operations in flight
and closes its sockets) and closes the relay client's connections.

## Sockets and host reads

`sockets.rs` is the machine's UDP sockets. `Bind` binds `0.0.0.0:0`,
non-blocking (and, on Windows, with port-unreachable reports off, so a
closed punch target cannot fail a receive), and starts a task reading it;
its datagrams go to the pump on one bounded channel shared by every socket
(a full channel drops a datagram, as a full kernel buffer does), and a
receive error or a failed send goes to the pump's inbox for the machine to
judge. `Close` stops the task and drops the socket; `Adopt` is queued
behind the socket's sends, so the ack to the probe a traversal adopts goes
out first, and then the task stops and hands the socket to the node as a
punched link (the node's `EstablishedTraversal`, in `node/handoff.rs`, with
the transport name `nostr-nat`); the pump closes every socket when it ends.
`classify.rs` holds the punch-packet test and the datagram classifier
registered with every UDP transport instance, so a punch packet that
arrives on an adopted socket is dropped before FMP sees it.
`stun.rs` reads the host for a traversal's local candidates (the interface
list, and the local address of each probe and wildcard bind) and hands them
to the machine raw; the machine selects. `traversal.rs` is the wall clock
the rendezvous reads. `signal.rs` holds the signal envelope wrappers the
shell's tests use; the machine seals and opens signals itself.

Pieces move from the shell into `machine/` one at a time, so which shell file
holds what changes as they do; `mod.rs` lists the shell files and its `pub use`
block is the module's surface to the rest of the crate.

## Tests

The shell's unit tests are in `tests/`, whose README describes each file. The
machine's tests are in the `tests/` directory beside the code they test, under
`machine/`.
