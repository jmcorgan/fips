# src/nostr

Nostr rendezvous: overlay adverts published to relays, traversal offers and
answers carried as encrypted Nostr events, STUN for the reflexive address, UDP
hole punching, and the handoff of a punched socket to the UDP transport.

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
channel, subscribing, fetching, sending, reading the pool) goes through its
`RelayClient`, one method per call, and each caller maps the client's error
onto `BootstrapError`. Each of the machine's subscriptions is opened under an
id the pump draws once and reuses on every retry, so a relay that already
holds it is not given a second. The client answers a relay's NIP-42 challenge through
`PumpAuthenticator`, which asks the pump, so the node key signs only in the
machine.

## The advert half: one task owning the machine

The advert half of rendezvous (the peer advert cache, this node's advert and
the transports it is assembled from, the relay subscriptions and the inbox
relay list) is owned by one task, the pump (`pump.rs`), which steps
`machine::rendezvous::Rendezvous`. The pump reads its inbox, the relay
client's notification stream and the machine's next deadline, with no
preference among them, hands each input to the machine with the step's two
clock readings (tokio's monotonic clock, so a test's paused clock moves the
machine, and Unix time), and carries out the actions it queues. It never
awaits I/O: each relay call and each public-address observation runs in a
task of its own, held in a `JoinSet` that is aborted when the pump ends, and
posts its result back to the inbox. That is what lets a relay's NIP-42
challenge reach the machine while a relay call is in flight. The machine's
log lines are rendered by `log.rs`, with the target, level, text and fields
each had before it moved (`fips::nostr::runtime`, and `fips::nostr::driver`
for the two assembly warnings), and so are the pump's three notify-loop
lines.

`NostrRendezvous` (`runtime.rs`) is the node's handle: its advert methods
post to the pump, a request carrying a `oneshot` for its answer. A request
the pump can no longer answer gets an empty answer (`Disabled`, `Skipped`,
nothing), never a hang. `start` builds the client, the machine and the pump,
takes the client's stream before the pump can send the first subscribe, then
connects and sends `Start`; start-up waits for the first advert to be
assembled, as it always has. `shutdown` stops the pump (which aborts its
operations in flight), stops the signal task, and closes the relay client's
connections.

## The traversal half, until it moves into the machine

The traversal flows (the initiator's connect, the responder's offer
handling, the signal sends and inbox lookups) are still served by
`TraversalShared` in `runtime.rs`, unchanged, until the traversal flows move
into the machine. Until then they reach the advert half by a few temporary
paths only:

- the signal task, `TraversalShared::run_signals`, reads the signal router's
  channel, as the old notify loop's signal arm did; a signal that ever
  reached the pool's stream is put on that channel by the pump
  (`SignalRouter::forwarder`);
- `connect_peer` asks the pump for a peer's advert (`ResolveAdvert`);
- the pump asks the traversal half to reset a peer's failure streak after a
  stale-advert refetch (`ResetStreak`);
- the traversal half keeps its own clone of the relay client and of the
  node's `Arc<NodeSigner>`;
- the traversal STUN exchange (`stun.rs`) is the async one it always was;
  the advert's public-address observation is the machine's, through the
  STUN client in `machine/stun/client.rs`.

## Sockets

`sockets.rs` is the machine's UDP sockets. `Bind` binds `0.0.0.0:0`,
non-blocking, and starts a task reading it; its datagrams go to the pump on
one bounded channel shared by every socket (a full channel drops a datagram,
as a full kernel buffer does), and a receive error or a failed send goes to
the pump's inbox for the machine to judge. `Close` stops the task and drops
the socket; the pump closes every socket when it ends. A host-name lookup is
a task of the pump's, like a relay call.

Pieces move from the shell into `machine/` one at a time, so which shell file
holds what changes as they do; `mod.rs` lists the shell files and its `pub use`
block is the module's surface to the rest of the crate.

## Tests

The shell's unit tests are in `tests/`, whose README describes each file. The
machine's tests are in the `tests/` directory beside the code they test, under
`machine/`.
