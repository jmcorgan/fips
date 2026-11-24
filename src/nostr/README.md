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
onto `BootstrapError`.

Pieces move from the shell into `machine/` one at a time, so which shell file
holds what changes as they do; `mod.rs` lists the shell files and its `pub use`
block is the module's surface to the rest of the crate.

## Tests

The shell's unit tests are in `tests/`, whose README describes each file. The
machine's tests are in the `tests/` directory beside the code they test, under
`machine/`.
