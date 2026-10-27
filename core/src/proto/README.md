# core/src/proto

The FIPS protocol, sans-IO: the wire codecs and the state machines that
decide what a node does with each frame, timer and event. Each
subdirectory is one protocol layer or subsystem; the files at this level
are the primitives they share.

The root crate drives all of it. Its node, peer and transport code owns
the sockets, the clock, the Noise sessions and the logging, calls into
this module with what arrived and the current time, and carries out the
actions it returns. The root crate reaches this module as `crate::proto`
through `pub(crate) use fips_core::proto;`, so its code names the same
paths as before the module moved here, and re-exports the public
protocol types (`TreeState`, `TreeCoordinate`, `BloomFilter` and the
rest) at its own crate root.

## Files

- `mod.rs`: declares the submodules and re-exports `Error`.
- `error.rs`: `Error`, the decode and validation error every codec
  returns.
- `codec.rs`: `Reader` and `Writer`, the bounds-checked byte cursor the
  wire codecs share.
- `coord.rs`: `TreeCoordinate` and `CoordEntry`, a node's path from the
  spanning-tree root, and their wire encoding. `stp` re-exports them.
- `link.rs`: the link-layer message type catalog (`LinkMessageType`)
  and the session datagram that carries end-to-end traffic.
- `framing.rs`: the encapsulation overhead of a session datagram, which
  spans the FMP and FSP layers and is summed from their wire sizes, and
  the largest FSP payload a path MTU admits once that overhead and the
  port header are paid.
- `math.rs`: `powi`, an integer power that gives the same bits on every
  platform, for the protocol arithmetic `core` has no float method for.
- `rate_limit.rs`: a per-address minimum-interval limiter and an
  exponential backoff helper, shared by the subsystems' `limits.rs`.
- `tests/`: unit tests for `framing.rs`, `link.rs` and `math.rs`.
- `bloom/`: reachability bloom filters and their announcements.
- `fmp/`: the link layer: connection lifecycle and link framing.
- `fsp/`: the end-to-end session layer.
- `lookup/`: mesh lookups for a destination's coordinates.
- `mmp/`: link and session metrics and their reports.
- `probe/`: the diagnostic path probe.
- `rekey/`: the key-rotation state machine one link peer or one session
  runs, shared by the link and session layers. Each layer binds it to its
  handshake pattern in a `rekey/` subdirectory of its own (`fmp/rekey/`,
  `fsp/rekey/`). Hidden from the docs. The root crate's session table
  holds each session in one, from its first handshake on, and each active
  link peer holds its link's keys, indices and drain in one, which the
  deployed link rekey decisions act on through state moves; see its
  README.
- `routing/`: next-hop selection and routing error signals.
- `stp/`: the spanning tree.

Each subdirectory has its own README.

## Invariants

- **Sans-IO.** Inputs in, actions out. No sockets, no clock reads (time
  is a `u64` millisecond argument), no randomness of its own, no logging
  and no async. A decision that used to log returns a value the caller
  logs. `rekey/` is the first module here to take time as instants of a
  host clock (`C: time::Clock`) instead of milliseconds, and the only one
  that holds keys: it owns its handshake states and transport sessions,
  so that a read is a transaction and an epoch exists only for the bonded
  peer.
- **Wire formats are protocol.** Every codec here encodes what other
  nodes decode. A change to one changes the protocol and does not happen
  on the deployed lines.
- **Items are `pub` because the root crate drives them.** Most of this
  module's public surface exists for the root crate's node code rather
  than as a designed interface; trimming it is later work. Peer input is
  untrusted all the same: a malformed frame returns an error, never a
  panic.
- **Test hooks.** Eleven items are gated `#[cfg(any(test, feature =
  "test-hooks"))]`: methods and re-exports that only tests use to set up
  or inspect state. The root crate's tests reach them through the
  `test-hooks` feature, which the root enables from its
  `[dev-dependencies]` only, so they reach only a build that compiles
  tests, examples or benches; a plain `cargo build`, release or not, leaves
  them out. They are `set_interval_ms` and `len` on the address limiter in
  `rate_limit.rs`, `set_interval_ms` on the lookup forward limiter, `len`
  on the routing error limiter, `BloomState::last_update_sent`,
  `TreeState::set_my_coords_for_test`, `SilentSessions::count`,
  `Msg2Header::noise_msg2`, and the
  `lookup::RecentRequest`, `lookup::MIN_RECENT_PER_PEER` and
  `probe::StageVerdict` re-exports.
- **Shared code lives at this level.** A primitive two subsystems need
  goes here, not in one of them, and subsystems import it downward from
  `crate::proto`.
