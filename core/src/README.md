# core/src

The source of the `fips-core` crate. The crate's purpose and the rules
its code follows are in `core/README.md`, one level up; read that before
changing anything here.

## What is here

- `lib.rs`: the crate root. It declares `#![no_std]`, brings in `alloc`,
  brings in `std` for tests only, and lists the crate's modules.
- `cache/`: the coordinate cache, which maps node addresses to tree
  coordinates for routing. Its own README describes it.
- `entropy.rs`: the `EntropySource` trait, through which the host supplies
  random bytes. A type that needs them takes the source as a type
  parameter; the core never reads a random source of its own.
- `faults.rs`: the mutation lane's switches, one list for both crates
  (`testing/mutations/`). Each puts back one break behind a
  `node_fault!(Name)` condition, read once per process from
  `FIPS_NODE_FAULTS`. Compiled for tests and under the `test-hooks`
  feature only, and hidden from the documentation.
- `identity/`: node and peer identity types and their encodings. Its own
  README describes it.
- `node/`: node-level bookkeeping that is not a protocol layer: the
  handshake, session-setup and lookup-signing rate limiters, and the
  stats history. Its own README describes it.
- `noise/`: the Noise handshakes, the transport sessions, the replay
  window, the cipher state and the AEAD under it, and the fixed sizes of
  the handshake messages. Its own README describes it.
- `proto/`: the protocol: wire codecs and sans-IO state machines for
  every layer. The root crate reaches it as `crate::proto`. Its own
  README describes it.
- `time/`: the `Clock` and `Instant` traits, through which the host
  supplies the time. The core takes instants as arguments and never
  reads a clock. Its own README describes it.
- `transport/`: the transport value types (identifiers, address,
  statistics) that transports and the protocol cores both name. Its own
  README describes it.
- `utils/`: small shared value types: the session index and its
  allocator, which draws from the host's entropy source, the hash
  map for keys a peer can choose, keyed from that source, and the set
  of this node's interface prefixes.
  Its own README describes it.
- `tests/`: the unit tests of the files at this level, attached from
  each file by `#[path]`. Its own README describes it.
- `testutil.rs`: fixtures shared by the crate's unit tests
  (`make_node_addr`, `make_keypair`; `TestEntropy`, the random source
  tests build randomized types with; and `FixedEntropy`, a source that
  fills every byte with one value; `TestClock` and `TestInstant`, a
  clock of whole milliseconds from 0 that moves only when a test
  advances it; `SplitMix64`, the seeded generator the rekey simulator
  draws from, so a run replays byte for byte from its seed;
  `SeededEntropy`, an entropy source on a per-thread `SplitMix64` that
  `seed_entropy` reseeds, and `seeded_keypair`, so a simulation with real
  Noise handshakes replays too; and the test binary's global allocator,
  the system's with a per-thread count of allocations that
  `allocations()` reads, so a test can show a call allocates nothing;
  and `bounded`, which runs jobs each on a thread of its own, at most
  `WORKERS` at once, for the explorers whose nextest `threads-required`
  in `.config/nextest.toml` counts that many).
  Compiled for tests only.

## Rules for this level

- `lib.rs` stays `#![no_std]`. The `extern crate std;` line stays behind
  `#[cfg(any(test, feature = "test-hooks"))]`, so only the host-run tests,
  this crate's and the root crate's, see `std`.
- Each module moved in from the root crate gets a `pub mod` line here,
  and its directory gets a README of its own.
- Keep this README's list in step with the directory: a module added,
  removed or renamed here updates it in the same change.
