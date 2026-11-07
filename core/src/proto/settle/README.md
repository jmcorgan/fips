# core/src/proto/settle

Peer settlement: how two nodes that dial each other, restart or rekey end
up holding one session on one link, and which connections each link still
needs. The module is declared in `../mod.rs` and hidden from the docs.
The settlement core is compiled in every build and called by nothing
yet; the reference model is declared in `mod.rs` under
`#[cfg(any(test, feature = "test-hooks"))]`, so it reaches no normal or
release build.

## Files

- `mod.rs`: the module doc and declarations, the `fault!` macro (the
  literal `false` outside test builds) and the module-wide deny of
  wildcard enum arms.
- `links.rs`: the core's link records: each link's setup address,
  direction, holder and bundle paths with their proven states, the
  transport-address index derived from them, and the one close rule over
  links and their paths (`in_use`, `retire`, `release`).
- `gates.rs`: the restart and replacement gates, one function
  (`Gates::gate`) that every restart source asks: a msg1 from an identity
  not held, a msg1 at a new epoch, a same-epoch replacement, and a new
  epoch found at this node's own msg2 or a rekey msg2. It holds the memory
  per identity the gates read (the dampener's stamp, the replay memory and
  the silent-session record), and judges as the current node does.
- `legs.rs`: the handshake legs in flight, by link: a dial leg with its
  msg1, its resend schedule (one interval after the dial, then doubling,
  up to the configured count) and its deadline; a responder leg with the
  msg1 it answered and its stored msg2; each holding its session index
  lease. A stored msg2 not yet sent answers any msg1 from its address
  (FRC-1201 Section 5.8); once sent, only its own msg1, byte for byte. A poll returns the resends due and the legs reaped, and
  `close` returns every lease.
- `table.rs`: the judgements. `Table` holds the links, the legs, the peer
  held for each identity and the gates; `step` takes one input and
  returns the outputs, `poll` runs the legs' timers and `close` gives
  everything back. It judges a msg1 from an identity not held or at a new
  epoch through the gate, hands a same-epoch msg1 to the peer's rekey
  machine with where it arrived (on the link from its setup address, the
  peer's current address or a proven path), takes the machine's
  replacement request back through the gate, completes this node's own
  dials (install, restart, the own-dial move and the crossing's
  tie-break), removes peers, and applies the path bundle's events to the
  link records.
- `input.rs`: what the shell tells the core, each built after any Noise
  read, carrying the msg2 the shell built and its lease.
- `output.rs`: what the core asks of the shell, run front to back:
  answers, resends, the hand-off to the rekey machine, installs, the
  per-peer data's transition, removals, retired links with their closes,
  released paths, freed leases, reconnects and refusals.
- `params.rs`: the intervals and bounds the core reads, with the current
  node's values and the line each is taken from, and the deadline and
  back-off arithmetic its timers share.
- `model/`: the reference model, written from FRC-1201 Sections 5.5 to
  5.8 and the operator's decisions, without reference to the code. See its
  README.
- `faults.rs`: the test-only switches that turn each guard of the core
  and of its tests off (`FIPS_SETTLE_FAULTS`), read through the `fault!` macro in
  `mod.rs`, and the choice of a candidate rule for the two settlement
  cases left for later (`Candidate`; `FIPS_SETTLE_CANDIDATE` for a
  process, or a test's choice for one thread's nodes).
- `tests/`: the deterministic world, the model and the core as nodes of
  it, the named starts, the bounded explorers, the settlement properties,
  the rekey machine's decisions, a model of the current node, the
  pinned late-dial cases, the scripted regressions, the seeded long
  runs, the candidate rules explored, the meta-test of the switches and
  the scans of this directory. See its README.

The core grows here beside the model, and its tests compare it with the
model. No core file (anything here outside `model/` and `tests/`) refers
to the model, and nothing in `model/` refers to a core item; the scans in
`tests/mod.rs` check both ways, by path.

## Rules for changing it

- Everything here stays `no_std` with `alloc`, as the rest of the crate
  (`testing/build-core-baremetal.sh` builds the crate without it, so a
  leak into a normal build shows there).
- Names follow the crate's style: at most one underscore outside tests.
- The index in `links.rs` is recomputed by `Links`' own methods after
  every change and never written directly.
- A lease leaves `legs.rs` only with its leg: taken with it, returned
  with a reap, or returned by `close`. Dropping one leaks an index, and
  the tests count leaks.
- Every lease an input brings comes back in an install or a free; the
  table keeps none beyond its legs.
- A teardown for a restart, a replacement, a rekey teardown, a dead link
  or a `Disconnect` keeps the old link's connections open, as the current
  node does; only an operator disconnect, an orphaned bundle and `close`
  apply the close rule to a held peer's link. A crossing's losing link and
  the link a late second dial moves off are retired by the close rule.
- A move does not set the peering heard, as the current node does not.
- Every deadline comes from `params::deadline`, which saturates at the
  end of the instant type's range rather than overflowing.
- Only an accepted restart or replacement that tears down a heard
  peering stamps the dampener; a refusal never does, so a sustained
  replay cannot keep a genuine restart out.
- A core file's unit tests sit in `tests/<file>.rs`, attached from the
  file with `#[path]`; a core file that holds a test fails a scan.
- No core type has a `set_` method, and a new source file here or in
  `model/` joins the scans' lists in `tests/mod.rs`, or the file count
  there fails.
- A new guard gets a switch in `faults.rs` and a row in
  `tests/faults.rs`, and a new test is named by a row or listed there as
  self-checked or characterisation; the scans fail otherwise.
- The candidate rules are test-only, every item of them under
  `#[cfg(test)]`: in `table.rs` the `Kept` record, the table's `cand` and
  `holds` fields and the candidates' `impl` block; in `input.rs` the
  `HeldFrame` and `HoldLost` inputs; in `output.rs` the `Hold` and
  `Settle` outputs. A table runs one only when built with `Table::under`,
  and the non-test build has no candidate code (the bare-metal build
  shows it). Each candidate keeps the core's own rules and changes one
  decision: the dialer's and the responder's late-dial rules keep the
  session a late second dial moves off (`Hold`) until a frame settles it
  (`Settle`), the responder's also a replaced unheard peering's for 15 s;
  the aged-link rule moves an own dial completing on an aged inbound link
  onto that dial.
