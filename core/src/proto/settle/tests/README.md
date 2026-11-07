# core/src/proto/settle/tests

Tests of peer settlement in a deterministic world of two or three nodes.
Nothing here reads a real clock, opens a socket or draws a random value,
so one sequence of events always builds the same world, and the explorer
can rebuild any state by replaying the path that reached it.

## Files

- `mod.rs`: declares the files below, and holds the scans of the
  settlement sources, read through the rekey machine's code reader
  (`rekey::code_text`, `code_idents`) so comments and literals never
  count: the wildcard-arm deny at the module root, no `set_` method in a
  core file, no core file naming the model (only `mod.rs`'s declaration
  line may) and no model file naming a core module through `super` or
  `settle`, every core and model file in the scans' lists, and every test
  under this directory named by a switch's row in `faults.rs` or listed
  there. Each scan also plants its own break and shows it is found.
- `faults.rs`: the table of every switch in `../faults.rs` and the tests
  it must turn red, the tests that plant their own break, and the
  characterisation tests with their reasons, which the coverage scan
  reads. Under `slow-tests`, the meta-test runs each row's tests in a
  child process with the switch on, each must fail, and once with none,
  each must pass (an ignored test does not); its children report a failing
  seeded run unshrunk. Without `slow-explorers` it leaves out the rows'
  tests in `legacy/explore.rs`, and fails a row left with none. A row
  names the cheapest tests its switch reds; the core explorer appears only
  in the rows where it is the closest observation of the defect.
- `world.rs`: the world. Three transport models (connectionless;
  connection-oriented with a connect window, replies on the arrival
  connection and an end-of-stream to the far end; BLE-like, one
  connection per address pair, shared by every dial between the pair,
  with a verified mark), a monotonic clock, and a wall clock the world can
  step, which each packet's stamp carries. Stub crypto opens a frame only
  under a session the receiver holds. `Party` is what a node is to the
  world; `Net` is how a party acts on it. Its own tests check the stub
  crypto, the heartbeat and each transport model's guarantee.
- `party.rs`: `ModelParty`, the reference model as a node: one `Judge`
  per peer identity. The model has no timers, so the party keeps them
  from the world's constants (msg1 resends, the handshake deadline, the
  reclaim of a stored msg2, the 10 s heartbeat, the reconnect, its own
  rekey's resends and its cutover one check after the reply), and
  announces itself with one frame after each peer change that leaves it a
  session, as the node's tree announce does.
- `starts.rs`: the named starts, each with the scripted schedule that
  reaches its target state, the depth it is explored to and the most
  states that depth may reach; `flipped` builds a thread's two-node
  starts with their identities exchanged, for the other address order.
- `explore.rs`: the breadth-first explorer, its events and budgets, and
  the reach test.
- `oracle.rs`: the seven settlement properties (`OneSession`,
  `RightLink`, `MapsAgree`, `ConnectionsInUse`, `Fresh`, `Classified`,
  `Bounded`), the heal (every connect window opened, everything delivered,
  then 60 s wake by wake, below the 120 s pending hold), and `sweep`, which
  checks every explored state and every healed leaf. Its tests plant the
  two states only one clause sees, show that a replacement closes the
  replaced link's connection, and run the model as both ends of every start
  but 7 and 12.
- `shadow.rs`: a party's log replayed through one model `Judge` per peer,
  the first difference per peer reported as `Classified` or `Fresh`, with
  the named differences and their resyncs (heard after a move, the late
  second dial's fallback, the replay memory, the silent-session
  back-off, an ephemeral the rekey machine recorded when it refused it
  (switch `RecordedCompared`), the rekey machine's cutover at the peer's
  frame (`FrameCutoverMissed`), the larger node's
  yielded rekey, an own rekey ended with its peering, and a frame under a
  drained session counted as heard). `resync_close` gives the close
  a node with no fallback makes at a late second dial's move.
- `rekeyside.rs`: `RekeySide`, the rekey machine's decisions transcribed
  from `master` at `2ba790b2`: `judge_msg1` and `apply`
  (`rekey/machine.rs:853-951`, `:1123-1135`), `respond` (from `:1380`), the
  pending cutover by frame (from `:1790`), the initiator's msg2 and cutover
  one check later (or at once, for the model's explicit cutover event), the drain, and `poll`'s resends, deadline and hold expiry
  (from `:2161`), with `rekey/params.rs:113-129` (link age 30 s, session age
  10 s, hold 120 s, drain 10 s). Its test runs the model's rule 3 and 4
  histories through it.
- `shapes.rs`: the shapes the model's convergence with itself exempts,
  each shown once on the schedule that found it, with the model of
  `master` converging on the same schedule; a control that each start's
  own script shows only the shape it carries by design (none, except the
  late second dial answered in the other order and the dial on the
  peer's aged link); and a test that those two show their shapes with the
  models of the current and the deployed node.
- `drive.rs`: the one-node driver: one core and the rekey side of the
  peer it holds, fed a model history event by event. It maps each event
  to the core's inputs, hands a same-epoch msg1 to the rekey side with the
  core's arrival, routes the side's replacement request and restart report
  back to the core, and reports each step in the model step's fields.
- `cmp.rs`: the core through the driver against a model `Judge` on every
  history of the model's table tests (restated, since those tests are
  private to the model), the gates' own-msg2 history one second after a
  frame, and two histories the model's tests lack (a move's new address,
  a roamed address). Class, refusal, reply, change and closes are compared
  with the named differences applied; a second test asserts each named
  difference is still met where it should be.
- `stub.rs`: `CoreParty`, the core as a node of the world: one `Table`
  and a rekey side per held peer, with a stub shell that carries out the
  core's outputs, keeps each installed session's lease until removal, and
  supplies the timers, reconnects and announces the core leaves to the
  node. Under a candidate rule it keeps a held session's rekey side and
  lease beside the peer's own, so frames under it still open, hands such
  a frame to the core as `HeldFrame` and the loss of its connection as
  `HoldLost`, and swaps or drops it at `Settle` (switch
  `CandidateHoldsNothing` drops it at `Hold`). On every call it checks
  that no lease is dropped unreleased, that the index equals its
  recomputation from the records, and that a poll
  before the next wake does nothing, and reports a broken promise as an
  incoherence. It holds the `PacketStamp` switch (the core called at a
  packet's wall stamp). Its explorer test runs every start but 6 and 7
  with the core at both ends and the core at either end against the
  model, and start 12 with the core at both ends and no shadow; a split on
  a path that showed a known shape is counted, not failed, and so is, on
  start 12, an address only a path event names, since the world opens no
  connection for a path its events report.
- `regress.rs`: the two late-dial cases left for later, pinned as known
  defects with the core at both ends (a late second dial whose msg2s are
  read in the other order, both dialers; the larger node's dial on the
  smaller node's aged link, then its own rekey), each with a control that
  passes (the same dials answered in order; the dial on a link too young
  to rekey). They are run by `testing/known-defect-lane.sh`. Beside them,
  one schedule per earlier settlement defect the core can see, each
  reaching the state that defect broke and asserting it holds: a removed
  link's index entries, a crossing over two transports, a crossing's move
  and its reset, a stored answer whose send failed, a dial judged on one
  clock across a wall step, a replayed msg1 that promoted an unheard
  peering, an own dial answered by a restarted peer, and a second restart
  inside the dampener's interval.
- `sim.rs`: seeded long runs of the core at both ends from a cold start on
  each transport model (connectionless, connection-oriented, BLE, one of
  each), with loss, duplication, a heavy-tailed delay (one past the next
  wake is a loss), a partition window, restarts, rekeys, frames,
  connection faults and wall steps, each decision a function of the seed
  and a stable key; clean runs with no fault; runs that once reached a
  difference the comparison now resyncs; a byte-identical replay check;
  and a planted failure shrunk to its cause. A run is recorded as the
  explorer's events, so a failure shrinks by removing events while it
  fails with the same property at the same node (`FIPS_SETTLE_SIM_NOSHRINK`
  reports it unshrunk).
- `table.rs`: the unit tests of `../table.rs`, attached from it with
  `#[path]`: the path events, attribution by a proven path, a punched
  dial, a failed msg2 send, the stored msg2 drawn by any msg1 from its
  address, an orphaned bundle, the admission cap, the
  links a crossing and a late second dial retire, and the reset a move
  hands the per-peer data.
- `links.rs`: the unit tests of `../links.rs`, attached from it with
  `#[path]` (so it is that module's child, not declared in `mod.rs`): the
  derived index, and the close rule's cases with a link a leg holds, a
  live path, a probing path and a release marked keep.
- `gates.rs`: the unit tests of `../gates.rs`, attached from it with
  `#[path]`: each gate edge and source, the replay memory and its bound,
  the silent-session refusal and its doubling, the frame that forgets
  both, the default intervals against the model's, and the gates run
  beside a model `Judge` on the model's own gate histories.
- `legs.rs`: the unit tests of `../legs.rs`, attached from it with
  `#[path]`: a leg reaped at its deadline with its lease, the resend
  schedule within and past the deadline, the stored answer to a resend,
  a poll before the next wake, a deadline at the end of a short clock's
  range, and `close` returning every lease with no leak.
- `legacy/`: models of deployed settlement as nodes of the world. See its
  README.
- `candidates.rs` (under `slow-tests`, its explored runs under
  `slow-explorers`): the candidate rules for the two cases left for
  later, explored. Each candidate runs on the start it
  addresses (6 for the two late-dial rules, 7 for the aged-link rule) and
  every start the core's own rules pass, at both ends and at either end
  against the core's own rules, the model and both deployed models, in
  both address orders; only the dialer's rule is compared with the model
  step by step. The splits of the shapes a candidate addresses are not
  exempt. Every breach found is recorded in `candidates.txt` as new, or
  kept when the same pairing with the core's own rules in the
  candidate's place shows it too, and every pairing in
  `legacy/not-converging.txt` the candidate no longer breaks as gone; the
  tests fail at any difference from the file. Two scripted tests run the
  pins' schedules under each candidate.
- `candidates.txt`: that record, one breach per line.

## Rules for changing it

- A start's depth is its script's length plus two. Its cap is the state
  count measured at that depth with about half again as headroom; one
  depth more reaches several times as many states, so a start whose reach
  grew fails the reach test. Remeasure (`--nocapture` prints each start's
  depth, states, frontier per depth and time; `FIPS_SETTLE_EXPLORE_TRACE=1`
  prints the frontier as it grows) and record the run when a change moves
  the counts.
- The explorer's key is the world's digest. A connection's direction keeps
  its order there, and everything else in flight is a set, so deliveries
  that commute reach one state.
- Each guard here has a test-only switch in `../faults.rs`
  (`FIPS_SETTLE_FAULTS`), and the test that guards it must fail with the
  switch on. A new switch needs a row in `faults.rs`, and a new test a
  row, or a place on its self-checked or characterisation list; the scans
  in `mod.rs` fail until it has one.
- The model is the reference; the world's adapters supply what it lacks
  (timers, announces, the close of a connection nothing uses) and say so
  where they choose something FRC-1201 leaves open. One such choice: a
  replacement or restart over another connection closes the replaced
  link's connection when no link uses it (switch `ReplacedConnKept`). The
  model of `master` keeps `master`'s behaviour there. The core keeps it
  too, and the core's stub shell makes the same close, and at a dead
  link's removal closes the link's other paths' connections no link uses,
  under the same switch.
- A BLE connection is shared by dials between one pair of addresses, the
  local address included.
- The core's stub shell knows only its own end of a connection: one the
  far end closed is reachable until its end-of-stream arrives (switch
  `ReachablePeeks`).
- A node running the dialer's late-dial rule opens its log with
  `Entry::Fallback`, and its comparison keeps the model's fallback at a
  late second dial instead of clearing it.
- The comparison resyncs three more differences between the rekey
  machine and the model, each named: the larger node's own rekey ends
  when it answers the smaller node's at a simultaneous rekey, which the
  model leaves open (`YieldKept`); an own rekey ends with the peering it
  rekeyed, which the model keeps across a removal or replacement
  (`RekeyOutlivesPeer`); and a frame under the session a rekey cut over
  from, still held for its drain, counts as heard, as the node touches
  the peer at a frame of either slot (`PreviousUnheard`).
- The shape that names a peer's own rekey msg1 asks the sender's view for
  its rekeys: the model and the model of `master` name the rekey in
  flight, the core every rekey sent in its life, since a replacement ends
  the core's rekey side while the msg1 it sent is still the peer's rekey.
- Exemption by shape. `oracle::by_shape` exempts a split on a path that
  showed `StaleFrame`, `RekeyInstall` or `OldLife`. The two defects left
  for later have shapes too, `LaterDialFirst` and `DialAsRekey`
  (`Shape::pinned`), which only the runs against the models of deployed
  nodes exempt (`oracle::by_any_shape`): the model's convergence with
  itself and the core explorer exclude the starts that carry them
  instead. Every shape is part of the world's digest, so a shaped path is
  never folded into an unshaped one.
- The world's delivery delay is bounded: what is in flight is lost when the
  clock moves and when a node restarts (switch `DelayUnbounded`), and a
  restart drops what is addressed to the restarting node.
- The `slow-tests` feature gates the model of `master` explored against
  itself on every start but 12 (`legacy/findings.rs`), the candidate
  rules' two scripted tests (`candidates.rs`) and the switches' meta-test
  (`faults.rs`); GitHub CI's Linux job runs them. The `slow-explorers`
  feature, which turns `slow-tests` on too, also gates the core explored
  against the models of `master` and `maint` (`legacy/explore.rs`) and
  the candidate rules explored (`candidates.rs`); only local CI with
  `--slow-tests` and the internal builder run those. The suites
  `slow-tests` gates are listed here as they arrive, since
  `core/Cargo.toml`'s comment on that feature is left to multipath stage
  A's rebase.
