# core/src/proto/settle/tests

Tests of peer settlement in a deterministic world of two or three nodes.
Nothing here reads a real clock, opens a socket or draws a random value,
so one sequence of events always builds the same world, and the explorer
can rebuild any state by replaying the path that reached it.

## Files

- `mod.rs`: declares the files below.
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
  states that depth may reach.
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
  back-off). `resync_close` gives the close
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
  `master` converging on the same schedule, and a control that no start's
  own script shows one.
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
- `table.rs`: the unit tests of `../table.rs`, attached from it with
  `#[path]`: the path events, attribution by a proven path, a punched
  dial, a failed msg2 send, an orphaned bundle, the admission cap, the
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
  switch on.
- The model is the reference; the world's adapters supply what it lacks
  (timers, announces, the close of a connection nothing uses) and say so
  where they choose something FRC-1201 leaves open. One such choice: a
  replacement or restart over another connection closes the replaced
  link's connection when no link uses it (switch `ReplacedConnKept`). The
  model of `master` keeps `master`'s behaviour there.
- The world's delivery delay is bounded: what is in flight is lost when the
  clock moves and when a node restarts (switch `DelayUnbounded`), and a
  restart drops what is addressed to the restarting node.
- The `slow-tests` feature gates the model of `master` explored against
  itself on every start but 12 (`legacy/findings.rs`). The suites it gates
  are listed here as they arrive, since `core/Cargo.toml`'s comment on the
  feature is left to multipath stage A's rebase.
