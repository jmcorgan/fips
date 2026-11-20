# src/node/settle

One owner for each of the node's per-peer maps, and the table of what each
change to a held peer does to each piece of its state. The module is
`node::settle`, declared `pub(crate)` in `../mod.rs` so that `src/peer/` can
name the table; `Node` holds each map as a field whose type is a wrapper
defined here, and the wrappers stay `pub(in crate::node)`.

Each wrapper keeps its map in a private field. It derefs to the map, so
every read in the node is written as it was against a plain `HashMap`, and
`&wrapper` iterates, but it has no `DerefMut`. A write goes through a named
method, one per event that changes the map, and each method transcribes the
statements its sites wrote before, in the same order: moving a write here
changes nothing a peer can see. The writers are methods on the field, not on
`Node`, so a handler can still borrow two maps, or a map and another `Node`
field, at once.

## Files

- `mod.rs`: the module doc, the `reads!` macro that gives each wrapper its
  `Deref`, its `&wrapper` iteration and, under `cfg(test)`, its `raw` and
  `planted`, the re-exports `Node` uses, `Core`, `Legs` and `Gates`, the
  settlement core's table, handshake legs and restart gates as the node
  holds them (`Node.core` is its one copy of the table, in any build, and
  decides through `Table::step`), and the `Node` methods of this level:
  `gates` and `legs`, which read those parts of `Node.core`, and under
  `cfg(test)` `gates_mut`, for a test that plants a memory; `audit_live`, which each node entry that can
  change a map calls on its way out (the audit in a debug build, nothing
  in a release one); and, for tests, `plant` and `planted`.
- `links.rs`: `LinkTable`, the node's links and the reverse lookup from a
  `(transport, address)` pair to the link at it, each writer taking the
  core (`Node.core`), whose records it reads and never writes outside a
  test: `bind` and `open` add a link the core numbered or opened, `close`
  and `forget` drop one the core retired, `held`, the path driver's
  `follow`, `claimed` and `unclaimed`, and `stepped` rebuild the lookup
  after a step of the core; `get_mut`; `index` for reads of the lookup, and
  under `cfg(test)` `raw_index`, and `hold`, `claim`, `unclaim` and
  `mirror` for a test that drives the table alone, writing the records as
  the core would. Its doc carries
  the warning about the lookup's key form. `used` is the node's close rule,
  asked of the core's records (`Links::in_use`): whether a live link other
  than the one closing uses a pair, a held link by the Live or acknowledged
  paths of its record and a handshake leg by its setup pair. `Node::in_use`
  asks it for every close site, the connect's and the drain's, and
  `Node::close_unused` closes a link's setup pair only when it answers no;
  `Node::close_pair` asks the same with another link excepted, for a
  move's close of its dial's own connection with the link it left excepted
  (`Node::close_setup`), for a msg1, a redial's among them, that the late
  ACL or index exhaustion refuses after the answer is asked for, and for a
  dial whose answer the restart gates refuse, with the dial's own link
  excepted.
  The lookup is
  derived from the settlement core's record of each link (`Links`), kept
  under the core's number for it (`no`): opened and retired with the link,
  held for a promoted peer (`hold`), and fed what the link's bundle reports
  (`mirror`) from `exec/links.rs`. `poll` runs the node's handshake legs
  (the core's `Legs` in `Node.core`, keyed by the same numbers) at the
  peers' timers (`drive_peer_timers`): the resends due, and each leg past
  its deadline reaped, its record retired by the close rule, which names
  the connections to close, and the index rebuilt after. `reap` is the
  same reap of one leg, which the stale-connection sweep
  (`check_timeouts`) asks of each answer's leg. It names each live link at its setup
  pair, unless the bundle released the path there, and at each Live or
  acknowledged path of its record, the newest link where several use a pair.
  The table keeps it as a cache that every writer rebuilds; `derived`
  computes it afresh for the audit. `placement` reads where a msg1 from a
  pair stands among the core's records (`Links::placement`), which answers
  the node's attribution questions: whether a link owns the pair
  (`is_established_link_msg1`, the msg1 rate limiter's class and the
  admission of a transport that accepts no new handshakes), the identity a
  waived msg1 is to prove (`msg1_waiver`), and whether a msg1 or a rekey
  msg2 is on a held peer's link (`link_arrival`); `id` gives the link the
  core numbers, for the identity a handshake leg expects. Under
  `cfg(test)` it carries the node's
  audit count; `raw_index`, whose entries are put back at every rebuild
  until their link closes, and which every rebuild also names in the
  core's records (`Links::name`), so the records answer for the lookup the
  test wrote; `plant_entry` and `plant_path`, writes past
  the table, to its lookup and to a core record, that do not mark it, for
  the tests that the audit catches each; and `resync`, which writes into the
  core's records what a test changed past the writers: a record for each
  link a test put in the map itself, for each index entry a test wrote
  naming a link with no record, and for the link of each peer a test
  planted on a link the map lacks, at the pair the peer is at; and each
  named peer's bundle paths and whether its bundle found it capable.
  `Node::resync`
  calls it at the head of each msg1 and msg2 and before each read of the
  close rule, so a test that changes a bundle and then drives the node needs
  no call of its own. `recorded` gives the paths a peer's bundle holds as the
  feed tells them, which the resync writes.
- `maps.rs`: `MachineMap`, the per-peer control machines with their timer
  store (`add`, `ensure`, `rekey`, `drop`, `get_mut`; `arm`, `cancel`, and
  `timers` for the tests), `rekey` keying a moved peer's machine under the
  dial's link; `PeerMap`,
  the authenticated peers (`install`, `take`, and `get_mut`, `values_mut`
  and `iter_mut` for a change to a peer that leaves the map as it is); and
  `BindMap`, our session indices and the peer each names (`bind`, `unbind`).
- `RedialMap`, in `maps.rs`: a cache of the settlement core's pending
  redials, one per held identity at most, each naming the inbound link its
  leg runs on and the index its msg2 named, for the dataplane's lookup by
  index and the tests. `Node::stepped` rebuilds it from the core after
  every step; nothing else writes it. The memory of the msg1 ephemerals
  that armed a redial is the core's restart gates'. The `redial-leg` clause
  holds each entry to a leg still at `Handshaking{ReceivedMsg1}` for that
  identity and index, an index no peer is bound to, on an open link.
- `params.rs`: `settle_params`, the settlement core's parameters for a
  node's configuration: the core's defaults with the handshake timeout,
  the msg1 resend interval, multiplier and count, the cap on answers in
  flight and the max-peers cap taken from the configuration, and nothing
  else, so the gate constants stay the core's; and `leg_params`, the same
  for the node's own handshake legs (the core's, in `Node.core`), with the deadline one
  millisecond later, since the node reaps a leg once it has been idle
  longer than the timeout in whole milliseconds and the core reaps at its
  deadline. The node's restart gates (the core's `Gates`, in `Node.core`)
  read `settle_params`, and `Node.core`, the node's one copy of the core's
  table, is built with them. The handshake legs in that table are counted
  from `leg_params`' deadline, so a leg opened at the instant the node
  stamped it is reaped at the node's tick.
- `decide.rs`: the settlement core's decisions, taken by the node. Each
  decision site builds the core's `Input` after any Noise read and hands
  it to `Node::decide` (or `decide_at`, for an input that opens a leg the
  node stamped earlier), which steps `Node.core` at `Node::settle_now` and
  returns the outputs for the site to run in order; `Node::core_tick` runs
  the legs' timers and `Node::reap` one leg's reap. `Node::stepped`, after
  every step, rebuilds the caches of the core's state the node reads on
  its hot paths: the link table's index and the pending redials by their
  legs' indices (`RedialMap`). `decide_removal` runs a removal the core
  decides (a dead link, an orphaned bundle, a `Disconnect`, an operator
  disconnect or a rekey teardown), `give_up` tells the core of a dial the
  node gave up for a cause the core has no timer for, and `close_each`
  closes the connections a close rule named. `adopt` and `unadopt` still
  write the core's record of a peer from the node's after an install or a
  move the node carries out. In a test build `decide` first runs the
  node's `resync`, which writes into `Node.core` what a test wrote past
  the writers, and counts the inputs by kind (`Node::seen`).
- `audit.rs`: the coherence of the maps, one function per clause, each
  naming what breaks it, and `live`, which runs every clause and panics on
  the first that fails, naming the node entry and the clause. Compiled in
  test and debug builds only. The node tests' quiescent audit calls the
  clauses it shares rather than restating them; what holds only once a test
  is quiet stays there. In a test, `live` skips a node written past its
  writers, counts each audit on the node's link table, and records the
  audit's reach when `FIPS_AUDIT_REACH` names a file
  (`testing/check-audit-reach.py`). The `index-cache` clause, after the
  other index clauses, holds the link table's cached lookup to the one its
  records give now, and `link-cache` holds each held peer's link, which
  the send path reads per frame, to the link the core holds it on. The
  last clause, `links-mirror`, holds
  each held peer's core link record to its bundle, capable when the bundle
  is and holding its paths, each in the state the bundle holds it, a
  switched-to path too; it skips a peer a test mutator of the peer's paths
  changed past the feed (`ActivePeer::past_feed`, test builds only), and
  records each skip in the reach file, where the check holds them to a
  ceiling.
- `table.rs`: `Transition`, each thing the code does to a held peer; `Row`,
  each piece of what the node holds per peer, with `DataRow` for the peer's
  record; `Cell` and `DataCell`, what a transition does to a row; `Owner` and
  `Facet`, who holds a row; and `cell`, `data_cell` and `owner`, the rule as
  nested total matches. The peer's record settles by `data_cell`, and the
  executor's effects and the rekey handler's cutover read `cell`. Only the
  tests read `owner`, `Owner` and `Facet`, and the rows no effect reads,
  which is why those alone keep a dead-code allowance outside test builds.
  It also defines `listed!`, which gives an
  enum its list of variants in test builds, and `exec/plan.rs` uses it for
  `Effect`.
- `exec/`: the executor, what the node runs for a transition outside the
  peer's record, as a list of effects in their order (`exec/plan.rs`), and
  `Node::run`, which runs them. Its own README names each file.
- `tests/`: the unit tests of this level; its own README names each file.

## Rules for this level

- No wrapper implements `DerefMut`, and no wrapper hands out its inner map
  outside `cfg(test)`. `src/node/tests/survivors.rs` scans this directory for
  both; a direct write to an inner map does not compile.
- A new write to a map is a new writer here, named for the event, not a
  wider accessor. A writer transcribes; a change of what an event does to a
  map is a change of behaviour and is made, and tested, as one.
- The link table's lookup is derived from the core's link records, not
  written: each of the table's writers changes the records, through the
  core, and rebuilds the lookup before it returns, and the records are
  private to the table, so nothing else can change them. A new way to
  change a record is a new writer that rebuilds.
- `raw` and the other `raw_*` methods are for tests that build a state no
  writer builds. They set the wrapper's `planted` flag, which marks the node
  as written past its writers, and the live audit skips a marked node for
  the rest of the test. A test that can build its state through the writers
  uses them: every mark costs the audit that node. `testing/check-audit-reach.py`
  holds the share of audited nodes to a floor.
- A clause states a rule that holds between any two node entries, mid
  handshake included. A rule that holds only at quiescence belongs to the
  quiescent audit in `../tests/settle/audit.rs`, not here.
- `table.rs` denies wildcard match arms and holds none, so a new row,
  transition or cause does not compile until it has taken a side at each cell.
- A peer's rekey and path machines are built, moved and closed only through
  the settlement core's join, which only `src/peer/active.rs` asks for a
  change of machines, and only `exec/` asks the active peer, but for a
  crossing's move at its site. `tests/scans.rs` holds the code to each, with
  its exemptions and their reasons.
  Its rule states what the code does today; a cell the code does not match is
  a wrong cell or a wrong site, and a change of what a transition does changes
  the cell and its golden line in the same commit.
- `exec/plan.rs` and `exec/mod.rs` deny wildcard arms as `table.rs` does,
  and a plan lists the statements it stands for in their old order: a
  reordering is a change of behaviour.
- Keep the file list in step with the directory.
