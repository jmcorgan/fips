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
  `planted`, the re-exports `Node` uses, `Core`, the settlement core's
  table the node holds (`Node.core`, a `Table` on the peer clock running
  the XX flow), with `core`, which builds it from the node's address and
  configuration, and the `Node` methods of this
  level. The table holds the node's one copy of the core's link records,
  handshake legs and restart gates. The node steps it at each of its
  decision sites (`decide.rs`); at a msg1, a dial, a connect, its own
  dial's msg2 and an answer's msg3 it carries out what the core decided,
  as it does the reconnect the core asks for at a removal and the retry
  it asks for at a timer's reap of a dial, and elsewhere it still decides
  itself, reading the parts through the table's `parts`: the restart
  gates (`Node::gates`, the table's `Gates`: the dampener's stamps and the
  silent-session records)
  and the handshake legs (`Node::legs`, the table's `Legs` on the peer
  clock: each of this node's own dials from its msg1 until the core
  decides its msg2, with its lease and its msg1 resends, and each of its
  answers from its msg2 until the core decides its msg3, with its lease
  and the msg1 and msg2 it stores). A leg is numbered by its link's
  record, as the link table numbers the link. `audit_live`, which each
  node entry that can change a map calls on its way out (the audit in a
  debug build, nothing in a release one), and, for tests, `legs_mut`,
  `gates_mut` and `gate_params` for a test that writes the parts past
  their writers, `leg_params`, `plant`, `planted`, `resync`,
  `handshake_index` and `resend_at`. `handshake_index` and `resend_at`
  read a handshake's index and next resend from its leg, or else its
  machine. `resync` writes into the link table's records what a test
  planted past the writers, before the node reads them
  (`LinkTable::resync`); the node runs it at the head of each msg1, and a
  test that reads the msg1 predicates itself runs it first.
- `links.rs`: `LinkTable`, the node's links and the reverse lookup from a
  `(transport, address)` pair to the link at it (`open`, `close`, `forget`;
  the path driver's `follow`, `claim` and `unclaim`; `get_mut`; `index` for
  reads of the lookup, and under `cfg(test)` `raw_index`). Its doc carries
  the warning about the lookup's key form. `used` is the node's close rule:
  whether a live link other than the one closing uses a pair, a held link by
  its bundle's proven paths and any other by its setup pair. `Node::in_use`
  asks it with each held peer's bundle, and `Node::close_unused` closes a
  link's setup pair only when it answers no. The lookup is
  derived from the settlement core's record of each link (`Links`, in
  `Node.core`, which each writer and each read of a record is handed), kept
  under the core's number for it (`no`, and `id` the other way): opened
  and retired with the link, or opened by the core at a dial's connect or
  an anonymous msg1 and taken under its number (`bind`), held for a
  promoted peer (`hold`), and changed by the core as it steps, after which
  the lookup is rebuilt (`stepped`); a link closed after the core retired
  its record retires nothing more. In a test build `core_no` also gives
  the record the core's resync opened for a link a test put in the map,
  which the table does not number and the lookup does not name
  (`plant_spare`); the table takes that record over if it numbers the link
  later, and `mirror` applies a path input to a table a test drives alone.
  It names each live link at its setup
  pair, which on this line stays named after the bundle releases the path
  there, and at each Live or acknowledged path of its record, the newest
  link where several use a pair. An inbound leg that takes a pair at msg1
  so names it while it lives, and the pair goes back to the link named
  there before once the leg is closed. `holder` says who holds a link, its
  leg or a peer, for the anonymous-beacon dedup, which skips a beacon only
  at a pair naming a handshake in flight or a live held peer's link.
  `placed` gives the link the lookup names at a pair with its record's
  direction and holder, which the duplicate-msg1 check reads, and
  `held_at` the peer holding it, the first limb of the msg1 predicates
  (`is_established_link_msg1`, and so a msg1's candidate rekey). Their
  second limb, a peer's active path at the pair, stays on the bundles,
  since a record does not say which of its paths is active.
  The table keeps the lookup as a cache that every writer rebuilds;
  `derived` computes it afresh for the audit. Under `cfg(test)` it carries
  the node's audit count; `raw_index`, whose entries are put back at every
  rebuild until their link closes; `take_entry`, which takes a pair out
  past the writers; and `plant_entry` and `plant_path`, writes past the
  table, to its lookup and to a core record, that do not mark it, for the
  tests that the audit catches each. Its `resync` gives a record to each
  link a test put in the map, each link an index entry a test wrote names
  with none (as a link this node dialed, so no duplicate msg1 is answered
  on it, until the test puts the link in the map), and each peer planted on
  a link the map lacks, at the pair it is at, each held by the peer on its
  link; and `rebuild` names a test's index entries through the records
  (`Links::name`). A bundle a test mutator changed past the feed is not
  written: `links-mirror` skips its peer instead.
- `maps.rs`: `MachineMap`, the per-peer control machines with their timer
  store (`add`, `ensure`, `rekey`, `drop`, `get_mut`; `timers`, `arm`,
  `cancel`), `rekey` keying a moved peer's machine under the dial's link;
  `DialMap`, the dials waiting for their msg2 (`note`, `forget`); `LegMap`,
  the inbound handshakes waiting for their msg3 (`note`, `take`, `forget`),
  each recording the peer it is a candidate rekey of when its msg1 came
  from that peer's established link, so `take_moved` finds such a leg for
  a msg3 that arrived on another path of the peer's bundle while every
  other leg stays bound to its msg1's transport; `PeerMap`,
  the authenticated peers (`install`, `take`, and `get_mut`, `values_mut`
  and `iter_mut` for a change to a peer that leaves the map as it is); and
  `BindMap`, our session indices and the peer each names (`bind`, `unbind`).
- `decide.rs`: the node's steps of its table. Each decision site builds
  the core's input and hands it to `Node::decide` (or `decide_stamped`,
  for an input that opens a leg, which counts from the node's stamp),
  which steps `Node.core`, carries out the leases itself and returns the
  rest of the core's outputs for the site to carry out. At a msg1 the
  site resends the stored msg2 of the core's `Answer`, or records its
  `Reject`, before any crypto, and sends the msg2 of the answer the
  core's `Hello` makes; at a dial and a connect it takes the link the
  core opened (`opened`) and asks for the reconnects of the core's
  `Retry` at a failed connect. At its own dial's msg2 the site sends no
  msg3 when the core kept the held peer at once (`withholds`), and
  otherwise steps the dial's `PeerMachine` with the establish decision
  the core made at the msg2 and the msg3's send (`outbound`: an install's
  promote or restart, a move, a keep), falling back to next's own
  decision on a link the core does not number, which only a test makes.
  At an answer's msg3 the site steps the leg's `PeerMachine` with the
  establish decision the core made (`inbound`: an install's promote or
  restart, a move or a keep at a crossing, the peer's rekey, a repeat of
  the stored msg2, or a gate's refusal), falling back to next's own
  decision where the core made none.
  Elsewhere the site decides itself, after
  stepping the core: the link a step opens is
  returned for the link table to take under its number, and each lease
  the core hands back (`Free`, an install's, a rekey's) goes back to the
  machine of the leg it came from (`PeerMachine::give_lease`, onto the
  leg's msg3 read while one is unsettled, else onto the carrier) or to the
  allocator; the lookup is rebuilt after each step. A handshake's lease is
  so the core's from the dial or the answer until the core lets the leg
  go. The site helpers: `core_arrived`, `core_anon`, `core_hello`,
  `core_unasked` (an answer the node could not build) and `core_sent` at
  msg1; `core_dial`, `core_connecting`,
  `core_connect_failed` and, where the node retries an identified dial,
  `core_unconnected` at a dial; `core_flow` for the flow's msg2, msg3 and
  refusal inputs; `core_heard` at an authenticated frame; `core_remove` at
  a removal, which returns whether the core asks for the peer's reconnect
  (`Decided`, which the removal's run follows in place of the table's
  reconnect cell; the connections the core's retirement closes are left to
  the node's release of the paths and its cells); `core_pathed`, from the
  feed of a link's bundle; `core_tick` where the node's timers run, which
  where the node's stale sweep runs steps the flow's sweep of its failed
  legs and returns the retry it asked for each, by the node's link;
  `core_timed` (`In::Timed`), the retry a dial asks for as the node's
  timer reaps it alone, which the node notes; `core_reap`, a single leg's reap, where the
  node's own timer reaps that class of handshake (the table's poll, which
  would reap every leg past its deadline at once, is not run, so a dial's
  record lives as long as the node's link);
  `core_drop_leg`, a leg the node gave up for a cause the core has no
  input for, its record left for the node to retire with the link; and
  `tend`, what the timer driver did with a leg the legs asked it to
  resend (`Sent`, `SendFailed`, `In::Quiet`). In a test build `Replant`
  (`Node.replanted`, boxed) keeps what the resync of a test's planted
  state needs; the timers do nothing until the table takes its first
  input. `Node::replant` writes into the table what a test built past the
  sites: a record for a link it put in the map that the link table does
  not number; a held peer the table never held, on a planted node one on a
  link the node's map lacks held on a record of its own at the pair it is
  at; a held peer's facts a test set since the table last decided, an
  instant last heard stepped back or an epoch changed, which only the
  test-only writers do; and a leg for a handshake machine a test planted,
  holding its machine's lease, reaped when its carrier's idle timeout
  says and resending only where the test armed a msg1 resend timer (before
  the first input, only those).
- `params.rs`: the core's parameters from the node's configuration
  (`settle_params`, `leg_params`), and the XX flow's (`xx_params`), which
  the node's table takes.
- `audit.rs`: the coherence of the maps, one function per clause, each
  naming what breaks it, and `live`, which runs every clause and panics on
  the first that fails, naming the node entry and the clause. Compiled in
  test and debug builds only. The node tests' quiescent audit calls the
  clauses it shares rather than restating them; what holds only once a test
  is quiet stays there. In a test, `live` skips a node written past its
  writers, counts each audit on the
  node's link table, and records the
  audit's reach when `FIPS_AUDIT_REACH` names a file
  (`testing/check-audit-reach.py`). The `index-cache` clause, after the
  other index clauses, holds the link table's cached lookup to the one its
  records give now. The `index` clause counts the leases the node's
  handshake legs hold, and `leg-handshake` holds each leg to a handshake in
  flight on its link, so a leg left behind by an exit of its handshake is
  caught with its lease. The last clause, `links-mirror`, holds
  each held peer's core link record to its bundle, holding its paths,
  each in the state the bundle holds it, a switched-to path too, and its
  capable flag to the bundle's. A crossing at the msg3 that keeps the peer
  on its link renews the bundle there, and the renewal tells the record
  (`Node::run_renewed`, through `LinkTable::renewed`). It skips a peer a test
  mutator of the peer's paths changed past the feed
  (`ActivePeer::past_feed`, test builds only), and records each skip in
  the reach file, where the check holds them to a ceiling.
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
  written: each of the table's writers takes the records from the node's
  settlement core (`Node.core`), changes them, and rebuilds the lookup
  before it returns. Nothing else in the node writes the records, but the
  feed through the core's steps and the writers' own calls. A new way
  to change a record is a new writer that rebuilds.
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
  crossing's move at its two sites and `promote_connection`'s unreached
  tie-break replacement. `tests/scans.rs` holds the code to each, with
  its exemptions and their reasons.
  Its rule states what the code does today; a cell the code does not match is
  a wrong cell or a wrong site, and a change of what a transition does changes
  the cell and its golden line in the same commit.
- `exec/plan.rs` and `exec/mod.rs` deny wildcard arms as `table.rs` does,
  and a plan lists the statements it stands for in their old order: a
  reordering is a change of behaviour.
- Keep the file list in step with the directory.
