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
  `planted`, the re-exports `Node` uses, and the three `Node` methods of
  this level: `audit_live`, which each node entry that can change a map
  calls on its way out (the audit in a debug build, nothing in a release
  one), and, for tests, `plant` and `planted`.
- `links.rs`: `LinkTable`, the node's links and the reverse lookup from a
  `(transport, address)` pair to the link at it (`open`, `close`, `forget`;
  the path driver's `follow`, `claim` and `unclaim`; `get_mut`; `index` for
  reads of the lookup, and under `cfg(test)` `raw_index`). Its doc carries
  the warning about the lookup's key form. `used` is the node's close rule:
  whether a live link other than the one closing uses a pair, a held link by
  its bundle's proven paths and any other by its setup pair. `Node::in_use`
  asks it with each held peer's bundle, and `Node::close_unused` closes a
  link's setup pair only when it answers no. The lookup is
  derived from the settlement core's record of each link (`Links`), kept
  under the core's number for it (`no`): opened and retired with the link,
  held for a promoted peer (`hold`), and fed what the link's bundle reports
  (`mirror`) from `exec/links.rs`. It names each live link at its setup
  pair, which on this line stays named after the bundle releases the path
  there, and at each Live or acknowledged path of its record, the newest
  link where several use a pair. An inbound leg that takes a pair at msg1
  so names it while it lives, and the pair goes back to the link named
  there before once the leg is closed. `holder` says who holds a link, its
  leg or a peer, for the anonymous-beacon dedup, which skips a beacon only
  at a pair naming a handshake in flight or a live held peer's link.
  The table keeps the lookup as a cache that every writer rebuilds;
  `derived` computes it afresh for the audit. Under `cfg(test)` it carries
  the node's audit count; `raw_index`, whose entries are put back at every
  rebuild until their link closes; `take_entry`, which takes a pair out
  past the writers; and `plant_entry` and `plant_path`, writes past the
  table, to its lookup and to a core record, that do not mark it, for the
  tests that the audit catches each.
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
  records give now. The last clause, `links-mirror`, holds
  each held peer's core link record to its bundle, letting off only the
  active path a switch recorded Live while the bundle holds it
  acknowledged; it skips a peer a test mutator of the peer's paths changed
  past the feed (`ActivePeer::past_feed`, test builds only), and records
  each skip and let-off in the reach file, where the check holds them to a
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
