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
  `open_leg`, an inbound handshake's msg1, which records the link a taken
  pair named so that `close` hands the pair back; `award`, a crossing's
  winner taking the pair; the path driver's `follow`, `claim` and `unclaim`;
  `get_mut`; `index` for reads of the lookup, and under `cfg(test)`
  `raw_index`). Its doc carries the warning about the lookup's key form. In
  test and debug builds it also holds each link's waivers (`Waiver`), the
  states the audit lets off, recorded at the event: `close` and `forget`
  record the one `held-entry` honours, on a link their removed entry
  shadowed; and the two crossing arms, in `handle_msg2` and at msg3 in the
  executor, record the ones the quiescent audit asks for. Under `cfg(test)` it
  carries the node's audit count and `plant_entry`, a write past the table that
  does not mark it, for the test that the audit catches one.
- `maps.rs`: `MachineMap`, the per-peer control machines with their timer
  store (`add`, `ensure`, `drop`, `get_mut`; `timers`, `arm`, `cancel`);
  `DialMap`, the dials waiting for their msg2 (`note`, `forget`); `LegMap`,
  the inbound handshakes waiting for their msg3 (`note`, `take`, `forget`);
  `PeerMap`,
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
  (`testing/check-audit-reach.py`).
- `table.rs`: `Transition`, each thing the code does to a held peer; `Row`,
  each piece of what the node holds per peer, with `DataRow` for the peer's
  record; `Cell` and `DataCell`, what a transition does to a row; `Owner` and
  `Facet`, who holds a row; and `cell`, `data_cell` and `owner`, the rule as
  nested total matches. The peer's record settles by `data_cell`, and the
  rekey handler marks the filter at a cutover by `cell`; the other rows wait
  for their sites to be routed.
- `plan.rs`: `Effect`, one step the node takes for a transition, `plan`, the
  effects of each transition in their order, and `Node::run_plan`, which runs
  them on a held peer. A restart found at a rekey runs from here; a
  transition whose list is empty runs its own statements at its site.
- `tests/`: the unit tests of this level; its own README names each file.

## Rules for this level

- No wrapper implements `DerefMut`, and no wrapper hands out its inner map
  outside `cfg(test)`. `src/node/tests/survivors.rs` scans this directory for
  both; a direct write to an inner map does not compile.
- A new write to a map is a new writer here, named for the event, not a
  wider accessor. A writer transcribes; a change of what an event does to a
  map is a change of behaviour and is made, and tested, as one.
- The link table's lookup is written, not derived from the links: its
  single-valued keys and its gaps (an entry a later dial overwrote, a pair a
  forgotten dial emptied) are today's behaviour, and a writer keeps them.
- `raw` and the other `raw_*` methods are for tests that build a state no
  writer builds. They set the wrapper's `planted` flag, which marks the node
  as written past its writers, and the live audit skips a marked node for
  the rest of the test. A test that can build its state through the writers
  uses them: every mark costs the audit that node. `testing/check-audit-reach.py`
  holds the share of audited nodes to a floor.
- A waiver is recorded where the state is made, computed from the maps at
  that event, never inferred by the audit.
- A clause states a rule that holds between any two node entries, mid
  handshake included. A rule that holds only at quiescence belongs to the
  quiescent audit in `../tests/settle/audit.rs`, not here.
- `table.rs` denies wildcard match arms and holds none, so a new row,
  transition or cause does not compile until it has taken a side at each cell.
  Its rule states what the code does today; a cell the code does not match is
  a wrong cell or a wrong site, and a change of what a transition does changes
  the cell and its golden line in the same commit.
- `plan.rs` denies wildcard arms as `table.rs` does, and a plan lists the
  statements it stands for in their old order: a reordering is a change of
  behaviour.
- Keep the file list in step with the directory.
