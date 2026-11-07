# src/node/settle

One owner for each of the node's per-peer maps. The module is
`node::settle`, declared in `../mod.rs`; `Node` holds each map as a field
whose type is a wrapper defined here.

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
  `planted`, and the re-exports `Node` uses.
- `links.rs`: `LinkTable`, the node's links and the reverse lookup from a
  `(transport, address)` pair to the link at it (`open`, `close`, `forget`;
  the path driver's `follow`, `claim` and `unclaim`; `get_mut`; `index` for
  reads of the lookup, and under `cfg(test)` `raw_index`). Its doc carries
  the warning about the lookup's key form.
- `maps.rs`: `MachineMap`, the per-peer control machines with their timer
  store (`add`, `ensure`, `drop`, `get_mut`; `timers`, `arm`, `cancel`);
  `DialMap`, the dials waiting for their msg2 (`note`, `forget`); `PeerMap`,
  the authenticated peers (`install`, `take`, and `get_mut`, `values_mut`
  and `iter_mut` for a change to a peer that leaves the map as it is); and
  `BindMap`, our session indices and the peer each names (`bind`, `unbind`).
- `tests.rs`: each writer against the statements it transcribes, and the
  rule that only the ways past the writers mark a map.

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
  as written past its writers. A test that can build its state through the
  writers uses them.
- Keep the file list in step with the directory.
