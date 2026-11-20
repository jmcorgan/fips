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
  `planted`, the re-exports `Node` uses, `Legs`, the settlement core's
  handshake legs as the node holds them, and the three `Node` methods of
  this level: `audit_live`, which each node entry that can change a map
  calls on its way out (the audit in a debug build, nothing in a release
  one), and, for tests, `plant` and `planted`.
- `links.rs`: `LinkTable`, the node's links and the reverse lookup from a
  `(transport, address)` pair to the link at it (`open`, `close`, `forget`;
  the path driver's `follow`, `claim` and `unclaim`; `get_mut`; `index` for
  reads of the lookup, and under `cfg(test)` `raw_index`). Its doc carries
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
  (`Node.legs`, the core's `Legs`, keyed by the same numbers) at the
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
- `RedialMap`, in `maps.rs`: the pending redials, one per held identity at
  most, each naming the inbound link its leg runs on, the index its msg2
  named and when it was armed, beside the memory of the msg1 ephemerals that
  armed one in the last 15 s. An entry is written when a redial is armed
  (`handlers/redial.rs`) and forgotten when its machine is removed or its
  link promoted. The `redial-leg` clause holds each entry to a leg still at
  `Handshaking{ReceivedMsg1}` for that identity and index, an index no peer
  is bound to, on an open link.
- `params.rs`: `settle_params`, the settlement core's parameters for a
  node's configuration: the core's defaults with the handshake timeout,
  the msg1 resend interval, multiplier and count, the cap on answers in
  flight and the max-peers cap taken from the configuration, and nothing
  else, so the gate constants stay the core's; and `leg_params`, the same
  for the node's own handshake legs (`Node.legs`), with the deadline one
  millisecond later, since the node reaps a leg once it has been idle
  longer than the timeout in whole milliseconds and the core reaps at its
  deadline. The node's restart gates (`Node.gates`, the core's `Gates`)
  read `settle_params`. The shadow below, the only reader that steps a
  whole table yet, reads `leg_params`, so its legs, opened at the instant
  the node stamped its own, are reaped at the node's tick.
- `decide.rs`: test builds only. `Shadow`, the settlement core beside the
  node (`Node.shadow`): a copy of the core's `Table` that each decision site
  feeds the input it would build, after its own decision, through
  `Node::decide` (or `decide_at`, for an input that opens a link, whose
  number then names the node's link) and `Node::shadow_tick`, the one callers of
  the shadow's `Table::step` and `Table::poll` (`shadow_tick` runs where the node
  resends and reaps its dials, in `drive_peer_timers`; a leg the node
  reaps at its deadline, at its dial timer or in the stale sweep, the core
  reaps by its own poll's reap of that leg at the node's instant plus the
  legs' skew, `shadow_reap`, and a leg it still holds then is the
  comparison's to find; a leg the node gives up for a cause the core has
  no timer for, a failed connect, a traversal's adoption or a test, is
  fed as given up, through `shadow_abandon`, and an answer whose msg2
  could not be sent at all through `shadow_unsendable`), and the site
  helpers built
  on them: `shadow_abandon`, `shadow_unsendable`, `shadow_reap`,
  `shadow_unasked`, `shadow_hello`,
  `shadow_sent`, `shadow_remove` and, from the feed of the node's own link
  records, `shadow_feed`. The shadow decides nothing: of its outputs it runs
  only its own bookkeeping, its numbers for the node's links and its
  leases, which are `IndexLease::for_test` of the index the node drew,
  counted minted and released in `Leases`; a dropped node closes its
  shadow and releases what its legs and installed peers hold. Feeding it
  writes nothing of the node's. `Node::shadow_resync`, which `decide` and
  `shadow_tick` call first, the live audit calls before it compares, and the
  node's `resync` calls before it clears the test mutators' flags, writes into the shadow what a test wrote past the
  writers on a planted node (its links and index entries); on any node, a
  held peer by its facts, through the core's `Table::plant` (and, on a
  planted node, a peer a test planted afresh on a link the shadow does not
  number, over one the shadow holds, whose old record goes when the
  node's map lacks that link), and a
  handshake machine as a leg reaped and resent at the machine's own
  instants (`audit::leg_times`), where a test built either past the decision
  sites (a seeded machine, a peer installed directly); and the paths and
  facts of each peer a test mutator or setter flagged, a peer taken by its
  facts bringing its bundle's paths to its link's record (an unheard peer
  holds no last frame, whatever a backdate did to its instants, so its end
  counts as silent in the core as in the node); and, on any node, a
  link a test opened through the table's writer but past the sites (a dial
  noted with no handshake), as a record held as a leg. A link a decision
  site named as the one its input opens is never taken for a plant, nor a
  link whose record the shadow retired, by its own timers or at an input,
  while the node still holds it, nor a peer on such a link. `shadow_gates`
  gives the shadow's restart gates, through their writers, what a test
  wrote into the node's own restart gates past its decisions. `shadow_link`, the
  site helpers' lookup of the shadow's number for a link, resyncs first.
  `Node::did` records what the node did in the words it shares with the
  core (`exec::Did`), at each transition `Node::run` or `run_promotion`
  runs, each reconnect noted, each refusal, ask and answer of a msg1 (a
  stored answer resent for a duplicate msg1 is recorded when the node
  decides it, and its send is then told to the shadow as sent or failed;
  a msg1 the rate limiter refuses, the node's resource admission, is neither
  fed to the shadow nor recorded), the
  refusal of a promotion at the max-peers cap, and a crossing's swap; the
  shadow records what it decided beside it, and the live audit compares
  the two. `Node::closed` records likewise each connection the node closes
  where a decision closes one (`close_pair`, a removal's close, a queued
  release, a refused own dial), and the shadow each pair its outputs close
  (`Shadow::closes`). `line` appends to the file `FIPS_CORE_SHADOW`
  names, if any: a test's first difference, and at each node's drop a
  `seen` row counting the inputs of each kind its shadow took.
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
  each held peer's core link record to its bundle, capable when the bundle
  is and holding its paths, each in the state the bundle holds it, a
  switched-to path too; it skips a peer a test mutator of the peer's paths
  changed past the feed (`ActivePeer::past_feed`, test builds only), and
  records each skip in the reach file, where the check holds them to a
  ceiling. In a test, after `index-cache`, five clauses compare the shadow
  settlement core with the node, on every node, a planted one included,
  which the node's own clauses skip: `core-agrees`, what the node did
  since the last audit against what the shadow decided, order aside;
  `closes-agree`, the connections the node closed since the last audit at
  the close sites its decisions reach (each calls `Node::closed`) against
  the pairs of the shadow's `Retire`, `Release` and `Close` outputs, each
  pair once, order aside, the connect's and the BLE sweep's closes and the
  drain's second look at a queued close being the shell's and not
  compared; `links-agree`, each link's record, by setup pair, direction, holder,
  paths and capability, passing over a link the node's table has not
  recorded, a planted peer's link the link map lacks, a link the node
  records from a planted index entry with no link in its map, and the link of a
  peer a test changed past the feed until the node's resync takes the
  change; `gates-agree`, each identity's dampener stamp,
  aged on the peer clock, replay memory and silent sessions, between the
  node's restart gates (`Node.gates`) and the shadow's; and `legs-agree`, each handshake's
  end, identity, resends sent, whether more may follow, deadline, whether
  a resend is due at the next tick, and when the next is, its instants
  on the interval clock within a quarter second (a resend due on one side
  only agrees while its two times are within that skew). While the node's timers
  run (`drive_peer_timers`) the shadow decides, and `legs-agree` compares,
  at the instant they run at, which a test may give in place of the
  clock's (`Node::shadow_clock`). The shadow decides a dial and an answer
  at the instant the node stamped the leg (`Node::decide_stamped`), so
  the work between, a Noise step among it, never shows as a difference
  however long it takes. A fifth clause, `placement-agrees`, runs
  at the one question the node still asks of a msg1's source before any
  Diffie-Hellman by its own reading, the duplicate msg1 check's read of the
  index, rather than at the audit, since what it reads moves before the
  next one (`audit::placed`): the node's answer against the one
  `Links::placement` gives over the node's own link records
  (`Node::placement`), which already answer the node's other attribution
  questions. A test's first difference is one line
  to `FIPS_CORE_SHADOW`, with a reach row `diverged`, and the node is
  compared no further; and unless `tests/shadow.txt` lists it by test,
  site and clause (`SHADOW_KNOWN`, read by `known`), it fails the test
  when the node is dropped (`Shadow::fail`), and not before, so a test
  that breaks the node fails at its own assertion first; and not at all
  while a switch of the mutation lane is on that the settlement core does
  not read (`node_broken`, against `CORE_READS`, which a scan of the
  core's settlement sources holds to them), since the node it breaks is
  then not the spec. The exception is a node-side site switch whose break
  the comparison is to fail a test on (`SHADOW_REDS`: `CrossedRunsKeep`).
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
