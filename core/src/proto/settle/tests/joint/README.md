# core/src/proto/settle/tests/joint

The joint world: nodes of the settlement world that run the settlement
core, a real rekey machine (`Rekey<Ik, TestClock>`, on the stub IK
profile) and a real path bundle per held peer. Everything here is test
code, compiled only in test
builds, and changes no line of the core, the machine or the bundle.

## Files

- `mod.rs`: declares the files below, and holds `Mode`, a joint node's
  multipath setting (`node.path.enabled`), with the rekey and path
  settings the node derives from it at the default configuration
  (`link_params`, `path_params`), read from their one statement in
  `../../parity.rs`, which a root test ties to the node's: the answer on
  a msg1's arrival path and the bundle's `enabled` follow the mode,
  everything else is the default's. It also holds the makers of a start's joint nodes (all at
  `Off`, all at `On`, and node 0 at one setting with the rest at the
  other), and the world's transports a node's facts are built over.
- `names.rs`: the world's identities on stub keys, and `NINTH`, the larger
  node of one of the driver's histories, chosen so that `A < B < C < NINTH
  < THIRD` holds for the keys' node addresses as for the world's numbers,
  each node's epoch written as the world's drivers write it;
  the names the ephemerals are drawn from (a msg1's from its handshake,
  a msg2's from the handshake it answers), so every ephemeral is a
  function of a world name; what an abstract far end (the model, the
  models of deployed nodes) sends on the wire, written from the name
  alone as that node's stub keys would write it; and `Names`, the
  one-to-one map from handshake names to the stub sessions they made.
  Each identity's key and node address are hashes, made once per process
  and read from there, since the shell asks for them at nearly every call.
  Its tests show the address order, that each abstract message is the
  bytes a joint end writes and makes the session of its handshake, that
  a frame opens only under its own handshake's session and direction,
  and that the stub profile selects the rows the link profile does but
  those a third message sets: where the link runs two messages, as the
  stub does, every row is the same; on a line whose link runs three, the
  joint world explores a two-message link.

- `facts.rs`: what a joint node's bundles read about the world: the
  facts of the world's transports (a stream or BLE transport is
  connection-oriented, BLE is a BLE binding and local, every transport
  is clear, Normal, and accepts and dials the peer, as at the node's
  default configuration), the world's addresses as the path machine's
  pairs, and each node's stream of path identifiers, which a bundle
  draws by a static call: `Stream::lend` sets a thread-local to the
  calling node's stream around each bundle call and takes it back after,
  so one node's draws never move another's.
- `machines.rs`: `Machines`, one held peer's rekey machine and bundle,
  and `Kit`, the node's capabilities they borrow per call (stub keys,
  index pool, epoch tags, jitter, scratch, path identifiers, transport
  facts). Every build, move and close goes through the core's join
  function (`../../join.rs`), which makes the machine calls in their
  order: `fresh` builds both at a link's setup, as the node does at
  promotion, and `held` does the same for a peer the core holds on a
  link, with the core input the join function gives for it (the original
  path, Live); `moved` closes the rekey machine, builds it again from
  what it carried and starts the bundle again at the pair moved to, as a
  cross-connection move does; `beside` builds the machines of a session a
  candidate rule moves the peer onto while it keeps this one, from what
  this one's rekey machine shows and a copy of its record, leaving it as
  it is, with the same core input as `held`; `close` closes both at
  removal, the bundle first; `msg1`,
  `reply`, `frame`, `poll`, `trigger`, `account` and `path` step them
  (`reply` hands every msg2 over as arrived on the link, so the rekey's
  cap on refused reads drops none), and `message` decodes a path
  message the peer sent, after its frame was accounted, and steps it
  into the bundle;
  `seal` seals a frame; `active` is the peer's address as the node
  treats it, the bundle's active path. Each returns what the machines
  asked for as `Event`s, in order: a prompt is sealed and a released
  lease freed into the pool on the way, a one-path roam (which the
  bundle reports in no output) is an event of its own, saying whether the
  path was a standby one, and everything
  else is the machine's output as it gave it. It keeps this node's own
  address for each path, since a path names only the peer's, and the
  address each candidate was offered from, for the path the bundle may
  admit it as in a later step. `account` also says whether the frame came
  from a pair no path holds and the roam did not follow it, which the
  heard feed reads. `key` is
  the machines' part of the explorer's key: every field of the rekey
  machine that can change (`Rekey::state`) and every field of the bundle
  (its `Debug`), since `view` and `bindings` leave out fields a
  successor reads (switches `KeyFromView`, `KeyOmitsBundle`). `quiet`
  turns off the rekey machine's own triggers for the driver
  (`../drive.rs`). Each bundle
  step runs the path shell's checks (`Checks`, from `../../path/tests/`),
  whose failures the shell takes (`failures`), and a test may plant a
  step's outputs for them (`plant`); a bundle output reaches the shell
  with each driver slot by its serial, the slots dropped once the checks
  have read the step, since nothing in the world reads a driver. Its tests
  show two peers' machines rekeying and cutting over to the session the
  world names for the rekey, a move keeping the record and the link's
  age and starting the bundle again (switches `MoveBuildsFresh`,
  `RenewSkipped`), and a disabled bundle taking a candidate as a poll
  where an enabled one holds it (switch `ModeIgnored`).
  `sealed` and `written` write what an abstract far end's frame is on the
  wire, with a counter per handshake the receiving node keeps (`party.rs`
  reads a model of the deployed node's frames this way), `matched` reads a
  pair as the node's `path_match` does and `eligible` the start floors.
  `../legacy/master.rs`, the model of the current node, runs its peers on
  the same `Machines` and `route`.
- `feeds.rs`: the node's feeds of path candidates and its rule on
  dialling a held peer. With multipath on, a held peer's configured
  addresses are offered to its bundle whenever the bundle starts again
  (an install or a move), an authentic frame from a pair the link holds
  no path at, not followed by the roam and no path message, is offered as
  heard (switch `HeardFeedDropped`), and a start's candidate act stands
  for the other feeds; each feed's pairs are listed so none is offered
  twice, and a request is always fresh. With multipath off nothing is
  offered. A capable peer whose link heard an authentic frame within the
  link-dead timeout is not dialled, its address held as a requested
  candidate instead; every other dial goes out. Its tests show an `On`
  pair turning capable on a heard candidate and holding a second path, an
  `On` end against an `Off` end staying not capable (`ModeIgnored`), the
  dial rule (by hand), a rekey answer on the arrival path at `On` and on
  the established link at `Off` (`ArrivalIgnored`, `ProvenCompared`), a
  closed connection on a link of two paths failing that path and keeping
  the link (by hand), and a path message roaming a one-path link at `Off`
  and not at `On` (by hand).
- `party.rs`: `JointParty`, a node of the world that runs the settlement
  core with a `Machines` per held peer. Its shell dials and answers with real stub IK
  messages carried beside the packets' abstract fields, keeps each
  link's handshake until the core installs it, builds the peer's
  machines at an install (the record taken from the node's record store,
  the setup noted for a responder), moves them at a move (onto the held
  link itself, from this node's address for the held pair, where the core
  keeps a peer on its link with the session of a handshake whose link the
  same step retires, as at a redial proven on the held link), closes them
  at a removal and files the record; hands a held peer's same-epoch msg1 to
  its machine and a replacement the machine asks for to the core's gates;
  takes frames by their receiver index through the machine, the bundle
  and the core's `Heard`, and a path message on to the bundle; seals the
  bundle's path messages under the current session and sends them on
  their path, from this node's address there, opens the connections the
  bundle asks for and tells it at a wake when each has settled (a list
  kept until the peer is removed, across a move, as the node keeps it);
  offers the bundles their candidates and decides a dial of a held peer
  as `feeds.rs` says; logs each msg1 with whether it came from a pair
  the bundle holds proven, and each frame with how many paths the bundle
  held and whether it is a path message at multipath on, for the shadow's
  comparison;
  polls the machines at their wakes, fires an
  own rekey through the machine's time trigger, and logs every history
  event with the class the machine's outputs give it, for the shadow,
  a switch of a held peer's active path and a path its bundle followed at
  a path message among them, so the model holds the peer where the bundle
  sends to it.
  A frame that names an index no machine binds is dropped as the node
  drops it, and a frame refused as a replay is not a broken promise:
  both are frames sealed under an earlier answer of the same handshake,
  which the world names as one session with the answer held now (one msg1
  answered again after the peer was removed, or in a later life), so the
  frame gate let them through; the name table and the keys still agree.
  A replacement or restart over another connection closes the replaced
  link's connections that no link uses, its paths' as well as its setup
  address's, as a dead link's are closed. It runs the node's liveness
  timer: a held peer whose rekey machine has authenticated no frame, under
  any session, for the link-dead timeout since that frame or the current
  session's start is removed as dead, and redialled if configured, unless
  this node's own rekey of it is in flight (`deadline`; `TimerNever`
  makes it never fire, which reds the timer's own tests here, the tests
  in `../regress.rs` that the split of a late second dial answered in the
  other order is ended by the timer and the redial within a heal, and the
  exemption of the model's missing timer in `explore.rs`, whose stale
  peering the timer leaves); at one path a close of the active
  path's connection removes the peer at once, which the timer would do
  within the timeout.
  It gives the joint world's oracles its facts (`Party::joint`): each
  peer the core holds beside what the shell holds for it, the lease each
  live leg holds by the shell's record of it, and what the pool and the
  machines hold; it notes a restart the core's gates refused, and each
  peer's first cutover, for one view of the peer; it counts, per step,
  the machine outputs the core must hear of and the inputs that told it,
  and judges each held peer's msg1 the core attributes. After each step it
  runs the machines' own oracles on each machine (as after a poll for one
  the step polled) and on the node, records the path shell's check
  failures of each bundle step, and around each msg1 handed to a machine
  and each copied reply compares the machine before and after, keeping per
  peer the list of ephemerals its record owes (carried across a move with
  the record) and when its own rekey started. A start's acts
  of a transport losing or regaining carrier and being removed go to
  every held peer's bundle.
  It names, for the exemption in `explore.rs`, the pairs its bundles hold as
  acknowledged paths that are not Live (`Party::lapsed`), and for the
  shared schedules whether the core counts a held peer heard
  (`Party::heard`).
  Under a candidate rule (`../candidates.rs`) the core may keep the
  session a peer is held on beside its next one: the shell then keeps
  that peer's machines and what it holds for it in a kept slot,
  receive-only (never polled and never sent on), builds the machines of
  the session a move goes to beside them (`Machines::beside`), hands a
  frame under the kept session to the core as a held frame and then to
  the machines the core settles the peer on, tells the core when the
  kept link's connection closes, and closes the kept machines or the
  ones held instead when the core settles. A kept session counts in the
  node's indices, its frames pass the world's gate, and its machines are
  keyed; it is compared with the model only under the dialer's rule,
  which the model encodes.
  Its digest, the explorer's key, names every field of the node's state
  one by one, keys each peer's machines by `Machines::key`, and leaves
  out only the kit's scratch buffer, which a machine writes before it
  reads, and the per-step lists drained before the next step.
  Its tests show a connection-oriented crossing leaving the smaller node
  at its dial's pair (switch `MoveKeepsOldPair`), a crossing settling on
  one session (`MoveNoReset`, `IndexStale`), a rekey cutting over at both
  ends and draining (by hand), sends staying on the active path after a
  frame from another transport (by hand, with `HeardMovesPeer`, since the
  core's record of where the peer is now follows the bundle and sending
  by it changes nothing alone; the send rule, `to` reading the bundle's
  active path, has no switch of its own, a coverage gap), a restart
  revealed at a
  rekey reaching the core (`RestartDropped`), a fresh msg1 on a young
  link reaching the gates (`ReplaceDropped`), a one-path roam reaching
  the link record (`PathsUnmirrored`), a peer silent for the link-dead
  timeout removed then and redialled, and the two crossings of start 3
  at On with On that leave one end holding a link of two paths whose
  connection failed healing once its timer removes the peer, the other
  end's redials lost until then (both by hand), every start but 6 and 7
  settling
  by its script (`MoveKeepsInboundLink`), and starts 6 and 7 showing their
  two shapes on real machines (`OneSessionNoFresh`, `OneSessionNoPending`):
  start 6's split, the accepted behaviour the link-dead timer and the
  redial end, and start 7's pending, the aged-link defect left for a
  later fix.
- `oracle.rs`: the joint world's own oracles over what a joint node
  gives (`Facts`, from `Party::joint`), checked at every step by the
  settlement oracles' `every_step`: one view of each peer the core holds
  (one rekey machine, built or carried at the install of the link the core
  holds the peer on, whose proven identity is the peer, whose record of
  the peer's startup epoch is the core's unless the core's gates refused
  the restart the machine found, and which until its first cutover runs
  the session of the install's handshake), the leases (the indices the
  pool handed out are exactly those the live legs and the machines hold),
  and no orphan machine (machines for every peer the core holds and for no
  other). Its tests show each on a schedule that reaches it: a restart
  found at a rekey and a restart replacement (switches `RestartDropped`,
  `ReplaceKeepsMachine`), a move (`MoveBuildsStale`), a crossing whose
  larger node's dial lease the core hands back (`LeaseForgotten`) and a
  removal
  (`CloseSkipped`), and that one view fires on each planted disagreement.
  It also checks the paths mirrored (each held link's paths in the core
  are its bundle's, with the state the shell reports, and the index is
  derived from the records), every output delivered (each replacement
  request, restart and teardown of a rekey machine and each orphaning of
  a bundle reached the core in its step, by the shell's per-step
  `Ledger`, and nothing else fed those inputs) and attribution (each held
  peer's msg1 is on the link to the core exactly where the node's rule
  puts it, the index naming the newest link at a pair as the node's does,
  judged by the shell when the core decides). Two clauses are
  pinned, not asserted, since the core parted there from the bundle or
  the node: the core's record of where the peer is against the bundle's
  active path, which the core now moves only where the bundle moves the
  peer, at a roam of its one path, a follow of the path the peer is at, or
  a switch; and the shapes of
  attribution where the core's rule was wider (a capable peer's setup
  pair with no path, a pair no index entry and no proven path holds, a
  setup pair whose path is probing), which the core's rule no longer
  shows. The mirror of the paths is asserted whole, a switched-to path in
  the state its bundle holds it. `pinned_in` lists the pinned clauses,
  and `pins.rs` holds a test of each shape. Its tests show the mirror at
  a roam and at a second path (`PathsUnmirrored`, `StateIgnored`), delivery of a
  replacement request, an orphaned bundle and a restart found at a rekey
  (`ReplaceDropped`, `OrphanKept`, `RestartDropped`), and attribution of
  a msg1 on a roamed one-path link (`AttributeBySetupOnly`).
  The machines' own oracles run through the predicates their simulators
  call: after every step each rekey machine's bounded memory and key
  retention, and after a poll its deadlines (`machine`), and the node's
  indices conserved against its machines' bindings and its legs (`node`);
  around each msg1 handed to a machine and each copied reply, that a msg1
  the record owes arms no pending, that a repeat changes nothing and that
  a copied msg1 that arms a pending, the accepted residual, adopts,
  confirms and refreshes nothing (`took`); the path shell's checks on each
  bundle step; and once healed each pair's machines converged, in the
  settlement oracles' `healed`. Its planted tests show each predicate
  firing on a planted reading, delivery or output through these
  wrappers.
- `starts.rs`: the named starts (`../starts.rs`) with joint nodes at both
  ends, at Off with Off and at On with On. A start keeps its script, but
  for the start with two paths, which `../starts.rs` writes with no
  paths, for the model: it is rebuilt on real bundles. Beside them, the
  starts only joint nodes run, each built mid-history on real bundles:
  rebuilt start 12, node 1's second dial opened before the capability
  exchange, its connection the one its bundle's second path then uses,
  and its resend arriving from a pair node 0's link holds as a Live
  path; start 15, the crossing over two transports with one end's
  capability probes due and neither end capable when it resolves; start
  16, a restart on a link of two paths whose dial arrives from the second
  path's pair; start 17, a late second dial of a capable peer, which the
  dial rule holds back at On with On and the peer's gates refuse where it
  goes out; start 18, two dials of one peer sharing a BLE connection, the
  first reaped at its deadline with the second out; start 20, the active
  path's transport losing carrier, then the bundle's mandatory switch;
  start 21, the only path's transport removed, the link orphaned and the
  peer redialled on the other; start 22, on one transport with each
  node's second address the source of a second path, a NAT rebinding that
  path's address at the peer; start 23, the peer's transport of the
  second path removed, so its bundle releases the path and tells this
  node; and start 25, start 22's link with the NAT rebinding the peer's
  home instead, the address of the active path, which the bundle follows
  at the peer's next path message on it, moving where the peer is with no
  roam. A two-path start runs the capability exchange in its build
  (`walk`, `exchange`), which turns both ends capable within a few wakes
  at On with On and leaves the link its one path at any other pairing, so
  each start runs at all four. Its tests show the crossing with the probes
  due renewing the moved bundle and both ends staying mirrored
  (`RenewSkipped`), the carrier loss and switch mirrored
  (`StateIgnored`), the orphaned link removed and the redial settling
  (`OrphanKept`, `OrphanedIgnored`), the rebound path moved in the link
  record (`PathMoveIgnored`), the rebound active path moving the peer
  with no reset, and the model told of it (`FollowResets`), the released
  path leaving it
  (`ReleaseKeepsPair`), and the reaped dial's retire keeping the
  connection the dial still out uses, read at that step
  (`CloseByPeerAddress`).
- `explore.rs`: the settlement world's explorer on the joint starts,
  where it serves two checks: that two worlds stepped in turn along one
  path have one digest, so no node's path identifiers move another's (by
  hand: the streams made one per process); and that a state differing
  only inside a machine, in a field neither `view` nor `bindings` shows,
  has its own key and its own successors (`KeyFromView`,
  `KeyOmitsBundle`). And the exemption of a healed leaf's breaches: a
  split a known shape left (`oracle::by_shape`), the breach `pins.rs`
  holds of a connection-closed pair the node's bundle holds as an
  acknowledged path that is not Live (`lapsed`), and what the model's
  missing link-dead timer leaves beside a joint node (`untimed`): the
  model still holds a joint node whose timer removed it after the link's
  frames were lost, and refuses every redial (one off the link of a
  peering it has not heard from, while that link can be reached), so the
  joint node holds a configured peer it cannot reach and the model keeps
  the refused redial's connection open. A node runs the timer too; two
  joint nodes never reach it. A test shows the pinned breach exempted by
  its cause and a settled, capable pair not, and builds the model's case
  by hand, the model answering one dial on UDP from a joint node
  configured with its TCP home, showing the exemption spares that world's
  two breaches and nothing else in it. The reaches and sweeps of every
  start at each pairing, and the core's own explorer on joint nodes, were
  retired.
- `pins.rs`: pins of what the joint world found. A known-defect pin is
  ignored, listed in `testing/ignored-tests.txt` and run by the
  known-defect lane, which reds when one passes; the fix that turns one
  green un-ignores it in the same change, and it then runs in every
  build. Ignored today, one: a proven second path
  whose connection fails: the bundle asks for a connection only for a
  path it admitted or whose connect failed, so the path stays
  acknowledged with no connection until its Dead grace ends, and the link
  counts a pair it cannot reach (start 2 at On with On). And one for each
  pinned clause of the joint world's
  oracles, in the unwired core, each now met by the core and run in every
  build: a frame from another transport leaves the core's record of where
  the peer is at the active path (start 2 at Off; `HeardMovesPeer`); a
  switch moves that record to the new active path (two paths at On,
  carrier lost on the active one; `SwitchLeavesPeer`); a switch to an
  acknowledged Suspect path leaves it acknowledged (the carrier lost on
  one path and the other's transport removed; `SwitchWritesLive`); a
  capable peer's msg1 from the setup pair,
  whose path its transport's removal took, is off the link to the core,
  as it is to the node, since the transport's removal released the path
  there and took the pair out of the index, a shape that now needs
  `SwitchLeavesPeer` and `AttributeByCurrent` both, so it is
  characterisation; a msg1 from the pair a frame
  from another transport came from is off the link to the core (start 2
  at Off), as is one from a pair whose path the bundle still holds
  probing (start 2 at On with On, found by a sweep since retired),
  shapes that now need `HeardMovesPeer` and `AttributeByCurrent` both,
  so they are characterisation too; and a crossing in which the smaller
  node's own dial is answered over the larger node's dial connection,
  from the larger node's second address (the named start with two paths
  as `../starts.rs` writes it, its nodes joint nodes), keeps that connection
  open, since the moved-onto link's record takes the pair before the
  inbound link is retired (`MoveClosesNewPair` puts back the close, after
  which both ends lose the link and redial).
- `runs.rs`: the per-start runs the switches' rows name, each the
  cheapest test that shows a guard can fail in a world of joint nodes:
  every start's script with its heal at On with On (its twin at Off with
  Off is `party.rs`'s), which reds fourteen of the core's switches at
  both settings and `HeardMovesPeer` at On with On alone; and two rekey
  schedules no named start's path holds,
  written out step by step: simultaneous rekeys whose msg1s both arrive
  before either answer, settling on the smaller node's (the rekey
  machine's switch `LargerKeepsOwn`), and a rekey msg1 refused once from
  a pair the link holds no path at and refused again when the same msg1
  comes on the link (`RefusalUnrecorded`); and, at Off with Off on the
  aged-link start in the flipped address order, a copy of a rekey msg1
  the smaller node answered, reaching it after it moved onto its dial's
  session, which the machine refuses as answered before
  (`CloseSkipsRecord`).
- `parity.rs`: the shared schedules (`../../parity.rs`) run in the
  world, each step translated one for one into the world's events, and
  each end's mark read from the party after every step: on the model of
  the node (`../legacy/master.rs`, at the setting the script states),
  which must give the trace's lines, and on joint nodes, which must give
  them with the trace's `core` lines applied. Each run fails if it walked
  fewer scripts than there are. Both are on the rows of the two switches
  a mark shows, `MoveBuildsStale` (whose dial the session came from) and
  `RenewSkipped` (the active pair, on a crossing whose dials' pairs
  differ); `MoveBuildsFresh` changes nothing a mark holds, so it keeps its
  own row.
- `route.rs`: `route`, which turns one call's machine events into what
  the shell sends (an own msg1, a reply by its route, a sealed prompt, a
  path message, a connection the bundle asks for),
  the core inputs they stand for, in order, each as the core's join
  function (`../../join.rs`) gives it (a bundle output as the path input
  it mirrors, a one-path roam as `Moved`, marked a roam unless the path
  was a standby one, and a bind as a Live path, a
  restart revealed as `Restarted`, a teardown as `Ended`), and what the
  call decided (a
  replacement asked for, a cutover, a refusal, a yield, a frame's
  plaintext); it keeps the node's index map as `Bind` and `Unbind` say,
  and holds no party state. An orphaned bundle becomes `Orphaned` (switch
  `OrphanKept` drops it). Beside it are what the driver (`../drive.rs`)
  shares with a joint node: what the core is told of a msg1 (`read`), its
  answer, built only once the core asks for it (`asked`, `answer`), a
  msg1's class in the model's names from what its call routed
  (`class`, which the model of `master` reads too), and the leases of
  outputs nobody carries out (`discard`).

## Rules for changing it

- A joint node always states its `Mode`. Nothing here reads a default
  setting: `node.path.enabled` changes with a release, and both settings
  ship.
- Name the next ephemeral before every call that may write one, with the
  name `names.rs` gives for it, so a resend is the same bytes and the
  order of answers changes no later key. `Machines` names it for each
  call it makes; a shell writing a handshake message itself names it the
  same way.
- `Machines` holds no settlement state and decides nothing: it carries
  out only what needs no more than the machine and the node's own
  capabilities, and a shell routes everything else.
- The peer's address, wherever the shell sends to the peer, asks whether
  its link is reachable or counts what its link uses, is the bundle's
  active path (`Machines::active`), never the core's `Held.current`;
  `Held.current` is read for the oracles' view alone.
- `../mod.rs` holds this directory to three scans of its own, beside the
  coverage scans: no file defines a `set_` method, no file names the
  wildcard-arm lint (it is denied at the settlement root, and a match over
  a machine's or the core's outputs names every arm), and the core's
  record of where a held peer is, read through the name `h` the shell
  binds the core's `Held` to, is read only in the functions the scan
  lists (the view, the joint oracles' facts and attribution's judge). A
  new reader goes on that list with its
  reason, or reads the bundle's active path instead.
- The core's record of a link's paths is written only by the bundle's
  outputs and the roam, through `route`.
- A frame the world let through because `holds` said so and that the
  machine then refuses is a broken promise, reported as an incoherence
  of the maps, as is an index map that differs from what the machines
  bind and a frame naming another peer's index. A frame refused as a
  replay, or naming an index no machine binds, is not: the world names
  two answers of one handshake as one session, and the stub keys make
  them one too, so such a frame belongs to an earlier answer.
- A bundle call draws path identifiers only inside `Stream::lend`; a
  draw outside one panics.
- A field added to a joint node's state, or to what a machine keeps, is
  keyed by the node's digest unless a reason it can never change a
  successor is written beside it: a field the key leaves out merges
  states the explorer must keep apart.
- What an abstract end sends is stub crypto, a function of world names:
  no decision goes in `names.rs`.
- A change to the link profile's constants reds
  `the_stub_profile_selects_the_rows_the_link_profile_does_but_those_of_a_third_message`:
  the joint world stands for the link only in the rows the stub selects
  alike, which on a line of a three-message link leave out the third
  message's.
- A pin asserts what the node does, fails today at an assertion whose
  message starts `defect:`, and checks the shape it needs with
  `precondition:` assertions; it lands with its `known-defect` line and
  its characterisation entry, and the fix removes all three.
- The lanes: the scripted runs, the feeds, the pins and the explorer
  checks run in every build. The reaches and sweeps that walked the
  joint starts, and the core's own explorer on joint nodes, were retired;
  whether one returns is an open decision.
- Tests here follow the settlement tests' coverage rules
  (`core/src/proto/settle/tests/README.md`): each needs a switch's row, a
  self-checked entry or a characterisation entry in `../faults.rs`, in the
  commit that adds it.
