# src/node/tests/settle

Peer settlement tests on real nodes: how two nodes that dial each other,
restart, or rekey end up holding one session on one link, and what each node
keeps per peer across those changes. The module is `node::tests::settle`,
declared in `../mod.rs`; it runs in nextest's `node-synthetic` group (a
`settle` override in `.config/nextest.toml`), because some of its files open
real TCP sockets.

## The multipath setting

Every test here states `node.path.enabled` and takes nothing from the daemon's
default, so a change of default changes none of them. The tests of
`crossing.rs`, `audit.rs`, `explore/` and `table/` run both ways: a test's
plain name runs multipath off, and its `_with_multipath_on` sibling runs it
on. They are two tests and not one loop, since a pin that fails in a loop's
first pass would never reach the second, and each pin has a line of its own
in `testing/ignored-tests.txt`. `readings.rs` runs on, but for its one test
named for off, and `cells.rs`'s heard crossing runs both ways. The other
files run off, which is what they test.

## Files

- `mod.rs`: the module declarations, the module doc, and the drivers the
  files share: the multipath setting (`with_path`, `loopback_node`), real TCP
  nodes on 127.0.0.1 (`tcp_node`, `tcp_pair`, `tcp_dial`, `resolve_connect`,
  `pool`), crossed TCP dials (`crossed_tcp`),
  delivery until idle for loopback and TCP nodes alike (`pump`), a fresh
  heartbeat check (`heartbeat_reaches`), the check that two nodes hold one
  session that carries a heartbeat each way (`settled`), and the wrappers
  over shared helpers whose signature or key multipath changed
  (`bind_index`, `alias`, `tap`): the session-index map keyed by the bare
  index, and loopback addresses registered under their transport. A
  wrapper's body is the one place such a change is made.
- `audit.rs`: the shell audit. `audit(nodes)` reports every breach
  of four properties over real nodes, after running
  `link_index_audit::audit` on each node (which panics on its own);
  `assert_coherent` fails the test, marked `defect:`, on any breach. The
  file's doc names each property and what it can and cannot see. Its tests
  show the audit passes coherent states and fires on a planted breach of
  each property it reports. Where a property is also a clause of the node's
  live audit (`src/node/settle/audit.rs`), it calls that clause.
  `assert_coherent` is visible to the rest of `node::tests`:
  the crossing, restart, rekey-move, stored-msg2 and BLE crossing tests
  call it at their end, where both nodes hold each other and are quiet.
- `bounds.rs`: a pending dial sprayed with 1000 forged msg2s, garbage or
  replayed: the dial is kept, no handshake or per-peer map grows, and the
  genuine msg2 still completes the dial. How many forged msg2s are read is
  not asserted.
- `carry.rs`: per-peer state across a change of the peer's link or
  session: a new or restart-replaced peer is sent a TreeAnnounce at once, a
  redial answered as a rekey resends the filter (both orders), a restart's
  msg1 releases the clamp entry of the session it clears, and, over the BLE
  mock, the initiator's link is verified when it promotes on its msg2.
- `cells.rs`: five per-peer cells a settlement change has to decide:
  characterisation tests (`chartest_`) of three, each asserting what master
  does today, and the tests that replaced the other two's when those cells
  moved, with a coverage map in its module doc. The characterisation tests
  are evidence, not coverage: a red one means the reading of master was
  wrong, and a change that moves a cell replaces its test with a
  reproduction. Two cells have moved: the index, so that the held link is
  still named at its pair after a second own dial to its address; and a
  crossing's move counts the peering heard, which its tests assert at both
  settings, with the replay memory the move forgets and the restart floor
  it keeps.
- `clock.rs`: settlement intervals against steps of the wall clock:
  handshake timers against forward and backward steps, an inbound leg
  holding its msg2 reaped at its timeout, the shown start and idle times of
  a pending handshake left on the wall clock, the restart gate for heard
  and unheard peerings against a forward step with no time passing and
  against monotonic time passing, the shown promotion time left on the
  wall clock, the replay memory across a forward step and its entries'
  expiry on the monotonic clock across a backward one, and the
  TreeAnnounce rate limit against a backward step and at the monotonic
  clock's first instants. They step the wall clock with the thread-local
  `crate::time::step_wall` and advance the monotonic one with
  `crate::time::advance`, so they run safely beside other tests. It holds
  copies of three private items of `handshake_lines.rs` and two private
  helpers of `handshake.rs`, each naming its original.
- `crossing.rs`: crossed dials and a dialer's second dial. Crossed TCP dials
  (one working session; the smaller node on the link it dialed and its redial
  after a drop, with a single-dial control and a run that rewrites the
  record); crossed loopback dials won on another transport or address (the
  pair the winning msg2 came from, then the audit); a second msg1 more than 1
  s after the first (in order, on another transport, the dialer left on its
  second dial's link, and with the second msg2 first, a known defect checked
  by heartbeat and by the audit); a move's link: the address dialed with the
  msg2's pair a path of it, the control machine moved with the peer, and the
  pin a second dial ends after a crossing; a TCP crossing whose one msg1
  arrives inside the other's connect window, keeping the handshake that
  completed first; a larger node's dial on a quiet peer's aged link (two known
  defects); a crossed msg1 the smaller node reads after installing from its
  own dial and hearing nothing for longer than the heard floor, from another
  transport and on the same one (known defects, with a control inside the
  floor); a larger node's dial on the aged link after the smaller node's own
  rekey, past the heard floor (a known defect, with the same control); and two
  dials to one address with no peer held, the first reaped, leaving open the
  connection the second runs on, on loopback and on the BLE mock; and the
  close rule where another link's second path holds the pair, at the link a
  crossing retires and at a path released while its link lives, and where a
  link's one path roamed to the pair of a dial the crossing tears down; and
  what a move closes of the link it left: on TCP, the left link's connection,
  after the msg2 queued on it is read, and on loopback, nothing a dial still
  in flight uses. Each two-order case is one test per order. It holds copies
  of private helpers of `crossed_dial.rs` and `control.rs`, each naming its
  original.
- `explore/`: the real-node explorer and its world: two or three real nodes
  on the loopback, TCP or the BLE mock, driven by a schedule written as data,
  every dial through `initiate_connection`, each node's receive channel
  held by the world; and the core's named starts run on them, each scripted
  and then varied packet by packet. Its tests show each step does what it
  says on each transport, and that the explorer reaches each start's target;
  `src/node/tests/settle/explore/README.md` says what the world models, what
  it does not, and which starts run.
- `fsp.rs`: an end-to-end session whose responder restarts before its
  frames reach the initiator. At the smaller address the pair carries data
  within one exchange. At the larger address it recovers when the
  initiator's msg3 resends end and the repair rekey it then starts
  completes, an accepted ceiling the test asserts (32 s at the defaults,
  counted on a frozen clock); a sooner recovery passes too.
- `readings.rs`: what a move or a restart does with multipath on to state
  outside the peer's record. A connect still out when a move releases its
  path is closed as it opens, unless another live link uses the pair, and a
  connect the bundle still holds a path for is stepped into it as before. A
  close queued at a restart's teardown is spared by the drain at the pair the
  new link runs on, and still made where nothing uses the pair, with the
  control that with multipath off the teardown queues none. A no-carrier
  reading stays across a move and goes with the peer. A characterisation
  test (`chartest_`, as in `cells.rs`) holds what a restart found at a rekey
  keeps of the bundle, and that the pin ends. Its `own_dial` and
  `restart_dial` also serve the replay tests of `decrypt_replay.rs`.
- `restart.rs`: a restarted node that reads a late rekey msg1 of its
  peer's previous run, past the unheard floor, after the peer has moved
  onto its new run: one session in every placement of the peer (a known
  defect), with a control inside the floor. It drives the floor with
  `crate::time::advance`.
- `lane.rs`: six planted tests for the lanes' self-checks. The first five
  serve the known-defect lane (`testing/known-defect-lane.sh`), and each must
  be classified as its name says: failing at its precondition, at a bare
  `unwrap()`, at a plain `expect` in a setup helper, at its defect
  assertion, or passing. The mutation lane (`testing/mutations/run.sh`) runs
  the last, `a_planted_switch_reds_at_its_defect_assertion`, with the
  `PlantedRed` switch, which must red it at its `defect:` assertion, and the
  passing one with `PlantedGreen`, which has no site, so the lane must call
  it a miss. Each is ignored and inventoried as `helper`. The known-defect
  lane pins three of the file's line numbers, so a new test goes last. They
  are not tests of the node.
- `links.rs`: the `(transport, address)` index derived from the link
  records, on real nodes: after a crossed dial won from another address or
  on another transport, the smaller node's link is named at the msg2's
  pair; a one-path roam names the new pair and keeps the setup pair named;
  and a second path proven by the peer's answers to its probes is named
  with no writer called after its state reached the record, the cache
  matching the records.
- `live.rs`: the node's live map audit on real nodes. A loopback and a TCP
  dial audit both nodes; a node a test wrote past the map writers is not
  audited and one written through them is; an index entry put in past the
  table fails at the next frame; a session a degraded decrypt-worker pool
  refused, and two started nodes on real pools, pass. The settlement core's record of a
  dialed link holds its original path Live, follows a one-path roam, and
  records a switch to an acknowledged path Live, which `links-mirror` lets
  off for the active path alone; a record off its bundle fails the clause.
  Tests that need the audit to run carry `#[cfg(debug_assertions)]`.
- `table/`: the transition table checked on real nodes. Its `mod.rs` is
  the harness: a reading of every row of a peer's state on one node
  (`Seen`), a writer that makes every row it can reach differ from a fresh
  peering's (`dirty`), the check of each row of a before and an after
  reading against the row's cell at the transition the test ran
  (`assert_cells`), and two BLE mock pairs for the BLE mark. Its other files
  check one column group each; `src/node/tests/settle/table/README.md` says
  what a test there must do.

## Markers: `defect:` and `precondition:`

Some tests here pin a defect: they assert the correct behaviour, fail today,
and are `#[ignore = "known defect: ..."]` with a `known-defect` line in
`testing/ignored-tests.txt`. The known-defect lane runs each one and
classifies the run with `testing/lib/test-verdict.sh`. It reads the test's
own panic, and counts the test as still failing only when the first message
line starts with `defect:`. So, in every test in this directory:

- the assertion that states the behaviour under test has a message starting
  `defect:`; an aggregated check is one assertion,
  `assert!(bad.is_empty(), "defect: {bad:#?}")`;
- a known-defect test has exactly one `defect:` assertion, so the lane's
  `defect` verdict is the test's stated reason and no other;
- every setup check has a message starting `precondition:`, including the
  `expect` that replaces a bare `unwrap()`.

A failure anywhere else (a bare `unwrap()`, a shared helper's plain
`expect`, an overflow, an unmarked `assert!`) is classified `unmarked`, and
the lane reds on it, as it does on `precondition`. That is the point: a pin
that breaks in its setup has stopped showing its defect, and a fix landing
elsewhere would go unseen.

## No exemptions

The audit takes none. The last two waived the inbound link record a
crossing or a node's own later dial left the mover on, and went when a
move came to hold the link it dialed. A green test that the audit reds is
a finding to report, not a reason to bring an exemption back.

## Rules for changing it

- A new file gets a `mod` line in `mod.rs` and an entry under Files above,
  in the same change.
- A new known-defect test gets its inventory line in the same change, naming
  its full path, `node::tests::settle::<file>::<fn>`. Run it through the lane
  (or `verdict`) and check it is classified `defect` for the reason it states.
- A test that opens a socket needs nothing more: the whole module is in
  `node-synthetic`, and `testing/check-node-test-groups.py` reads the files
  `mod.rs` declares.
- Tracker IDs and planning labels stay out of names, comments and messages;
  a test's name states the behaviour it asserts.
