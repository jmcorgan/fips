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
  `pool`), crossed TCP dials (`crossed_tcp`), the age a test backdates a
  session to for an aged link (`AGED`, kept within a fresh CI runner's
  uptime), a step just past the restart interval
  (`PAST_THE_RESTART_INTERVAL`, used by `clock.rs` and to seed an expired
  dampener in `table/`),
  delivery until idle for loopback and TCP nodes alike (`pump`), a fresh
  heartbeat check (`heartbeat_reaches`), the check that two nodes hold one
  session that carries a heartbeat each way (`settled`, over `indices` and
  `one_session`), the run that ends a split pair (`outlast`: `ride_out`
  runs every node past the link-dead timeout on a frozen test clock, a
  second at a time, each node's receive-loop tick and a full delivery
  between steps, and records when each end dropped the other; then
  `redial` dials again through `initiate_connection`), the split's shape
  (`assert_split`), and the wrappers
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
  a pending handshake left on the wall clock, a pending dial's shown state,
  expected peer and resend count on the loop and off it, the restart gate
  for heard and unheard peerings against a forward step with no time passing and
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
  s after the first (in order, on another transport, where it is a redial the
  dialer's first frame proves, the dialer left on its second dial's link, and
  with the second msg2 first, a split accepted as behaviour: checked by
  heartbeat and by the audit, it splits the pair until link-dead drops both
  ends and the dialer redials, with the control that a working pair run past
  the link-dead timeout the same way keeps its session); a move's link: the
  address dialed with the
  msg2's pair a path of it, and the
  pin a second dial ends after a crossing; a TCP crossing whose one msg1
  arrives inside the other's connect window, which reaches the larger node
  off its link as a redial and settles both ends on the smaller node's dial
  at its first frame; a larger node's dial on a quiet peer's aged link (two known
  defects); a crossed msg1 the smaller node reads after installing from its
  own dial and hearing nothing for longer than the heard floor, from another
  transport (one session) and on the same one (a split accepted as
  behaviour, ended by link-dead and the smaller node's redial), with a
  control inside the floor; a larger node's dial on the aged link after the
  smaller node's own rekey, past the heard floor (a split accepted as
  behaviour, ended by link-dead and the larger node's redial, with the same
  control); and two
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
- `redialed.rs`: crossed TCP dials, then the larger node alone drops the
  smaller, as link-dead does at the end that stops hearing first after a
  flap, and dials it again once the connection the smaller node's link ran
  on has closed: the smaller node answers as a rekey on the msg1's
  connection, and the larger installs the answer as a peer it dialed. The
  larger node must then hold the link `Outbound` and the smaller `Inbound`:
  the smaller node's adoption of the answer turns its link `Inbound`. With
  multipath on the pair here holds one path, not the two the chaos run
  that found it held. A second test runs the other role, the larger node
  alone dialing and the smaller dropping and redialing, then has the
  larger node dial again: with its link turned, that dial is decided by
  the node address ordering, and the pair stays on the smaller node's dial.
- `rekey_cross.rs`: the core's start 9 scripted by hand on two loopback
  nodes with two transports each, outside the explorer's world: a pair
  settled on one transport, one node's rekey, crossed dials on the second
  transport, the packets read in the start's order (and a variant that
  loses the rekeying node's dial msg1 on the second transport), then the
  explorer's leaf heal run on to 60 s. Each run prints a record of the
  packets sent, the peer changes and their causes, and each node's peer,
  pending rekey session and live links with their index entries at each
  checkpoint; each test judges the pair at the explorer's leaf, at 31 s
  and at 60 s, and asserts it coherent at all three. The smaller order
  passes. The larger-order tests are known defects, ignored and run by the
  known-defect lane: the smaller node is left holding a responder pending
  of the larger's rekey that the larger never adopts, and with the dial
  msg1 lost a resent dial msg1 is answered as a rekey into such a pending.
  The explorer's start 9 pins it where it finds it. Beside them, tests
  that pass: the larger order judged for a split alone (the crossed
  redials are settled by the dial tie-break at each leg's first frame); a
  rekey msg1 at the pair the smaller order's pending redial leg shares
  with the held link, judged on the held link; and the other arrival order
  of crossed dials, the larger dialing from a second address of its own,
  whose dial msg1 the smaller node answers after it has moved onto its own
  dial, ending on the smaller node's dial.
- `restart.rs`: a restarted node that reads a late rekey msg1 of its
  peer's previous run, past the unheard floor, after the peer has moved
  onto its new run: a split accepted as behaviour in every placement of the
  peer, which link-dead ends at both ends and the peer's redial turns into
  one session, with a control inside the floor. It drives the floor with
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
- `legacy_dialer.rs`: a deployed release's dialer on two transports, which
  wins the tie-break between its dials and moves onto its second dial's
  session without moving address, against this node as the responder. A
  test-only device makes a node of this tree send as one: a relay the
  driver applies as it hands packets over, off at the start of each cycle,
  engaged once the client holds the server on its transport-2 link (the
  client's transport-2 packets reach the server on transport 1 from its
  transport-1 address, the server's to the client's transport-1 address
  reach the client on transport 2, and the server's to the client's
  transport-2 address are lost), and off again once the client drops the
  server. The driver runs `roam_redial.rs`'s frozen clock and timer tick,
  and redials both transports at once where a test asks, in place of a
  configured peer's reconnect, since two loopback transports share a type.
  The tests: the reproduction at both address orders and multipath
  settings (the server keeps the held link and pair with the redial's
  session, the redial's link and entry go, the index allocators hold
  exactly the sessions' indices, the client is sent a tree announce and a
  filter, heartbeats and the audit); a 300 s run with the second transport
  4 s behind, one promotion and no drop at either end, and a link rekey at
  each; a dialer of this tree that moves to its second dial, swapped as
  before, multipath off and on; and the adopted redial's msg1 sent again,
  refused. Before the fix, a debug build stops at the node's live audit at
  the proof (`held-cache`), where the core and the node disagree about the
  peer's pair; a release test build reaches each test's `defect:`
  assertion.
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
  dialed link holds its original path Live, follows a one-path roam, the
  roam of a link's one path while it is not the active path among them,
  which moves the record and resets nothing, and records a switch to an
  acknowledged path Live, which `links-mirror` lets off for the active
  path alone; a record off its bundle fails the clause.
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
- A test whose doc line says it records current behaviour is listed in the
  settlement core's `current.txt` (`core/src/proto/settle/`); rename, move or
  delete it only with its line there.
- Tracker IDs and planning labels stay out of names, comments and messages;
  a test's name states the behaviour it asserts.
