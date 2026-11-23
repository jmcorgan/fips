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
named for off. The other files run off, which is what they test.

## Files

- `mod.rs`: the module declarations, the module doc, and the drivers the
  files share: the multipath setting (`with_path`, `loopback_node`), real TCP
  nodes on 127.0.0.1 (`tcp_node`, `tcp_pair`, `tcp_dial`, `resolve_connect`,
  `pool`), crossed TCP dials (`crossed_tcp`), the age a test backdates a
  session to for an aged link (`AGED`, kept within a fresh CI runner's
  uptime), a step just past the restart interval
  (`PAST_THE_RESTART_INTERVAL`, used to seed an expired dampener in
  `table/`),
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
- `carry.rs`: per-peer state across a change of the peer's link: a peer
  promoted for an identity announced to just now, or replaced by a restart at
  a msg3 or a msg2, is sent a TreeAnnounce at once.
- `clock.rs`: settlement intervals against steps of the wall clock:
  handshake timers against forward and backward steps, an inbound leg
  holding its msg2 reaped at its timeout, the shown start and idle times of
  a pending handshake left on the wall clock, the restart gate on the peer
  clock and what a real frame refreshes, and the TreeAnnounce rate limit
  against a backward step and at the monotonic clock's first instants. They
  step the wall clock with the thread-local
  `crate::time::step_wall` and advance the monotonic one with
  `crate::time::advance`, so they run safely beside other tests.
- `crossing.rs`: crossed dials and a dialer's second dial. Crossed TCP dials
  (one working session on one connection by the audit; the
  smaller node's link record, which is the link it dialed; a single-dial
  redial control); a larger node's dial on the aged link after the smaller
  node's own rekey, read inside the heard floor; two dials to one address
  with no peer held, the first reaped, leaving open the connection the
  second runs on, on loopback and on the BLE mock; a move at the dial's
  msg2: the address dialed with the msg2's pair a path of it, and the
  control machine moved with the peer; the close rule where another link's
  second path holds the pair, at the link a crossing retires and at a path
  released while its link lives, and where a link's one path roamed to the
  pair of a dial the crossing tears down; and what a move at the msg2 closes
  of the link it left: on TCP, the left link's connection, and on loopback,
  nothing a dial still in flight uses. The same TCP crossing leaves the
  larger node, which settles it at the peer's msg3, held on a link whose
  connection is open. Each two-order case is one test per order. It holds copies of private helpers
  of `control.rs`, each naming its original.
- `explore/`: the real-node explorer and its world: two or three real nodes
  on the loopback, TCP or the BLE mock, driven by a schedule written as data,
  every dial through `initiate_connection`, each node's receive channel
  held by the world; and the core's named starts run on them, each scripted
  and then varied packet by packet. Its tests show each step does what it
  says on each transport, and that the explorer reaches each start's target;
  `src/node/tests/settle/explore/README.md` says what the world models, what
  it does not, and which starts run. Not built on next: its `mod` line is
  under `#[cfg(any())]`, since next's link handshake is XX and the explorer
  is written for master's IK (that README says why).
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
  test (`chartest_`) holds what a restart found at a rekey keeps of the
  bundle, and that the pin ends. Its `own_dial`, where the smaller node
  dials and both ends move, and `restart_dial`, which runs the three
  messages, also serve the replay tests of `decrypt_replay.rs`.
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
  dialed link holds its original path Live, follows a one-path roam, the
  active path's or a standby one's, and records a switch to an acknowledged path Live, which `links-mirror` lets
  off for the active path alone; a record off its bundle fails the clause.
  Tests that need the audit to run carry `#[cfg(debug_assertions)]`.
- `redialed.rs`: which direction each end holds its link in. After crossed
  TCP dials the smaller node must hold it `Outbound` and the larger
  `Inbound`; a crossed peer the larger node alone drops and redials must
  end, after the smaller node's link-dead reap and reconnect, on one
  working session held `Outbound` at one end and `Inbound` at the other; a
  peer the smaller node alone drops and redials must stay, through the
  larger node's later dial, on one session on the smaller node's dial; and
  the smaller node's redial after the mixed-schedule crossing of
  `crossing.rs` must leave it `Outbound` and the larger `Inbound`. Each
  turns on the larger node's msg3 crossing, which holds it on the link the
  smaller node dialed. They are the counterparts of master's `redialed.rs`,
  which answers a redial at the msg1.
- `withheld.rs`: a lost first msg3 beside a withheld one. The smaller node
  dials on two loopback transports at once, the second dial's msg3 is
  withheld by the own-dial keep, and the first dial's msg3 is lost: the
  larger node must still hold the smaller on the smaller's session. A known
  defect on this line, with multipath off and on.
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

## On this line

These files came from the master line, where they pin how that line's
handshake settles. This line's handshake is the XX pattern, with crossings
settled at a dial's msg2 or the peer's msg3, so the master line's cases that
rest on a peering promoted at msg1 (a restart's msg1, a redial answered as a
rekey, late second dials, second own dials, crossings won on another pair,
dials on a quiet peer's aged link, a TCP crossing with one msg1 inside the
other's connect window, the restart gate and the replay memory), the BLE
claim cases and the five cell characterisations are not here.

A move at this node's dial's msg2 holds the link it dialed and closes the
one it left, as on master. A move at the peer's msg3, which the larger node
makes, holds the inbound leg's link, the link the smaller node dialed, and
closes the one it left, its own dial's, unless a live link uses it; the
smaller node's keep at the peer's msg3 closes the leg's connection the same
way. Both ends settle on the smaller node's dial (FRC-2201 Section 5.7).

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
