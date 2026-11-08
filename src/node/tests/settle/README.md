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
`crossing.rs` and `audit.rs` run both ways: a test's plain name runs multipath
off, and its `_with_multipath_on` sibling runs it on. They are two tests and
not one loop, since a pin that fails in a loop's first pass would never reach
the second, and each pin has a line of its own in
`testing/ignored-tests.txt`. The other files run off, which is what they test.

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
- `audit.rs`: the shell audit. `audit(nodes, exempt)` reports every breach
  of four properties over real nodes, after running
  `link_index_audit::audit` on each node (which panics on its own);
  `assert_coherent` fails the test, marked `defect:`, on any breach. The
  file's doc names each property and what it can and cannot see. Its tests
  show the audit passes coherent states and fires on a planted breach of
  each property it reports. Where a property is also a clause of the node's
  live audit (`src/node/settle/audit.rs`), it calls that clause.
  `assert_coherent` and `Exempt` are visible to the rest of `node::tests`:
  the crossing, restart, rekey-move, stored-msg2 and BLE crossing tests
  call it at their end, where both nodes hold each other and are quiet.
- `bounds.rs`: a pending dial sprayed with 1000 forged msg2s, garbage or
  replayed: the dial is kept, no handshake or per-peer map grows, and the
  genuine msg2 still completes the dial. How many forged msg2s are read is
  not asserted.
- `carry.rs`: per-peer state across a change of the peer's link: a peer
  promoted for an identity announced to just now is sent a TreeAnnounce at
  once.
- `clock.rs`: settlement intervals against steps of the wall clock:
  handshake timers against forward and backward steps, an inbound leg
  holding its msg2 reaped at its timeout, the shown start and idle times of
  a pending handshake left on the wall clock, and the TreeAnnounce rate
  limit against a backward step and at the monotonic clock's first
  instants. They step the wall clock with the thread-local
  `crate::time::step_wall` and advance the monotonic one with
  `crate::time::advance`, so they run safely beside other tests.
- `crossing.rs`: crossed TCP dials (one working session by the audit, a
  known difference on this line; the smaller node's link record, which is
  the link it dialed; a single-dial redial control), and a larger node's
  dial on the aged link after the smaller node's own rekey, read inside
  the heard floor. Each two-order case is one test per order. It holds
  copies of private helpers of `control.rs`, each naming its original.
- `fsp.rs`: an end-to-end session whose responder restarts before its
  frames reach the initiator. At the smaller address the pair carries data
  within one exchange. At the larger address it recovers when the
  initiator's msg3 resends end and the repair rekey it then starts
  completes, an accepted ceiling the test asserts (32 s at the defaults,
  counted on a frozen clock); a sooner recovery passes too.
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
- `live.rs`: the node's live map audit on real nodes. A loopback and a TCP
  dial audit both nodes; a node a test wrote past the map writers is not
  audited and one written through them is; an index entry put in past the
  table fails at the next frame; the crossing's waiver is recorded at the
  crossing on that link only, and a crossing that keeps the link's entry
  records none; a session a degraded decrypt-worker pool refused, and two
  started nodes on real pools, pass. Tests that need the audit to run carry
  `#[cfg(debug_assertions)]`.

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
settled at msg3, so the master line's cases that rest on a peering promoted
at msg1 (a restart's msg1, a redial answered as a rekey, late second
dials, crossings won on another pair, dials on a quiet peer's aged link,
the restart gate and the replay memory), the BLE claim cases and the five
cell characterisations are not here.

Four tests that run here fail, each with multipath off and on: the two
crossed TCP dial tests of `crossing.rs` and the two crossing tests of
`audit.rs`. Why is not established. What they show is that after crossed dials, which this line
settles as it settles a later dial of our own, each node keeps both its
connections open, the larger node's link record is at another pair than the
one it holds the peer at, and the larger node's live link has no
address-index entry at its pair. The missing entry is seen with the
multipath path machine on this line; next without the path machine shows
the first two and not it. They are ignored as
`known difference on next, cause not established: ...` and listed as
`known-defect` in `testing/ignored-tests.txt`, so the lane sees a change in
them.

## The audit's exemptions

An exemption waives one property for one node, and applies only when the
test passes it; the audit never infers one from state. Each is listed in
`audit.rs`'s `Exempt` with its reason and the change that removes it. The
node records its own waiver for the same state at the event that makes it
(`settle::Waiver`, in test and debug builds), and `assert_coherent` fails
on a passed exemption its node did not record, so the two cannot drift. A new
one needs a test that constructs it in the same change (an enum variant no
code constructs fails clippy), and a test showing it waives only what it
names. A green test that the audit reds is a finding to report, not a
reason to add an exemption.

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
