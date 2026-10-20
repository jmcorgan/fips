# src/node/session

End-to-end (FSP) session state for the node: one `SessionEntry` per remote
endpoint, from the first message of its handshake to its removal, holding
the session's rekey machine (`fips_core::proto::rekey::Rekey` on the
profile `FspProfile`). The machine runs the first handshake: the shell
opens it with `SessionEntry::opened` when this node wants a session, with
`SessionEntry::answering` for the first setup naming an address, and with
`SessionEntry::open` (the machine's `Open`) on a session the peer's setups
opened, which starts this node's own attempt at once beside them. Every
setup, forged or genuine, is held as one of a bounded set of candidates
(four, two per link peer the setups arrived over) and changes nothing
else, since it authenticates nothing; only an authenticated msg3 decides
between crossing handshakes. The machine resends this node's first setup
on its ladder, ends its attempt at the handshake timeout and each
candidate 40 s after its setup, and asks for its own teardown when it
holds neither; it retains the initiator's first msg3 and resends it until
any frame from the peer authenticates (the responder prompts at once
under the new keys), and starts a repair rekey if its last copy goes
unheard. Who the peer is stays the claimed address until a completion
bonds its key (`identity`, `peer_key`), and the shell caches, uses and
reports a peer key only from there: the control socket shows an unproved
session with no `npub` and `identity: "unproven"` (`identity_status`).

Once established, the machine owns the current, pending and previous key
epochs, seals every frame, runs every inbound frame through its rows
(`step_frame`), starts its own rekeys when its trigger falls due on a
poll, takes every rekey setup, ack and msg3 (`step_setup`, `step_reply`,
`step_final`, the same steps as the first handshake's), and decides every
cutover, drain and rekey msg3 resend: the initiator keeps its data on the
old keys and probes until it hears the peer under the new ones, or decides
at its confirmation deadline; the responder cuts over at msg3 and prompts.
The machine is polled on the node's 1 s tick, and also just before a
setup naming it is admitted and stepped into it whenever one of its
deadlines or start instants has come (`wake_due`), so a setup is never
judged against a state a passed deadline ended: the smaller node would
refuse a setup while its completed rekey waits, and a deployed peer sends
its rekey setup once. The setup is admitted against the table that poll
leaves, so a session the poll ends is charged anew. A start instant that
has come starts this node's own rekey before the setup is judged, the
order a shell polling at the machine's next wake produces.
The machine resends an unanswered rekey setup on its ladder, which the
executor wraps afresh with the destination's coordinates of the moment. It
starts a rekey after 30 s in which this node sent data and heard nothing
from the peer under the current keys, and a completion whose peer startup
epoch changed is a restart: the old keys are retired rather than drained,
an initiator cuts over at its msg3 and resends it until the peer is heard,
and the executor counts and logs the restart (`peer_restarted`) and keeps
the session. The entry keeps no handshake or rekey state of its own.

- `mod.rs`: the session table types (`SessionEntry`, `SessionRekey`,
  `SessionOutputs`), the machine's parameters (`session_params`, which
  takes the node's rekey thresholds, handshake timeout, tick and resend
  count, with a fallback to the defaults for a part the machine refuses),
  the constructors of a session's machine for a first handshake either way,
  the seal and the frame and handshake steps the send and receive paths
  use, the machine's poll, whether a poll is due (`wake_due`) and the
  prompt seal, the query the half-open share of the session table is
  charged by (`grows`), and the session clock aliases. Test builds add
  constructors of an established, an opened and an answering session.
  The handlers that send and receive session messages, and the executor
  of the machine's outputs (`run_session_outputs` in
  `handlers/rekey.rs`), live under `src/node/handlers/`, not here.

Two rules about epochs hold here, and a change must keep them:

- Every field an epoch fixes is taken from the epoch a message is sealed
  under. `seal_frame` and `reserve_send` build the whole message from the
  machine's seal result: the key and counter, the header's key-epoch bit
  (whatever the caller's flags say of it), the inner-header timestamp
  counted from that epoch's base, and the spin bit. No send path builds
  an established FSP header or inner header itself.
- The session MMP receiver and spin state measure one epoch, the current
  one, named by its tag (`mmp_epoch`). After every machine call the entry
  restarts them if the current epoch changed (a cutover, or a return to the
  drained epoch after an assumed cutover), and `epoch_mmp(tag)` hands them
  out only for frames and reports authenticated under that epoch, so what
  the peer sealed under the epoch a cutover retired is delivered but never
  recorded. Path MTU state,
  SRTT and the sender-side counts are properties of the path and the
  session, not of an epoch, and are kept across a cutover.
- `tests.rs`: unit tests for `mod.rs`, declared from it as
  `#[cfg(test)] #[path = "tests.rs"] mod overlapping_epoch_tests;` so they stay
  a child module that can reach private items and keep their test names.
  One of them scans the code of every non-test source file of the root
  crate for a name of the deployed session rekey shell (its snapshots,
  resend sweeps, trial decrypt, first-handshake hold and tie-break, rekey
  predicates and resend slots, and the transitional entry points), and
  this directory and `handlers/session.rs` also for the predicates, state
  moves and constants the link layer's deployed rekey still uses and for
  any policy value (`Policy`, `policy`, `DEPLOYED`). Code is read through
  fips-core's `rekey::code_idents`, so comments and literals are not
  scanned, and the scan fails if that reader blanked a line opening an
  item. A session rule belongs in the machine; a test that
  fails here has found a second copy of one in the shell.

Unit tests go in `tests.rs`, never in an inline `mod tests` block in
`mod.rs`.
