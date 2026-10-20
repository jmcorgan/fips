# core/src/proto/rekey/tests/legacy

Executable models of the deployed releases, and the interop simulation of
new nodes against them. A new node cannot change a deployed peer, so the
rekey machine on the production profiles must complete rotations and
first handshakes with what v0.5.0 to v0.5.3 actually do. Everything here
runs on real Noise handshakes and the real wire codecs, with a seeded
entropy source, so a run replays byte for byte. It exists on master only:
next does not speak the v1 wire, and its merge of the production profiles
deletes this directory.

## Files

- `mod.rs`: the harness. `Rel` names the three behaviours (0.5.0 and
  0.5.1 share every rekey file, so one model stands for both). `End` is
  one endpoint, new or modelled; `Duo` connects two over a channel with
  per-direction latency, scripted faults by message class (`Rule`: drop,
  delay, the first n, until the sender sends a given class) and seeded
  random loss. It drives each end on its 1 s tick, half a second out of
  phase, and a new node also at its `next_wake`. Every data frame is
  numbered: one the channel delivered that the receiver did not accept is
  lost, and an end's outage is the span of its lost frames. `Expect`
  states a trace's outcome: the outage allowed each way, notes each end
  must or must not report, and the end state after a heal with the faults
  off (converged: both alive, nothing in flight, a frame each way
  accepted under the current epoch; or, where a deployed defect is the
  accepted outcome, the link removed at one end or rotation stopped). It
  also closes each new node and checks its index map, pool and lease
  count. For the explorer, `Duo::hold` keeps every packet in flight until
  it is delivered by id, and `release` loses what is left and restarts
  the periodic data.
- `new.rs`: the new nodes: the machine on `FmpIk` and on `FspXk` behind a
  shell that executes the outputs as the root crate's shell will (sends,
  prompts sealed at once, the index map from `Bind` and `Unbind`, leases
  returned on `Release`), frames every message with the deployed codecs,
  and for a link keeps the deployed 10 s heartbeat and 30 s link-dead
  reap on `view().last_rx`.
- `fmp.rs`: `FmpPeer`, a deployed node's link to one peer, and the link
  traces.
- `fsp.rs`: `FspPeer`, a deployed node's session entry for one peer, and
  the session traces.
- `explore.rs`: the bounded exhaustive explorer over a `Duo`, against
  every release and between two new nodes.

## The models

Each rule of `FmpPeer` and `FspPeer` cites the tagged lines it implements
(`v0.5.0:src/...:line`, read with `git show <tag>:<path>`); the citations
are the record of the line-by-line review against each tag. The models
keep each release's decisions and timers:

- **Link**: the msg1 ladder (1, 3, 7, 15, 31 s, abandon at about 32 s),
  the next-tick initiator cutover, the responder's own-tick cutover before
  v0.5.2 and the 120 s hold and adoption by frame from v0.5.2, the K-differs
  pending trial (and the index trial at v0.5.3), K flipped from its own
  (0 after a revealed restart and the frame's K at adoption, v0.5.3), the
  stored setup msg2 for a msg1 inside the 30 s session floor (the link and
  cutover floors, the held answer and the ended record at v0.5.3), the
  dual-initiation tie-break, a msg2 that does not read abandoning the
  cycle before v0.5.2, the fixed 10 s drain, 20 decrypt failures removing
  the peer before v0.5.3, previous-session frames out of liveness at
  v0.5.3, and the heartbeat and link-dead timers.
- **Session**: the 2 s initiator cutover, promotion on any frame under
  pending, the sliding 10 s drain under a 120 s ceiling, the armed
  handshake's 30 s expiry and the own rekey's (from v0.5.2; none before),
  30 s dampening after arming, the pending that refuses setups until it is
  90 s old and is never retired by a timer, the tie-break at a setup (the
  larger abandons before reading), the `RekeyHeld` drop and the rolling
  msg3 read at v0.5.3, the rekey msg3 ladder and its abandon, the idle
  purge, and the first handshake: one half-open entry before v0.5.3 (its
  ack resent, removed by an unreadable msg3, replaced by an own attempt
  when a session is wanted), candidates beside the initiator leg at
  v0.5.3 (the smaller drops a crossing setup while its leg is young, the
  larger pauses its leg), and the initial msg3 retained and resent from
  v0.5.2.

Not modelled, because no trace needs them: the node-level restart gates,
second paths and off-link arrivals, the coordinate cache and its error
signals, and MMP reports (a peer that sends is modelled by its data
frames; a silent one, as in session MMP mode Minimal, sends none).

## The tests

- `fmp::link_traces_hold_against_every_deployed_release` and
  `fsp::session_rekey_traces_hold_against_every_deployed_release`,
  `fsp::session_first_handshake_traces_hold_against_every_deployed_release`:
  the interop traces (a rekey started by either end under the losses that
  matter, simultaneous initiation, restarts, and first handshakes opened
  by either end or both) against every release in each role they involve,
  with the schedules that hold the machine's guards to their interop
  consequences.
  Each case states its outcome and bound; the failure message names the
  case and release and prints the run's notes.
- `fmp::lossy_link_runs_converge_against_every_deployed_release` and
  `fsp::lossy_session_runs_converge_against_every_deployed_release`:
  seeded runs at 15 % loss each way for 600 s against every release and
  between two new nodes (the production profiles against themselves),
  healed and required to converge.

- `explore::every_explored_interleaving_against_each_deployed_release_heals`:
  from the first handshake message of a rekey started by the new node, by
  the deployed node or by both, and of a first handshake opened by both
  ends at either address order, every sequence of up to 3 events
  (deliver any packet in flight, copy a handshake message once, seal one
  data frame at either end, advance to the next tick or wake), against
  every release and between two new nodes. The ends cannot be cloned, so
  each path is replayed from its start and paths are not de-duplicated.
  After each event no new link node's index map drifts; at each frontier
  path the heal must converge (or end as the release forces: the 0.5.0
  link split, the 0.5.0 session's stopped rotation) with no lease leaked,
  and no data frame a new node sealed in a rekey may be refused once
  delivered. The depth is 3 by default (about 14 s on 13 cores in a debug
  build); `FIPS_LEGACY_DEPTH` sets another.

Several guard switches of `../../faults.rs` name these tests in the
meta-test of `../faults.rs`, so a guard whose interop consequence these
schedules show is held to them too. `FIPS_LEGACY_TRACE=1` with
`--nocapture` prints every passing case's notes.
