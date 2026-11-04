# core/src/proto/settle/tests/legacy

Models of deployed settlement, each a `Party` of the world, so the world
can run a deployed node at either end of a start and the settlement
properties can be checked on it.

## Files

- `mod.rs`: declares the files below.
- `master.rs`: `MasterParty`, the current node's settlement transcribed
  from `master` at `2ba790b2` by reading the code. Its rekey rules are
  `RekeySide`'s (`../rekeyside.rs`), held one per peer as the node holds a
  rekey machine per link. It logs every history event and what it did, so
  the oracles compare it with the model step by step (`../shadow.rs`).
- `maint.rs`: `MaintParty`, the deployed node's settlement transcribed
  from `maint` at `9fc10516`, with its own rekey rules (`Rekey`), since
  `maint` has no rekey machine.
- `explore.rs` (under `slow-explorers`): the settlement core explored against
  each model, on every start but 12, with the core at node 0 and at node
  1, in both address orders. One session must hold at every node except
  on a path that showed a known shape; every other property must hold at
  the core's node; the legacy nodes' other breaches are counted by
  property and printed.
- `not-converging.txt`: the pairings found not to converge, one per line
  (run, property, node), read by `explore.rs`. Each is a finding reported
  with its schedule, not fixed here; the runs fail on a breach the file
  does not list and on a listed one that no longer shows.
- `findings.rs`: the four defects of the current node the properties must
  find in `MasterParty` (crossed dials leave the smaller node on the wrong
  link, on a connectionless and on a connection-oriented transport; a late
  second dial answered in the other order splits the session; a dial on the
  peer's aged link leaves a pending the peer cannot adopt; a forward wall
  step lets a msg1 replace a peering heard just now), and, under
  `slow-tests`, `MasterParty` explored against itself on every start but
  12 with every breach printed.

## What `master.rs` transcribes

At `2ba790b2`, with the line ranges its author read:

- `src/node/handlers/handshake.rs`: the replay memory (`:136-232`,
  `ReplayedMsg1s::verdict` at `:170-190`, `MAX_REPLAYED_MSG1S` at `:103`),
  the peer snapshots (`:240-282`), `is_established_link_msg1`,
  `msg1_waiver` and `established_link` (`:407-551`), `answer_msg1`
  (`:575-621`), `handle_msg1` (`:623-1430`) with the restart and
  replacement gates (`:973-1130`, the heard floor's wall-clock idle time
  and the unheard floor's packet stamps), `finish_inbound`,
  `promote_resent` and `note_unheard_promotion` (`:1430-1537`),
  `msg1_to_link`'s arrival (`:1538-1640`), and `handle_msg2`'s swap and
  keep (`:1870-2300`); `EPOCH_RESTART_MIN_INTERVAL_SECS` at `:58`.
- `core/src/proto/fmp/core.rs`: `cross_connection_winner` (`:40-56`),
  `establish_inbound` (`:478`) and `establish_outbound` (`:538-560`).
- `src/node/mod.rs`: `close_handshake_link_connection`,
  `addr_carries_other_peer` and `remove_link` (`:3215-3270`).
- `src/node/handlers/timeout.rs:164`: a reaped leg's connection closed.
- `src/peer/active.rs`: `move_session` (`:699-738`).
- `core/src/proto/rekey/mod.rs`: `impl From<Carry> for SetupFacts`, what a
  move carries into the rebuilt rekey machine.

## What `maint.rs` transcribes

At `9fc10516`, with the line ranges its author read:

- `src/node/handlers/handshake.rs`: the replay memory (`:100-200`,
  `MAX_REPLAYED_MSG1S` at `:91`), `establish_snapshot` and
  `outbound_snapshot` (`:220-278`), `answer_msg1` and `link_reachable`
  (`:482-576`), `handle_msg1` (`:578-1535`): the duplicate short circuit
  (`:667-716`), the `RekeyRespond` arm (`:948-1068`), the restart and
  replacement gates (`:1069-1225`), the promotion tails (`:1380-1395`,
  `:1514-1530`); `handle_msg2` (`:1576-2120`): the rekey arm
  (`:1599-1735`) and the cross-connection swap and keep (`:1904-2050`);
  `EPOCH_RESTART_MIN_INTERVAL_SECS` at `:52`,
  `UNHEARD_PEERING_MIN_AGE_MS` at `:73`.
- `src/proto/fmp/core.rs`: `AnsweredMsg1s` and `ENDED_MSG1_RECORD`
  (`:163-255`), `REKEY_MIN_LINK_AGE_SECS` (`:627`), `poll_rekey` (`:738`),
  `poll_rekey_resends` (`:784`), `establish_inbound` (`:827-948`),
  `establish_outbound` (`:950-959`).
- `src/peer/active.rs`: `replace_session` (`:619-635`), `is_heard`, the
  rekey slots: `answered_before`, `is_setup`, `note_setup`,
  `set_pending_session`, `answer_rekey`, `release_pending`,
  `cutover_to_new_session`, `handle_peer_kbit_flip`, `adopt_pending`,
  `retire_pending`, `abandon_rekey` (`:1155-1630`).
- `src/node/handlers/rekey.rs`: `DRAIN_WINDOW_SECS` (`:27`),
  `pending_hold` (`:120-137`), `check_rekey` (`:148-345`), the rekey
  resends (`:511-540`).
- `src/node/dataplane/encrypted.rs`: `handle_encrypted_frame`
  (`:47-370`), the pending trial (`:100-200`) and the first-heard forget
  (`:351`).
- `src/node/dataplane/peer_actions.rs`: the `SendHandshake` arm's failed
  msg2 send (`:170-215`). `src/node/dataplane/dispatch.rs`:
  `remove_active_peer` (`:114`). `src/node/mod.rs`:
  `close_handshake_link_connection`, `addr_carries_other_peer` and
  `remove_link` (`:2878-2930`).

Where it differs from `master.rs`, each read at both refs:

- A held peer's own-dial msg2 swaps by the address tie-break alone
  (`establish_outbound` has no own-dial clause and no epoch check), and
  the swap replaces the session only: the peer's link, address, epoch on
  record, session age and pending slot stay (`replace_session`).
- A failed msg2 send at a msg1 leaves no leg with a stored msg2; a resend
  of that msg1 is judged afresh.
- The rekey record holds the setup msg1 and each armed msg1 whose pending
  has left, by its bytes; a refused or replaced msg1 is not recorded.
- The rekey msg2 puts the peer's new epoch on record at once, not at the
  cutover.
- A frame under the previous session also marks the peering heard and
  moves its address; the replay memory is forgotten at the first frame.
- An own rekey is abandoned after its resends, with no deadline of its
  own; a rekey answer that cannot be sent arms no pending.

Which deployed tags it stands for (`git diff --stat <tag> 9fc10516` over
the transcribed files, `p4/logs/c10-maint-tags.log` in the planning
workspace): `v0.5.3` differs only in the inbound cap at `max_peers`
(`has_pending_outbound_to_peer`) and an MMP reset at `replace_session`,
neither of which the world models, so the model stands for `v0.5.3` as
well. `v0.5.0` to `v0.5.2` differ by over two thousand lines in those
files; whether their settlement differs is not established.

Not transcribed: the inbound cap at `max_peers`, the rekey dampening of
an own rekey after the peer's, the rekey trigger's age and message
count (the world's explorer starts a rekey once the link and session are
old enough, as for `master.rs`), MMP and the decrypt workers.

## Rules for changing it

- `master.rs` is the current node, not the FRC: where the two differ, it
  keeps the node's behaviour, and the comparison names the difference
  (`../shadow.rs`) or the finding tests show it.
- Not transcribed: the node's back-off for silent sessions
  (`fmp/silent.rs`). Whether any start reaches three silent sessions in a
  row is not established.
- Neither model knows paths, so start 12 is not run against them.
- Refresh it to the multipath landing commit before a later step leans on
  it; until then it is the node before multipath.
