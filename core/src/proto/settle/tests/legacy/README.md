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

## Rules for changing it

- `master.rs` is the current node, not the FRC: where the two differ, it
  keeps the node's behaviour, and the comparison names the difference
  (`../shadow.rs`) or the finding tests show it.
- Not transcribed: the node's back-off for silent sessions
  (`fmp/silent.rs`). Whether any start reaches three silent sessions in a
  row is not established.
- It knows no paths, so start 12 is not run against it.
- Refresh it to the multipath landing commit before a later step leans on
  it; until then it is the node before multipath.
