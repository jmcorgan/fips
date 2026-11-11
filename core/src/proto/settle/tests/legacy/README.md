# core/src/proto/settle/tests/legacy

Models of deployed settlement, each a `Party` of the world, so the world
can run a deployed node at either end of a start and the settlement
properties can be checked on it.

## Files

- `mod.rs`: declares the files below.
- `master.rs`: `MasterParty`, the current node's settlement transcribed
  from `master` at `db946033` by reading the code. Its rekey is a real
  rekey machine and its paths a real bundle, one per held peer as the node
  holds them (`../joint/machines.rs`, `../joint/route.rs`), so its messages
  are real stub IK messages, and an abstract far end's are written from
  their names (`../joint/names.rs`). It logs every history event and what
  it did, so the oracles compare it with the model step by step
  (`../shadow.rs`).
- `maint.rs`: `MaintParty`, the deployed node's settlement pinned to the
  tag `v0.5.3`, with its own rekey rules (`Rekey`), since that node has no
  rekey machine.
- `explore.rs` (under `slow-explorers`): a joint node (`../joint/party.rs`)
  explored against each model, on every start, the two-path starts
  included, at each pairing: a setting at the joint node with `master.rs`
  at each setting and with `maint.rs`, which has none. The joint node runs
  at node 0 and at node 1, in both address orders. One session must hold at
  every node except for what a known shape left (`oracle::by_any_shape`):
  a split sharing a session with it, or the pending a dial left; every other
  property must hold at the joint node, a proven path left with no
  connection aside, which `../joint/pins.rs` holds; the legacy nodes' other
  breaches are counted by property and printed.
- `not-converging.txt`: the runs found not to converge, one per line (run,
  property, node), read by `explore.rs`. A run's name holds its pairing.
  Each is a finding reported with its schedule, not fixed here; the runs
  fail on a breach the file does not list and on a listed one that no
  longer shows.
- `findings.rs`: the three defects of the current node the properties must
  find in `MasterParty`, each test at both multipath settings (crossed dials
  leave the smaller node on the wrong link, on a connectionless and on a
  connection-oriented transport; a late second dial answered in the other
  order splits the session; a dial on the peer's aged link leaves a pending
  the peer cannot adopt), a test that a forward wall step no longer lets a
  msg1 replace a peering heard just now, since the gates read the peer
  clock, and, under `slow-tests`, `MasterParty` explored against itself at
  each setting on every start but 12 with every breach printed, the starts
  whose links turn capable at multipath on under `slow-explorers`, since
  each healed leaf there steps a minute of probes.

## What `master.rs` transcribes

At `db946033`, each site with its line, read at that ref. The machines and
the shell keep the same split the node does: what is a machine's decision
is the real machine's here, and each row is the shell around it. This table
is a reviewer's checklist. Nothing tests it: a change at one of these lines
does not red a test, and the coverage gap is that a re-read is the only
check that the transcription still stands.

| Site | Line | In `master.rs` |
| --- | --- | --- |
| `handshake.rs`, `EPOCH_RESTART_MIN_INTERVAL_SECS`, `UNHEARD_PEERING_MIN_AGE_MS`, `MAX_REPLAYED_MSG1S` | `:59`, `:85`, `:104` | the constants |
| `handshake.rs`, `ReplayedMsg1s::verdict` | `:173` | `replay`, on the interval clock |
| `handshake.rs`, `answer_msg1` | `:600` | `answer` and the msg2 arm of `sends`, by the machine's `Route` |
| `handshake.rs`, `link_reachable`, `established_link` | `:557`, `:538` | `reachable`, `to`: the active path |
| `handshake.rs`, `handle_msg1` | `:664` | `msg1` |
| `peer/machine.rs`, `inbound_msg1`; `fmp/core.rs`, `establish_inbound` | `:1296`, `:478` | the class in `msg1` |
| `handshake.rs`, the gates on the peer clock | `:1093` | the gates in `msg1`: `heard_at` and `promoted_at` |
| `handshake.rs`, `finish_inbound`, `promote_resent`, `note_unheard_promotion` | `:1479`, `:1513`, `:1561` | `install`, the stored answer's arm of `msg1` |
| `handshake.rs`, `msg1_to_link`: attribution by `path_match` and the capable rule, and the answer's route | `:1576`, `:1612`, `:1735` | `handed` |
| `handshake.rs`, `msg2_to_link` | `:1846` | `reply` |
| `handshake.rs`, `handle_msg2`; `fmp/core.rs`, `cross_connection_winner`, `establish_outbound` | `:1934`, `:40`, `:538` | `msg2` |
| `handshake.rs`, the swap: `move_session`, `run_renewed`, `paths_renewed` | `:2289`, `:2300` | `msg2`'s move arm |
| `peer/active.rs`, `move_session`, `current_addr`, `path_match`, `touch` | `:739`, `:803`, `:951`, `:1385` | `Machines::moved`, `to`, `Machines::matched`, the heard fields in `frame` |
| `node/mod.rs`, `close_handshake_link_connection`, `addr_carries_other_peer`, `remove_link` | `:3229`, `:3251`, `:3279` | `close_leg`, `carried`, `unlink` |
| `node/dataplane/dispatch.rs`, `remove_active_peer` | `:176` | `close` |
| `node/dataplane/encrypted.rs`, `handle_encrypted_frame`, `account_authentic` | `:99`, `:440` | `frame`: a frame of any slot is heard, the bundle follows or does not follow it, the heard feed |
| `node/handlers/rekey.rs`, `poll_link_rekeys`, `run_link_step`, `reset_restarted`, `send_link_msg1`, `send_link_prompt` | `:209`, `:258`, `:353`, `:413`, `:456` | `wake`, `carry`, the restart arm of `carry`, `sends` |
| `node/handlers/path.rs`, `poll_connects`, `run_outputs`, `run_renewed`, `switched`, `release_path`, `drain_closes`, `send_unreachable`, `forget_connects` | `:461`, `:487`, `:619`, `:647`, `:698`, `:725`, `:853`, `:909` | `connects`, `carry`, `release`, `drain`, `closed`, `close` |
| `node/handlers/path_intake.rs`, `intake`, `paths_renewed`, `connect_candidate` | `:436`, `:478`, `:521` | `offer`, `renewed`, `dial`'s first arm |
| `node/lifecycle/mod.rs`, `active_peer_link_is_live`, its capable clause | `:3448` | `feeds::dials` |
| `node/handlers/mmp.rs`, `check_link_heartbeats` | `:517` | the timer in `wake`, `party::deadline` |
| `node/handlers/timeout.rs`, a reaped leg's connection | `:146` | `reap` |
| `core/src/proto/rekey/mod.rs`, `impl From<Carry> for SetupFacts` | | `Machines::moved` |

Read at `db946033` and not modelled, each because the world has no way to
reach it: the operator's pin and its `Unpin` at a swap or a restart
(`handshake.rs:2333`, no start pins a path); the silent-session back-off and
the inbound cap; `is_established_link_msg1` and `msg1_waiver`, which price a
msg1 before its crypto; `close_unproven_ble_links`, for a BLE channel that
never carries a msg1 (`timeout.rs:144`); the node's staleness clause of the
dial rule (`feeds.rs`). The link-dead timer was left out of this model at
`2ba790b2`, since the world then had none; a joint node runs it since the
world grew one, so this model does too.

### The crossed-dial fix

The node changes these rules in the same work, and this model with them, so
they are not `db946033`'s:

| Rule | At `db946033` | Here |
| --- | --- | --- |
| A move's heard (FRC-1201 Section 5.5) | the peering keeps the heard it had, so one promoted on the peer's msg1 is unheard until the peer's first frame | the move counts the peering heard, and forgets the msg1s remembered against replay for it if it was unheard, as that first frame would. `MoveLeavesUnheard` puts back the old heard, and with it the memory |

## What `maint.rs` transcribes

The deployed node, at the tag `v0.5.3` (`f4a5b4a8`), with the line ranges
read there:

- `src/node/handlers/handshake.rs`: the replay memory (`:100-200`,
  `MAX_REPLAYED_MSG1S` at `:91`), `establish_snapshot` and
  `outbound_snapshot` (`:220-284`), `answer_msg1` and `link_reachable`
  (`:488-582`), `handle_msg1` (`:584-1541`): the duplicate short circuit
  (`:673-722`), the `RekeyRespond` arm (`:954-1074`), the restart and
  replacement gates (`:1075-1231`), the promotion tails (`:1386-1401`,
  `:1520-1536`); `handle_msg2` (`:1582-2126`): the rekey arm
  (`:1605-1741`) and the cross-connection swap and keep (`:1910-2056`);
  `EPOCH_RESTART_MIN_INTERVAL_SECS` at `:52`,
  `UNHEARD_PEERING_MIN_AGE_MS` at `:73`.
- `src/proto/fmp/core.rs`: `AnsweredMsg1s` and `ENDED_MSG1_RECORD`
  (`:163-255`), `REKEY_MIN_LINK_AGE_SECS` (`:630`), `poll_rekey` (`:741`),
  `poll_rekey_resends` (`:787`), `establish_inbound` (`:830-948`),
  `establish_outbound` (`:950-959`).
- `src/peer/active.rs`: `replace_session` (`:617-630`), `is_heard`
  (`:840`), the rekey slots: `answered_before`, `is_setup`, `note_setup`,
  `set_pending_session`, `answer_rekey`, `release_pending`,
  `cutover_to_new_session`, `handle_peer_kbit_flip`, `adopt_pending`,
  `retire_pending`, `abandon_rekey` (`:1150-1622`).
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
  `remove_link` (`:2836-2888`).

Where it differs from `master.rs`, each read at both refs:

- A held peer's own-dial msg2 swaps by the address tie-break alone
  (`establish_outbound` has no own-dial clause and no epoch check), and
  the swap replaces the session only: the peer's link, address, epoch on
  record, session age and pending slot stay (`replace_session`).
- A failed msg2 send at a msg1 leaves no leg with a stored msg2; a resend
  of that msg1 is judged afresh.
- The rekey record holds the setup msg1 and each armed msg1 whose pending
  has left, by its bytes; a refused or replaced msg1 is not recorded.
- An own rekey is abandoned after its resends, with no deadline of its
  own; a rekey answer that cannot be sent arms no pending.
- The gates read the wall clock; the node has them on the peer clock
  since `f7db531c`.
- The peer's address is its own field, with no bundle, no link-dead timer
  and no feed.

It keeps its own rekey transcription, so a change to the machine reaches
`master.rs` and not this model. Two rules the two models used to part on
now agree, and neither is a difference any more: the rekey msg2 puts the
peer's new epoch on record at once (the machine does too, at the msg2 that
reveals it), and a frame under the previous session marks the peering heard
(a frame of any slot does, at `db946033`), the replay memory being forgotten
at the first frame.

### Why the tag

No tag newer than `v0.5.3` exists, and this model was first transcribed from
`9fc10516`, 65 commits after it, so pinning it to the tag is a step back.
`git diff v0.5.3 9fc10516` over the transcribed files touches four of them.
Each hunk, by the line at `v0.5.3`, and what it decides here:

| File | Lines | What differs at the tag | Verdict |
| --- | --- | --- | --- |
| `handshake.rs` | `:261-266` | `establish_snapshot` fills `has_pending_outbound_to_peer` | the inbound cap's bypass, not modelled: the world's nodes never reach `max_peers` |
| `handshake.rs` | `:1397`, `:1531`, `:2049` | a comment on the filter announce | none |
| `fmp/core.rs` | `:396-398` | the snapshot's field | the same bypass |
| `fmp/core.rs` | `:577-578` | `InboundReject::AtMaxPeers`'s doc | none |
| `fmp/core.rs` | `:835-837` | the cap's test skips a peer with an own dial in flight | the same bypass |
| `peer/active.rs` | `:616` | `replace_session`'s doc | none |
| `peer/active.rs` | `:627` | the tag does not reset MMP's counter state at a swap | not modelled: MMP is not transcribed, and no property reads it |
| `peer/active.rs` | `:1622` | a test module's declaration | none |
| `node/mod.rs` | `:800-805`, `:1051`, `:1216` | a rate-limit field against a sequence origin, for the bloom filter | none: not settlement |
| `node/mod.rs` | `:893`, `:1068-1070` | the constructors do not apply the config's floors | none at the default configuration the model reads |
| `node/mod.rs` | `:1650`, `:1675`, `:2217-2219`, `:2385` | the IPv6 shortfall's warning, comments on the MTU's fallback and the filter's metrics | none: not settlement |
| `node/mod.rs` | `:3375-3398` | the identity cache's eviction and lookup | none: not settlement |
| `node/mod.rs` | `:3509-3527`, `:3537-3542`, `:3577`, `:3603`, `:3683-3686` | docs of routing and of the app-owned TUN | none |
| `node/mod.rs` | `:3986`, `:3995-3996` | the send path's MTU check before a counter is reserved | none: the world's frames all fit |

So no hunk decides a modelled rule, and the model's code is what it was: only
its line references moved. `src/node/handlers/rekey.rs`, `encrypted.rs`,
`peer_actions.rs`, `dispatch.rs` and `fsp/limits.rs` have no difference
between the two refs (`git diff --stat`). `v0.5.0` to `v0.5.2` differ by over
two thousand lines in those files (`git diff --stat <tag> 9fc10516`); whether
their settlement differs is not established, and the model does not claim them.

A path message reaches this model as a frame of an unknown type: the deployed
node's link layer reads it no further and discards it after marking the peering
heard (`../../../path/tests/stub.rs`, `Deployed`). So a legacy end never answers
a capability probe, and its peer never turns capable.

Not transcribed: the inbound cap at `max_peers`, the rekey dampening of
an own rekey after the peer's, the rekey trigger's age and message
count (the world's explorer starts a rekey once the link and session are
old enough, as for `master.rs`), MMP, the decrypt workers, and the link-dead
timer. The last of these has a cost in the runs against it: this model holds
a silent peer for the rest of a heal where the deployed node removes it at 30
s, so a joint node's redial is refused off the link for the rest of the heal.
A `OneSession` at the joint node that says a configured peer is not held is
therefore the model's, and is not shown of the deployed node: a scratch edit
giving the model the timer removes every one of them from the runs at
multipath off.

## Rules for changing it

- `master.rs` is the current node, not the FRC: where the two differ, it
  keeps the node's behaviour, and the comparison names the difference
  (`../shadow.rs`) or the finding tests show it.
- Neither model's rekey or paths are its own to change here: `master.rs`
  runs the machines, and `maint.rs` keeps its transcription of `maint`.
- `maint.rs` knows no paths, and a path message is a frame to it: it never
  answers a probe, so a start on real bundles runs against it at one path.
