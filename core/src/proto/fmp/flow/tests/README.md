# core/src/proto/fmp/flow/tests

The unit tests of the XX flow, each stepping a settlement table that runs
it (`Table<TestInstant, Xx>`), declared from `../mod.rs` as `tests`.

## Files

- `mod.rs`: the helpers every file shares: the pairs, the smaller and the
  larger node, the epochs, a table of either node, and the steps.
- `mod.rs` also holds the scans of the flow's sources: the wildcard-arm
  deny at its root, no test in a source file, and every test named by a
  switch's row or listed with why (the settlement core's
  `tests::faults::uncovered`).
- `slot.rs`: what the flow keeps in the table, through the table's own
  inputs: the XX parameters, the marks an install and a move set, and the
  frame mark.
- `msg1.rs`: the anonymous answer, its send, and the admission cap.
- `msg2.rs`: this node's dials, the anonymous ones included, the decision
  parked until the msg3 is sent, the own-dial keep, address order and the
  connection the smaller node's move leaves open, the restart, the promote
  refusals, the shell's failures and refusals, the retries of a dial past
  its deadline and of an identified dial's failed connection, and a dialed
  session that ends unheard, which counts as no silent session.
- `msg3.rs`: the promote, the restart gate, the claims, the crossing,
  the silent-session refusal, and the promote refusals at msg3.
- `chars.rs`: characterisations of where the flow on the shared table
  meets next's code: the stored msg2's byte rule; the gates' silent
  sessions against next's `SilentSessions`, event by event; the admission
  cap's count; the crossing's two guards, always true; the install mark
  against next's `predates`; the retry after each failure at msg2; the
  shell's refusals at msg1 and at the crossing's returns; and next's
  restart floor and dampener against the gate, over a grid.
- `next.rs`: `NextParty`, next's handshake settlement transcribed from
  its shell at `be5204f9e` (the table below), as a node of the settlement
  world (`proto::settle::tests::world`), with `Packet`, the XX packets it
  adds to the world's (the anonymous msg1 and the msg3). It runs no keys,
  rekey machine or path bundle, and logs, per peer identity, each event of
  the judge's history and what it did, in the judge's terms. It does not
  run the flow.
- `judged.rs`: the check of `NextParty` against the judge (`../model/`):
  scripted runs of two next nodes over one connectionless transport, each
  node's log replayed peer by peer through a judge with the local rules
  on, every difference required to have a known cause, and each run
  stating which it shows: the two pinned defects (no restart gate at
  msg2; the same-side second handshake settled by address order) and two
  differences the check found (the larger node's keep at msg2 sends msg3;
  next's restart gate counts from the install).
- `joint.rs`: `FlowParty`, the flow on a settlement table as a node of the
  settlement world, its shell turning the world's packets into the flow's
  inputs and the table's outputs into packets, with no keys, rekey machine
  or path bundle; and scripted runs of two such nodes, each run also on two
  `NextParty` nodes with the same deliveries: each flow node must log, peer
  by peer, the events and outcomes the next node in its place logs (link
  numbers aside), end on the same sessions, and differ from the judge only
  where `judged.rs` names a cause for next. The larger node's redial off a
  link it dialed runs on flow nodes alone, since the flow withholds that
  redial's msg3 where next sends it (the same-side rule); its one
  difference from the judge is row N2's.
- `faults.rs`: each switch's row, the tests listed as characterisation
  with why, and the meta-test, which runs under the `slow-tests` feature:
  each row's tests in a child with the switch on, which must fail, and
  with none, which must pass.

## Rules

- A test's name states what it asserts, and its behaviour assertion
  carries a message starting `defect:` where a switch is meant to red it,
  `precondition:` for its setup.

## What `next.rs` transcribes

At `be5204f9e`, each site with its line. The port has since replaced the
node's sites with the node carrying out this flow's decisions, and removed
`establish_inbound` and `establish_outbound`, so the lines record what was
transcribed. This is a reviewer's
checklist: a change at one of these lines reds no test here, so a re-read
is the check that the transcription stands.

| Site | Line | In `next.rs` |
| --- | --- | --- |
| `handshake.rs`, `handle_msg1`: the address's pending leg and `is_new_msg1_attempt` | `:309`, `:415-470`, `:694` | `msg1`: the same bytes from a pending leg's source draw its stored msg2; any other msg1 opens a leg |
| `handshake.rs`, `handle_msg2`; `fmp/core.rs`, `dial_outbound` | `:874`, `:801` | `msg2`: a static other than the dial named drops the msg2 and keeps the dial |
| `fmp/core.rs`, `establish_outbound`; `handshake.rs`, `outbound_snapshot` (`beside_own`) | `:765`, `:52-75` | `msg2`'s classes: promote, replace with no gate, the own-dial keep, swap or keep by address order |
| `handshake.rs`, the withheld msg3 and the send | `:1202-1243` | no msg3 at the own-dial keep; msg3 at every other class |
| `handshake.rs`, the swap and the keep, `facts.loser` | `:1250-1535`, `:1518` | the swap onto the dial at the msg2's pair; the keep dropping the dial's link |
| `fmp/core.rs`, `establish_inbound` | `:642` | `msg3`'s classes |
| `handshake.rs`, the msg3 snapshot: `peering_idle_ms` from `heard_at`, the dampener | `:1969-1981` | the restart gate: idle since the install or the last frame under 15 s, or the dampener |
| `peer/data.rs`, `heard_at` set at the install | `:148` | `Peer::heard` at the install |
| `handshake.rs`, the stamp on an accepted msg3 restart | `:2174` | `dampener` |
| `handshake.rs`, `RepeatMsg2` and `PeerRekey` | `:2121`, `:2098` | the two claims |
| `peer_actions.rs`, `ResolveInboundCrossConnection` | `:553-690` | the crossing at msg3: the larger node moves onto its inbound's session at the msg3's pair, on the link it holds, the leg's link retired; the smaller keeps |
| `peer/active.rs`, `predates`, `heard_on_session` | `:1504`, `:1514` | `Peer::mark`, `Peer::framed` |
| `config/node.rs`, the handshake and heartbeat defaults | `:147-150`, `:1756-1757` | the world's constants and `LINKDEAD` |

Read and not modelled, each because the runs here do not reach it or
because it is outside one pair of nodes: the rate limiter and the accept
gate; the ACL, the self check and the negotiation verdict (no run refuses
at them); the session index draw failing at msg1; `SilentSessions`
(`fmp/core.rs:928`), the peer cap and the leaf rule; anonymous dials (the
world's dial names a peer); the msg3 send failing; the heard-path offer
at the own-dial keep; the rekey machine, so a `Matches` claim is held as a
pending session until the peer's frame; the closes, since the runs use a
connectionless transport; and the address index, whose newest link at an
address the duplicate test reads, which here is any pending leg at the
msg1's source.
