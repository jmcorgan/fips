# core/src/proto/fmp/flow/model

A reference model of the XX handshake's settlement: the judge. It reads an
abstract history of what one node saw of one peer identity and says what
that node does: each completed handshake's class (FRC-2201 Section 5.7),
the check that refused it (Sections 5.2, 5.3, 5.6, 5.7, 7.3), what the
node sends, the peer change, and the connections the change closes. The
XX flow and the transcription of next's rules are compared with it.

It is written from FRC-2201 Sections 5.2 to 5.7 and 7.2 to 7.4 (fips-frcs
`c5df033`; the text is unchanged at `f73c5ce`) by an author who had read
neither next's handshake code nor the XX flow, so neither's choices leak
into it. That author had read the port plan, whose Section 1.1 describes
next's rules in prose; the judge takes from the plan only the three local
rules it names (N2, N4, N7) and nothing of next's other choices. When the
code and the judge disagree, ask in order: does the judge misread the FRC,
does the code break it, or does a local rule below decide it.

## Files

- `mod.rs`: the module doc and declarations. The flow declares it
  `#[cfg(test)] pub mod model;`, on a line of its own, which a scan reads.
- `history.rs`: the events (`Event`) and the values they carry. A
  handshake is named by its msg1's ephemeral (`Hs`), which both ends know.
  An XX msg1 carries no identity, so the history, not the node, says whose
  it is; the judge reads a msg1 only by its source and handshake.
- `judge.rs`: `Judge`, one node's view of one peer, and `Step`, what one
  event did. Each FRC rule's outcome is one line with its FRC line beside
  it.
- `tests/`: table tests, one per FRC rule and local rule, and the scans
  that keep the judge apart from the flow and the settlement core. See its
  README.

## What the judge leaves out

Admission (the token buckets, the pending-handshake cap, the cookie of
Section 5.5, the policy that declines inbound peering and its attribution):
the history holds only msg1s that passed it. The negotiation verdict, the
peering decision and the attribution check are one flag on a msg2 or msg3,
`refused`. Retransmission (Section 7.6) is the history's: a resent msg1 is
a second `Msg1` event, and a lost msg3 is one the history never delivers.
The rekey trigger (Section 7.1) is the history's `RekeyStart`. The node's
other peers, and so a cap on peers, are outside one identity's view.

## Local rules

Where FRC-2201 is silent, or where a node keeps its own rule in place of an
FRC rule, the judge follows a named rule (`judge::LocalRule`). The first
three replace an FRC rule and are switched on together by
`Params::local()`; `Params::default()` is the FRC.

- `NoLiveTest` (port plan row N2): no live-link test. Where Section 5.7
  has the initiator test whether the established link is live (a frame on
  it, or the msg2 that installed it, within `LINK_LIVE_WINDOW`), the node
  stays on the established link only when it is its own dial, unheard
  since it was installed or moved onto, and installed or moved onto after
  this attempt began: the own-dial keep. Which came first is read from
  the order of events, not the clock, since an attempt and an install can
  fall in one millisecond. Marked on a step where the FRC's test would
  have decided otherwise.
- `RefusalDisconnect` (row N4): a responder that refuses a msg3 at its
  peering decision sends a `Disconnect`. The FRC sends nothing.
- `DampenerStamp` (row N7): only an epoch change accepted at a msg3 stamps
  the dampener. The gates are optional, so counting fewer acceptances
  refuses less, which a node may do.
- `KeepEndsAttempt`: the larger node of a crossing that completes at its
  own msg2 keeps what it holds and sends no msg3. Section 5.7 says it
  keeps, and that a check after the identity check that refuses ends the
  attempt without msg3; it does not say the keep is such a refusal.
- `StaleKeepsLeg`: a msg3 whose declaration names a session index not
  held changes nothing, and its pending inbound handshake is left for its
  timeout. Section 5.7 keeps the session and resends the stored msg2, and
  is silent on the handshake.

The restart gates are optional (Section 5.6); the judge applies both
whenever their condition holds. The first counts frames of the peering on
any link; the second counts accepted epoch changes. The live test counts
frames on the established link only, since a move changes the link.

## Rules for changing it

- Change the judge only from FRC-2201 or an operator decision, never from
  the code. A new local rule gets a `LocalRule` variant, a line above, and
  a test of its value.
- It names nothing outside itself: no `crate::` path, and no module of the
  flow or the settlement core (`tests/mod.rs` scans for both), and no flow
  source names it but its declaration.
- `no_std` with `alloc`; at most one underscore in a name outside tests.
