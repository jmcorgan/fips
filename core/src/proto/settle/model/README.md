# core/src/proto/settle/model

A reference model of peer settlement. It reads an abstract history of what
one node saw of one peer identity and says what that node does: each
msg1's class (FRC-1201 Section 5.7), whether a restart gate refused it
(Section 5.5), the reply, the peer change, the connections the change
closes (Section 5.6's close clause), and which `(transport, address)` each
live link still needs. Tests on real nodes and, later, the settlement core
are compared with it.

It is written from FRC-1201 Sections 5.5 to 5.8 and the operator's
decisions only, by an author who had not read the handshake code, so the
code's choices do not leak into it. When the code and the model disagree,
ask in order: does the model misread the FRC, does the code break it, or
does a local rule below decide it.

## Files

- `mod.rs`: the module doc and declarations.
- `history.rs`: the events (`Event`) and the values they carry. A
  handshake is named by its msg1's ephemeral (`Hs`), which both ends know;
  a msg1's exact bytes are named separately (`Bytes`).
- `judge.rs`: `Judge`, one node's view of one peer, and `Step`, what one
  event did. Each FRC rule's outcome is one line with the rule and its FRC
  line beside it.
- `tests/`: table tests, one per FRC rule and local rule value. See its
  README.

## Local rules

Where FRC-1201 is silent, or leaves the choice to the node, the model
follows a named rule (`judge::LocalRule`). Each says what it decides:

- `LateSecondDial`: a node whose own later dial is answered while it holds
  the peer on a link it dialed moves onto the new session, but keeps the
  session it moved off until the peer's first authenticated frame shows
  which one to keep (the operator's decision). The FRC moves the peer and
  is silent on the old session.
- `StoredLate`: a responder leg whose stored msg2 is sent after the peer
  is already held through another link resends that msg2 and installs
  nothing. The FRC says to install once a send succeeds, and is silent on
  a peer already held by then.
- `DampenerStamp`: which accepted restarts and replacements stamp the
  dampener the gates' ceiling counts from. A restart or replacement found
  at a msg1 stamps it if the old peering was heard; a restart found at
  this node's own msg2 does not; a restart revealed in a rekey msg2 with
  the link kept does not. The FRC does not say which acceptances count.
- `AgedLink`: this node's own dial, sent on the peer's established link
  once that link was old enough to rekey, completes while the peer is
  held. The peer will have read that msg1 as a rekey. The operator has
  left this undecided, so the model sets `Step::open` and changes nothing;
  no test asserts an outcome for it.
- `BetweenFloors`: between the gates' floors and their ceiling the FRC
  lets a node refuse or accept; the model refuses there only while the
  dampener holds.
- `RecordScope`: the msg1 record of rules 3.2 and 4.3 holds the setup
  msg1's ephemeral and every msg1 of the epoch on record answered or
  refused under rules 3 and 4, for the life of the peering; a new peering
  starts a new record.
- `SessionAge`: `REKEY_MIN_SESSION_AGE`, which a node chooses between 10 s
  and 30 s, is 10 s by default (`Params::sessionage`).

One more outcome is marked `Step::open`, because it lies outside the
model's sources: rule 4.4's simultaneous rekey is resolved only as far as
FRC-1201 Section 5.8 states Section 7.3's outcome (the smaller node
discards the peer's rekey msg1; the larger answers it), and what then
becomes of the larger node's own rekey is left open.

## Rules for changing it

- Change the model only from the FRC or an operator decision, never from
  the code. A new local rule gets a `LocalRule` variant, a line above, and
  a test of its value.
- Every item is `pub`: the root crate's `test-hooks` build compiles the
  model outside `cfg(test)`, where a private item only the model's own
  tests use would be dead code.
- `no_std` with `alloc`; at most one underscore in a name outside tests.
