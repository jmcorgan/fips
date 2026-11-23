# core/src/proto/fmp/flow/model/tests

Table tests of the XX judge, declared from `../mod.rs` as `tests`. Each
test cites the FRC-2201 rule or the local rule it holds the judge to.

## Files

- `mod.rs`: the helpers every file shares (the smaller and larger node,
  the epochs, the events, a judge holding the peer by its dial or by its
  answer), and the scans: no judge source names a module of the flow or
  the settlement core or any `crate::` path, the judge's tests take only
  the scan helpers from outside, no flow source names the judge but its
  declaration, and every judge source file is in the scans' list. Each
  scan plants its own failing case.
- `msg1.rs`: Section 5.2's duplicate and its new handshake beside a
  pending one.
- `msg2.rs`: the initiator's order of checks: the identity check, the
  peering decision, the restart gates, the crossing completed at msg2 and
  the second dial by the same side, with the live-link test.
- `msg3.rs`: the responder's checks and classification: a new peer, the
  restart gates, the two declarations, the simultaneous rekey, the
  crossing completed at msg3 and the second handshake dialed by the peer;
  and both ends of a simultaneous dial settling on the smaller node's dial
  in every order.
- `session.rs`: frames and the peer's address, this node's own rekey and
  its cutover, the changed epoch in a rekey msg2, timeouts, loss and
  restart.
- `rules.rs`: each local rule's value and the outcome it decides.

## Rules

- A test's name states what it asserts.
- A new judge source file is added to `MODEL` in `mod.rs`, or the scan
  that counts them reds.
