# core/src/proto/settle/model/tests

Table tests for the reference model. Each cites the FRC-1201 line it reads
(`frc-1201:<line>`, at fips-frcs `7c41380`), or names the local rule whose
value it asserts.

## Files

- `mod.rs`: the module list and the history builders the tests share
  (`dial`, `msg1`, `msg2`, `frame`, `wait`, `last`, `responder`).
- `classify.rs`: Section 5.7, one test per rule, 1 to 4.5, in order.
- `gates.rs`: Section 5.5: each gate edge (the unheard floor, the heard
  interval, the dampener's ceiling), the definition of heard from, and
  the dampener stamping values.
- `crossing.rs`: Section 5.6: the tie-break in both address orders, the
  own-dial rule, a msg1 after the peer is held, a msg2 with a changed
  epoch, and the late-second-dial, late-stored-msg2 and aged-link values.
- `close.rs`: Section 5.6's close clause and the addresses each live link
  still needs.

## Rules for changing it

- A test asserts what the FRC line it cites says, or a local rule's value.
  If the FRC line moves, re-read it and update the citation.
- Each rule's outcome lives on one line of `judge.rs`; flipping that line
  must red the test that cites the rule.
