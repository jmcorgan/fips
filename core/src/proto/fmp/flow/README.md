# core/src/proto/fmp/flow

The XX handshake flow of the settlement core (`proto::settle`): how
next's three-message Noise XX handshake is classified, written as a
profile of the one settlement table, as `rekey/` is next's profile of the
one rekey machine. The node's settlement table runs it, and the node
carries out its decisions. Hidden from the docs.

The table (`proto::settle::table`) keeps the rules every handshake shares:
the link records, the legs, the gates' memory, the held peers, removal,
the path inputs and the close rule. This flow decides what an XX msg1,
msg2 and msg3 do, as next's shell decided them at `be5204f9e`
(`src/node/handlers/handshake.rs`, and `establish_inbound` and
`establish_outbound` in `../core.rs`, which the node no longer has: it
carries out this flow's decisions instead). Next's code is the spec here, not
FRC-2201; the module comment of `mod.rs` lists where the flow differs from
the IK flow.

## Files

- `mod.rs`: `Xx`, the state the flow keeps in the table's flow slot (its
  anonymous answers and dials, the msg2 decisions parked on their dials,
  the failed legs, and the per-peer marks next's msg2 rule reads),
  `params`, the XX parameters of a table, the `xx_fault!` macro, the rules
  every message shares (the shell's refusals, whose connections the node
  closes by its own rule; next's
  promote refusals, the leaf rule and the max-peers cap; the failed legs
  and their sweep; the retry a dial past its deadline asks for, and an
  identified dial's at a failed connection), and the flow's implementation
  of `settle::flow::Flow`:
  its hooks, which the table's shared rules call, among them the one that
  counts a removed silent session only when the peer dialed it, and its
  step.
- `msg1.rs`: an anonymous msg1 opens its link and asks for its answer, and
  the answer opens a leg that names no one.
- `msg2.rs`: this node's anonymous dials, and next's `establish_outbound`
  at msg2, parked until the msg3 is sent: promote, restart with no gate,
  the own-dial keep with no msg3, and address order, where the smaller
  node's move closes the link it left but not its dial's own connection,
  as next's move does, which the table's move would close when the msg2
  came from another pair.
- `msg3.rs`: next's `establish_inbound` at msg3 (its crossing told as the
  column next's node runs, a move at the larger node and a keep at the
  smaller): the promote, unless the
  identity's silent sessions refuse it; the restart, through next's one
  floor and the dampener; the repeat of the stored msg2 for a claim of a
  session not held; the crossing, which the larger node's inbound wins,
  the larger node moving the peer onto the answer's link, session and
  lease and retiring the link it held (`Ops::move_answer`), so both ends
  settle on the link the smaller node dialed (FRC-2201 Section 5.7);
  and the rekey handed to the peer's machine with the leg's lease.
- `faults.rs`: the flow's test-only switches, read from
  `FIPS_SETTLE_XX_FAULTS`; each is a variant of the node's list too
  (`crate::faults`), and a site reads `xx_fault!(X) || node_fault!(X)`.
  `Msg3MoveKeepsHeldLink` puts back the crossing next settled before: the
  larger node keeps the peer on its own dial's link with the answer's
  session (`Ops::hold_answer`). That defect shape is the only caller of
  `hold_answer`, which stays in the core's facade for it; the call is
  compiled only in builds that can turn the switch (tests and
  `test-hooks`).
- `input.rs`: `In`, the flow's inputs: the anonymous msg1 and its answer,
  the anonymous dial, the msg2 with the identity it taught, the outcome of
  the msg3 send, the shell's refusals and failures, the msg3, the sweep,
  the node's timers ahead of the table's poll (`Due`), or a node's timer
  reaping one dial alone (`Timed`), a dial's failed
  connection with the identity it named (`Unconnected`), and the shell's
  word that a dial sends no more resends (`Quiet`). The anonymous msg1's
  `rekey_of` stays the shell's: the node computes it and keeps its own map
  of it for the moved-msg3 lookup, and the flow reads it only in
  `AnonLegNamed`'s defect shape.
- `output.rs`: `Out`, the flow's outputs (the ask for an anonymous msg1's
  answer, the msg3 to send, the stored msg2 to repeat, the rekey handed to
  the peer's machine with its lease, the heard path offered), and `Deny`,
  its refusal (the leaf rule).
- `model/`: the judge, a reference model of the XX handshake's settlement
  written from FRC-2201 alone, by an author who read neither next's
  handshake code nor this flow. It is compiled for tests only, names
  nothing of the flow or the settlement core, and no flow source names it
  but its declaration in `mod.rs`. Its README says what it covers and its
  local rules.
- `rules.txt`: the flow's incidental rules, each rule of next's handshake
  settlement whose outcome no clause of FRC-2201 and no decision fixes, with
  rule IDs `XX-NN`; and `current.txt`, each test that records one, whose doc
  line says it records current behaviour. They are next-only, beside the
  settlement core's own `../../settle/rules.txt` and `current.txt`, which
  mark master's node tests. `src/node/settle/tests/rules.rs` checks the two
  against each other and the tests' doc lines.
- `tests/`: the unit tests; its README describes them.

## The closes this flow decides

On next the node carries out none of the connection closes the core
decides. It reads a `Retire` only for the link it names
(`src/node/settle/decide.rs`), drops every close the core's link records
return (`let _closes` in `src/node/settle/links.rs`), and closes a
connection by its own rule, `Node::in_use` in `src/node/mod.rs`. So the
closes this flow writes are checked only by the core's tests: the strip in
`msg2.rs`'s `swap` and its switch `MoveClosesDial`, the "closing nothing"
of `end` and of the refusals, and the closes of `Ops::move_answer`. They
state next's close rule in the core's terms and agree with what the node
does, but a change to them changes nothing in a running node. Making the
node carry out `Retire.closes`, or dropping the core's close decisions on
next, is a design change left for its own decision; until then a fix to
which connections next closes goes in the node.

## Rules for changing it

- **No file under `proto/settle/` changes for this flow.** The flow reaches
  the table only through `settle::table::Ops`, its facade, and the hooks of
  `settle::flow::Flow`. A shape, operation or hook the flow needs and the
  facade lacks is added on master's line, as a change that leaves the IK
  flow's every outcome as it was, and merged here; it is never written here
  first.
- **Every guard has a switch.** A condition that stands for a rule of next's
  is written behind `xx_fault!(X) || node_fault!(X)`, with the variant in
  `faults.rs` and in the node's list, a row in `tests/faults.rs`, and a
  line in `testing/mutations/manifest.txt`.
- **Every match is exhaustive.** `mod.rs` denies the wildcard arm at the
  root, as the settlement root does, and the tests check that it does.
- **An outcome no FRC-2201 clause and no decision fixes is an incidental
  rule.** It gets a line in `rules.txt`, and each test that asserts it a
  line in `current.txt` and the doc line "Records current behaviour (rule
  XX-NN): open to change by decision". Changing such an outcome is a
  decision, made with both lists and the tests in one change.
- **The flow's state is keyed by link number or identity**, in ordered
  maps, as the table's is. A leg the table reaps leaves its entries behind;
  each step forgets the entries whose leg or link is gone.
