# core/src/proto/fmp/flow

The XX handshake flow of the settlement core (`proto::settle`): how
next's three-message Noise XX handshake is classified, written as a
profile of the one settlement table, as `rekey/` is next's profile of the
one rekey machine. Nothing in the node runs it yet. Hidden from the docs.

The table (`proto::settle::table`) keeps the rules every handshake shares:
the link records, the legs, the gates' memory, the held peers, removal,
the path inputs and the close rule. This flow decides what an XX msg1,
msg2 and msg3 do, as next's shell decides them today
(`src/node/handlers/handshake.rs`, and `establish_inbound` and
`establish_outbound` in `../core.rs`). Next's code is the spec here, not
FRC-2201; the module comment of `mod.rs` lists where the flow differs from
the IK flow.

## Files

- `mod.rs`: `Xx`, the state the flow keeps in the table's flow slot (its
  anonymous answers and dials, the msg2 decisions parked on their dials,
  the failed legs, and the per-peer marks next's msg2 rule reads),
  `params`, the XX parameters of a table, the `xx_fault!` macro, the rules
  every message shares (the shell's refusals, which close nothing; next's
  promote refusals, the leaf rule and the max-peers cap; the failed legs
  and their sweep), and the flow's implementation of `settle::flow::Flow`:
  its hooks, which the table's shared rules call, and its step.
- `msg1.rs`: an anonymous msg1 opens its link and asks for its answer, and
  the answer opens a leg that names no one.
- `msg2.rs`: this node's anonymous dials, and next's `establish_outbound`
  at msg2, parked until the msg3 is sent: promote, restart with no gate,
  the own-dial keep with no msg3, and address order.
- `msg3.rs`: next's `establish_inbound` at msg3 (its crossing told as the
  column next's node runs, a move at the larger node and a keep at the
  smaller): the promote, unless the
  identity's silent sessions refuse it; the restart, through next's one
  floor and the dampener; the repeat of the stored msg2 for a claim of a
  session not held; the crossing, which the larger node's inbound wins;
  and the rekey handed to the peer's machine with the leg's lease.
- `faults.rs`: the flow's test-only switches, read from
  `FIPS_SETTLE_XX_FAULTS`; each is a variant of the node's list too
  (`crate::faults`), and a site reads `xx_fault!(X) || node_fault!(X)`.
- `input.rs`: `In`, the flow's inputs: the anonymous msg1 and its answer,
  the anonymous dial, the msg2 with the identity it taught, the outcome of
  the msg3 send, the shell's refusals and failures, the msg3 and the sweep.
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
