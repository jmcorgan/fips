# core/src/proto/rekey/tests

The rekey machine's unit tests. They drive the real machine through its
public interface with synthetic instants (`testutil::TestInstant`,
milliseconds) and deterministic stub crypto, read no clock and never
sleep.

## Files

- `mod.rs`: declares the files below, checks that the module root still
  denies wildcard match arms, and scans every source file of the machine
  for a state setter (a test must reach every state through inputs),
  with a planted setter to show the scan can find one and a count of the
  directory's files to show none is left out.
- `stub.rs`: the stub profiles and the test shell.
  - `Ik` (two messages, index-bearing: the link shape), `Xk` (three
    messages with candidates: the session shape), `XkFrame` (as `Xk`,
    with a responder that cuts over on the initiator's frame) and `Xx`
    (three messages, index-bearing, a delayed initiator cutover and a
    leg table's completions: the shape only next selects).
  - Stub handshakes: an ephemeral is an attempt identifier from a
    per-node counter, and every message carries a keyed hash over its
    transcript in place of an AEAD tag, so forged, replayed, corrupt and
    wrong-identity messages are all easy to build. `read_msg1` stands
    for the node-level IK msg1 read; `leg_answer` and `leg_done` for a
    leg table; `forge3`, `ik_frame` and `leg_frame` build messages a
    peer or a third identity would send.
  - `Node`, the test shell: it owns one machine and the capabilities its
    `Env` lends, executes outputs as a shell does (returning leases to
    its pool, sealing each `Prompt` at once, putting sends and frames on
    its wire) and records each output as a comparable `Ev`. `pair`
    builds two machines that share a first epoch as link setup leaves
    them; `open_out` and `open_in` start first handshakes; `rebuild`
    makes a machine from what `close` carried.
  - The shell checks three properties on every call, so every test that
    drives a machine checks them: a poll before the instant the last
    call's `next_wake` named does nothing (a re-offer to a worker
    excepted, since it answers the shell's worker state); the machine
    holds no more candidates than its profile allows; and `close`
    retires every epoch held, abandons an own attempt as closed, unbinds
    every index and returns every lease.
  - `Mid`, the jitter source, draws the middle of the band (a zero
    jitter) unless a test queued draws. `failed` counts the frames this
    thread's stub sessions failed to open, which shows the order epochs
    were tried in.
- `fmp.rs`: the two-message tables: trigger, attempt and ladder, every
  IK msg1 and msg2 cell, the poll cutover, adoption by frame, the drain,
  restart in a msg2, decrypt workers, the counter limits, the abandon
  backoff, the record, a cross-connection move and `close` in every
  cycle state.
- `fsp.rs`: the three-message tables: setups, acks and the msg3
  dispatcher, probes and the confirmation deadline, the assumed cutover
  and its revert, prompts answering probes, Karn's rule, the silence
  trigger and its doubling, restart, the trial order, and the first
  handshake.
- `next.rs`: the rows only next's profiles select: leg completions, the
  delayed cutover and its retained msg3, and a frame-driven session
  responder.
- `sim.rs`: the deterministic two-party simulator. `World` holds two
  shells and the datagrams between them, executes outputs as a shell
  does, models a decrypt worker (indexed profiles) and next's leg table
  (`Xx`), and checks the oracles after every event: convergence once
  healed (O1), bounded outage of data frames (O2), index and lease
  conservation (O3), a next wake in the future after every poll and no
  own attempt past its deadline (O4), forged input changing nothing but
  candidates and copies nothing but candidates and the record (O5, with
  the replayed-msg1 residual, its sender index rewritten or not, reported
  and contained, O10; whether a msg1 is that residual is judged from the
  world's own list of the ephemerals each node answered or refused, never
  from the machine's record, so a lost replay defence fails O5 instead of
  passing as the residual), bounded memory (O6), cadence under forgery
  (O7), drain ceilings (O8), the worker's epochs (O9), no orphan machine
  (O11),
  and data sealed only under an epoch the peer has held. The channel draws
  loss, duplication, heavy-tailed delay, partitions, suspensions, worker
  losses and adversary actions from a seed; each decision is keyed by a
  stable identifier, so a run replays from its seed and a failing run's
  decisions are removed one at a time while it still fails (`shrink`).
  Scripted `Rule`s drop or withhold one class of datagram from one node
  in a window. Its tests run faulty seed sets per profile, clean sets
  (no rejects, abandons, reverts or assumed cutovers, cadence-exact
  rotation; a healthy crossing's outcomes allowed), equal-jitter crossing
  sets, lossless runs under forgery, and the byte-identical replay check.
- `explore.rs`: bounded exhaustive exploration. From each scenario's
  start, every sequence of events up to its depth (deliver, duplicate a
  handshake message, deliver a bit-flipped frame, advance to the next
  wake, poll one end late, seal data, third-identity msg3, a stranger's
  setup) is enumerated breadth first with states de-duplicated on a
  canonical key and the event budget the path spent, the simulator's
  oracles checked on every step, and every frontier state first fed
  seeded random byte strings of every input kind (which must change
  nothing and panic nowhere) and then healed to O1. A machine cannot be
  cloned (its leases are linear), so each state is rebuilt by replaying
  its path. Depths are 5 or 6; the scenarios run on threads of their own.
- `legacy/`: executable models of the deployed releases v0.5.0 to
  v0.5.3, the interop simulation of new nodes on the production
  profiles against them, the same for the session node this release
  ships (the machine polled on the shell's tick), and the bounded
  explorer over the same pairs; its README describes it. It exists on master
  only: next's merge of the production profiles replaces it.
- `regress.rs`: scripted schedules of historical defects and adversarial
  traces, each run with a zero O2 bound and each asserting that it reached
  the state it targets, so a schedule that drifts tests nothing loudly.
- `faults.rs`: the meta-test of the guard switches (`../faults.rs`). Each
  row's tests run in a child process of this test binary with its
  switches on and must fail; each named test runs once with none and must
  pass; a switch with no row fails the test.
- `candidates.rs`, `ladder.rs`, `lease.rs`, `params.rs`, `reason.rs`,
  `record.rs`, `resolve.rs`: tests of one module's private items, each
  attached from that module with `#[path]`, so their names are
  `proto::rekey::<module>::tests::...`.

## Conventions

- **A state digest is the machine's `Debug` rendering** (`Node::digest`),
  which names every field, the sessions' windows and counters included.
  A cell that must change nothing compares it before and after; a cell
  that may change only the replay record compares the rendered `view()`,
  which leaves the record out.
- **Leases are conserved:** `conserved` checks that the indices a shell's
  pool holds are exactly the ones the machine binds.
- **Test names say what they assert** and carry no tracker identifiers.
- **Every test must be able to fail.** Each guard has a switch, and the
  meta-test in `faults.rs` shows the tests named for it go red with it
  on; guards without a switch were broken by a temporary edit, reverted.
- **Debugging aids.** `FIPS_SIM_NOSHRINK=1` makes a failing faulty run
  print its whole log instead of shrinking it; `FIPS_EXPLORE_TRACE=1`
  prints each exploration's frontier per depth and a non-healing state's
  whole log. Both need `--nocapture`.
- **The leak counter is per thread in test builds**, so a test that
  leaks on purpose, or runs a guard switched off, cannot disturb another
  test thread's count.
