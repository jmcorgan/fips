# core/src/proto/rekey

Rekey as one sans-IO state machine per keyed relationship. `Rekey<P, C>`
holds every piece of one relationship's key rotation: the current epoch,
an optional previous epoch being drained, one cycle slot (idle, an own
attempt in flight, an own completed attempt, a peer's completed
attempt), a bounded list of peer-started attempts (candidates), the IK
replay record, the facts that survive an idle cycle, and every deadline
as an instant of the host's clock. One machine serves a link peer (FMP)
or an end-to-end session (FSP); the profile type `P` says which, and the
transitions are written once for both.

The module is `#[doc(hidden)]`. Its production profiles sit with the
layers they bind: FMP over Noise IK in `proto/fmp/rekey/` (with the
node-level read of a peer's IK msg1) and FSP over Noise XK in
`proto/fsp/rekey/`; the root crate names only their aliases `FmpProfile`
and `FspProfile`. The root crate's session table holds each session in a
machine on `FspProfile` from its first handshake on: the shell opens it
with `opening_outbound` when this node wants a session, with
`opening_inbound` for the first setup naming an address, and with `Open`
on a session the peer's setups opened; the machine takes every setup,
ack, msg3 and inbound frame through `step`, seals the session's frames,
and is polled on the shell's tick. So the first handshake (its resends,
its candidates, the crossing decided at msg3, its retained msg3 and its
teardown) and every rekey of a session, its start, its handshake, its
cutover and its drain, are decided by the rows below, the silence
trigger and restart detection by the peer's startup epoch included. Each
active link peer holds a machine on `FmpProfile` from promotion on, and
the root crate hands it every rekey msg1 (read first by
`fmp::rekey::ik::read_msg1`), msg2 and slow-path frame of the link through
`step` and polls it on the shell's tick, so every link rekey (its start,
its msg1 resends, the answer, the cutover, the adoption, the drain and a
restart its msg2 reveals) is decided by the rows below. A frame a decrypt
worker opened and handed back to the node (every frame but bulk session
data) reaches the machine as a worker report, so the key-epoch bit it
sees from the peer and the evidence that the peer moved count those
frames too.
The machine's own tests run on the stub profiles in `tests/`;
`tests/legacy/` runs it on the production profiles against models of the
deployed releases, and runs the session and link nodes this release ships
(the machine polled on the shell's tick) against them as well.

## Files

- `mod.rs`: the public interface: `Input`, `Output`, `Env` (what a call
  borrows from the shell), `SetupFacts` and `Carry` (what a machine is
  built from and hands back, and the conversion from one to the other a
  cross-connection move makes), `View` and the seal results; and the
  re-exports. It holds the module-wide `deny` of wildcard match arms.
- `machine.rs`: `Rekey` itself: `step` as `judge` then `apply`, the poll,
  `next_wake`, `seal`, `seal_prompt`, `view`, `bindings` and `close`, and
  every transition below.
- `access.rs`: the read-only accessors the link shell reads (an epoch's
  keys, tag, indices and stamps, the key-epoch bit, the send counter, the
  jitter, the drain's end, the last cutover, the held answer), and the
  one move the shell still makes outside `step`: taking the link setup's
  record (its msg1 and answer) in front of the record the machine was
  built with, once the link is promoted. None carries a rule or is
  reachable from a row. A decrypt worker's acceptance is an input to
  `step`, a promoted link's machine is built with the peer's startup
  epoch in `SetupFacts` and offers its first epoch to the workers itself,
  and a cross-connection move closes the machine and builds a new one
  from the `Carry` (`SetupFacts::from`).
- `cycle.rs`: the cycle enum and its states: an own attempt, an own
  completed attempt (`PendI`, with its `Wait`), a peer's completed
  attempt (`PendR`, which records its arming msg1 on every exit).
- `hooks.rs`: built only for tests and behind `test-hooks`: `quiet`,
  which stops the time and message triggers as the largest configured
  thresholds would; the link shell's test seams, which move a machine's
  stamps back in time, force the key-epoch bit and the peer's startup
  epoch, start an own rekey without its trigger, offer the current epoch
  to a worker pool started after promotion, read dampening, reserve a
  counter under any slot to forge a peer's frame, and read the observed
  key-epoch bit and the record a cross-connection move carries; and the
  source reader (`code_text`, `code_idents`, `lost_items`) both crates'
  tests use to scan their code, comments and literals left out, for the
  names of deleted rekey rules of both layers. None is reachable from
  `step`.
- `epoch.rs`: `Epoch` (a boxed session and what is derived from it),
  `Drain`, `Ids` (an epoch's indices), `Slot`, `Role`, `RecvHome`,
  `Purpose`, and the trial open of one epoch's key.
- `proof.rs`: the values that carry authority and the only code that
  makes them: `Bond` and `Bonded`, `Authentic` with `Fresh` and
  `Replayable`, the reply, msg3 and frame proofs, and `Evidence`. It
  re-exports `PeerKey`, the peer's static key, from the identity module
  (`crate::identity`), which defines it beside the node address it
  derives, so `proto::rekey::PeerKey` keeps naming it.
- `candidates.rs`: the bounded candidate list, its per-carrier quota and
  the first-handshake eviction rule.
- `resolve.rs`: `resolve`, the one tie-break both ends evaluate alike.
- `ladder.rs`: resend schedules as integer offsets, truncated at their
  deadline, and ladders over them. A rung cut by the deadline or by the
  schedule's fixed room is counted, and `Params::inert` reports it.
- `params.rs`: `Config`, `Params::new` (which refuses settings under
  which a timer fires on every poll or never, and a time trigger below
  the jitter plus the link-age floor), and every derived value.
  `msg1_span` gives the offset of the last msg1 resend, which the link
  shell's silence bounds allow for.
- `lease.rs`: `IndexLease` (a linear session index), `allocate`, the
  leak counter, `EpochTag` and `TagSource`. `IndexLease::for_test`, a
  lease no allocator handed out, exists only for tests and behind
  `test-hooks`.
- `record.rs`: the IK replay record, the answer a responder pending
  holds, and `RecordStore`, the bounded store in which the link shell
  files the ephemerals of a closed machine's record under the peer's
  address and startup epoch and from which it hands them to the next
  machine built for the peer at that epoch. The setup msg1 and its msg2
  are never filed: they belong to the link they set up, so a copy of an
  earlier link's setup msg1 is a msg1 answered before on the next link,
  whichever node dialled it.
- `reason.rs`: `Reason`, `Abandon`, `Teardown` and `Close`, with who each
  is attributed to and whether input that did not authenticate can cause
  it.
- `faults.rs` (test builds only): one switch per guard, each turning one
  enforcement off in the shape a real defect would take, read from the
  `FIPS_REKEY_FAULTS` environment variable. Guard sites test it through
  the `fault!` macro of `mod.rs`, which is the literal `false` outside
  test builds.
- `profile.rs`: the `Profile` trait, the session interface the machine
  uses (`SessionKeys`), the IK msg1 and leg-completion token traits, and
  the constants that select rows.
- `keys.rs`: what the production profiles share over the Noise code:
  `NoiseKeys<AAD>`, a Noise transport session as an epoch's keys
  (authenticating the first `AAD` bytes of every frame, 16 for a link and
  12 for a session), the receive and send halves it hands out
  (`RecvCopy`, `SendCopy`), `NodeKeys` (the node's static keypair and
  startup epoch), and the even-parity pinning of a peer's x-only key. The
  machine never names this file; next's XX profiles will use it too.
- `tests/`: the tests; its README describes them.

## Where it sits

The shared machine lives at `proto/` level because both the link and the
session layer use it. It differs from its neighbours in two ways. It
takes time as instants of a host clock (`C: time::Clock`) where the rest
of `proto` takes `u64` milliseconds, and it holds keys: its attempts'
and candidates' handshake states and every epoch's transport session,
each behind a `Box`, so moving an epoch between slots copies a pointer
and its key bytes are erased in place when it is retired. It reads
handshakes on a fork (`crate::noise::Fork`), and draws session indices
through `IndexSource`, which the node's `IndexAllocator` implements. The
machine itself never names Noise: only `keys.rs` and the profiles in the
layers' `rekey/` directories do.

## How a call works

`step(now, input, env)` judges the input with a shared borrow, which does
every read and check of the input's row (a handshake read on a fork, the
bond of a completion to the peer's key, a frame's trial open into
`env.scratch` and its replay-window check), and either rejects it or
produces a commit. `apply` is the only code that changes the machine.
Every commit a network input causes, except adding or evicting a
candidate, carries a proof only this module tree can make. At the end of
the step any `Prompt` output whose epoch is no longer sealable (a later
row of the same step demoted it) is withdrawn, because the shell seals
prompts after the step.

The outputs are an ordered list. The shell executes them front to back:
sends, prompts (by calling `seal_prompt`), deliveries of plaintext the
machine wrote into the frame's own buffer, index bindings recorded with
their transport, worker offers and revokes, lease releases, and the
counted outcomes (`Installed`, `Retired`, `Reverted`, `Reject`,
`Abandoned`, `Teardown`, `PeerRestarted`, `Rekeyed`).

A poll runs an expiry pass and then a start pass. The expiry pass
collects every stored deadline at or before `now`, processes them in
instant order (at equal instants: drain end, candidate expiry, responder
pending hold, held proof, probe rung, delayed-cutover msg3 rung,
retained-msg3 rung, prompt repeat, confirmation deadline, delayed
cutover, attempt resend, attempt deadline), and measures every deadline
it creates from `now`, so one poll never creates a state and expires it.
A row that hands a stored deadline to another owner (a delayed cutover
moves its retained msg3, ladder and all, into the new current epoch) can
leave one at or before `now` uncollected, so the pass repeats over the
deadlines it has not yet processed until none is due.
Then an empty first handshake and an exhausted send counter end the
machine. The start pass starts an own rekey when it is due (a silence
start for a session only) and offers any epoch a worker does not hold.

`next_wake` names the earliest instant a poll has work: every stored
deadline, and the instant each start condition next holds. A counter
trigger that is already met counts from the floor, dampening or backoff
that holds it, and an exhausted counter makes the wake an instant
already past, so a shell that arms one timer at `next_wake` loses no
work against one that polls every second.

Either shell loses no work only if it processes due work before it steps
a session setup. A shell that polls on a tick can take a setup up to a
tick after a deadline has passed, and a setup stepped then is judged
against the state that deadline ends: the smaller node refuses a setup
while its completed rekey waits, though the confirmation deadline has
given that rekey up, and a deployed peer sends its rekey setup once. So
before stepping a setup, the shell polls the machine whenever
`next_wake` is at or before the setup's instant. The poll also starts an
own rekey whose start instant has come, the order a shell with a timer
at `next_wake` produces.

## The transitions, by input

- **Poll.** A drain ends at its deadline (counted when nothing showed
  the peer moved). A candidate expires. A responder pending past its
  hold is retired, never installed. A held IK proof cuts over at the
  next poll. A probe rung resends msg3 with a probe under the pending
  epoch, and every rung seals a keepalive under the current one; a late
  pass sends no probe the confirmation deadline could not judge. At the
  confirmation deadline a completed own attempt is retired with a
  repair due if the peer was heard staying (or after a revert), and is
  otherwise installed as an assumed epoch. A retained msg3 is resent on
  its ladder and dropped after its last rung, making a repair due if
  the peer was never heard; a delayed cutover whose msg3 ladder already
  ran out while it was pending drops the msg3 at once, with a repair
  due. Prompt repeats run until the peer is seen to move. An attempt
  resends its first message on its ladder (the larger node of a
  first-handshake crossing holds back the early rungs while it holds a
  candidate) and is abandoned at its deadline with a backoff, ending a
  first handshake that has no candidate left.
- **IK msg1** (read at node level). A msg1 from another epoch is
  refused. While the link or session is too young: a resend of the
  setup msg1 draws the setup msg2, a copy is refused, a fresh one asks
  the shell to apply the restart gates. Once eligible: a msg1 off the
  established link while it is reachable is refused; a resend of the
  msg1 that armed the held pending draws its msg2; any other msg1 meets
  a pending in either role and is refused; a copy is refused while idle
  or attempting; a fresh msg1 is answered into a pending when idle, and
  while attempting the tie-break keeps the smaller node's attempt (the
  larger abandons its own and answers). Every fresh msg1 refused after
  authentication is recorded.
- **Reply.** An index-bearing reply naming no held index, or one held by
  an epoch rather than the attempt, is refused. A reply that does not
  read on the attempt's fork, or reads as another static, changes
  nothing. A two-message reply completes into a held proof; a
  three-message reply sends msg3 and completes into a pending that waits
  for evidence (with a probe and a keepalive at once) or for a delay, or,
  when it reveals a restart, cuts over at once and retains msg3; in a
  first handshake it installs the session's first epoch.
- **Setup** (three-message only). A malformed setup is refused. A resend
  draws the stored ack. The smaller node refuses a new setup while its
  own attempt has completed, while it is resending its own msg3, or
  while its first-handshake attempt is young. Otherwise the setup
  becomes a candidate if there is room overall and on its carrier; a
  first handshake may evict an unprotected candidate of the fullest
  carrier, never a carrier's only one; an established session never
  evicts.
- **Msg3** (three-message only). One dispatcher tries every candidate,
  newest first. A msg3 no candidate reads changes nothing; one from
  another static drops its candidate; one from the peer's incarnation
  before a recorded restart drops its candidate. Otherwise the tie-break
  decides against the own attempt, completed own epoch or retained
  msg3, and an accepted candidate cuts over (or, for a frame-driven
  responder, becomes a pending), keeping only the candidates born after
  it.
- **Frame.** The epoch is found by index or by trial. The pending
  epoch's frame cuts over with frame evidence. A current-epoch frame
  confirms a retained msg3 (dropping crossing candidates), records that
  the peer moved (shortening an unevidenced drain), answers a probe with
  a prompt at most once a second, and after the last probe plus the
  grace marks a completed own attempt's peer as staying. A
  previous-epoch frame counts for liveness only; after an assumed
  cutover it returns the assumed epoch to pending (abandoning an
  unanswered repair first), or, while a newer own attempt awaits
  evidence, only counts toward that attempt's decision. A frame that no
  key opens, that a window refuses, or that names a worker's epoch
  changes nothing; a short plaintext has its row's effects and is not
  delivered.
- **Worker and local reports.** A worker's frame counts as a frame under
  its epoch and raises the epoch's floor; a delegation and its loss move
  the epoch's receive half; `Open` starts a first handshake's own
  attempt toward the wanted key, keeping every candidate; `DataSent` and
  `PathFacts` feed the silence trigger, the route gate and the setup
  ladder.
- **Leg completion** (next's profiles only, dormant here). A completion
  becomes a responder pending after the tie-break against the own
  attempt, completed own epoch, retained msg3 or a held pending; a
  refused one releases its leg's index.

## Rules for changing it

- **No wildcard arms.** Every match on an enum lists its variants; the
  module root denies `clippy::wildcard_enum_match_arm`, and a test checks
  that it does. A new input or state is a compile error until every
  table handles it.
- **Only `apply` mutates, and only after every check of the row.**
  `judge` takes `&self`. A commit from a network input carries a proof,
  and a proof's constructor is private to this module tree.
- **Input that has not authenticated changes nothing but the candidate
  list**, and a refused IK msg1 changes nothing but the record.
- **Time and randomness come in.** No clock reads, no random source of
  the machine's own: instants are arguments, jitter comes from
  `Env::jitter`, epoch tags from `Env::tags`, ephemerals from the
  handshake's entropy type. No `std`, no logging, no `async`.
- **Leases are linear.** An index leaves the machine only in
  `Output::Release`. A lease dropped instead is counted as a leak and
  never panics.
- **Deadlines are absolute and never extended by peer input.** Instant
  arithmetic saturates (`ladder::later`).
- **Every state reachable in a test is reachable in production.** There
  are no state setters; tests reach states through inputs.
- **Every guard can be switched off.** A new enforcement gets a switch in
  `faults.rs` and a row in the meta-test of `tests/faults.rs` naming the
  tests that must fail without it; a switch with no row fails that test.
  The meta-test runs only with the crate's `slow-tests` feature, so run
  `cargo test -p fips-core --features slow-tests` after adding a switch.

The unit tests drive the machine on stub profiles; the README in `tests/`
describes them.
