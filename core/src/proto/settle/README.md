# core/src/proto/settle

Peer settlement: how two nodes that dial each other, restart or rekey end
up holding one session on one link, and which connections each link still
needs. The module is declared in `../mod.rs` and hidden from the docs.
The settlement core is compiled in every build, and the node decides
every handshake and removal through it: `src/node/settle/decide.rs` steps
the node's one copy of `Table` and is, with two path feeds, the only
caller of `Table::step`, `poll`, `reap_leg` and `close`, which a root
scan (`src/node/settle/tests/scans.rs`) holds. The reference model is
declared in `mod.rs` under `#[cfg(any(test, feature = "test-hooks"))]`,
so it reaches no normal or release build.

## Files

- `mod.rs`: the module doc and declarations, the `fault!` macro (the
  literal `false` outside test builds) and the module-wide deny of
  wildcard enum arms.
- `links.rs`: the core's link records: each link's setup address,
  direction, holder and bundle paths with their proven states, the
  transport-address index derived from them, and the one close rule over
  links and their paths (`in_use`, `retire`, `release`), which the node
  asks of its own copy of the records for every close it makes. A record
  also holds whether the bundle found the peer capable. `placement`
  reads, in one walk, where a msg1 from a pair stands among the records,
  and its `Placement` answers each question the node asks of a msg1's
  source before any Diffie-Hellman: whether a link owns the pair, the
  identity the msg1 is to prove, the answered leg it is a resend to, and
  whether it is on a held peer's link, which `table.rs` asks. `mirror` is
  the one reading of what a link's bundle reported (a path moved,
  switched to, changed state or released, or the peer turned capable),
  which `table.rs` applies and a shell's own record of its links can apply
  the same way. `renewed` forgets a record's capable flag when its
  bundle is renewed on a new session on the same link, which no IK rule
  does and a flow's hold of a peer on its link does. Under the test hooks, `resync` sets a record's paths and
  its capable flag outright, for a shell that resyncs a record whose
  bundle a test changed past the feed, and `name` names a link in the
  index at pairs past its record, for a shell that resyncs the index
  entries a test wrote past its writers at a pair the link's bundle holds
  no proven path at, which no record can give.
- `gates.rs`: the restart and replacement gates, one function
  (`Gates::gate`) that every restart source asks: a msg1 from an identity
  not held, a msg1 at a new epoch, a same-epoch replacement, a redial (a
  fresh same-epoch msg1 off the link of a held peering heard from, the
  operator's 2026-11-17 decision), and a new epoch found at this node's
  own msg2 or a rekey msg2. It holds the memory per identity the gates
  read (the dampener's stamp, the replay memory, the ephemerals that armed
  a redial and the silent-session record), and judges as the current node
  does. The node holds one, in its `Table`, as its own restart gates. The
  memory holds only identities with something live: a question about an
  identity with no memory inserts none, and an identity whose stamp,
  replays, silence and redial memory have all lapsed is dropped; a frame
  or a move forgets an identity's redial memory never, only its swap does.
  `refusing` gives the silent-session refusal in force, for a shell that
  classifies a msg1 before it asks the gate, and `silent` the sessions
  counted. The silent-session record also counts the msg1s refused while
  its refusal runs, for a shell's line that reports them (`count_refused`,
  read and reset by `take_refused`), so the count goes with the record. A
  question, a promotion and a session's end may name the instant the
  replay memory is read at (`Ask.memory`, `promoted`'s and `ended`'s
  `memory`), for a shell whose replay memory runs on another clock than
  the gate's instant; a redial's question reads the redial memory there
  too, and `redialed` notes it at the instant it is given. Under the test
  hooks `known` and `replays` read that memory, for a shell's comparison
  of its own, and `plant` and `unstamp` set and clear a dampener stamp for
  a test.
- `legs.rs`: the handshake legs in flight, by link: a dial leg with its
  msg1, its resend schedule (a second after the dial, as the node sends
  its first resend whatever its configured interval, then waits of the
  configured interval growing by the configured multiplier as the node
  computes them, up to the configured count or the dial's own lower cap,
  as the node caps an mDNS-directed dial) and its deadline; a responder leg with the
  msg1 it answered and its stored msg2; each holding its session index
  lease, and a dial the link its peer was held on when the dial's link
  opened, which decides whether a move onto it ends an operator's pin. A
  stored msg2 not yet sent answers any msg1 from its address
  (FRC-1201 Section 5.8); once sent, only its own msg1, byte for byte. A poll returns the resends due and the legs reaped, and
  `close` returns every lease. A dial resend whose send failed is tried
  again at the next poll, as the node retries one at its next tick, and
  the wake reported meanwhile is one tick on (`Params::retry`). Under the
  test hooks `iter` lists every leg, a leg's `sent` and `resends` give
  its resend count and cap, `next_resend` when its next resend is
  scheduled, and `resend_due` whether a poll at a given instant resends
  it, for a shell's comparison of its own; `replant` (through
  `Table::replant_leg`) gives a leg a test planted its own deadline and
  next resend; and `reap_one` (through `Table::reap_leg`) is a poll's reap
  of one leg alone at a given instant, through the same reap a poll
  makes, for a shell asking whether the core reaps a leg the shell is
  reaping. For a shell that keeps its own handshake timing, which no IK
  rule calls: `quiet` stops a dial's resends and leaves
  it to be reaped at its deadline, and `resends` is a poll's resends
  without its reap, for a shell that reaps its legs at sweeps of its own.
- `flow.rs`: the handshake flow a table runs, the `Flow` trait. A flow
  classifies a handshake's messages; the table's shared rules (the
  records, the legs, the gates, the held peers, removal, the path inputs
  and the close rule) hold for every flow. A flow adds its own inputs,
  outputs and refusals through one extension variant of each enum
  (`Input::Flow`, `Output::Flow`, `Denial::Flow`), whose payloads are its
  associated types, keeps its own state as the value of its type in the
  table, and is called back at the hooks where a flow may differ: the
  stored answer, the count the admission cap reads, an answer sent with
  no peer named, an install, move, frame or removal of a held peer, and
  whether a removed session that carried no frame counts as silent.
  `Ik`, the flow of FMP's IK handshake, is every rule the table's own
  inputs carry: its payloads are `Infallible`, the enums' and the table's
  type parameters default to it, and each hook's body, in `table.rs`, is
  the table's own rule. Another flow lives outside this directory and
  reaches the table only through `table::Ops`.
- `table.rs`: the judgements. `Table` holds the links, the legs, the peer
  held for each identity, the gates and its flow (`Table::new` runs `Ik`,
  `Table::flowing` another); `step` takes one input and
  returns the outputs, `poll` runs the legs' timers, `reap_leg` reaps one
  leg alone and `close` gives everything back. `gates` lends the gates'
  memory for a shell's reads;
  hidden from the docs, `count_refused` and `take_refused` keep a shell's
  count of the msg1s a silent-session back-off refused, for its log,
  `drop_leg` ends a leg for a cause the table has no input for, with the
  answer and the redial it carried, `open_link` opens a record for a
  link a shell adds outside any handshake, and `parts` and `parts_mut`
  lend the records, the legs and the gates together, to read and to
  write, for a shell that holds its one copy of each in the table while
  it still decides with them itself; no IK rule calls them. `Ops`, hidden from the docs, is
  the table as a flow reaches it, which only the table builds: its reads,
  writers to the records, legs and gates, and the shared operations a
  flow's rules invoke, each a one-line call of the table's own, so the IK
  flow's tests run every body. Three of them are the table's own steps,
  taken out of the inputs that run them: `install_answer` (a responder
  leg's install, from `Sent`), `keep` (the larger node's keep of its held
  peer at its own dial's msg2) and `open_answer` (a responder leg's
  opening, from `Hello`). Two no IK rule calls: `hold_answer`, under the
  test hooks only, since its one caller is a switch's defect shape, keeps a
  held peer on the link it holds with a responder leg's session and
  lease, at a pair the flow names, and retires the leg's link; it seats
  the peer as `install_answer` does, through the same step, forgets the
  held link's capable flag, since the shell renews the peer's bundle at
  that move. `move_answer` moves a held peer onto a responder leg's link,
  session and lease, at a pair the flow names, seated the same way but
  keeping whether the peering was heard, its install instant and its last
  frame, as the dialer's move at msg2 does, and retires the link it held,
  closing that link's pairs no remaining link uses. Their own tests are in `tests/table.rs`. Under the test hooks `plant`, `plant_leg` and
  `records` write a held peer, a leg and the link records outright, for a
  shell that resyncs into its copy of the table what a test planted past
  its writers (a responder's leg planted as an answer whose send failed,
  the one state in which a node keeps a responder's handshake with no
  peer), and `gates_mut` lends the gates' memory, with the table's parameters, for a shell's
  test that writes its own memory past its decisions and gives the gates
  the same through their writers. It judges a msg1 from an identity not held or at a new
  epoch through the gate, refuses an identity not held at the max-peers
  cap, and asks the shell for an admitted msg1's answer only after that
  and any teardown it causes, hands a same-epoch msg1 to the peer's rekey
  machine with where it arrived (on the link from a path that is Live or
  acknowledged, or, from a pair the link holds no path at, when the peer
  is not capable and the index names the link there), takes the machine's
  replacement request back through the gate, answers its redial request
  by a leg beside the held peer (one per identity) that the first frame
  under it (`LegHeard`) installs in the peer's place, opens a dial's link
  when the node starts it (before its msg1 for a dial on a connection
  still to be opened), completes this node's own dials (install, restart,
  the own-dial move and the crossing's tie-break), removes peers, and
  applies the path bundle's events to the link records and to where the
  peer held on the link is: a move of the path it is at, a one-path roam
  among them, or a switch of the active path moves it, and a frame alone
  never does. When the peer adopts a rekey answer that went out on the
  connection its msg1 arrived on, the link's own connection having gone
  (`Adopted`), the held link's record says the peer set it up, since the
  peer opened that connection, and a later dial of this node for the peer
  is decided by the node address ordering. Only a one-path roam resets
  the peer's data, as a roam; a path the bundle moved at a path message,
  which the node runs as its own Follow, resets nothing, as a switch does
  not, and nor does the roam of a link's one path while it is not the
  active path, as the node resets nothing for it.
- `input.rs`: what the shell tells the core, each built after any Noise
  read. A msg1 comes in two steps: what the shell read, which the core
  classifies, and then, only for a msg1 the core admitted, the msg2 the
  shell built and its lease (`Hello`), or the shell's refusal
  (`Abandon`), so a refused or rekey msg1 costs no msg2 and draws no
  index. A dial on a connection still to be opened comes in two inputs,
  `Connecting` when the node starts it, which opens its link, and `Dial`
  with its msg1, naming that link. Such a dial given up before its msg1
  (`ConnectFailed`) retires its link and closes nothing, as the node closes
  nothing for it. An answer whose msg2 could not be sent at all
  (`Unsendable`, where `SendFailed` keeps it for the msg1's resend) is
  given up the same way, closing nothing.
- `join.rs`: the one function (`join`) that joins a peer's rekey machine
  and path bundle to the core, generic over the rekey profile, the clock,
  the entropy source and the driver slot. It builds both machines for a
  new link (the rekey machine first, so a setup of another key builds
  neither), moves them across a cross-connection move (close, build from
  what the machine carried, then renew the bundle only if it was built)
  and closes them at a removal (the bundle first), taking the slots where
  the shell keeps them. Its result says front to back what the shell is to
  carry out: a restart report and a teardown are core inputs, a
  replacement or redial request goes to the core's gates, every bundle
  output is the shell's own and is followed by the core input it stands
  for, and a one-path roam or bind, which the bundle reports in no output,
  is a move marked a roam (unless the path was a standby one, not the
  active path) or a Live path. Rekey outputs are converted as they are
  taken, so a frame through it allocates nothing. The order is the machine
  calls' and the routing's; a shell's loop that carries the steps (a node's sends
  between steps, a test shell's sends first) stays the shell's own. One
  switch sits in it, `MoveBuildsFresh`, which builds the moved machine as
  a new link's; outside the core's tests it is the literal `false`. The
  joint world's shell (`tests/joint/`) calls it for every machine build,
  move and close and for every output it routes. The node runs each step
  of a link's rekey machine through it.
- `output.rs`: what the core asks of the shell, run front to back: the
  ask for an admitted msg1's answer, answers, resends, the hand-off to
  the rekey machine, installs, the per-peer data's transition, whether a
  move onto this node's own dial ends an operator's pin of the peer's
  path (`Swapped`), a link whose record now says the peer set it up
  (`Turned`), removals, retired links with their closes, released
  paths, freed leases, reconnects and refusals.
- `params.rs`: the intervals and bounds the core reads, with the current
  node's values and the line each is taken from (the node's one-second
  tick among them, the wake of a failed resend, and its fixed first resend
  wait beside the configured interval the later ones grow from), the
  resend wait the node computes (`Params::wait`, the multiplier held as `f64` bits so the
  parameters stay `Eq`), and the deadline and back-off arithmetic its
  timers share. The node maps its configuration onto these in
  `src/node/settle/params.rs`.
- `model/`: the reference model, written from FRC-1201 Sections 5.5 to
  5.8 and the operator's decisions, without reference to the code. See its
  README.
- `parity.rs`: the schedules a real node and the joint world both run
  (`SCRIPTS`), each step by node index and packet kind, never by an index
  or address value; what an end holds after a step (`Mark`: held, whose
  dial its session came from, its link record's direction and setup pair,
  the pair it sends on, heard); the closed list of node defects a `core`
  line may name (`Cause`); the reader of `parity.txt` and its checks; and
  the link rekey and path settings a node derives at the default
  configuration at each multipath setting (`rekey`, `path`), which a root
  test (`src/node/settle/tests/defaults.rs`) ties to the node's own.
  Declared under `#[cfg(any(test, feature = "test-hooks"))]`, so the root
  crate's tests read it and no normal or release build holds it.
- `parity.txt`: the trace both sides compare with, `include_str!`d by
  `parity.rs`: one block per script, a line per step and end saying what
  the node holds, and `core` lines where the settlement core differs, each
  naming its cause; it holds none since a crossing's mover holds the link
  it dialed, as the core does. Its head states where its lines came from.
- `rules.txt`: the core's incidental rules, those whose outcome no FRC
  clause and no decision with a reason fixes, one line each: its ID, class
  I (no record) or I-kept (kept as the node had it), whether a test asserts
  it, and what part is incidental.
- `current.txt`: the tests, of either crate, that assert a rule of
  `rules.txt`, one line per test and rule. Each carries a doc line saying it
  records current behaviour, open to change by decision. The root crate's
  `src/node/settle/tests/rules.rs` checks the two files and the doc lines
  against each other, since only the root crate's tests can read both
  crates' sources.
- `faults.rs`: the test-only switches that turn each guard of the core
  and of its tests off (`FIPS_SETTLE_FAULTS`), read through the `fault!` macro in
  `mod.rs`, and the choice of a candidate rule for the two settlement
  cases left for later (`Candidate`; `FIPS_SETTLE_CANDIDATE` for a
  process, or a test's choice for one thread's nodes).
- `tests/`: the deterministic world, the model and the core as nodes of
  it, the named starts, the bounded explorers, the settlement properties,
  the rekey machine's decisions, a model of the current node, the
  late-dial cases (the accepted split's recovery tested, the aged-link
  defect pinned), the scripted regressions, the seeded long
  runs, the candidate rules explored, the meta-test of the switches and
  the scans of this directory. See its README.

The core grows here beside the model, and its tests compare it with the
model. No core file (anything here outside `model/` and `tests/`) refers
to the model, and nothing in `model/` refers to a core item; the scans in
`tests/mod.rs` check both ways, by path.

## Rules for changing it

- Everything here stays `no_std` with `alloc`, as the rest of the crate
  (`testing/build-core-baremetal.sh` builds the crate without it, so a
  leak into a normal build shows there).
- Names follow the crate's style: at most one underscore outside tests.
- A change to the outcome of a rule in `rules.txt` is a decision, not a
  fix: it changes the rule's line and its tests in the same change. A rule
  a decision fixes leaves `rules.txt`, and its tests leave `current.txt`
  and lose their doc line. A new test that asserts an incidental outcome
  takes a line in `current.txt` and the doc line.
- The index in `links.rs` is recomputed by `Links`' own methods after
  every change and never written directly.
- A lease leaves `legs.rs` only with its leg: taken with it, returned
  with a reap, or returned by `close`. Dropping one leaks an index, and
  the tests count leaks.
- Every lease an input brings comes back in an install or a free; the
  table keeps none beyond its legs.
- Every teardown of a held peer's link closes what the node's bundle does
  not keep of it, by the close rule: on a link known capable, each path
  other than the one the peer sends on (the source of its last frame that
  shows it, as the bundle reads it, forgotten at a move), and on any other
  link no path, the bundle keeping them all. `close` closes every pair no
  other link uses. A crossing's losing link and
  the link a late second dial moves off are retired by the close rule,
  closing its connection and only the paths its bundle does not keep,
  after the moved-onto link's record takes the msg2's pair as a Live path:
  the node renews the bundle there before it closes the link it leaves, so
  a dial answered over the peer's own dial connection keeps that
  connection. That retire also closes the pair the dial was set up at when
  no link uses it, the moved-onto link included, as the node closes it
  after such a move; never when the msg2 came over that pair, since the
  peer has just answered there, whatever the record says of it.
- A removal never closes a setup pair whose path the bundle released
  first (that release closed it or kept it); an operator disconnect also
  closes the pair the peer was held at, whether or not another link uses
  it.
- A removal asks for a reconnect (`Output::Retry`) where the node notes
  the loss for one: a dead link, a `Disconnect` and an orphaned bundle,
  which the node removes through its link-dead path, and a restart, a
  replacement and an own-dial restart, whose loss the node notes before
  the new session is promoted.
- A move sets the peering heard, as FRC-1201 Section 5.5 counts a
  peering this node set up as initiator, and as the node does. A move
  that makes an unheard peering heard forgets the identity's replay
  memory (`Gates::forget`), as the node does at the move, and keeps its
  silent sessions, which only an authenticated frame forgets. A frame
  forgets both where it makes the peering heard (`Gates::heard`); the
  first frame of a peering heard already, by this node's own dial or a
  move, forgets the silent sessions alone (`Gates::framed`).
- A removed session counts toward the identity's silent-session back-off
  when it carried no frame (`Held.last` is `None`), whatever its role, as
  the node does: a session of this node's own dial, heard from its
  install, counts when it ends before the peer's first frame.
- Every deadline comes from `params::deadline`, which saturates at the
  end of the instant type's range rather than overflowing.
- The gate constants are `Params::default`'s, and the node takes them as
  they are: it moves only the handshake timers and the two caps from its
  configuration (`src/node/settle/params.rs`). The root crate's
  decision-input scan (`src/node/settle/tests/scans.rs`) holds every
  other appearance of them, of the rekey machine's parameters and of the
  node-address ordering to an exempt list with reasons.
- Only an accepted restart or replacement that tears down a heard
  peering stamps the dampener; a refusal never does, so a sustained
  replay cannot keep a genuine restart out.
- A core file's unit tests sit in `tests/<file>.rs`, attached from the
  file with `#[path]`; a core file that holds a test fails a scan.
- No core type has a `set_` method, and a new source file here or in
  `model/` joins the scans' lists in `tests/mod.rs`, or the file count
  there fails.
- A new guard gets a switch in `faults.rs` and a row in
  `tests/faults.rs`, and a new test is named by a row or listed there as
  self-checked or characterisation; the scans fail otherwise.
- A guard whose break the root crate's tests and the mutation lane must
  reach too, since `fault!` is this crate's test build alone, is read as
  `fault!(X) || node_fault!(X)`: declared in `faults.rs` with its row and
  in `core/src/faults.rs` with a line in `testing/mutations/manifest.txt`.
- `parity.txt` says what the node does, read against FRC-1201 and the
  model of the node, never copied from one side's output alone, since a
  trace taken from code passes that code. A change to it goes in a commit
  of its own, with `parity.rs` when a script changes, and its message says
  why the old line was wrong.
- The candidate rules are test-only, every item of them under
  `#[cfg(test)]`: in `table.rs` the `Kept` record, the table's `cand` and
  `holds` fields and the candidates' `impl` block; in `input.rs` the
  `HeldFrame` and `HoldLost` inputs; in `output.rs` the `Hold` and
  `Settle` outputs. A table runs one only when built with `Table::under`,
  and the non-test build has no candidate code (the bare-metal build
  shows it). Each candidate keeps the core's own rules and changes one
  decision: the dialer's and the responder's late-dial rules keep the
  session a late second dial moves off (`Hold`) until a frame settles it
  (`Settle`), the responder's also a replaced unheard peering's for 15 s;
  the aged-link rule moves an own dial completing on an aged inbound link
  onto that dial.
