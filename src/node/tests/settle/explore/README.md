# src/node/tests/settle/explore

The real-node explorer and its world: two or three real `Node`s on one
transport, driven by a schedule a test writes as data, and the core's named
starts run on them, each scripted and then varied. The module is
`node::tests::settle::explore`, declared in `../mod.rs`. It runs in nextest's
`node-synthetic` group with the rest of `settle`, since its TCP worlds open
real sockets.

The walks, `oracle.rs`, `parity.rs` and the reach and walk-bound tests of
`explore.rs`, are compiled only with the root crate's `explorers` feature
(`Cargo.toml`). No GitHub workflow and no tier 1 run of the internal
builder runs them; `testing/ci-local.sh` does at tiers 2 and 3, the
builder's trunk-tip, landing and nightly runs (recorded as
`root-explorers`, with the mutation lane's explorer lines as
`mutations-explorers`), and with `--explorers`. The world's own tests and
the map of pinned defects run in every build.

Where the core's settlement world (`fips-core`, `proto::settle::tests`) runs
the settlement machines on a model of the network, this runs the node itself:
real Noise, the real receive dispatch (`process_packet`), and every dial
through `initiate_connection`, the path a configured peer takes, never a
helper that seeds a handshake machine by hand.

## Files

- `mod.rs`: the module declarations and the module doc.
- `world.rs`: the `World` and what each step does to it, then the world's
  own tests.
  - `Medium`: the transport every node of a world runs: the in-process
    loopback, TCP on 127.0.0.1, or the BLE transport over the mock radio
    (`#[cfg(ble_available)]`, since only those builds have the BLE
    transport); or `Mixed`, two transports per node, the loopback as
    transport 0, standing in for UDP, and TCP on 127.0.0.1 as transport 1,
    whose packets are forwarded into the loopback's receive channel, so the
    node has one channel as the daemon does.
  - `World::new(medium, count, on)`: `count` nodes with multipath set as
    `on`, sorted so node 0 has the smallest node address. A loopback world
    can take more transports per node (`add_transport`), each an address of
    its own delivering to the node's one receive channel; `transports` and
    `ends` give each node's transports, ids and own addresses.
  - The steps: `dial` (`initiate_connection`), `connected` (the node polls
    its pending connects until none is left), `deliver`, `lose`,
    `duplicate` and `swap` (one held msg1 or msg2, named by its node, class
    and place among that class), `heal` (everything held and sent is handed
    over until the nodes are quiet), `advance` (the monotonic clock moves on
    through `crate::time::advance`, then every node runs its timers once, in
    its receive loop's tick order), `restart` (a new run of the node's
    identity at the same addresses), and `rekey` (the node's sessions aged
    past its rekey trigger, its peers' ends past the 30 s floor below which
    a msg1 is a fresh dial, then a rekey poll). Every step but `heal` ends
    with `flow`, below. `held` counts what a node holds of one class.
  - A node that runs a decrypt-worker pool hands a frame under a delegated
    session to its workers; each round of `flow` and `heal` first waits for
    every worker to handle what it was sent before (bounded at 60 s), then
    runs what the workers sent back, as the receive loop does (below), so a
    round never counts quiet with a frame on a worker.
  - The world's tests: the settlement core reaps a dial whose msg1
    was lost where the node does, in its peers' timers and not in
    `check_timeouts`, by its own reap and not by being handed the node's
    give-up; a dial is the one `initiate_connection` makes on each
    transport (a connection-oriented link starts connecting, with a pending
    connect and no msg1; the loopback's is connected with its msg1 armed); a
    node is handed a msg1 or a msg2 only at the step that names it, on each
    transport; a held msg1 can be dropped, duplicated and swapped; a rekey, a
    restart and a redial each do what their step says; a dial on a second
    loopback transport runs on it; a pair on a frozen clock holds one
    session while time passes a second at a time past the 30 s link-dead
    timeout, a heal after each second; a dial on a mixed world's TCP
    transport runs on it, each handshake packet handed over only at its
    step; and in a mixed world a held TCP msg1 holds back only frames from
    its own source, so the loopback's heartbeats keep the pair on its
    session past link-dead. Each runs with multipath off and, as its
    `_with_multipath_on` sibling, on.
  - For the shared schedules: `packets` gives what a node holds of one
    class, so a step can name a packet by what it carries; `clear` loses
    everything in flight; `hold` keeps established frames held too, until
    a `heal`.
- `script.rs`: a schedule as data. `Step` names nodes and transports by
  index, so a schedule says which end does what by address order, and
  `run` applies the steps in order, returning whether every `Heal` went
  quiet.
- `starts.rs`: the named starts in the world's steps, the map from each
  pinned defect of the node to the start that reaches it, and the core's
  starts no real pair runs, each with its reason.
  - `Start`: the core's number and name, the medium, how many nodes and
    transports, a `build` run as written and a `script` the explorer varies.
    Node 0 is the smaller node as written; `Order::Larger` exchanges nodes 0
    and 1, as the core's `flipped` does.
  - `PINS`: every `fips-mesh` known-defect line of
    `testing/ignored-tests.txt`, at its setting, and where the explorer
    finds its defect: a start, an order, a path (the scripted one or one
    variation) and the clause that breaks, or no start, with the reason. The
    first entries were written before the explorer first ran; later ones name
    where the explorer found the defect their test reproduces.
  - `NOT_RUN`: the core's start numbers no real pair runs, with reasons.
  - `Start.workers`: the decrypt-worker pool each node runs, if any: none,
    the production worker, or a worker that sleeps a set time before each
    job (`DecryptWorkerPool::slowed`).
  - `pooled`: start 1 with a decrypt-worker pool at each node (Unix only,
    where the pool exists), apart from `starts`, which run with none.
    `lagging` is `pooled` with each worker sleeping 200 ms before each job,
    as a worker thread descheduled on a loaded host is.
- `explore.rs`: the explorer. `paths` gives a start's scripted path and one
  path per variation, `walk` runs one path to its leaf (`build` and
  `walk_from` are its two halves), and
  `heal` heals the leaf (below); `spawn_walk` starts one walk on a thread
  of its own, with an 8 MiB stack, since a walk in a debug build comes
  within a few per cent of the default 2 MiB, and a runtime of its own, once
  fewer than `WALKS_AT_ONCE` walks run in the process (below), the thread
  `titled` for the test that started it, followed by `::walk`, so the
  audit's reach rows from a walk's nodes name
  that test, while a panic on the walk's thread is not taken for the test
  thread's own by `testing/lib/test-verdict.sh` (`parity.rs` names its
  threads the same way); `parallel` runs a job per start and order that way
  and gathers what they found. `WALKED` lists the media the explorer walks:
  the loopback, TCP, the mixed world and, where it builds, BLE. Its tests:
  a walk's thread is named for its test; the map covers every pinned defect
  and every core start number (`fips-core`'s
  `proto::settle::parity::NAMED_STARTS`, which a core test holds to the
  core's starts), a start counting as run only on a medium in `WALKED`;
  every start reaches its target: its scripted path runs to its end on its
  medium, and the explorer walks the number of paths the start states, in
  both orders and at both settings, on every medium in `WALKED`; and no
  more than `WALKS_AT_ONCE` walks run at once.
- `oracle.rs`: what is checked at each leaf (`judge`), and the explorer's
  tests over the starts: every path of every start keeps its properties,
  per medium (loopback, TCP, mixed, BLE) and setting; each pinned defect
  the map gives a start is found there (start 9's three). And the crossing
  with a decrypt-worker pool (`pooled`): every path heals to one session
  per pair with every node's current session held by its workers, the
  session a crossing moves its peer onto among them; and the same on each
  path of the crossing whose workers lag (`lagging`) that drops a msg1.
- `parity.rs`: the schedules `fips-core` shares with its settlement world
  (`proto::settle::parity`) run on a real pair, each end's mark after each
  step compared with the node's lines of the committed trace, at each
  setting (below). `UNRUN` lists the scripts no world here runs, each with
  its reason.

## How a packet reaches a node

Each node's receive channel is the test's (`TestNode.packet_rx`); nothing
reads it but the world. The world moves what has arrived into its own hold,
per node, in arrival order, and hands a packet over only through
`Node::process_packet`, the dispatch the receive loop runs.

- **A msg1 or a msg2 is handed over only at a step that names it**, a first
  dial's or a rekey's alike: `Step::Handshake { to, kind, nth }` names the
  `nth` of that class held at `to`, counting from 0 in arrival order.
  `Drop`, `Duplicate` and `Swap` name one the same way. These are the
  packets a schedule's variations act on.
- **An established frame flows on its own** after every step but `heal`
  (`flow`): it is handed over once no msg1 or msg2 that arrived before it
  from the same source, the same transport and remote address, is still
  held. So a frame never overtakes the handshake packet it followed, which
  it cannot on one connection, and a schedule need not name the frames a
  node sends that the core's world does not model. A frame behind a
  dropped packet flows at the drop.
- **`heal` hands over everything**, round by round: each round hands each
  node all it held when the round began, so an exchange moves one hop per
  round, as on a real network, and every node polls its pending connects.

**A decrypt worker's results are run at the start of each round** of `flow`
and `heal`: the frames the node's workers opened and the failures they
reported, each through `process_decrypt_worker_event`, as the receive loop
runs them, and each counts as a move. A worker runs on a thread of its own,
so each round first waits for every worker to handle what it was sent
before (`DecryptWorkerPool::barrier`, a message the worker answers once it
reaches it in its queue, bounded at 60 s). Every job a round hands over then
has its result run in the next round, and a round that moves nothing has no
frame left on a worker, so a heal never moves the clock on past a frame a
worker still holds. A node with no pool sends none.

On the loopback a send is in the receiver's channel when it returns, so one
round that moves nothing means the nodes are quiet, and a named packet that
is not held is not coming. Over TCP and the BLE mock a frame reaches the
channel from its connection's own task, so a `heal` waits for ten idle
rounds 10 ms apart, as `settle::pump` does, `flow` for five, and a step
naming a packet waits up to 2 s for it to arrive.

## The explorer

A start's `build` runs as written; its `script` is varied. A variation acts
on the packet a `Step::Handshake` names: dropped, handed over twice (a copy,
then the step), or swapped with the next packet of its class held at the
same node (then the step hands over what is in its place). The script's
steps before the variation run as written, and a step after it that names a
packet the variation took away is skipped. So a start of `n` handshake steps
has one scripted path and up to `3n` varied ones; a swap is not a path where
no second packet of its class is held.

Every start runs in both address orders and at both settings. The starts
that run are 1 to 6, 8, 9, 11 and 26, each on the transport the core's start
names (UDP's is the loopback's; start 2's second transport and start 9's
second addresses are a second loopback transport; start 4 only where the BLE
transport builds; start 26, which dials on UDP and then TCP, on the mixed
world). Starts 5 and 6 dial twice before either msg1 is read, the
shape of `settle::crossing`'s late second dial: the core's start 5 dials the
second time after the first completes, and on a real pair the dialer's
frames would then reach the responder before the second msg1, which the
start is not about. `NOT_RUN` gives the reason for each other start.

Start 26 dials on the loopback, lets the pair settle and 2 s pass, then
dials the peer's TCP address; its script opens that connection and hands
over the msg1 and the answer. Between two nodes of this tree the responder
answers the second dial as a redial and the dialer moves onto its second
dial at the msg2, so the redial is promoted at the dialer's first frame
over TCP. A deployed release's dialer, which keeps its first address and
never moves at the msg2, is not reached here: `../legacy_dialer.rs` makes
a node send as one.

## The explorer's reach

Measured at the first run, 2026-11-09, one-minute load 13 to 17 on 12 cores:
the paths per start and order are 9 for starts 1 to 4 (four handshake
steps, no swap applies), 11 for starts 5 and 6 (two swaps apply), 10 for
starts 9 and 11 (one), and 5 for start 8 (two handshake steps), the same in
either order and at either setting; each start states its count, and the
reach test reds on any other. That is 166 paths per setting on a build with
the BLE transport, 148 without.

Start 9 has walked 11 paths in either order and at either setting since the
node began answering a fresh msg1 from a held, heard peer off its link as a
redial (2026-11-18): node 1 answers node 0's dial on the second transport
with a msg2 from a pending redial leg, where it had refused that msg1, so at
step 3 node 0 holds two msg2s, its rekey's answer and the redial's, and a
swap applies there as well as at step 0.

Start 26, added 2026-11-24 on the mixed world, walks 5 paths in either
order and at either setting (two handshake steps, no swap applies). With
start 9's and start 26's paths, that makes 178 paths per setting with the
BLE transport and 160 without.

Every start and order runs on a thread of its own, each with its own
runtime, and so its own test clock. Measured 2026-11-09: a loopback start
took 3 to 11 s, a TCP or BLE crossing 23 s, and the whole module 23 s of
wall time. Measured 2026-11-24, with the reference-model test retired,
start 9's defects pinned and the mixed world walked, at a one-minute load of
11 to 16 on 12 cores: the whole module, 47 tests, took 47 to 49 s of wall
time in three runs under `cargo test`, where it took 39 s before start 26
and the mixed world. It runs inside the default lane's 120 s, in
nextest's `node-synthetic` group with the rest of `settle`. Nothing here is
`long-running`.

## How many walks run at once

Every walk, `parallel`'s and `parity.rs`'s alike, starts through
`spawn_walk`, which holds it until fewer than `WALKS_AT_ONCE` (16) walks run
in the process, across every test. By the counts measured, a walk holds two
epoll instances and an eventfd and its nodes' sockets: about five
descriptors on the loopback and up to eleven on TCP. The reach test alone
runs 36 jobs, and under `cargo test` libtest runs as many tests at once as
the host has CPUs, so without the bound the walks of every walking test ran
together and the process's descriptor peak grew with the host: on a 20-CPU
host the walking tests together reached the unit tests' open-file limit of
512, and five of them failed. With the bound the walks hold at most 16
walks' worth wherever they run, and the limit (`testing/unit-fd-limit.sh`)
is sized from it. Measured 2026-11-15 on 12 cores, each test alone: the
reach test held 173 descriptors at most before and 93 after, the parity
tests 103 and 93, every other test here no more than 85 either way, and
each took about as long as before (the reach test 10 s, a TCP or BLE
properties test 22 to 24 s), since a walk spends most of its time waiting.

Not covered by this design: an exhaustive search, which no test runs
since `fips-core`'s settlement explorers were retired (whether one returns
is an open decision), two variations on one path, a variation of time or of
an established frame, and the starts `NOT_RUN` lists.

## Each leaf: the heal and the oracles

A path's leaf is healed before it is checked. Everything sent is handed
over; until every pair the start dials holds each other on one session, a
dialer holding neither its peer nor a dial in progress dials again, as a
configured peer is redialed, and time moves on a second, for at most 25 s:
short of the 30 s handshake and link-dead timeouts, so a split is judged
before either reaps it, and past the 15 s heard floor, so a restarted node's
dial can be answered. Once every pair agrees, time moves on while any node
still has a dial in progress, or a connection a path machine asked for
still opening, for at most 31 s, past the handshake timeout, every pair
still agreeing after each delivery: the shell audit holds only once no dial
is out and no path's connection is half open. With multipath on, a dial to
a live peer that times out leaves its address a path candidate, whose
connection opens after the timeout.

Then, at the leaf:

- `settle::settled` for every pair the start dials;
- the shell audit, `settle::audit::audit`;
- the node's live audit, inherited: in a debug build it runs at every packet
  a node is handed and panics on a breach. A walk runs on a thread of its
  own, so the property test reports such a panic, with the path it was
  walking, at its own `defect:` assertion.

A start names the clauses a pinned defect, or a split accepted as
behaviour, breaks (`pinned`), each in one order and on one path, or on every
path of that order: start 6's split, in both orders on every path, which
the leaf's heal does not mend. A pinned clause is not asserted where its pin
names, and is asserted everywhere else: a pin in one order leaves the other
order checked, and a pin on one variation leaves every other path checked.
A defect's pin is named in the map with its start, order and path, and the
finder walks that path and asserts the clause there; start 6's split is
accepted behaviour with no pin, and the node tests in `../crossing.rs` named
`..._with_its_msg2_first_..._after_link_dead_and_a_redial_...` assert it
and its end at link-dead and a redial.

Start 9 carries three known defects of the node, each reproduced by a
scripted node test in `../rekey_cross.rs` that is ignored as a known defect
and mapped in `PINS`: in the smaller order, on every path, a pending redial
leg takes its held link's index entry (`MapsAgree`); in the larger order, on
every path, the crossed redials split the pair until link-dead (`Split`,
`Settled`, `Quiet`); and in the larger order on the path that drops step 1's
msg1, node 0's dial msg1, the resent msg1 is answered as a rekey the peer
cannot adopt (`Unadoptable`). Each is pinned in that order and on that path
only, and the finder walks the scripted path for the first two and the drop
at step 1 for the third.

Nothing here holds the node against the settlement core's reference model
(`fips-core`, `proto::settle::model`): the test that held each peer change
of a start's scripted path against the model's transition was retired on
2026-11-24 by the operator's decision, since the model is a second,
hand-written account of the node's behaviour.

## Parity with the core's world

`fips-core` states a set of schedules (`SCRIPTS` in
`core/src/proto/settle/parity.rs`) and what a node holds after each step of
each (`parity.txt` beside it). Its settlement world runs them on its model
of the node and on its joint nodes; `parity.rs` here runs them on a real
pair, and each side compares with the same lines, so a difference reds the
side that moved. Nothing here writes either file. Each test walks every
script at its setting, multipath off and, as the `_with_multipath_on`
sibling, on, and fails on a difference, on a step it could not take, and on
a walk of fewer scripts than are due: every script at the setting less those
not run here.

The translation, one step for one, is in the module's doc. Three things it
does that the explorer does not, each because the core's world does it:

- **Only what a step names is handed over.** The world holds established
  frames too (`World::hold`) until a heal, since the core's nodes send no
  frame between handshake steps; a node's own frames at a promotion would
  otherwise mark its peer heard a step early.
- **An advance loses what is in flight**, before each second it passes.
- **A heal is a minute**, a second at a time, with a dialer that holds
  neither its peer nor a dial in progress redialed, as a configured peer
  is.

A packet is named by its handshake: a msg1 by its sender index, a msg2 by
the index it echoes, each handshake numbered in its dialer's life in the
order its msg1 was first seen in flight. On BLE a connection opening opens
both ends' dials, which share the pair's one connection.

Run, on a build with the BLE transport: all 22 scripts at multipath off and
24 at on, the crossings of starts 1, 3 and 4 (UDP, TCP, BLE), start 5's and
start 6's late second dials, start 8's restart, start 18's BLE dials lost
to the first dial's deadline (on only), an own rekey, the peer's rekey and a
rekey after a TCP crossing, and on the mixed world (`Medium::Mixed`, the
loopback for UDP beside TCP) `crossing-mixed`, start 2's crossing over UDP
and TCP (start 15's is the same schedule), and `redial-transport`, a second
dial over TCP to a pair settled over UDP and answered as a redial; each in
both address orders. A script's transport names the world's transport of
the same index: in the mixed world, UDP is transport 0 and TCP is
transport 1. Not run (`UNRUN` is empty): every BLE script on a build
without the BLE transport, which leaves 20 at each setting.

What the trace cannot show: a mark says whose dial an end's session came
from, own or the peer's, not which of its own dials. So a dialer left on
its first session where it should have taken its second reads the same,
and the split that leaves is reaped and redialed inside the heal's minute;
the explorer's properties see it, the trace does not.

## The crossing with the decrypt workers

`pooled` is start 1 with a decrypt-worker pool started at each node before
either dial, Unix only. The crossing moves the smaller node's peer onto the
session of its own dial, and the rebuilt link machine must offer that
session to the workers at once, as a promotion's is offered once its peer
is in the table. Its test walks the start's nine paths in both orders and at
both settings; each leaf is healed, and then every node's workers must hold
every current session it has (`link_index_audit::audit`, whose breach is a
panic that `parallel` reports against the path), and the paths walked must
be the stated nine. The switch that leaves the moved session unoffered reds
the scripted path in both orders, at node 0, the smaller.

`lagging` is the same start with each node's one worker sleeping 200 ms
before each job, the shape of a worker thread descheduled on a loaded host.
Its test walks, in both orders and at both settings, the two paths that drop
a msg1 (steps 0 and 1 of the script), whose lost dial stays open until its
30 s handshake timeout, so the heal moves the clock on a second at a time
for about 30 s; each is judged as above, and two paths must be walked per
order. If a round counted quiet with a frame still on a worker, the heal
would move simulated seconds on past it, and the node whose frames were held
would count nothing from its peer and reap it, as the pooled
crossing's test did on a loaded host.

The leaf is not judged by the shell audit or `settle::settled`. Their
heartbeats go through `settle::pump`, which hands a frame to the node but
never runs what its workers send back, so on a pooled node no heartbeat
under a delegated session is counted. Those properties of the crossing are
the property tests', on start 1 with no pool.

## What the world does not model

- Time is the node's monotonic clock as `crate::time` serves it to the test
  thread. `World::new` freezes that clock in a loopback world, so only
  `advance` moves it, and real time spent waiting, for a decrypt worker or
  on a loaded host, does not. A TCP or BLE world's clock still runs with
  real time: frozen, the TCP crossing with multipath on does not heal its
  dropped-msg1 paths, which end with a connection open and unused. A timer
  that reads another clock does not move with `advance`, and the receive
  loop's own tick does not run: a node runs its timers only at an
  `advance`.
- A node's receive loop, its periodic announces and its path tick between
  steps do not run. The world drives the node; it does not start it.
- A mixed world's clock runs with real time, as a TCP world's does, and no
  step restarts one of its nodes: no start that runs on it restarts.
- A restart over TCP or BLE closes the old run's connections and waits until
  no other node holds one at the restarted node's address. A connection the
  other node accepted from the old run is keyed by the old run's port and is
  not waited for.

## Rules for changing it

- Every setting is stated: a test passes `on` to `World::new`, and runs
  both ways as two tests, the second named `_with_multipath_on`, as
  `src/node/tests/settle/README.md` says.
- A dial goes through `World::dial`. A helper that seeds a handshake
  machine, or opens a link by hand, would test a node that never ran, and
  the dial tests here red on it.
- A new file gets a `mod` line in `mod.rs` and an entry under Files above,
  in the same change.
