# src/node/tests/settle/explore

The real-node explorer and its world: two or three real `Node`s on one
transport, driven by a schedule a test writes as data, and the core's named
starts run on them, each scripted and then varied. The module is
`node::tests::settle::explore`, declared in `../mod.rs`. It runs in nextest's
`node-synthetic` group with the rest of `settle`, since its TCP worlds open
real sockets.

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
    transport).
  - `World::new(medium, count, on)`: `count` nodes with multipath set as
    `on`, sorted so node 0 has the smallest node address. A loopback world
    can take more transports per node (`add_transport`), each an address of
    its own delivering to the node's one receive channel.
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
  - `tap`: the reference model beside the nodes, where a test sets one
    (`model.rs`). The world tells it of each packet a node is sent and
    hands each packet and each rekey poll to it to run, and tells it of each
    advance of the clock, rekey and restart.
  - A node that runs a decrypt-worker pool hands a frame under a delegated
    session to its workers; each round of `flow` and `heal` first runs what
    the workers sent back, as the receive loop does (below).
  - The world's tests: a dial is the one `initiate_connection` makes on each
    transport (a connection-oriented link starts connecting, with a pending
    connect and no msg1; the loopback's is connected with its msg1 armed); a
    node is handed a msg1 or a msg2 only at the step that names it, on each
    transport; a held msg1 can be dropped, duplicated and swapped; a rekey, a
    restart and a redial each do what their step says; a dial on a second
    loopback transport runs on it. Each runs with multipath off and, as its
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
    finds its defect: a start, an order and the clause that breaks, or no
    start, with the reason. It was written before the explorer first ran.
  - `NOT_RUN`: the core's start numbers no real pair runs, with reasons.
  - `pooled`: start 1 with a decrypt-worker pool at each node (Unix only,
    where the pool exists), apart from `starts`, which run with none.
- `explore.rs`: the explorer. `paths` gives a start's scripted path and one
  path per variation, `walk` runs one path to its leaf (`build` and
  `walk_from` are its two halves, for a world a test made itself), and
  `heal` heals the leaf (below); `parallel` runs walks on threads of their
  own. Its
  tests: the map covers every pinned defect and every core start number,
  and every start reaches its target: its scripted path runs to its end on
  its transport, and the explorer walks the number of paths the start
  states, in both orders and at both settings.
- `oracle.rs`: what is checked at each leaf (`judge`), and the explorer's
  tests over the starts: every path of every start keeps its properties, per
  transport and setting; each pinned defect the map gives a start is found
  there, with every waiver lifted; and each peer change of every start's
  scripted path, healed, does what the reference model's transition says,
  per setting, every transport in one test (below). And the crossing with a
  decrypt-worker pool (`pooled`): every path heals to one session per pair
  with every node's current session held by its workers, the session a
  crossing moves its peer onto among them.
- `model.rs`: `Tap`, the reference model of `fips-core`
  (`proto::settle::model`) beside a world, one judge per node and peer: the
  world's packets turned into the model's history, and each change the
  model makes held against what the node did (below).
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
so a result it has not finished when a round begins is run in a later one.
A node with no pool sends none.

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
that run are 1 to 6, 8, 9 and 11, each on the transport the core's start
names (UDP's is the loopback's; start 2's second transport and start 9's
second addresses are a second loopback transport; start 4 only where the BLE
transport builds). Starts 5 and 6 dial twice before either msg1 is read, the
shape of `settle::crossing`'s late second dial: the core's start 5 dials the
second time after the first completes, and on a real pair the dialer's
frames would then reach the responder before the second msg1, which the
start is not about. `NOT_RUN` gives the reason for each other start.

## The explorer's reach

Measured at the first run, 2026-11-09, one-minute load 13 to 17 on 12 cores:
the paths per start and order are 9 for starts 1 to 4 (four handshake
steps, no swap applies), 11 for starts 5 and 6 (two swaps apply), 10 for
starts 9 and 11 (one), and 5 for start 8 (two handshake steps), the same in
either order and at either setting; each start states its count, and the
reach test reds on any other. That is 166 paths per setting on a build with
the BLE transport, 148 without. Every start and order runs on a thread of
its own, each with its own runtime, and so its own test clock: a loopback
start takes 3 to 11 s, a TCP or BLE crossing 23 s, and the whole module 23 s
of wall time, inside the default lane's 120 s, in nextest's `node-synthetic`
group with the rest of `settle`. Nothing here is `long-running`.

Not covered by this design: an exhaustive search (a joint start explores
562 to 78,926 states, `fips-core`'s `proto::settle::tests::joint`), two
variations on one path, a variation of time or of an established frame, and
the starts `NOT_RUN` lists.

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
- the shell audit, `settle::audit::audit`, with the start's
  waivers passed only where the node recorded them on the link it holds the
  peer on (a start names what may be waived, and the node says whether it
  is);
- the node's live audit, inherited: in a debug build it runs at every packet
  a node is handed and panics on a breach. A walk runs on a thread of its
  own, so the property test reports such a panic, with the path it was
  walking, at its own `defect:` assertion.

A start names the clauses a pinned defect breaks on its scripted path
(`pinned`): start 6's split, which the leaf's heal does not mend. They are
not asserted on any of that start's paths; the map names the pin, and the
finder asserts it on the scripted path with every waiver lifted.

Each msg1's class against the model's is not checked here.

## Each peer change against the model

`each_peer_change_of_a_named_start_does_what_the_models_transition_says`
and its `_with_multipath_on` sibling run every start's scripted path in
both orders, healed, with a `Tap` on the world from its first step. The
tap turns what the world does into the model's history for each node and
peer: a msg1 is named by the ephemeral key it carries in the clear, which
both ends see, and its exact bytes; a msg2 and an established frame by the
session index they carry, which the msg1 and msg2 of a handshake give each
end; a frame counts only where the node holds a session of that index for
the peer. A node's new msg1 is its dial, or its rekey's while the world is
starting one; its own cutover is seen when its index becomes its pending
rekey's; the world's rekey ages the model's session and link as it ages the
nodes'; a restart starts the node's judges again, and its packets carry the
next epoch.

Each step of the model that changes a peer is held against the node over
the same packet or rekey poll. The model's transition is mapped onto the
node's (`mapped`), and each row of the peer's state, read before and after,
is held to that transition's cell (`table::check_decided`): a row the cell
keeps must read the same; a row the cell changes is held to change where
that can be seen, which is from a peer not held before, or a row of the
record made to differ from a fresh one's first (only those rows the
transition changes, so the start runs as written); and a row whose cell
turns on the script is held to change where the model's own state says it
must (a peer held anew, the peer's session moved). A step where the model
changes nothing must leave the session and link the node holds the peer on.
The tree announce's own send writes two rows of the record at a transition
that announces, which is not the transition's cell, so those two are not
held there. A change the mapping has no node transition for is listed and
not checked: the model's return, at a frame, to the session a later dial
moved off, a restart found at a rekey, and the model's roam at a frame to
a peer the node held on more than one path. The model holds one path per
link; the node's roaming rule moves a link's one path only, so it accounts
such a frame to its path and moves none. That roam is held as a step where
the model changes nothing: the node must keep the session and link.

Measured at the first run, 2026-11-10: every start's scripted path gives
four changes per order (six for start 11) and every one is held, at either
setting. The test fails on a start that holds none.

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
  is. The node times its heartbeats by the host's clock, which the world
  does not move, while its link-dead check reads the clock the world
  moves, so each time the walk passes a heartbeat interval every held
  peer's heartbeat is made due; without it each link is reaped 31 s into
  the minute.

A packet is named by its handshake: a msg1 by its sender index, a msg2 by
the index it echoes, each handshake numbered in its dialer's life in the
order its msg1 was first seen in flight. On BLE a connection opening opens
both ends' dials, which share the pair's one connection.

Run, on a build with the BLE transport: 18 scripts at multipath off and 20
at on, the crossings of starts 1, 3 and 4 (UDP, TCP, BLE), start 5's and
start 6's late second dials, start 8's restart, start 18's BLE dials lost
to the first dial's deadline (on only), an own rekey, the peer's rekey and a
rekey after a TCP crossing, each in both address orders. Not run:
`crossing-mixed`, start 2's crossing over UDP and TCP (and start 15's,
the same schedule), since a world's nodes share one medium; and every BLE
script on a build without the BLE transport.

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

The leaf is not judged by the shell audit or `settle::settled`. Their
heartbeats go through `settle::pump`, which hands a frame to the node but
never runs what its workers send back, so on a pooled node no heartbeat
under a delegated session is counted. Those properties of the crossing are
the property tests', on start 1 with no pool.

## What the world does not model

- Time is the node's monotonic clock as `crate::time` serves it to the test
  thread. A timer that reads another clock does not move with `advance`, and
  the receive loop's own tick does not run: a node runs its timers only at an
  `advance`.
- A node's receive loop, its periodic announces and its path tick between
  steps do not run. The world drives the node; it does not start it.
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
