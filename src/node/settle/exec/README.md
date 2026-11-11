# src/node/settle/exec

The executor: what the node runs for each change to a held peer, as a list
of effects in their order. The module is `node::settle::exec`, declared in
`../mod.rs`. The table one level up, `../table.rs`, says what a change does
to each piece of the peer's state; this directory says in what order the
node does it, and does it.

A site builds a `Run`: the peer, the `Transition`, and what the effects
read beyond it. `Node::run` takes each `Effect` of `plan(&r.t)` in turn and
carries it out. A transition whose list is empty, a cutover, runs its own
statements at its site.

## Files

- `mod.rs`: `Run` and `Facts`; `Node::run`, which boxes its one body
  because an effect can reach the peer action executor and through it
  another run; the total match on `Effect`; the bodies of the effects two
  kinds of change share (the restart's, the dial's forget, the tree
  announce with `announce_line`, the filter mark, the backoff reset, the
  path renewal, and the connected-socket clear and relink under a moved
  pair); and the call of every other effect's function in its file.
- `plan.rs`: `Effect`, one step the node takes for a transition, and
  `plan`, the effects of each transition in their order, each list the
  statements its sites ran.
- `install.rs`: a promotion's effects, and the promotion a replacement
  ends with, with their `Facts`; `Node::install`, the part of a promotion a
  test may run alone through `promote_connection`, which builds the peer's
  machines and puts it in the node's maps; and `Run::promotion`, the run the
  peer action executor's promotion arm builds once `promote_connection`
  succeeded, a replacement's where the step says why it removed the held
  peer. What the leg's control machine returns for the outcome goes back to
  that arm's worklist, after the plan. A replacement is not one step: the
  ACL check and the index allocation between its removal and its promotion
  may stop it with the removal done. So the executor's removal arm runs the
  removal's part of its plan, through `Run::replacement` and
  `Node::run_removal`, and the promotion arm the rest, through
  `Node::run_promotion`, which runs a promotion's whole plan.
- `cross.rs`: a crossing's effects, moved onto this node's dial or kept on
  the peer's inbound session, with their `Facts`, which the site in
  `handle_msg2` fills through `Run::crossing`, since this file's module is
  private to `exec/`. The move itself, `move_session`, stays at the site,
  and so does the decision between a move and a keep, which passes through
  `Run::swaps` for the mutation lane's break of it. A move that rebuilt the
  machine holds the peer on the dial's link: `move_session` sets the
  peer's link id, and `HoldDial` holds the core's record of that link and
  keys the control machine, its timers and the carrier readings under it.
  `Facts.loser` names the link torn down, the one the move left or, at a
  refused move and a keep, the dial's, which `LoserClose` and
  `LoserRemoved` close by the close rule (`Node::close_unused`) and
  remove; the renewal's released paths go to the link left.
- `paths.rs`: a followed, switched or released path's effects, which are
  plain functions because a removal reaches a release where it cannot
  await, with `Node::run_now`, which walks such a plan without awaiting;
  their `Facts`, and the `Run` constructors their sites in
  `../../handlers/path.rs` build them with. A roam's effects are shared
  ones, in `mod.rs`, and its site in `../../dataplane/encrypted.rs` runs
  them through `Node::run`. A release at the peer's removal runs the same
  plan, and leaves the link's lookup to the removal.
- `remove.rs`: the one removal routine, `Node::remove`, which every way a
  peer is removed calls with its cause and which is synchronous because
  some of them cannot await; `Removed`, what it hands on; and
  `Node::removed`, which runs the removal's plan, each effect by the
  table's cell for the cause, with their `Facts`. The same effects run at
  a replacement's removal, reading its `Removed` from `install.rs`'s
  `Facts` and the replacement's cells. A loss noted for a reconnect where
  the removal was decided is not noted again.
- `links.rs`: the feed of the settlement core's link records, which the
  link table keeps beside its own: `pathed`, which runs what a step of a
  link's bundle returned through the core's join, each output followed by
  the core input it stands for, for the path machine's executor in
  `../../handlers/path.rs`; `Node::roamed`, which tells the join of a
  one-path roam or a bind, which the bundle reports in no output, for the
  frame's accounting in `../../dataplane/encrypted.rs`; and `Node::feed`,
  which applies a path's state, move, switch or release to the record. A
  promotion, in `install.rs`, holds the record for its peer and records the
  new bundle's original path. Nothing reads the records to decide anything
  yet.

## Rules for this level

- `plan.rs` and `mod.rs` deny wildcard arms as `../table.rs` does, and the
  deny in `mod.rs` holds for every file below it. A new `Effect` does not
  compile until each match has taken it.
- A plan lists the statements it stands for in their old order: a
  reordering is a change of behaviour. Where a list and the code it stands
  for disagree, the code is right and the list is corrected.
- An effect's body is a function with its final signature in its change's
  file: `async fn(node: &mut Node, r: &mut Run)`, or a plain `fn` in
  `paths.rs`. An effect not yet routed stops a debug build if reached.
- `Run` holds only what effects of two changes read; what one change's
  effects read goes in that change's `Facts`.
- A peer's machines are built and closed here, through the active peer's
  `with_session` and `stop`, which alone ask the settlement core's join for
  those changes; a crossing's move is the one change its site asks for,
  through `move_session`, before running the rest here. No code outside the
  join calls a machine to build, renew or close it but the exemptions
  `../tests/scans.rs` lists with their reasons, and that scan reds on any
  other.
- Its tests are in `../tests/plan.rs`, `../tests/remove.rs`,
  `../tests/links.rs` and `../tests/scans.rs`, with the other tests of
  `src/node/settle/`.
- Keep the file list in step with the directory.
