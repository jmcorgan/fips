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
  ends with, with their `Facts`.
- `cross.rs`: a crossing's effects, moved onto this node's dial or kept on
  the peer's inbound session, with their `Facts`.
- `paths.rs`: a followed, switched or released path's effects, which are
  plain functions because a removal reaches a release where it cannot
  await, with `run_now`, which walks such a plan without awaiting, and
  their `Facts`.
- `remove.rs`: a removal's effects, each by the table's cell for the cause,
  with their `Facts`.
- `links.rs`: the place the settlement core's link records are fed from;
  it holds nothing yet.

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
- Its tests are in `../tests/plan.rs`, with the other tests of
  `src/node/settle/`.
- Keep the file list in step with the directory.
