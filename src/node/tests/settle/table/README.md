# src/node/tests/settle/table

The transition table of `src/node/settle/table.rs` checked on real nodes. A
test here runs one site of one column on real nodes, reads the peer's whole
state before and after, and holds each row against the row's cell at the
transition the site made. A wrong cell, a wrong row, or a site that does not
do what the table says turns the test red at a message starting `defect:`.
The module is `node::tests::settle::table`, declared in `../mod.rs`, and runs
in the `node-synthetic` group with the rest of `settle`.

## Files

- `mod.rs`: the harness the column files share, and its own tests.
  - `Seen::of(node, peer, also)` reads every `Row` of `peer` on `node`
    through the existing accessors and maps. Rows read per pair (the BLE
    mark, the connection, the connected socket) cover the peer's paths and
    the pairs in `also`, since a pair that a move, a roam or a removal leaves
    is on no path afterwards. Rows keyed by link cover the peer's link and
    every link no held peer names, so a link or an index entry a removal
    leaves behind is still read.
  - `dirty(node, peer)` makes every row differ from a fresh peering's, but
    those `dirty_misses(on)` lists with the reason, through accessors and map
    writers and never `raw`. The peering still carries frames afterwards.
  - `check_cells(before, after, &t, &others)` and `assert_cells`, the same
    failing at `defect:`, hold each row against `cell(row, &t)`. `expect`
    turns a cell into what the reading must do: kept, changed, or stated by
    the test. A cell is stated when its effect turns on the test's own
    script, such as whether the pair moved or the peering was heard; the
    test names each such row in `others` with its outcome, and may name no
    other row, so it cannot overrule the table.
  - `peered(on)`, two loopback nodes peered with multipath set as `on`;
    `ble_pair(on)`, the same on the BLE mock; `ble_paths()`, the BLE pair
    with multipath on, paths of mixed kinds, and a loopback path beside the
    BLE one, both Live, whose frames `BlePaths::shuttle` delivers.
  - Its tests show that the harness reads a change planted in each row, that
    it never calls the BLE mark kept where the mark is not read, and that
    `dirty` reaches the rows its list says.
- `promote.rs`, `replace.rs`, `crossing.rs`, `rekey.rs`, `paths.rs`,
  `remove.rs`: one file per column group, Promote, Replace, Move and Keep,
  Cutover and Restarted, Roam, Follow, Switch and Release, and Remove.
  Handshakes here are three messages: a responder promotes at the msg3, a
  restart replaces a peer at the msg3 or at this node's own msg2, and a
  crossing settles at the msg2 of a node's own dial or at the msg3 of the
  peer's (`crossing.rs` drives each order, `to_msg2` and `to_msg3`). A
  same-epoch replacement and an own or later dial answered over a held
  peering have no site on this line, and so no test.
  `paths.rs` also holds `assert_steps`, for one step of the path machine
  that made two transitions, as a handover releases the active path and
  switches in the same step: a row may change where either cell changes it,
  and must stay where both keep it.

## What a test here must do

- **Both settings.** Every test is a plain test, multipath off, and a
  `_with_multipath_on` sibling, as in `src/node/tests/settle/crossing.rs`, and
  takes nothing
  from the daemon's default. A cell whose value differs by setting is
  asserted at its own setting, in the test that runs it. `cell` itself takes
  no setting: a difference comes from what the setting lets a link hold, so
  the sibling asserts the same rule against what its setting makes. The
  exception is a column with no output with multipath off (Follow, Switch,
  Release): its cells are asserted in `_with_multipath_on` tests on a
  capable link of two paths, and the column's plain test runs the same
  script with multipath off and asserts there is no such output.
- **A driver takes the setting as an argument**: `with_path`,
  `loopback_node`, `tcp_dialled(on, ..)`, `loopback_dialled(on)`,
  `peered(on)`, `ble_pair(on)`.
- **Dirty before the transition.** Read `before` after `dirty`, so a reset
  shows as a change. Run `dirty` after peering: a node audited before it is
  dirtied counts as audited, and the writers it uses leave the audit on. A
  test that has to plant through `raw` costs its node the audit, as
  `src/node/settle/README.md` says.
- **Readings leave out what any frame moves**: `last_seen`, the link and
  per-path statistics, the instant last heard, and every MMP counter but
  the highest seen, which `dirty` puts past any counter of the session.
  Whether a frame arrived since the promotion is read, but `dirty` cannot
  move it on a peering that has carried frames.
- **A transition an authentic frame carries** (a roam, a moved path) is
  read with the per-path failure count left as the peering built it: any
  authentic frame on a path starts the path's count again, so a planted
  count cannot be kept across it. The count is read by the path's own
  identifier, and the per-pair rows in the order of the pairs' names, so
  that a path whose pair changes reads as the same path.
- **Which pair reads the connected socket and the BLE mark.** The
  connected socket (`Row::ConnectedUdp`) is read per path
  on the loopback pairs, where `install_connected_udp` seats a real socket
  on the active path and `ActivePeer::seat_socket` on any path, behind
  `any(target_os = "linux", target_os = "macos")`; elsewhere the row is not
  read. The BLE mark (`Row::BleMark`) has state only on a BLE transport: it is read per pair
  on `ble_pair` and `ble_paths`, behind `ble_available`, and is `None` on
  any other transport and where no link is pooled. A test of the mark states
  its `before` as `Some(true)` by a `precondition:`, so it cannot pass on a
  constant.
- **A manifest line on a test that runs on `ble_pair` or `ble_paths`** also
  names the test's full path in `BLE_ONLY` in `testing/mutations/run.sh`, or
  a host with no BLE build reds on it.
- **A red cells test changes the table, not the code**: the old code is the
  spec. Fix `cell` and its golden line in `src/node/settle/tests/table.rs`
  in the same commit.

## Coverage gap: the BLE mark where it is not read

The mark's "none" cells at Cutover, Restarted and Follow have no test: those
sites run on loopback, where the mark is not read. They stand on the golden
line and on reading the code, which has no `relink`, `mark_verified` or
`clear_verified` at those sites but the one a frame makes on its own link.
`assert_cells` reports such a row unread; it never counts it as kept.

The mark's cells at a replacement have no BLE test on this line either: a
restart is driven on loopback only. They stand on the golden line and on
reading the teardown's `relink` to no link and the promotion's mark.
