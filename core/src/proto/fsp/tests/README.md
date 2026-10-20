# core/src/proto/fsp/tests

Unit tests for the session layer, declared from `fsp/mod.rs` as
`#[cfg(test)] mod tests;`.

- `mod.rs`: declares the test files, and scans the code of every
  non-test source file of the core for a name of the deployed session
  rekey code (its stateless decisions and snapshots, the timer cutover,
  the tie-break at a setup, the session's transitional state moves and
  entry points, the deployed policy values and fault switches), any
  `struct Policy` for a field the session's policy had (`silence` among
  them, which `Params` also has and so cannot be banned by name), and the
  session module's files also for the names the link layer's deployed
  rekey still uses and for any policy value. Code is read through
  `rekey::code_idents`, which the root crate's scan shares, so comments
  and literals are not scanned; the scan also fails if that reader
  blanked a line opening an item. A planted name shows each scan finds
  one, and named files show it reaches the session module, its rekey
  profile, the machine and its parameters. When the link layer's
  deployed rekey goes, its names move from the session-only list to the
  core-wide one. The link layer's own transitional moves are named for
  the deployed functions they replace; if one would take a banned
  session name (`trial_open` or `mark_established`, say), rename it
  rather than removing the name from the list.
- `core.rs`: the coordinate and path-MTU reactions and the data
  transforms.
- `quorum.rs`: `LinkQuorum`.
- `wire.rs`: the session message and header codecs.
