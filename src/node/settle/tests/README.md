# src/node/settle/tests

Unit tests for the files of `src/node/settle/` and of `exec/` below it.
`mod.rs` is the module
`node::settle::tests`, declared in `../mod.rs`, and a file's own tests are
that file's child module, by `#[path]`. They run with the crate's other library
tests.

## Files

- `mod.rs`: each writer of the map wrappers against the statements it
  transcribes, the rule that only the ways past the writers mark a map, and
  each clause of the audit against a state, built through the writers, that
  breaks it alone.
- `table.rs`: the table's rule stated again as data, one line per row and case,
  against `cell`; that every row and case has a line; that a cause no code
  reaches has no cell outside the record; each row's owner; and the scan that
  `../table.rs` denies wildcard arms and holds none, with `wildcard_arms` and
  `denies_wildcards` for another file that does the same. It is a child module
  of `../table.rs`, declared there with `#[path]`, as `node::settle::table::tests`.
- `census.rs`: every field of `Node` and of the path driver, each with what
  holds it (a map wrapper of this module, the facets of the table whose rows
  it holds, or an exemption with its reason), read against the structs'
  source; that every facet has a field and every map wrapper is the table's;
  that `ActivePeer` has no setter but the listed ones; and that every field of
  the peer's record is `pub(super)`. Each scan finds a planted line. The
  sources are read with LF line endings, and a test reads and plants in a
  CRLF copy, as a Windows checkout has. The census cannot tell a field put on
  the exempt list wrongly.
- `defaults.rs`: the link rekey and path settings the node derives at the
  default configuration, at each multipath setting, against the ones
  `fips_core::proto::settle::parity` states for the schedules a real node
  and the joint world both run, so the two run alike.
- `params.rs`: the settlement core's parameters a node's configuration
  gives, against the core's defaults at the default configuration, and
  against the node's own resend schedule (the first resend one interval
  after the dial, each later wait the interval times the multiplier to the
  power of the resends made, truncated to the millisecond) at four
  multipliers. It is a
  child module of `../params.rs`, declared there with `#[path]`, as
  `node::settle::params::tests`.
- `links.rs`: the settlement core's link records the link table keeps, from
  a link's open to its close or a dial's forget, and holding a link capable
  once its bundle turns capable through the core's join; and the live audit's
  `links-mirror` clause, which skips only a peer a test mutator changed past
  the feed, every other clause still reading it, with one row per mutator
  that it flags its peer; and the node's resync of the records, after each
  mutator, after a msg1 or msg2 refused at its parse and after a drain with
  nothing queued, and of a link and an index entry a test planted, the entry
  named by its link's records rather than held as a path; and of a peer a
  test planted on a link the map lacks, at the pair the peer is at, and of
  an entry naming such a link, which is no inbound leg until the link is
  put in the map. The clause on real nodes is in
  `../../tests/settle/live.rs`.
- `plan.rs`: each transition's plan against the statements its sites ran,
  in their order, written beside each effect; that every transition but a
  cutover has a list and every effect is in one; each announcing
  transition's failure line; that a redial proven on the held link runs
  the move's effects that keep the link, in the move's order, through a
  list no transition selects; and the scan that `../exec/plan.rs` and
  `../exec/mod.rs` deny wildcard arms and hold none, through `table.rs`'s.
  That scan reads both files with LF line endings, and a test runs it on
  CRLF copies. The tests read the cases of `table.rs`, so a new case is
  planned here too.
- `remove.rs`: that every way the node removes a peer runs the one removal
  routine of `../exec/remove.rs`, by a scan of the node's code outside its
  tests for a peer taken out of the peer map, with its one exemption and a
  planted line.
- `rules.rs`: that the settlement core's `rules.txt` and `current.txt`
  (`core/src/proto/settle/`) and the doc lines of the tests they list agree:
  every listed test, of either crate, exists at its path, and its doc line
  names the rules it is listed under; every rule marked tested lists a test
  and none marked untested does; only I and I-kept rules are listed; and
  every test with the doc line is listed. It resolves each path through the
  crates' `mod` declarations, `#[path]` honoured, and finds a planted line of
  each kind.
- `scans.rs`: that no code of the root crate outside its tests builds,
  renews or closes a link's rekey or path machine but through the
  settlement core's join, with each exemption's reason and a check that
  each still names a call: a `.close(` with any argument counts, but in the
  files that close only flows and channels, and a path machine counts under
  either name, `Bundle` or `PeerBundle`; that the settlement core's table
  is stepped, polled, reaped and closed (`Table::step`, `poll`, `reap_leg`,
  `close`) only from `../decide.rs` and the two path feeds of `../exec/`,
  `pathed_core` and `release_core`, each with its reason; that only
  `src/peer/active.rs` asks the join for a change of machines, one function
  for each, and that only `../exec/` calls those functions in the node's
  code but for a crossing's move and a redial proven on the held link at
  their sites; and that the settlement
  core's gate constants, the rekey machine's parameters and constants and
  the node-address ordering (`cross_connection_winner`, and a comparison
  or `cmp` of a node address) appear in the root crate only on its exempt
  list, each item with its reason: the configuration mappings
  (`../params.rs`, `link_params`, the session's `session_params`), the
  core built and the gates' own parameters, the configuration's checks of
  the rekey jitter and cap, compile-time assertions, the published
  re-export, and the address comparisons of NAT traversal and the BLE
  transport, which choose before any handshake or below the link layer.
  Each scan finds planted lines of every shape it reads.

`remove.rs` and `scans.rs` walk the source with `src/node/tests/survivors.rs`'s
`sources`, and name each file with its `label`: the file's path below `src/`,
its components joined with `/`, which is what their lists of allowed sites are
written in. They read each file as it is checked out; every scan in them reads
by line, so a CRLF checkout reads as an LF one.

## Rules for this level

- A new field of `Node` or of the path driver takes a line in `census.rs`
  in the same change; a new exemption states why no change to a held peer
  writes the field.
- A test that builds a state no writer builds goes through `raw` and marks the
  map, as `src/node/settle/README.md` says; a test of a writer does not.
- A scan that compares a file with a path written in the test names it with
  `label`, never with the path's display form, which joins the components
  with `\` on Windows.
- Keep the file list in step with the directory.
