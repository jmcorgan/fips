# src/node/settle/tests

Unit tests for the files of `src/node/settle/`. `mod.rs` is the module
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
- `plan.rs`: a restart's plan against the statements it ran before, in their
  order; that every other transition's plan is empty; and the scan that
  `../plan.rs` denies wildcard arms and holds none, through `table.rs`'s. That
  scan reads the file with LF line endings, and a test runs it on a CRLF copy.

## Rules for this level

- A new field of `Node` or of the path driver takes a line in `census.rs`
  in the same change; a new exemption states why no change to a held peer
  writes the field.
- A test that builds a state no writer builds goes through `raw` and marks the
  map, as `src/node/settle/README.md` says; a test of a writer does not.
- Keep the file list in step with the directory.
