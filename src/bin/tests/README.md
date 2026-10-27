# `src/bin/tests/`

Unit tests for the binaries in `src/bin/` that keep their tests outside the
source file. Each file here is a child module of the binary it tests,
declared from that binary's source file as `#[cfg(test)] #[path =
"tests/<file>.rs"] mod <name>;`, so it can reach the binary's private items.
The tests run with `cargo test -p fips-mesh --bins`.

- `fipsctl.rs` tests `../fipsctl.rs` as module `query_tests`: `query`, which
  sends a request to the control socket and, for `show_status` when the
  node's reply leaves out one of the IPv6 adapter's keys, also asks the
  adapter's socket beside the given control socket and merges its answer
  in. Two nodes in separate directories each get their own adapter's
  values; an error from the node is returned without asking the adapter;
  and a node that answers the adapter's keys itself is not followed by an
  adapter query. Runs against fake Unix domain sockets in a temporary
  directory, so it is Unix only.

## Rules

- `../fipsctl.rs` keeps its older tests in its inline `mod tests` block, so
  the module declared from here has a different name.
- The binaries are listed as `[[bin]]` targets in `Cargo.toml`. This
  directory holds no `main.rs`, so Cargo never takes it for a binary of its
  own; do not add one.
- `fipstop`, a directory binary, keeps its tests in `../fipstop/tests.rs`.
