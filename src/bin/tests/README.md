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
- `fipsctl_path.rs` tests `../fipsctl.rs` as module `path_tests`: the
  requests `path show`, `path pin` (with and without an address) and
  `path unpin` build. It reads
  `../../control/snapshots/fipsctl_path_requests.json`, the request fixture
  the control socket's round trip test in `src/node/tests/path_control.rs`
  also sends, so the client and the daemon are checked against one source.
  It opens no socket, so unlike `fipsctl.rs` it runs on every platform.
- `fipsctl_probe.rs` tests `../fipsctl.rs` as module `probe_tests`: the
  probe client's ceiling (`probe_ceiling_ms`). The client waits for the
  daemon's reported budget plus five seconds, or for an explicit `--timeout`
  instead. A saturated budget, which a daemon reports for a lookup retry
  ladder with a huge entry, and a huge `--timeout` both give a ceiling of
  `u64::MAX` rather than overflowing. It opens no socket, so it runs on every
  platform.
- `fipsctl_npub.rs` tests `../fipsctl.rs` as module `npub_tests`: an npub
  given in any letter case. An argument in upper or mixed case is read as an
  npub rather than looked up as a host name (`resolve_peer`), its mesh
  address is its owner's (`mesh_address`), and a public key file holding it
  gives the same address (`address_from_file`).

## Rules

- `../fipsctl.rs` keeps its older tests in its inline `mod tests` block, so
  the modules declared from here have different names.
- The binaries are listed as `[[bin]]` targets in `Cargo.toml`. This
  directory holds no `main.rs`, so Cargo never takes it for a binary of its
  own; do not add one.
- `fipstop`, a directory binary, keeps its tests in `../fipstop/tests.rs`.
