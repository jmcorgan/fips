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
  `path unpin` build, and the warning `path pin` prints on stderr when the
  reply's pin is set but not in force (`pin_warning`), with none for a pin
  in force, an unpin or an error. It reads
  `../../control/snapshots/fipsctl_path_requests.json`, the request fixture
  the control socket's round trip test in `src/node/tests/path_control.rs`
  also sends, so the client and the daemon are checked against one source.
  It opens no socket, so unlike `fipsctl.rs` it runs on every platform.
- `fipsctl_probe.rs` tests `../fipsctl.rs` as module `probe_tests`: the
  probe client's ceiling (`probe_ceiling_ms`) and its cleanup lines
  (`probe_cleanup_lines`). The client waits for the daemon's reported budget
  plus five seconds, or for an explicit `--timeout` instead. A saturated
  budget, which a daemon reports for a lookup retry ladder with a huge
  entry, and a huge `--timeout` both give a ceiling of `u64::MAX` rather
  than overflowing. The cleanup lines describe a session the probe opened
  and left to the idle timeout as its own, with no note about warmups on a
  session it does not own; a preexisting session with warmups gets that
  note, and a removed session is described as torn down. It opens no
  socket, so it runs on every platform.
- `fipsctl_npub.rs` tests `../fipsctl.rs` as module `npub_tests`: an npub
  given in any letter case. An argument in upper or mixed case is read as an
  npub rather than looked up as a host name (`resolve_peer`), its mesh
  address is its owner's (`mesh_address`), and a public key file holding it
  gives the same address (`address_from_file`).
- `fipsctl_socket.rs` tests `../fipsctl.rs` as module `socket_tests`: the
  control socket client (`send_request`). A listener in a temporary
  directory answers one request. A reply message carrying terminal escapes
  comes back with each control character replaced by U+FFFD, as does every
  other string in a reply, object keys included. A server running as the
  test's own user is talked to, and an honest reply comes back unchanged. A
  refusal needs a server running under another uid, which needs root to set
  up, so nothing here checks that the peer check runs before the request is
  written. Like `fipsctl.rs` it opens Unix domain sockets, so it is Unix
  only.

## Rules

- `../fipsctl.rs` keeps its older tests in its inline `mod tests` block, so
  the modules declared from here have different names.
- The binaries are listed as `[[bin]]` targets in `Cargo.toml`. This
  directory holds no `main.rs`, so Cargo never takes it for a binary of its
  own; do not add one.
- `fipstop`, a directory binary, keeps its tests in `../fipstop/tests.rs`.
