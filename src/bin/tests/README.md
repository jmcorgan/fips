# Binary unit tests

Unit tests for the binaries whose source is a single file in `src/bin/`. Each
file here is a test module of the binary of the same name, declared from that
binary's source as `#[cfg(test)] #[path = "tests/<file>.rs"] mod <name>;`, so
it is a child module of the binary's crate root and can reach its private
items. This directory has no `main.rs`, so Cargo does not take it for a binary
of its own.

- `fipsctl.rs`: tests for the probe client's ceiling (`probe_ceiling_ms`). The
  client waits for the daemon's reported budget plus five seconds, or for an
  explicit `--timeout` instead. A saturated budget, which a daemon reports for
  a lookup retry ladder with a huge entry, and a huge `--timeout` both give a
  ceiling of `u64::MAX` rather than overflowing. `fipsctl`'s older tests are
  still in its inline `tests` module.
- `fipsctl_npub.rs`: a second test module of `fipsctl`, declared as
  `mod npub_tests`, for an npub given in any letter case. An argument in upper
  or mixed case is read as an npub rather than looked up as a host name
  (`resolve_peer`), its mesh address is its owner's (`mesh_address`), and a
  public key file holding it gives the same address (`address_from_file`).
- `fipsctl_socket.rs`: a third test module of `fipsctl`, declared as
  `mod socket_tests` (Unix only), for the control socket client
  (`send_request`). A listener in a temporary directory answers one request.
  A reply message carrying terminal escapes comes back with each control
  character replaced by U+FFFD, as does every other string in a reply, object
  keys included. A server running as the test's own user is talked to, and an
  honest reply comes back unchanged. A refusal needs a server running under
  another uid, which needs root to set up, so nothing here checks that the
  peer check runs before the request is written.
