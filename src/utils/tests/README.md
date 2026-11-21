# src/utils/tests

Unit tests for the modules in `src/utils/`, one file per module, each compiled
as a child module of the file it tests so it can reach that file's private
items.

- `onlink.rs`: the test of `read_system` in `onlink.rs`, attached from there
  with `#[cfg(test)] #[path = "tests/onlink.rs"] mod tests;` (names
  `utils::onlink::tests::...`): the system read holds every decodable up
  non-loopback IPv4 prefix of the host, including the first and last address
  of its range, and counts as discarded each prefix the platform listed with
  length 0 (a macOS VPN `utun` netmask the reader cannot decode). The host's
  interfaces can change while it runs, so it judges the read only against a
  listing of them taken unchanged before and after it, retrying a few times.
  Two more tests drive that check with the listing a Mac with VPNs up
  produces and with reads that lost, zeroed or narrowed a decodable prefix.
  The prefix set itself is `fips-core`'s, and its tests are in
  `core/src/utils/tests/onlink.rs`.
- `sockbind.rs`: the `fips` group lookup that every Unix socket bind makes,
  run from many threads at once. On musl a lookup through libc's static
  buffers corrupts the heap under that load, so a regression there crashes the
  test binary.
- `sockpeer.rs`: the control clients' check of who serves a socket. The trust
  table accepts a server running as root, as the client's own uid or as the
  `fips` account, and refuses any other uid, including a member of group
  `fips` and the `fips` uid on a host with no `fips` account. Root and the
  client's own uid are accepted without looking the `fips` account up. A
  refusal names the path and the server's uid. `peer_ids` on a connection to a
  listener of the test's own reports the test's effective uid and gid. Binding
  a listener under another uid needs root, so these tests cannot catch a
  `peer_ids` that reports the wrong id when it happens to equal the right one:
  the client's own uid, or the gid on a host where the test's uid and gid are
  the same number.

`sockbind.rs` in the parent directory also keeps an older inline `tests`
module for its directory and permission policy; it has not been moved here.
