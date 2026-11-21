# src/utils/tests

Unit tests for the modules in `src/utils/`, one file per module, each compiled
as a child module of the file it tests so it can reach that file's private
items.

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
