# `src/gateway/tests/`

Unit tests for files in `src/gateway/` that keep their tests outside the
source file. Each file here is a child module of the source file it tests,
declared from that file as `#[cfg(test)] #[path = "tests/<file>.rs"] mod
<name>;`, so it can reach the source file's private items.

- `dns.rs` tests `../dns.rs` as module `mesh_tests`: the gateway DNS
  listener does not answer, forward or map a query that arrived on the mesh
  interface (`fips0`). It covers the drop rule (`mesh_arrival`), that
  `bind_listener` turns on arrival-interface reporting, `serve_excluding`
  with loopback standing in for the mesh, and, in root network-namespace
  tests, the listener on a wildcard bind with a veth named `fips0`, including
  a `fips0` recreated under the running listener.

## Rules

- Older tests in `src/gateway/` stay in their source files' inline
  `mod tests` blocks; new tests go here. A file that already has an inline
  `tests` module declares its file here under a different module name. The
  inline `tests` module in `../dns.rs` exposes the query, answer and pool
  helpers these tests share as `pub(super)`.
- The network-namespace tests need root. They are `#[ignore]`d, so the
  normal test run skips them, and no CI job runs them; build with
  `cargo test --lib --no-run` and run the test binary under `sudo` with
  `--ignored`. They use the crate-wide namespace helpers in
  `src/testutil.rs` (`run_ok`, `in_netns`).
- The listener resolves the mesh interface's index in the calling thread's
  network namespace for every query, so a namespace test runs `serve` on a
  thread inside the gateway namespace, not on the test's own runtime.
