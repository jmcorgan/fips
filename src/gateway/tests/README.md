# `src/gateway/tests/`

Unit tests for files in `src/gateway/` that keep their tests outside the
source file. Each file here is a child module of the source file it tests,
declared from that file as `#[cfg(test)] #[path = "tests/<file>.rs"] mod
<name>;`, so it can reach the source file's private items.

- `dns.rs` tests `../dns.rs` as module `mesh_tests`: the gateway DNS
  listener does not answer, forward or map a query that arrived on the mesh
  interface, the daemon's TUN, whose name `serve` is given (`fips0` in these
  tests). It covers the drop rule (`mesh_arrival`), that
  `bind_listener` turns on arrival-interface reporting, `serve_excluding`
  with loopback standing in for the mesh, and, in root network-namespace
  tests, the listener on a wildcard bind with a veth named `fips0`, including
  a `fips0` recreated under the running listener. The root tests also check
  that the listener does not send its reply to a LAN query from a forged mesh
  source (`fd00::/8`) into the mesh, on a wildcard bind and on a bind to one
  LAN address, while LAN clients with a global or an on-link ULA address are
  still answered: an nftables counter in the gateway namespace counts UDP
  leaving by `fips0` from the listener's port
  (`GatewayNetns::forge_source`, `mesh_replies`). The reply-path
  decision is the daemon responder's (`reply_path` in `src/upper/dns.rs`),
  whose table is tested in `src/upper/tests/`. It also covers the
  gateway's startup probe of the daemon's resolver (`probe_upstream`): it
  passes on the daemon's own answer, ignores a datagram from another source
  or one that does not answer its question, and waits out its time on a
  closed upstream port. These run without root, on loopback.
- `nat.rs` tests `../nat.rs` as module `tun_tests`: every rule that matches
  the TUN by interface name uses the name the manager is given, the daemon's
  `tun.name`, so with a TUN named `fipsx` no rule names `fips0` and as many
  rules name `fipsx` as name `fips0` under the default name. Runs without
  root; it builds the rules and opens no netlink socket.
- `net.rs` tests `../net.rs` as module `proxy_tests`: how the gateway reads
  the proxy NDP sysctls for its start-up warning (`proxy_on`). Proxy NDP
  counts as on when either `all/proxy_ndp` or the LAN interface's own
  `proxy_ndp` is set, off when both read zero, and unknown when neither can
  be read. Runs without root, on a sysctl tree in a temporary directory.
- `shutdown.rs` tests `../shutdown.rs` as module `tests`: stopping the
  gateway's tasks returns, so the cleanup after it is reached, with the real
  resolver or a stand-in with the tick's shape parked in `send` on a full
  pool-event channel of the gateway's capacity; and that a task which does
  not end on the signal (the real resolver waiting on a silent upstream, a
  tick waiting on a lock) is abandoned at the stop bound. Runs without root,
  on an IPv4 loopback listener with a fake upstream.

## Rules

- Older tests in `src/gateway/` stay in their source files' inline
  `mod tests` blocks; new tests go here. A file that already has an inline
  `tests` module declares its file here under a different module name. The
  inline `tests` module in `../dns.rs` exposes the query, answer and pool
  helpers these tests share as `pub(in crate::gateway)`, so the tests of
  other files in `src/gateway/` can use them too.
- The network-namespace tests need root. They are `#[ignore]`d, so the
  normal test run skips them, and no CI job runs them; build with
  `cargo test --lib --no-run` and run the test binary under `sudo` with
  `--ignored`. They use the crate-wide namespace helpers in
  `src/testutil.rs` (`run_ok`, `in_netns`).
- The listener resolves the mesh interface's index, and on a specific bind
  probes the reply's route, in the calling thread's network namespace for
  every query, so a namespace test runs `serve` on a thread inside the
  gateway namespace, not on the test's own runtime.
