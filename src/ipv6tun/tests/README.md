# `src/ipv6tun/tests/`

Unit tests for files in `src/ipv6tun/` that keep their tests outside the source
file. Each file here is a child module of the source file it tests, declared
from that file as `#[cfg(test)] #[path = "tests/<file>.rs"] mod <name>;`, so it
can reach the source file's private items.

- `dns.rs` tests `../dns.rs` as module `reply_tests`: where the DNS
  responder sends a reply to a mesh source address (`fd00::/8`) when no strict
  pin to the arrival interface is known to hold, and how it recognises a
  query from the mesh when the mesh interface's index is unknown (by the
  node's own mesh address, or on Windows by a remote mesh source). It covers
  the pure decisions (`reply_path`, `returns_by`, `mesh_query`), the
  destination address the receive path reports, and, in root
  network-namespace tests, the replies themselves, including with a mesh
  interface that carries no address (`ForgedSourceNetns::with_addressless_mesh`)
  and one known residual case pinned as a test.
- `tun.rs` tests `../tun.rs` as module `name_tests`: TUN startup never
  deletes, downs or takes over an existing interface named `tun.name`. A
  link of any kind but TUN is refused and left untouched, a TUN another
  process holds is an error, and an unheld persistent TUN is reopened,
  including one an earlier node left configured by exiting without stopping.
  It covers the pure kind decision (`existing_link_verdict`) and, in root
  network-namespace tests, `TunDevice::create` itself.

## Rules

- Older tests in `src/ipv6tun/` stay in their source files' inline `mod tests`
  blocks; new tests go here. A file that already has an inline `tests` module
  declares its file here under a different module name.
- The network-namespace tests need root. They are `#[ignore]`d, so the normal
  test run skips them; build with `cargo test --lib --no-run` and run the test
  binary under `sudo` with `--ignored`. They share the namespace harness
  (`ForgedSourceNetns`) with the inline tests in `../dns.rs`, which exposes it
  as `pub(super)`. The generic parts, running a setup command
  (`testutil::run_ok`) and running code inside a named namespace
  (`testutil::in_netns`), are crate-wide in `src/testutil.rs` for any
  namespace test.
- `TunDevice::create` makes its device, and reads links, in the calling
  thread's network namespace, so the TUN tests run it inside
  `testutil::in_netns` on a current-thread runtime built in that closure.
- Anything the responder reads at reply time (its route probe, the interface
  prefixes) is read in the calling thread's network namespace. A namespace
  test therefore runs the responder on a thread inside the node namespace
  (`spawn_responder`), not on the test's own runtime, and checks that the
  probe sees that namespace.
