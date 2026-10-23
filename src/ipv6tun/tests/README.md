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
  It also covers the `fd00::/8` policy rule (priority 5265) startup adds:
  both teardown paths (`shutdown_tun_interface` and `TunDevice::shutdown`)
  remove it, startup replaces an older version's rule rather than adding
  beside it, and a rule left by an exit without stop does not send another
  routing table's ULA traffic out the default route. It covers the pure kind
  decision (`existing_link_verdict`) and, in root network-namespace tests,
  `TunDevice::create` and teardown themselves.

- `bsdnet.rs` tests `../bsdnet.rs` (macOS and FreeBSD only) as module `tests`:
  the routing message layout and socket-address padding, the kernel's error
  codes surfacing for calls it refuses (an unknown sysctl name or interface,
  a route add the kernel rejects), and, as root, a route added twice through
  one interface being accepted, one present through another interface being
  refused with the other interface named, a TUN device created twice in turn
  coming up with its address, MTU and `fd00::/8` route both times and going
  down at shutdown with its other flags kept, and a configured device set up
  a second time accepting its own address and route.

## Rules

- Older tests in `src/ipv6tun/` stay in their source files' inline `mod tests`
  blocks; new tests go here. A file that already has an inline `tests` module
  declares its file here under a different module name.
- The network-namespace tests, and the macOS and FreeBSD tests that change
  routes or create a device, need root. They are `#[ignore]`d, so the normal
  test run skips them; build with `cargo test --lib --no-run` and run the test
  binary under `sudo` with `--ignored`. The FreeBSD package workflow and the
  macOS unit-test job run the `bsdnet` tests that way, with
  `--include-ignored`. They share the namespace harness
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
