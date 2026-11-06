# `src/transport/ethernet/tests/`

Unit tests for files in `src/transport/ethernet/` that keep their tests
outside the source file. Each file here is a child module of the source file
it tests, declared from that file as
`#[cfg(...)] #[path = "tests/<file>.rs"] mod <name>;`, so it can reach the
source file's private items.

- `rebind.rs` tests `../mod.rs` as module `rebind_tests`: an Ethernet
  transport whose interface is deleted and recreated under the same name, as
  an OpenWrt network or wifi reload does, goes on beaconing, sending and
  receiving on the new interface without a restart, with beacons on and off.
  The tests build a network namespace with a bridge and two veth pairs, run
  a node transport and a peer transport on them, and recreate the node's
  veth, which gives it a new index and MAC. A third test moves the node's
  veth to another namespace and back, which keeps its index, and checks
  that the node is rebound all the same; on this branch the binder does not
  rebind in that case, so that test fails when run by hand until it does.
- `detach.rs` tests `../mod.rs` as module `detach_tests`: a beacon buffered
  before the interface detaches is dropped with the binding, not left for
  the next discovery tick to drain. It needs no root and runs in the normal
  test run: the transport names an interface no host has and is marked
  bound, so the binder's next probe takes the detach branch without a
  socket.
- `congestion.rs` tests `../mod.rs` as module `congestion_tests`: on Linux
  the transport reports its kernel drop total to the node's congestion
  sample, where it used to report nothing, and a sample with no socket to
  read leaves the total as it was. Elsewhere it reports nothing.
- `stats.rs` tests `../stats.rs` as its `tests` module: kernel drop readings
  add up to a running total, and the total appears under `kernel_drops` in
  the stats JSON that `show_transports` serves and the chaos harness reads.
- `io_linux.rs` tests `../io_linux.rs` as module `drop_tests`, beside that
  file's older inline `tests` block: frames turned away by a full receive
  buffer are counted by `take_drops`, and reading the count resets it. It
  opens a packet socket on `lo`, so it needs `CAP_NET_RAW`; unprivileged it
  returns early, and fails instead when `FIPS_TEST_PRIVILEGED` is set. Run
  it by hand under `sudo` with that variable set.

## Rules

- Older tests in `src/transport/ethernet/` stay in their source files' inline
  `mod tests` blocks; new tests go here. `mod.rs` already has an inline
  `tests` module, so its file here is declared under a different name.
- The network-namespace tests need root. They are `#[ignore]`d, so the normal
  test run skips them, and no CI job runs them: build with
  `cargo test --lib --no-run` and run the test binary under `sudo` with
  `--ignored rebind_tests`. That hand run is the only coverage of the rebind.
- `rebind_tests` is declared `#[cfg(all(test, target_os = "linux"))]`, not
  per test, because its harness calls the Linux-only `testutil::run_ok` and
  `testutil::in_netns`, and the macOS cross-check type-checks test modules.
- A transport opens its socket, and reopens it after a recreate, in the
  calling thread's network namespace, so each test runs its whole body
  inside `testutil::in_netns` on a current-thread runtime built there.
- macOS (BPF) is compiled by the cross-check and not run.
