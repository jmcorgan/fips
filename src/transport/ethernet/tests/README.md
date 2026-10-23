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
  that the node is rebound all the same.

## Rules

- Older tests in `src/transport/ethernet/` stay in their source files' inline
  `mod tests` blocks; new tests go here. `mod.rs` already has an inline
  `tests` module, so its file here is declared under a different name.
- The network-namespace tests need root. They are `#[ignore]`d, so the normal
  test run skips them, and no CI job runs them: build with
  `cargo test --lib --no-run` and run the test binary under `sudo` with
  `--ignored rebind_tests`. That hand run is the only coverage of the rebind.
- The module is declared `#[cfg(all(test, target_os = "linux"))]`, not per
  test, because its harness calls the Linux-only `testutil::run_ok` and
  `testutil::in_netns`, and the macOS cross-check type-checks test modules.
- A transport opens its socket, and reopens it after a recreate, in the
  calling thread's network namespace, so each test runs its whole body
  inside `testutil::in_netns` on a current-thread runtime built there.
- macOS (BPF) is compiled by the cross-check and not run.
