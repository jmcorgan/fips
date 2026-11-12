# BLE transport tests

Unit tests for files in `src/transport/ble/`. Each file here is declared
from a source file one level up with `#[cfg(test)] #[path = "tests/<file>.rs"]`,
so it stays a child module of that source file and can reach its private
items. A file named after its source file is that file's test module,
declared as `mod tests`. A file named after a topic is a further test module
of one source file, declared under its own name; it is used only where the
source file already has a `mod tests` block, so the names would clash.

- `recall.rs`: tests for `recall.rs`, the probe loop's bounded memory of
  link addresses: the bound on non-live addresses, eviction order, the age
  limit, and that live addresses are never dropped.
- `bluez.rs`: tests for the scan-start and dial-address decisions of the
  BlueZ backend in `io_linux.rs`: which cached device objects scan start
  removes, and which LE address type a dial uses. Declared from
  `io_linux.rs` as `mod bluez_tests`. It is an exception to the
  one-file-per-module rule, because `io_linux.rs` keeps its older inline
  `mod tests` block.

`pool.rs`, `mod.rs` and `io_linux.rs` still carry inline `mod tests`
blocks. Those blocks predate the rule that unit tests live in this
directory, and are due to move here; a test written for any of these files
once its block has moved belongs here.
