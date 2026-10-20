# Configuration tests

Unit tests for files in `src/config/`. Each file here is a test module of a
source file one level up, declared from that file with
`#[cfg(test)] #[path = "tests/<file>.rs"]`, so it stays a child module of
that file and can reach its private items.

- `udp_interface.rs`: tests for the interface-name rules in
  `Config::validate` (`mod.rs`): the UDP `interface` field, and the Ethernet
  `interface` rules that share the same name check.
- `rekey_switch.rs`: tests for the removed `node.rekey.enabled` key: a file
  that still sets it loads through `Config::load_from_paths`, the key is
  ignored and never written back, and one warning names it. The load runs
  under `LoadLog::hold` (`loadlog.rs`), as the daemon's does, so the test
  also checks that the warning is held during the load and arrives when the
  held log is replayed.

`mod.rs` declares these as `mod udp_interface_tests` and `mod rekey_switch`,
not as `mod tests`, because `mod.rs` still carries an inline `mod tests`
block of that name. That block, and the inline blocks in the other files
here, predate the rule that unit tests live in this directory; moving them is a
separate change. Once `mod.rs`'s block has moved, its tests and these can
share the usual `mod tests;` declaration.
