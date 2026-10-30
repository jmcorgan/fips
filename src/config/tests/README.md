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
- `buffers.rs`: tests for the internal buffer sizes in `Config::validate`
  (`mod.rs`): the floor of 1 on `node.buffers.host_channel`, and its default
  for a file that does not name it.
- `grants.rs`: tests for `node.native_api.grants`: the default writes no
  key, an entry reads from the documented shape, the IPv6 adapter's built-in
  grant in `NativeApiConfig::effective_grants` (`node.rs`) keeps port 256
  unless an entry takes it and keeps its feed and learn request either way,
  and the rules `Config::validate` refuses an entry by.
- `sockets.rs`: tests for `ipv6tun_socket` and `ipv6tun_client` (`mod.rs`),
  which place the IPv6 adapter's status socket beside the control socket: on
  Unix a sibling with `-ipv6tun` before the extension, distinct for any two
  control sockets in one directory, none for a path with no file name, and
  for a client a symlink to the control socket followed first while a path
  that does not exist is used as given; on Windows the control port plus 2.
- `merge.rs`: tests for how a later file's `tun` and `dns` sections and
  `node.identity.persistent` layer over an earlier one's, with
  `TunConfig::merge` and `DnsConfig::merge` (`src/ipv6tun/config.rs`)
  holding the sections' rules. Through `Config::load_from_paths` (`mod.rs`),
  with real files, each on-off setting takes the value of the last file that
  names it, and a bare section header names nothing. Through `Config::merge`,
  which has only parsed values, the TUN turns on but not off and
  `dns.enabled` is always taken. Each optional field is replaced only when a
  later file sets one.
- `floors.rs`: tests for `Config::apply_floors` (`floors.rs`): a value
  outside its protocol bound runs at the bound with one warning, target
  `fips::config`, naming the key, the configured value and the value used; a
  value inside it, and every shipped default, is kept without a warning; a
  second call changes nothing; and `Node::with_identity` applies the bounds
  as `Node::new` does. `floors.rs` has no inline test block, so it declares
  this file as its `mod tests`, and the tests are `floors::tests`.

`mod.rs` declares the others as `mod udp_interface_tests`, `mod rekey_switch`,
`mod buffers`, `mod grants`, `mod sockets` and `mod merge`, not as
`mod tests`, because `mod.rs` still carries an inline `mod tests` block of
that name. That block, and the inline blocks in the other files here,
predate the rule that unit tests live in this directory; moving them is a
separate change. Once `mod.rs`'s block has moved, its tests and these can
share the usual `mod tests;` declaration.
