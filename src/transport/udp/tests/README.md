# UDP transport tests

Unit tests for files in `src/transport/udp/`. Each file here is the test
module of the source file of the same name one level up, declared from that
file as `#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`, so it stays a
child module of its source file and can reach that file's private items.

- `classify.rs`: tests for `classify.rs`, the datagram classification hook.
  The default filter discards the two reserved punch-packet prefixes and
  passes everything else; a classifier registered with an instance decides
  in its place. Each receive path is checked to apply the classifier it was
  given: a started instance, an adopted instance, the receive loop itself
  and, on Linux and macOS, a per-peer connected socket's drain thread. The
  tests register a classifier that discards only datagrams starting `0xAA`,
  so a registered classifier can be told apart from the default filter.
  The classifier the Nostr rendezvous registers
  (`crate::nostr::classify_datagram`) is checked to discard both punch
  packets, alone and on a started instance. Being a child of `classify`,
  the module also reaches the receive loop, which is private to `mod.rs`.

`mod.rs` and `dns.rs` still carry inline `mod tests` blocks.
Those blocks predate the rule that unit tests live in this directory, and
this directory's tests do not move them. The tests of `io/` live in
`io/tests/`.
