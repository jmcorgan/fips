# src/transport/tests

Unit tests for `src/transport/mod.rs`, kept out of the source file. Each
entry here is declared from `mod.rs` with `#[cfg(test)]` and a
`#[path = "tests/..."]` attribute naming the file, or the `mod.rs` of a
directory, so it stays a child module of the transport module and can
reach its private items.

- `conformance/`: declared as
  `#[cfg(test)] #[path = "tests/conformance/mod.rs"] mod conformance;`.
  The lifecycle rules every connection-oriented transport keeps, written
  once and run against TCP, Tor, Nym and BLE, with a listing that fails the
  build when a transport kind has no entry. Its README states the rules.

`mod.rs` still carries an older inline `mod tests` block. New tests go
here rather than into that block; the inline block is not converted in
passing. The transports' own tests live beside each transport, in its
directory; a rule every connection-oriented transport must keep goes in
`conformance/` instead, so it is written once.
