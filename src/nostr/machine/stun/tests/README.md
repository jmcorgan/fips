# src/nostr/machine/stun/tests

Unit tests of `src/nostr/machine/stun/`.

- `mod.rs` is `stun::tests`, declared from `stun/mod.rs` as
  `#[cfg(test)] mod tests;`. It holds the codec's tests: the binding-success
  parser refuses a truncated header, a wrong magic cookie, a transaction id
  that is not ours, a truncated XOR-MAPPED-ADDRESS and an attribute whose
  length runs past the datagram, and skips an unknown attribute to find the
  mapped address after it. It builds its own packets.
- `candidates.rs`, of `candidates.rs` (declared there as
  `#[cfg(test)] #[path = "tests/candidates.rs"] mod tests;`): the private
  overlay candidate filter (private IPv4 and unique-local IPv6 in; public,
  link-local and documentation addresses out), and selection on raw inputs:
  listing order, then the observed addresses, with down, loopback and public
  interface addresses skipped and unspecified addresses and repeats dropped.

The STUN URL parser's accepted forms and the binding success round trip are
tested in `src/nostr/tests/mod.rs`, through the shell's paths; the exchange
with a server over a socket is tested in `src/nostr/tests/stun.rs`.
