# src/transport/tests

Unit tests for `src/transport/mod.rs` and the other files directly in
`src/transport/`, kept out of the source files. Each entry here is
declared from the file it tests with `#[cfg(test)]` and a
`#[path = "tests/..."]` attribute naming the file, or the `mod.rs` of a
directory, so it stays a child module of that file and can reach its
private items.

- `conformance/`: declared as
  `#[cfg(test)] #[path = "tests/conformance/mod.rs"] mod conformance;`.
  The lifecycle rules every connection-oriented transport keeps, written
  once and run against TCP, Tor, Nym and BLE, with a listing that fails the
  build when a transport kind has no entry. Its README states the rules.
- `error.rs`: declared as `mod error_tests`, because `mod.rs` already has
  an inline `tests` module. It covers the unreachable class of
  `TransportError`: `is_unreachable` is true for `Unreachable` and for an
  I/O error of kind `NetworkUnreachable`, `HostUnreachable` or
  `NetworkDown`, and false for `NotConnected` and every other failure;
  and `send_error` gives an unreachable error the same text a
  `SendFailed` of it shows, the kernel's `ENETUNREACH`, `EHOSTUNREACH`
  and `ENETDOWN` among them, while leaving any other error a
  `SendFailed`, neither of them transient.
- `sockbuf.rs`: declared from `../sockbuf.rs` as its `tests` module. A
  buffer sized through `set_buffer` is never smaller than the plain socket
  option alone gives and is what the kernel reports, with or without
  `CAP_NET_ADMIN`; a grant below the request reads as clamped, and Linux's
  doubled report of a forced grant does not; a descriptor that is not a
  socket is an error. On Linux, with `CAP_NET_ADMIN`, a receive buffer is
  granted past `net.core.rmem_max`. Unprivileged that test returns early,
  and fails instead when `FIPS_TEST_PRIVILEGED` is set; run it by hand
  under `sudo` with that variable set.

`mod.rs` still carries an older inline `mod tests` block. New tests go
here rather than into that block; the inline block is not converted in
passing. The transports' own tests live beside each transport, in its
directory; a rule every connection-oriented transport must keep goes in
`conformance/` instead, so it is written once.
