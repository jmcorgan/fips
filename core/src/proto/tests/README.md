# core/src/proto/tests

Unit tests for the files at the `proto` level. This directory is not a
module of its own: each file is attached from its source file with
`#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`, so it is a child
module of that file, sees its private items and keeps its test names.

- `framing.rs`: tests for `framing.rs` (`proto::framing::tests::...`):
  the payload limit against a copy of its earlier two-step subtraction
  at every `u16` input, and its values at the saturation edge, the IPv6
  minimum MTU and the top of the range.
- `link.rs`: tests for `link.rs` (`proto::link::tests::...`): the
  message type catalog and the session datagram codec, including a
  timing loop that is ignored by default.
- `math.rs`: tests for `math.rs` (`proto::math::tests::...`): `powi`
  agrees bit for bit with the standard library's `powi` over the inputs
  the protocol uses.
