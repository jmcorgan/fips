# core/src/noise/tests

Unit tests for `core/src/noise`.

- `mod.rs`: the module's tests, declared from `../mod.rs` with
  `#[cfg(test)] mod tests;`, so their names are `noise::tests::*`. The
  XX handshake end to end and its message sizes, the sessions
  and the replay window, the clearing of secrets on drop and by
  `take_cleared` and `clear_slot`,
  `cipher_state_still_implements_zeroize_on_drop` (the trait impl
  `CipherState` keeps, and on RustCrypto that its `AeadKey` clears itself
  on drop), `cipher_state_clone_and_handed_out_key_seal_like_the_original`
  (a clone and the key `cipher_clone` hands out seal the same bytes as
  the original, and an un-keyed state hands out none), and
  `test_cipher_state_output_is_pinned`, which pins `CipherState`'s
  transport bytes and so checks whichever AEAD backend the build uses.
  The tests under "Cost of reading an XX msg2" count DHs with `dh_ops`:
  a msg2 refused at its encrypted static key's AEAD costs one DH (`ee`),
  a genuine msg2 two (`ee` and `es`), and an invalid ephemeral none.
  `HandshakeState` is named through `crate::testutil::TestEntropy`;
  `test_handshake_ephemeral_draws_from_the_entropy_source` uses
  `FixedEntropy` instead, to show the ephemeral key comes from the
  handshake's source.
- `fork.rs`: the tests for `../fork.rs`, attached from it with
  `#[cfg(test)] #[path = "tests/fork.rs"] mod tests;`, so their names are
  `noise::fork::tests::*`.
  `every_read_on_garbage_leaves_the_handshake_byte_identical` feeds both
  read-on-fork methods, each with and without a negotiation payload
  after the base message, messages that fail before and after the read
  has advanced the state, and compares every field of the handshake
  (through a fingerprint that names each field) before and after. A
  control reads the deepest-failing message in place, to show the
  garbage would spoil a state read that way; then the genuine message
  must read, on a fork, to exactly the state an untouched copy reaches by
  reading it in place, and hand back the payload it carried.
  `a_msg2_payload_read_on_the_fork_keeps_msg3_readable` shows why the
  payload is read on the same fork: a msg3 written past an unread msg2
  payload is one nonce behind and the responder cannot read it.
- `aead.rs`: the tests for `../aead.rs`, attached from it with
  `#[cfg(test)] #[path = "tests/aead.rs"] mod tests;`, so they are a
  child module of `aead` and see its private items. The RFC 8439
  section 2.8.2 vector and the rejection of altered or short input run
  on each backend; `ring_and_rustcrypto_interoperate_both_ways` seals
  with one backend and opens with the other at every length up to 2048
  bytes and at 9000, under the AAD sizes the transport uses; and the
  nonce layout is checked against a fixed value. The `ring` tests are
  behind `cfg(feature = "ring")`, so `cargo test -p fips-core`, which
  has no `ring`, runs only the RustCrypto ones.

`cargo test -p fips-core` is the run in which `CipherState` and the
handshakes use RustCrypto; the workspace run uses `ring`.
