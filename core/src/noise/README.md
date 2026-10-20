# core/src/noise

The Noise Protocol Framework as FIPS uses it, over secp256k1: the IK
handshake that authenticates a link (FMP), the XK handshake that opens
an end-to-end session (FSP), the transport session each produces, the
replay window, and the ChaCha20-Poly1305 AEAD they seal and open with.
The link-layer wire codec in `proto/fmp/wire.rs` checks frame lengths
against the sizes here.

The root crate's `src/noise.rs` re-exports the handshake, session,
replay and cipher-state items and the sizes under `fips::noise`. It does
not re-export the `aead` module: root code meets `AeadKey` only as the
type the sessions' key hand-outs return, and in the compile-time tie
that pins that type to `ring`. `HandshakeState` takes the
host's entropy source as a type parameter, for its ephemeral keys; the
root fixes it with the alias
`fips::noise::HandshakeState = HandshakeState<OsEntropy>`, so its
callers are unchanged. The root also reaches `take_cleared` and
`clear_slot` (hidden from the docs here), `seal`, with which its session
send paths seal a frame on a counter and key the session's rekey machine
reserved, and, from its tests only, `open`, which is behind the
`test-hooks` feature.

## Files

- `mod.rs`: declares the submodules and re-exports their public items,
  then holds the six size constants. `TAG_SIZE` (the AEAD tag),
  `PUBKEY_SIZE` (a compressed secp256k1 key) and `EPOCH_SIZE` (the
  startup epoch) are the parts; `EPOCH_ENCRYPTED_SIZE`,
  `HANDSHAKE_MSG1_SIZE` and `HANDSHAKE_MSG2_SIZE` are built from them.
- `cipher.rs`: the module's former root header: the module
  documentation of the two patterns, the protocol names, the XK message
  sizes, `MAX_MESSAGE_SIZE`, `REPLAY_WINDOW_SIZE`, `NoiseError`,
  `HandshakeRole`, `NoisePattern` and `HandshakeProgress`; then
  `CipherState`, the transport cipher with its nonce counter, its
  `seal` and `open` helpers, and `take_cleared` and `clear_slot`, which
  clear the bytes a moved-out secret leaves in its slot.
- `handshake.rs`: `HandshakeState<E>`, the IK and XK state machines,
  and the symmetric state under them; `into_session` turns a completed
  handshake into a `NoiseSession`. Its fields are visible to the rest of
  the module only for `fork.rs` and that file's tests.
- `fork.rs`: the `Fork` trait, a copy of a handshake made for one read,
  its implementation for `HandshakeState`, and the read-on-fork methods
  `fork_msg2` (IK msg2 at the initiator), `fork_xk2` (XK msg2 at the
  initiator) and `fork_xk3` (XK msg3 at the responder). Each borrows the
  handshake immutably and returns the fork the read advanced.
- `session.rs`: `NoiseSession`, the two cipher states and the replay
  window of a completed handshake, and the key hand-outs
  (`send_cipher_clone`, `recv_cipher_clone`) and counter calls the
  root crate's encrypt and decrypt workers use. `open_unmarked`
  authenticates a frame without touching the window, for the rekey
  machine, which checks the window, opens, and marks the counter only
  once it has decided to accept the frame.
- `replay.rs`: `ReplayWindow`, the sliding window that rejects repeated
  or too-old counters.
- `aead.rs`: ChaCha20-Poly1305 (RFC 8439) behind the `Aead` trait, with
  two backends. `AeadKey` is the one this build uses: `ring`'s
  `LessSafeKey` when the crate's `ring` feature is on, RustCrypto's
  `ChaCha20Poly1305` otherwise. `nonce(counter)` builds the transport's
  nonce: four zero bytes, then the counter little-endian.
- `tests/`: the module's unit tests. Its own README describes it.

## Choosing the AEAD backend

The backend is chosen by feature, not by target, since this crate has
no target `cfg`. The root crate's `fips-core` line enables `ring`, so
every hosted build seals and opens with `ring`'s assembly. A build of
this crate alone (`cargo build -p fips-core`, the bare-metal build,
firmware) has no `ring` and uses RustCrypto, which builds for any
target; `ring` does not build for the bare-metal targets. RustCrypto is
always a dependency, so the cross-backend tests can run in any build
that has `ring` on. When both are present `ring` wins, which keeps the
features additive.

The root's `src/noise.rs` holds a compile-time tie: a function from
`AeadKey` to `ring::aead::LessSafeKey`, which fails to compile if the
root's `fips-core` line loses the `ring` feature. On Unix the workers'
use of the handed-out keys would fail too; on Windows, where those
paths are not built, the tie is the check that keeps the daemon on
`ring`.

## Invariants

- **A message nothing has authenticated is read on a fork.** A Noise
  read advances the symmetric state before the AEAD that authenticates
  the message has run, so a read that fails partway would leave a
  handshake the genuine message can no longer complete. Every caller
  that reads a msg2 or msg3 into a handshake it keeps on failure uses
  the read-on-fork methods and commits by replacing the handshake with
  the returned fork. There is no restore after a failed read, and no
  list of fields to restore: the fork copies every field through a
  struct literal the compiler checks, and both copies erase their
  secrets on drop. `every_read_on_garbage_leaves_the_handshake_byte_identical`
  in `tests/fork.rs` holds the methods to it.

- **The sizes and the nonce layout are wire format.** Every node must
  agree on them, and they do not change on the deployed lines. A new
  handshake message adds a constant rather than changing one.
- **The handshake's AEAD calls pass empty associated data**
  (`SymmetricState`, `handshake.rs`). That is wire behaviour: binding
  the handshake hash into the AAD would change every handshake message.
- **The two backends compute the same function.** A node on one
  interoperates with a node on the other; the cross-backend tests in
  `tests/aead.rs` hold them to it, and
  `test_cipher_state_output_is_pinned` checks `CipherState`'s output
  on each.
- **The trait's methods are `with_key`, `seal` and `open`.** `ring`'s
  `LessSafeKey` has inherent `new` and `open_in_place`, and an inherent
  method wins over a trait method of the same name, so the trait must
  not reuse those names.
- **The small per-packet calls are `#[inline]`**: `NoiseSession`'s
  `take_send_counter`, `current_send_counter`, `check_replay`,
  `accept_replay` and `highest_received_counter`, and `ReplayWindow`'s
  `check`, `accept` and `highest`. The root crate calls them per packet
  across the crate boundary. Measured on the release daemon, the leaf
  calls inline across it without the attribute; `ReplayWindow::accept`
  is the one whose code the attribute changes, inlined into the daemon
  rather than called. What counts is the daemon's call counts, not the
  attribute.
- **The key hand-out is deliberately not `#[inline]`**
  (`send_cipher_clone`, `recv_cipher_clone`, `CipherState::cipher_clone`).
  It clones and returns the cached keyed cipher. Inlining it into the
  root measured slower on the `handout/send_cipher_clone` row of
  `benches/noise_aead.rs`, but that was measured when the hand-out
  rebuilt the cipher from retained key bytes, and has not been measured
  again since. Against that rebuilding hand-out, the clone measured
  29.2 ns to 28.2 ns on the hand-out row (median of five interleaved
  rounds each, on a loaded host), within the +5 ns the change was held
  to, and the `session/*` and `worker/*` rows moved by -2.5 to +0.1
  percent, within +5 percent. The release daemon still calls the
  hand-out rather than inlining it.
- **The randomness comes from the host.** The ephemeral secret is filled
  by `E::fill`, and the ephemeral public key is derived with the shared
  context from `identity::secp()`; nothing here reads a random source
  of its own.
