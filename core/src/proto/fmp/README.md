# core/src/proto/fmp

The FIPS Mesh Protocol link layer: the lifecycle of a connection to a
direct peer, from the Noise XX handshake through rekeying to teardown,
and the framing of every frame on a link. The root crate's peer and
node handlers own the sockets and the handshakes in flight, and hold
each established link's sessions in a rekey machine on the `rekey/`
profile, which decides each link's rekeys; they ask this module what to
do with a connection on each tick and each handshake message, and carry
it out. Handshake message bytes are opaque here.

## Files

- `mod.rs`: declares the files and re-exports their public items.
- `core.rs`: the `LifecycleView` trait through which the root crate's
  `Node` shows its connections, the `ConnAction` vocabulary, the
  snapshot types, the msg1 digests (`Msg1Digest` of the whole wire
  message, which joins both ends' log lines for one handshake, and
  `EphemeralDigest` of the ephemeral an XX msg1 consists of, which the
  silent-session record can key on; this line passes it none, since an
  XX session is promoted only at msg3), the `poll_*` decisions
  (handshake timeout and msg1 resend), the classification of an inbound
  msg3 (a msg3 declaring a rekey of the session held goes to the peer's
  rekey machine, which owns the tie-break against a rekey of its own) and
  of an outbound msg2, the cross-connection tie-break, and the
  negotiation payload's version and profile checks.
- `state.rs`: `ConnectionState`, the bookkeeping of a connection in its
  handshake phase, which holds this node's index for the handshake as an
  `IndexLease` from the rekey machine's `lease::allocate`, so promotion
  hands that lease to the link's machine; and `Fmp`, the stateless
  lifecycle anchor `Node` holds.
- `silent.rs`: `SilentSessions`, the record of link sessions that ended
  without an authenticated frame, and the handshake refusal it drives,
  applied at msg3, where the XX handshake first names the initiator.
- `limits.rs`: the connection-retry backoff arithmetic.
- `rekey/`: the link's profile of the shared rekey machine
  (`proto::rekey`) over Noise XX, and the node-level read of an inbound
  leg's msg3. Hidden from the docs; the root crate's active peers hold
  their link's sessions in a machine on it. Its README describes it.
- `wire.rs`: the link framing codec: the common prefix, the encrypted,
  msg1, msg2 and msg3 headers, the handshake message types, the
  negotiation payload, disconnect reasons and the disconnect message.
- `tests/`: the unit tests; its README describes it.

## Invariants

- **The silent-session records are an ordered map on purpose.** They are
  keyed by peer identity, which a remote party chooses. A B-tree needs
  no hash seed, so a target without the standard library's random seed
  cannot be made to collide, and its worst case stays logarithmic. The
  map is never iterated, so its order is not observable.
- **Handshake sizes come from `crate::noise`.** `wire.rs` checks msg1,
  msg2 and msg3 lengths against the constants there; it does not restate
  them.
- **The framing is wire format** and does not change on the deployed
  lines.
- **No encryption here.** Encryption, decryption and key derivation
  are in the Noise code in `core/src/noise` (`crate::noise`). The rule
  covers the files at this level; `rekey/` drives the Noise handshake and
  holds keys, as the shared machine it binds does.
