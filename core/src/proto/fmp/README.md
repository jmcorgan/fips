# core/src/proto/fmp

The FIPS Mesh Protocol link layer: the lifecycle of a connection to a
direct peer, from the Noise IK handshake through rekeying to teardown,
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
  snapshot type, the msg1 digests (`Msg1Digest` of the
  whole wire message, which recognises resends, and `EphemeralDigest` of
  the ephemeral the msg1's AEAD binds, which recognises a copy whatever
  its header says), the `poll_timeouts` decision (handshake timeout),
  the outcome of the shell's Noise read of a msg1 (`WireOutcome`), the
  refusals a msg1 is counted under (`InboundReject`), the promotion's
  result and the cross-connection tie-break. Each handshake msg1 and
  msg2 is classified by the settlement core (`proto::settle`).
- `state.rs`: `ConnectionState`, the bookkeeping of a connection in its
  handshake phase, which holds this node's index for the handshake as an
  `IndexLease` from the rekey machine's `lease::allocate`, so promotion
  hands that lease to the link's machine, and stamps its activity with a
  `LegStamp`: a wall-clock reading for the start and idle times operators
  are shown, and the caller's interval-clock reading, which the handshake
  timeout reads; and `Fmp`, the stateless lifecycle anchor `Node` holds.
- `silent.rs`: `ActiveBackoff`, the refusal in force for an identity
  whose link sessions ended without an authenticated frame, as the msg1
  refusal's log reads it. The node keeps the record of those sessions in
  the settlement core's restart gates (`proto::settle::gates`) and fills
  the refusal from them.
- `limits.rs`: the connection-retry backoff arithmetic.
- `rekey/`: the link's profile of the shared rekey machine
  (`proto::rekey`) over Noise IK, the node-level read of a peer's msg1,
  and the replay record of a link setup. Hidden from the docs; the root
  crate's active peers hold their link's sessions in a machine on it. Its
  README describes it.
- `wire.rs`: the link framing codec: the common prefix, the encrypted,
  msg1 and msg2 headers, the handshake message types, disconnect
  reasons and the disconnect message, and `FRAME_OVERHEAD`, the bytes an
  established frame adds around a link message, which the node's wire
  length accounting and the path ack size rule both use.
- `tests/`: the unit tests; its README describes it.

## Invariants

- **Handshake sizes come from `crate::noise`.** `wire.rs` checks msg1
  and msg2 lengths against the constants there; it does not restate
  them.
- **The framing is wire format** and does not change on the deployed
  lines.
- **No encryption here.** Encryption, decryption and key derivation
  are in the Noise code in `core/src/noise` (`crate::noise`). The rule
  covers the files at this level; `rekey/` drives the Noise handshake and
  holds keys, as the shared machine it binds does.
