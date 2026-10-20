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
- `core.rs`: the `EstablishView` and `LifecycleView` traits through
  which the root crate's `Node` shows its connections, the `ConnAction`
  vocabulary, the snapshot types, the msg1 digests (`Msg1Digest` of the
  whole wire message, which recognises resends, and `EphemeralDigest` of
  the ephemeral the msg1's AEAD binds, which recognises a copy whatever
  its header says), the `poll_*` decisions (handshake timeout and link
  setup msg1 resend), the inbound msg1 classification (FRC-1201 rules 1
  and 2 and the restart gates of a replacement; a held peer's same-epoch
  msg1 goes to its link's rekey machine, which owns rules 3 and 4) and
  the outbound msg2 classification (a restart when the msg2's epoch
  differs from the held peer's; a move to this dial's session when the
  held peer came from an earlier dial of this node's, whose session the
  peer's answer to this one supersedes (a replacement on a link too young
  to rekey, a rekey on an older one); else the cross-connection
  tie-break).
- `state.rs`: `ConnectionState`, the bookkeeping of a connection in its
  handshake phase, which holds this node's index for the handshake as an
  `IndexLease` from the rekey machine's `lease::allocate`, so promotion
  hands that lease to the link's machine; and `Fmp`, the stateless
  lifecycle anchor `Node` holds.
- `silent.rs`: `SilentSessions`, the record of link sessions that ended
  without an authenticated frame, and the msg1 refusal it drives.
- `limits.rs`: the connection-retry backoff arithmetic.
- `rekey/`: the link's profile of the shared rekey machine
  (`proto::rekey`) over Noise IK, the node-level read of a peer's msg1,
  and the replay record of a link setup. Hidden from the docs; the root
  crate's active peers hold their link's sessions in a machine on it. Its
  README describes it.
- `wire.rs`: the link framing codec: the common prefix, the encrypted,
  msg1 and msg2 headers, the handshake message types, disconnect
  reasons and the disconnect message.
- `tests/`: the unit tests; its README describes it.

## Invariants

- **The silent-session records are an ordered map on purpose.** They are
  keyed by peer identity, which a remote party chooses. A B-tree needs
  no hash seed, so a target without the standard library's random seed
  cannot be made to collide, and its worst case stays logarithmic. The
  map is never iterated, so its order is not observable.
- **Handshake sizes come from `crate::noise`.** `wire.rs` checks msg1
  and msg2 lengths against the constants there; it does not restate
  them.
- **The framing is wire format** and does not change on the deployed
  lines.
- **No encryption here.** Encryption, decryption and key derivation
  are in the Noise code in `core/src/noise` (`crate::noise`). The rule
  covers the files at this level; `rekey/` drives the Noise handshake and
  holds keys, as the shared machine it binds does.
