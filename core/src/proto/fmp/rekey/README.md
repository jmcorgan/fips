# core/src/proto/fmp/rekey

The link layer's binding of the shared rekey machine (`proto::rekey`):
the profile that makes it rotate an FMP link's keys over Noise IK, exactly
as deployed nodes do on the wire. Hidden from the docs and not yet called;
the root crate will reach it only through the alias `FmpProfile`.

## Files

- `mod.rs`: declares `ik` and the alias `FmpProfile<E>`, which names the
  pattern this line speaks (IK on master; next points it at XX).
- `ik.rs`: `FmpIk<E>`, the profile: two messages, the responder commits
  at its answer, the initiator cuts over at the next poll, frames found by
  receiver index, a Heartbeat as the prompt. It writes msg1 and msg2 in
  the 114- and 69-byte link framing (`proto::fmp::wire`) around the Noise
  IK messages, reads a msg2 on a fork of the attempt's handshake, and
  binds every epoch to `LinkKeys` (a Noise session authenticating the
  16-byte established header). Also `read_msg1`, the node-level read of a
  peer's msg1 under this node's static key, which mints the replayable
  proof the machine takes as `Input::PeerMsg1`, and `setup_record`, the
  replay record of a link set up from a given msg1.
- `tests/`: the profile's conformance test; its README describes it.

## Rules

- **The wire is the deployed one.** Every byte comes from the link codec
  and the Noise code; this file adds no field and changes no size. The
  conformance test checks the pieces against the deployed parsers, and
  the interop simulation in `proto::rekey::tests::legacy` runs whole
  rekeys against models of v0.5.0 to v0.5.3.
- **A peer's msg1 is read before any machine sees it.** `read_msg1`
  authenticates the initiator's identity and epoch and nothing more: the
  proof is `Replayable`, because a captured msg1 reads as the peer again.
  The machine's replay record tells a copy from a fresh msg1.
- **Master only.** next speaks XX on the link; its merge of this
  directory deletes `ik.rs` and adds an XX profile behind the same alias.
