# core/src/proto/fmp/rekey

The link layer's binding of the shared rekey machine (`proto::rekey`):
the profile that makes it rotate an FMP link's keys over Noise XX, with
the handshake messages and framing next's link already sends. Hidden
from the docs; the root crate reaches it only through the alias
`FmpProfile` and the pattern-neutral names `mod.rs` re-exports. Each
active peer holds its link's sessions in a machine on this profile,
built at promotion from the link setup's session and index lease. The
machine starts the link's own rekeys, reads the peer's msg2 by index,
retains and resends its msg3, cuts over after its delay, and takes every
frame the decrypt workers do not.

A peer's rekey arrives as a new link handshake and is answered by the
node's inbound leg, never by a machine. At msg3 the node reads the leg's
handshake with `read_final`, decides from what it learned whether the
completion is a link setup or a rekey of a held peer's session, and
hands a rekey to that peer's machine as `Input::PeerDone`, carrying the
leg's index lease.

## Files

- `mod.rs`: declares `xx`, the alias `FmpProfile<E>` (the pattern this
  line speaks: XX on next, IK on master), and re-exports `LinkKeys`,
  `LinkLocal`, `Final`, `Unread` and `read_final` under names that do
  not name the pattern.
- `xx.rs`: `FmpXx<E>`, the profile: three messages, the responder
  commits at msg3, the initiator cuts over after a fixed delay and
  retains msg3 until the peer is heard, the responder cuts over on the
  initiator's first frame, frames found by receiver index, a Heartbeat as
  the prompt. It writes msg1 in the 41-byte link framing and msg3 in the
  msg3 framing with this node's negotiation payload, which declares the
  session the rekey replaces by the peer's index of it (`LinkLocal`
  carries that index, the node keys and the node profile per call; the
  shell builds it with `LinkLocal::for_call` from the node keys it
  holds, and reads back from it the key a msg2 authenticated, so it can
  count a msg2 that read under another key apart from one that did not
  read), and
  reads msg2 and the responder's payload on one fork of the attempt's
  handshake. Epochs bind to `LinkKeys`, a Noise session authenticating
  the 16-byte established header. Also `read_final`, the node-level read
  of a leg's msg3 and its payload on a fork, which yields `XxFinal`: the
  initiator's static key, startup epoch and index, the declared session
  and the negotiated profile, and the completion, which becomes either
  the authenticated `XxDone` a machine takes or the session and lease of
  a link setup.
- `tests/`: the profile's tests; its README describes them.

## Rules

- **The wire is next's.** Every byte comes from the link codec and the
  Noise code; this directory adds no field and changes no size. The
  conformance test holds msg1 and msg3 byte for byte to what next's
  plain code writes from the same state.
- **Every read of an unauthenticated message runs on a fork**, and the
  negotiation payload after it is read on the same fork: its decrypt
  advances the cipher the next message is written under.
- **A rekey's msg3 always declares the session it replaces.** Without an
  index to declare, `reply` fails rather than send a msg3 the peer would
  read as a fresh dial.
- **Every exit of a leg's completion hands its lease on**: to the peer's
  machine, to link setup, or back to the caller to release. A failed
  `read_final` returns it in `Unread`.
- **Next only.** master's link speaks IK, with its own profile behind the
  same alias.
