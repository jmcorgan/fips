# core/src/proto/fsp/rekey

The session layer's binding of the shared rekey machine (`proto::rekey`):
the profile that makes it rotate an FSP session's keys, and run its first
handshake, over Noise XK, exactly as deployed nodes do on the wire.
Hidden from the docs. The root crate reaches it only through the alias
`FspProfile`: each session in its session table is a machine on this
profile from its first handshake on. The machine runs that handshake (its
own attempt, the peer's setups held as candidates, the crossing decided at
msg3, the retained msg3), then seals the session's frames, opens them by
trial, starts its own rekeys, takes every setup, ack and msg3 of a rekey,
and decides every cutover and drain.
This directory is the one part of `proto/fsp/` that holds keys, under
the exemption that module's README states.

## Files

- `mod.rs`: declares `xk` and the alias `FspProfile<E>`, which names the
  pattern this line speaks (XK on master).
- `xk.rs`: `FspXk<E>`, the profile: three messages, the responder commits
  at msg3 and cuts over there, the initiator probes and waits for
  evidence, frames found by trial, a `CoordsWarmup` as the prompt (and a
  probe when sealed under a pending epoch), candidates per carrier, the
  silence trigger and an RTT-scaled setup ladder. Its `Wire` values are
  the bare 33-, 57- and 73-byte Noise XK messages; the shell wraps each in
  `SessionSetup`, `SessionAck` or `SessionMsg3` with the coordinates it
  has when it sends, so a resent setup carries current coordinates around
  identical Noise bytes. Epochs bind to `SessionKeys`, a Noise session
  authenticating the 12-byte encrypted-message header; coordinates
  between that header and the ciphertext stay outside the AEAD.
- `tests/`: the profile's conformance test; its README describes it.

## Rules

- **The wire is the deployed one.** Every byte comes from the session
  codec and the Noise code. The conformance test checks the pieces; the
  interop simulation in `proto::rekey::tests::legacy` runs whole rekeys
  and first handshakes against models of v0.5.0 to v0.5.3.
- **A probe is recognised by its inner message type**, `CoordsWarmup`,
  which `is_probe` reads from the opened plaintext; a responder that cut
  over at msg3 never takes a probe as evidence that the initiator moved.
- **Master only for now.** next's FSP speaks XX until its v2 switch to
  XK; its merge deletes `xk.rs` and adds a transitional XX profile behind
  the same alias, and the v2 profile starts again from this one.
