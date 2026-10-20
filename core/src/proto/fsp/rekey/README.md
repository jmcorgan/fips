# core/src/proto/fsp/rekey

The session layer's binding of the shared rekey machine (`proto::rekey`):
the profile that makes it rotate an FSP session's keys, and run its first
handshake, over Noise XX, with the messages next's session already
sends. Hidden from the docs. The root crate reaches it only through the
alias `FspProfile` and the names `mod.rs` re-exports: each session in its
session table is a machine on this profile from its first handshake on.
The machine runs that handshake (its own attempt, the peer's setups held
as candidates, the crossing decided at msg3, the retained msg3), then
seals the session's frames, opens them by trial, starts its own rekeys,
takes every setup, ack and msg3 of a rekey, and decides every cutover
and drain. This directory is the one part of `proto/fsp/` that holds
keys, under the exemption that module's README states.

## Files

- `mod.rs`: declares `xx`, the alias `FspProfile<E>` (the pattern this
  line speaks: XX on next, XK on master), and re-exports `SessionKeys`
  and `SessionLocal`.
- `xx.rs`: `FspXx<E>`, the profile, with the session rules of master's
  XK profile over XX messages: three messages, the responder commits at
  msg3 and cuts over there, the initiator probes and waits for evidence,
  frames found by trial, a `CoordsWarmup` as the prompt (and a probe when
  sealed under a pending epoch), candidates per carrier, the silence
  trigger and an RTT-scaled setup ladder. Its `Wire` values are the bare
  33-byte msg1, the 106-byte msg2 and the 73-byte msg3, the last two
  followed by the encrypted negotiation payload on a session's first
  handshake only; `SessionLocal` tells it per call whether the session
  is opening (the shell builds it with `SessionLocal::for_call`), and
  records the key an ack it read authenticated (`replied`), so the shell
  can count an ack the machine's bond refused apart from one that did
  not read. It reads an ack or a msg3 with or without a payload, on a
  fork. Epochs bind to `SessionKeys`, a Noise session authenticating the
  12-byte encrypted-message header; coordinates between that header and
  the ciphertext stay outside the AEAD.
- `tests/`: the profile's tests; its README describes them.

## Rules

- **The wire is next's.** Every byte comes from the session codec and
  the Noise code, and the conformance test holds the ack and msg3 byte
  for byte to what next's plain code writes. A rekey's ack and msg3
  carry no payload because next reads a rekey's ack as exactly the base
  msg2.
- **Both msg3 shapes complete.** A peer that restarted opens with a
  payload-bearing msg3 against a responder that answered as a rekey.
- **A probe is recognised by its inner message type**, `CoordsWarmup`,
  which `is_probe` reads from the opened plaintext; a responder that cut
  over at msg3 never takes a probe as evidence that the initiator moved.
- **Transitional.** The session layer's v2 handshake is XK; its profile
  replaces this one behind the same alias, starting again from master's
  XK profile.
