# core/src/proto/fsp

The FIPS Session Protocol: end-to-end sessions between two nodes over
any number of hops. This module holds the session wire codec, the
stateless coordinate and path-MTU decisions and the transforms applied to
session data, and in `rekey/` the session's profile of the shared rekey
machine. The root crate's `node::session` keeps the session table, and
each session's first handshake and keys live in a rekey machine on that
profile; outside `rekey/` this module has no cryptography.

## Files

- `mod.rs`: declares the files and re-exports their public items.
- `core.rs`: `Fsp`, the stateless anchor, and `FspAction`: the
  coordinate and path-MTU reactions, and the MTU clamp and bounded queue
  transforms. Marking a delivered IPv6 packet Congestion Experienced is the
  IPv6 adapter's, in the root crate's `ipv6tun::inbound`. The first
  handshake, with its resends and the decision between crossing
  handshakes, and every rekey, with its handshake messages, cutovers and
  drains, are the rekey machine's.
- `quorum.rs`: `LinkQuorum`, the distinct-link count that must report a
  broken path before verified coordinates are demoted.
- `rekey/`: the session's profile of the shared rekey machine
  (`proto::rekey`) over Noise XK. Hidden from the docs; the root crate's
  session table holds one machine per session, from its first handshake.
  Its README describes it.
- `wire.rs`: the session message types (`SessionSetup`, `SessionAck`,
  `SessionMsg3`), packet flags, the inner message catalog and the
  header codecs.
- `tests/`: the unit tests; its README describes it.

## Invariants

- **No cryptography and no clock.** Time comes in as an argument; keys
  and ciphertext are handled by the Noise code in `core/src/noise`
  (`crate::noise`). The rule covers the files here. A session's first
  handshake and its key rotation are run by the shared machine one level
  up, `proto/rekey/`, which holds keys and takes a clock's instants; the
  session profile that
  binds it to Noise XK sits in `rekey/` here with the same exemption, and
  `core.rs` keeps the rule.
- **The session wire is protocol** and does not change on the deployed
  lines.
- **The quorum counts links, not reporters.** A vote is keyed on the
  authenticated link peer a `PathBroken` arrived over. The reporter the
  body names is plaintext the sender chooses, so counting reporters
  would let one sender cast every vote.
