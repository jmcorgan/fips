# core/src/proto/fsp

The FIPS Session Protocol: end-to-end sessions between two nodes over
any number of hops. This module holds the session wire codec and the
stateless decisions about rekeying, handshake resends and the
transforms applied to session data. The session state machine that owns
the Noise XK crypto stays in the root crate's `node::session`, so this
module has no cryptography.

## Files

- `mod.rs`: declares the files and re-exports their public items.
- `core.rs`: `Fsp`, the stateless anchor, and `FspAction`: the rekey
  choreography, the msg3 resend decisions, epoch classification after
  decryption, the initiation tie-break, and the MTU clamp, bounded queue
  and ECN transforms.
- `limits.rs`: the session rekey timing constants.
- `quorum.rs`: `LinkQuorum`, the distinct-link count that must report a
  broken path before verified coordinates are demoted.
- `rekey/`: the session's profile of the shared rekey machine
  (`proto::rekey`) over Noise XK. Hidden from the docs and not yet
  called; its README describes it.
- `wire.rs`: the session message types (`SessionSetup`, `SessionAck`,
  `SessionMsg3`), packet flags, the inner message catalog and the
  header codecs.
- `tests/`: the unit tests; its README describes it.

## Invariants

- **No cryptography and no clock.** Time comes in as an argument; keys
  and ciphertext are handled by the Noise code in `core/src/noise`
  (`crate::noise`). The rule covers the files here. Session key rotation
  is moving to the shared machine one level up, `proto/rekey/`, which
  holds keys and takes a clock's instants; the session profile that
  binds it to Noise XK sits in `rekey/` here with the same exemption, and
  `core.rs` keeps the rule.
- **The session wire is protocol** and does not change on the deployed
  lines.
- **The quorum counts links, not reporters.** A vote is keyed on the
  authenticated link peer a `PathBroken` arrived over. The reporter the
  body names is plaintext the sender chooses, so counting reporters
  would let one sender cast every vote.
