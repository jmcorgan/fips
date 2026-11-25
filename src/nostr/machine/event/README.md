# src/nostr/machine/event

The Nostr events a node signs and opens: the node's signer, and one codec per
event kind FRC-1601 has a node publish or send. The shell builds its events
through these and passes in the time and the random bytes each needs; nothing
here reads a clock or draws randomness of its own.

## Files

- `mod.rs`: `NodeSigner`, the only holder of the node key in FIPS's Nostr
  code, and `SignedKind`, the four kinds FRC-1601 Section 3.2 lets that key
  sign (the advert 37195, the inbox relay list 10050, the seal 13 and the
  NIP-42 authentication 22242). `NodeSigner::sign` takes one of them, a
  `created_at` and 32 aux bytes, builds the event with `UnsignedEvent::new`
  and signs it with `sign_schnorr_with_aux_rand` on the core's secp256k1
  context.
- `advert.rs`: the overlay advert event (tags `d`, `protocol`, `version`,
  `expiration`, in that order) and the reading of a peer's first `protocol`
  tag.
- `inbox.rs`: the inbox relay list a node publishes (one `["r", url]` per
  relay), and the reading of a peer's list by the rules nostr 0.44 used,
  written out because nostr 0.45's per-NIP readers accept more shapes.
- `auth.rs`: the NIP-42 authentication event (tags `challenge`, then
  `relay`), which the shell's relay client sends when a relay asks for one.
- `signal.rs`: the traversal signal. The rumor (kind 14), the seal (kind 13,
  NIP-44 encrypted to the receiver, signed by the node key, `created_at`
  backdated by 0 to 172,799 s) and the wrap (kind 21059, signed by a one-time
  key, tagged `p` and `expiration`), composed by hand because nostr's NIP-59
  builders emit kind 1059 and read the clock and the OS random source. Every
  random value is drawn from the caller's `EntropySource`. Opening checks the
  wrap's kind and signature, then decrypts and checks the seal, then decrypts
  the rumor.
- `tests/`: the tests of the files above.

## Rules for changing it

- Every event is built with `UnsignedEvent::new` from a time passed in, never
  with nostr's `EventBuilder`, which fills an unset `created_at` from the
  clock.
- A codec that needs one random value takes it as an argument; one that needs
  several takes an `EntropySource` type parameter.
- An error is the machine's `Error`: `Nostr` for a primitive that refused,
  `EventParse` for JSON that did not parse, `Protocol` for a wrong kind, each
  with the text `BootstrapError` gives the same case.
