# core/src/identity

<!-- markdownlint-disable MD013 -->

Identity types for FIPS nodes: the local node's identity, which holds
its keypair and signs; a peer's key held as its 32 bytes; the 16-byte
node address derived from a Nostr public key; the node's IPv6 address
and the 15-byte node prefix it carries; a remote peer's identity; the authentication challenge and response;
and the NIP-19 npub and nsec encodings.

The root crate re-exports the types, the encodings and `init_secp`
under `fips::identity`, next to the deprecated `FipsAddress` alias it
keeps; it does not re-export `secp` or `sha256`, and re-exports
`ErasingKeypair` only as `pub(crate)`. It does not re-export `PeerKey`
or `NodePrefix` under `fips::identity`; the rekey machine names it as
`proto::rekey::PeerKey`, and the root crate's IPv6 adapter imports it
from here for its own link. `Identity` and `AuthChallenge` take the
host's entropy source as a type parameter; the root crate fixes it with
type aliases at the same paths,
`fips::identity::Identity = Identity<OsEntropy>` and likewise
`AuthChallenge`, where `OsEntropy` is `rand`'s thread-local generator.

## Three identifiers from one key

A node's identity is a Nostr secp256k1 keypair. Three identifiers derive
from its x-only public key:

| Identifier | Type | Derivation | Used for |
| ---------- | ---- | ---------- | -------- |
| npub | `String` | NIP-19 bech32 of the public key | what people configure and see |
| node address | `NodeAddr` | first 16 bytes of SHA-256 of the public key | routing and every protocol table |
| IPv6 address | `Ipv6Address` | `0xfd` followed by the first 15 bytes of the node address | the TUN interface, so IP applications can reach a node |
| node prefix | `NodePrefix` | the first 15 bytes of the node address, which are bytes 1 to 15 of the IPv6 address | what a host packet names its destination by: the identity cache's key and the IPv6 adapter's key map |

The derivations start from the key's 32 bytes, which `PeerKey` holds
where a peer is compared and hashed without a secp256k1 call.
`PeerKey::addr` is the one place the node address is derived;
`NodeAddr::from_pubkey` and `PeerKey::address` go through it, and a
known-answer test in `tests.rs` pins its output for the generator's key.
`NodeAddr::prefix` and `Ipv6Address::prefix` are the two ways to the
node prefix, `NodePrefix::from_octets` takes it from any 16 address
bytes without checking byte 0 (a host may send outside `fd00::/8`), and
`NodeAddr::from_prefix` turns it back into a node address with a zero
last byte. The node prefix is not `IPV6_ADDRESS_PREFIX`, the `0xfd`
byte in front of it.

These derivations are part of the protocol: every node computes them the
same way, and a change to any of them stops nodes agreeing on who is
who. Treat them as wire format; they do not change on the deployed
lines. The node address hashes the key rather than using its bytes
directly, which denies grinding attacks that exploit secp256k1's
algebraic structure.

## Files

- `mod.rs`: declares the submodules and re-exports their public items.
  It also holds the shared secp256k1 context with `init_secp`, which
  installs it, and its `secp()` accessor; `IPV6_ADDRESS_PREFIX`
  (`0xfd`); `IdentityError` and its `From` impls; the `sha256` helper
  and the private `hex_encode` helper.
- `address.rs`: `Ipv6Address`, the node's 128-bit IPv6 address with the
  `0xfd` prefix, its conversion to `core::net::Ipv6Addr`, and the node
  prefix it carries.
- `key.rs`: `PeerKey`, a node's static key held as the 32 bytes of its
  x-only public key, compared and hashed as bytes. Any 32 bytes make
  one, so its conversion back to an `XOnlyPublicKey`, `to_xonly`, can
  fail; `addr` derives the node address from the bytes and `address`
  the IPv6 address. Its `Debug` shows the first four bytes, and the
  rekey machine's state digests use that form.
- `node_addr.rs`: `NodeAddr`, the 16-byte node identifier taken from the
  SHA-256 of the public key, which it derives through `PeerKey::addr`;
  its `prefix`, and `from_prefix`, the zero-padded reverse.
- `prefix.rs`: `NodePrefix`, bytes 0 to 14 of a node address, and
  `from_octets`, which reads bytes 1 to 15 of an IPv6 address.
- `peer.rs`: `PeerIdentity`, a remote peer known by its public key only.
- `encoding.rs`: npub and nsec encoding and decoding, and
  `decode_secret`, which accepts an nsec or a hex secret key.
- `local.rs`: `Identity`, the local node's keypair with its node address
  and IPv6 address. It generates a key, signs data and authentication
  challenges, and erases its private key when dropped. Also
  `ErasingKeypair`, a guard that erases a borrowed `Keypair` in place
  when it goes out of scope.
- `auth.rs`: the authentication challenge-response: `AuthChallenge`
  (32 random bytes, and the check of a response to them),
  `AuthResponse`, and the digest the response signs.
- `tests.rs`: the unit tests for the items above. Most build `Identity`
  and `AuthChallenge` with the test entropy source, through aliases at
  the top of the file. The entropy tests, which check that signing and
  `generate` draw on the type's source, name
  `super::Identity::<FixedEntropy<N>>` and
  `super::AuthChallenge::<FixedEntropy<N>>` directly, since the aliases
  take no parameter.

## Invariants

- **The shared context.** `secp()` returns one `Secp256k1<All>`, built
  once and reused by every caller in a build, the root crate's
  included. The host installs it first with `init_secp(seed)`, which
  blinds it with the 32 random bytes it is given; the daemon does so at
  start-up from the OS random source, and refuses to start if the
  context was already built. The first install wins and is never
  replaced; `init_secp` returns `false` if it came too late. Without
  `init_secp`, `secp()` builds the context with `Secp256k1::new()` on
  first use, which is blinded only when `secp256k1` is built with its
  `rand` and `std` features. This crate does not enable them, so a
  build of the core alone (firmware, for example) gets an unblinded
  context unless it calls `init_secp`. Any build that includes the root
  crate has them on through the root's own `secp256k1` dependency, so
  `fipsctl`, `fipstop`, `fips-gateway` and library users that never
  call `init_secp` still get a blinded context. Blinding protects
  secret keys from side channels; it never changes a key or signature.
- **Randomness comes from the host.** `Identity<E>` and
  `AuthChallenge<E>` draw every random byte from `E`, an
  `EntropySource`: `generate` the secret key or the challenge, and
  `sign` and `sign_challenge` the 32 BIP-340 auxiliary bytes they pass
  to `sign_schnorr_with_aux_rand`. Nothing here reads a random source
  of its own. A source that returns predictable bytes makes the keys
  predictable, and one that returns only zeros makes
  `Identity::generate` panic on an invalid secret key.
- **Public but hidden.** `secp`, `sha256` and `ErasingKeypair` are
  `pub` and `#[doc(hidden)]`, because they are not part of the crate's
  interface. The root crate re-exports `ErasingKeypair` as `pub(crate)`;
  no crate outside this one names `secp` or `sha256`, so they could be
  narrowed.
- **`hex_encode` stays private.** It formats `NodeAddr` for display and
  is not re-exported.
- **`IdentityError`.** The `From` impls for the `secp256k1`, `bech32`
  and `hex` errors are written by hand, not derived with `#[from]`:
  `#[from]` also makes the field the error's `source()`, which needs
  the error trait on the field type, and those crates implement it
  only with their `std` features. So `source()` returns `None` for
  `InvalidSecretKey`, `Bech32Encode`, `Bech32Decode` and `InvalidHex`;
  the inner error's text is in the message. Changing a variant or a
  message changes what the root crate's callers see.
- **Secret material.** `Identity` holds the node's long-term private
  key. It erases the key when dropped, its constructors erase the
  intermediate secret they built it from, and `ErasingKeypair` erases a
  borrowed copy; each erase clears only the copy it reaches (see
  `Identity`'s doc comment). `encoding.rs` touches secret keys to encode
  or decode an nsec, and clears the raw byte copies it makes
  (`Zeroizing`). The nsec string `encode_nsec` returns is the secret in
  another form, and clearing it is the caller's job.
