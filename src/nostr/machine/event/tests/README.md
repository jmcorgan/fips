# src/nostr/machine/event/tests

Unit tests of `src/nostr/machine/event/`. Test files are not scanned by
`testing/check-nostr-machine.py`, so they may name `std`. The keys are those
of FRC-1601 Appendix C.1, and the vectors are that appendix's, written out as
literals so they do not follow a branch's own constants.

- `mod.rs` is `machine::event::tests`, declared from `event/mod.rs`. It holds
  the shared helpers (the C.1 keys and time, `seal_in`, which decrypts a
  wrap's seal without the codec's checks, and `ScriptedEntropy`, an entropy
  source whose draws a test scripts) and the signer's tests: every kind the
  node key signs carries the `created_at` passed in, and the same inputs and
  aux bytes give the same event while other aux bytes give another signature
  over the same id.
- The tests of one file, declared from that file as
  `#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`:
  - `advert.rs`, of `advert.rs`: the two adverts of C.2 have C.2's ids.
  - `inbox.rs`, of `inbox.rs`: node B's list of C.4 has C.4's id and reads
    back as its relays.
  - `auth.rs`, of `auth.rs`: the authentication event passes nostr's NIP-42
    check, which refuses another relay or challenge.
  - `signal.rs`, of `signal.rs`: node B opens C.9's sample wrap to C.9's seal
    and C.6's rumor (`src/nostr/fixtures/frc1601/c9.json`); a wrap with a
    changed signature is refused by the signature check; the seal's backdate
    spans 0 to 172,799 s; and only the recipient's key opens a wrap.
