# src/nostr/machine/tests

Unit tests of the files at the top of `src/nostr/machine/`, and the helpers
the machine's tests share. Test files are not scanned by
`testing/check-nostr-machine.py`, so they may name `std` and the shell.

- `mod.rs` is `machine::tests` (`#[cfg(test)] pub(crate) mod tests;` in
  `machine/mod.rs`). It holds the shared helpers: `TestInstant`, an
  instant of whole milliseconds from 0 that a test sets directly, for the
  pieces that take a `fips_core::time::Instant`; and `ZeroEntropy`, an
  entropy source of zero bytes, for the hash keys of the pieces that hold a
  `fips_core::utils::hash::HashMap`; and `SeededEntropy`, an entropy source
  drawing from a per-thread generator that a test seeds with
  `SeededEntropy::seed`, for the pieces that draw at random.
- The tests of one file, declared from that file as
  `#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`, so each is its
  file's child module and reaches its private items:
  - `error.rs`, of `error.rs`: the golden text of every machine error, as the
    machine prints it and as `BootstrapError` prints it after the shell's
    mapping, and that each maps to the variant of the same name.
