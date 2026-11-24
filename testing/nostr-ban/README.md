# testing/nostr-ban

Break test for the nostr ban in the root `clippy.toml`.

The root `clippy.toml` bans every public `nostr` item that reads the clock or
the OS random source under the nostr features the root package enables:
`EventBuilder` as a type, and the methods and trait methods that reach
`Timestamp::now`, `SystemTime::now` or `SysRng`. FIPS's Nostr events take
their time and random bytes from the caller (`src/nostr/machine/event/`), so
non-test code may use none of them; the test files that build events with
nostr's own helpers carry a file-level allow. Clippy resolves each entry by
path, and an entry it cannot resolve, misspelt or moved by a nostr release,
draws only a warning that `-D warnings` does not turn into an error. Such an
entry bans nothing while clippy stays green, so the ban is tested here.

## Files

- `Cargo.toml`: a crate of its own workspace, depending on `nostr` with the
  root package's nostr features, so every entry resolves.
- `lib.rs`: declares the two modules below.
- `banned.rs`: one use of each banned item, one per line, the asynchronous
  forms in an `async fn`.
- `allowed.rs`: the same uses under
  `#![allow(clippy::disallowed_types, clippy::disallowed_methods)]`, the shape
  the allowed test files take.
- `test.sh`: copies the fixture, the root `clippy.toml`, `Cargo.lock` and
  `rust-toolchain.toml` into a temporary directory, so cargo there runs the
  pinned toolchain and the root's nostr version, and runs
  `cargo clippy -- -D warnings` there, offline when the local registry holds
  every crate. It prints the toolchain it ran.

## How it decides

`test.sh` passes (exit 0) only when clippy fails, the set of paths its
`use of a disallowed` errors name equals the set of entries in the
`clippy.toml`, each entry draws exactly one error, and every error is in
`banned.rs`. Any other outcome is exit 1. A fixture that does not compile, a
missing file or a failed fetch is exit 2: nothing was checked, which is never
a pass. `test.sh <file>` checks another `clippy.toml` in place of the root's.

The mutation: give one entry its crate-root spelling, for example
`nostr::SubscriptionId::generate` for `nostr::message::SubscriptionId::generate`,
in a copy of the `clippy.toml`, and run `test.sh` on the copy. Clippy then
draws one error fewer and warns that the path does not refer to a reachable
function, so the set check and the count check both fail.

## Changing the ban

A new entry needs a matching line in both `banned.rs` and `allowed.rs`, or
the set check fails. The list is drawn up from the nostr source for the
features the root enables; it must be drawn up again when a nostr feature or
the nostr version changes. This test catches an entry that no longer
resolves, but not an item a new release adds.

It runs in local CI's lint stage (`nostr-ban`, after
`clippy-default-features`) and in the clippy job of
`.github/workflows/ci.yml`.
