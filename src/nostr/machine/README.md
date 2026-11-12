# src/nostr/machine

The Nostr rendezvous machine: the decisions of FRC-1601 (what to publish,
what to accept, whom to punch, when to give up), with no I/O. The shell
around it, the rest of `src/nostr/`, owns the relay client, the sockets, the
clocks, the random draws and the logging, and passes what it read in as
arguments.

## The fence

Code here is written against `core`, `alloc`, `fips_core`, `serde` and
`sha2`. The guard does not hold that list: it holds a list of what may not
appear, so a crate on neither list (`ring`, `secp256k1`) passes it and is kept
out in review. What it flags:

- a `std`, `tokio`, `tracing`, `nostr_sdk`, `rand`, `libc`, `if_addrs`,
  `socket2` or `arc_swap` path, and `println!`, `dbg!`, `thread_local!` or the
  instrumentation macro;
- a `crate::` path outside `crate::nostr::machine`, and a `super` chain that
  climbs out of this directory;
- `extern crate`; `include!`, bare, as a path (`core::include!`) or imported
  under another name; a `#[path]` other than one to `tests/<file>.rs`, and any
  `path =` inside `#[cfg_attr]`;
- a `mod` named `tests`, or carrying a `#[path]`, without `#[cfg(test)]`.

Nothing compiles this module without `std`, so the fence is a convention held
by `testing/check-nostr-machine.py`, which reads the committed files and runs
in local CI (`run_nostr_machine` in `testing/ci-local.sh`) and in GitHub CI's
`ci-parity` job. Its fixtures are in `testing/nostr-machine/`. Test files
(anything under a `tests/` directory) are not scanned: they build only for the
host, under the `#[cfg(test)]` the guard requires, and may use `std`.

## Rules for changing it

- A piece that needs something outside the fence stays in the shell, or is
  split so that the part needing it does: the guard has no exemption for a
  non-test file.
- The shell keeps every path its callers use: `src/nostr/mod.rs` and the shell
  files re-export a moved name rather than having callers change.
- A clock reading arrives as an argument of a type bounded by
  `fips_core::time::Instant`; an error is this module's own, which the shell
  maps onto `BootstrapError` with the same text.
- Each subdirectory carries a README, and its tests live in its `tests/`
  directory, never in an inline test module.

## Files

- `mod.rs`: the module and its fence.
- `error.rs`: the machine's `Error`. The shell's `types.rs` maps each variant
  onto the `BootstrapError` variant of the same name with the same text.
- `params.rs`: `Params`, the configuration values the machine's pieces read.
  The machine cannot name the node's configuration, so the shell's `types.rs`
  converts `NostrRendezvousConfig` into it, one field per key.
- `signal.rs`: the traversal offer and answer bodies and their checks:
  freshness against the caller's wall-clock reading, with
  `FRESHNESS_SKEW_TOLERANCE_MS` of grace (configuration validation reads the
  same constant), the answer's match to our offer, and the clock-skew
  estimate. Sealing and unsealing the Nostr event stay in the shell's
  `signal.rs`.
- `types.rs`: the wire and payload types (the event kinds and identifiers, the
  advert, offer, answer and punch packet bodies, and the failure-state views
  the node reads). Their serde attributes are the wire format; the shell's
  `types.rs` re-exports every one.
- `punch/`: the punch packet's prefixes and codec, punch planning, and the
  suspicious-offer warning limit.
- `stun/`: the STUN codec and local-candidate selection.
- `traversal/`: what the node remembers about traversal attempts: the
  failure streaks and cooldowns, the initiator election and the seen-sessions
  cache, and the rate limit on inbound traversal signals.
- `tests/`: the unit tests of the files above, and helpers the machine's
  tests share.
