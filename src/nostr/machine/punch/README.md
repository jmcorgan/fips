# src/nostr/machine/punch

The punch packet and the decisions around a punch attempt. No sockets and no
clocks: the rendezvous machine plans the attempt through `plan.rs` and runs
the attempt machine in `attempt.rs`, and the shell's pump sends what it asks
on the traversal socket and hands it what arrives.

## Files

- `mod.rs`: the two reserved prefixes (`PUNCH_MAGIC`, `PUNCH_ACK_MAGIC`), the
  check a UDP receive path makes on a datagram (`is_punch_packet`, which the
  UDP transport's default filter and the Nostr classifier both call through
  `crate::nostr`), and the 24-byte codec: `session_hash`,
  `build_punch_packet`, `parse_punch_packet` and `classify_punch_packet`,
  which tells the punch loop whether a datagram is to be ignored, acked or
  taken as the peer's answer.
- `attempt.rs`: `Attempt`, one punch attempt as a machine (FRC-1601
  Section 6.3). It converts the punch hint's start, in Unix time, once to a
  monotonic deadline, then probes every planned target once a round, every
  `max(interval, 20 ms)`, until the start plus `max(duration, 1 ms)`. It
  reads a datagram in the FRC's order: a source that is no planned target's
  address is refused and counted before anything else, a probe is acked, an
  exact target is adopted at once, and a target's address on another port
  is held for the 250 ms settle (`PUNCH_SETTLE`), a later one replacing it.
  It ends with `Adopt` or, at its timeout, `TimedOut`, and keeps a `Tally` of
  the refused sources, superseded holds and receive errors for the one line
  the shell logs at the end.
- `plan.rs`: punch planning. It vets each peer-supplied candidate once
  (unparsable text, port 0, never-routable ranges, private addresses off our
  interface prefixes), bounds the candidate list and the target list, pairs
  our addresses with the peer's in order (reflexive to reflexive, same-LAN,
  then mixed), ranks the source of a received punch packet against the plan,
  and keeps the per-class tally of what it refused. The IP classes here are
  also the advert endpoint filter's.
- `refusal.rs`: `RefusalWarnGate`, which lets one suspicious-offer warning
  through a minute and counts the rest. It takes the instants it is handed,
  of any `fips_core::time::Instant` type; the shell passes its host clock's.
- `tests/`: this directory's unit tests.

## Rules for changing it

- The prefixes are reserved on every UDP instance, with or without a Nostr
  rendezvous, so changing either value changes what the UDP transport keeps
  from FMP.
- `parse_punch_packet` returns the machine's `Error`, which the shell maps to
  `BootstrapError::Protocol` with the same reason string.
