# src/nostr/machine/punch

The punch packet and the decisions around a punch attempt. No sockets and no
timers: the shell's `traversal.rs` plans the attempt through `plan.rs`, sends
and receives the datagrams, and calls in here to build and read them. The
attempt's own timing (the probe rounds and the settle window for a remapped
source) stays in the shell with the socket loop.

## Files

- `mod.rs`: the two reserved prefixes (`PUNCH_MAGIC`, `PUNCH_ACK_MAGIC`), the
  check a UDP receive path makes on a datagram (`is_punch_packet`, which the
  UDP transport's default filter and the Nostr classifier both call through
  `crate::nostr`), and the 24-byte codec: `session_hash`,
  `build_punch_packet`, `parse_punch_packet` and `classify_punch_packet`,
  which tells the punch loop whether a datagram is to be ignored, acked or
  taken as the peer's answer.
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
