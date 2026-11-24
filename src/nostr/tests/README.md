# Nostr rendezvous tests in their own files

This directory holds the unit tests of `src/nostr/`: the `nostr::tests`
module itself and two kinds of test file beside it.

- `mod.rs` is `nostr::tests`, declared from `src/nostr/mod.rs` as
  `#[cfg(test)] mod tests;`. It holds the tests that span several files of
  `src/nostr/` (the runtime, signalling, traversal and advert paths
  together), and the helpers its child modules share.
- Child modules of `mod.rs`, which declares each as `mod <name>;`. Each is a
  child of `nostr::tests` and reaches the `pub(super)` items of the files in
  `src/nostr/` and the private helpers of `mod.rs` (such as `send_probe`).
  Each holds one behaviour's tests.
- The tests of one file in `src/nostr/`, declared from that file as
  `#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`, so they are its
  child module and reach its private items.

Child modules of `mod.rs`:

- `clock_skew.rs`: the clock-skew estimate (`estimate_clock_skew` in
  `machine/signal.rs`) yields no estimate, rather than a panic or a wrapped
  figure, when the responder's timestamps are outside the `i64` range or
  overflow the offset arithmetic, and still estimates an ordinary round
  trip.
- `fixtures.rs`: the nostr 0.44 events recorded in `src/nostr/fixtures/v044/`
  open and parse with today's code (each wrap with its recipient's key, the
  advert through `parse_overlay_advert_event`, the inbox list through
  `inbox_relays`), and today's event builders, run again at the capture
  time, still emit what they hold.
- `inbox_read.rs`: golden tables for two readings of what a peer sends,
  each row pinned to what nostr 0.44 reads from that shape. The relays a
  kind 10050 inbox relay list names (`inbox_relays` in `runtime.rs`), over
  32 tag shapes one at a time and all together, so duplicates collapse; that
  an advert is read by its first `protocol` tag; and the validity
  `compute_advert_valid_until_ms` gives an advert over 18 `expiration` tag
  shapes, where four rows follow nostr 0.45's reading, which the relay
  client applies before the shell sees the event.
- `notify_channels.rs`: the notify loop in `runtime.rs` logs a lag on the
  signals' channel and reads on, and ends when that channel closes or the
  relay client's notification stream ends.
- `npub_spelling.rs`: a peer named by its npub in any letter case is
  handled by its key. `request_connect` addresses the offer to the canonical
  npub and registers the initiator under it, so an upper-case configured
  peer still wins the dual-init election; the stale-advert check evicts the
  canonical cache entry; `advert_endpoints_for_peer` finds the cached advert
  from an upper- or mixed-case npub; and a cooldown recorded under one
  spelling holds for the canonical npub. A spelling that is not a NIP-19 npub
  (a bech32m checksum, non-zero padding bits) finds no advert.
- `punch_recv_error.rs`: a punch attempt (`run_punch_attempt` in
  `traversal.rs`) is not ended early by a receive error on its socket. An
  attempt whose only target is a closed port runs to its timeout, on the
  socket as the runtime makes it and, on Linux, on a socket with
  `IP_RECVERR` set, where the port-unreachable is reported to `recv_from` as
  Windows reports it by default; on that Linux socket a peer's probe
  arriving after the reports is still adopted. A Windows-only test checks
  that a port-unreachable does not fail a receive on the traversal socket
  at all.
- `seen_session_cap.rs`: the seen-sessions memory
  (`Election::note_session_seen` in `machine/traversal/election.rs`) never
  forgets a session id whose offer can still be fresh. A full memory refuses
  a new session instead, and the incoming-offer handler in `runtime.rs`
  reports that as `seen-sessions-full`; a captured offer is still refused as
  a replay after the memory fills; a full memory takes new sessions again
  once its entries expire; and the default size holds every session id the
  signal gate (`machine/traversal/gate.rs`) admits in one replay window,
  derived from the gate's rate and burst constants.
- `seen_session_floor.rs`: a responder at the defaults remembers a recorded
  session id for as long as its offer can still be fresh, through as many
  other offers as the signal gate (`machine/traversal/gate.rs`) admits
  meanwhile. The test derives that fill from the gate's rate and burst
  constants.
- `signal_bounds.rs`: a peer's traversal offer or overlay advert carrying
  an oversized string or list is refused before anything from it is kept.
  The incoming-offer handler in `runtime.rs` refuses an offer whose session
  id or nonce is over 128 bytes as `oversized-offer`, logged at warn, so a
  second copy is not a replay; `parse_overlay_advert_event` refuses an
  advert whose content is over 8 KiB, or whose `endpoints`, `signalRelays`
  or `stunServers` list has more than 32 entries, including the shape a
  byte bound alone lets through (about 2000 one-character relays). Each
  bound is tested at its value and one past it. The content bound is
  checked before decoding, and the entry bound before unusable endpoints
  are dropped. The advert published from
  the default configuration is inside every bound, and one from a
  configuration with 33 entries in each list is cut to the first 32, in
  order, and accepted by a peer.
- `signal_lag.rs`: a traversal answer delivered ahead of a flood of
  advertisements twice the relay client's notification channel size still
  reaches the traversal waiting for it, through the relay client's
  admission policy and the notify loop in `runtime.rs`.
- `unknown_transport.rs`: an overlay advert with an endpoint of a transport
  kind this node does not know keeps its known endpoints
  (`OverlayTransportKind::Unknown` in `machine/types.rs`, dropped by
  `validate_overlay_advert` in `machine/adverts/mod.rs`); one whose only
  endpoint is of an unknown kind is still refused; and an unknown endpoint
  cannot be serialized, so it is never published.

Tests of one file, each named `nostr::<file>::tests::...`:

- `offer_admission.rs`, of `offer_admission.rs`: the per-npub allowance of
  concurrent inbound offers, and that idle senders are reclaimed.
- `relay.rs`, of `relay.rs`: the adapter against nostr-sdk's in-process
  relay. A round trip through a plain relay (a subscription delivers a
  peer's advert on the stream, a fetch by author finds it, a send naming a
  relay outside the pool is refused whole); a traversal signal goes to the
  router's channel, opens to its sender and never reaches the stream; the
  adapter answers a relay that requires NIP-42 authentication, which refuses
  a client with no authenticator as `auth-required`; and a stream taken
  before a subscribe receives the relay's stored replay.
- `signal_route.rs`, of `signal_route.rs`: the admission policy takes a
  traversal signal off the pool's channel and queues it on its own, once
  however many relays deliver it, and leaves every other event to the pool.
  The router remembers the last 35,000 signals it queued and forgets the
  oldest first.
- `stun.rs`, of `stun.rs`: a STUN exchange over a loopback socket believes
  a binding success only from the server it asked, and accepts the server's
  own answer; an observation survives one lost binding request, because the
  request is retransmitted within the deadline; and only local candidates
  and server addresses of the socket's address family are used
  (`offerable`, `pick_family`).
