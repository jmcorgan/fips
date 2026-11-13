# Nostr rendezvous tests in their own files

This directory holds two kinds of test file.

- Child modules of `src/nostr/tests.rs`, which declares each as
  `mod <name>;`. Each is a child of `nostr::tests` and reaches the
  `pub(super)` items of the files in `src/nostr/` and the private helpers of
  `tests.rs` (such as `send_probe`). Most of the directory's unit tests are
  still in `tests.rs` itself; the files here each hold one behaviour's tests.
- The tests of one file in `src/nostr/`, declared from that file as
  `#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`, so they are its
  child module and reach its private items.

Child modules of `tests.rs`:

- `clock_skew.rs`: the clock-skew estimate (`estimate_clock_skew` in
  `signal.rs`) yields no estimate, rather than a panic or a wrapped figure,
  when the responder's timestamps are outside the `i64` range or overflow
  the offset arithmetic, and still estimates an ordinary round trip.
- `notify_channels.rs`: the notify loop in `runtime.rs` logs a lag on
  either of its two channels and reads on, and ends only when a channel
  closes.
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
  (`TraversalMachine::note_session_seen` in `traversal_machine.rs`) never
  forgets a session id whose offer can still be fresh. A full memory refuses
  a new session instead, and the incoming-offer handler in `runtime.rs`
  reports that as `seen-sessions-full`; a captured offer is still refused as
  a replay after the memory fills; a full memory takes new sessions again
  once its entries expire; and the default size holds every session id the
  signal gate (`signal_gate.rs`) admits in one replay window, derived from
  the gate's rate and burst constants.
- `seen_session_floor.rs`: a responder at the defaults remembers a recorded
  session id for as long as its offer can still be fresh, through as many
  other offers as the signal gate (`signal_gate.rs`) admits meanwhile. The
  test derives that fill from the gate's rate and burst constants.
- `signal_lag.rs`: a traversal answer delivered ahead of a flood of
  advertisements twice the relay pool's notification channel size still
  reaches the traversal waiting for it, through the relay client's
  admission policy and the notify loop in `runtime.rs`.
- `unknown_transport.rs`: an overlay advert with an endpoint of a transport
  kind this node does not know keeps its known endpoints
  (`OverlayTransportKind::Unknown` in `types.rs`, dropped by
  `validate_overlay_advert` in `runtime.rs`); one whose only endpoint is of
  an unknown kind is still refused; and an unknown endpoint cannot be
  serialized, so it is never published.

Tests of one file:

- `stun.rs`, of `stun.rs`: the binding-success parser refuses truncated,
  malformed and mismatched replies and skips unknown attributes; the
  local-candidate filter keeps RFC 1918 and ULA addresses only;
  `perform_stun` believes a reply only from the server it asked; an
  observation survives one lost binding request, because the request is
  retransmitted within the deadline; and only local candidates and server
  addresses of the socket's address family are used (`offerable`,
  `pick_family`).
- `signal_route.rs`, of `signal_route.rs`: the admission policy takes a
  traversal signal off the pool's channel and queues it on its own, once
  however many relays deliver it, and leaves every other event to the pool.
