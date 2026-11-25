# Nostr rendezvous tests in their own files

This directory holds the unit tests of `src/nostr/`: the `nostr::tests`
module itself and two kinds of test file beside it.

- `mod.rs` is `nostr::tests`, declared from `src/nostr/mod.rs` as
  `#[cfg(test)] mod tests;`. It holds the tests that span several files of
  `src/nostr/` (the runtime, signalling, traversal and advert paths
  together), and the helpers its child modules share, among them
  `SignerAuthenticator`, a NIP-42 authenticator that signs with a node key
  directly, for clients a test builds outside the pump. Among its tests:
  the stale-advert refetch tests, one of which finds a newer advert by the
  peer on an in-process relay and refreshes the cached entry, the only
  refetch outcome that runs the full ingest check (`ingest::check` in
  `machine/adverts/ingest.rs`); the liveness tests, which find the engine
  finished when the pump has ended, or once its handle is taken; and a
  test that pins how `cached_endpoints` parses a peer's npub (the
  lower-case npub and the key in hex are found, an upper-case npub is not),
  unlike the dial path, which takes either case and refuses hex; and a test
  that the failure reply carries the time its decision was computed at,
  with the cooldown measured from it and held in the status the node
  reads. The inbox relay list's publish tests are the machine's now
  (`machine/rendezvous/tests/startup.rs`).
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
- `notify_channels.rs`: the pump's reading of the signals' channel
  (`received` in `runtime.rs`) logs a lag and reads on, and ends when that
  channel closes; the pump ends when the relay client's notification
  stream ends (the test closes the runtime's stand-in for it).
- `npub_spelling.rs`: a peer named by its npub in any letter case is
  handled by its key: the stale-advert check evicts the canonical cache
  entry; `advert_endpoints_for_peer` finds the cached advert from an upper-
  or mixed-case npub; a cooldown recorded under one spelling holds for
  the canonical npub; and a connect refused for capacity, asked for through
  the handle, comes back as a failure event carrying the configuration in
  the spelling it was given. A spelling that is not a NIP-19 npub (a bech32m
  checksum, non-zero padding bits) finds no advert. The offer's recipient
  and the initiator set are the machine's
  (`machine/rendezvous/tests/traversal.rs`).
- `punch_recv_error.rs`: a punch attempt (the machine's `Attempt`, run on a
  real socket as the pump runs it) is not ended early by a receive error on
  its socket. An attempt whose only target is a closed port runs to its
  timeout, on the socket as the machine's sockets make it (`bind_on`) and,
  on Linux, on a socket with
  `IP_RECVERR` set, where the port-unreachable is reported to `recv_from` as
  Windows reports it by default; on that Linux socket a peer's probe
  arriving after the reports is still adopted. A Windows-only test checks
  that a port-unreachable does not fail a receive on the traversal socket
  at all.
- `seen_session_cap.rs`: the seen-sessions memory
  (`Election::note_session_seen` in `machine/traversal/election.rs`) never
  forgets a session id whose offer can still be fresh. A full memory refuses
  a new session instead (the responder's refusal, `seen-sessions-full`, and
  the captured offer still refused after the memory fills, are tested in
  `machine/rendezvous/tests/traversal.rs`); a full memory takes new sessions again
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
  An `oversized-offer` refusal is logged at warn (the responder's refusal of
  an offer whose session id or nonce is over 128 bytes, at the bound
  exactly, is tested in `machine/rendezvous/tests/traversal.rs`);
  `parse_overlay_advert_event` refuses an
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
  admission policy and the signal router's channel, which the pump reads;
  the flood goes to the runtime's stand-in for the client's notification
  channel.
- `unknown_transport.rs`: an overlay advert with an endpoint of a transport
  kind this node does not know keeps its known endpoints
  (`OverlayTransportKind::Unknown` in `machine/types.rs`, dropped by
  `validate_overlay_advert` in `machine/adverts/mod.rs`); one whose only
  endpoint is of an unknown kind is still refused; and an unknown endpoint
  cannot be serialized, so it is never published.

Tests of one file, each named `nostr::<file>::tests::...`:

- `driver.rs`, of `driver.rs`: the dial candidates a peer's advert
  endpoints give. A configured peer's fallback candidates start one past
  the highest configured priority (101 with none, held at 255), and leave
  out an address already configured or already taken and an endpoint of a
  kind this node does not know; an open-discovery candidate's addresses
  start at 120 in advert order under the same rules. Each carries the time
  it was given.
- `log.rs`, of `log.rs`: the golden list of the lines the rendezvous machine
  asks the shell to log, and the pump's three notify-loop lines, each with
  the level, text, fields and target it was logged with before the code
  moved, and the two lines added since for a peer event whose signature
  does not verify; and the protocol-mismatch warning, which keeps the
  receive loop's target, text and fields now that the engine's handle logs
  it, once per cooldown.
- `pump.rs`, of `pump.rs`: the pump against nostr-sdk's in-process relay. It
  answers a relay that requires NIP-42 through the machine, and the stored
  advert the relay replays to the first subscribe is cached, which needs the
  stream taken before that subscribe, as `start` takes it; a failed
  subscribe is retried on the machine's deadline under tokio's paused clock,
  in well under a second of real time; a signal that reached the pool's
  stream is handed to the machine and opened; a request to a stopped pump gets the
  empty answer; a query sees every input sent before it; shutdown cancels a
  relay operation in flight; the start-up assembly waits for the public
  address the pump learns from a loopback STUN server; a retried subscribe
  reuses the first attempt's ids, so the client holds one subscription, not
  two; and shutdown closes the relay connections. Three tests step a pump
  built in the test without running it: a reply is sent only after the
  status it describes is stored; a socket the machine adopts reaches the
  node as an established link named `nostr-nat`, and its connect is
  forgotten; and a released connect is forgotten with no event sent.
- `sockets.rs`, of `sockets.rs`: a bound socket's datagrams reach the pump's
  channel and its sends go out, on loopback; a send that fails (to the
  broadcast address, without `SO_BROADCAST`) is reported with its error;
  and a send queued before a hand-over goes out before the socket is handed
  over.
- `relay.rs`, of `relay.rs`: the adapter against nostr-sdk's in-process
  relay. A round trip through a plain relay (a subscription delivers a
  peer's advert on the stream, a fetch by author finds it, a send naming a
  relay outside the pool is refused whole); a traversal signal goes to the
  router's channel, opens to its sender and never reaches the stream; the
  adapter answers a relay that requires NIP-42 authentication, which refuses
  a client with no authenticator as `auth-required`; and a stream taken
  before a subscribe receives the relay's stored replay; and a send to a
  relay in the pool but not connected is accepted and counted as reaching
  none; a subscribe repeated under its id leaves the client one
  subscription. The adapters here
  answer authentication with `SignerAuthenticator`, so these tests check the
  adapter's wiring; the pump's own answer is `pump.rs`'s.
- `signal_route.rs`, of `signal_route.rs`: the admission policy takes a
  traversal signal off the pool's channel and queues it on its own, once
  however many relays deliver it, and leaves every other event to the pool.
  The router remembers the last 35,000 signals it queued and forgets the
  oldest first.
- `stun.rs`, of `stun.rs`: only local candidates and server addresses of
  the socket's address family are used (`offerable`, `pick_family`). The
  STUN exchange is the machine's client (`machine/stun/tests/client.rs`).
