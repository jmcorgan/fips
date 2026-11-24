# src/nostr/machine/stun

The STUN pieces that read no socket: the codec, the binding exchange as a
machine, and the choice of which of this host's own addresses a traversal
offers as same-LAN candidates. The rendezvous machine runs the advert's
public-address observation through `client.rs`, and the shell's sockets
carry its datagrams. The traversal flows still run their exchange from the
shell's `stun.rs`, whose `perform_stun` drives the same client for one
server on the traversal socket (the lookup, the sends and the receives
against the client's deadlines), and which reads the host's interfaces and
probe sockets, calling in here for the selection.

## Files

- `mod.rs`: the codec. `parse_stun_url` reads a `stun:host:port` server
  entry, `create_stun_binding_request` builds the 20-byte binding request,
  and `parse_stun_binding_success` accepts a binding success for our
  transaction id and returns its MAPPED-ADDRESS or XOR-MAPPED-ADDRESS (IPv4
  or IPv6), refusing anything malformed rather than reading past it.
- `client.rs`: `Observation`, one STUN observation over a list of servers,
  as a machine. Per server it parses the URL, resolves the host (an IP
  literal needs no lookup) and picks the first address of the socket's
  family (`pick_family`, which the shell's `stun.rs` tests also use), then sends
  a binding request with a fresh transaction id from the caller's entropy,
  retransmitting from 500 ms, doubling, until the server's deadline. It
  believes a binding success only from the exact address it asked, counts
  datagrams from anywhere else, and ends a server's wait on the deadline,
  on a receive error, or at once when the first send fails (a failed
  retransmission is ignored). It says what to do as `Out` values and ends
  with the first answer or the last server's error, in `BootstrapError`'s
  text.
- `candidates.rs`: local-candidate selection. The shell passes the
  interface list (each address with its interface's up and loopback flags,
  in listing order) and the local address each probe and wildcard bind
  returned; `local_candidates` keeps the private addresses of up,
  non-loopback interfaces, then the observed addresses, dropping unspecified
  ones and repeats. `PROBES` and `WILDCARDS` are the probe and bind targets
  the shell uses.
- `tests/`: this directory's unit tests.

## Rules for changing it

- `parse_stun_url` returns the machine's `Error::Stun`, which the shell maps
  to `BootstrapError::Stun` with the same text, which the shell logs when an
  observation fails; the lab's STUN fault suite reads those lines. The
  client's error texts are the same ones, written out.
- Selection order is the order the candidates go on the wire in an offer.
