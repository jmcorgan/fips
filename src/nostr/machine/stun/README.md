# src/nostr/machine/stun

The STUN pieces that read no socket: the codec, and the choice of which of
this host's own addresses a traversal offers as same-LAN candidates. The
shell's `stun.rs` sends the binding request, waits for the answer, resolves
the server, draws the transaction id, and reads the host's interfaces and
probe sockets; it calls in here for everything else.

## Files

- `mod.rs`: the codec. `parse_stun_url` reads a `stun:host:port` server
  entry, `create_stun_binding_request` builds the 20-byte binding request,
  and `parse_stun_binding_success` accepts a binding success for our
  transaction id and returns its MAPPED-ADDRESS or XOR-MAPPED-ADDRESS (IPv4
  or IPv6), refusing anything malformed rather than reading past it.
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
  observation fails; the lab's STUN fault suite reads those lines.
- Selection order is the order the candidates go on the wire in an offer.
