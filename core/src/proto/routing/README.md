# core/src/proto/routing

Routing decisions: choosing the next hop toward a destination from the
spanning tree and the peers' bloom filters, the transit-forward decision
for a datagram passing through, and the error signals a node sends back
when it cannot forward. The root crate's forwarding code reads its
peers through the `RoutingView` trait it implements, and carries out
the outcome.

## Files

- `mod.rs`: declares the files and re-exports their public items.
- `core.rs`: the `RoutingView` trait, `NextHop` and `RouteOutcome`,
  `Router::route`, the transit decision (local or forward, TTL, path-MTU
  fold, ECN), and the candidate selection and route classification
  helpers.
- `state.rs`: `Router`, the routing state `Node` holds.
- `limits.rs`: the error-signal rate limiter.
- `wire.rs`: the error signals (`CoordsRequired`, `PathBroken`,
  `MtuExceeded`) and their message type registry. Only a session endpoint
  decodes a signal, so the decoders refuse one with bytes after its body,
  as FRC-2501 Section 5.1 requires. They ignore the reserved flags byte,
  as FRC-2201 Section 6.3 has a source do.
- `tests/`: the unit tests; its README describes it.

## Invariants

- **Error signals are rate-limited** per destination at transit nodes,
  and the limiter's map stays bounded however many destinations a sender
  names.
- **The signal formats are wire format** and do not change on the
  deployed lines.
