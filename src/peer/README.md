# src/peer

What the node holds about each peer: the entry for a handshake in flight,
before the peer's identity is verified, and the active peer, after the
Noise handshake authenticates it. The module is `crate::peer`, declared
`pub` in `../lib.rs`; the node (`../node/`) builds, holds and changes each
peer through the settlement core and its executor (`../node/settle/`), and
nothing here decides a handshake, a restart, a crossing or a removal.

## Files

- `mod.rs`: the module doc and declarations, and the types every level of
  the node names a peer's parts by: `PeerClock`, the host's monotonic
  clock a peer's rekey and path timers run on, with `PeerInstant`,
  `peer_now` and `since`; `LinkProfile`, `LinkRekey`, `LinkOutputs` and
  `LinkOutput`, a link's rekey machine and what it asks of the node;
  `PeerBundle` and `PeerPath`, a link's path machine and one of its paths;
  `LinkCaps` and `PathCaps`, what building a link's two machines borrows
  from the node and reads of its configuration and transports; and
  `unbound_caps`, the path machine of a peer bound by its first frame
  rather than a promotion. Compile-time assertions hold the link profile's
  jitter, drain window and dampening to the deployed link shell's values.
  Under `cfg(test)` it gives a test's link machine parameters
  (`test_link_params`) and path machine (`test_caps`), and the `PathSet`
  and `Admission` aliases. It still carries an older inline `mod tests`
  block.
- `active.rs`: `ActivePeer`, an authenticated peer: its identity, its
  link's rekey machine and path machine, which only the settlement core's
  join (`fips_core::proto::settle::join`) builds, moves and closes, each
  change asked for from its one function (`with_session` to start,
  `rebuild` to move, `stop` to close), and the peer's record behind its
  accessors. The frame path seals, opens and steps the machines per frame
  here.
- `data.rs`: `PeerData`, the peer's record, everything held about an
  authenticated peer but its identity and its two machines, reachable only
  from `active.rs`. `settle` applies the transition table's cell
  (`../node/settle/table.rs`) to each of its rows, and `depart` ends it at
  a removal, handing over what the removal reads.
- `handshake.rs`: `Handshake`, the node's entry for one handshake in
  flight beside the settlement core's leg: the Noise handshake and the
  session it completes, the pair, indices, epoch and wall stamps the
  promotion and the control API read, the stored msg1 and msg2, the dial's
  origin, and whether it failed past recovery. The core holds the leg
  itself (msg1, resends, deadline and lease).
- `udp_slot.rs`: `UdpSlot`, the driver slot each of a peer's paths
  carries: the path's connected UDP socket and its drain on Linux and
  macOS, nothing on other targets.
- `tests/`: the unit tests of the files here, each a child module of its
  source file; its own README names each file.

## Rules for this level

- A peer's rekey and path machines are built, moved and closed only
  through the settlement core's join, asked for only from `active.rs`'s
  three functions, which the node reaches only from its executor
  (`with_session`, `adopt_dial` and `stop`) but for a crossing's move at
  its site. `../node/settle/tests/scans.rs` holds the
  code to it, with its exemptions and their reasons.
- The rekey machine's parameters are the core's, with the node's
  configuration mapped onto them in `../node/handlers/rekey.rs`
  (`link_params`); this level holds no copy of them but the compile-time
  assertions in `mod.rs`, which the decision-input scan of
  `../node/settle/tests/scans.rs` lists.
- `data.rs` denies wildcard arms, and `settle` and `depart` destructure the
  record with no rest pattern, so a new field takes a side in each; its
  tests scan for both.
- New unit tests go in `tests/`, not in a source file.
- Keep the file list in step with the directory.
