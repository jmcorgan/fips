# One peer, several paths: switchover without a second handshake

> **Status: implemented on `feat/multi-path-switchover`; not calibrated.
> Refs [#143](https://github.com/jmcorgan/fips/issues/143).**
>
> Written from a code read of `feat/dynamic-interface-binding` at `21faff52`
> (`0.6.0-dev`). Decisions are recorded as decisions, with the alternatives
> that lost and why. Where the code as landed differs from the design text
> below, the code is the reference and the difference is listed here.
>
> **Landing.** The branch is two series. The first carries no wire change
> and can land on `master`: index-only demux, the `PeerPath` refactor,
> the `quality_index` refactor, and UDP `interface:` binding. The second
> puts three inner link-message types on the wire (`0x52`–`0x54`, see
> "Wire and config changes") and by the branch rules lands on `next`, with
> the types allocated in the v2 link-control registry. The commits are
> stacked in that order; the choice of landing branch for the second
> series is the maintainer's.
>
> **Deviations from the text below, all deliberate:**
>
> - **`MmpPeerState` stays per peer** (§2 said per path). §7's own review
>   decision keeps the receiver report per peer and counts per-path loss
>   from the probe/heartbeat ack ratio instead, so nothing per path needs
>   the report machinery. `PeerPath` carries its own min-RTT window, ETX
>   (long EWMA of ack outcomes), liveness marks and probe state.
> - **Carrier is polled, not watched.** Presence deliberately tracks
>   `IFF_UP` only; rather than plumbing a `CarrierLost` edge through the
>   binder, the fast path tick (`active_heartbeat_ms`) reads
>   `interface_presence().carrier` per interface-bound transport and marks
>   paths `Suspect` on the falling edge. Same latency bound, no new watcher.
> - **Unreachable-on-send** is classified (`TransportError::is_unreachable`,
>   `ENETUNREACH`/`EHOSTUNREACH`) but only the inline send path sees
>   errors; the UDP encrypt-worker path sends off-task and reports none.
> - **The bare `0x51` heartbeat is still sent** on the active path at the
>   slow interval for old nodes, alongside the per-path probes.
> - **Selection runs from the fast tick only**, right after heartbeats, so
>   a `Suspect` mark is acted on inside the same tick.
> - **A `Backup` path carrying traffic yields to a selectable `Normal` one
>   outright** (no margin, no dwell), since its role says it should not be
>   carrying traffic at all; §8 left this implicit.
> - **Dead-path history** expires after a fixed 5 min grace
>   (`DEAD_PATH_GRACE_MS`), pruned on the heartbeat sweep. A transport
>   returning inside the grace revives its `Dead` paths as `Probing`,
>   history kept, on the presence edge.
> - **Path MTU on path add** is not stored on the path; the switch re-seeds
>   from `transport.link_mtu(addr)` live, which is the same value.
> - **Link record on switch:** the peer's `Link` and `addr_to_link` entry are
>   re-pointed at the new path; the control machine keyed on the link is
>   untouched. The msg1 established-peer predicates match any path.
> - **A handshake never creates path state.** A dial to, or a msg1 from, a
>   peer we already hold a session with is classified and resolved exactly
>   as before this work — rekey, duplicate, or cross-connection tie-break,
>   whichever transport it arrived on — and the transport becomes a path
>   only through the probe exchange. The dialled address is left as a
>   candidate for the heartbeat tick. See §4, "Handshakes and paths".
> - **A peer with one `Live` path is not path-heartbeated.** Selection has
>   nothing to move to, and the link heartbeat keeps liveness. Probes start
>   when a second path (a candidate included) exists.
> - **A standby the peer never acknowledges is given up** after
>   `MAX_DISCOVERY_PROBES` (8) unanswered probes: `Dead`, pruned after the
>   grace. Until it is acknowledged it also does not count as a transport
>   the peer is on for the decrypt-failure gate. The active path is never
>   given up: the handshake proved it, and an old node answers no probe.
> - **A dial's connection is kept for the candidate it leaves.** On TCP,
>   Tor or Nym the socket a second handshake opened is the path's socket:
>   the probe rides it, and `api_disconnect` closes every path's
>   connection, not the active one's alone.
>
> Probes and acks carry the sender's per-path id, and a `PathClose`
> (`0x54`, names the receiver's id) tells the peer a path is going, on a
> surviving path. The first probe on a standby and one a minute after on
> every path are padded to the link MTU (the "data-sized probes" option
> under "Untrusted standby media"; wireless is *not* backup by default).
> Heartbeat interval and echo timeout stretch with each path's own round
> trip, in place of a per-transport interval knob. Defaults lean
> responsive: `K` 1.3, `D` 2 s, `N` 2, 200 ms active, 1 s standby,
> timeout 2 × fast.
>
> Nothing in "Calibration" has been measured: those defaults are chosen,
> not derived. The "Open questions" below record, per question, what the
> code does today; each of those is a decision awaiting confirmation, not
> a settled one.
>
> This is the "hold both links" option of an earlier note on the dual-path
> link flap (two nodes, a cable and a wifi to the same peer, the cable
> flapping): the alternatives there were a configured transport prior and
> holding both links measured. This document is the second, worked out. A
> prior is not needed once both paths are measured, and the reasons a
> prior was attractive turned out to be reasons against it; see "Why not
> tiers". That note's warning about calibration stands: `parent_hysteresis`,
> `hold_down_secs` and `flap_dampening_secs` were each needed before the
> tree stopped oscillating, and their values do not transfer to path space.

**Component:** `peer.active` (the binding), `node.dataplane` (demux, send
path), `node.handlers.mmp` (liveness, reap), `node.lifecycle` (discovery
gate), `transport` (presence, carrier).

**Goal:** an FMP peer that is reachable over more than one transport keeps
one Noise session and moves its traffic between transports on failure or
degradation, with no handshake and with loss bounded to what was in flight
on the dead path. Not multipath: one direction of traffic is on one path at a
time. Both directions need not be on the same path.

**The motivating setup:** two nodes joined by BLE, a direct Ethernet cable
and a shared wifi AP (as raw Ethernet on `wlan0`, or as UDP over the AP's
IP network — both shapes must work). The cable should carry traffic while it
works. When it is unplugged, traffic should be on wifi within about a
second, and stay there until wifi degrades.

---

## What is already right

The Noise session, the send counter, the replay window and the session
indices all live in `ActivePeer`, keyed by `NodeAddr`
(`src/node/mod.rs:512`). None of them mention a transport. The cipher state
is path-agnostic today; only the *lookup* and the *binding* are path-bound.

- Address roaming is free: an authentic frame from a new address on the
  same transport re-pins the peer (`src/node/dataplane/encrypted.rs:380`).
- A local medium change (WLAN↔LAN) costs no re-peering
  (`src/node/handlers/netmon.rs`).
- Session indices are allocated from one global set
  (`src/utils/index.rs:80`), so an index is unique across transports even
  though nothing yet relies on that.

## What is not there yet

Things this design leans on that do **not** exist at `21faff52`, so they are
work, not renames:

- **No min RTT anywhere.** MMP holds SRTT and rttvar only
  (`src/proto/mmp/algorithms.rs:80`). `Link.base_rtt`
  (`src/transport/mod.rs:509`) is the config constant `node.base_rtt_ms`
  (100 ms), written once in `src/node/lifecycle/mod.rs:471`, never measured,
  and has no non-test reader. §8's RTT term is new machinery.
- **The heartbeat has no echo.** It is a bare type byte and the receiver is
  a no-op (`src/node/dataplane/dispatch.rs:57`). RTT today comes only from
  receiver-report timestamp echoes at 1–5 s intervals.
- **Spin-bit RTT is discarded** at every rx site
  (`src/node/dataplane/encrypted.rs:277,387`). §9 treats it as the peer
  RTT; nothing consumes it.
- **A link watcher already exists.** `LinkWatcher`
  (`src/transport/watcher.rs`) wraps netlink `RTNLGRP_LINK` on Linux and
  `PF_ROUTE` `RTM_IFINFO` on Darwin/FreeBSD and is used by the Ethernet
  binder and netmon. §7 reuses it rather than adding one.

## What binds a peer to one path

Four places, all mechanical:

| Where | What | Line |
| ----- | ---- | ---- |
| `PeerSendState` | one `transport_id`, one `current_addr`, one `link_id`, one `connected_udp`, one `MmpPeerState` | `src/peer/active.rs:89-145` |
| `peers_by_index` | keyed `(TransportId, u32)`, so a valid index on another transport is dropped | `src/node/mod.rs:622`, `src/node/dataplane/encrypted.rs:32-42` |
| decrypt worker | `cache_key = (TransportId, u32)` | `src/node/decrypt_worker.rs:97` |
| `reap_peers_on_transport` | a transport going absent tears the *peer* down | `src/node/handlers/mmp.rs:631` |

And one place that is policy rather than structure: a completed handshake on
a second path resolves by cross-connection tie-break, and the loser is
destroyed (`promote_connection`, `src/node/handlers/handshake.rs:1653`).
There is no merge.

---

## Design

### 1. A path is a transport instance

**Decision.** Path identity is `TransportId`. One transport instance holds
at most one path to a given peer. Addresses roam *inside* a path exactly as
they roam today; a new address on a known transport is a roam, never a new
path. A new transport is a new path, never a roam.

Ethernet and BLE transports are per interface, so there transport and path
coincide already. UDP binds the wildcard (`0.0.0.0:2121`) and so covers every
local interface with one `TransportId`; under this rule that is one path.
An operator who wants two UDP paths declares two UDP instances
(`TransportInstances::Named` exists, `src/config/transport.rs:195`), each
bound to an interface. That needs an `interface:` field on `UdpConfig`
(`SO_BINDTODEVICE` on Linux, `IP_BOUND_IF` on Darwin) and puts UDP under the
same presence machine as Ethernet — which is where it belongs anyway.

**Rejected: path = `(TransportId, remote_addr)`.** Every distinct remote
address would be a path. A NAT port rebind becomes a new path; a peer's LAN
and hairpinned public address become two "paths" through the same local
interface; and the rule that separates "the peer moved" from "the peer is
dual-homed" is a heuristic that is wrong under exactly the NAT churn
`netmon` was written for. Egress is also still the kernel's choice, so a
"cable path" is only cable while the routing table agrees.

**Rejected: path = `(TransportId, local_interface)`** via `IP_PKTINFO`. Models
the problem correctly but the send fast path (`sendmmsg`, GSO, connected
sockets) needs per-interface sockets anyway, so it is the first option with
more machinery.

### 2. The peer holds a path set

`PeerSendState.{transport_id, current_addr, link_id, connected_udp,
link_stats, mmp}` becomes:

```rust
paths:  SmallVec<[PeerPath; 3]>,
active: Option<PathIdx>,          // where *my* frames go

struct PeerPath {
    transport_id:  TransportId,
    addr:          TransportAddr,          // roams
    link_id:       LinkId,
    connected_udp: Option<Arc<ConnectedPeerSocket>>,
    mmp:           MmpPeerState,           // per path, both directions
    link_mtu:      u16,                    // transport.link_mtu(addr) at add
    hb_seq:        PathSeq,                // per-path heartbeat sequence, both directions (§7)
    rx:            RxLiveness,             // last authentic frame heard here
    tx:            TxLiveness,             // last echo proving they hear me here
    state:         Probing | Live | Suspect | Dead,
    role:          Normal | Backup,        // from transport config
    pinned:        bool,                   // operator override
}
```

Everything that is per session (Noise slots, K-bit, indices, rekey state)
stays where it is. The one real cost here is `MmpPeerState` per path:
per-path etx, RTT and heartbeats need it, and today it is per peer.

`link_cost()` (`src/peer/active.rs:755`) reads `paths[active].mmp`.

### 3. Demux by index alone

`peers_by_index: HashMap<u32, NodeAddr>`. Same for `pending_outbound` and
the decrypt-worker key. A frame carrying a known `receiver_idx` decrypts no
matter which transport delivered it. This is what makes a switch a no-op for
the receiver.

The roaming rule in `process_authentic_fmp_plaintext` changes shape: an
authentic, non-replayed frame from `(T, addr)` updates `addr` on the path
with `transport_id == T` if one exists, and marks that path `rx_live`. If no
path exists for `T`, the frame is delivered but **no path is created**. Only
the probe exchange below creates paths. This is tighter than today's
roaming, on purpose: an attacker cannot forge an authentic frame, but can
reflect a captured one from an address of their choosing, and the only harm
that allows today is one re-pin. It should not be allowed to allocate path
state either.

Two consequences of dropping the transport from the key. Both land **with
step 1**, because step 1 is what opens cross-transport delivery:

- `ActivePeer::set_current_addr` (`src/peer/active.rs:597`) re-pins
  `transport_id` as well as the address on any authentic frame. That is
  unreachable today only because the demux key drops cross-transport frames.
  With index-only demux it becomes live: an on-path relay that rewrites the
  source (a rogue AP, anyone on a shared L2) moves the peer's whole send side
  to another transport, undamped, with no probe. Step 1 freezes
  `transport_id` in `set_current_addr`; only the probe exchange (§4) may add
  a path or change which transport one is on.
- Decrypt-failure accounting charges the peer by index
  (`src/node/dataplane/encrypted.rs:539`, `DECRYPT_FAILURE_THRESHOLD = 20`)
  with no source attribution. Today an attacker must be on the session's own
  transport. With index-only demux, 20 garbage frames carrying a sniffed
  32-bit index from *any* bound transport (Internet UDP included) would tear
  down a cable or BLE peering. Rule: a decrypt failure on a transport that is
  not in the peer's path set is dropped and never counted. Index reuse is
  immediate with no quarantine (`src/utils/index.rs:123`), so a stale
  in-flight frame landing on a new owner fails AEAD and would otherwise count
  too; the same rule covers it.

### 4. Paths are added by a probe under the existing session

Three new inner link-message types next to `0x51 Heartbeat`
(`src/proto/link.rs`, dispatched in `src/node/dataplane/dispatch.rs`):

```
0x52 PathProbe  { probe_id: u32, remote_active: bool, path_id: u32 }
0x53 PathAck    { probe_id: u32, remote_active: bool, path_id: u32 }
0x54 PathClose  { path_id: u32, reason: u8 }
```

`path_id` is the sender's own random identifier for the path the message
travels on; each side learns the other's from its probes and acks, and a
`PathClose` names the path by the *receiver's* id. Layouts are under
"Wire and config changes".

Both are ordinary encrypted FMP frames under the current session, with the
usual 16-byte header and `their_index`. The prober sends `PathProbe` on the
candidate transport. The receiver, having decrypted it against the session
found by index, now has proof the peer is reachable on `(T, addr)`: it adds
the path in `Probing`, records `rx_live`, and replies `PathAck` **on that
same path**. The prober receives the ack, marks the path `tx_live` and
`Live`, and takes an RTT sample for it. One round trip, no handshake, no new
key material, no index allocation.

`remote_active` says "this path is where I currently send". It costs one bit
and is a free detection signal (see §7).

**Rejected: full Noise IK on the second path, then merge at promote.** Works,
and keeps the existing dial machinery, but it is a handshake per path add
and it allocates a second set of indices that then have to be reconciled
with the first. The user's constraint was no additional handshake; the probe
meets it and is smaller.

**Discovery gate.** The beacon gate at `src/node/lifecycle/mod.rs`
(`active_peer_link_is_live`) used to skip a live peer entirely. It
becomes: peer with a session, candidate transport not in the path set →
the address is a path candidate (`add_path_candidate`), `Probing`, and the
heartbeat tick probes it; a peer that holds a session is never dialled.
An address on a transport whose path is not eligible re-points that path
(the peer moved: an Aware data path that re-formed, a DHCP lease that
changed); one on a transport whose path is carrying acknowledged traffic
changes nothing. The cross-connection path in `promote_connection` stays
for the cases it still owns: a remote epoch change (restart), and a peer
that does not yet know us.

**Handshakes and paths.** A handshake never creates path state. The
inbound classifier (`establish_inbound`) does not read which transport a
msg1 arrived on: a msg1 from a peer we hold a session with is a rekey, a
duplicate, or a restart, on any transport, exactly as before this work.
An outbound completion to such a peer is the cross-connection tie-break,
as before; either way the dialled `(transport, address)` is left as a
candidate and the probe exchange proves it. Two reasons. Both ends must
resolve a handshake on the same information, and "is this a new
transport to a live peer" was a fact only one end could see — a rule
that read it split pairs onto different sessions under mutual dials and
against older nodes. And the IK handshake is one round trip: the
responder commits at msg1, which carries no freshness beyond the startup
epoch, so a captured msg1 replayed from any address would otherwise have
planted a path — probed full-size for the life of the peering, and
counting as a transport the peer is on for the decrypt-failure gate. The
probe is authenticated under the session and replay-checked; the
handshake is not, until msg3, which IK does not have.

**Probe backoff.** A probe to a node that does not implement `0x52` is never
acked and the path stays `Probing`. The gate must not re-probe every
discovery tick: exponential backoff per `(peer, transport)`, capped at the
standby heartbeat interval, reset when the transport's presence cycles.

**Path MTU on path add.** `Node::transport_mtu()` (`src/node/mod.rs:1551`)
takes the minimum of `Transport::mtu()` across bound transports; for BLE that
is the configured 2048, not the negotiated per-connection L2CAP MTU
(`src/transport/ble/pool.rs:59`). Today the per-link value reaches
`path_mtu_lookup` only through `seed_path_mtu_for_link_peer` at promote. A
probe-added path never promotes, so the `PathAck` handler records
`transport.link_mtu(addr)` on the `PeerPath` at creation; it is applied when
the path becomes active (§5).

### 5. The sender picks `paths[active]`

`send_encrypted_link_message_with_ce` (`src/node/mod.rs:3676-3700`) reads
`transport_id` and `remote_addr` from the active path instead of the peer.
A switch is an index change. The send counter continues; the session is not
touched. Frames still in flight on the old path arrive with lower counters
and land inside the 2048-entry replay window (`src/noise/replay.rs`) — **if**
the new path has not already moved the window past them. A discretionary
switch from a slow, deeply buffered path (BLE, or wifi under bufferbloat
holding 100–500 ms of queue) to a cable at 100k frames/s closes the window
in about 20 ms; everything still queued on the old path then arrives outside
it and is dropped silently in the decrypt worker
(`src/node/decrypt_worker.rs:433`, no counter). Loss per discretionary
switch is bounded by the old path's queue depth, not by "a handful".
Sessions see it as one loss burst and forwarders may mark ECN CE on it
(`src/node/dataplane/forwarding.rs:580`). Measure it (see "Calibration").

The encrypt-worker pool shards on `hash(dest_addr)`
(`src/node/encrypt_worker.rs:506`), so a switch briefly interleaves two
shards and can reorder across the boundary. Accepted: it is a handful of
packets, once per switch, and the replay window tolerates it.

**A switch is also an MTU change.** Three places size traffic from the
peer's transport and none of them re-run on their own:

- `seed_path_mtu_for_link_peer` (`src/node/handlers/lookup.rs:880`) runs
  only at promote. Its `relinked` branch (`:942`, "two links to one peer can
  be up at once") is exactly the hook: call it with the new active path on
  every `active` change. Without it, one cable→BLE excursion clamps the TCP
  MSS for every new flow to that peer at the BLE MTU and leaves it there
  after fail-back, because `path_mtu_lookup` never loosens otherwise.
- The per-session `PathMtuState` (`src/proto/mmp/path_mtu.rs`) tightens on
  the next send via `seed_source_mtu` (`src/node/handlers/session.rs:2576`)
  and loosens only after 3 consecutive notifications spanning ≥ 2 × the
  notification interval (≥ 10 s), so widening back takes 20–30 s at the
  narrow size. On an `active` change to a narrower path, walk
  `self.sessions` whose next hop is this peer and tighten `mmp.path_mtu` at
  once, so the TUN gate (`session.rs:3038`) answers with PTB instead of
  losing the first packet per flow at the transport (`session.rs:3049`,
  debug log, no PTB — forwarded traffic gets the `MtuExceeded` routing
  signal, `src/node/dataplane/forwarding.rs:157`; local origin does not).
- `refresh_tun_mss_ceiling` (`src/node/mod.rs:1522`) runs on presence
  edges; run it on `active` change too.

Multi-hop: a forwarder's `active` change moves the `path_mtu` annotation on
every transit datagram (`src/node/dataplane/forwarding.rs:200`), so all
sources routing through it narrow at once and widen back on the 20–30 s
rule. A forwarder oscillating at dwell `D = 5 s` keeps transit sessions at
the narrow MTU permanently, and sources' `path_mtu_lookup` for remote
destinations never loosens until the session is purged
(`node.session.idle_timeout_secs`, 90). `D` must be large relative to the
notification interval, and calibration needs a forwarder in the flapping
position, not only an endpoint.

### 6. Presence loss withdraws a path

The rx-loop presence arm (`src/node/dataplane/rx_loop.rs:413-422`) calls
`withdraw_path(transport_id)` instead of `reap_peers_on_transport`. For each
peer: drop the path; if it was active, run selection (§8); if it was the
last path, fall through to the existing full reap. The reap and everything
`remove_active_peer` does (`src/node/dataplane/dispatch.rs:104`) stay as the
zero-paths case.

`withdraw_path` does not go through `route_link_dead`
(`src/node/handlers/mmp.rs:684`): that raises `PeerEvent::LinkDeadSuspected`,
which the executor resolves to `InvalidateSendState` → `remove_active_peer`,
and `remove_active_peer` also deletes the peer's FSP session
(`src/node/dataplane/dispatch.rs:145`). While any path remains, the peer
machine sees nothing. Only the zero-paths case enters it.

A withdrawn path keeps its history. Presence flaps on a cable (dock sleep,
autoneg bounce) are the case the binder's `ChurnGuard`
(`src/transport/presence.rs:316`) exists for: after three short bindings it
stops announcing until one survives 10 s. If withdraw dropped the
`PeerPath`, each return would need a fresh probe plus `N` samples at the
standby heartbeat rate (≈ 30 s at defaults) before the path is eligible
again. Instead the path goes `Dead` with its RTT and etx history intact and
is re-probed on presence return; the history expires after a grace period
(minutes), after which it is a fresh path.

A rekey in flight when the active path changes costs one retry: msg1 is
pinned to the transport and address it was sent on
(`src/node/handlers/rekey.rs:318`) and msg2 returns on the arrival link.
Index-only demux covers the rest, except that K-bit promotion re-registers
the decrypt-worker session under `(transport_id, idx)`
(`src/node/dataplane/encrypted.rs:128`), which changes with step 1.

### 7. Detection is per path and per transport kind

The goal is near-instant for direct peers. That comes from using each
medium's own failure signal, not from a faster timer. A hard signal (carrier,
send error, failed ack) moves a path to `Suspect`; selection acts on
`Suspect` immediately because the standby is warm; a later confirmation
moves it to `Dead`. A soft signal (the last two rows) only triggers a probe.

| Kind | Signal | Latency | Traffic |
| ---- | ------ | ------- | ------- |
| Ethernet, direct cable | carrier. Unplug at either end drops carrier on **both** NICs. `has_carrier()` exists (`src/transport/ethernet/mod.rs:321`), reported never acted on; add a netlink `RTM_NEWLINK` operstate watcher on Linux, `PF_ROUTE` `RTM_IFINFO` on Darwin, publishing a `CarrierLost` edge alongside presence | 100 ms – 1 s | none |
| Ethernet via wifi AP | local: disassociation drops `wlan0` operstate, same watcher. Remote peer leaving the AP: invisible locally, needs the per-path heartbeat | local instant; remote ≈ 3 × active-path heartbeat | heartbeat |
| BLE | stack disconnect event (supervision timeout) → `CarrierLost` | 100 ms – 2 s | none |
| UDP | `ENETUNREACH` / `EHOSTUNREACH` / ICMP on send → `Suspect` at once. Extend the classification in `src/transport/mod.rs:270` beyond `is_transient`. Otherwise heartbeat | send-error instant; else heartbeat | heartbeat |
| any | `remote_active` flipped away from this path in a probe/ack/heartbeat: peer stopped sending here, so it may have stopped hearing me here too. **Probe now; not `Suspect`** (see below) | one frame | none |
| any | peer heard on a standby path but silent on the active one for 2 × the heartbeat interval *the peer uses on this path*. **Probe now; not `Suspect`** | ≈ 2 heartbeats | none |

**The last two rows are hints, not verdicts.** They trigger a probe on the
path, never a `Suspect`. Read as `Suspect` they would force both sides onto
one path and undo §9: a discretionary switch on A flips `remote_active`, B
reads it as `Suspect`, and §8's mandatory rule moves B with no margin.
Worse, under a one-way failure (A→B dead on the cable, B→A alive) A is on
wifi and B is correctly on the cable; A hears B fast on the cable and slowly
on wifi, the silence rule fires on A's active path every 500 ms, A moves to
the dead cable, the echo times out, A moves back. That loop has the period
of the echo timeout and loses data on every lap. Only a failed echo, a
carrier edge or a send error move a path to `Suspect`.

Heartbeats become per path and adaptive: fast on a path (200 ms by
default) if **either** side's active path is this one, slow (1 s)
otherwise — and none at all while a peer holds one `Live` path, since
there is nothing for a verdict to act on. The peer's `remote_active` bit says which, so
each side knows the rate to expect on each path and the silence rule is
measured against the rate the peer actually sends, not against my own.
Heartbeats gain an ack so they feed `tx_live` and per-path RTT. The existing
two-gate `heartbeat_due` rule (a failed send does not satisfy the interval,
`src/node/handlers/mmp.rs:50`) applies per path.

**The ack carries a per-path sequence number, and the receiver report stays
per peer.** The report's delivery ratio is `packets_delta / counter_span`
over the outer Noise counter (`src/proto/mmp/metrics.rs:244`), and the
counter is per session, not per path. On a standby path `counter_span`
covers every frame that went over the active path, so delivery ≈ 0 and etx
clamps to 100 (`src/proto/mmp/algorithms.rs:265`). Per-path loss is
therefore counted from gaps in the heartbeat sequence on that path
(`PeerPath.hb_seq`), and per-path RTT from the ack. The report keeps
feeding the per-peer numbers. After a switch the report's next interval
spans the gap and produces one etx spike; the post-switch cost hold (§10)
is held until that report and the one that replaces it have arrived, so
the spike does not reach the tree. `link_cost()` itself keeps reading the
per-report value it always has.

**Airtime.** Fifty peers at 200 ms plus acks is about 500 small frames per
second. On a shared wifi AP each small frame pays preamble, ACK and backoff,
so that is a real fraction of the medium; on BLE it is a large fraction of
the link. Only peers with more than one path pay it; the 200 ms cadence is
for an *idle* active path, and what it drops to while data is flowing is an
open item.

For the cable case the outcome is: unplug → carrier edge on both machines →
both switch inside a second → loss is whatever left the NIC between the
unplug and the edge. No handshake, no tree change, no route withdrawal.

### 8. Selection is measured, not configured

**Decision.** No tiers, no priorities, no per-transport cost. A path's score
is the existing quality index, computed per path from its own samples:

```
score = etx × (1 + min_rtt_ms / 100)
```

with **min** RTT over a window rather than `srtt`. `srtt` on the active path
inflates under load (wifi bufferbloat) while an idle standby looks pristine,
which is a ping-pong generator; min RTT is a property of the medium, not of
the load, and `Link.base_rtt` (`src/transport/mod.rs:497`) is already that
number. Loss enters through etx as before, but as the long EWMA
(`smoothed_etx()`, α = 1/32, `src/proto/mmp/limits.rs:13`), not the
per-report value `link_cost()` reads today (`src/peer/active.rs:755`). On
an idle path a report interval holds about two heartbeats; one lost gives
etx 2.0, over `K`, and `D = 5 s` is about one report. The raw value is a
flap generator on any lightly loaded link. The min-RTT window is time-based
and at least `N` × the standby heartbeat interval, otherwise a standby
never accumulates a min.

The media separate themselves:

| path | min RTT | etx | score |
| ---- | ------- | --- | ----- |
| direct cable | 0.2 ms | 1.00 | 1.00 |
| Ethernet over wifi AP | 3–8 ms | 1.05 | ≈ 1.10 |
| BLE | 30–100 ms | 1.10 | 1.5–2.2 |

Rule, mirroring `Stp::evaluate_parent` (`src/proto/stp/state.rs:367`),
which solved this shape once already:

- **Mandatory:** active path not `tx_live` (Suspect or Dead) → switch to the
  best eligible path now. No margin, no dwell.
- **Discretionary:** `active.score > best.score × K`, sustained for dwell
  `D` → switch. Defaults to calibrate, not to reason about: `K ≈ 1.5`,
  `D ≈ 5 s` (see "Calibration").
- **Eligible** = `Live`, `tx_live`, at least `N` RTT samples, and either
  `role == Normal` or no Normal path is eligible.
- **Ties keep the current path.** A pinned path wins while it is `tx_live`.
- **Mandatory with nothing eligible:** a `Live` path with fewer than `N`
  samples beats no path. Take the best by whatever samples exist, `Probing`
  last; fall through to the full reap only when no path is `Live`. At
  defaults a fresh standby needs ≈ 30 s of slow heartbeats to reach `N`, and
  a cable can die inside that window.

`K` is what encodes the fail-back policy. The cable returning while traffic
is on wifi is 1.10 vs 1.00: ratio 1.1, below `K`, stay. Wifi degrading to
`etx 1.5` crosses `K`, move. BLE against a returning wifi is 1.5–2.0, move —
which is right, BLE is bad enough to leave. "Fail back only when the current
path degrades" is not a separate rule; it is the margin.

An unmeasured path is ineligible rather than assumed good. The prior note's
worry — that the alternate is unmeasured until dialled, and dialling it
displaces the incumbent — dissolves here: the alternate is measured by
probes and heartbeats while the incumbent keeps carrying traffic.

#### Why not tiers

Tiers (an operator-ranked integer per transport, `cable 10 / wifi 20 /
BLE 90`) were the first draft and were dropped.

- A tier is a guess about the medium; a measurement is a fact about it. The
  guess is stale the day `eth0` becomes a bridge, a virtio NIC, or a dock
  that moved. The motivating case is two *Ethernet* transports that only RTT
  tells apart.
- Each node in a mesh would carry its own ranking. Disagreement between
  configs produces asymmetric paths for no physical reason. Measurement is
  the same physics on both sides.
- Measurement is not extra work: the per-path echo is required for `tx_live`
  regardless, and the formula exists. Tiers would be the extra work: a
  config field, kind defaults, validation, an advertised byte, docs.
- Failure modes differ in kind. Measured-wrong is a flap between near-equal
  paths, bounded by `K` and `D`, visible in logs, harmless to the session.
  Tier-wrong is traffic pinned to a bad path while the operator believes it
  is on the cable, silently.
- The reverse migration is the cheap one. A per-transport weight multiplier
  on top of the score is a small change if measurement ever proves
  insufficient. Starting from tiers and moving to measurement rewrites the
  selection logic.

Also rejected, and for the reason the prior note gave: inferring
wired-vs-wireless from the OS. That is a tier hidden in code.

#### What the operator gets instead

Two escape hatches, both booleans, both rare:

- `role: backup` on a transport. The path is never active while any
  non-backup path is eligible. This is the "drop BLE when something better
  is stable" case, and it is a statement about the transport's purpose, not
  a rank.
- `fipsctl path pin <peer> <transport>` / `unpin`. Runtime, per peer,
  overrides scoring until unpinned or the path dies.

Anything past that — weights, ranked lists — is tiers again and is not
designed now.

### 9. Preference is directional

Selection decides where *my* frames go. Where the peer's frames arrive is
the peer's decision. So every path has two liveness states, `rx_live`
(free, from any authentic frame) and `tx_live` (needs the echo), and
selection uses `tx_live` + score. Hearing the peer on a path is a hint, not
proof that my direction works.

**Decision: each side selects independently.** No negotiation. Convergence
comes from both sides measuring the same physics.

Consequences, all accepted:

- Asymmetric paths are possible and sometimes correct. A one-way failure
  (typical on a wifi AP) leaves A sending on wifi and B on cable, each on
  the path that actually works in its direction. A symmetric model would
  force one side onto a broken path.
- On half-duplex media the asymmetry is a gain: A→B on wifi and B→A on
  cable removes wifi contention. On full-duplex cable it is neither gain nor
  loss. Real throughput gain across two cables needs striping one direction
  over both, which is multipath; nothing here prevents it later (the counter
  is global, the window is wide) but nothing here does it.
- Spin-bit RTT measures A→X→B→Y→A, a mixed-path number. It stays as the
  *peer* RTT, which is honest for the traffic actually flowing. Per-path RTT
  comes only from same-path echoes.
- ETX is forward × reverse and under asymmetry measures real traffic. Right
  for routing, misleading as a path diagnostic; `fipsctl path show` reports
  per path per direction.
- `tx_live` needs the reverse direction for its ack. A reverse-only failure
  on a path (my frames arrive, theirs do not) marks it not `tx_live` on my
  side although my direction works, so the asymmetry above holds for
  forward-only failure; a reverse-only one abandons the path in both
  directions. Accepted: the alternative is an unacknowledged claim.

Rejected: negotiated symmetric selection (initiator decides, peer mirrors).
Needs a state machine, a race on simultaneous switch, and gives up the
half-duplex gain. The `remote_active` bit in probes gives most of the
observability for none of the protocol.

### 10. The tree follows the active path, with dampening

`link_cost()` reads the active path, so a switch changes the peer's cost
and can move the parent. Re-announce only when the cost change crosses
`parent_hysteresis` **and** a dwell since the last switch has expired; the
tree's existing `hold_down_secs` and `flap_dampening_secs` apply on top.
Short switches (cable flap, replug) must not ripple mesh-wide.

Numbers: cable→wifi is +10 % cost, under `parent_hysteresis` 0.2, so no
parent change; cable→BLE (1.5–2.2) crosses it. `link_cost()` also orders
the greedy next-hop choice (`src/node/mod.rs:3943`) with no dampening of its
own, so a switch reorders transit traffic at once; the tree dwell above does
not cover it. Read the dampened cost there too.

---

## Wire and config changes

Wire: three inner link-message types in the FMP link-control block
(`0x50`–`0x5F`, of which `0x50 Disconnect` and `0x51 Heartbeat` were
allocated). All are ordinary encrypted FMP frames under the session; no
header change, no handshake change, no index change.

```
0x52 PathProbe   [type:1][probe_id:4 LE][flags:1][path_id:4 LE][padding…]
0x53 PathAck     [type:1][probe_id:4 LE][flags:1][path_id:4 LE][padding…]
0x54 PathClose   [type:1][path_id:4 LE][reason:1]

flags   bit 0 = remote_active ("this path is where I send")
reason  0 unspecified, 1 interface gone, 2 carrier lost, 3 operator
```

`PathMessage::WIRE_SIZE` is 10 and `PathClose::WIRE_SIZE` is 6, type byte
included. A probe may be padded past its 10 bytes to the link MTU (the
first on a standby, and one a minute after on every path); the ack echoes
the probe's size; a decoder reads the fixed fields and ignores the tail.
The per-path heartbeat of §7 **is** a `PathProbe` whose `probe_id` is the
path's sequence number, and `PathAck` is its echo, so the sequenced ack
adds no further type; `0x51` stays as the bare per-peer heartbeat for old
nodes.

Old nodes drop an unknown inner type at `debug` after authenticating the
frame (`src/node/dataplane/dispatch.rs`), with no misbehaviour accounting,
so a probe sent to an old node is harmless and simply never acked: the
path stays `Probing`, never becomes eligible, and is given up after the
discovery budget. Compatible in bytes; the project rule that `master`
takes no wire change still applies and is why the second series lands on
`next`, where the three codes need allocating in the v2 link-control
registry from the layouts above.

Config (defaults shown; every key optional):

```yaml
transports:
  ethernet:
    cable: { interface: en12 }
    wifi:  { interface: en0 }
  udp:
    lan:   { interface: en0, bind_addr: "0.0.0.0:2121" }   # new: interface
  ble:
    role: backup                                            # new
node:
  path:
    switch_margin: 1.3          # K, finite and >= 1.0
    switch_dwell_secs: 2        # D
    min_samples: 2              # N
    active_heartbeat_ms: 200
    standby_heartbeat_ms: 1000
```

Control: `path_show` (a query), `path_pin` and `path_unpin` (mutating);
`fipsctl path show <peer>`, `fipsctl path pin|unpin <peer> <transport>`.

---

## Order of work

Each step leaves the tree green and shippable.

1. **Index-only demux.** Drop `TransportId` from `peers_by_index`,
   `pending_outbound`, the decrypt-worker key and the K-bit re-registration.
   Frames that used to drop on the wrong transport now decrypt, so this step
   also freezes `transport_id` in `set_current_addr` and adds the
   not-in-path-set rule for decrypt failures (§3). Not zero behaviour
   change: it is the step that opens cross-transport delivery, and those two
   rules are what keep it closed to a relay.
2. **`PeerPath` inside `ActivePeer`, single path.** Mechanical refactor of
   `PeerSendState`; `MmpPeerState` moves into the path. No behaviour change.
3. **PathProbe / PathAck + discovery gate.** Peers grow paths. Still no
   switching; `active` never changes.
4. **Presence → `withdraw_path`.** First real switchover, driven by the
   presence edge. Cable unplug now moves traffic without re-peering.
   Includes the MTU work from §5 (re-seed `path_mtu_lookup`, tighten
   sessions, refresh the MSS ceiling on `active` change) and the
   keep-history rule from §6. Without the MTU work the first switch breaks
   TCP.
5. **Selection**: score, mandatory/discretionary rule, `role: backup`, pin.
6. **Detection**: per-path adaptive heartbeats with sequenced ack, carrier
   edge from the existing `LinkWatcher`, send-error classification,
   `remote_active` and silence hints as probe triggers.
7. **Tree dampening, `fipsctl path`, UDP `interface:` binding.**

Steps 1–2, the `quality_index` refactor and UDP `interface:` binding
carry no wire change and are stacked first, for `master`. Steps 3–7 put
`0x52`–`0x54` on the wire and are stacked after them, for `next`.

---

## Calibration

`K`, `D`, `N` and the heartbeat intervals are not to be picked by
reasoning; the earlier note's warning stands (see the status block).
Two chaos scenarios exist to set them from a distribution rather than a
guess — `dual-path-flap` (raw Ethernet veth as the cable, the Docker
bridge over UDP as the wifi) and `dual-udp-flap` (two interface-bound UDP
instances) — each flapping one path under iperf for three minutes. Both
carry the detectors that can fail on a switchover that did not carry:
`max_promotions` (a second "Peer promoted to active" on a node is a
re-peering), `switch_latency` (link down to first switch, ceiling 1 s)
and `max_stall` (no iperf interval run at zero bytes past 2 s), alongside
the `path_switches` band. Neither has yet been run in anger; the defaults
above are chosen, not derived.

Things to measure before trusting the design:

- switch latency from carrier edge to first frame on the new path, both
  ends, direct cable;
- packets lost per switch versus packets in flight;
- number of discretionary switches per hour on a healthy dual-path pair
  (should be zero);
- behaviour with `K` one step too small (flap) and one step too large
  (stuck on degraded wifi), so the failure on each side is known;
- packets lost per discretionary switch from a slow path to a fast one,
  against the old path's queue depth (replay window, §5);
- MTU widening time after fail-back, with the switching node as endpoint and
  as forwarder (§5);
- behaviour under a one-way failure on the AP, forward-only and
  reverse-only, which the §7 hint rules must survive without a loop.

---

## Open questions

Each of these changes what gets built. None is settled by the code read;
they need a decision from the operator side of the design. Where the
code had to take an option to exist at all, the option it takes is named
under **Code today** — that is a default awaiting confirmation, not a
decision.

### Path identity when the peer is multi-homed on one local transport

§1 keys a path by `TransportId` and lets the address roam inside it.
That models a multi-homed *sender* (two of our transports, two paths)
but not a multi-homed *peer seen through one of our transports*: two of
our dongles wired into one router whose fips has one bridged Ethernet
transport, or a router with a wifi MAC and a wired MAC behind our one
bridge interface. The receiver there holds one path, `note_path_probe`
re-points its address to whichever of the peer's sources probed last,
`remote_active` flips true/false several times a second (the active
path's probes say true, a standby's say false) and every false edge fires
an immediate probe; the peer's data and acks go to the last-heard
address, the other side's active path hears silence, goes `Suspect`, and
switches. Seen on a bridged home router: six mandatory switches in
sixteen minutes on a healthy LAN. Any bridged router is this case.

Prior art keys neighbours by `(local attachment, remote attachment)` and
lets the *sender* say whether it is roaming or adding (QUIC multipath Path
ID, MPTCP address ID, Babel and batman-adv `(interface, MAC)`). The
sender's `path_id`, already in every probe and ack, is that
discriminator: keying the receiver's paths by `(local TransportId, peer
path_id)` and treating the address as a roaming attribute gives one
record per peer path, keeps today's single-path NAT/DHCP roaming as the
rule for a transport holding one path, changes no bytes, and needs a
per-peer cap because ids are peer-chosen. Per-transport-kind identity
(link-layer by address, overlay by transport) was considered and
rejected: it misclassifies interface-bound UDP on a LAN and Wi-Fi Aware.
Not built; needs a decision.

**Code today:** `TransportId` identity, as §1.

### Fail-back policy versus capacity

§8 as written keeps traffic on wifi after the cable returns. The scores are
1.00 for the cable and about 1.10 for wifi, a ratio under `K = 1.5`, so the
discretionary rule never fires and the doc's own worked example calls that
correct. The motivating setup says two things that conflict after a replug:
"the cable should carry traffic while it works" and "stay there until wifi
degrades". The score cannot see the difference because it has no capacity
term. Wifi under load hides loss behind MAC-layer retries until the link
saturates, so etx stays near 1; and min RTT ignores queueing by design (that
is what stops the ping-pong that `srtt` would cause). A gigabit cable and a
50 Mbit/s wifi hop are therefore indistinguishable until the wifi actually
drops frames, and traffic sits at wifi rate for as long as wifi is merely
adequate. Three ways out, in rising order of machinery: accept it and
document the path as sticky, with `fipsctl path pin` as the manual
fail-back; add a load-aware term to the score, from a signal the node
already has (the kernel drop counter behind `SO_RXQ_OVFL`, or the goodput
EWMA at `src/proto/mmp/metrics.rs:278` against offered load, both of which
see saturation before etx does); or add a third boolean, `role: preferred`,
which makes a path win at equal-or-better score and is the smallest possible
tier. The last is honest about being a tier and "Why not tiers" argues
against it; the middle one needs calibration of its own.

**Code today:** sticky via `K` (1.3); `fipsctl path pin` is the manual fail-back. No capacity term.

### Path policy: which transports may carry which peers

The discovery gate in §4 probes every transport a live peer beacons on, so
the path set grows to the union of the media both nodes happen to share. On
a LAN that is the intended cable-plus-wifi set. On a node that also binds an
Internet-facing UDP instance, a Tor or a Nym transport, the same rule probes
the LAN peer over those too, and once the path is `Live` and measured, `K`
can move LAN traffic across it: a cable at 1.00 against a Tor circuit at 2.0
stays put, but a degraded wifi at 1.6 against a clean Internet UDP path at
1.3 switches. The traffic stays encrypted; what leaks is that the two nodes
talk, their addresses, and timing, to the ISP or the circuit. `role: backup`
does not express this: it is per transport, and "backup" still means
"usable". The question is whether path-add needs an allow rule, and what
its default is. Candidates: a per-transport `paths: never | backup | normal`
that subsumes `role`; a per-peer list in the static-peer config; or a
default that probes only transports with the same `auto_connect` posture
as the one the peer was first reached on. The first is the least new
concept.

**Code today:** every datagram transport a live peer is reachable on is probed; `role: backup` is the only restriction.

### Untrusted standby media

In the motivating setup the wifi AP is a third party, and once wifi is a
standby path the AP is in a position it did not have before. It can forward
heartbeats and acks faithfully, so the path measures well, then blackhole
data the moment the cable dies and the path goes active; the peer sees a
failed ack, marks the path `Suspect`, and has nowhere to go. That is no
worse than today's single-path wifi, but it is now reachable from a cable
setup that the operator believed did not depend on the AP. The AP can also
rewrite the source address on relayed frames, which the roaming rule turns
into a re-pin of the wifi path's tx address to the AP itself, so B's frames
to A on wifi route through the attacker without any cryptographic event.
Mitigations to choose between: default `role: backup` for wireless
transports so they never carry traffic while any wired path is eligible
(a tier by another name, but a statement about trust rather than speed);
data-sized probes, so a path that forwards 5-byte probes and drops 1400-byte
frames is not `Live`; or accepting the exposure and documenting that a
standby path trusts its medium exactly as much as an active one does.

**Code today:** data-sized probes (the first on a standby, one a minute after on every path); wireless is not `backup` by default.

### Heartbeat cadence while data flows

§7 puts the active-path heartbeat at 200 ms so a dead path is noticed
within a second. Per peer, plus an ack each, that is 8 small frames a
second; fifty peers on one AP is 400. On wifi a small frame costs almost as
much airtime as a large one (preamble, ACK, backoff), so that is a real
share of the medium whether or not any data flows, and on BLE it is a large
share of the link. While data is flowing the heartbeat is redundant in one
direction: data frames already prove `rx_live` at the far end. What they
do not prove is `tx_live` at this end, which needs an ack, and the receiver
report the peer already sends every 1–5 s arrives on the *peer's* active
path, which may not be this one. Options: keep 200 ms and accept the
airtime; drop to the receiver-report interval while data flows and accept
that detection on a loaded path slows to 1–5 s (a carrier edge still gives
the sub-second case for the cable); or piggyback the per-path sequence and
ack on data frames, which touches the outer header the design wants to
leave alone.

**Code today:** 200 ms on a path either side sends on, 1 s on a standby, both stretched by the path's round trip; nothing while a peer has one path.

### Soft signals: probe or Suspect

§7 now treats the two inference rows (`remote_active` flipped away; peer
heard on a standby but silent here) as probe triggers rather than `Suspect`.
That was a review decision, made because reading them as `Suspect` forces
both sides onto one path (undoing §9) and produces a standing loop under a
one-way failure. The cost of the decision is latency: a peer that really
did lose this path in the direction we cannot see is noticed only when the
probe's ack fails, one RTT plus the ack timeout later, instead of at once.
For the cable that is covered by carrier; for wifi and UDP it is the
difference between "one frame" and "one frame plus a probe round trip" in
the table. If sub-frame detection on those media matters more than the
asymmetric-selection property, the alternative is to keep them as `Suspect`
and drop §9's independence: negotiated selection, initiator decides, peer
mirrors. That is the design §9 rejected for its state machine and its
simultaneous-switch race. Confirm probe-not-`Suspect`, or reopen §9.

**Code today:** probe, not `Suspect`.

### Per-path echo: sequenced ack versus receiver report

The first draft left open whether the per-path echo is a heartbeat ack or a
per-path MMP receiver report. The code read closed it in favour of the ack:
the report's delivery ratio is computed from gaps in the outer Noise counter
(`src/proto/mmp/metrics.rs:244`), and that counter is per session, so a
report scoped to a standby path would count every active-path frame as
lost there. The ack with a per-path sequence (`PathProbe.probe_id`) is the
smallest thing that gives per-path loss. What it does not give is what the
report carries: one-way delay trend, jitter, burst-loss shape, ECN counts.
Those stay per peer. If per-path OWD or jitter is wanted later (for
example to prefer a path with lower jitter at equal etx and min RTT), the
choice is a wider ack, or a per-path counter in the outer header, which the
design has so far refused to touch. Confirm the sequenced ack, or say now
that per-path OWD/jitter is a requirement, because that changes the wire.

**Code today:** the sequenced ack; no per-path OWD or jitter.

### UDP `interface:` on Darwin

`IP_BOUND_IF` binds egress, but inbound on a wildcard socket still arrives
from any interface; per-instance bind needs a per-interface address or
`IP_RECVIF` filtering. Linux `SO_BINDTODEVICE` does both. Not a design
question, but it decides whether two UDP paths are supported on Darwin in
step 7 or documented as Linux-only.

**Code today:** egress-only on Darwin (`IP_BOUND_IF`); documented as such in `configuration.md`.
