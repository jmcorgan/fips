# One peer, several paths: switchover without a second handshake

> **Status.** This describes the node's multipath as it is built: the
> switchover feature of the FIPS multipath version 1 draft. It is off by
> default, and `node.path.enabled: true` turns it on. Aggregation, the
> draft's second feature, is not implemented.
>
> **Conformance.** The node claims the draft's **switchover** level:
> Sections 4, 5, 7 and 8 and Appendix A, with every `PathAck` field filled
> as Section 6.5 requires. The draft is the reference for what a peer can
> observe. This document explains why the design is what it is and records
> the choices the draft leaves to a node. The constants the draft marks
> "value proposed" are not calibrated, here or there.

**Component:** `core/src/proto/path` (the machine of one link's paths, its
wire format and its rules, with no I/O), `src/node/handlers/path.rs` and
its neighbours (the shell that feeds the machine and carries out what it
decides), `src/config` (`node.path.*` and each transport's `role` and
`kind`).

**Goal:** an FMP peer that can be reached over more than one transport
keeps one Noise session, and moves its traffic between paths on failure or
degradation, with no handshake and with loss bounded to what was in flight
on the path that went. This is not aggregation: one direction of a link's
traffic is on one path at a time. The two directions need not be on the
same path.

**The motivating setup:** two nodes joined by a direct Ethernet cable and a
shared Wi-Fi network, as raw Ethernet on `wlan0` or as UDP over the access
point's IP network. The cable should carry traffic while it works. When it
is unplugged, traffic should be on Wi-Fi within about a second, and stay
there until the cable has come back and proved itself.

## The model

A **bundle** carries one link. Everything FMP v1 defines per link stays per
link: the key epochs, the Noise session and its keys, the two session
indices, the counter space of each direction, the anti-replay window, and
rekey. A frame carries the same receiver index on every path, and the
sender's counter is one sequence across all paths.

A **path** is a local transport and a remote address. Identity is that
pair, not the transport, so a peer with one socket and a node with two
interfaces still give each side two distinct paths. A link holds at most
eight paths, at most four on one transport, and at most one on one BLE
binding. Each node keeps its own `path_id` for each path, a random non-zero
number stable for the path's life, and learns the peer's.

Two facts follow from demultiplexing by receiver index alone. A frame of
the link is accepted on any path, whichever the receiver is sending on, so
each end chooses its active path alone and a link may be asymmetric. And
the arrival transport and source address say which path a frame came on,
which is how per-path counters are kept without a field on the wire.

The machine is sans-I/O. `Bundle` takes one input at an instant (a path
message, a tick, a report, a carrier edge, an operator's pin) and returns
the outputs for the shell to execute. It reads no clock and allocates
nothing, so every rule below is tested in `fips-core` on a stepped clock.

## Learning that a peer is capable

Version 1 has no way to advertise an optional feature, and the FMP
handshake has no room for one. A node learns that a peer implements
multipath from its answer to a probe.

A node sends capability probes only while it holds a candidate for the peer
that its path policy allows, so a link with nowhere else to go sends none.
They go on the link's original path, at the smallest size, 27 bytes. The
first round is at most three probes spread over 30 seconds. After that the
gap starts at 30 seconds and doubles to a cap of 10 minutes, which comes to
twelve probes in a link's first hour and six in each hour after.

A node without multipath authenticates such a frame, counts it for
liveness as any frame of the link, and discards the message. So it sees a
few small messages it already ignores, and the pair behaves as two version
1 nodes: one path, the link-dead timeout, and a new handshake after a
failure. A node with multipath disabled does the same, and sends no path
message at all.

Any authenticated path message marks the peer capable. Until then nothing
but capability probes is sent, and every connection is kept, as FMP v1
does.

## Where paths come from

A **candidate** is an address a node might probe. It comes from the
configuration, the peer's Nostr advert, local discovery, an address the
peer was heard from, an operator's `connect`, or a dial to the peer that
timed out after the peer came up on another link. A candidate proves nothing
and changes no existing path. An address learned from an unauthenticated
source, such as an Ethernet beacon, stays a candidate until a probe
exchange proves it.

**A handshake never adds a path.** A dial to, or a msg1 from, a peer the
node already holds is resolved by FMP v1 as it would be without multipath.
When that resolution moves the link to another session, the bundle starts
again at the pair FMP v1 chose: the peer is no longer known to be capable
and the other paths go. A handshake that would establish a new link stays
bound to its transport, so a response on another transport is discarded
before any state changes. A rekey is not bound that way.

A node does not dial a capable peer whose link is live: it adds paths by
probing. A peer not known to be capable is dialled as it would be without
multipath.

## Proving a path

The prober sends a `PathProbe` on the candidate's transport to its address,
as an established frame of the link. The receiver authenticates it, checks
the anti-replay window, finds or creates the path it concerns, and answers
with a `PathAck` on the arrival transport to the address the probe came
from. The prober matches the answer on (`echo_path_id`, `probe_id`), on any
transport, and only a match teaches it the peer's `path_id`, samples a
round trip and makes the path Live.

A path created by a received probe stays Probing and carries nothing but
path messages until the receiver's own probe on it has been answered. The
proof is two-way on purpose: a probe an attacker redirects can create a
Probing entry at most, and that never carries data. Once a link has two
paths, a path's address moves only on its own authenticated probe or
matching ack, from a pair no other path holds.

Probes on a Probing or Dead path are padded to the link MTU, so a path that
carries small frames and drops large ones does not prove itself. Padding is
a local choice. Since each end's link MTU is its own, a padded probe that
goes unanswered is followed by the smallest size, and then the two
alternate, so a path to a peer with a smaller MTU still proves itself. An
ack is padded to the smaller of the probe and the answerer's own link MTU.

On a connection-oriented transport the node opens a connection to a
candidate before probing it. When a path goes, the node closes that
connection, except one the peer still sends frames of the link on.

## Liveness

Each node watches each path with its own probes. The peer's probes are
answered but do not decide this node's view.

- **Probing:** not proven, or back after Dead. Probed from 200 ms, doubling
  to the heartbeat interval, at most eight times.
- **Live:** answering. Probed every 200 ms if either end sends data on it,
  and every second otherwise.
- **Suspect:** three probes in a row unanswered. Probed at the same cadence.
- **Dead:** ten more unanswered, or given up. An acked path is probed from
  one second, doubling to 30 seconds. A path never acked is not probed.

A probe goes unanswered at the larger of 400 ms and three round trips. A
late answer gives a round-trip sample and nothing else: it does not revive
a path or end a backoff. The standby interval is fixed; it does not stretch
with a path's round trip. A link whose one path is Live is not probed,
because the FMP heartbeat already covers it and there is nowhere to move
to.

The other inputs are faster than timeouts where the node has them. On
interface-bound transports the node reads carrier for the links of more
than one path that use them. A loss makes each Live path on that transport
Suspect and tells the peer with a `PathClose` on another path, and a return
brings Dead paths back to Probing. An unreachable error on a send makes a
Live path Suspect. A link of one path ignores both and is left to the
heartbeat. A carrier reading is kept per link and transport, because the
rule it serves is about a link: a link that gains its second path after
another link saw the loss still sees it. A first reading of carrier is not
a return, so a pair held back on a link that took no reading of the loss
stays held until its source reports it again.

Authentication failures are counted per path, on the original path or an
acked one only, and an authentic frame on that path clears the count. Twenty
in a row make that path Dead if another path is Live or acked Suspect, and
otherwise log one warning and change nothing, so a stranger cannot take a
link's last path. A frame from any other pair counts against nothing, since
index-only demux means anyone who has seen an index can send one.

A Dead path that is not active is discarded after 600 seconds if it was
never acked or a path is Live. The link itself dies only when nothing
authenticated has arrived on any path for the link-dead timeout, or when
neither the original path nor an acked path remains.

## The active path

A node sends every link message on its active path, except path messages
and, as below, rekey messages. It may change that path at any time with no
handshake and no notice. The `ACTIVE` flag in its path messages tells the
peer which path it is on, and the peer then probes that path at the active
cadence.

**Failure is immediate.** When the active path becomes Suspect or Dead, or
is discarded, the node moves to a Live path if it has one, with no dwell.
If none is Live, it uses an acked Suspect path and probes it, and probes at
once every acked Dead path and acked Probing path, so a link that has lost
its good path finds whichever answers first. With nothing better the
Suspect or Dead active path stays active and the node keeps sending on it,
which is why a link does not go silent while a peer can still hear it.

**Choosing among Live paths** is local policy, and no peer can observe how
it is done. This node ranks them in order:

1. An operator's pin comes first: while a Live, acked path it names is
   held, only the paths it names are ranked.
2. Then the tier of the transport's `role`. A `backup` path ranks below a
   `normal` or `preferred` one, and a path held on a transport since set to
   `never` ranks below them all.
3. Within the top tier present, a path whose link MTU carries a
   `FilterAnnounce` is taken over one whose MTU does not, whatever their
   scores.
4. Among those, a `preferred` path is taken over a better-scoring one while
   its score is within the switch margin of the best.
5. Otherwise the best score, where a path is scored only once it has
   `node.path.min_samples` round trips.

A path's score is the quality index the spanning tree costs a link by: ETX
times one plus the least round trip over 100 ms, lower being better. A
discretionary move needs another path to beat the active one by the margin
(1.3) for the dwell (2 seconds), so two similar paths do not swap. Whole
millisecond round trips on a LAN put a cable and Wi-Fi inside that margin,
which is what `role: preferred` is for: without it the handshake race, not
the operator, decides which of the two carries traffic.

## The link's cost and the tree

Selection does not consult the spanning tree, and the tree does not follow
a path: it sees one link cost per peer. That cost is the quality index of
the link's own measurements, and for a link of one path it is exactly that.
When the active path changes, the measurements are about to shift to a
different medium, so the node holds the cost at its value from before the
change until the switch dwell has passed and two receiver reports have
arrived since. Without the hold one switch could reparent the tree. The
hold is this node's choice: the draft leaves a bundle's link cost to the
node.

MMP stays per link. One-way delay, jitter and spin are sampled only from
frames on the peer's active path, the path of its latest link message that
is neither a session datagram nor a path message, since a mix of two paths'
samples describes neither. Per-path quality comes from the probes instead:
each path has its own least round trip and its own ETX, where only a Live
path's timeouts count as losses.

## Rekey across a switch

Rekey is unchanged, but its messages go where the link is now. The
initiator sends each rekey message, each resend included, on its active
path as it stands when that message goes, so a msg1 is not pinned to the
transport it first went out on. The responder treats a rekey msg1 arriving
on the original path, or on a Live or acked path, as arriving on the
established link. A rekey is matched by its receiver index and not by the
pair, so a change of active path during a rekey does not abandon it, and
the rekey completes.

## One replay window, several paths

All paths of a link share the epoch's anti-replay window of 8192 counters.
That is a real limit. A frame on a slow path falls behind the window once
the fast path has carried 8192 frames past it, which at 1 Gbit/s of
full-size frames is about 90 ms of path skew. A standby is the slow path by
construction: under bulk load its probes can be refused as replays, it goes
Suspect, and it recovers once the load falls.

The width is set by the receiver's own queues. A link whose paths end on
different sockets of the receiver is reordered by them: under load the busy
socket's kernel queue fills to its buffer, and a probe arriving on an idle
socket is read ahead of all of it. A default UDP receive buffer holds about
4400 of the smallest frames on Linux, and the sender's encrypt queue for
another destination can add up to 1024 between the two, so the window is
wide enough for both. A node configured with a larger `recv_buf_size` can
queue more than the window covers, and then a probe on an idle path can
cause the loaded path's own queued frames to be refused.

The node handles this at two points. A link whose only remaining path is
such a starved standby switches to an acked Suspect path and probes it
rather than reaping the peer. And the receiver does not add skew of its own:
the receive loop gives the runtime thread back once per round of its
select, so a socket reader waiting behind a busy receive path falls behind
by about one channel's worth of frames and not by a whole scheduler budget.
Refused replays are counted per peer, on either receive path, in `show_peers`
as `replay_suppressed` since the last session reset and
`replay_suppressed_total` for the peer's life.

The yield frees spawned tasks, not the later arms of the receive loop's
biased select: while an early arm stays ready, the path tick and the other
arms after it wait for that arm to read empty. That has been shown only
with a constructed feeder that outruns the loop, not with a real sender.

## Path policy

All paths of a bundle run over transports of one anonymity class. A link
reached over Tor gains no path over a clear transport or over Nym, and the
other way round, whether the node would be probing or answering. The node
does not create a path from a probe on a transport where it would refuse
that peer's handshake, and it does not probe where it would not initiate
one.

Beyond that, each path has a **kind**, local or Internet. Ethernet, BLE and
serial are local; Tor and Nym are Internet. UDP and TCP take the kind of the
peer's address: loopback, link-local, RFC 1918 and ULA addresses are local,
and everything else is Internet, `100.64.0.0/10` included. By default a link
keeps to its original path's kind, which stops a LAN peering from quietly
moving onto the Internet. `node.path.mix_kinds` allows both in one link, and
a transport's `kind` overrides what the address implies: a VPN on RFC 1918
space needs `kind: internet`, or it reads as local.

## Watching it

`fipsctl path show <peer>` gives a link's whole state: whether multipath is
on, whether the peer is capable, the pin, the cost and whether it is held,
and each path's state, score, age and counters. `fipsctl show peers` lists
each peer's paths. A switch is logged at info as `Path switched`, with its
reason. Each change of a path's state (`Path state changed`) and each path
message (`Path message sent`, `Path message received`) is logged at debug by
the node's path handler.

## What it does not do

- It does not spread traffic across paths. That is aggregation, the draft's
  Section 6.
- It does not move a session between peers or across a restart. A restart
  is a new handshake, and the bundle starts again.
- It adds nothing a peer without multipath must understand, and nothing to
  the handshake. The three path messages are link message types `0x52` to
  `0x54`, carried inside the existing encrypted link.
- It adds no failure detection to a link of one path, which keeps FMP v1's
  heartbeat and link-dead timeout.

## See also

- [fips-mesh-layer.md](fips-mesh-layer.md): the link this runs on
- [fips-mmp.md](fips-mmp.md): what is measured per link
- [../reference/configuration.md](../reference/configuration.md):
  `node.path.*`, `role` and `kind`
- [../reference/cli-fipsctl.md](../reference/cli-fipsctl.md): `fipsctl path`
- [../reference/control-socket.md](../reference/control-socket.md): the
  control commands and `connect`
