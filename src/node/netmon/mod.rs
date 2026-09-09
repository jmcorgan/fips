//! Transport-medium change detection.
//!
//! A node that moves between media (WLAN → LAN, WLAN → 5G, a BLE adapter
//! coming or going) would otherwise learn about it only as *silence*: the peer
//! sits in the table until `node.link_dead_timeout_secs` reaps it, and the
//! reconnect then waits out whatever backoff the old medium had already
//! accumulated. The host kernel knew within milliseconds; the node would find
//! out half a minute later.
//!
//! This module closes that gap. It samples a coarse [`NetFingerprint`] of the
//! host's network attachment and publishes a [`NetChange`] on the channel the
//! rx loop drains whenever the fingerprint moves. The node's reaction lives in
//! [`crate::node::handlers::netmon`].
//!
//! # Backends
//!
//! Detection is split in two, and the split is what keeps a per-OS backend
//! small. A backend's whole job is to answer *when is it worth sampling* — see
//! [`WakeSource`]. Everything else, and in particular the decision about
//! whether a medium change actually happened, is the shared fingerprint
//! comparison below, so no backend parses kernel messages or owns its own
//! definition of a medium change.
//!
//! | Platform | Backend | Latency |
//! |---|---|---|
//! | Linux, Android | `NETLINK_ROUTE` multicast | kernel event, ~ms |
//! | macOS, FreeBSD | `PF_ROUTE` socket | kernel event, ~ms |
//! | everything else | timer, `node.netmon.poll_interval_secs` | up to one period |
//!
//! Both kernel sources are [`crate::transport::watcher::LinkWatcher`], which
//! this module is currently the only consumer of. It is asked for
//! [`groups::EGRESS_PATH`](crate::transport::watcher::groups::EGRESS_PATH)
//! rather than the watcher's default link-presence mask: a route moving
//! between two interfaces that both stay up emits nothing in the link group, so
//! a presence subscription would never fire for the change this detector exists
//! to catch. `PF_ROUTE` has no group selection and delivers everything
//! regardless.
//!
//! Still to come, behind the same seam and without touching the handler:
//! `NotifyIpInterfaceChange` on Windows, and an embedder push on iOS. Android
//! takes the netlink source above, which is the right backend when the policy
//! allows the group bind and degrades to the timer when it does not; a
//! `ConnectivityManager` push belongs there too, because a timer is not
//! reliable under Doze. Every platform runs the
//! timer regardless — as the only signal where there is no backend, and as a
//! backstop where there is one, since a kernel event stream can drop messages
//! or stop.
//!
//! # What the fingerprint captures
//!
//! One local source address per peer: for every peer whose transport address is
//! a numeric IP endpoint, the address the kernel would pick to reach *that
//! peer*. A connected-but-never-sending UDP socket makes the kernel run its
//! route lookup and bind the source address it would use; five syscalls, read
//! off [`NetFingerprint::sample`] rather than measured, no packets, no name
//! resolution, and it works identically on every platform std supports.
//!
//! Keying on peers bounds the *reaction* — only the peers a change names are
//! acted on — and does not bound the *sampling*. One roaming peer still makes
//! the detector re-probe every target, up to [`MAX_DEBOUNCE_ROUNDS`] extra
//! times per wake, and the only limit on how often that can start is
//! `node.netmon.poll_interval_secs`.
//!
//! That set is exactly the quantity the reaction cares about. The stale
//! `connect(2)` this whole subsystem exists to repair pinned a *local source
//! address chosen for one destination*, so measuring the same thing for the
//! same destinations asks the kernel the question the bug is about, rather
//! than a proxy for it.
//!
//! Two consequences fall out of aiming the probe at peers rather than at the
//! host:
//!
//! - **Interfaces the node does not peer over cannot move it.** A container
//!   bridge, a VPN coming up, a `veth` pair, a tunnel — none of them is the
//!   route to any peer, so none of them enters the fingerprint. This is by
//!   construction rather than by a filter that has to keep guessing which
//!   interface names are infrastructure, which is what the host-wide address
//!   set this replaced could never get right: on a host running containers it
//!   moved, and the node dropped every connected socket and heartbeated every
//!   peer, for a `docker compose up`.
//! - **On-link peers are visible.** A peer on the same LAN is reached by its
//!   subnet route, not the default route, so a host-wide probe at an off-link
//!   destination looked straight past it: unplug the LAN cable on a host whose
//!   default route is cellular and nothing host-wide moved while every socket
//!   to that peer was stranded. Its own probe follows its own route and moves.
//!
//! It is also the right granularity for a *more specific* route changing under
//! one peer while the rest of the host is untouched, which no single host-wide
//! sample can represent at all.
//!
//! # What it deliberately does not capture
//!
//! **A peer whose address is not a probeable IP destination** contributes
//! nothing — an Ethernet or BLE peer addressed by MAC, a `.onion` or a Nym
//! recipient reached through a local proxy, an IPv6 literal carrying a scope
//! suffix. None of them is IP-attached in the way this detector reasons about,
//! and the connected-UDP pinning it repairs cannot happen to them.
//!
//! **A peer still carrying the hostname it was configured with**, because
//! resolving one on the sample path would put a DNS lookup, with its timeouts,
//! inside the detector's tick. In practice the window is small: the address is
//! replaced by the observed numeric source the first time an authenticated
//! packet arrives (`dataplane::encrypted`), and a peer that has never been
//! heard from has no established peering to strand.
//!
//! **A node with no peers** has an empty fingerprint and detects nothing, which
//! is correct — there is nothing bound to the old path to repair.
//!
//! **A BLE adapter's state** is invisible here, as it was before: it is not an
//! IP attachment at all. That signal comes from the radio (BlueZ properties,
//! the Android callback) and belongs on this same channel, pushed by the BLE
//! transport rather than sampled here.
//!
//! # Where the peer list comes from
//!
//! [`crate::control::snapshot::EntitySnapshot`], the node's existing lock-free
//! read side, republished from the tick. The detector is deliberately a
//! detached task holding no node state and taking no node lock, so it reads
//! the peer table the same way the off-loop `show_peers` renderer does. The
//! view is at most one `node.tick_interval_secs` stale, which does not matter:
//! a peer that has just appeared is absorbed on the next sample (see below),
//! and one that has just left is dropped from the comparison rather than
//! reported.
//!
//! # Comparing two samples
//!
//! Over the **intersection** of the two peer sets, never their union: a change
//! is reported when some peer present in both samples is now reached from a
//! different local address. Peers joining and leaving is ordinary node
//! behaviour and says nothing about the medium, so on its own it must not fire
//! a reaction that tears down a working send path. A peer whose probe stops
//! answering entirely — the route to it is gone — is a move to "no source
//! address" and does count, because that peer is exactly the one now stranded.
//!
//! A peer seen for the *first* time is the one case the intersection cannot
//! decide, and it cannot simply be skipped: the sample in which a peer first
//! appears may already be the post-change one, and adopting it silently would
//! swallow the event while that peer's socket stayed pinned to the path the
//! host has just left. Such a peer is judged against its own send path
//! instead — the source `connect(2)` pinned its socket to, which needs no
//! history and asks directly whether that socket is already stale. Churn still
//! fires nothing on its own, because a peer joining onto a path that has not
//! moved is pinned exactly where its traffic goes. See
//! [`NetFingerprint::moved`] for the residual this leaves.
//!
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use crate::transport::watcher::LinkWatcher;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

use crate::config::NetmonConfig;
use crate::control::snapshot::EntitySnapshot;
use crate::identity::NodeAddr;

/// How many resample rounds the debounce will ride out before reporting
/// anyway. A handover emits a burst (address gone, address added, route
/// replaced), and reporting mid-burst would act on a picture that is about to
/// change again; riding it out coalesces the burst into one event. Bounded so
/// an interface that flaps continuously still produces events rather than
/// starving the handler forever.
pub(crate) const MAX_DEBOUNCE_ROUNDS: u32 = 8;

/// Minimum spacing between two reported changes.
///
/// The reaction is not free: it drops the connected UDP socket of each peer
/// the change names (each carrying a drain thread) and sends that peer a
/// heartbeat. An interface flapping cleanly is the worst case for that, because
/// a medium change moves the whole table at once, so the set the reaction is
/// scoped to is every peer: settling between each transition, so the debounce
/// reports each one, could otherwise drive it several times a second across up
/// to `node.limits.max_peers` peers, which is thread churn rather than
/// recovery.
///
/// A genuine change is delayed by at most this long, against a
/// `link_dead_timeout_secs` measured in tens of seconds, so the trade is
/// heavily one-sided.
const MIN_CHANGE_INTERVAL: Duration = Duration::from_secs(1);

/// Receiver the rx loop drains.
pub(crate) type NetChangeRx = mpsc::Receiver<NetChange>;
/// Sender held by a detection backend.
pub(crate) type NetChangeTx = mpsc::Sender<NetChange>;

/// Where this host sits relative to the peers it holds: one local source
/// address per peer, as the routing table would choose it right now.
///
/// Each peer carries both the answer to that question and the source its
/// connected socket is already pinned to, because a peer seen for the first
/// time has no earlier sample to be compared against and is judged against its
/// own socket instead. [`NetFingerprint::moved`] is the whole definition of
/// "the medium changed" and the only thing the detector asks of a sample.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NetFingerprint {
    /// Peer → where its traffic leaves from. A peer with no probeable address
    /// never appears at all.
    sources: BTreeMap<NodeAddr, PeerPath>,
}

/// One peer's local end, from two directions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PeerPath {
    /// The local address the kernel would choose to reach this peer right now.
    /// `None` when the route lookup fails, which is a real value rather than a
    /// missing one: the peer is still ours, and having no route to it is
    /// precisely the state worth reacting to.
    current: Option<IpAddr>,
    /// The local address this peer's connected UDP socket is bound to, if it
    /// has one. Unlike `current` this is not a question put to the kernel — it
    /// is what the send path is already doing, and it is the only thing that
    /// gives a peer the detector has not seen before a baseline to be judged
    /// against. See [`NetFingerprint::moved`].
    bound: Option<IpAddr>,
}

impl NetFingerprint {
    /// Probe every target and record the local address the kernel picks.
    ///
    /// Five non-blocking syscalls per target: `socket(2)` and `bind(2)` behind
    /// `UdpSocket::bind`, a `connect(2)` that sends no packet, a
    /// `getsockname(2)`, and the `close(2)` the socket takes on drop. No I/O
    /// wait, no name resolution, and no allocation beyond the map.
    ///
    /// The count matters because a debounced handover resamples: up to
    /// `MAX_DEBOUNCE_ROUNDS` rounds plus the settled sample, times the peers
    /// held. `node.limits.max_peers` bounds that only where it is set —
    /// the value 0 means unlimited, and there the cost tracks the live peer
    /// count instead. It runs inline in the detector's own task rather than
    /// through `spawn_blocking`, which is what keeps it off every other task
    /// regardless.
    pub(in crate::node) fn sample(targets: &[ProbeTarget]) -> Self {
        Self {
            sources: targets
                .iter()
                .map(|t| {
                    (
                        t.peer,
                        PeerPath {
                            current: preferred_source(t.dest, t.bind),
                            bound: t.bound,
                        },
                    )
                })
                .collect(),
        }
    }

    /// Build a fingerprint directly, so a test can script a sequence of
    /// samples instead of probing real peers. No peer has a connected socket;
    /// [`Self::for_test_bound`] is the variant that gives one.
    #[cfg(test)]
    pub(crate) fn for_test(sources: &[(NodeAddr, Option<IpAddr>)]) -> Self {
        Self {
            sources: sources
                .iter()
                .map(|(peer, current)| {
                    (
                        *peer,
                        PeerPath {
                            current: *current,
                            bound: None,
                        },
                    )
                })
                .collect(),
        }
    }

    /// As [`Self::for_test`], with each peer's connected socket bound where the
    /// third element says.
    #[cfg(test)]
    pub(crate) fn for_test_bound(sources: &[(NodeAddr, Option<IpAddr>, Option<IpAddr>)]) -> Self {
        Self {
            sources: sources
                .iter()
                .map(|(peer, current, bound)| {
                    (
                        *peer,
                        PeerPath {
                            current: *current,
                            bound: *bound,
                        },
                    )
                })
                .collect(),
        }
    }

    /// Which peers are now leaving from somewhere other than where their
    /// traffic is actually going out.
    ///
    /// Two rules, because there are two ways to know:
    ///
    /// **A peer in both samples** is judged on whether its probe answer moved.
    /// The comparison is over the *intersection* of the two peer sets, never
    /// the union: a peer that has only just been authenticated, or one that has
    /// just been reaped, differs between the samples for reasons that have
    /// nothing to do with the host's attachment, and the reaction — drop the
    /// peer's connected socket and heartbeat it — is pure churn on a peer whose
    /// send path was never stale.
    ///
    /// **A peer only in the newer sample** has no previous probe answer to be
    /// compared against, and skipping it outright leaves a hole this detector
    /// cannot afford. `last` gains a peer only at the first wake *after* it
    /// appears, so a medium change in that window is the detector's first
    /// sight of that peer, and adopting it silently would swallow the very
    /// event being adopted — while the peer's connected socket stays pinned to
    /// the path the host has just left. The window is up to one
    /// `poll_interval_secs` after every peer that authenticates, and a medium
    /// change wakes the detector, so the two coincide readily rather than
    /// rarely.
    ///
    /// So such a peer is judged against `bound` instead: the address its
    /// connected socket is *actually* using. That needs no history — it asks
    /// whether the send path is already stale, which is the question the whole
    /// subsystem exists to answer, and it is exactly the peer that would
    /// otherwise be left stranded. Churn still cannot fire anything on its own:
    /// a peer joining onto a path that has not moved has `bound == current` and
    /// reports nothing.
    ///
    /// A first-seen peer with no `bound` is still skipped, and that is the
    /// residual. It covers three groups, and they are not equally harmless.
    ///
    /// Where there is genuinely no connected socket — every platform but Linux
    /// and macOS, and every peer on a stream or proxied transport on those two
    /// — nothing is pinned to repair, because the wildcard socket resolves a
    /// route per packet. Such a peer is not stranded; it loses only the
    /// immediate heartbeat that would have told the far side to re-pin, and
    /// notices at its next `heartbeat_interval_secs`.
    ///
    /// The third group is a real hole rather than a harmless one, and it is one
    /// tick wide. The tick publishes the entity snapshot before it installs
    /// connected sockets (`record_stats_history` then
    /// `activate_connected_udp_sessions`, in that order), so a socket installed
    /// on tick N is first visible to this detector in the snapshot published on
    /// tick N+1. A peer that joins and has its socket installed, and whose path
    /// then moves before that next publish, is first seen with `bound` still
    /// `None` and is skipped — and it *does* hold a pinned socket. The window
    /// in which it can be missed is about one `tick_interval_secs` per join,
    /// against a `poll_interval_secs` five times longer, but the *consequence*
    /// is not so short: the ordinary diff does not recover the peer. Once it is
    /// in both samples it is judged on its probe answer alone, and `bound` is
    /// consulted only on the first-sight arm, so the socket stays pinned where
    /// it was. While the reaction was node-wide such a peer was repaired as
    /// collateral the next time any other peer moved; scoping the reaction to
    /// the peers a change names removed that. What bounds it now is
    /// `node.link_dead_timeout_secs` reaping the peering.
    ///
    /// A non-wildcard `transports.udp.bind_addr` is not part of the residual;
    /// see [`ProbeTarget::bind`], which keeps both sides answering the same
    /// question rather than skipping the peer.
    ///
    /// An empty result means nothing moved; it is the detector's entire
    /// definition of "no change".
    pub(in crate::node) fn moved(&self, next: &Self) -> Vec<PeerSourceMove> {
        next.sources
            .iter()
            .filter_map(|(peer, now)| {
                let before = match self.sources.get(peer) {
                    // Seen before: its own previous probe answer.
                    Some(then) => then.current,
                    // First sight: what its socket is bound to, if it has one.
                    None => match now.bound {
                        Some(bound) => Some(bound),
                        None => return None,
                    },
                };
                (before != now.current).then_some(PeerSourceMove {
                    peer: *peer,
                    before,
                    after: now.current,
                })
            })
            .collect()
    }
}

/// One peer to probe: where to aim, and what its send path is already using.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node) struct ProbeTarget {
    /// The peer this is about.
    pub peer: NodeAddr,
    /// Its transport address — the destination the route lookup is run for.
    pub dest: SocketAddr,
    /// The local address its connected UDP socket is bound to, if it has one.
    pub bound: Option<IpAddr>,
    /// The address to bind the probe to, when the peer's transport binds a
    /// specific one rather than the wildcard. `None` means bind unspecified
    /// and let the kernel choose, which is the default posture.
    ///
    /// This exists so the probe asks the same question the send path answers.
    /// `open_connected_fd` binds the transport's configured address verbatim
    /// and only then connects, so under a non-wildcard `transports.udp.bind_addr`
    /// the socket's source is that address whatever the routing table says. An
    /// unconstrained probe would answer with the kernel's choice instead, and
    /// the two would disagree permanently — reporting a first-sight move, on
    /// every peer, forever, with nothing having moved.
    ///
    /// It does not preserve per-peer detection under such a bind, and should
    /// not be read as if it did. [`preferred_source`] returns the configured
    /// address for every destination, which is the same value the pinned socket
    /// already holds, so a route moving under one peer while that address stays
    /// configured on the host is invisible here. What is still reported is the
    /// bind address itself going away, which moves every peer at once. That is
    /// a trade rather than a loss: the send path is pinned to the configured
    /// address whatever the routing table says, so there is no per-peer pinning
    /// left to repair.
    pub bind: Option<IpAddr>,
}

/// One peer whose local source address changed between two samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PeerSourceMove {
    /// The peer that is now reached from somewhere else.
    pub peer: NodeAddr,
    /// The local address it was reached from, or `None` if there was no route.
    pub before: Option<IpAddr>,
    /// The local address it is reached from now, or `None` if the route is gone.
    pub after: Option<IpAddr>,
}

/// What moved between two fingerprints.
///
/// Operator-facing, and — unlike the host-wide summary this replaced — it now
/// names the peers affected, because the fingerprint is keyed on them. It is
/// also the reaction's whole input: the handler acts on exactly the peers in
/// [`Self::moved`] and touches no others.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NetChangeSummary {
    /// Every peer whose local source address changed, in `NodeAddr` order.
    pub moved: Vec<PeerSourceMove>,
    /// How many peers were probed in the newer of the two samples, so a log
    /// line shows what fraction of the table moved.
    pub probed: usize,
}

impl fmt::Display for NetChangeSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.moved.is_empty() {
            return write!(f, "no visible difference");
        }
        write!(f, "{}/{} peers: ", self.moved.len(), self.probed)?;
        // Bounded: an operator needs the shape of the change, and a full table
        // moving at once is the common case rather than the interesting one.
        const NAMED: usize = 3;
        for (i, m) in self.moved.iter().take(NAMED).enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            // Both ends: the address the stale `connect(2)` had pinned is what
            // an operator correlates against route history, so a line naming
            // only the destination leaves out the half being diagnosed.
            let before = match m.before {
                Some(ip) => ip.to_string(),
                None => "no route".to_string(),
            };
            let after = match m.after {
                Some(ip) => ip.to_string(),
                None => "no route".to_string(),
            };
            write!(f, "{} {} -> {}", m.peer.short_hex(), before, after)?;
        }
        if self.moved.len() > NAMED {
            write!(f, ", +{} more", self.moved.len() - NAMED)?;
        }
        Ok(())
    }
}

/// One settled transport-medium change, as delivered to the rx loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NetChange {
    /// Monotonically increasing across the life of one detector, starting at 1.
    /// Present so a log line can be tied to the handler's reaction, and so a
    /// coalesced delivery is visibly a coalesced delivery.
    pub generation: u64,
    /// What moved.
    pub summary: NetChangeSummary,
}

impl NetChange {
    /// A synthetic change naming no peers, for tests that assert the node does
    /// *nothing* — the reaction is scoped to the peers the summary names, so an
    /// empty summary must move nothing.
    #[cfg(test)]
    pub(crate) fn for_test(generation: u64) -> Self {
        Self {
            generation,
            summary: NetChangeSummary {
                moved: Vec::new(),
                probed: 0,
            },
        }
    }

    /// A synthetic change naming `peers` as having moved, for tests that
    /// exercise the node's *reaction* rather than its detection.
    ///
    /// The addresses are placeholders: the handler reads only which peers
    /// moved, not where from or to.
    #[cfg(test)]
    pub(crate) fn for_test_moved(generation: u64, peers: &[NodeAddr]) -> Self {
        let moved: Vec<PeerSourceMove> = peers
            .iter()
            .map(|peer| PeerSourceMove {
                peer: *peer,
                before: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
                after: Some(IpAddr::V4(Ipv4Addr::new(10, 40, 0, 7))),
            })
            .collect();
        Self {
            generation,
            summary: NetChangeSummary {
                probed: moved.len(),
                moved,
            },
        }
    }
}

/// What tells the detector it is worth taking another sample.
///
/// The split between *being woken* and *deciding whether anything changed* is
/// the reason a per-OS backend stays small: a backend only has to say "something
/// happened", and the fingerprint comparison, the debounce and the
/// settled-back-unchanged suppression are shared by all of them. No backend
/// parses kernel messages or decides what a medium change is.
struct WakeSource {
    /// What, besides the timer, can wake the detector.
    source: Wake,
    /// The timer. Without a backend it is the only signal, and its period is
    /// the detection latency. With one it is a backstop, and not a
    /// belt-and-braces backstop: a netlink socket drops messages under memory
    /// pressure (`ENOBUFS`), and the backend task can exit on a socket error,
    /// either of which would otherwise leave the node noticing nothing at all.
    /// Keeping the period the poller would have used makes an event-driven
    /// backend a strict latency improvement rather than a replacement that can
    /// regress, for the cost of a few syscalls per period.
    timer: tokio::time::Interval,
}

/// Where a wake-up can come from, besides the timer.
enum Wake {
    /// Nothing but the timer. The platform has no event source, or one could
    /// not be opened.
    Timer,
    /// Kernel link and route events, via the shared [`LinkWatcher`].
    ///
    /// The watcher parks forever when it has no source and after it gives up
    /// on a broken one, so selecting it against the timer degrades to the
    /// timer without any bookkeeping here.
    #[cfg(unix)]
    Kernel(LinkWatcher),
    /// An injected channel, so the tests can drive the detector on a paused
    /// clock without a live network or a real interface to flap.
    ///
    /// Single-slot upstream, so a burst coalesces into one wake-up rather
    /// than queueing a wake-up per message.
    #[cfg(test)]
    Injected(mpsc::Receiver<()>),
}

impl WakeSource {
    /// A wake source with no event-driven backend: the timer alone.
    fn timer_only(period: Duration) -> Self {
        Self {
            source: Wake::Timer,
            timer: Self::make_timer(period),
        }
    }

    /// A wake source driven by the kernel, with the timer as backstop.
    #[cfg(unix)]
    fn kernel(watcher: LinkWatcher, period: Duration) -> Self {
        Self {
            source: Wake::Kernel(watcher),
            timer: Self::make_timer(period),
        }
    }

    /// A wake source driven by an injected channel, with the timer as backstop.
    #[cfg(test)]
    fn events(pings: mpsc::Receiver<()>, period: Duration) -> Self {
        Self {
            source: Wake::Injected(pings),
            timer: Self::make_timer(period),
        }
    }

    /// `Delay` rather than the default `Burst`: a debounced handover can hold
    /// the loop for longer than one period, and catching up afterwards would
    /// fire several immediate wake-ups to sample a picture that just settled.
    ///
    /// `reset` drops the free first tick a fresh `Interval` hands out. Without
    /// it the detector's opening `wait` returns instantly and re-samples an
    /// attachment it read microseconds earlier — harmless, but it would also
    /// mean the very first wake-up on a netlink host came from the backstop
    /// rather than the backend.
    fn make_timer(period: Duration) -> tokio::time::Interval {
        let mut timer = tokio::time::interval(period);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        timer.reset();
        timer
    }

    /// The netlink groups this wake source is subscribed to, or `None` if it
    /// is not a live netlink source. For the group-mask assertion in the
    /// tests — see `the_detector_subscribes_to_the_route_groups_not_just_link`.
    #[cfg(all(test, any(target_os = "linux", target_os = "android")))]
    fn subscribed_groups(&self) -> Option<u32> {
        match &self.source {
            Wake::Kernel(watcher) => watcher.subscribed_groups(),
            _ => None,
        }
    }

    /// Wait until it is worth sampling again.
    async fn wait(&mut self) {
        let WakeSource { source, timer } = self;
        // Only the injected source can stop: [`LinkWatcher`] parks forever
        // once it gives up, so a kernel source that dies simply stops firing
        // and the timer carries on underneath it with nothing to unwind here.
        #[cfg(test)]
        let mut backend_gone = false;

        match source {
            Wake::Timer => {
                timer.tick().await;
            }
            #[cfg(unix)]
            Wake::Kernel(watcher) => {
                tokio::select! {
                    _ = watcher.changed() => {}
                    _ = timer.tick() => {}
                }
            }
            #[cfg(test)]
            Wake::Injected(pings) => {
                tokio::select! {
                    ping = pings.recv() => {
                        // A closed channel is the sender giving up. Sampling
                        // once more on the way past is deliberate: it may have
                        // died part-way through a change.
                        backend_gone = ping.is_none();
                    }
                    _ = timer.tick() => {}
                }
            }
        }

        #[cfg(test)]
        if backend_gone {
            warn!("Network-change backend stopped; falling back to polling");
            self.source = Wake::Timer;
        }
    }
}

/// Spawn the medium-change detector, using the best backend this platform has.
///
/// Returns the receiver the rx loop drains and the task handle the supervisor
/// aborts at teardown. The channel holds a single slot, and a full channel
/// drops rather than queues: the detector must never apply backpressure to
/// itself, and the node must never work through a backlog of network states
/// the host has already left.
///
/// Dropping is only safe because the dropped change is not the last word on
/// the peers it named. The handler acts on exactly those peers, so discarding
/// one would strand them if the detector had already adopted the sample it was
/// derived from. It has not: the baseline in [`run_detector`] advances only on
/// a successful send, so the next sample re-derives the move against the same
/// baseline and reports it again once the queue drains. Repairing a peer is
/// idempotent, which is what makes re-reporting cheap rather than a loop.
pub(crate) fn spawn_detector(
    cfg: NetmonConfig,
    peers: Arc<arc_swap::ArcSwap<EntitySnapshot>>,
) -> (NetChangeRx, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(1);
    let handle = tokio::spawn(async move {
        let wake = build_wake_source(&cfg);
        let sample = move || NetFingerprint::sample(&probe_targets(&peers.load()));
        run_detector(tx, cfg, sample, wake).await;
    });
    (rx, handle)
}

/// The peers worth probing, read off the node's published entity snapshot.
///
/// Every peer carrying a numeric IP endpoint, paired with it. The filter is
/// [`crate::control::snapshot::PeerRow::probe_target`] being `Some`, which is
/// already exactly "this peer is an IP destination we could `connect(2)` to":
/// a MAC, a `.onion`, a Nym recipient and an unresolved hostname all arrive
/// here as `None` and are skipped, with no per-transport special-casing in
/// this module.
pub(in crate::node) fn probe_targets(snapshot: &EntitySnapshot) -> Vec<ProbeTarget> {
    snapshot
        .peers
        .iter()
        .filter_map(|row| {
            row.probe_target.map(|dest| ProbeTarget {
                peer: row.node_addr,
                dest,
                bound: row.bound_source,
                bind: row.probe_bind,
            })
        })
        .collect()
}

/// Pick the wake source: the event-driven backend where one exists and starts,
/// the timer otherwise.
///
/// A backend that fails to start is a downgrade, not a failure — an unprivileged
/// container, a locked-down sandbox or a kernel without the socket all land
/// here, and the node keeps working with the detection latency the poller
/// gives. It is logged once at `warn` so a slow recovery is explicable.
///
/// Built inside the spawned task rather than by the caller because a backend
/// binds sockets and spawns tasks, which belongs on the runtime that will own
/// them.
fn build_wake_source(cfg: &NetmonConfig) -> WakeSource {
    let period = Duration::from_secs(cfg.poll_interval_secs.max(1));

    #[cfg(unix)]
    {
        // Where the backend is netlink the mask matters: the default route
        // moving between two interfaces that stay up emits nothing in the
        // link group, so a presence watcher would never fire for the change
        // this detector exists to catch. Under `PF_ROUTE` every routing
        // message is delivered regardless and the mask is ignored.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let watcher = LinkWatcher::with_groups(crate::transport::watcher::groups::EGRESS_PATH);
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let watcher = LinkWatcher::new();

        if watcher.is_event_driven() {
            debug!(
                backstop_secs = cfg.poll_interval_secs,
                "Network-change detection: kernel events"
            );
            return WakeSource::kernel(watcher, period);
        }

        warn!("Kernel medium-change events unavailable; falling back to polling");
    }

    debug!(
        poll_interval_secs = cfg.poll_interval_secs,
        "Network-change detection: polling"
    );
    WakeSource::timer_only(period)
}

/// The detection loop, over an injected sampler and wake source.
///
/// `sample` is [`NetFingerprint::sample`] in production; the tests drive the
/// debounce and coalescing against a scripted one, so neither needs a live
/// network nor a real interface to flap.
async fn run_detector<F>(tx: NetChangeTx, cfg: NetmonConfig, sample: F, mut wake: WakeSource)
where
    F: Fn() -> NetFingerprint,
{
    let debounce = Duration::from_millis(cfg.debounce_ms);

    let mut last = sample();
    let mut generation: u64 = 0;
    let mut last_emit: Option<tokio::time::Instant> = None;
    debug!(
        poll_interval_secs = cfg.poll_interval_secs,
        debounce_ms = cfg.debounce_ms,
        "Network-change detector started"
    );

    loop {
        wake.wait().await;

        let mut candidate = sample();
        if last.moved(&candidate).is_empty() {
            // Nothing the node is peering over moved. Adopt the sample anyway:
            // it is how a peer that has just joined enters the comparison, and
            // one that has left leaves it. Skipping this would freeze `last` on
            // the peer set the detector started with, and a peer authenticated
            // later would never be compared against anything.
            last = candidate;
            continue;
        }

        // The picture is moving. Ride out the burst: resample after the
        // debounce window until two consecutive samples agree, so the reported
        // change is against a settled state rather than a mid-handover one.
        // Settling is judged the same way — no peer moved since the previous
        // round — so peers joining or leaving mid-handover cannot extend the
        // debounce on their own either.
        for _ in 0..MAX_DEBOUNCE_ROUNDS {
            if debounce.is_zero() {
                break;
            }
            tokio::time::sleep(debounce).await;
            let resampled = sample();
            let settled = candidate.moved(&resampled).is_empty();
            candidate = resampled;
            if settled {
                break;
            }
        }

        // The burst may have settled back to where it started (a route that
        // flapped away and returned). Nothing moved, so nothing is reported —
        // but the sample is still adopted, for the reason above.
        let moved = last.moved(&candidate);
        if moved.is_empty() {
            trace!("Network fingerprint settled back unchanged; no event");
            last = candidate;
            continue;
        }

        // Space out reactions. Deliberately after the debounce and the
        // settled-back check, so a burst that resolves to no change costs
        // nothing here, and only a real report is paced.
        if let Some(previous) = last_emit {
            let since = previous.elapsed();
            if since < MIN_CHANGE_INTERVAL {
                tokio::time::sleep(MIN_CHANGE_INTERVAL - since).await;
            }
        }
        last_emit = Some(tokio::time::Instant::now());

        generation += 1;
        let change = NetChange {
            generation,
            summary: NetChangeSummary {
                moved,
                probed: candidate.sources.len(),
            },
        };
        match tx.try_send(change) {
            // The baseline advances only here. A dropped change is a peer set
            // nobody will act on, and the reaction is scoped to the peers a
            // change names, so adopting `candidate` regardless would leave
            // those peers unrepaired for good: the next diff would compare the
            // post-change sample against itself and report nothing. Holding
            // `last` where it was makes the next sample re-derive the move.
            Ok(()) => last = candidate,
            Err(mpsc::error::TrySendError::Full(dropped)) => {
                debug!(
                    generation = dropped.generation,
                    "Network change coalesced into the one already queued"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                debug!("Network-change receiver gone; poller exiting");
                return;
            }
        }
    }
}

/// The source address the kernel would use to reach `probe`, from `bind_to` if
/// the transport constrains it.
///
/// `connect(2)` on a UDP socket is a pure routing-table operation: it resolves
/// the route, binds a source address, and sends nothing. The socket is dropped
/// here and never written to, so a peer is probed without a single packet
/// reaching it.
///
/// A failure — most often `ENETUNREACH`, no route to that peer at all — is
/// itself a fingerprint value, reported as `None` rather than swallowed. It is
/// the state a stranded peer is in, so losing it would blind the detector to
/// the case it most needs to see.
fn preferred_source(probe: SocketAddr, bind_to: Option<IpAddr>) -> Option<IpAddr> {
    // Port 0 always: the probe wants the transport's *address* constraint, not
    // its port, and binding the live port would collide with the socket the
    // transport already holds there. A family mismatch between the configured
    // bind and this peer is not an error to report — the transport could not
    // have reached the peer from it either — so fall back to unspecified and
    // let the connect below fail on its own terms.
    let bind: SocketAddr = match (probe, bind_to) {
        (SocketAddr::V4(_), Some(ip @ IpAddr::V4(_))) => SocketAddr::new(ip, 0),
        (SocketAddr::V6(_), Some(ip @ IpAddr::V6(_))) => SocketAddr::new(ip, 0),
        (SocketAddr::V4(_), _) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        (SocketAddr::V6(_), _) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(probe).ok()?;
    let local = socket.local_addr().ok()?.ip();
    // An unspecified local address means the kernel deferred the choice, which
    // tells us nothing about the medium. Treat it as "no answer".
    if local.is_unspecified() {
        return None;
    }
    Some(local)
}

#[cfg(test)]
mod tests;
