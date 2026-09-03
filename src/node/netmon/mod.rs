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
//! | Linux | `NETLINK_ROUTE` multicast | kernel event, ~ms |
//! | macOS, FreeBSD | `PF_ROUTE` socket | kernel event, ~ms |
//! | everything else | timer, `node.netmon.poll_interval_secs` | up to one period |
//!
//! Both kernel sources are [`crate::transport::watcher::LinkWatcher`], shared
//! with the interface binder. It is asked for a wider set of netlink groups
//! here than the binder asks for: presence is a link question, but a default
//! route moving between two interfaces that both stay up emits nothing in the
//! link group, so a presence subscription would never fire for the change this
//! detector exists to catch. `PF_ROUTE` has no group selection and delivers
//! everything regardless.
//!
//! Still to come, behind the same seam and without touching the handler:
//! `NotifyIpInterfaceChange` on Windows, and an embedder push on Android and
//! iOS (where netlink is blocked by SELinux policy). Every platform runs the
//! timer regardless — as the only signal where there is no backend, and as a
//! backstop where there is one, since a kernel event stream can drop messages
//! or stop.
//!
//! # What the fingerprint captures
//!
//! Two independent signals, because neither alone is sufficient:
//!
//! - **The preferred source addresses.** A connected-but-never-sending UDP
//!   socket makes the kernel run its route lookup and pick the source address
//!   it *would* use to reach an off-link destination. That address changes
//!   exactly when the default route moves between media, which is the
//!   WLAN → 5G case. It costs two syscalls and no packets, and works
//!   identically on every platform std supports.
//! - **The set of up, non-loopback interface addresses**, on unix, where
//!   `getifaddrs(3)` is available through the `libc` dependency the crate
//!   already carries. This catches a medium arriving or leaving without
//!   displacing the default route — a LAN cable plugged in beside live WLAN,
//!   or the address a link-local Ethernet transport peers over.
//!
//! On platforms without `getifaddrs` (Windows) only the source-address probe
//! contributes, which still catches every default-route move. The native
//! backend is the answer there, not a richer sample.
//!
//! # What it deliberately does not capture
//!
//! A BLE adapter's state is invisible to both signals — it is not an IP
//! attachment at all. That signal comes from the radio (BlueZ properties, the
//! Android callback) and belongs on this same channel, pushed by the BLE
//! transport rather than sampled here.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

#[cfg(unix)]
use crate::transport::watcher::LinkWatcher;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

use crate::config::NetmonConfig;

/// Off-link IPv4 probe destination — RFC 5737 TEST-NET-1, which is guaranteed
/// not to be routed anywhere. Nothing is ever sent to it; `connect(2)` on a UDP
/// socket only resolves the route and binds a source address.
const PROBE_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9);

/// Off-link IPv6 probe destination — RFC 3849 documentation prefix. Same
/// no-packets-sent contract as [`PROBE_V4`].
const PROBE_V6: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
    9,
);

/// How many resample rounds the debounce will ride out before reporting
/// anyway. A handover emits a burst (address gone, address added, route
/// replaced), and reporting mid-burst would act on a picture that is about to
/// change again; riding it out coalesces the burst into one event. Bounded so
/// an interface that flaps continuously still produces events rather than
/// starving the handler forever.
const MAX_DEBOUNCE_ROUNDS: u32 = 8;

/// Minimum spacing between two reported changes.
///
/// The reaction is not free: it drops every peer's connected UDP socket (each
/// carrying a drain thread) and sends a heartbeat per peer. An interface that
/// flaps cleanly — settling between each transition, so the debounce reports
/// each one — could otherwise drive that several times a second across up to
/// `node.limits.max_peers` peers, which is thread churn rather than recovery.
///
/// A genuine change is delayed by at most this long, against a
/// `link_dead_timeout_secs` measured in tens of seconds, so the trade is
/// heavily one-sided.
const MIN_CHANGE_INTERVAL: Duration = Duration::from_secs(1);

/// Receiver the rx loop drains.
pub(crate) type NetChangeRx = mpsc::Receiver<NetChange>;
/// Sender held by a detection backend.
pub(crate) type NetChangeTx = mpsc::Sender<NetChange>;

/// A coarse fingerprint of how this host is attached to the network.
///
/// Equality is the whole point: the poller reports a change iff two
/// consecutive samples differ. The contents are only ever used for the
/// operator-facing description of what moved.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NetFingerprint {
    /// Source address the routing table would pick for an off-link IPv4
    /// destination. `None` when there is no IPv4 route at all — itself a
    /// meaningful state, and distinct from any address.
    v4_source: Option<IpAddr>,
    /// IPv6 counterpart of `v4_source`.
    v6_source: Option<IpAddr>,
    /// Every up, non-loopback unicast address on the host. Always empty on
    /// platforms with no `getifaddrs`, which makes the fingerprint degrade to
    /// the source-address probe rather than to nothing.
    local_addrs: BTreeSet<IpAddr>,
}

impl NetFingerprint {
    /// Sample the host's current attachment.
    ///
    /// Every call is a handful of non-blocking syscalls — a bind, a connect
    /// that sends no packet, a `getifaddrs` walk — with no I/O wait, no name
    /// resolution, and no allocation beyond the address set. It is called from
    /// a dedicated task on a multi-second timer, so it runs inline rather than
    /// through `spawn_blocking`.
    pub(crate) fn sample() -> Self {
        Self {
            v4_source: preferred_source(PROBE_V4),
            v6_source: preferred_source(PROBE_V6),
            local_addrs: interface_addrs(),
        }
    }

    /// Build a fingerprint directly, so a test can script a sequence of
    /// samples instead of reading the host's real attachment.
    #[cfg(test)]
    pub(crate) fn for_test(v4_source: Option<IpAddr>, local_addrs: &[IpAddr]) -> Self {
        Self {
            v4_source,
            v6_source: None,
            local_addrs: local_addrs.iter().copied().collect(),
        }
    }

    /// Describe the transition from `self` to `next` for the operator log.
    fn diff(&self, next: &Self) -> NetChangeSummary {
        NetChangeSummary {
            added: next
                .local_addrs
                .difference(&self.local_addrs)
                .copied()
                .collect(),
            removed: self
                .local_addrs
                .difference(&next.local_addrs)
                .copied()
                .collect(),
            v4_source_moved: self.v4_source != next.v4_source,
            v6_source_moved: self.v6_source != next.v6_source,
            v4_source: next.v4_source,
            v6_source: next.v6_source,
        }
    }
}

/// What moved between two fingerprints. Operator-facing only — the handler
/// re-evaluates everything regardless of which field changed, because it
/// cannot map an address back to the peers that were reaching over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NetChangeSummary {
    /// Local addresses present now but not before.
    pub added: Vec<IpAddr>,
    /// Local addresses present before but not now.
    pub removed: Vec<IpAddr>,
    /// The preferred IPv4 source address changed (a default-route move).
    pub v4_source_moved: bool,
    /// The preferred IPv6 source address changed.
    pub v6_source_moved: bool,
    /// The preferred IPv4 source address as of this sample.
    pub v4_source: Option<IpAddr>,
    /// The preferred IPv6 source address as of this sample.
    pub v6_source: Option<IpAddr>,
}

impl fmt::Display for NetChangeSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts: Vec<String> = Vec::new();
        if self.v4_source_moved {
            parts.push(match self.v4_source {
                Some(ip) => format!("v4 source -> {}", ip),
                None => "v4 source lost".to_string(),
            });
        }
        if self.v6_source_moved {
            parts.push(match self.v6_source {
                Some(ip) => format!("v6 source -> {}", ip),
                None => "v6 source lost".to_string(),
            });
        }
        if !self.added.is_empty() {
            parts.push(format!("+{} addr", self.added.len()));
        }
        if !self.removed.is_empty() {
            parts.push(format!("-{} addr", self.removed.len()));
        }
        if parts.is_empty() {
            return write!(f, "no visible difference");
        }
        write!(f, "{}", parts.join(", "))
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
    /// A synthetic change, for tests that exercise the node's *reaction* to a
    /// medium change rather than its detection. The summary is empty because
    /// the handler never reads it — it re-evaluates every peer regardless of
    /// which address moved, having no way to map an address back to the peers
    /// that were reaching over it.
    #[cfg(test)]
    pub(crate) fn for_test(generation: u64) -> Self {
        let empty = NetFingerprint::default();
        Self {
            generation,
            summary: empty.diff(&empty),
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
/// aborts at teardown. The channel holds a single slot: a change already queued
/// and not yet handled makes a newer one redundant, because the handler's
/// reaction is "re-evaluate every peer and every backoff", which subsumes any
/// number of coalesced changes. A full channel therefore drops rather than
/// queues, and never applies backpressure to the detector.
pub(crate) fn spawn_detector(cfg: NetmonConfig) -> (NetChangeRx, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(1);
    let handle = tokio::spawn(async move {
        let wake = build_wake_source(&cfg);
        run_detector(tx, cfg, NetFingerprint::sample, wake).await;
    });
    (rx, handle)
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
        // On Linux the mask matters: the default route moving between two
        // interfaces that stay up emits nothing in the link group, so a
        // presence watcher would never fire for the change this detector
        // exists to catch. Elsewhere `PF_ROUTE` delivers every routing
        // message regardless and the mask is ignored.
        #[cfg(target_os = "linux")]
        let watcher = LinkWatcher::with_groups(crate::transport::watcher::groups::EGRESS_PATH);
        #[cfg(not(target_os = "linux"))]
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
        if candidate == last {
            continue;
        }

        // The picture is moving. Ride out the burst: resample after the
        // debounce window until two consecutive samples agree, so the reported
        // change is against a settled state rather than a mid-handover one.
        for _ in 0..MAX_DEBOUNCE_ROUNDS {
            if debounce.is_zero() {
                break;
            }
            tokio::time::sleep(debounce).await;
            let resampled = sample();
            if resampled == candidate {
                break;
            }
            candidate = resampled;
        }

        // The burst may have settled back to where it started (an address that
        // flapped away and returned). Nothing changed, so nothing is reported.
        if candidate == last {
            trace!("Network fingerprint settled back unchanged; no event");
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
            summary: last.diff(&candidate),
        };
        last = candidate;

        match tx.try_send(change) {
            Ok(()) => {}
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

/// The source address the kernel would use to reach `probe`.
///
/// `connect(2)` on a UDP socket is a pure routing-table operation: it resolves
/// the route, binds a source address, and sends nothing. A failure — most often
/// `ENETUNREACH` with no route of that family — is itself a fingerprint value,
/// reported as `None` rather than swallowed.
fn preferred_source(probe: SocketAddr) -> Option<IpAddr> {
    let bind: SocketAddr = match probe {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
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

/// Every up, non-loopback unicast address on the host.
#[cfg(unix)]
fn interface_addrs() -> BTreeSet<IpAddr> {
    let mut out = BTreeSet::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();

    // SAFETY: `getifaddrs` either returns 0 and writes an owned linked list
    // into `head`, or returns non-zero and leaves `head` untouched — so the
    // list is only walked on success. Every node is read behind a null check,
    // and `freeifaddrs` releases the list exactly once, after the walk.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return out;
    }

    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: `cursor` is non-null here and points at a node of the list
        // `getifaddrs` allocated, which stays valid until `freeifaddrs` below.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;

        if entry.ifa_addr.is_null() {
            continue;
        }
        let flags = entry.ifa_flags as i32;
        let up = flags & libc::IFF_UP != 0 && flags & libc::IFF_RUNNING != 0;
        if !up || flags & libc::IFF_LOOPBACK != 0 {
            continue;
        }
        if let Some(ip) = sockaddr_ip(entry.ifa_addr) {
            out.insert(ip);
        }
    }

    // SAFETY: `head` is the list `getifaddrs` allocated above, freed once, and
    // not read after this point (`cursor` is null by loop exit).
    unsafe { libc::freeifaddrs(head) };
    out
}

/// No portable interface enumeration without `getifaddrs`. The fingerprint
/// degrades to the source-address probe, which still catches every
/// default-route move; the native `NotifyIpInterfaceChange` backend is the
/// answer here rather than a richer poll.
#[cfg(not(unix))]
fn interface_addrs() -> BTreeSet<IpAddr> {
    BTreeSet::new()
}

/// Read an `IpAddr` out of a kernel-supplied `sockaddr`, if it is one of the
/// two families we fingerprint.
#[cfg(unix)]
fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    // SAFETY: `sa` is non-null (checked by the caller) and points at a
    // kernel-supplied `sockaddr` whose `sa_family` selects the concrete layout
    // that follows. Both branches copy out through `read_unaligned`, so nothing
    // here assumes the pointer is aligned for the larger type.
    let family = unsafe { std::ptr::addr_of!((*sa).sa_family).read_unaligned() } as i32;
    match family {
        libc::AF_INET => {
            // SAFETY: family is AF_INET, so the allocation is at least a
            // `sockaddr_in`.
            let raw: libc::sockaddr_in = unsafe { std::ptr::read_unaligned(sa.cast()) };
            // `s_addr` holds the octets in network order, so its native-endian
            // bytes are the address octets in order.
            Some(IpAddr::V4(Ipv4Addr::from(
                raw.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: family is AF_INET6, so the allocation is at least a
            // `sockaddr_in6`.
            let raw: libc::sockaddr_in6 = unsafe { std::ptr::read_unaligned(sa.cast()) };
            Some(IpAddr::V6(Ipv6Addr::from(raw.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
