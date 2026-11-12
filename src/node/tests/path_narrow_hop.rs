//! A path that crosses a hop narrower than the link MTU at both of its
//! ends, such as a bridge or tunnel at layer 2 between two Ethernet ports:
//! the hop drops every frame longer than its own MTU and says nothing. Each
//! test links two nodes over the loopback transport, gives each a second
//! loopback transport `t2()` of one MTU, and puts a stand-in for the hop
//! between them on `t2()`: every frame on `t2()` longer than the hop's MTU
//! is dropped, in both directions, before the receiver sees it. A offers
//! B's `t2()` address, the path is probed until it is Live, A pins its
//! link to it, and A then sends B one small `SessionDatagram` and one as
//! large as A's own path MTU entry for B allows. The node's TUN reader and
//! TCP clamp read that entry, so the large one stands for the largest IPv6
//! packet A would send B. Every run is on the frozen clock, stepped only by
//! the machines' wakes.

use super::paths::{enabled, loopback_mut, second_transport, state_at, t2};
use super::rekey_parity::linked_pair;
use super::spanning_tree::{TestNode, cleanup_nodes};
use super::*;
use crate::peer::{PathState, peer_now};
use crate::proto::fmp::wire::{
    COMMON_PREFIX_SIZE, CommonPrefix, FRAME_OVERHEAD, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2,
};
use crate::proto::link::SessionDatagram;
use crate::transport::TransportType;

/// The stand-in for the narrow hop on `t2()`, with what it saw.
struct Hop {
    /// The longest frame it carries, in bytes.
    mtu: usize,
    /// The length of each frame it dropped, in order.
    dropped: Vec<usize>,
    /// The length of each frame it carried, in order.
    carried: Vec<usize>,
}

impl Hop {
    fn new(mtu: usize) -> Self {
        Self {
            mtu,
            dropped: Vec::new(),
            carried: Vec::new(),
        }
    }
}

/// Hand every frame waiting at either node to that node, dropping each one
/// on `t2()` longer than the hop's MTU, until a round moves none.
async fn settle(nodes: &mut [TestNode], hop: &mut Hop) {
    loop {
        let mut moved = 0;
        for tn in nodes.iter_mut() {
            while let Ok(packet) = tn.packet_rx.try_recv() {
                if packet.transport_id == t2() {
                    if packet.data.len() > hop.mtu {
                        hop.dropped.push(packet.data.len());
                        continue;
                    }
                    hop.carried.push(packet.data.len());
                }
                moved += 1;
                if packet.data.len() < COMMON_PREFIX_SIZE {
                    continue;
                }
                match CommonPrefix::parse(&packet.data).map(|p| p.phase) {
                    Some(PHASE_MSG1) => tn.node.handle_msg1(packet).await,
                    Some(PHASE_MSG2) => tn.node.handle_msg2(packet).await,
                    Some(PHASE_ESTABLISHED) => tn.node.handle_encrypted_frame(packet).await,
                    _ => {}
                }
            }
        }
        if moved == 0 {
            return;
        }
    }
}

/// The earliest wake of either node's machine for the other.
fn next_wake(nodes: &[TestNode]) -> Option<crate::peer::PeerInstant> {
    let wake = |k: usize| {
        let peer = nodes[1 - k].node.node_addr();
        nodes[k].node.get_peer(peer)?.bundle()?.next_wake()
    };
    match (wake(0), wake(1)) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Step both machines at each wake, every frame passed through the hop
/// between steps, until `done` holds or `limit` has passed on the node
/// clock.
async fn run_until(
    nodes: &mut [TestNode],
    hop: &mut Hop,
    limit: Duration,
    mut done: impl FnMut(&[TestNode]) -> bool,
) {
    settle(nodes, hop).await;
    let end = fips_core::time::deadline(peer_now(), limit);
    while !done(nodes) {
        let Some(wake) = next_wake(nodes).filter(|w| *w <= end) else {
            break;
        };
        {
            use fips_core::time::Instant as _;
            crate::time::advance(wake.saturating_duration_since(peer_now()));
        }
        for tn in nodes.iter_mut() {
            tn.node.path_tick().await;
        }
        settle(nodes, hop).await;
    }
}

/// Two linked nodes, A (0) and B (1), with A's link to B pinned to the path
/// across the hop on `t2()`.
struct Rig {
    nodes: Vec<TestNode>,
    hop: Hop,
    a: NodeAddr,
    b: NodeAddr,
    /// B's `t2()` address.
    b2: TransportAddr,
    /// A's path to B's `t2()` address: its states in order, from the first
    /// it was seen in, until it was Live or Dead.
    states: Vec<PathState>,
    /// The frames the hop dropped before the path was Live.
    dropped_probing: Vec<usize>,
}

impl Rig {
    /// Link the pair with both ends' `t2()` link MTU `iface` and the hop's
    /// MTU `hop_mtu`, prove A's path across the hop, and pin A's link to
    /// it.
    async fn pinned(iface: u16, hop_mtu: usize) -> Self {
        Self::pinned_on(iface, hop_mtu, TransportType::LOOPBACK).await
    }

    /// As [`Rig::pinned`], with both ends' `t2()` reporting the type `ty`.
    async fn pinned_on(iface: u16, hop_mtu: usize, ty: TransportType) -> Self {
        crate::time::freeze();
        let mut nodes = linked_pair(enabled(), enabled()).await;
        let a = *nodes[0].node.node_addr();
        let b = *nodes[1].node.node_addr();
        second_transport(&mut nodes[0], t2(), iface);
        let b2 = second_transport(&mut nodes[1], t2(), iface);
        loopback_mut(&mut nodes[0], t2()).typed(ty.clone());
        loopback_mut(&mut nodes[1], t2()).typed(ty);
        let mut hop = Hop::new(hop_mtu);
        nodes[0].node.offer_path(&b, t2(), b2.clone()).await;

        let mut states: Vec<PathState> = Vec::new();
        let mut note = |nodes: &[TestNode]| {
            if let Some(s) = state_at(&nodes[0], &b, t2(), &b2).filter(|s| states.last() != Some(s))
            {
                states.push(s);
            }
            matches!(states.last(), Some(PathState::Live | PathState::Dead))
        };
        run_until(&mut nodes, &mut hop, Duration::from_secs(40), &mut note).await;
        note(&nodes);
        let dropped_probing = std::mem::take(&mut hop.dropped);
        assert_eq!(
            states.last(),
            Some(&PathState::Live),
            "precondition: A's path across the hop is proven: {states:?}, hop dropped {dropped_probing:?}"
        );

        let npub = nodes[1].node.npub();
        nodes[0]
            .node
            .pin_path(&npub, "2", None)
            .await
            .expect("precondition: the pin is taken");
        settle(&mut nodes, &mut hop).await;
        let active = nodes[0].node.get_peer(&b).unwrap().active_path().unwrap();
        assert_eq!(
            (active.transport_id(), active.addr().clone()),
            (t2(), b2.clone()),
            "precondition: A's link to B sends on the path across the hop"
        );
        Self {
            nodes,
            hop,
            a,
            b,
            b2,
            states,
            dropped_probing,
        }
    }

    /// The path's proven MTU at A, as a path message length.
    fn proven(&self) -> Option<usize> {
        let paths = self.nodes[0].node.get_peer(&self.b)?.bundle()?.paths();
        paths.get(paths.find(t2(), &self.b2)?)?.live().mtu()
    }

    /// A's path MTU entry for B.
    fn entry(&self) -> Option<u16> {
        entry(&self.nodes, &self.b)
    }

    /// Datagrams delivered at B.
    fn delivered(&self) -> u64 {
        self.nodes[1]
            .node
            .metrics()
            .forwarding
            .delivered_packets
            .get()
    }

    /// A `SessionDatagram` from A to B whose encoding is `len` bytes long.
    fn datagram(&self, len: usize) -> Vec<u8> {
        let header = SessionDatagram::new(self.a, self.b, Vec::new())
            .encode()
            .len();
        SessionDatagram::new(self.a, self.b, vec![0x10; len.saturating_sub(header)]).encode()
    }

    /// Send B a datagram of `len` bytes from A, and return whether it
    /// arrived and the length of the longest frame on `t2()` the send put
    /// through the hop, carried or dropped.
    async fn send(&mut self, len: usize) -> (bool, usize) {
        let before = self.delivered();
        let (carried, dropped) = (self.hop.carried.len(), self.hop.dropped.len());
        let bytes = self.datagram(len);
        self.nodes[0]
            .node
            .send_encrypted_link_message(&self.b, &bytes)
            .await
            .expect("precondition: the datagram goes out, within A's link MTU");
        settle(&mut self.nodes, &mut self.hop).await;
        let frame = self.hop.carried[carried..]
            .iter()
            .chain(&self.hop.dropped[dropped..])
            .copied()
            .max()
            .unwrap_or(0);
        (self.delivered() == before + 1, frame)
    }

    /// Send B the largest datagram A's own path MTU entry for B admits: the
    /// one that fills a frame of exactly the entry's length.
    async fn send_largest(&mut self) -> (bool, usize) {
        let entry = self
            .entry()
            .expect("precondition: A holds a path MTU entry for B");
        self.send(usize::from(entry) - FRAME_OVERHEAD).await
    }
}

/// `nodes[0]`'s path MTU entry for `b`.
fn entry(nodes: &[TestNode], b: &NodeAddr) -> Option<u16> {
    let fips_b = crate::Ipv6Address::from_node_addr(b);
    nodes[0].node.path_mtu_lookup_get(&fips_b)
}

/// What one run saw.
#[derive(Debug)]
struct Seen {
    /// A's path across the hop: its states until it was Live or Dead.
    states: Vec<PathState>,
    /// That path's proven MTU at A once it was Live.
    proven: Option<usize>,
    /// The frames the hop dropped before the path was Live.
    dropped_probing: Vec<usize>,
    /// A's path MTU entry for B once the link was pinned to the path.
    entry: Option<u16>,
    /// Whether the small datagram reached B.
    small: bool,
    /// The length of the large datagram's frame.
    large_frame: usize,
    /// Whether the large datagram reached B.
    large: bool,
    /// The path's state at A ten seconds after the large datagram.
    state_after: Option<PathState>,
    /// A's path MTU entry for B ten seconds after the large datagram.
    entry_after: Option<u16>,
    /// The frames the hop dropped from the large datagram until ten seconds
    /// after it, the large datagram's included.
    dropped_later: Vec<usize>,
}

/// Run the scenario with both ends' `t2()` link MTU `iface` and the hop's
/// MTU `hop_mtu`.
async fn cross(iface: u16, hop_mtu: usize) -> Seen {
    let mut rig = Rig::pinned(iface, hop_mtu).await;
    let proven = rig.proven();
    let entry = rig.entry();
    let (small, _) = rig.send(64).await;
    let (large, large_frame) = rig.send_largest().await;
    run_until(
        &mut rig.nodes,
        &mut rig.hop,
        Duration::from_secs(10),
        |_| false,
    )
    .await;
    let state_after = state_at(&rig.nodes[0], &rig.b, t2(), &rig.b2);
    let entry_after = rig.entry();
    let dropped_later = std::mem::take(&mut rig.hop.dropped);
    cleanup_nodes(&mut rig.nodes).await;
    let seen = Seen {
        states: rig.states,
        proven,
        dropped_probing: rig.dropped_probing,
        entry,
        small,
        large_frame,
        large,
        state_after,
        entry_after,
        dropped_later,
    };
    eprintln!("link MTU {iface}, hop MTU {hop_mtu}: {seen:?}");
    seen
}

/// A hop of 1000 bytes between two link MTUs of 1280: the padded probe is
/// dropped, the path is proven at a smaller rung of the size ladder, the
/// link is pinned to it, and A's entry for B is that proven size, so the
/// largest datagram A admits for B crosses the hop as a small one does, and
/// ten seconds later the path is still Live with the entry no wider than
/// the hop.
#[tokio::test]
async fn a_path_across_a_hop_narrower_than_its_link_mtu_carries_the_largest_frame_the_node_admits_for_the_peer()
 {
    let seen = cross(1280, 1000).await;
    assert!(
        !seen.dropped_probing.is_empty() && seen.dropped_probing.iter().all(|&len| len > 1000),
        "precondition: the hop dropped padded path messages while the path was probed: {seen:?}"
    );
    assert!(!seen.states.contains(&PathState::Dead), "{seen:?}");
    assert!(
        seen.proven
            .is_some_and(|mtu| mtu + FRAME_OVERHEAD <= 1000 && mtu > 64),
        "precondition: the path proves a size the hop carries: {seen:?}"
    );
    assert!(
        seen.small,
        "precondition: small traffic crosses the hop: {seen:?}"
    );
    assert!(
        seen.large,
        "defect: the largest frame A's path MTU for B admits, {} bytes, is lost at the 1000-byte hop \
         while the path is Live and proven at a smaller size: {seen:?}",
        seen.large_frame
    );
    assert_eq!(seen.state_after, Some(PathState::Live), "{seen:?}");
    assert!(
        seen.entry_after.is_some_and(|mtu| mtu <= 1000),
        "A's entry for B stays within the hop: {seen:?}"
    );
    assert!(
        seen.dropped_later.iter().all(|&len| len > 1000),
        "only frames past the hop's MTU are dropped: {seen:?}"
    );
}

/// Control: with the hop as wide as the link MTU, the padded probe proves
/// the path's MTU, and the largest datagram arrives.
#[tokio::test]
async fn a_path_across_a_hop_as_wide_as_its_link_mtu_carries_the_largest_frame_the_node_admits() {
    let seen = cross(1280, 1280).await;
    assert_eq!(seen.proven, Some(1280 - FRAME_OVERHEAD), "{seen:?}");
    assert_eq!(seen.entry, Some(1280), "{seen:?}");
    assert!(seen.small && seen.large, "{seen:?}");
}

/// Control: with both ends' link MTU set by hand to the hop's, A's entry
/// for B is the hop's MTU and the largest datagram it admits arrives.
#[tokio::test]
async fn a_path_whose_link_mtu_is_set_to_the_narrow_hops_carries_the_largest_frame_the_node_admits()
{
    let seen = cross(1000, 1000).await;
    assert_eq!(seen.entry, Some(1000), "{seen:?}");
    assert!(seen.small && seen.large, "{seen:?}");
}

/// A hop of 1000 bytes between two link MTUs of 1280 widens to 1280 once
/// A's link is pinned to the path across it. The upward size search, which
/// starts again from the size proven ten minutes after it ends, proves the
/// link MTU, and A's entry for B rises with it to 1280, so a datagram that
/// fills a 1280-byte frame then arrives.
#[tokio::test]
async fn after_the_narrow_hop_widens_the_path_mtu_entry_rises_to_the_size_the_path_proves() {
    let mut rig = Rig::pinned(1280, 1000).await;
    let narrow = rig.entry();
    assert!(
        narrow.is_some_and(|mtu| mtu <= 1000),
        "precondition: A's entry for B is within the narrow hop: {narrow:?}"
    );
    rig.hop.mtu = 1280;
    let b = rig.b;
    run_until(
        &mut rig.nodes,
        &mut rig.hop,
        Duration::from_secs(15 * 60),
        |nodes| entry(nodes, &b) == Some(1280),
    )
    .await;
    let proven = rig.proven();
    let widened = rig.entry();
    let (large, frame) = rig.send_largest().await;
    let state = state_at(&rig.nodes[0], &rig.b, t2(), &rig.b2);
    cleanup_nodes(&mut rig.nodes).await;
    assert_eq!(
        proven,
        Some(1280 - FRAME_OVERHEAD),
        "precondition: the search proves the widened hop's size: entry {widened:?}"
    );
    assert_eq!(
        widened,
        Some(1280),
        "defect: A's entry for B stays at {narrow:?} after the path proves {proven:?}"
    );
    assert!(large && frame == 1280, "a {frame}-byte frame arrives");
    assert_eq!(state, Some(PathState::Live));
}

/// A path on a connection-oriented transport between two link MTUs of 1280,
/// with nothing narrower on it: its padded probes are lost while it is
/// probed (a 1000-byte hop, widened to 1280 once the link is pinned to the
/// path, stands for that loss), so it is proven at a smaller rung of the
/// size ladder, and no search raises that size on a stream. The size says
/// only that probes were lost, so A's entry for B stays the link MTU, and
/// a datagram that fills a 1280-byte frame arrives.
#[tokio::test]
async fn a_stream_path_proven_below_its_link_mtu_by_lost_probes_keeps_the_link_mtu_for_the_peer() {
    let mut rig = Rig::pinned_on(1280, 1000, TransportType::TCP).await;
    rig.hop.mtu = 1280;
    let proven = rig.proven();
    let entry = rig.entry();
    let (large, frame) = rig.send_largest().await;
    let state = state_at(&rig.nodes[0], &rig.b, t2(), &rig.b2);
    let dropped = rig.dropped_probing.clone();
    cleanup_nodes(&mut rig.nodes).await;
    assert!(
        !dropped.is_empty(),
        "precondition: padded path messages were lost while the path was probed"
    );
    assert!(
        proven.is_some_and(|mtu| mtu + FRAME_OVERHEAD <= 1000),
        "precondition: the lost probes prove a rung below the link MTU: {proven:?}"
    );
    assert_eq!(
        entry,
        Some(1280),
        "defect: A's entry for B follows a size a stream path proved by losing probes, \
         {proven:?}, not its link MTU"
    );
    assert!(large && frame == 1280, "a {frame}-byte frame arrives");
    assert_eq!(state, Some(PathState::Live));
}
