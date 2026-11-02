//! Crossed dials whose deciding handshake message arrives on another pair
//! than the one the moving node's link was installed on.
//!
//! When both nodes dial each other at once, each completes both an
//! outbound and an inbound XX handshake against the same identity. The
//! first of a node's two halves to complete installs the peer; the second
//! applies the tie-break, and both ends converge on the link the smaller
//! node dialled (FRC-2201, Section 5.7). The smaller node moves when its
//! outbound half completes second, on the peer's msg2; the larger node moves
//! when its inbound half completes second, on the smaller node's msg3. The
//! node that moves takes the transport and source address of the message
//! that completed the winning handshake as the peer's. These tests cross the
//! dials so that message arrives on another transport, or from another
//! address on the same transport, than the link the peer was installed on,
//! and check where each link sits after the move and where its next frame
//! goes. A third case has the msg2 answered from the address the larger
//! node's own msg1 came from rather than the one dialled, so a fix that took
//! the dialled address instead of the msg2's source is caught.
//!
//! Every packet is taken from its queue and handed on by the test, so each
//! precondition is asserted between the steps. The address the smaller node
//! dials is a loopback tap, so the test sees which of the larger node's
//! addresses a frame was sent to before it hands the frame on.
//!
//! [`cross_dials`] runs everything up to the msg2 the smaller node settles
//! on and is shared with the connected-socket tests in `connected_udp`; the
//! BLE test in `ble` reuses [`hand`] and [`phase`].

use super::link_index_audit;
use super::rekey_parity::heartbeat;
use super::spanning_tree::{
    LOOPBACK_REGISTRY, TestNode, add_loopback_alias, cleanup_nodes, loopback_tap, make_test_node,
};
use super::*;
use crate::proto::fmp::wire::{
    CommonPrefix, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2, PHASE_MSG3,
};
use crate::transport::loopback::LoopbackTransport;
use tokio::sync::mpsc::UnboundedReceiver;

/// The MTU of each node's first loopback transport, as `make_test_node`
/// builds it.
const T1_MTU: u16 = 1280;

/// The MTU of the second transport the other-transport case gives both
/// nodes: wider than the first, so the path MTU a node holds for the peer
/// shows which link it was seeded from.
const T2_MTU: u16 = 1400;

/// The second transport the other-transport case gives each node.
fn t2() -> TransportId {
    TransportId::new(2)
}

/// Where the smaller node dials the larger one, other than the pair the
/// larger node's own dial comes from, and where the larger node answers
/// from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Dial {
    /// From a second transport of the smaller node's, to the larger node's
    /// address on its own second transport.
    OtherTransport,
    /// On the transport the larger node dials from, to a second address of
    /// the larger node's, which the larger node answers from.
    OtherAddress,
    /// As `OtherAddress`, but the larger node answers from its first
    /// address, the one its own msg1 came from.
    AnsweredFromFirst,
}

/// Both nodes' dials started and the larger node's msg2 answering the
/// smaller node's dial sent, with nothing yet handed to the smaller node.
struct Dials {
    /// Both nodes.
    nodes: Vec<TestNode>,
    /// The index in `nodes` of the smaller node.
    s: usize,
    /// The index in `nodes` of the larger node.
    l: usize,
    /// The smaller node's session index on its outbound handshake.
    outbound: SessionIndex,
    /// The larger node's msg1, queued at the smaller node.
    msg1: ReceivedPacket,
    /// The larger node's msg2 answering the smaller node's dial, queued at
    /// the smaller node after `msg1`.
    msg2: ReceivedPacket,
    /// What the smaller node sends to the address it dialled.
    tap: UnboundedReceiver<ReceivedPacket>,
    /// The transport the msg2 came on and its source address.
    to: (TransportId, TransportAddr),
    /// The smaller node's own address on the transport it dialled from.
    source: TransportAddr,
}

/// Two nodes whose dials have crossed, stopped just before the smaller node
/// is handed the msg2 that answers its own dial, after the larger node's
/// msg3 has completed the smaller node's inbound half.
pub(super) struct Crossed {
    /// Both nodes.
    pub(super) nodes: Vec<TestNode>,
    /// The index in `nodes` of the smaller node, whose outbound handshake
    /// wins.
    pub(super) s: usize,
    /// The index in `nodes` of the larger node.
    pub(super) l: usize,
    /// How the dials were crossed.
    pub(super) dial: Dial,
    /// The smaller node's session index on its outbound handshake.
    pub(super) outbound: SessionIndex,
    /// The larger node's msg2 answering the smaller node's dial, not yet
    /// handed to the smaller node.
    pub(super) msg2: ReceivedPacket,
    /// What the smaller node sends to the address it dialled.
    pub(super) tap: UnboundedReceiver<ReceivedPacket>,
    /// The transport the msg2 came on and its source address: where the
    /// smaller node must hold the larger one after the move.
    pub(super) to: (TransportId, TransportAddr),
    /// The smaller node's own address on the transport it dialled from:
    /// where the larger node must hold the smaller one after its own move.
    pub(super) source: TransportAddr,
}

/// Take every packet queued on `rx` without handling it.
fn take(rx: &mut UnboundedReceiver<ReceivedPacket>) -> Vec<ReceivedPacket> {
    let mut packets = Vec::new();
    while let Ok(packet) = rx.try_recv() {
        packets.push(packet);
    }
    packets
}

/// The handshake phase of `packet`, if its prefix parses.
pub(super) fn phase(packet: &ReceivedPacket) -> Option<u8> {
    CommonPrefix::parse(&packet.data).map(|p| p.phase)
}

/// Hand `packet` to `node` by its handshake phase, as the receive loop does.
pub(super) async fn hand(node: &mut Node, packet: ReceivedPacket) {
    match phase(&packet) {
        Some(PHASE_MSG1) => node.handle_msg1(packet).await,
        Some(PHASE_MSG2) => node.handle_msg2(packet).await,
        Some(PHASE_MSG3) => node.handle_msg3(packet).await,
        Some(PHASE_ESTABLISHED) => node.handle_encrypted_frame(packet).await,
        _ => panic!("an unparseable packet"),
    }
}

/// Give `tn` a loopback transport `id` of `mtu` whose own address is
/// `addr`: what it sends carries `addr` as its source, and what is sent to
/// `addr` goes wherever the registry delivers it.
fn add_transport(tn: &mut TestNode, id: TransportId, addr: TransportAddr, mtu: u16) {
    let lo = LoopbackTransport::with_mtu(id, addr, mtu, LOOPBACK_REGISTRY.clone());
    tn.node.transports.insert(id, TransportHandle::Loopback(lo));
}

/// The transport `tn` holds its peer `peer` on and the peer's current
/// address there.
fn pair(tn: &TestNode, peer: &NodeAddr) -> (Option<TransportId>, Option<TransportAddr>) {
    let peer = tn.node.get_peer(peer).expect("the node holds the peer");
    (peer.transport_id(), peer.current_addr().cloned())
}

/// The path MTU `tn` holds for the node `peer`.
fn path_mtu(tn: &TestNode, peer: &NodeAddr) -> Option<u16> {
    tn.node
        .path_mtu_lookup_get(&crate::Ipv6Address::from_node_addr(peer))
}

/// Check that `tn` binds its current session index for `peer` under `tid`
/// and under no other transport: `tid` is where the peer's frames on that
/// session arrive and are looked up.
fn check_bound(tn: &TestNode, peer: &NodeAddr, tid: TransportId, who: &str) {
    let index = tn
        .node
        .get_peer(peer)
        .and_then(|p| p.our_index())
        .expect("the node holds the peer on a session");
    let elsewhere = tn
        .node
        .peers_by_index
        .keys()
        .filter(|(t, i)| *i == index.as_u32() && *t != tid)
        .count();
    assert_eq!(
        (
            tn.node.peers_by_index.get(&(tid, index.as_u32())).copied(),
            elsewhere
        ),
        (Some(*peer), 0),
        "{who} binds the moved session's index under {tid:?} and under no other transport"
    );
}

/// Start both nodes' dials as `dial` says, let the larger node answer the
/// smaller node's msg1, and stop before the smaller node is handed
/// anything, with every precondition up to that point asserted.
async fn dial_both(dial: Dial) -> Dials {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let (s, l) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    let t1 = nodes[s].transport_id;
    let s1 = nodes[s].addr.clone();
    let l1 = nodes[l].addr.clone();
    // The larger node's address the smaller node dials: what is sent there
    // lands in `tap`, and the test hands it to the larger node.
    let (dialled, mut tap) = loopback_tap();
    // The transport the smaller node dials on, and its own address there.
    let (s_tid, source) = match dial {
        Dial::OtherTransport => {
            let s2 = add_loopback_alias(&s1);
            add_transport(&mut nodes[s], t2(), s2.clone(), T2_MTU);
            add_transport(&mut nodes[l], t2(), dialled.clone(), T2_MTU);
            (t2(), s2)
        }
        Dial::OtherAddress | Dial::AnsweredFromFirst => (t1, s1.clone()),
    };
    let l_id = PeerIdentity::from_pubkey_full(nodes[l].node.identity().pubkey_full());
    let s_id = PeerIdentity::from_pubkey_full(nodes[s].node.identity().pubkey_full());

    // The smaller node dials the larger at `dialled`; the larger dials the
    // smaller from its first address on t1.
    nodes[s]
        .node
        .initiate_connection(s_tid, dialled.clone(), Some(l_id))
        .await
        .expect("precondition: s's dial starts");
    nodes[l]
        .node
        .initiate_connection(t1, s1.clone(), Some(s_id))
        .await
        .expect("precondition: l's dial starts");
    let outbound = {
        let keys: Vec<_> = nodes[s].node.pending_outbound.keys().copied().collect();
        assert_eq!(keys.len(), 1, "precondition: s has one dial pending");
        assert_eq!(keys[0].0, s_tid, "precondition: s's dial is on {s_tid:?}");
        SessionIndex::new(keys[0].1)
    };

    // The larger node takes the smaller's msg1 and answers it. Under XX a
    // msg1 names nobody, so nothing is installed yet.
    let at_dialled = take(&mut tap);
    assert_eq!(
        at_dialled.len(),
        1,
        "precondition: one packet at the dialled address"
    );
    assert_eq!(
        phase(&at_dialled[0]),
        Some(PHASE_MSG1),
        "precondition: s's msg1 at the dialled address"
    );
    for packet in at_dialled {
        hand(&mut nodes[l].node, packet).await;
    }
    let s_addr = *nodes[s].node.node_addr();
    assert!(
        nodes[l].node.get_peer(&s_addr).is_none(),
        "precondition: l installs nobody on s's msg1"
    );

    let at_s = take(&mut nodes[s].packet_rx);
    assert_eq!(
        at_s.iter().map(phase).collect::<Vec<_>>(),
        vec![Some(PHASE_MSG1), Some(PHASE_MSG2)],
        "precondition: l's msg1, then its msg2 answering s's dial, queued at s"
    );
    let mut at_s = at_s.into_iter();
    let msg1 = at_s.next().expect("l's msg1");
    let mut msg2 = at_s.next().expect("l's msg2");
    assert_eq!(
        (msg1.transport_id, &msg1.remote_addr),
        (t1, &l1),
        "precondition: l's msg1 came on t1 from l's first address"
    );
    if dial != Dial::OtherTransport {
        // A loopback send carries its transport's own address as the
        // source, so the larger node answers from its first address.
        assert_eq!(
            (msg2.transport_id, &msg2.remote_addr),
            (t1, &l1),
            "precondition: loopback stamped the msg2 with l's first address"
        );
    }
    if dial == Dial::OtherAddress {
        // A host that answers from the address it was dialled at, as one
        // UDP socket per address does, is modelled by giving the msg2 that
        // source.
        msg2.remote_addr = dialled.clone();
    }
    let to = match dial {
        Dial::OtherTransport | Dial::OtherAddress => (s_tid, dialled),
        Dial::AnsweredFromFirst => (t1, l1),
    };
    assert_eq!(
        (msg2.transport_id, &msg2.remote_addr),
        (to.0, &to.1),
        "precondition: the msg2 came on {:?} from {:?}",
        to.0,
        to.1
    );
    Dials {
        nodes,
        s,
        l,
        outbound,
        msg1,
        msg2,
        tap,
        to,
        source,
    }
}

/// Cross the two nodes' dials as `dial` says and stop just before the
/// smaller node is handed the msg2 answering its own dial, with every
/// precondition up to that point asserted.
///
/// The smaller node answers the larger node's msg1; the larger node
/// completes its own dial on that msg2, installs the smaller one and sends
/// its msg3, which completes the smaller node's inbound half and installs
/// the larger one there. The msg2 answering the smaller node's own dial is
/// held until then, so the smaller node's outbound half completes second
/// and settles the crossing on that msg2.
pub(super) async fn cross_dials(dial: Dial) -> Crossed {
    let Dials {
        mut nodes,
        s,
        l,
        outbound,
        msg1,
        msg2,
        tap,
        to,
        source,
    } = dial_both(dial).await;
    let s_addr = *nodes[s].node.node_addr();
    let l_addr = *nodes[l].node.node_addr();
    let t1 = nodes[s].transport_id;
    let s1 = nodes[s].addr.clone();
    let l1 = nodes[l].addr.clone();

    hand(&mut nodes[s].node, msg1).await;
    let at_l = take(&mut nodes[l].packet_rx);
    assert_eq!(
        at_l.iter().map(phase).collect::<Vec<_>>(),
        vec![Some(PHASE_MSG2)],
        "precondition: s's msg2 answering l's dial, and nothing else, at l"
    );
    for packet in at_l {
        hand(&mut nodes[l].node, packet).await;
    }
    assert_eq!(
        pair(&nodes[l], &s_addr),
        (Some(t1), Some(s1)),
        "precondition: l installed s on its own dial, on t1 at s's first address"
    );

    let mut at_s = take(&mut nodes[s].packet_rx).into_iter();
    let msg3 = at_s.next().expect("precondition: l's msg3 at s");
    assert_eq!(
        (phase(&msg3), msg3.transport_id, &msg3.remote_addr),
        (Some(PHASE_MSG3), t1, &l1),
        "precondition: l's msg3 first at s, on t1 from l's first address"
    );
    hand(&mut nodes[s].node, msg3).await;
    assert_ne!(
        nodes[s]
            .node
            .get_peer(&l_addr)
            .expect("precondition: s installed l on l's msg3")
            .our_index(),
        Some(outbound),
        "precondition: s is on its inbound session"
    );
    assert_eq!(
        pair(&nodes[s], &l_addr),
        (Some(t1), Some(l1)),
        "precondition: before the move s's link is on l's first address on t1"
    );
    assert_eq!(
        path_mtu(&nodes[s], &l_addr),
        Some(T1_MTU),
        "precondition: s seeded l's path MTU from t1 when it installed l"
    );
    // What follows the msg3 are the larger node's frames on the session the
    // smaller node now holds, and they reach it before the held msg2.
    for packet in at_s {
        assert_eq!(
            phase(&packet),
            Some(PHASE_ESTABLISHED),
            "precondition: only frames follow the msg3 at s"
        );
        hand(&mut nodes[s].node, packet).await;
    }
    Crossed {
        nodes,
        s,
        l,
        dial,
        outbound,
        msg2,
        tap,
        to,
        source,
    }
}

/// Hand the smaller node the msg2 and check that it takes the msg2's
/// transport and source address as the peer's, binds the moved session
/// there, seeds the peer's path MTU from that link, and sends its next
/// frame there; then that the larger node, handed the msg3 the move sent,
/// takes that msg3's transport and source address as the smaller node's in
/// its own move; and that each authenticates the other's next frame.
async fn check_move(crossed: Crossed) {
    let Crossed {
        mut nodes,
        s,
        l,
        dial,
        outbound,
        msg2,
        mut tap,
        to,
        source,
    } = crossed;
    let s_addr = *nodes[s].node.node_addr();
    let l_addr = *nodes[l].node.node_addr();
    hand(&mut nodes[s].node, msg2).await;
    let link = {
        let peer = nodes[s].node.get_peer(&l_addr).expect("s keeps l");
        assert_eq!(
            peer.our_index(),
            Some(outbound),
            "precondition: s swapped to its outbound session"
        );
        nodes[s]
            .node
            .links
            .get(&peer.link_id())
            .map(|k| (k.transport_id(), k.remote_addr().clone()))
    };

    assert_eq!(
        pair(&nodes[s], &l_addr),
        (Some(to.0), Some(to.1.clone())),
        "s takes the msg2's transport and source address as l's (s's link record: {link:?})"
    );
    let mtu = if dial == Dial::OtherTransport {
        T2_MTU
    } else {
        T1_MTU
    };
    assert_eq!(
        path_mtu(&nodes[s], &l_addr),
        Some(mtu),
        "s seeds l's path MTU from the link it moved to"
    );
    check_bound(&nodes[s], &l_addr, to.0, "s");
    link_index_audit::audit(&nodes[s].node, "the crossed-dial move");

    // A frame the smaller node sends after the move goes to the msg2's
    // address, from its own address on that transport, and authenticates at
    // the larger node.
    let at_tap = to.1 != nodes[l].addr;
    // What reached the larger node before the heartbeat, the smaller node's
    // msg3 answering the msg2 among it, is handed on first.
    let sent_at_move: Vec<_> = take(&mut nodes[l].packet_rx)
        .into_iter()
        .chain(take(&mut tap))
        .collect();
    assert_eq!(
        sent_at_move
            .iter()
            .filter(|p| phase(p) == Some(PHASE_MSG3))
            .map(|p| (p.transport_id, p.remote_addr.clone()))
            .collect::<Vec<_>>(),
        vec![(to.0, source.clone())],
        "precondition: s sent one msg3, on {:?} from its own address there",
        to.0
    );
    heartbeat(&mut nodes[s], &l_addr).await;
    let (mut sent, elsewhere) = if at_tap {
        (take(&mut tap), take(&mut nodes[l].packet_rx))
    } else {
        (take(&mut nodes[l].packet_rx), take(&mut tap))
    };
    assert_eq!(
        (sent.len(), elsewhere.len()),
        (1, 0),
        "s's heartbeat goes to {:?} and nowhere else",
        to.1
    );
    let frame = sent.remove(0);
    assert_eq!(
        (phase(&frame), frame.transport_id, &frame.remote_addr),
        (Some(PHASE_ESTABLISHED), to.0, &source),
        "s's heartbeat comes from s's own address on {:?}",
        to.0
    );
    for packet in sent_at_move {
        hand(&mut nodes[l].node, packet).await;
    }

    // The msg3 settled the crossing at the larger node, which moved onto its
    // inbound session at that msg3's pair.
    assert_eq!(
        pair(&nodes[l], &s_addr),
        (Some(to.0), Some(source.clone())),
        "l takes the msg3's transport and source address as s's"
    );
    check_bound(&nodes[l], &s_addr, to.0, "l");
    link_index_audit::audit(&nodes[l].node, "the larger node's msg3 move");

    let received = nodes[l]
        .node
        .get_peer(&s_addr)
        .expect("l keeps s")
        .link_stats()
        .packets_recv;
    hand(&mut nodes[l].node, frame).await;
    let peer = nodes[l].node.get_peer(&s_addr).expect("l keeps s");
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "no decrypt failure at l"
    );
    assert_eq!(
        peer.link_stats().packets_recv,
        received + 1,
        "s's heartbeat after the move authenticates at l"
    );

    // The larger node's answer, sent on the pair it holds the smaller node
    // at, authenticates at the smaller node: the moved session is found
    // under the transport its frames arrive on. What the larger node sent
    // after its own move is handed first.
    for packet in take(&mut nodes[s].packet_rx) {
        hand(&mut nodes[s].node, packet).await;
    }
    let received = nodes[s]
        .node
        .get_peer(&l_addr)
        .expect("s keeps l")
        .link_stats()
        .packets_recv;
    heartbeat(&mut nodes[l], &s_addr).await;
    let back = take(&mut nodes[s].packet_rx);
    assert_eq!(back.len(), 1, "l's heartbeat reaches s");
    for packet in back {
        hand(&mut nodes[s].node, packet).await;
    }
    let peer = nodes[s].node.get_peer(&l_addr).expect("s keeps l");
    assert_eq!(
        (
            peer.consecutive_decrypt_failures(),
            peer.link_stats().packets_recv
        ),
        (0, received + 1),
        "l's heartbeat after the move authenticates at s"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A crossed dial whose winning msg2 arrives on a second transport moves the
/// smaller node's link to that transport and the msg2's source address.
#[tokio::test]
async fn a_crossed_dial_won_on_another_transport_moves_the_link_to_the_msg2s_transport_and_address()
{
    check_move(cross_dials(Dial::OtherTransport).await).await;
}

/// A crossed dial whose winning msg2 comes from a second address of the
/// peer's on the same transport moves the smaller node's link to that
/// address.
#[tokio::test]
async fn a_crossed_dial_won_from_another_address_moves_the_link_to_the_msg2s_address() {
    check_move(cross_dials(Dial::OtherAddress).await).await;
}

/// A crossed dial whose winning msg2 comes from another address than the
/// one the smaller node dialled holds the peer at the msg2's source, not at
/// the dialled address.
#[tokio::test]
async fn a_crossed_dial_takes_the_msg2s_source_address_not_the_address_it_dialled() {
    check_move(cross_dials(Dial::AnsweredFromFirst).await).await;
}

/// A crossed dial whose outbound halves both complete first is settled at
/// msg3 on both nodes: the smaller node keeps the outbound session it
/// installed at its msg2's pair, and the larger node moves onto its inbound
/// session at the transport and source address of the smaller node's msg3,
/// which here is a second transport.
#[tokio::test]
async fn a_crossed_dial_settled_at_msg3_moves_the_larger_nodes_link_to_the_msg3s_transport_and_address()
 {
    let Dials {
        mut nodes,
        s,
        l,
        outbound,
        msg1,
        msg2,
        mut tap,
        to,
        source,
    } = dial_both(Dial::OtherTransport).await;
    let s_addr = *nodes[s].node.node_addr();
    let l_addr = *nodes[l].node.node_addr();
    let t1 = nodes[s].transport_id;
    let s1 = nodes[s].addr.clone();

    // The smaller node answers the larger node's msg1, then completes its
    // own dial on the msg2 queued behind it and installs the larger node.
    hand(&mut nodes[s].node, msg1).await;
    hand(&mut nodes[s].node, msg2).await;
    assert_eq!(
        nodes[s].node.get_peer(&l_addr).and_then(|p| p.our_index()),
        Some(outbound),
        "precondition: s installed l on its own dial's outbound session"
    );
    assert_eq!(
        pair(&nodes[s], &l_addr),
        (Some(to.0), Some(to.1.clone())),
        "precondition: s installed l at the msg2's transport and source address"
    );

    // The larger node completes its own dial on the smaller node's msg2 and
    // installs the smaller node on t1.
    let at_l = take(&mut nodes[l].packet_rx);
    assert_eq!(
        at_l.iter().map(phase).collect::<Vec<_>>(),
        vec![Some(PHASE_MSG2)],
        "precondition: s's msg2 answering l's dial, and nothing else, at l"
    );
    for packet in at_l {
        hand(&mut nodes[l].node, packet).await;
    }
    assert_eq!(
        pair(&nodes[l], &s_addr),
        (Some(t1), Some(s1)),
        "precondition: l installed s on its own dial, on t1 at s's first address"
    );
    assert_eq!(
        path_mtu(&nodes[l], &s_addr),
        Some(T1_MTU),
        "precondition: l seeded s's path MTU from t1 when it installed s"
    );

    // The smaller node's msg3, sent to the address it dialled on t2,
    // completes the larger node's inbound half second.
    let mut at_tap = take(&mut tap).into_iter();
    let msg3 = at_tap.next().expect("precondition: s's msg3 at the tap");
    assert_eq!(
        (phase(&msg3), msg3.transport_id, &msg3.remote_addr),
        (Some(PHASE_MSG3), t2(), &source),
        "precondition: s's msg3 comes on t2 from s's own address there"
    );
    hand(&mut nodes[l].node, msg3).await;
    assert_eq!(
        pair(&nodes[l], &s_addr),
        (Some(t2()), Some(source.clone())),
        "l takes the msg3's transport and source address as s's"
    );
    assert_eq!(
        path_mtu(&nodes[l], &s_addr),
        Some(T2_MTU),
        "l seeds s's path MTU from the link it moved to"
    );
    check_bound(&nodes[l], &s_addr, t2(), "l");
    link_index_audit::audit(&nodes[l].node, "the larger node's msg3 move");
    // The smaller node's frames on its session follow its msg3.
    for packet in at_tap {
        hand(&mut nodes[l].node, packet).await;
    }

    // The larger node's msg3 completes the smaller node's inbound half
    // second; the smaller node keeps its outbound session where it is.
    for packet in take(&mut nodes[s].packet_rx) {
        hand(&mut nodes[s].node, packet).await;
    }
    assert_eq!(
        nodes[s].node.get_peer(&l_addr).and_then(|p| p.our_index()),
        Some(outbound),
        "s keeps its outbound session"
    );
    assert_eq!(
        pair(&nodes[s], &l_addr),
        (Some(to.0), Some(to.1.clone())),
        "s keeps l at the msg2's transport and source address"
    );
    for packet in take(&mut nodes[l].packet_rx)
        .into_iter()
        .chain(take(&mut tap))
    {
        hand(&mut nodes[l].node, packet).await;
    }

    // Each end's next frame authenticates at the other.
    let received = nodes[s]
        .node
        .get_peer(&l_addr)
        .expect("s keeps l")
        .link_stats()
        .packets_recv;
    heartbeat(&mut nodes[l], &s_addr).await;
    let back = take(&mut nodes[s].packet_rx);
    assert_eq!(
        back.iter()
            .map(|p| (p.transport_id, p.remote_addr.clone()))
            .collect::<Vec<_>>(),
        vec![(to.0, to.1.clone())],
        "l's heartbeat reaches s on t2 from l's address there"
    );
    for packet in back {
        hand(&mut nodes[s].node, packet).await;
    }
    let peer = nodes[s].node.get_peer(&l_addr).expect("s keeps l");
    assert_eq!(
        (
            peer.consecutive_decrypt_failures(),
            peer.link_stats().packets_recv
        ),
        (0, received + 1),
        "l's heartbeat after the move authenticates at s"
    );
    let received = nodes[l]
        .node
        .get_peer(&s_addr)
        .expect("l keeps s")
        .link_stats()
        .packets_recv;
    heartbeat(&mut nodes[s], &l_addr).await;
    for packet in take(&mut tap) {
        hand(&mut nodes[l].node, packet).await;
    }
    let peer = nodes[l].node.get_peer(&s_addr).expect("l keeps s");
    assert_eq!(
        (
            peer.consecutive_decrypt_failures(),
            peer.link_stats().packets_recv
        ),
        (0, received + 1),
        "s's heartbeat after the move authenticates at l"
    );
    cleanup_nodes(&mut nodes).await;
}
