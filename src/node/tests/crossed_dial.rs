//! Crossed dials whose winning msg2 arrives on another pair than the one
//! the smaller node's link was promoted on.
//!
//! When both nodes dial each other at once, each promotes the msg1 of the
//! other's dial, and the smaller node, whose outbound handshake wins, moves
//! its link to that session when the peer's msg2 arrives. The node that
//! keeps its outbound handshake takes the transport and source address of
//! that msg2 as the peer's (FRC-1201, Section 5.6). These tests cross the
//! dials so that the msg2 arrives on another transport, or from another
//! address on the same transport, than the peer's msg1 did, and check where
//! the link sits after the move and where its next frame goes. A third
//! case has the msg2 answered from the address the peer's msg1 came from
//! rather than the one dialled, so a fix that took the dialled address
//! instead of the msg2's source is caught.
//!
//! Every packet is taken from its queue and handed on by the test, so each
//! precondition is asserted between the steps. The address the smaller node
//! dials is a loopback tap, so the test sees which of the larger node's
//! addresses a frame was sent to before it hands the frame on.
//!
//! [`cross_dials`] runs everything up to the msg2 and is shared with the
//! connected-socket tests in `connected_udp`; the BLE test in `ble` reuses
//! [`hand`] and [`phase`].

use super::link_index_audit;
use super::rekey_parity::heartbeat;
use super::spanning_tree::{
    LOOPBACK_REGISTRY, TestNode, add_loopback_alias, cleanup_nodes, loopback_tap, make_test_node,
};
use super::*;
use crate::proto::fmp::wire::{CommonPrefix, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2};
use crate::transport::loopback::LoopbackTransport;
use tokio::sync::mpsc::UnboundedReceiver;

/// The MTU of each node's first loopback transport, as `make_test_node`
/// builds it.
const T1_MTU: u16 = 1280;

/// The MTU of the second transport the other-transport case gives both
/// nodes: wider than the first, so the path MTU the smaller node holds for
/// the peer shows which link it was seeded from.
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

/// Two nodes whose dials have crossed, stopped just before the smaller node
/// is handed the msg2 that answers its own dial.
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
    /// What the larger node sent the smaller one after that msg2, not yet
    /// handed: established frames only.
    pub(super) rest: Vec<ReceivedPacket>,
    /// What the smaller node sends to the address it dialled.
    pub(super) tap: UnboundedReceiver<ReceivedPacket>,
    /// The transport the msg2 came on and its source address: where the
    /// smaller node must hold the larger one after the move.
    pub(super) to: (TransportId, TransportAddr),
    /// The smaller node's own address on the transport it dialled from.
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

/// Cross the two nodes' dials as `dial` says and stop just before the
/// smaller node is handed the msg2 answering its own dial, with every
/// precondition up to that point asserted.
pub(super) async fn cross_dials(dial: Dial) -> Crossed {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let (s, l) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    let s_addr = *nodes[s].node.node_addr();
    let l_addr = *nodes[l].node.node_addr();
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
        .initiate_connection(s_tid, dialled.clone(), l_id)
        .await
        .expect("precondition: s's dial starts");
    nodes[l]
        .node
        .initiate_connection(t1, s1.clone(), s_id)
        .await
        .expect("precondition: l's dial starts");
    let outbound = {
        let keys: Vec<_> = nodes[s].node.pending_outbound.keys().copied().collect();
        assert_eq!(keys.len(), 1, "precondition: s has one dial pending");
        assert_eq!(keys[0].0, s_tid, "precondition: s's dial is on {s_tid:?}");
        SessionIndex::new(keys[0].1)
    };

    // The larger node takes the smaller's msg1 and answers it.
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
    assert!(
        nodes[l].node.get_peer(&s_addr).is_some(),
        "precondition: l promoted on s's msg1"
    );

    // The smaller node takes the larger's msg1; the msg2 answering its own
    // dial is held for the caller.
    let mut at_s = take(&mut nodes[s].packet_rx).into_iter();
    let msg1 = at_s.next().expect("precondition: l's msg1 at s");
    assert_eq!(
        phase(&msg1),
        Some(PHASE_MSG1),
        "precondition: l's msg1 first at s"
    );
    hand(&mut nodes[s].node, msg1).await;
    assert_ne!(
        nodes[s]
            .node
            .get_peer(&l_addr)
            .expect("precondition: s promoted on l's msg1")
            .our_index(),
        Some(outbound),
        "precondition: s is on its inbound session"
    );
    assert_eq!(
        pair(&nodes[s], &l_addr),
        (Some(t1), Some(l1.clone())),
        "precondition: before the move s's link is on l's first address on t1"
    );
    assert_eq!(
        path_mtu(&nodes[s], &l_addr),
        Some(T1_MTU),
        "precondition: s seeded l's path MTU from t1 when it promoted l"
    );
    let mut msg2 = at_s.next().expect("precondition: l's msg2 at s");
    assert_eq!(
        phase(&msg2),
        Some(PHASE_MSG2),
        "precondition: l's msg2 second at s"
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
    let rest: Vec<_> = at_s.collect();
    assert!(
        rest.iter().all(|p| phase(p) == Some(PHASE_ESTABLISHED)),
        "precondition: only frames follow the msg2 at s"
    );
    Crossed {
        nodes,
        s,
        l,
        dial,
        outbound,
        msg2,
        rest,
        tap,
        to,
        source,
    }
}

/// Hand the smaller node the msg2 and check that it takes the msg2's
/// transport and source address as the peer's, binds the moved session
/// there, seeds the peer's path MTU from that link, sends its next frame
/// there, and authenticates the peer's answer.
async fn check_move(crossed: Crossed) {
    let Crossed {
        mut nodes,
        s,
        l,
        dial,
        outbound,
        msg2,
        rest,
        mut tap,
        to,
        source,
    } = crossed;
    let s_addr = *nodes[s].node.node_addr();
    let l_addr = *nodes[l].node.node_addr();
    // What the larger node sent after the msg2 (`rest`) is held until the
    // move is checked: in the other-address case it comes from the larger
    // node's first address, and an authenticated frame from there would
    // move the link back.
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
    let elsewhere = nodes[s]
        .node
        .peers_by_index
        .keys()
        .filter(|(tid, index)| *index == outbound.as_u32() && *tid != to.0)
        .count();
    assert_eq!(
        (
            nodes[s]
                .node
                .peers_by_index
                .get(&(to.0, outbound.as_u32()))
                .copied(),
            elsewhere
        ),
        (Some(l_addr), 0),
        "s binds the moved session's index under {:?} and under no other transport",
        to.0
    );
    link_index_audit::audit(&nodes[s].node, "the crossed-dial move");

    // A frame the smaller node sends after the move goes to the msg2's
    // address, from its own address on that transport, and authenticates at
    // the larger node.
    let at_tap = to.1 != nodes[l].addr;
    // What reached the larger node before the heartbeat, the smaller node's
    // msg2 answering the larger node's dial first, is handed on first.
    let sent_at_move: Vec<_> = take(&mut nodes[l].packet_rx)
        .into_iter()
        .chain(take(&mut tap))
        .collect();
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
    // under the transport its frames arrive on.
    for packet in rest {
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
