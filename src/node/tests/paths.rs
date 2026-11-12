//! The node's side of each link's path machine (`handlers/path.rs`): the
//! facts it gives the machine about its transports, the parameters
//! `node.path` maps to, and the machine every promotion builds and a won
//! crossed handshake starts again. Loopback nodes only.

use super::rekey_parity::{age_link, deliver, linked_pair};
use super::spanning_tree::{
    TestNode, add_loopback_alias, cleanup_nodes, drain_all_packets, initiate_handshake,
    make_test_node_with_config,
};
use super::*;
use crate::config::{PathKind, TransportRole};
use crate::node::handlers::path::{class_of, kind_of, path_params, role_of};
use crate::peer::{PathState, Roam, peer_now};
use crate::proto::bloom::BloomFilter;
use crate::proto::link::LinkMessageType;
use crate::transport::TransportType;
use fips_core::proto::path::wire::{PathCaps, PathClose, PathCloseReason, PathFlags, PathProbe};
use fips_core::proto::path::{Class, Input, Kind, PathRef, Role, Scope, Source};

/// Each transport type maps to its class and the kind its medium fixes, and a
/// configured kind wins on UDP and TCP.
#[test]
fn transport_types_map_to_their_class_and_kind() {
    let cases = [
        (TransportType::UDP, Class::Clear, None),
        (TransportType::TCP, Class::Clear, None),
        (TransportType::ETHERNET, Class::Clear, Some(Kind::Local)),
        (TransportType::WIFI, Class::Clear, Some(Kind::Local)),
        (TransportType::TOR, Class::Tor, Some(Kind::Internet)),
        (TransportType::SERIAL, Class::Clear, Some(Kind::Local)),
        (TransportType::BLE, Class::Clear, Some(Kind::Local)),
        (TransportType::NYM, Class::Nym, Some(Kind::Internet)),
    ];
    for (ty, class, kind) in cases {
        assert_eq!(class_of(&ty), class, "{}", ty.name);
        assert_eq!(kind_of(&ty, None), kind, "{}", ty.name);
    }
    // A configured kind wins on UDP and TCP.
    for ty in [TransportType::UDP, TransportType::TCP] {
        assert_eq!(kind_of(&ty, Some(PathKind::Local)), Some(Kind::Local));
        assert_eq!(kind_of(&ty, Some(PathKind::Internet)), Some(Kind::Internet));
    }
}

/// Each configured transport role maps to the core role of the same name.
#[test]
fn transport_roles_map_to_the_cores_four_roles() {
    assert_eq!(role_of(TransportRole::Never), Role::Never);
    assert_eq!(role_of(TransportRole::Backup), Role::Backup);
    assert_eq!(role_of(TransportRole::Normal), Role::Normal);
    assert_eq!(role_of(TransportRole::Preferred), Role::Preferred);
}

/// Each path setting of the node's configuration reaches the core machine's
/// parameters, and the default configuration runs multipath disabled.
#[test]
fn the_path_settings_map_onto_the_machines_parameters() {
    let mut node = crate::config::NodeConfig::default();
    node.path.enabled = true;
    node.path.min_samples = 4;
    node.path.mix_kinds = true;
    node.path.switch.margin = 1.5;
    node.path.switch.dwell_secs = 7;
    node.path.probe.active_ms = 250;
    node.path.probe.standby_ms = 3000;
    node.heartbeat_interval_secs = 15;
    let params = path_params(&node);
    let cfg = params.config();
    assert!(cfg.enabled);
    assert_eq!(cfg.min_samples, 4);
    assert!(cfg.mix_kinds);
    assert_eq!(cfg.switch_margin, 1.5);
    assert_eq!(cfg.switch_dwell, Duration::from_secs(7));
    assert_eq!(cfg.active_interval, Duration::from_millis(250));
    assert_eq!(cfg.standby_interval, Duration::from_millis(3000));
    assert_eq!(cfg.heartbeat, Duration::from_secs(15));
    // The default configuration runs multipath disabled.
    assert!(
        !path_params(&crate::config::NodeConfig::default())
            .config()
            .enabled
    );
}

/// A configured heartbeat of zero maps to the node's tick, so the path
/// parameters stay valid and multipath stays enabled.
#[test]
fn a_zero_heartbeat_maps_to_the_tick_and_keeps_multipath_enabled() {
    let mut node = crate::config::NodeConfig::default();
    node.path.enabled = true;
    node.heartbeat_interval_secs = 0;
    let params = path_params(&node);
    assert!(
        params.config().enabled,
        "a zero heartbeat must not turn multipath off"
    );
    assert_eq!(params.config().heartbeat, crate::node::TICK);
}

/// The pair `node`'s link to `peer` holds, as its one path.
fn one_path(tn: &TestNode, peer: &NodeAddr) -> (TransportId, TransportAddr) {
    let peer = tn.node.get_peer(peer).expect("the peer is held");
    let bundle = peer.bundle().expect("promotion builds the bundle");
    let paths = bundle.paths();
    assert_eq!(paths.len(), 1, "a promoted link holds one path");
    let path = paths.get(0).unwrap();
    assert_eq!(path.state(), PathState::Live);
    assert!(
        path.acked(),
        "the original path is acked from the handshake"
    );
    assert_eq!(paths.active_index(), Some(0));
    assert!(!bundle.capable());
    (path.transport_id(), path.addr().clone())
}

/// Promotion builds each peer's bundle with multipath disabled at the link's
/// own pair, with its scope from the facts, so it roams on a path message's
/// frame.
#[tokio::test]
async fn promotion_builds_a_disabled_bundle_at_the_link_pair() {
    let mut nodes = linked_pair(disabled(), disabled()).await;
    for (me, other) in [(0, 1), (1, 0)] {
        let peer = *nodes[other].node.node_addr();
        let pair = one_path(&nodes[me], &peer);
        assert_eq!(pair, (nodes[me].transport_id, nodes[other].addr.clone()));
        let bundle = nodes[me].node.get_peer(&peer).unwrap().bundle().unwrap();
        // A loopback transport is clear and fixes no kind, so the link
        // takes its kind from the peer's address, which is not an IP one.
        assert_eq!(
            bundle.scope(),
            Scope {
                class: Class::Clear,
                kind: Kind::Internet
            }
        );
        // A disabled bundle roams its one path even on a path message's
        // frame (multipath v1 draft, Sections 8.2 and 9.2); an enabled one
        // would not.
        let moved = TransportAddr::from_string("loopback:elsewhere");
        let tid = nodes[me].transport_id;
        let roam = nodes[me].node.get_peer_mut(&peer).unwrap().account(
            peer_now(),
            tid,
            &moved,
            100,
            LinkMessageType::PathProbe.to_byte(),
        );
        assert!(
            matches!(roam.roam, Roam::Roamed { .. }),
            "multipath is disabled: {roam:?}"
        );
    }
    cleanup_nodes(&mut nodes).await;
}

/// The smaller and the larger of a linked pair's two nodes, by address,
/// and the larger's address.
fn smaller_first(nodes: &[TestNode]) -> (usize, usize, NodeAddr) {
    let (s, l) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    (s, l, *nodes[l].node.node_addr())
}

/// Have the smaller node `s` dial the larger `l` again on a second address
/// of `l`'s, which the larger answers and the smaller completes by moving
/// its link onto the new session, as a won crossed handshake does. The link
/// is first made older than the 30 s at which a msg1 counts as a rekey and
/// quiet at `s`, so the dial goes out as one to a peer not heard from.
pub(super) async fn cross_move(nodes: &mut [TestNode], s: usize, l: usize) {
    let l_addr = *nodes[l].node.node_addr();
    age_link(nodes, s, l, Duration::from_secs(31));
    super::control::quieten(&mut nodes[s], &l_addr);
    redial(nodes, s, l).await;
}

/// [`cross_move`] for a peer `l` that is capable at `s`: `s` hears nothing
/// from `l` for 31 s, past link-dead, since until then a capable peer's
/// link is live and is not dialled.
pub(super) async fn cross_move_dead(nodes: &mut [TestNode], s: usize, l: usize) {
    let l_addr = *nodes[l].node.node_addr();
    age_link(nodes, s, l, Duration::from_secs(31));
    quiet_for(&mut nodes[s], &l_addr, 31);
    redial(nodes, s, l).await;
}

/// The dial and the exchange of [`cross_move`], once the link is old and
/// quiet at `s`.
async fn redial(nodes: &mut [TestNode], s: usize, l: usize) {
    let alias = add_loopback_alias(&nodes[l].addr, nodes[l].transport_id);
    let l_npub = nodes[l].node.npub();
    nodes[s]
        .node
        .api_connect(&l_npub, &alias.to_string(), "loopback")
        .await
        .expect("precondition: a dial on the second address starts");
    assert_eq!(deliver(&mut nodes[l]).await, 1, "precondition: one msg1");
    let queued = take_packets(&mut nodes[s]);
    assert_eq!(queued.len(), 1, "precondition: one msg2");
    // A loopback send stamps the sender transport's own address as the
    // source, so `l` answers from its first address whichever of its
    // addresses `s` dialled: the msg2 comes from the pair the link was
    // already on, and the move cannot tell that pair from the msg2's.
    let msg2 = &queued[0];
    assert_eq!(
        (msg2.transport_id, &msg2.remote_addr),
        (nodes[s].transport_id, &nodes[l].addr),
        "precondition: the msg2 comes from the larger node's first address"
    );
    for packet in queued {
        hand(&mut nodes[s], packet).await;
    }
}

/// Take every packet queued at `tn` without handling it.
pub(super) fn take_packets(tn: &mut TestNode) -> Vec<ReceivedPacket> {
    let mut packets = Vec::new();
    while let Ok(packet) = tn.packet_rx.try_recv() {
        packets.push(packet);
    }
    packets
}

/// Hand `packet` to `tn` by its handshake phase, as the receive loop does.
pub(super) async fn hand(tn: &mut TestNode, packet: ReceivedPacket) {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2};
    match CommonPrefix::parse(&packet.data).map(|p| p.phase) {
        Some(PHASE_MSG1) => tn.node.handle_msg1(packet).await,
        Some(PHASE_MSG2) => tn.node.handle_msg2(packet).await,
        Some(PHASE_ESTABLISHED) => tn.node.handle_encrypted_frame(packet).await,
        _ => panic!("an unparseable packet"),
    }
}

/// The phase of a queued packet, if its prefix parses.
pub(super) fn phase(packet: &ReceivedPacket) -> Option<u8> {
    crate::proto::fmp::wire::CommonPrefix::parse(&packet.data).map(|p| p.phase)
}

/// A crossed handshake whose winning dial went out on a second transport
/// starts the smaller node's bundle again on the pair the msg2 came from:
/// the transport and address FMP v1 moves the link to (multipath v1 draft,
/// Section 5.4; FRC-1201, Section 5.6), not the pair the link was on.
#[tokio::test]
async fn a_crossed_dial_starts_the_bundle_on_the_pair_its_msg2_came_from() {
    use crate::proto::fmp::wire::{PHASE_MSG1, PHASE_MSG2};
    let mut nodes = vec![
        make_test_node_with_config(enabled(), 1280).await,
        make_test_node_with_config(enabled(), 1280).await,
    ];
    let seconds = [
        second_transport(&mut nodes[0], t2(), 1280),
        second_transport(&mut nodes[1], t2(), 1280),
    ];
    let (s, l, l_addr) = smaller_first(&nodes);
    let s_addr = *nodes[s].node.node_addr();
    let l2 = seconds[l].clone();
    let l_id = PeerIdentity::from_pubkey_full(nodes[l].node.identity().pubkey_full());
    let s_id = PeerIdentity::from_pubkey_full(nodes[s].node.identity().pubkey_full());
    // `s` dials `l` on its second transport, at `l`'s second address; `l`
    // dials `s` on its first, at `s`'s first address.
    nodes[s]
        .node
        .initiate_connection(t2(), l2.clone(), l_id)
        .await
        .expect("precondition: s's dial starts");
    let s1 = nodes[s].addr.clone();
    let t1 = nodes[l].transport_id;
    nodes[l]
        .node
        .initiate_connection(t1, s1, s_id)
        .await
        .expect("precondition: l's dial starts");
    let outbound = {
        let keys: Vec<_> = nodes[s].node.pending_outbound.keys().copied().collect();
        assert_eq!(keys.len(), 1, "precondition: s has one dial pending");
        assert_eq!(keys[0].0, t2(), "precondition: s's dial is on t2");
        SessionIndex::new(keys[0].1)
    };

    // `l` takes `s`'s msg1 and answers it; then `s` takes `l`'s msg1,
    // before the msg2.
    let at_l = take_packets(&mut nodes[l]);
    assert_eq!(at_l.len(), 1, "precondition: one packet at l");
    assert_eq!(phase(&at_l[0]), Some(PHASE_MSG1), "precondition: s's msg1");
    for packet in at_l {
        hand(&mut nodes[l], packet).await;
    }
    assert!(
        nodes[l].node.get_peer(&s_addr).is_some(),
        "precondition: l promoted on s's msg1"
    );
    let mut at_s = take_packets(&mut nodes[s]).into_iter();
    let msg1 = at_s.next().expect("precondition: l's msg1 at s");
    assert_eq!(
        phase(&msg1),
        Some(PHASE_MSG1),
        "precondition: l's msg1 first"
    );
    hand(&mut nodes[s], msg1).await;
    let before = nodes[s]
        .node
        .get_peer(&l_addr)
        .expect("precondition: s promoted on l's msg1")
        .our_index();
    assert_ne!(
        before,
        Some(outbound),
        "precondition: s is on its inbound session"
    );
    let msg2 = at_s.next().expect("precondition: l's msg2 at s");
    assert_eq!(
        phase(&msg2),
        Some(PHASE_MSG2),
        "precondition: l's msg2 second"
    );
    assert_eq!(
        (msg2.transport_id, &msg2.remote_addr),
        (t2(), &l2),
        "precondition: the msg2 came on t2 from l's second address"
    );
    hand(&mut nodes[s], msg2).await;
    for packet in at_s {
        hand(&mut nodes[s], packet).await;
    }
    assert_eq!(
        nodes[s].node.get_peer(&l_addr).unwrap().our_index(),
        Some(outbound),
        "precondition: s swapped to its outbound session"
    );

    let paths = {
        let bundle = nodes[s].node.get_peer(&l_addr).unwrap().bundle().unwrap();
        assert!(!bundle.capable(), "the bundle starts again not capable");
        let paths = bundle.paths();
        (0..paths.len())
            .map(|i| {
                let path = paths.get(i).unwrap();
                (path.transport_id(), path.addr().clone())
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        paths,
        vec![(t2(), l2.clone())],
        "the bundle starts again on the pair the msg2 came from"
    );

    // What `s` sends now reaches `l` and authenticates.
    deliver(&mut nodes[l]).await;
    let received = nodes[l]
        .node
        .get_peer(&s_addr)
        .unwrap()
        .link_stats()
        .packets_recv;
    super::rekey_parity::heartbeat(&mut nodes[s], &l_addr).await;
    deliver(&mut nodes[l]).await;
    let peer = nodes[l].node.get_peer(&s_addr).expect("l keeps s");
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "no decrypt failure at l"
    );
    assert!(
        peer.link_stats().packets_recv > received,
        "s's frame after the move reached l"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A node that redials its capable peer, once the link is dead to it, at
/// the pair of a standby path it holds, and moves its link there when the
/// answer comes from that pair (FRC-1201, Section 5.6), keeps the
/// connection at that pair: the renewed bundle holds that path as the new
/// link's original path (multipath v1 draft, Section 5.4) rather than
/// releasing it, so no close of the connection the link now sends on
/// follows.
#[tokio::test]
async fn a_redial_answered_from_a_held_standby_keeps_the_connection_the_link_moves_to() {
    use crate::proto::fmp::wire::PHASE_MSG2;
    let (mut nodes, b, _a2, b2) = two_transports(1280).await;
    let t1 = nodes[0].transport_id;
    let b1 = nodes[1].addr.clone();
    assert!(capable_at(&nodes[0], &b), "precondition: B capable at A");
    assert_eq!(
        active_of(&nodes[0], &b),
        (t1, b1.clone()),
        "precondition: p active"
    );
    let index = nodes[0].node.get_peer(&b).unwrap().our_index();
    age_link(&mut nodes, 0, 1, Duration::from_secs(31));
    quiet_for(&mut nodes[0], &b, 31);
    let b_id = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    nodes[0]
        .node
        .initiate_connection(t2(), b2.clone(), b_id)
        .await
        .expect("precondition: A's dial on t2 starts");
    assert_eq!(
        deliver(&mut nodes[1]).await,
        1,
        "precondition: one msg1 at B"
    );
    let queued = take_packets(&mut nodes[0]);
    assert!(
        queued
            .iter()
            .any(|p| phase(p) == Some(PHASE_MSG2) && p.transport_id == t2() && p.remote_addr == b2),
        "precondition: B's msg2 came on t2 from B2: {:?}",
        queued
            .iter()
            .map(|p| (phase(p), p.transport_id, p.remote_addr.clone()))
            .collect::<Vec<_>>()
    );
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    for packet in queued {
        hand(&mut nodes[0], packet).await;
    }
    assert_ne!(
        nodes[0].node.get_peer(&b).unwrap().our_index(),
        index,
        "precondition: the link moved to the new session"
    );
    assert_eq!(
        active_of(&nodes[0], &b),
        (t2(), b2.clone()),
        "precondition: the link is at q's pair"
    );
    nodes[0].node.path_tick().await;
    let closed = logs.lines_with("Closed a released path's connection");
    drop(guard);
    assert!(
        !closed
            .iter()
            .any(|l| l.contains(&format!("remote_addr={b2}"))),
        "A closed the connection at the pair its link moved to: {closed:#?}"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A won crossed handshake starts the link again with a new original `path_id`
/// at the same pair, and the path's count of failures carries over.
#[tokio::test]
async fn a_won_cross_connection_starts_the_link_with_a_new_bundle() {
    let mut nodes = linked_pair(Config::new(), Config::new()).await;
    let (s, l, l_addr) = smaller_first(&nodes);
    let (tid, addr) = one_path(&nodes[s], &l_addr);
    let (before, index) = {
        let peer = nodes[s].node.get_peer_mut(&l_addr).unwrap();
        let bundle = peer.bundle_mut().unwrap();
        for _ in 0..3 {
            bundle.charge(peer_now(), tid, &addr);
        }
        let path = bundle.paths().get(0).unwrap();
        assert_eq!(path.live().fails(), 3, "precondition: three failures");
        (path.path_id(), peer.our_index())
    };

    cross_move(&mut nodes, s, l).await;

    let peer = nodes[s].node.get_peer(&l_addr).unwrap();
    assert_ne!(peer.our_index(), index, "precondition: the link moved");
    assert_eq!(one_path(&nodes[s], &l_addr), (tid, addr));
    let path = peer.bundle().unwrap().paths().get(0).unwrap();
    assert_ne!(path.path_id(), before, "a new link's original path");
    assert_eq!(path.live().fails(), 3, "the failure count carried");
    cleanup_nodes(&mut nodes).await;
}

/// A configuration with multipath enabled.
pub(super) fn enabled() -> Config {
    let mut config = Config::new();
    config.node.path.enabled = true;
    config
}

/// A configuration with multipath disabled, for a test of that setting or of
/// a peer without multipath, which must not follow the daemon's default.
pub(super) fn disabled() -> Config {
    let mut config = Config::new();
    config.node.path.enabled = false;
    config
}

/// Give `tn` a second loopback transport `id` with MTU `mtu` at an address
/// of its own, and return the address. A packet sent to it reaches `tn` on
/// `id`; one sent from it carries that address as its source.
pub(super) fn second_transport(tn: &mut TestNode, id: TransportId, mtu: u16) -> TransportAddr {
    let addr = add_loopback_alias(&tn.addr, id);
    let lo = crate::transport::loopback::LoopbackTransport::with_mtu(
        id,
        addr.clone(),
        mtu,
        super::spanning_tree::LOOPBACK_REGISTRY.clone(),
    );
    tn.node.transports.insert(id, TransportHandle::Loopback(lo));
    addr
}

/// The state of `tn`'s path to `peer` at (`transport`, `addr`), if held.
pub(super) fn state_at(
    tn: &TestNode,
    peer: &NodeAddr,
    transport: TransportId,
    addr: &TransportAddr,
) -> Option<PathState> {
    let paths = tn.node.get_peer(peer)?.bundle()?.paths();
    paths
        .find(transport, addr)
        .map(|i| paths.get(i).unwrap().state())
}

/// Two linked nodes with multipath enabled, A (0) dialling B (1), where A
/// holds p, its original path (t1, B1), and q (t1, B2), a second address
/// of B's on the same transport, both Live, p active: A offers q, its
/// capability probe on p is answered, and its probe on q is answered.
pub(super) async fn same_transport() -> (Vec<TestNode>, NodeAddr, TransportAddr) {
    same_transport_with(enabled()).await
}

/// [`same_transport`] with A built from `a`.
pub(super) async fn same_transport_with(a: Config) -> (Vec<TestNode>, NodeAddr, TransportAddr) {
    let mut nodes = linked_pair(a, enabled()).await;
    let b = *nodes[1].node.node_addr();
    let b2 = add_loopback_alias(&nodes[1].addr, nodes[1].transport_id);
    let t1 = nodes[0].transport_id;
    nodes[0].node.offer_path(&b, t1, b2.clone()).await;
    super::rekey_parity::pump(&mut nodes).await;
    let b1 = nodes[1].addr.clone();
    assert_eq!(state_at(&nodes[0], &b, t1, &b1), Some(PathState::Live));
    assert_eq!(
        state_at(&nodes[0], &b, t1, &b2),
        Some(PathState::Live),
        "precondition: q is Live at A"
    );
    (nodes, b, b2)
}

/// The second transport each node of a two-transport pair holds.
pub(super) fn t2() -> TransportId {
    TransportId::new(2)
}

/// Two linked nodes with multipath enabled, A (0) dialling B (1), each
/// with a second loopback transport `t2()`, A's of MTU `mtu`, where A holds
/// p, its original path (t1, B1), and q (`t2()`, B2), both Live, p active:
/// A offers q, its capability probe on p is answered, and its probe on q
/// is answered. Returns the nodes, B's address, and A's and B's second
/// addresses.
pub(super) async fn two_transports(
    mtu: u16,
) -> (Vec<TestNode>, NodeAddr, TransportAddr, TransportAddr) {
    transports_with(enabled(), mtu).await
}

/// [`two_transports`] with A built from `a`.
pub(super) async fn transports_with(
    a: Config,
    mtu: u16,
) -> (Vec<TestNode>, NodeAddr, TransportAddr, TransportAddr) {
    let mut nodes = linked_pair(a, enabled()).await;
    let a2 = second_transport(&mut nodes[0], t2(), mtu);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    let b = *nodes[1].node.node_addr();
    nodes[0].node.offer_path(&b, t2(), b2.clone()).await;
    super::rekey_parity::pump(&mut nodes).await;
    assert_eq!(
        state_at(&nodes[0], &b, t2(), &b2),
        Some(PathState::Live),
        "precondition: q is Live at A"
    );
    (nodes, b, a2, b2)
}

/// A path probe of `len` bytes from the sender's path `path_id`, as a
/// link message.
pub(super) fn probe(path_id: u32, len: usize) -> Vec<u8> {
    PathProbe::new(
        7,
        path_id,
        PathFlags::default(),
        PathCaps::with_aggregate(false),
    )
    .with_len(len)
    .encode()
}

/// Take every packet queued at `tn` without handling it, with the
/// transport it arrived on and its source.
fn take_queued(tn: &mut TestNode) -> Vec<(TransportId, TransportAddr)> {
    let mut seen = Vec::new();
    while let Ok(packet) = tn.packet_rx.try_recv() {
        seen.push((packet.transport_id, packet.remote_addr));
    }
    seen
}

/// Handle every packet queued at `tn` as though it came from `from`.
pub(super) async fn deliver_from(tn: &mut TestNode, from: &TransportAddr) {
    while let Ok(mut packet) = tn.packet_rx.try_recv() {
        packet.remote_addr = from.clone();
        tn.node.handle_encrypted_frame(packet).await;
    }
}

/// The loopback transport `id` of `tn`.
pub(super) fn loopback(
    tn: &TestNode,
    id: TransportId,
) -> &crate::transport::loopback::LoopbackTransport {
    match tn.node.transports.get(&id) {
        Some(TransportHandle::Loopback(t)) => t,
        _ => panic!("transport {id} is a loopback transport"),
    }
}

/// The loopback transport `id` of `tn`, to change.
pub(super) fn loopback_mut(
    tn: &mut TestNode,
    id: TransportId,
) -> &mut crate::transport::loopback::LoopbackTransport {
    match tn.node.transports.get_mut(&id) {
        Some(TransportHandle::Loopback(t)) => t,
        _ => panic!("transport {id} is a loopback transport"),
    }
}

/// Each end of a path message leaves a line, so two nodes' logs say which
/// direction lost one: the probe at its receiver, the ack back at the prober.
#[tokio::test]
async fn a_received_probe_and_its_ack_each_leave_a_received_line() {
    let (logs, _guard) = crate::testutil::capture_logs_scoped();
    let mut nodes = linked_pair(enabled(), enabled()).await;
    let b = *nodes[1].node.node_addr();
    nodes[0]
        .node
        .send_encrypted_link_message(&b, &probe(0x1234, 64))
        .await
        .expect("precondition: the probe goes out on the link");
    assert_eq!(
        deliver(&mut nodes[1]).await,
        1,
        "precondition: B delivers the probe"
    );
    assert_eq!(
        deliver(&mut nodes[0]).await,
        1,
        "precondition: A delivers the ack"
    );
    let lines = logs.lines_with("Path message received");
    let seen: Vec<_> = lines
        .iter()
        .map(|line| {
            (
                crate::testutil::log_field(line, "msg_type"),
                crate::testutil::log_field(line, "transport_id").is_some(),
                crate::testutil::log_field(line, "remote_addr").is_some(),
                crate::testutil::log_field(line, "len").is_some(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            (Some("82"), true, true, true),
            (Some("83"), true, true, true)
        ],
        "one line for the probe and one for the ack: {lines:?}"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A node with multipath disabled discards a path probe, answers nothing, and
/// is not made capable by it.
#[tokio::test]
async fn a_disabled_node_discards_a_probe_and_sends_nothing() {
    let mut nodes = linked_pair(disabled(), disabled()).await;
    let b = *nodes[1].node.node_addr();
    let a = *nodes[0].node.node_addr();
    nodes[0]
        .node
        .send_encrypted_link_message(&b, &probe(0x1234, 64))
        .await
        .expect("the probe goes out on the link");
    assert_eq!(deliver(&mut nodes[1]).await, 1, "B delivers the probe");
    assert_eq!(
        take_queued(&mut nodes[0]),
        [],
        "a node with multipath disabled answers nothing"
    );
    let bundle = nodes[1].node.get_peer(&a).unwrap().bundle().unwrap();
    assert_eq!(bundle.paths().len(), 1);
    assert!(!bundle.capable(), "a discarded probe makes no peer capable");
    cleanup_nodes(&mut nodes).await;
}

/// A path probe is answered on the pair it arrived on, not the active pair, and
/// the receiver holds a Probing path there.
#[tokio::test]
async fn a_probe_is_answered_on_the_pair_it_arrived_on() {
    let mut nodes = linked_pair(enabled(), enabled()).await;
    let a2 = second_transport(&mut nodes[0], t2(), 1280);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    let via = PathRef {
        transport: t2(),
        addr: b2.clone(),
    };
    nodes[0]
        .node
        .send_via(&b, &probe(0x2345, 64), false, Some(&via))
        .await
        .expect("the probe goes out on A's second transport");
    assert_eq!(deliver(&mut nodes[1]).await, 1, "B delivers the probe");
    // The ack is padded to the probe's 64 bytes. B, capable now and
    // holding two paths, also probes its paths, on each one's own pair.
    let ack_len = 64 + crate::proto::fmp::wire::FRAME_OVERHEAD;
    let mut acks = Vec::new();
    while let Ok(packet) = nodes[0].packet_rx.try_recv() {
        if packet.data.len() == ack_len {
            acks.push((packet.transport_id, packet.remote_addr));
        }
    }
    assert_eq!(
        acks,
        [(t2(), b2.clone())],
        "B answers on the pair the probe came from"
    );
    assert_eq!(state_at(&nodes[1], &a, t2(), &a2), Some(PathState::Probing));
    cleanup_nodes(&mut nodes).await;
}

/// Build two nodes with multipath enabled, let `prep` change their
/// transports before they link, and link them, A (0) dialling B (1).
pub(super) async fn prepared_pair(prep: impl FnOnce(&mut [TestNode])) -> Vec<TestNode> {
    prepared_pair_with(enabled(), prep).await
}

/// As [`prepared_pair`], with both nodes built from `config`.
async fn prepared_pair_with(config: Config, prep: impl FnOnce(&mut [TestNode])) -> Vec<TestNode> {
    let mut nodes = vec![
        super::spanning_tree::make_test_node_with_config(config.clone(), 1280).await,
        super::spanning_tree::make_test_node_with_config(config, 1280).await,
    ];
    prep(&mut nodes);
    super::spanning_tree::initiate_handshake(&mut nodes, 0, 1).await;
    super::spanning_tree::drain_all_packets(&mut nodes, false).await;
    let b = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&b).is_some(), "precondition: linked");
    nodes
}

/// Give `tn` a loopback transport `id` whose own address is `addr`.
pub(super) fn transport_at(tn: &mut TestNode, id: TransportId, addr: &str) -> TransportAddr {
    let registry = &super::spanning_tree::LOOPBACK_REGISTRY;
    let (_, tx) = registry.lock().unwrap().get(&tn.addr).unwrap().clone();
    let addr = TransportAddr::from_string(addr);
    registry.lock().unwrap().insert(addr.clone(), (id, tx));
    let lo =
        crate::transport::loopback::LoopbackTransport::new(id, addr.clone(), (*registry).clone());
    tn.node.transports.insert(id, TransportHandle::Loopback(lo));
    addr
}

/// A probes B from A's transport `from` to B's second address `b2`, B
/// delivers it, and the packets A then holds are dropped. Returns B's path
/// state at the probe's source, if B holds one.
async fn probe_b(
    nodes: &mut [TestNode],
    from: TransportId,
    source: &TransportAddr,
    b2: &TransportAddr,
) -> Option<PathState> {
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    let via = PathRef {
        transport: from,
        addr: b2.clone(),
    };
    nodes[0]
        .node
        .send_via(&b, &probe(0x3456 + from.as_u32(), 64), false, Some(&via))
        .await
        .expect("the probe goes out");
    deliver(&mut nodes[1]).await;
    take_queued(&mut nodes[0]);
    state_at(&nodes[1], &a, t2(), source)
}

/// The probe rules read their facts from the transports: a probe of another
/// class, or on a transport that accepts no handshake, makes no path, and,
/// with `mix_kinds` off, a link over Ethernet takes a local path and no
/// Internet one.
#[tokio::test]
async fn policy_facts_come_from_the_configuration() {
    // (a) The link runs over Tor: a probe on B's clear transport is refused.
    let mut nodes = prepared_pair(|n| {
        loopback_mut(&mut n[1], TransportId::new(1)).typed(crate::transport::TransportType::TOR)
    })
    .await;
    let a2 = second_transport(&mut nodes[0], t2(), 1280);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    assert_eq!(
        probe_b(&mut nodes, t2(), &a2, &b2).await,
        None,
        "another class"
    );
    cleanup_nodes(&mut nodes).await;

    // (b) B's second transport accepts no handshake: no path is made there.
    let mut nodes = linked_pair(enabled(), enabled()).await;
    let a2 = second_transport(&mut nodes[0], t2(), 1280);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    loopback(&nodes[1], t2()).set_accepts(false);
    assert_eq!(
        probe_b(&mut nodes, t2(), &a2, &b2).await,
        None,
        "not accepted"
    );
    cleanup_nodes(&mut nodes).await;

    // (c) With `mix_kinds` off, an Ethernet link takes local paths only: B's
    // UDP transport makes a path to a private address and none to a public
    // one.
    let mut unmixed = enabled();
    unmixed.node.path.mix_kinds = false;
    let mut nodes = prepared_pair_with(unmixed, |n| {
        loopback_mut(&mut n[1], TransportId::new(1))
            .typed(crate::transport::TransportType::ETHERNET)
    })
    .await;
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    loopback_mut(&mut nodes[1], t2()).typed(crate::transport::TransportType::UDP);
    let local = transport_at(&mut nodes[0], t2(), "192.168.7.2:2121");
    let public = transport_at(&mut nodes[0], TransportId::new(3), "8.8.4.4:2121");
    assert_eq!(
        probe_b(&mut nodes, t2(), &local, &b2).await,
        Some(PathState::Probing),
        "a local address on a UDP transport"
    );
    assert_eq!(
        probe_b(&mut nodes, TransportId::new(3), &public, &b2).await,
        None,
        "an Internet address beside a local link"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A peer the peer ACL denies after its link came up creates no path by
/// probing: B's ACL is reloaded to deny A, so B would refuse A's handshake
/// on every transport, and A's probe from a second transport makes no path
/// at B (multipath draft Section 5.5). The link itself stays.
#[tokio::test]
async fn a_probe_from_a_peer_the_acl_denies_after_link_up_creates_no_path() {
    let mut nodes = linked_pair(enabled(), enabled()).await;
    let a2 = second_transport(&mut nodes[0], t2(), 1280);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    let a = *nodes[0].node.node_addr();
    let dir = tempfile::tempdir().unwrap();
    let deny = dir.path().join("peers.deny");
    std::fs::write(&deny, format!("{}\n", nodes[0].node.npub())).unwrap();
    nodes[1]
        .node
        .isolate_peer_acl_for_test(dir.path().join("peers.allow"), deny);
    nodes[1].node.reload_peer_acl().await;
    let a_id = crate::PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
    assert!(
        nodes[1]
            .node
            .authorize_peer(
                &a_id,
                crate::node::acl::PeerAclContext::InboundHandshake,
                t2(),
                &a2,
            )
            .is_err(),
        "precondition: B would refuse A's handshake on t2"
    );
    assert!(nodes[1].node.get_peer(&a).is_some(), "the link stays");
    let created = probe_b(&mut nodes, t2(), &a2, &b2).await;
    cleanup_nodes(&mut nodes).await;
    assert_eq!(created, None, "B created a path from a denied peer's probe");
}

/// The control for the denied peer: in the same setup without the ACL
/// reload, A's probe from a second transport creates a Probing path at B.
#[tokio::test]
async fn a_probe_on_a_second_transport_from_an_allowed_peer_creates_a_probing_path() {
    let mut nodes = linked_pair(enabled(), enabled()).await;
    let a2 = second_transport(&mut nodes[0], t2(), 1280);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    let created = probe_b(&mut nodes, t2(), &a2, &b2).await;
    cleanup_nodes(&mut nodes).await;
    assert_eq!(created, Some(PathState::Probing));
}

/// The IPv6 address the path MTU lookup keys `node` under.
fn fips(node: &NodeAddr) -> crate::Ipv6Address {
    crate::Ipv6Address::from_node_addr(node)
}

/// B closes A's path p, sending the `PathClose` so that it reaches A on q
/// at `b2`, and A handles it.
pub(super) async fn shut_p(nodes: &mut [TestNode], b: &NodeAddr, b2: &TransportAddr) {
    let a = *nodes[0].node.node_addr();
    let t1 = nodes[0].transport_id;
    let b1 = nodes[1].addr.clone();
    let paths = nodes[0].node.get_peer(b).unwrap().bundle().unwrap().paths();
    let p_id = paths.get(paths.find(t1, &b1).unwrap()).unwrap().path_id();
    let close = PathClose {
        path_id: p_id,
        reason: PathCloseReason::Operator,
    };
    nodes[1]
        .node
        .send_encrypted_link_message(&a, &close.encode())
        .await
        .expect("B's close goes out");
    deliver_from(&mut nodes[0], b2).await;
}

/// The pair `tn`'s link to `peer` sends on.
pub(super) fn active_of(tn: &TestNode, peer: &NodeAddr) -> (TransportId, TransportAddr) {
    let path = tn.node.get_peer(peer).unwrap().active_path().unwrap();
    (path.transport_id(), path.addr().clone())
}

/// A switch to another path on the same transport seeds the new path's MTU in
/// place of the value learned on the old one.
#[tokio::test]
async fn a_switch_on_one_transport_replaces_the_value_learned_on_the_old_path() {
    let (mut nodes, b, b2) = same_transport().await;
    let t1 = nodes[0].transport_id;
    assert_eq!(nodes[0].node.path_mtu_lookup_get(&fips(&b)), Some(1280));
    nodes[0]
        .node
        .path_mtu_lookup_learn(fips(&b), 900, crate::time::mono_ms());
    assert_eq!(nodes[0].node.path_mtu_lookup_get(&fips(&b)), Some(900));

    shut_p(&mut nodes, &b, &b2).await;

    assert_eq!(active_of(&nodes[0], &b), (t1, b2.clone()), "A moved to q");
    assert_eq!(
        nodes[0].node.path_mtu_lookup_get(&fips(&b)),
        Some(1280),
        "the switch seeds q's MTU in place of the value learned on p"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Handle the one packet queued at `tn`, which arrived on `transport`.
async fn handle_one_on(tn: &mut TestNode, transport: TransportId) {
    let packet = tn.packet_rx.try_recv().expect("a packet is queued");
    assert_eq!(
        packet.transport_id, transport,
        "the packet came on {transport}"
    );
    assert!(
        tn.packet_rx.try_recv().is_err(),
        "only one packet is queued"
    );
    tn.node.handle_encrypted_frame(packet).await;
}

/// Draft 5.12: the echo in a node's `ReceiverReport` comes from a frame on
/// the peer's active path, so a probe on a standby whose transit is far
/// longer does not move the round trip the peer derives from the report.
///
/// B's heartbeat on p, its active path, reaches A 30 ms after it is sent;
/// 70 ms later B's probe on q reaches A 400 ms after it is sent; 10 ms
/// after that A builds its report. The echo is then the heartbeat's
/// timestamp and the dwell runs from the heartbeat's arrival, 70 + 400 +
/// 10 = 480 ms, so B's sample is now - echo - dwell = 510 - 480 = 30 ms.
/// Echoing the probe would give a dwell of 10 ms and a sample of 510 -
/// 100 - 10 = 400 ms. The clock is frozen, so no figure carries the real
/// time the test takes. The sample is a difference of four clock readings,
/// each truncated to the millisecond, so it can read up to 2 ms under 30.
/// Mutation: pass `sample: true` for every frame in `account_authentic`.
#[tokio::test]
async fn a_standby_probe_does_not_move_the_round_trip_the_peer_derives_from_our_report() {
    // With the clock running, time the test spends descheduled adds to the
    // dwell and the sample, and can carry them past their bounds.
    crate::time::freeze();
    let (mut nodes, b, a2, b2) = two_transports(1280).await;
    // The clock has not moved since the session began, and a timestamp of
    // 0 reads as no echo, so B's heartbeat goes out 10 ms in.
    crate::time::advance(Duration::from_millis(10));
    let a = *nodes[0].node.node_addr();
    let t1 = nodes[0].transport_id;
    let on_q = PathRef {
        transport: t2(),
        addr: a2,
    };
    let stamp = |nodes: &[TestNode]| nodes[1].node.get_peer(&a).unwrap().session_elapsed_ms();
    let received = |nodes: &[TestNode]| {
        let peer = nodes[0].node.get_peer(&b).unwrap();
        peer.mmp().unwrap().receiver.cumulative_packets_recv()
    };
    let heartbeat = [LinkMessageType::Heartbeat.to_byte()];

    let sent_lo = stamp(&nodes);
    nodes[1]
        .node
        .send_via(&a, &heartbeat, false, None)
        .await
        .expect("B's heartbeat goes out on p");
    let sent_hi = stamp(&nodes);
    crate::time::advance(Duration::from_millis(30));
    handle_one_on(&mut nodes[0], t1).await;

    crate::time::advance(Duration::from_millis(70));
    let paths = nodes[0]
        .node
        .get_peer(&b)
        .unwrap()
        .bundle()
        .unwrap()
        .paths();
    let q_peer = paths
        .get(paths.find(t2(), &b2).unwrap())
        .unwrap()
        .peer_id()
        .expect("q learned the peer's identifier");
    let probed = stamp(&nodes);
    let before = received(&nodes);
    nodes[1]
        .node
        .send_via(&a, &probe(q_peer, 64), false, Some(&on_q))
        .await
        .expect("B's probe goes out on q");
    crate::time::advance(Duration::from_millis(400));
    handle_one_on(&mut nodes[0], t2()).await;
    assert_eq!(
        received(&nodes),
        before + 1,
        "precondition: A's receiver counted the probe"
    );

    crate::time::advance(Duration::from_millis(10));
    let rr = nodes[0]
        .node
        .get_peer_mut(&b)
        .unwrap()
        .mmp_mut()
        .unwrap()
        .receiver
        .build_report(crate::time::mono_ms())
        .expect("A has a report to send");
    assert!(
        (sent_lo..=sent_hi).contains(&rr.timestamp_echo),
        "the echo {} is the heartbeat's timestamp, sent in {sent_lo}..={sent_hi}, \
         not the probe's, {probed} or later",
        rr.timestamp_echo
    );
    assert!(
        (480..680).contains(&rr.dwell_time),
        "the dwell {} runs from the heartbeat's arrival",
        rr.dwell_time
    );

    nodes[1]
        .node
        .handle_receiver_report(&a, &rr.encode()[1..])
        .await;
    let sample = stamp(&nodes) - rr.timestamp_echo - u32::from(rr.dwell_time);
    assert!(
        (28..230).contains(&sample),
        "B's sample from the report, {sample} ms, is p's 30 ms, not q's 400 ms"
    );
    let taken = nodes[1].node.get_peer(&a).unwrap().mmp().unwrap();
    let taken = taken.metrics.last_rtt_ms().expect("B took a sample");
    assert!(
        (28..=sample).contains(&taken),
        "B took the sample, {taken} ms, from the report"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Frames from the peer only on a standby path, for longer than the link-dead
/// timeout, keep the link alive.
#[tokio::test]
async fn a_frame_on_a_standby_path_keeps_the_link_alive() {
    let (mut nodes, b, a2, _b2) = two_transports(1280).await;
    let a = *nodes[0].node.node_addr();
    let on_q = PathRef {
        transport: t2(),
        addr: a2.clone(),
    };
    let heartbeat = [crate::proto::link::LinkMessageType::Heartbeat.to_byte()];
    // 35 s, past the 30 s link-dead floor, with B's frames only on q.
    for _ in 0..7 {
        crate::time::advance(Duration::from_secs(5));
        nodes[1]
            .node
            .send_via(&a, &heartbeat, false, Some(&on_q))
            .await
            .expect("B's heartbeat goes out on q");
        assert_eq!(deliver(&mut nodes[0]).await, 1);
    }
    nodes[0].node.check_link_heartbeats().await;
    assert!(
        nodes[0].node.get_peer(&b).is_some(),
        "frames on a standby path keep the link alive"
    );
    cleanup_nodes(&mut nodes).await;
}

/// After a switch both pairs map to the link; a released pair no longer maps to
/// it, and a moved path's entry moves with it.
#[tokio::test]
async fn a_switch_points_addr_to_link_at_the_new_pair_and_releases_follow_it() {
    let (mut nodes, b, b2) = same_transport().await;
    let t1 = nodes[0].transport_id;
    let b1 = nodes[1].addr.clone();
    let link = nodes[0].node.get_peer(&b).unwrap().link_id();
    let maps = |tn: &TestNode, addr: &TransportAddr| {
        tn.node.links.index().get(&(t1, addr.clone())) == Some(&link)
    };
    shut_p(&mut nodes, &b, &b2).await;
    assert_eq!(active_of(&nodes[0], &b), (t1, b2.clone()));
    assert!(maps(&nodes[0], &b1), "the link's own pair still maps to it");
    assert!(maps(&nodes[0], &b2), "the new active pair maps to the link");

    // p, Dead since the close, is released once its grace has passed.
    super::rekey_parity::pump(&mut nodes).await;
    crate::time::advance(Duration::from_secs(601));
    nodes[0].node.step_path(&b, Input::Poll).await;
    assert_eq!(state_at(&nodes[0], &b, t1, &b1), None, "p is released");
    assert!(
        !maps(&nodes[0], &b1),
        "a released pair no longer maps to the link"
    );
    assert!(maps(&nodes[0], &b2));

    // q's probe from a third address moves q, and its entry with it.
    let b3 = TransportAddr::from_string("loopback:inc4-moved");
    let paths = nodes[0]
        .node
        .get_peer(&b)
        .unwrap()
        .bundle()
        .unwrap()
        .paths();
    let q_peer = paths
        .get(paths.find(t1, &b2).unwrap())
        .unwrap()
        .peer_id()
        .expect("q learned the peer's identifier");
    let a = *nodes[0].node.node_addr();
    nodes[1]
        .node
        .send_encrypted_link_message(&a, &probe(q_peer, 64))
        .await
        .expect("B's probe goes out");
    deliver_from(&mut nodes[0], &b3).await;
    assert_eq!(state_at(&nodes[0], &b, t1, &b2), None, "q left B2");
    assert!(state_at(&nodes[0], &b, t1, &b3).is_some(), "q is at B3");
    assert!(!maps(&nodes[0], &b2));
    assert!(maps(&nodes[0], &b3), "the moved path's entry follows it");
    cleanup_nodes(&mut nodes).await;
}

/// B sends a heartbeat that reaches A on `via`, B's pair for that path,
/// or on B's active path when `via` is `None`, and A handles it.
pub(super) async fn beat(nodes: &mut [TestNode], via: Option<&PathRef>) {
    let a = *nodes[0].node.node_addr();
    let heartbeat = [crate::proto::link::LinkMessageType::Heartbeat.to_byte()];
    nodes[1]
        .node
        .send_via(&a, &heartbeat, false, via)
        .await
        .expect("B's heartbeat goes out");
    assert_eq!(deliver(&mut nodes[0]).await, 1);
}

/// Removing a capable peer closes the connections of the paths the peer does
/// not send on and keeps open the one it does, whichever path that is.
#[tokio::test]
async fn removal_closes_the_paths_the_peer_does_not_send_on_and_keeps_the_one_it_does() {
    let t1 = TransportId::new(1);
    for peer_on_q in [true, false] {
        let (mut nodes, b, a2, b2) = two_transports(1280).await;
        let b1 = nodes[1].addr.clone();
        let on_q = PathRef {
            transport: t2(),
            addr: a2,
        };
        beat(&mut nodes, peer_on_q.then_some(&on_q)).await;
        nodes[0].node.remove_active_peer(&b);
        nodes[0].node.drain_closes().await;
        let (closed_t1, closed_t2) = (
            loopback(&nodes[0], t1).closed(),
            loopback(&nodes[0], t2()).closed(),
        );
        if peer_on_q {
            assert_eq!(
                (closed_t1, closed_t2),
                (vec![b1], vec![]),
                "p closes, q stays"
            );
        } else {
            assert_eq!(
                (closed_t1, closed_t2),
                (vec![], vec![b2]),
                "q closes, p stays"
            );
        }
        cleanup_nodes(&mut nodes).await;
    }
}

/// Removing a peer whose link is not known to be capable closes no connection.
#[tokio::test]
async fn removing_a_peer_whose_link_is_not_capable_closes_nothing() {
    let mut nodes = vec![
        super::spanning_tree::make_test_node().await,
        super::spanning_tree::make_test_node().await,
    ];
    super::spanning_tree::initiate_handshake(&mut nodes, 0, 1).await;
    assert_eq!(deliver(&mut nodes[1]).await, 1, "B promotes on A's msg1");
    let a = *nodes[0].node.node_addr();
    assert!(
        nodes[1].node.get_peer(&a).is_some(),
        "precondition: B holds A, and no frame of A's has been accounted"
    );
    nodes[1].node.remove_active_peer(&a);
    nodes[1].node.drain_closes().await;
    assert_eq!(loopback(&nodes[1], TransportId::new(1)).closed(), []);
    cleanup_nodes(&mut nodes).await;
}

/// On a capable link, the original path's connection closes when that path is
/// discarded past its grace, and the peer is kept.
#[tokio::test]
async fn a_capable_links_original_connection_closes_when_its_path_is_discarded() {
    let (mut nodes, b, a2, _b2) = two_transports(1280).await;
    let t1 = TransportId::new(1);
    let b1 = nodes[1].addr.clone();
    loopback_mut(&mut nodes[0], t1).typed(crate::transport::TransportType::TCP);
    let on_q = PathRef {
        transport: t2(),
        addr: a2,
    };
    beat(&mut nodes, Some(&on_q)).await;
    nodes[0].node.get_peer_mut(&b).unwrap().kill_path(t1, &b1);
    nodes[0].node.step_path(&b, Input::Poll).await;
    super::rekey_parity::pump(&mut nodes).await;
    crate::time::advance(Duration::from_secs(601));
    nodes[0].node.step_path(&b, Input::Poll).await;
    assert_eq!(state_at(&nodes[0], &b, t1, &b1), None, "p is discarded");
    assert!(nodes[0].node.get_peer(&b).is_some(), "the peer is kept");
    assert_eq!(
        loopback(&nodes[0], t1).closed(),
        [b1],
        "p's connection closes"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A filter update the active path's MTU cannot carry stays pending and the
/// peer keeps the last filter it accepted (draft Section 5.11); once the link
/// is back on a path that carries it, the update reaches the peer.
#[tokio::test]
async fn a_filter_the_active_path_cannot_carry_stays_pending_and_the_peer_keeps_the_last() {
    let (mut nodes, b, _a2, b2) = two_transports(1000).await;
    let a = *nodes[0].node.node_addr();
    let t1 = TransportId::new(1);
    let b1 = nodes[1].addr.clone();
    let seq = |nodes: &[TestNode]| nodes[1].node.get_peer(&a).unwrap().filter_sequence();
    let held: fn(&[TestNode], &NodeAddr) -> Option<BloomFilter> =
        |nodes, a| nodes[1].node.get_peer(a).unwrap().inbound_filter().cloned();
    let before = (seq(&nodes), held(&nodes, &a));
    assert!(before.0 > 0, "precondition: B accepted A's filter on p");

    let pin = |addr: &TransportAddr, transport| Input::Pin {
        transport,
        addr: Some(addr.clone()),
    };
    nodes[0].node.step_path(&b, pin(&b2, t2())).await;
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2.clone()), "pinned to q");

    crate::time::advance(Duration::from_millis(600));
    nodes[0].node.bloom_state.mark_update_needed(b);
    nodes[0].node.send_pending_filter_announces().await;
    deliver(&mut nodes[1]).await;
    assert!(
        nodes[0].node.bloom_state.needs_update(&b),
        "a filter q cannot carry stays pending"
    );
    assert_eq!(
        (seq(&nodes), held(&nodes, &a)),
        before,
        "B keeps the last filter"
    );

    nodes[0].node.step_path(&b, pin(&b1, t1)).await;
    assert_eq!(active_of(&nodes[0], &b), (t1, b1));
    nodes[0].node.send_pending_filter_announces().await;
    deliver(&mut nodes[1]).await;
    assert!(!nodes[0].node.bloom_state.needs_update(&b));
    assert!(seq(&nodes) > before.0, "the update reaches B on p");
    cleanup_nodes(&mut nodes).await;
}

/// The warnings captured so far that report excessive decryption failures.
pub(super) fn excessive(logs: &crate::testutil::LogCapture) -> usize {
    logs.warnings()
        .iter()
        .filter(|line| line.contains("Excessive decryption failures"))
        .count()
}

/// Deliver `k` frames to B (node 1) that name the receiver index B gave A
/// and fail to authenticate, on B's transport `transport` from `from`.
async fn garbage(nodes: &mut [TestNode], transport: TransportId, from: &TransportAddr, k: u32) {
    let a = *nodes[0].node.node_addr();
    let index = nodes[1].node.get_peer(&a).unwrap().our_index().unwrap();
    for n in 0..k {
        let frame = super::decrypt_forged::forged_frame(index, 1_000_000 + u64::from(n));
        let packet = ReceivedPacket::new(transport, from.clone(), frame);
        nodes[1].node.handle_encrypted_frame(packet).await;
    }
}

/// B's count of consecutive failures on its link to A.
fn b_failures(nodes: &[TestNode]) -> u32 {
    let a = nodes[0].node.node_addr();
    nodes[1]
        .node
        .get_peer(a)
        .expect("failures never remove the peer")
        .consecutive_decrypt_failures()
}

/// Frames that fail to authenticate on a transport the one-path link does not
/// use count nothing against it and log no warning, even from the peer's own
/// address.
#[tokio::test]
async fn garbage_on_a_second_transport_counts_nothing_against_a_one_path_link() {
    let mut nodes = linked_pair(Config::new(), Config::new()).await;
    second_transport(&mut nodes[1], t2(), 1280);
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    // From A's own address, so only the transport tells the pairs apart.
    let a1 = nodes[0].addr.clone();
    garbage(&mut nodes, t2(), &a1, 20).await;
    assert_eq!(b_failures(&nodes), 0, "no path of the link is on t2");
    assert_eq!(excessive(&logs), 0);
    drop(guard);
    cleanup_nodes(&mut nodes).await;
}

/// Frames that fail to authenticate from an address no path holds, on the
/// original transport, count nothing against the link and log no warning.
#[tokio::test]
async fn garbage_from_the_original_transport_at_another_address_counts_nothing() {
    let mut nodes = linked_pair(Config::new(), Config::new()).await;
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    let elsewhere = TransportAddr::from_string("10.9.9.9:9999");
    let t1 = nodes[1].transport_id;
    garbage(&mut nodes, t1, &elsewhere, 20).await;
    assert_eq!(b_failures(&nodes), 0, "no path of the link is there");
    assert_eq!(excessive(&logs), 0);
    drop(guard);
    cleanup_nodes(&mut nodes).await;
}

/// Failures on the original pair warn once at the threshold, and the count goes
/// on past it without warning again.
#[tokio::test]
async fn the_threshold_warning_fires_once_for_the_original_pair() {
    let mut nodes = linked_pair(Config::new(), Config::new()).await;
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    let (t1, a1) = (nodes[1].transport_id, nodes[0].addr.clone());
    garbage(&mut nodes, t1, &a1, 20).await;
    assert_eq!(b_failures(&nodes), 20);
    assert_eq!(excessive(&logs), 1, "one warning at the threshold");
    garbage(&mut nodes, t1, &a1, 5).await;
    assert_eq!(b_failures(&nodes), 25, "the count goes on");
    assert_eq!(excessive(&logs), 1, "and does not warn again");
    drop(guard);
    cleanup_nodes(&mut nodes).await;
}

/// An authentic frame on the original pair whose plaintext is shorter than the
/// inner header starts that path's count of failures again and leaves the
/// peer's address as it was.
#[tokio::test]
async fn a_short_authentic_frame_starts_the_original_paths_count_again() {
    use super::connected_udp::{PROMOTED_ADDR, promoted_peer_with_the_far_side_session};
    use crate::proto::fmp::wire::{build_encrypted, build_established_header};
    let tid = TransportId::new(1);
    let (mut node, peer, index, mut far_side) = promoted_peer_with_the_far_side_session(tid);
    let original = TransportAddr::from_string(PROMOTED_ADDR);
    for _ in 0..3 {
        node.charge_failure(&peer, tid, &original);
    }
    assert_eq!(
        node.get_peer(&peer).unwrap().consecutive_decrypt_failures(),
        3,
        "precondition: three failures"
    );
    // Three bytes of plaintext, shorter than the five-byte inner header.
    let inner = [0u8; 3];
    let counter = far_side.current_send_counter();
    let header = build_established_header(index, counter, 0, inner.len() as u16);
    let sealed = far_side.encrypt_with_aad(&inner, &header).unwrap();
    let frame = build_encrypted(&header, &sealed);
    node.handle_encrypted_frame(ReceivedPacket::new(tid, original.clone(), frame))
        .await;
    let held = node.get_peer(&peer).expect("the peer is kept");
    assert_eq!(held.consecutive_decrypt_failures(), 0);
    assert_eq!(held.current_addr(), Some(&original));
}

/// The earliest next wake of `tn`'s path machine for `peer`.
fn wake_at(tn: &TestNode, peer: &NodeAddr) -> Option<crate::peer::PeerInstant> {
    tn.node.get_peer(peer)?.bundle()?.next_wake()
}

/// Advance the clock to `d` before `at`, if that is ahead of now.
fn advance_to(at: crate::peer::PeerInstant, before: Duration) {
    use fips_core::time::Instant as _;
    let left = at.saturating_duration_since(peer_now());
    crate::time::advance(left.saturating_sub(before));
}

/// With multipath disabled the path tick stays disarmed and steps no
/// machine; a machine of two paths arms it and is stepped only at its wake.
#[tokio::test]
async fn the_path_tick_is_disarmed_and_steps_nothing_without_work() {
    // The tick is run 20 ms before the wake. With the clock running, time
    // the test spends descheduled can bring the wake due in that tick.
    crate::time::freeze();
    let mut nodes = linked_pair(disabled(), disabled()).await;
    let b = *nodes[1].node.node_addr();
    // A step of a disabled machine, as a path message or a tick makes.
    nodes[0].node.step_path(&b, Input::Poll).await;
    assert!(!nodes[0].node.paths.armed(), "nothing to do when disabled");
    for _ in 0..100 {
        crate::time::advance(Duration::from_millis(50));
        nodes[0].node.path_tick().await;
    }
    assert_eq!(nodes[0].node.paths.polls, 0, "no machine stepped in 5 s");
    assert!(!nodes[0].node.paths.armed());
    cleanup_nodes(&mut nodes).await;

    let (mut nodes, b, _, _) = two_transports(1280).await;
    assert!(
        nodes[0].node.paths.armed(),
        "two Live paths have probes due"
    );
    let wake = wake_at(&nodes[0], &b).expect("a machine of two paths has a wake");
    let before = Duration::from_millis(20);
    advance_to(wake, before);
    nodes[0].node.path_tick().await;
    assert_eq!(
        nodes[0].node.paths.polls, 0,
        "nothing is due before the wake"
    );
    crate::time::advance(before);
    nodes[0].node.path_tick().await;
    assert_eq!(
        nodes[0].node.paths.polls, 1,
        "the one machine due, at its wake"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Hand every frame queued at B (node 1) to B and every frame then queued
/// at A to A, until a round moves none, and return how many frames reached
/// B on `t2()`.
pub(super) async fn exchange(nodes: &mut [TestNode]) -> usize {
    let mut on_t2 = 0;
    for _ in 0..10 {
        let mut moved = 0;
        while let Ok(packet) = nodes[1].packet_rx.try_recv() {
            on_t2 += usize::from(packet.transport_id == t2());
            nodes[1].node.handle_encrypted_frame(packet).await;
            moved += 1;
        }
        moved += deliver(&mut nodes[0]).await;
        if moved == 0 {
            break;
        }
    }
    on_t2
}

/// Run `ticks` path ticks at A 50 ms apart and return how many frames
/// reached B on `t2()` in each. The frames are taken from B's queue, not
/// handed to B, so B's machine is not stepped and does not send: what is
/// counted is what A sent. Handed over, they could step B when its own
/// probe on q is due, and A's answer to that probe would be counted too.
async fn t2_ticks(nodes: &mut [TestNode], ticks: usize) -> Vec<usize> {
    let mut seen = Vec::new();
    for _ in 0..ticks {
        crate::time::advance(Duration::from_millis(50));
        nodes[0].node.path_tick().await;
        seen.push(t2_taken(nodes));
    }
    seen
}

/// A standby probe goes out on the tick at which its path is due, and not
/// before.
#[tokio::test]
async fn a_probe_goes_out_when_its_path_is_due() {
    // The ticks run 100 ms before the probe is due and 50 ms apart after.
    // With the clock running, time the test spends descheduled brings
    // probes due a tick sooner than the ticks say.
    crate::time::freeze();
    let (mut nodes, b, _, b2) = two_transports(1280).await;
    exchange(&mut nodes).await;
    let due = {
        let paths = nodes[0]
            .node
            .get_peer(&b)
            .unwrap()
            .bundle()
            .unwrap()
            .paths();
        let q = paths.find(t2(), &b2).unwrap();
        paths
            .get(q)
            .unwrap()
            .live()
            .next_at()
            .expect("q has a standby probe due")
    };
    advance_to(due, Duration::from_millis(100));
    nodes[0].node.path_tick().await;
    assert_eq!(
        exchange(&mut nodes).await,
        0,
        "no frame on q before it is due"
    );
    let seen = t2_ticks(&mut nodes, 2).await;
    assert_eq!(
        seen.iter().sum::<usize>(),
        1,
        "one probe on q once due: {seen:?}"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A candidate on a connection-oriented transport is not probed until its
/// connection opens; the wait arms the path tick, and the tick that finds the
/// connection open sends the probe.
#[tokio::test]
async fn a_connection_oriented_candidate_is_probed_once_its_connection_opens() {
    use crate::node::handlers::path::PathDriver;
    let mut driver = PathDriver::default();
    assert!(!driver.armed());
    let at = PathRef {
        transport: t2(),
        addr: TransportAddr::from_string("loopback:elsewhere"),
    };
    driver.wait(NodeAddr::from_bytes([1; 16]), at);
    assert!(driver.armed(), "a connection to settle arms the tick");

    let mut nodes = linked_pair(enabled(), enabled()).await;
    second_transport(&mut nodes[0], t2(), 1280);
    loopback_mut(&mut nodes[0], t2()).typed(TransportType::TCP);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    let b = *nodes[1].node.node_addr();
    nodes[0].node.offer_path(&b, t2(), b2.clone()).await;
    // The capability exchange on p, without a tick, makes the peer capable
    // and asks for q's connection.
    assert_eq!(
        exchange(&mut nodes).await,
        0,
        "no probe before the connection"
    );
    assert!(
        nodes[0]
            .node
            .get_peer(&b)
            .unwrap()
            .bundle()
            .unwrap()
            .capable()
    );
    assert!(
        nodes[0].node.paths.armed(),
        "the connection to settle arms it"
    );
    nodes[0].node.path_tick().await;
    let sent: Vec<_> = take_queued(&mut nodes[1]);
    assert_eq!(
        sent.iter().filter(|(t, _)| *t == t2()).count(),
        1,
        "the tick that finds the connection open sends q's probe: {sent:?}"
    );
    cleanup_nodes(&mut nodes).await;
}

/// The frames queued at B (node 1) that arrived on `t2()`, taken without
/// handling them.
fn t2_taken(nodes: &mut [TestNode]) -> usize {
    take_queued(&mut nodes[1])
        .iter()
        .filter(|(t, _)| *t == t2())
        .count()
}

/// A one-path link whose interface goes is reaped as before, with its reconnect
/// scheduled, and a peer on another transport is untouched.
#[tokio::test]
async fn a_one_path_link_whose_interface_goes_is_reaped_as_before() {
    let mut nodes = linked_pair(Config::new(), Config::new()).await;
    let b = *nodes[1].node.node_addr();
    let b_npub = nodes[1].node.npub();
    // B is a configured peer of A's, so its loss schedules a reconnect.
    nodes[0].node.replace_context(|ctx| {
        let mut cfg = (*ctx.config).clone();
        cfg.peers.push(crate::config::PeerConfig::new(
            b_npub,
            "udp",
            "127.0.0.1:5001",
        ));
        ctx.config = std::sync::Arc::new(cfg);
    });
    let t1 = nodes[0].transport_id;
    let other = TransportId::new(t1.as_u32() + 100);
    assert_eq!(nodes[0].node.path_presence(other, false).await, 0);
    assert!(
        nodes[0].node.get_peer(&b).is_some(),
        "a peer on another transport is untouched"
    );
    assert!(nodes[0].node.peering.reconciler.retry_pending.is_empty());
    assert_eq!(nodes[0].node.path_presence(t1, false).await, 1);
    assert!(nodes[0].node.get_peer(&b).is_none(), "the peer is reaped");
    assert!(
        nodes[0]
            .node
            .peering
            .reconciler
            .retry_pending
            .contains_key(&b),
        "its reconnect is scheduled, as a link that goes dead schedules it"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A configuration with multipath enabled and the IPv6 adapter's link, so
/// the node keeps the adapter's per-peer limits.
fn enabled_tun() -> Config {
    let mut config = enabled();
    config.tun.enabled = true;
    config.dns.enabled = false;
    config
}

/// Open an FSP session from `tn` to the node of `remote`, with session MMP.
fn open_session(tn: &mut TestNode, remote: &crate::Identity) {
    let session = super::session::make_noise_session(tn.node.identity(), remote);
    let dest = *remote.node_addr();
    let at = crate::node::session::session_at(1000);
    let mut entry = crate::node::session::SessionEntry::keyed(dest, session, at, true);
    entry.init_mmp(&tn.node.config().node.session_mmp);
    tn.node.sessions.insert(dest, entry);
}

/// Record carrier on A's (node 0) transport `t` as `up`, and run a tick.
pub(super) async fn carrier(nodes: &mut [TestNode], t: TransportId, up: bool) {
    loopback(&nodes[0], t).set_carrier(Some(up));
    crate::time::advance(Duration::from_millis(50));
    nodes[0].node.path_tick().await;
}

/// Carrier loss on the active path's transport moves the link to the standby by
/// a mandatory switch, with the link's map entry, the adapter's limit, the MTU
/// lookup and the session's MTU following the standby, and the node-wide
/// ceiling unchanged.
#[tokio::test]
async fn carrier_loss_moves_the_link_and_its_mtu_to_the_standby() {
    let (mut nodes, b, _, b2) = transports_with(enabled_tun(), 1200).await;
    nodes[0].node.attach_host();
    let b_identity = nodes[1].node.identity().clone();
    open_session(&mut nodes[0], &b_identity);
    let t1 = nodes[0].transport_id;
    let ceiling = nodes[0].node.tun_mss_ceiling();
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    carrier(&mut nodes, t1, true).await;
    assert!(
        logs.lines_with("Path switched").is_empty(),
        "the first reading"
    );
    carrier(&mut nodes, t1, false).await;
    let switched = logs.lines_with("Path switched");
    drop(guard);
    assert_eq!(switched.len(), 1, "{switched:?}");
    assert!(switched[0].contains("why=\"mandatory\""), "{}", switched[0]);
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2.clone()));
    let link = nodes[0].node.get_peer(&b).unwrap().link_id();
    assert_eq!(nodes[0].node.links.index().get(&(t2(), b2)), Some(&link));
    let limit = crate::node::path_mtu::payload_limit(1200);
    let replica = nodes[0]
        .node
        .supervisor
        .ipv6tun
        .applied()
        .2
        .read()
        .unwrap()
        .clone();
    assert_eq!(
        replica.get(&fips(&b)),
        Some(&limit),
        "the adapter has q's limit"
    );
    assert_eq!(nodes[0].node.path_mtu_lookup_get(&fips(&b)), Some(1200));
    let mtu = nodes[0]
        .node
        .sessions
        .get(&b)
        .and_then(|e| e.mmp())
        .map(|m| m.path_mtu.current_mtu());
    assert!(
        mtu.is_some_and(|m| m <= 1200),
        "the session follows q: {mtu:?}"
    );
    assert_eq!(
        nodes[0].node.tun_mss_ceiling(),
        ceiling,
        "node-wide, unchanged"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A carrier drop on the active path's transport makes that path Suspect within
/// one tick.
#[tokio::test]
async fn the_carrier_producer_reports_a_drop_within_one_tick() {
    let (mut nodes, b, _, _) = two_transports(1280).await;
    let (t1, b1) = (nodes[0].transport_id, nodes[1].addr.clone());
    carrier(&mut nodes, t1, true).await;
    assert_eq!(state_at(&nodes[0], &b, t1, &b1), Some(PathState::Live));
    carrier(&mut nodes, t1, false).await;
    assert_eq!(
        state_at(&nodes[0], &b, t1, &b1),
        Some(PathState::Suspect),
        "one tick after the loss"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A transport whose carrier is already down at the first reading the node
/// takes of it, as when a link gains its second path while the first
/// path's interface has no carrier, counts as a loss: the Live path on it
/// turns Suspect and the link moves to the other path (multipath draft
/// Sections 5.6 and 12).
#[tokio::test]
async fn a_carrier_already_down_at_its_first_reading_makes_the_path_suspect_and_moves_the_link() {
    let (mut nodes, b, _, b2) = two_transports(1280).await;
    let (t1, b1) = (nodes[0].transport_id, nodes[1].addr.clone());
    assert_eq!(active_of(&nodes[0], &b), (t1, b1.clone()), "precondition");
    carrier(&mut nodes, t1, false).await;
    let p = state_at(&nodes[0], &b, t1, &b1);
    let active = active_of(&nodes[0], &b);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(p, Some(PathState::Suspect), "p after the first reading");
    assert_eq!(active, (t2(), b2), "the link moved to q");
}

/// How many paths `tn`'s link to `peer` holds.
fn paths_held(tn: &TestNode, peer: &NodeAddr) -> usize {
    tn.node
        .get_peer(peer)
        .unwrap()
        .bundle()
        .unwrap()
        .paths()
        .len()
}

/// A carrier reading kept from while a link held two paths does not hide a
/// loss of carrier that happened while the link held one: after the carrier
/// goes, the link drops to one path, the carrier returns and goes again
/// unread, and a second path returns, the next reading makes the path on
/// that transport Suspect (multipath draft Section 5.6).
#[tokio::test]
async fn a_carrier_loss_while_a_link_held_one_path_is_seen_when_a_second_path_returns() {
    let (mut nodes, b, _, b2) = two_transports(1280).await;
    let (t1, b1) = (nodes[0].transport_id, nodes[1].addr.clone());
    carrier(&mut nodes, t1, false).await;
    let p_lost = state_at(&nodes[0], &b, t1, &b1);
    nodes[0].node.path_removed(t2()).await;
    let held = paths_held(&nodes[0], &b);
    // The carrier returns while the link holds p alone, and p is answered
    // back to Live.
    loopback(&nodes[0], t1).set_carrier(Some(true));
    for _ in 0..10 {
        crate::time::advance(Duration::from_millis(50));
        nodes[0].node.path_tick().await;
        super::rekey_parity::pump(&mut nodes).await;
    }
    let p_back = state_at(&nodes[0], &b, t1, &b1);
    // The carrier goes again, unread, and q returns.
    loopback(&nodes[0], t1).set_carrier(Some(false));
    nodes[0].node.offer_path(&b, t2(), b2.clone()).await;
    super::rekey_parity::pump(&mut nodes).await;
    let rejoined = paths_held(&nodes[0], &b);
    crate::time::advance(Duration::from_millis(50));
    nodes[0].node.path_tick().await;
    let p = state_at(&nodes[0], &b, t1, &b1);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(p_lost, Some(PathState::Suspect), "precondition: first loss");
    assert_eq!(held, 1, "precondition: one path");
    assert_eq!(p_back, Some(PathState::Live), "precondition: p is Live");
    assert_eq!(rejoined, 2, "precondition: two paths again");
    assert_eq!(p, Some(PathState::Suspect), "the loss is seen");
}

/// A carrier return on a transport while no link of more than one path used
/// it is seen when the transport is read again: after a candidate there is
/// discarded and its pair held back, the carrier goes, the link drops to one
/// path, the carrier returns unread, and a second path returns, the next
/// reading releases the held pair (multipath draft Section 5.6, "No
/// scheduled retry").
#[tokio::test]
async fn a_carrier_return_while_a_link_held_one_path_releases_a_pair_held_back_on_it() {
    let (mut nodes, b, _, _b2) = two_transports(1280).await;
    let (t1, b1) = (nodes[0].transport_id, nodes[1].addr.clone());
    // r: a candidate on t2 at an address nobody answers.
    let sink = TransportAddr::from_string("loopback:carrier-return-sink");
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<crate::transport::ReceivedPacket>();
    super::spanning_tree::LOOPBACK_REGISTRY
        .lock()
        .unwrap()
        .insert(sink.clone(), (t2(), tx));
    nodes[0].node.offer_path(&b, t2(), sink.clone()).await;
    let r_offered = state_at(&nodes[0], &b, t2(), &sink);
    // r goes Dead unanswered, and is discarded past its grace.
    for _ in 0..100 {
        crate::time::advance(Duration::from_secs(1));
        nodes[0].node.path_tick().await;
        super::rekey_parity::pump(&mut nodes).await;
        if state_at(&nodes[0], &b, t2(), &sink) != Some(PathState::Probing) {
            break;
        }
    }
    let r_dead = state_at(&nodes[0], &b, t2(), &sink);
    crate::time::advance(Duration::from_secs(601));
    nodes[0].node.path_tick().await;
    super::rekey_parity::pump(&mut nodes).await;
    let r_gone = state_at(&nodes[0], &b, t2(), &sink).is_none();
    // The carrier on t2 is read up, then down.
    carrier(&mut nodes, t2(), true).await;
    carrier(&mut nodes, t2(), false).await;
    // p's transport goes: the link holds q alone and t2 is not read.
    nodes[0].node.path_removed(t1).await;
    let held = paths_held(&nodes[0], &b);
    // The carrier on t2 returns, unread.
    loopback(&nodes[0], t2()).set_carrier(Some(true));
    crate::time::advance(Duration::from_millis(50));
    nodes[0].node.path_tick().await;
    super::rekey_parity::pump(&mut nodes).await;
    // A path on t1 returns, so t2 is read again.
    nodes[0].node.offer_path(&b, t1, b1.clone()).await;
    super::rekey_parity::pump(&mut nodes).await;
    let rejoined = paths_held(&nodes[0], &b);
    let r_before = state_at(&nodes[0], &b, t2(), &sink);
    crate::time::advance(Duration::from_millis(50));
    nodes[0].node.path_tick().await;
    let r_after = state_at(&nodes[0], &b, t2(), &sink);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        r_offered,
        Some(PathState::Probing),
        "precondition: r admitted"
    );
    assert_eq!(r_dead, Some(PathState::Dead), "precondition: r unanswered");
    assert!(r_gone, "precondition: r discarded");
    assert_eq!(held, 1, "precondition: one path");
    assert_eq!(rejoined, 2, "precondition: two paths again");
    assert_eq!(r_before, None, "precondition: r held back before the read");
    assert_eq!(r_after, Some(PathState::Probing), "the return releases r");
}

/// A (node 0) linked to B (1) and C (2), each on t1, with a second transport
/// at each of the three. Returns the nodes, B's and C's addresses, and B's and
/// C's addresses on t2.
async fn linked_to_two() -> (
    Vec<TestNode>,
    NodeAddr,
    NodeAddr,
    TransportAddr,
    TransportAddr,
) {
    let mut nodes = vec![
        make_test_node_with_config(enabled(), 1280).await,
        make_test_node_with_config(enabled(), 1280).await,
        make_test_node_with_config(enabled(), 1280).await,
    ];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    initiate_handshake(&mut nodes, 0, 2).await;
    drain_all_packets(&mut nodes, false).await;
    let (b, c) = (*nodes[1].node.node_addr(), *nodes[2].node.node_addr());
    second_transport(&mut nodes[0], t2(), 1280);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    let c2 = second_transport(&mut nodes[2], t2(), 1280);
    (nodes, b, c, b2, c2)
}

/// A linked to B and C. C is made capable through a third transport, which
/// then goes, leaving C one path on t1. When `keep_read`, B's link holds two
/// paths, so that it keeps t1 read across the loss. Carrier drops on t1, then
/// C gains a path on t2. Returns the state of C's path on t1 after the next
/// tick.
async fn second_path_after_a_loss(keep_read: bool) -> Option<PathState> {
    let (mut nodes, b, c, b2, c2) = linked_to_two().await;
    let t3 = TransportId::new(3);
    second_transport(&mut nodes[0], t3, 1280);
    let c3 = second_transport(&mut nodes[2], t3, 1280);
    let t1 = nodes[0].transport_id;
    let (b1, c1) = (nodes[1].addr.clone(), nodes[2].addr.clone());
    if keep_read {
        nodes[0].node.offer_path(&b, t2(), b2.clone()).await;
        super::rekey_parity::pump(&mut nodes).await;
        assert_eq!(
            state_at(&nodes[0], &b, t2(), &b2),
            Some(PathState::Live),
            "precondition: B holds two paths"
        );
    }
    nodes[0].node.offer_path(&c, t3, c3).await;
    super::rekey_parity::pump(&mut nodes).await;
    assert!(capable_at(&nodes[0], &c), "precondition: C is capable");
    nodes[0].node.path_removed(t3).await;
    assert_eq!(
        paths_held(&nodes[0], &c),
        1,
        "precondition: C holds one path"
    );

    carrier(&mut nodes, t1, true).await;
    carrier(&mut nodes, t1, false).await;
    if keep_read {
        assert_eq!(
            state_at(&nodes[0], &b, t1, &b1),
            Some(PathState::Suspect),
            "precondition: the loss is read and stepped into B's link"
        );
    }
    assert_eq!(
        state_at(&nodes[0], &c, t1, &c1),
        Some(PathState::Live),
        "precondition: C's one path is left to the heartbeat"
    );
    nodes[0].node.offer_path(&c, t2(), c2).await;
    super::rekey_parity::pump(&mut nodes).await;
    assert_eq!(
        paths_held(&nodes[0], &c),
        2,
        "precondition: C holds two paths"
    );
    crate::time::advance(Duration::from_millis(50));
    nodes[0].node.path_tick().await;
    let p = state_at(&nodes[0], &c, t1, &c1);
    cleanup_nodes(&mut nodes).await;
    p
}

/// A link that gains its second path after another link took the reading of a
/// loss is told of the loss at the next read: the reading is the link's own,
/// since the rule it serves is about the link (multipath draft Section 5.6).
#[tokio::test]
async fn a_link_gaining_a_second_path_after_a_loss_another_link_saw_is_told_of_it() {
    assert_eq!(
        second_path_after_a_loss(true).await,
        Some(PathState::Suspect),
        "the link's path is told of the loss"
    );
}

/// The control of the test above: with no other link keeping the transport
/// read, the first reading after the second path sees the loss.
#[tokio::test]
async fn a_first_reading_sees_the_loss_when_no_other_link_keeps_the_transport_read() {
    assert_eq!(
        second_path_after_a_loss(false).await,
        Some(PathState::Suspect)
    );
}

/// A carrier return is seen by a link that read the loss, though another link
/// read the return while this one held one path: with a pair held back at C on
/// t2, C holds two paths when the loss is read and then one, B keeps t2 read
/// and reads the return, and C gains a second path. The next read releases the
/// pair (multipath draft Section 5.6, "No scheduled retry").
#[tokio::test]
async fn a_carrier_return_releases_a_pair_held_back_on_a_link_that_read_the_loss_and_fell_to_one_path()
 {
    let (mut nodes, b, c, b2, c2) = linked_to_two().await;
    let t3 = TransportId::new(3);
    let t1 = nodes[0].transport_id;
    let c1 = nodes[2].addr.clone();
    second_transport(&mut nodes[0], t3, 1280);
    let b3 = second_transport(&mut nodes[1], t3, 1280);
    for (peer, transport, addr) in [(&b, t2(), &b2), (&b, t3, &b3), (&c, t2(), &c2)] {
        nodes[0]
            .node
            .offer_path(peer, transport, addr.clone())
            .await;
        super::rekey_parity::pump(&mut nodes).await;
        assert_eq!(
            state_at(&nodes[0], peer, transport, addr),
            Some(PathState::Live),
            "precondition: the offered path is Live"
        );
    }
    // r: a candidate on t2 at C's link, at an address nobody answers.
    let sink = TransportAddr::from_string("loopback:carrier-return-per-link-sink");
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<crate::transport::ReceivedPacket>();
    super::spanning_tree::LOOPBACK_REGISTRY
        .lock()
        .unwrap()
        .insert(sink.clone(), (t2(), tx));
    nodes[0].node.offer_path(&c, t2(), sink.clone()).await;
    assert_eq!(
        state_at(&nodes[0], &c, t2(), &sink),
        Some(PathState::Probing),
        "precondition: r admitted"
    );
    // r goes Dead unanswered, and is discarded past its grace.
    for _ in 0..100 {
        crate::time::advance(Duration::from_secs(1));
        nodes[0].node.path_tick().await;
        super::rekey_parity::pump(&mut nodes).await;
        if state_at(&nodes[0], &c, t2(), &sink) != Some(PathState::Probing) {
            break;
        }
    }
    assert_eq!(
        state_at(&nodes[0], &c, t2(), &sink),
        Some(PathState::Dead),
        "precondition: r unanswered"
    );
    crate::time::advance(Duration::from_secs(601));
    nodes[0].node.path_tick().await;
    super::rekey_parity::pump(&mut nodes).await;
    assert_eq!(
        state_at(&nodes[0], &c, t2(), &sink),
        None,
        "precondition: r discarded"
    );

    carrier(&mut nodes, t2(), true).await;
    carrier(&mut nodes, t2(), false).await;
    // p's transport goes: C holds q alone, and B's two left keep t2 read.
    nodes[0].node.path_removed(t1).await;
    assert_eq!(
        paths_held(&nodes[0], &c),
        1,
        "precondition: C holds one path"
    );
    assert!(
        paths_held(&nodes[0], &b) > 1,
        "precondition: B holds more than one path"
    );
    // B reads the return; C is out of the rule.
    carrier(&mut nodes, t2(), true).await;
    super::rekey_parity::pump(&mut nodes).await;
    // C gains its second path after the return.
    nodes[0].node.offer_path(&c, t1, c1).await;
    super::rekey_parity::pump(&mut nodes).await;
    assert_eq!(
        paths_held(&nodes[0], &c),
        2,
        "precondition: C holds two paths"
    );
    assert_eq!(
        state_at(&nodes[0], &c, t2(), &sink),
        None,
        "precondition: r held back before the read"
    );
    crate::time::advance(Duration::from_millis(50));
    nodes[0].node.path_tick().await;
    let r = state_at(&nodes[0], &c, t2(), &sink);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(r, Some(PathState::Probing), "the return releases the pair");
}

/// A link's carrier reading goes when the link goes, as does one kept for a
/// transport that goes, so that a node's readings stay bounded by its links.
/// A link that lost a path keeps a reading of no carrier, marked as lapsed,
/// until then.
#[tokio::test]
async fn a_carrier_reading_goes_with_its_link_or_its_transport() {
    async fn read(nodes: &mut [TestNode]) -> usize {
        crate::time::advance(Duration::from_millis(50));
        nodes[0].node.path_tick().await;
        nodes[0].node.paths.readings()
    }

    let (mut nodes, b, _, _) = two_transports(1280).await;
    let t1 = nodes[0].transport_id;
    loopback(&nodes[0], t1).set_carrier(Some(false));
    loopback(&nodes[0], t2()).set_carrier(Some(false));
    let both = read(&mut nodes).await;
    nodes[0].node.path_removed(t2()).await;
    let lapsed = read(&mut nodes).await;
    nodes[0].node.transports.remove(&t2());
    let one = read(&mut nodes).await;
    nodes[0].node.remove_active_peer(&b);
    let none = read(&mut nodes).await;
    cleanup_nodes(&mut nodes).await;
    assert_eq!(both, 2, "precondition: one reading per transport");
    assert_eq!(lapsed, 2, "a reading of no carrier lapses");
    assert_eq!(one, 1, "the gone transport's reading goes");
    assert_eq!(none, 0, "the gone link's reading goes");
}

/// Two carriers lost between two reads step a link in its path order, so the
/// same losses always end the same way: the active path goes first and the link
/// switches to the standby, which goes in turn. In the other order the standby
/// goes first, nothing is left to switch to, and the link stays on p. The standby
/// sits on the transport of the lower id, so an order by key fails too, and there
/// are enough links that an order varying from link to link cannot pass by luck.
#[tokio::test]
async fn two_carrier_losses_in_one_read_step_each_link_in_its_path_order() {
    const LINKS: usize = 24;
    let lower = TransportId::new(0);
    let mut nodes = Vec::new();
    for _ in 0..=LINKS {
        nodes.push(make_test_node_with_config(enabled(), 1280).await);
    }
    for peer in 1..=LINKS {
        initiate_handshake(&mut nodes, 0, peer).await;
    }
    drain_all_packets(&mut nodes, false).await;
    let t1 = nodes[0].transport_id;
    second_transport(&mut nodes[0], lower, 1280);
    let mut links = Vec::new();
    for peer in 1..=LINKS {
        let addr = *nodes[peer].node.node_addr();
        let q = second_transport(&mut nodes[peer], lower, 1280);
        nodes[0].node.offer_path(&addr, lower, q.clone()).await;
        links.push((addr, nodes[peer].addr.clone(), q));
    }
    super::rekey_parity::pump(&mut nodes).await;
    loopback(&nodes[0], t1).set_carrier(Some(true));
    carrier(&mut nodes, lower, true).await;
    let active =
        |nodes: &[TestNode], addr: &NodeAddr| nodes[0].node.get_peer(addr).unwrap().transport_id();
    for (addr, _, q) in &links {
        assert_eq!(
            state_at(&nodes[0], addr, lower, q),
            Some(PathState::Live),
            "precondition: q is Live"
        );
        assert_eq!(active(&nodes, addr), Some(t1), "precondition: p is active");
    }

    loopback(&nodes[0], t1).set_carrier(Some(false));
    carrier(&mut nodes, lower, false).await;
    let after: Vec<_> = links
        .iter()
        .map(|(addr, p, q)| {
            let states = (
                state_at(&nodes[0], addr, t1, p),
                state_at(&nodes[0], addr, lower, q),
            );
            (states, active(&nodes, addr))
        })
        .collect();
    cleanup_nodes(&mut nodes).await;
    for (states, active) in after {
        assert_eq!(
            states,
            (Some(PathState::Suspect), Some(PathState::Suspect)),
            "precondition: both losses were stepped"
        );
        assert_eq!(
            active,
            Some(lower),
            "the link switched on p's loss, before q's"
        );
    }
}

/// The return of an interface probes the pairs on its transport in the step of
/// the return. The return of a transport's carrier brings back the Dead paths on
/// it, each keeping the stop it took on becoming Dead, so its first probe waits
/// for the floor's first instant, 1 s after the path became Dead.
#[tokio::test]
async fn a_returning_interface_probes_at_once_and_a_returning_carrier_at_the_floor() {
    // The floor is checked 50 ms either side. With the clock running, time
    // the test spends descheduled can bring q's probe due before it.
    crate::time::freeze();
    // (a) The interface of q's transport goes and comes back.
    let (mut nodes, b, _, b2) = two_transports(1280).await;
    exchange(&mut nodes).await;
    nodes[0].node.path_presence(t2(), false).await;
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), None, "q is discarded");
    take_queued(&mut nodes[1]);
    nodes[0].node.path_presence(t2(), true).await;
    assert_eq!(t2_taken(&mut nodes), 1, "q's pair is probed on the return");
    cleanup_nodes(&mut nodes).await;

    // (b) q is closed by B, Dead, and its transport's carrier goes and
    // comes back, 150 ms after q became Dead.
    let (mut nodes, b, _, b2) = two_transports(1280).await;
    exchange(&mut nodes).await;
    let a = *nodes[0].node.node_addr();
    let paths = nodes[0]
        .node
        .get_peer(&b)
        .unwrap()
        .bundle()
        .unwrap()
        .paths();
    let q_id = paths.get(paths.find(t2(), &b2).unwrap()).unwrap().path_id();
    let close = PathClose {
        path_id: q_id,
        reason: PathCloseReason::Operator,
    };
    nodes[1]
        .node
        .send_encrypted_link_message(&a, &close.encode())
        .await
        .expect("B's close goes out");
    deliver(&mut nodes[0]).await;
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), Some(PathState::Dead));
    carrier(&mut nodes, t2(), true).await;
    carrier(&mut nodes, t2(), false).await;
    take_queued(&mut nodes[1]);
    carrier(&mut nodes, t2(), true).await;
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), Some(PathState::Probing));
    assert_eq!(
        t2_taken(&mut nodes),
        0,
        "q is not probed in the tick of the return"
    );
    crate::time::advance(Duration::from_millis(800));
    nodes[0].node.path_tick().await;
    assert_eq!(t2_taken(&mut nodes), 0, "nor 950 ms after it became Dead");
    crate::time::advance(Duration::from_millis(50));
    nodes[0].node.path_tick().await;
    assert_eq!(
        t2_taken(&mut nodes),
        1,
        "q is probed 1 s after it became Dead"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A removed transport hands a link of two paths to its standby by one
/// handover, and orphans a link of one path, whose peer is removed.
#[tokio::test]
async fn a_removed_transport_hands_the_link_to_the_standby() {
    let (mut nodes, b, _, b2) = two_transports(1280).await;
    let t1 = nodes[0].transport_id;
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    nodes[0].node.path_removed(t1).await;
    let switched = logs.lines_with("Path switched");
    drop(guard);
    assert_eq!(switched.len(), 1, "{switched:?}");
    assert!(switched[0].contains("why=\"handover\""), "{}", switched[0]);
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2));
    cleanup_nodes(&mut nodes).await;

    let mut nodes = linked_pair(Config::new(), Config::new()).await;
    let b = *nodes[1].node.node_addr();
    let t1 = nodes[0].transport_id;
    nodes[0].node.path_removed(t1).await;
    assert!(
        nodes[0].node.get_peer(&b).is_none(),
        "a link of one path is orphaned and its peer removed"
    );
    cleanup_nodes(&mut nodes).await;
}

/// With nothing Live, a removed transport hands the link to its Suspect
/// standby and probes that path in the same step (draft Section 5.7): one
/// handover, the peer kept, and a probe reaching B on the standby's pair.
#[tokio::test]
async fn a_removed_transport_hands_the_link_to_a_suspect_standby_and_probes_it() {
    let (mut nodes, b, _, b2) = two_transports(1280).await;
    exchange(&mut nodes).await;
    let t1 = nodes[0].transport_id;
    carrier(&mut nodes, t2(), true).await;
    carrier(&mut nodes, t2(), false).await;
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), Some(PathState::Suspect));
    take_queued(&mut nodes[1]);
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    nodes[0].node.path_removed(t1).await;
    let switched = logs.lines_with("Path switched");
    drop(guard);
    assert_eq!(switched.len(), 1, "{switched:?}");
    assert!(switched[0].contains("why=\"handover\""), "{}", switched[0]);
    assert!(nodes[0].node.get_peer(&b).is_some(), "the peer is kept");
    assert_eq!(
        t2_taken(&mut nodes),
        1,
        "q is probed in the step that makes it active"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A bootstrap transport that carries another peer's standby path is kept when
/// the peer it was adopted for is removed.
#[tokio::test]
async fn a_bootstrap_transport_that_carries_a_standby_path_is_kept() {
    let mut node = make_node();
    let (t1, boot) = (TransportId::new(1), TransportId::new(7));
    let lo = crate::transport::loopback::LoopbackTransport::new(
        boot,
        TransportAddr::from_string("loopback:boot"),
        crate::transport::loopback::new_registry(),
    );
    node.transports.insert(boot, TransportHandle::Loopback(lo));
    // Peer X on t1, and Y, the peer the rendezvous adopted the transport for.
    let x = seed_completed_connection(&mut node, LinkId::new(1), t1, 1_000);
    node.promote_connection(LinkId::new(1), x, 2_000).unwrap();
    let y = seed_completed_connection(&mut node, LinkId::new(2), boot, 1_000);
    node.promote_connection(LinkId::new(2), y, 2_000).unwrap();
    node.supervisor.nostr_rendezvous.insert_bootstrap_transport(
        boot,
        y.npub(),
        *y.node_addr(),
        "198.51.100.7:4000".parse().unwrap(),
    );
    // X holds an acked path on the bootstrap transport beside its active one.
    let standby = TransportAddr::from_string("127.0.0.1:6000");
    let peer = node.get_peer_mut(x.node_addr()).unwrap();
    peer.admit_path(boot, standby.clone());
    peer.ack_path(boot, &standby);
    assert_eq!(peer.transport_id(), Some(t1), "precondition: X sends on t1");

    node.remove_active_peer(y.node_addr());
    assert!(
        node.get_peer(y.node_addr()).is_none(),
        "precondition: Y is gone"
    );
    assert!(
        node.transports.contains_key(&boot),
        "a transport a standby path uses is kept"
    );
    assert!(
        node.supervisor
            .nostr_rendezvous
            .is_bootstrap_transport(&boot)
    );
}

/// Have A (node 0) send B a heartbeat on its active path, and return what
/// the send returned and the "Path switched" lines it logged.
async fn heartbeat_to(nodes: &mut [TestNode], b: &NodeAddr) -> (bool, Vec<String>) {
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    let beat = [LinkMessageType::Heartbeat.to_byte()];
    let sent = nodes[0].node.send_encrypted_link_message(b, &beat).await;
    let switched = logs.lines_with("Path switched");
    drop(guard);
    (sent.is_ok(), switched)
}

/// A send to an unreachable address on the active path of a link of two paths
/// returns its error as before and moves the link to the standby by a mandatory
/// switch.
#[tokio::test]
async fn an_unreachable_send_on_the_active_path_moves_the_link() {
    let (mut nodes, b, _, b2) = two_transports(1280).await;
    let t1 = nodes[0].transport_id;
    loopback(&nodes[0], t1).set_unreachable(true);
    let (sent, switched) = heartbeat_to(&mut nodes, &b).await;
    assert!(!sent, "the send's error is returned as before");
    assert_eq!(switched.len(), 1, "{switched:?}");
    assert!(switched[0].contains("why=\"mandatory\""), "{}", switched[0]);
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2));
    cleanup_nodes(&mut nodes).await;
}

/// A send the transport has no connection for is not treated as unreachable: no
/// switch, and the path stays Live and active.
#[tokio::test]
async fn a_send_the_transport_has_no_connection_for_is_not_unreachable() {
    let (mut nodes, b, _, _) = two_transports(1280).await;
    let (t1, b1) = (nodes[0].transport_id, nodes[1].addr.clone());
    loopback(&nodes[0], t1).set_unconnected(true);
    let (sent, switched) = heartbeat_to(&mut nodes, &b).await;
    assert!(!sent);
    assert!(switched.is_empty(), "{switched:?}");
    assert_eq!(state_at(&nodes[0], &b, t1, &b1), Some(PathState::Live));
    assert_eq!(active_of(&nodes[0], &b), (t1, b1));
    cleanup_nodes(&mut nodes).await;
}

/// A send to an unreachable address on a one-path link leaves its path Live,
/// for the FMP heartbeat to judge.
#[tokio::test]
async fn a_one_path_link_ignores_an_unreachable_send() {
    let mut nodes = linked_pair(Config::new(), Config::new()).await;
    let b = *nodes[1].node.node_addr();
    let (t1, b1) = (nodes[0].transport_id, nodes[1].addr.clone());
    loopback(&nodes[0], t1).set_unreachable(true);
    let (sent, _) = heartbeat_to(&mut nodes, &b).await;
    assert!(!sent);
    assert_eq!(
        state_at(&nodes[0], &b, t1, &b1),
        Some(PathState::Live),
        "a link of one path is left to the FMP heartbeat"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A `ReceiverReport` from the peer, as `handle_receiver_report` takes it
/// (its type byte stripped), whose counters stand at `highest` and whose
/// echo of 1 ms gives a round trip of the session's age.
pub(super) fn report_body(highest: u64) -> Vec<u8> {
    let rr = crate::proto::mmp::ReceiverReport {
        highest_counter: highest,
        cumulative_packets_recv: highest,
        cumulative_bytes_recv: highest * 100,
        timestamp_echo: 1,
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: 10,
        interval_bytes_recv: 1_000,
    };
    rr.encode()[1..].to_vec()
}

/// A one-path link never holds its cost, so its cost is the quality index of
/// its measured ETX and round trip.
#[tokio::test]
async fn a_one_path_links_cost_is_its_quality_index() {
    let mut nodes = linked_pair(Config::new(), Config::new()).await;
    let b = *nodes[1].node.node_addr();
    crate::time::advance(Duration::from_millis(500));
    for highest in [1_000_000, 2_000_000] {
        nodes[0]
            .node
            .handle_receiver_report(&b, &report_body(highest))
            .await;
    }
    let peer = nodes[0].node.get_peer(&b).unwrap();
    let metrics = &peer.mmp().unwrap().metrics;
    let srtt = metrics
        .srtt_ms()
        .expect("precondition: the reports gave a round trip");
    let index = crate::proto::mmp::quality_index(metrics.etx, srtt);
    assert!(
        index > 1.0,
        "precondition: the measured cost is not the default"
    );
    assert!(
        !peer.bundle().unwrap().holding(),
        "a link of one path never holds"
    );
    assert_eq!(peer.link_cost(), index);
    cleanup_nodes(&mut nodes).await;
}

/// A switch holds the link's cost at its value before the switch until the
/// dwell has passed and two reports have each brought a sample; then it follows
/// the measured cost.
#[tokio::test]
async fn a_switch_holds_the_link_cost_until_the_dwell_and_two_reports() {
    let (mut nodes, b, b2) = same_transport().await;
    let t1 = nodes[0].transport_id;
    let set = |nodes: &mut [TestNode], etx: f64| {
        let peer = nodes[0].node.get_peer_mut(&b).unwrap();
        let mmp = peer.mmp_mut().unwrap();
        mmp.metrics.etx = etx;
        mmp.metrics.srtt.update(20_000);
    };
    let cost = |nodes: &[TestNode]| {
        let peer = nodes[0].node.get_peer(&b).unwrap();
        (peer.link_cost(), peer.live_cost())
    };
    set(&mut nodes, 1.0);
    let before = cost(&nodes).0;

    shut_p(&mut nodes, &b, &b2).await;
    assert_eq!(active_of(&nodes[0], &b), (t1, b2.clone()), "A moved to q");
    super::rekey_parity::pump(&mut nodes).await;
    set(&mut nodes, 3.0);
    let (held, live) = cost(&nodes);
    assert_ne!(live, before, "precondition: the measured cost moved");
    assert_eq!(held, before, "held at the change");

    crate::time::advance(Duration::from_millis(2_100));
    assert_eq!(
        cost(&nodes).0,
        before,
        "the dwell has passed, with no report"
    );
    let a = &mut nodes[0].node;
    a.handle_receiver_report(&b, &report_body(1_000_000)).await;
    assert_eq!(cost(&nodes).0, before, "one report");
    let a = &mut nodes[0].node;
    a.handle_receiver_report(&b, &report_body(1_000_000)).await;
    assert_eq!(cost(&nodes).0, before, "a repeated report brings no sample");
    let a = &mut nodes[0].node;
    a.handle_receiver_report(&b, &report_body(2_000_000)).await;
    let (now, live) = cost(&nodes);
    assert_ne!(
        live, before,
        "precondition: the measured cost still differs"
    );
    assert_eq!(now, live, "the dwell and two reports end the hold");
    cleanup_nodes(&mut nodes).await;
}

/// A msg1 from a pair still being probed is not the established peer's and gets
/// no waiver, while one from an acked pair is and does, and stays so when that
/// path is Dead.
#[tokio::test]
async fn a_msg1_from_a_probing_pair_gets_no_waiver_and_one_from_an_acked_pair_does() {
    use crate::node::handlers::handshake::Msg1Waiver;
    let mut nodes = linked_pair(Config::new(), Config::new()).await;
    let b = *nodes[1].node.node_addr();
    second_transport(&mut nodes[0], t2(), 1280);
    loopback(&nodes[0], t2()).set_accepts(false);
    let r = TransportAddr::from_string("loopback:inc4-r");
    let a = &mut nodes[0].node;
    a.get_peer_mut(&b).unwrap().admit_path(t2(), r.clone());
    let waiver = |a: &Node| {
        let established = a.is_established_link_msg1(t2(), &r);
        (established, a.msg1_waiver(established, t2(), &r))
    };
    assert_eq!(
        waiver(a),
        (false, Msg1Waiver::Unattributed),
        "a pair still being probed is no path of the peer's"
    );
    a.get_peer_mut(&b).unwrap().ack_path(t2(), &r);
    assert_eq!(
        waiver(a),
        (true, Msg1Waiver::Expect(b)),
        "an acked standby is the established peer's"
    );
    a.get_peer_mut(&b).unwrap().kill_path(t2(), &r);
    assert_eq!(
        waiver(a),
        (true, Msg1Waiver::Expect(b)),
        "an acked path stays proven when it is Dead"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Closing a handshake link's connection leaves it open when a peer's acked
/// standby path uses the same pair, and closes it when no peer does.
#[tokio::test]
async fn an_acked_standby_of_another_peer_keeps_a_handshake_links_connection_open() {
    let mut nodes = linked_pair(Config::new(), Config::new()).await;
    let b = *nodes[1].node.node_addr();
    let t1 = nodes[0].transport_id;
    let standby = add_loopback_alias(&nodes[1].addr, t1);
    let stranger = add_loopback_alias(&nodes[1].addr, t1);
    let a = &mut nodes[0].node;
    a.get_peer_mut(&b).unwrap().admit_path(t1, standby.clone());
    a.get_peer_mut(&b).unwrap().ack_path(t1, &standby);
    let leg = |a: &mut Node, addr: &TransportAddr| {
        let id = a.allocate_link_id();
        let link = Link::connectionless(
            id,
            t1,
            addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        );
        a.links.raw().insert(id, link);
        id
    };
    let other = leg(a, &stranger);
    a.close_unused(other).await;
    assert_eq!(
        loopback(&nodes[0], t1).closed(),
        vec![stranger.clone()],
        "precondition: a leg no peer shares is closed"
    );
    let a = &mut nodes[0].node;
    let shared = leg(a, &standby);
    a.close_unused(shared).await;
    assert_eq!(
        loopback(&nodes[0], t1).closed(),
        vec![stranger],
        "the peer's acked standby keeps the connection open"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A rekey msg1 from an acked path that is Dead is on the link: it is accepted,
/// and the msg2 goes back on that path's pair.
#[tokio::test]
async fn a_rekey_from_an_acked_dead_path_is_answered_on_its_pair() {
    let (mut nodes, b, a2, b2) = two_transports(1280).await;
    let a = *nodes[0].node.node_addr();
    let peer = nodes[1].node.get_peer_mut(&a).unwrap();
    assert!(
        matches!(
            peer.path_match(t2(), &a2),
            crate::peer::Match::Proven { .. }
        ),
        "precondition: B holds A's second pair, acked by the probe exchange"
    );
    peer.kill_path(t2(), &a2);
    assert_eq!(
        state_at(&nodes[1], &a, t2(), &a2),
        Some(PathState::Dead),
        "precondition: the acked pair is Dead"
    );
    age_link(&mut nodes, 0, 1, Duration::from_secs(31));
    super::start_link_rekey(&mut nodes[0].node, &b).await;
    let mut msg1 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("A's rekey msg1 is queued at B");
    assert!(
        nodes[1].packet_rx.try_recv().is_err(),
        "precondition: one packet"
    );
    // A's msg1, as it arrives over A's second transport.
    msg1.transport_id = t2();
    msg1.remote_addr = a2.clone();
    let off_link = nodes[1].node.stats().handshake.off_link;
    nodes[1].node.handle_msg1(msg1).await;
    assert_eq!(
        nodes[1].node.stats().handshake.off_link,
        off_link,
        "a msg1 on an acked path is on the link"
    );
    assert_eq!(
        nodes[1].node.get_peer(&a).unwrap().pending_role(),
        Some(crate::proto::rekey::Role::Responder),
        "B accepted the rekey"
    );
    assert_eq!(
        take_queued(&mut nodes[0]),
        vec![(t2(), b2)],
        "B's msg2 arrives at A's second transport, from B's"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Node 1 holds node 0 on a link whose one path has followed node 0's
/// frames from the address the link was set up at to a third address, and
/// node 0's rekey msg1 then arrives from the setup address. Node 1 runs
/// with multipath `enabled` or not; node 0 runs with it disabled, so node 1
/// never holds node 0 as capable. Returns (a msg2 reached the current
/// address, a msg2 reached the msg1's source, node 1 holds a pending
/// session).
async fn setup_rekey(enabled: bool) -> (bool, bool, bool) {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG2};

    const REKEY_AFTER_SECS: u64 = 60;
    let trigger_age =
        Duration::from_secs(REKEY_AFTER_SECS + crate::node::REKEY_JITTER_SECS as u64 + 1);
    let mut cfg0 = disabled();
    cfg0.node.rekey.after_secs = REKEY_AFTER_SECS;
    cfg0.node.rekey.after_messages = u64::MAX;
    let mut cfg1 = crate::config::Config::new();
    cfg1.node.rekey.after_secs = u64::MAX;
    cfg1.node.rekey.after_messages = u64::MAX;
    cfg1.node.path.enabled = enabled;
    let super::session::AgedLinkPair {
        mut nodes,
        node0_addr,
        fips0,
        fips1,
        ..
    } = super::session::aged_link_pair(cfg0, cfg1, trigger_age).await;
    let mut third = vec![super::spanning_tree::make_test_node().await];
    let setup = nodes[0].addr.clone();
    let moved = third[0].addr.clone();
    assert!(
        !nodes[1]
            .node
            .get_peer(&node0_addr)
            .unwrap()
            .bundle()
            .is_some_and(|b| b.capable()),
        "precondition: node 1 does not hold node 0 as capable"
    );
    while nodes[1].packet_rx.try_recv().is_ok() {}
    while nodes[0].packet_rx.try_recv().is_ok() {}

    // One authentic frame of node 0's, arriving from the third address:
    // node 1's one path follows it there (FMP's address rule).
    let pkt = super::session::build_ipv6_packet(&fips0, &fips1, b"roam");
    nodes[0].node.handle_tun_outbound(pkt).await;
    let mut frame = nodes[1]
        .packet_rx
        .try_recv()
        .expect("node 0's frame is queued at node 1");
    frame.remote_addr = moved.clone();
    nodes[1].node.handle_encrypted_frame(frame).await;
    while nodes[1].packet_rx.try_recv().is_ok() {}
    assert_eq!(
        nodes[1].node.get_peer(&node0_addr).unwrap().current_addr(),
        Some(&moved),
        "precondition: node 1's path to node 0 followed it to the third address"
    );
    while third[0].packet_rx.try_recv().is_ok() {}
    while nodes[0].packet_rx.try_recv().is_ok() {}

    nodes[0].node.poll_link_rekeys().await;
    let msg1 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("node 0's rekey msg1 is queued at node 1");
    assert_eq!(
        msg1.remote_addr, setup,
        "precondition: from the setup address"
    );
    nodes[1].node.handle_msg1(msg1).await;

    let is_msg2 = |p: &crate::transport::ReceivedPacket| {
        CommonPrefix::parse(&p.data).map(|p| p.phase) == Some(PHASE_MSG2)
    };
    let to_current = std::iter::from_fn(|| third[0].packet_rx.try_recv().ok()).any(|p| is_msg2(&p));
    let to_source = std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).any(|p| is_msg2(&p));
    let pending = nodes[1]
        .node
        .get_peer(&node0_addr)
        .unwrap()
        .pending_new_session()
        .is_some();
    cleanup_nodes(&mut nodes).await;
    cleanup_nodes(&mut third).await;
    (to_current, to_source, pending)
}

/// With multipath disabled, a rekey msg1 from the setup address after a roam
/// is answered on the established link, at the peer's current address.
#[tokio::test]
async fn a_setup_address_rekey_after_a_roam_is_answered_at_the_current_address_with_multipath_disabled()
 {
    assert_eq!(setup_rekey(false).await, (true, false, true));
}

/// With multipath enabled, a link whose peer is not capable follows FMP's
/// rules: the msg1 from the setup address is on the link, and its msg2 goes
/// on the established link to the peer's current address, never to the
/// msg1's source.
#[tokio::test]
async fn a_setup_address_rekey_after_a_roam_of_a_link_not_capable_is_answered_at_the_current_address()
 {
    assert_eq!(setup_rekey(true).await, (true, false, true));
}

/// Both nodes enabled; node 1 learns node 0 is capable over the original
/// path alone (node 0's candidate is a third node's address, so node 1
/// gains no second path), the original path then follows node 0's frames
/// to the third node's address, and node 0's rekey msg1 arrives from the
/// setup address, where node 1 now holds no path. Returns (a msg2 at the
/// current address, a msg2 at the msg1's source, a pending session, the
/// off-link refusals added, node 1 holds node 0 capable, node 1's path
/// count).
async fn capable_rekey() -> (bool, bool, bool, u64, bool, usize) {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG2};

    const REKEY_AFTER_SECS: u64 = 60;
    let trigger_age =
        Duration::from_secs(REKEY_AFTER_SECS + crate::node::REKEY_JITTER_SECS as u64 + 1);
    let mut cfg0 = crate::config::Config::new();
    cfg0.node.rekey.after_secs = REKEY_AFTER_SECS;
    cfg0.node.rekey.after_messages = u64::MAX;
    cfg0.node.path.enabled = true;
    let mut cfg1 = crate::config::Config::new();
    cfg1.node.rekey.after_secs = u64::MAX;
    cfg1.node.rekey.after_messages = u64::MAX;
    cfg1.node.path.enabled = true;
    let super::session::AgedLinkPair {
        mut nodes,
        node0_addr,
        fips0,
        fips1,
        ..
    } = super::session::aged_link_pair(cfg0, cfg1, trigger_age).await;
    let mut third = vec![super::spanning_tree::make_test_node().await];
    let decoy = add_loopback_alias(&third[0].addr, third[0].transport_id);
    let node1_addr = *nodes[1].node.node_addr();
    let t0 = nodes[0].transport_id;
    nodes[0].node.offer_path(&node1_addr, t0, decoy).await;
    for _ in 0..3 {
        crate::time::advance(Duration::from_millis(50));
        nodes[0].node.path_tick().await;
        nodes[1].node.path_tick().await;
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            super::spanning_tree::process_available_packets(&mut nodes).await;
        }
    }
    let setup = nodes[0].addr.clone();
    let moved = third[0].addr.clone();
    while third[0].packet_rx.try_recv().is_ok() {}
    let held = nodes[1].node.get_peer(&node0_addr).unwrap().bundle();
    let capable = held.is_some_and(|b| b.capable());
    let npaths = held.map_or(0, |b| b.paths().len());
    while nodes[1].packet_rx.try_recv().is_ok() {}
    while nodes[0].packet_rx.try_recv().is_ok() {}

    let pkt = super::session::build_ipv6_packet(&fips0, &fips1, b"roam");
    nodes[0].node.handle_tun_outbound(pkt).await;
    let mut frame = nodes[1]
        .packet_rx
        .try_recv()
        .expect("node 0's frame is queued at node 1");
    frame.remote_addr = moved.clone();
    nodes[1].node.handle_encrypted_frame(frame).await;
    while nodes[1].packet_rx.try_recv().is_ok() {}
    assert_eq!(
        nodes[1].node.get_peer(&node0_addr).unwrap().current_addr(),
        Some(&moved),
        "precondition: node 1's one path to node 0 followed it to the third address"
    );
    let t1 = nodes[1].transport_id;
    assert!(
        matches!(
            nodes[1]
                .node
                .get_peer(&node0_addr)
                .unwrap()
                .path_match(t1, &setup),
            crate::peer::Match::None
        ),
        "precondition: node 1 holds no path at the setup address"
    );
    while third[0].packet_rx.try_recv().is_ok() {}
    while nodes[0].packet_rx.try_recv().is_ok() {}

    let off_link = nodes[1].node.stats().handshake.off_link;
    nodes[0].node.poll_link_rekeys().await;
    let msg1 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("node 0's rekey msg1 is queued at node 1");
    assert_eq!(
        msg1.remote_addr, setup,
        "precondition: from the setup address"
    );
    nodes[1].node.handle_msg1(msg1).await;

    let is_msg2 = |p: &crate::transport::ReceivedPacket| {
        CommonPrefix::parse(&p.data).map(|p| p.phase) == Some(PHASE_MSG2)
    };
    let to_current = std::iter::from_fn(|| third[0].packet_rx.try_recv().ok()).any(|p| is_msg2(&p));
    let to_source = std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).any(|p| is_msg2(&p));
    let pending = nodes[1]
        .node
        .get_peer(&node0_addr)
        .unwrap()
        .pending_new_session()
        .is_some();
    let refused = nodes[1].node.stats().handshake.off_link - off_link;
    cleanup_nodes(&mut nodes).await;
    cleanup_nodes(&mut third).await;
    (to_current, to_source, pending, refused, capable, npaths)
}

/// On a link whose peer is capable and which holds one path, a rekey msg1
/// from the setup address after the path followed the peer elsewhere comes
/// from a pair holding no path: it is refused as off the established link
/// while that link can be reached, and nothing is answered.
#[tokio::test]
async fn a_setup_address_rekey_after_a_roam_of_a_capable_one_path_link_is_refused_while_the_link_is_reachable()
 {
    let got = capable_rekey().await;
    assert!(got.4, "precondition: node 1 holds node 0 capable: {got:?}");
    assert_eq!(got.5, 1, "precondition: node 1 holds one path: {got:?}");
    assert_eq!(
        (got.0, got.1, got.2, got.3),
        (false, false, false, 1),
        "refused as off the established link: {got:?}"
    );
}

/// On a link whose peer is capable, a rekey msg1 from a pair where the
/// responder holds no path is refused while the link is reachable (loopback
/// is connectionless, so it is), even with the pair mapped to the link in
/// `addr_to_link`, as the address a link was set up at stays mapped after
/// its original path moves.
#[tokio::test]
async fn a_capable_links_rekey_from_a_mapped_pair_holding_no_path_is_refused_while_the_link_is_reachable()
 {
    let (mut nodes, b, _a2, _b2) = two_transports(1280).await;
    let a = *nodes[0].node.node_addr();
    let t1 = nodes[1].transport_id;
    assert!(
        nodes[1]
            .node
            .get_peer(&a)
            .unwrap()
            .bundle()
            .unwrap()
            .capable(),
        "precondition: B holds A as capable"
    );
    let elsewhere = add_loopback_alias(&nodes[0].addr, nodes[0].transport_id);
    assert!(
        matches!(
            nodes[1]
                .node
                .get_peer(&a)
                .unwrap()
                .path_match(t1, &elsewhere),
            crate::peer::Match::None
        ),
        "precondition: B holds no path at the pair"
    );
    let link = nodes[1].node.get_peer(&a).unwrap().link_id();
    nodes[1]
        .node
        .links
        .raw_index()
        .insert((t1, elsewhere.clone()), link);
    age_link(&mut nodes, 0, 1, Duration::from_secs(31));
    super::start_link_rekey(&mut nodes[0].node, &b).await;
    let mut msg1 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("A's rekey msg1 is queued at B");
    msg1.remote_addr = elsewhere;
    let off_link = nodes[1].node.stats().handshake.off_link;
    nodes[1].node.handle_msg1(msg1).await;
    assert_eq!(
        nodes[1].node.get_peer(&a).unwrap().pending_role(),
        None,
        "B does not accept the rekey from a pair with no path"
    );
    assert_eq!(
        nodes[1].node.stats().handshake.off_link,
        off_link + 1,
        "B refuses it as off the established link"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A holds p (original, Live, active) and q (t2, acked, Live). One authentic
/// heartbeat from B reaches A on q; twenty copies of that same frame follow
/// on q. Section 5.3 of the multipath draft: a frame the anti-replay window
/// rejects is not an authentication failure, so q stays Live. Counted, the
/// replays would bring q's count to the limit and A would mark q Dead.
#[tokio::test]
async fn replays_of_one_authentic_frame_on_a_standby_path_do_not_mark_it_dead() {
    let (mut nodes, b, a2, b2) = two_transports(1280).await;
    let a = *nodes[0].node.node_addr();
    let on_q = PathRef {
        transport: t2(),
        addr: a2.clone(),
    };
    let heartbeat = [LinkMessageType::Heartbeat.to_byte()];
    nodes[1]
        .node
        .send_via(&a, &heartbeat, false, Some(&on_q))
        .await
        .expect("B's heartbeat goes out on q");
    let packet = nodes[0].packet_rx.try_recv().expect("A has B's frame");
    assert_eq!(packet.transport_id, t2(), "precondition: the frame is on q");
    let (tid, from, data) = (
        packet.transport_id,
        packet.remote_addr.clone(),
        packet.data.clone(),
    );
    nodes[0].node.handle_encrypted_frame(packet).await;
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), Some(PathState::Live));
    for _ in 0..20 {
        let copy = ReceivedPacket::new(tid, from.clone(), data.clone());
        nodes[0].node.handle_encrypted_frame(copy).await;
    }
    assert_eq!(
        state_at(&nodes[0], &b, t2(), &b2),
        Some(PathState::Live),
        "twenty replays of an authentic frame marked the standby path Dead"
    );
    cleanup_nodes(&mut nodes).await;
}

/// The machine's dial fact reads the peer ACL as its accept fact does: for a
/// peer the ACL denies, the node would neither accept its handshake nor
/// initiate one, on any transport (multipath draft Section 5.5).
#[tokio::test]
async fn the_dial_fact_is_false_on_every_transport_for_a_peer_the_acl_denies() {
    use crate::node::handlers::path::NodeFacts;
    use fips_core::proto::path::Facts;
    let (mut nodes, _, _, _) = two_transports(1280).await;
    let transports = &nodes[0].node.transports;
    for held in [TransportId::new(1), t2()] {
        assert!(transports.contains_key(&held), "precondition: {held} held");
        let allowed = NodeFacts {
            transports,
            denied: false,
        };
        assert!(allowed.dials(held), "an allowed peer is dialled on {held}");
        let denied = NodeFacts {
            transports,
            denied: true,
        };
        assert!(!denied.dials(held), "a denied peer is dialled on {held}");
        assert!(!denied.accepts(held), "a denied peer is accepted on {held}");
    }
    cleanup_nodes(&mut nodes).await;
}

/// A holds p (t1) and q (t2) to B, both Live; if `deny`, A's peer ACL is
/// reloaded to deny B, so A would not dial B on any transport; then B closes
/// q, which is Dead at A. Returns how many frames A sends B on t2 over the
/// next 3 s of path ticks, with nothing delivered back.
async fn dead_q_probes_after(deny: bool) -> usize {
    let (mut nodes, b, _, b2) = two_transports(1280).await;
    exchange(&mut nodes).await;
    let _dir = if deny {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("peers.deny");
        std::fs::write(&file, format!("{}\n", nodes[1].node.npub())).unwrap();
        nodes[0]
            .node
            .isolate_peer_acl_for_test(dir.path().join("peers.allow"), file);
        nodes[0].node.reload_peer_acl().await;
        let b_id = crate::PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
        assert!(
            nodes[0]
                .node
                .authorize_peer(
                    &b_id,
                    crate::node::acl::PeerAclContext::OutboundConnect,
                    t2(),
                    &b2,
                )
                .is_err(),
            "precondition: A would not dial B on t2"
        );
        Some(dir)
    } else {
        None
    };
    assert!(
        nodes[0].node.get_peer(&b).is_some(),
        "precondition: the link stays"
    );
    let a = *nodes[0].node.node_addr();
    let paths = nodes[0]
        .node
        .get_peer(&b)
        .unwrap()
        .bundle()
        .unwrap()
        .paths();
    let q_id = paths.get(paths.find(t2(), &b2).unwrap()).unwrap().path_id();
    let close = PathClose {
        path_id: q_id,
        reason: PathCloseReason::Operator,
    };
    nodes[1]
        .node
        .send_encrypted_link_message(&a, &close.encode())
        .await
        .expect("B's close goes out");
    deliver(&mut nodes[0]).await;
    assert_eq!(
        state_at(&nodes[0], &b, t2(), &b2),
        Some(PathState::Dead),
        "precondition: q Dead at A"
    );
    take_queued(&mut nodes[1]);
    for _ in 0..60 {
        crate::time::advance(Duration::from_millis(50));
        nodes[0].node.path_tick().await;
    }
    let sent = t2_taken(&mut nodes);
    cleanup_nodes(&mut nodes).await;
    sent
}

/// A node probes a Dead path only while its path policy allows it
/// (multipath draft Section 5.6), and never on a transport on which it
/// would not initiate a handshake to the peer (Section 5.5). A peer the ACL
/// denies is one the node would not dial on any transport, so after the ACL
/// turns, its Dead path q is not probed.
#[tokio::test]
async fn a_dead_path_of_a_peer_the_acl_now_denies_is_not_probed() {
    let sent = dead_q_probes_after(true).await;
    assert_eq!(
        sent, 0,
        "A probed B's Dead path q on t2 after its ACL denied B"
    );
}

/// The healthy case beside the denied one: an allowed peer's Dead path q is
/// probed at its Dead cadence (multipath draft Section 5.6).
#[tokio::test]
async fn a_dead_path_of_an_allowed_peer_is_probed_at_its_dead_cadence() {
    let sent = dead_q_probes_after(false).await;
    assert!(sent >= 1, "q not probed in 3 s of Dead cadence");
}

/// Queue at `tn`'s loopback transport `id` a beacon of `from`'s key heard
/// from `at`, for the next discovery poll.
pub(super) fn beacon(tn: &TestNode, id: TransportId, at: &TransportAddr, from: &TestNode) {
    loopback(tn, id).inject_discovered(at.clone(), from.node.identity().pubkey());
}

/// Make `tn` last have heard `peer` `secs` seconds ago.
pub(super) fn quiet_for(tn: &mut TestNode, peer: &NodeAddr, secs: u64) {
    tn.node
        .get_peer_mut(peer)
        .expect("the node holds the peer")
        .touch(Node::now_ms().saturating_sub(secs * 1000));
}

/// Whether `tn` holds `peer` as capable.
pub(super) fn capable_at(tn: &TestNode, peer: &NodeAddr) -> bool {
    tn.node
        .get_peer(peer)
        .and_then(|p| p.bundle())
        .is_some_and(|b| b.capable())
}

/// Two linked nodes, A (0) with multipath enabled dialling B (1), each with
/// a second loopback transport `t2()`, A running and dialling what its
/// `t2()` discovers. With `capable`, B has multipath enabled too and A has
/// proven B's second address as a path, so B is capable at A; without it,
/// B has multipath disabled and A holds no second path. Returns the nodes,
/// B's address and B's second address.
async fn dialling_pair(capable: bool) -> (Vec<TestNode>, NodeAddr, TransportAddr) {
    let (mut nodes, b, b2) = if capable {
        let (nodes, b, _a2, b2) = two_transports(1280).await;
        (nodes, b, b2)
    } else {
        let mut nodes = linked_pair(enabled(), disabled()).await;
        second_transport(&mut nodes[0], t2(), 1280);
        let b2 = second_transport(&mut nodes[1], t2(), 1280);
        let b = *nodes[1].node.node_addr();
        (nodes, b, b2)
    };
    assert_eq!(
        capable_at(&nodes[0], &b),
        capable,
        "precondition: B's capability at A"
    );
    nodes[0].node.supervisor.state = NodeState::Running;
    loopback(&nodes[0], t2()).set_autoconnect(true);
    (nodes, b, b2)
}

/// Whether A, quiet from B for `quiet_secs` seconds, dials B's beacon on
/// its second transport, for B capable at A or not.
async fn dials_beacon_after(capable: bool, quiet_secs: u64) -> bool {
    let (mut nodes, b, b2) = dialling_pair(capable).await;
    quiet_for(&mut nodes[0], &b, quiet_secs);
    beacon(&nodes[0], t2(), &b2, &nodes[1]);
    nodes[0].node.poll_transport_discovery().await;
    let dialled = nodes[0].node.is_connecting_to_peer_on_path(&b, t2(), &b2);
    cleanup_nodes(&mut nodes).await;
    dialled
}

/// A node SHOULD NOT initiate a new handshake to a capable peer while the
/// link to it is live, meaning an authentic frame within link-dead, 30 s
/// (multipath v1 draft, Section 5.4). Quiet for 15 s, past the 10 s
/// heartbeat interval, a capable peer's beacon is not dialled; a peer not
/// known to be capable is dialled on it, as before. Mutation: the
/// heartbeat interval's gate for capable peers too.
#[tokio::test]
async fn a_capable_peer_quiet_for_fifteen_seconds_is_not_dialled_and_one_not_capable_is() {
    assert!(
        !dials_beacon_after(true, 15).await,
        "A dialled a capable peer whose link is live"
    );
    assert!(
        dials_beacon_after(false, 15).await,
        "A did not dial a peer not known to be capable, quiet past the \
         heartbeat interval"
    );
}

/// Past link-dead a capable peer's link is no longer live, and its beacon
/// is dialled as before. Mutation: never dial a capable peer.
#[tokio::test]
async fn a_capable_peer_quiet_past_link_dead_is_dialled_as_before() {
    assert!(
        dials_beacon_after(true, 31).await,
        "A did not dial a capable peer quiet past link-dead"
    );
}

/// The sources `tn`'s link to `peer` holds (`transport`, `addr`) from as a
/// candidate, if it holds it.
pub(super) fn sources_at(
    tn: &TestNode,
    peer: &NodeAddr,
    transport: TransportId,
    addr: &TransportAddr,
) -> Option<fips_core::proto::path::Sources> {
    tn.node
        .get_peer(peer)?
        .bundle()?
        .candidates()
        .iter()
        .find(|e| e.transport() == transport && e.addr() == addr)
        .map(|e| e.sources())
}

/// Take every packet queued at `tn`, and return the msg1s among them.
fn msg1s_at(tn: &mut TestNode) -> usize {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG1};
    std::iter::from_fn(|| tn.packet_rx.try_recv().ok())
        .filter(|p| CommonPrefix::parse(&p.data).is_some_and(|c| c.phase == PHASE_MSG1))
        .count()
}

/// The #147 property, kept under multipath: a beacon from a peer whose link
/// is live never starts a handshake, whether or not the peer is capable.
/// With multipath enabled the beacon is a path candidate instead. A's
/// second transport dials what it discovers. Mutation: hand a linked peer's
/// beacon to the dialler whether or not its link is live.
#[tokio::test]
async fn a_beacon_from_a_live_peer_never_starts_a_handshake_whether_or_not_it_is_capable() {
    for capable in [true, false] {
        let (mut nodes, b, b2) = dialling_pair(capable).await;
        beacon(&nodes[0], t2(), &b2, &nodes[1]);
        nodes[0].node.poll_transport_discovery().await;
        assert!(
            !nodes[0].node.is_connecting_to_peer_on_path(&b, t2(), &b2),
            "A dials a live peer's beacon (capable: {capable})"
        );
        assert_eq!(
            msg1s_at(&mut nodes[1]),
            0,
            "a msg1 reached B (capable: {capable})"
        );
        cleanup_nodes(&mut nodes).await;
    }
}

/// A discovered address of a peer not known to be capable is held as a
/// candidate, which opens capability probing: A's step sends one smallest
/// probe on the link's original path, and dials nothing (multipath v1
/// draft, Sections 5.2 and 5.4). Mutation: drop the candidate.
#[tokio::test]
async fn a_discovered_address_of_a_peer_not_known_capable_starts_capability_probing_and_no_dial() {
    let (mut nodes, b, b2) = dialling_pair(false).await;
    let t1 = nodes[0].transport_id;
    take_queued(&mut nodes[1]);
    beacon(&nodes[0], t2(), &b2, &nodes[1]);
    nodes[0].node.poll_transport_discovery().await;
    assert!(
        sources_at(&nodes[0], &b, t2(), &b2).is_some_and(|s| s.has(Source::Discovery)),
        "the beacon's pair is a candidate from discovery"
    );
    let probe_len =
        fips_core::proto::path::wire::PATH_PROBE_MIN_SIZE + crate::proto::fmp::wire::FRAME_OVERHEAD;
    let mut seen = Vec::new();
    while let Ok(packet) = nodes[1].packet_rx.try_recv() {
        seen.push((packet.transport_id, packet.data.len()));
    }
    assert_eq!(
        seen,
        [(t1, probe_len)],
        "one capability probe of the smallest size, on the original path"
    );
    assert!(!nodes[0].node.is_connecting_to_peer_on_path(&b, t2(), &b2));
    assert_eq!(nodes[0].node.get_peer(&b).unwrap().paths().len(), 1);
    cleanup_nodes(&mut nodes).await;
}

/// Two linked nodes with multipath enabled, A (0) dialling B (1), each
/// with a second loopback transport `t2()` that does not auto-connect, as
/// the loopback's default is. B is not yet known to be capable at A.
/// Returns the nodes, B's address and B's second address.
async fn plain_pair() -> (Vec<TestNode>, NodeAddr, TransportAddr) {
    let mut nodes = linked_pair(enabled(), enabled()).await;
    second_transport(&mut nodes[0], t2(), 1280);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    let b = *nodes[1].node.node_addr();
    assert!(
        !capable_at(&nodes[0], &b),
        "precondition: B not yet capable"
    );
    (nodes, b, b2)
}

/// Candidates come from a transport that does not auto-connect, for a peer
/// the node holds a link with (multipath v1 draft, Section 5.5, the third
/// bullet): the beacon's pair is admitted and proven. Mutation: skip
/// transports with `auto_connect` off.
#[tokio::test]
async fn a_beacon_on_a_transport_that_does_not_auto_connect_is_a_candidate_for_a_linked_peer() {
    let (mut nodes, b, b2) = plain_pair().await;
    assert!(!nodes[0].node.transports[&t2()].auto_connect());
    beacon(&nodes[0], t2(), &b2, &nodes[1]);
    nodes[0].node.poll_transport_discovery().await;
    super::rekey_parity::pump(&mut nodes).await;
    assert_eq!(
        state_at(&nodes[0], &b, t2(), &b2),
        Some(PathState::Live),
        "the beacon's pair is proven as a path"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Ported from the earlier multipath branch: a beacon of a live peer on a
/// transport its link does not use is probed, not dialled. The pair is a
/// candidate at once; once the capability probe it opens is answered, it
/// is a Probing path, then Live. No handshake starts at either end.
/// Mutation: no candidate from discovery.
#[tokio::test]
async fn a_beacon_from_a_live_peer_on_a_new_transport_probes_instead_of_dialling() {
    let (mut nodes, b, b2) = plain_pair().await;
    loopback(&nodes[0], t2()).set_autoconnect(true);
    nodes[0].node.supervisor.state = NodeState::Running;
    beacon(&nodes[0], t2(), &b2, &nodes[1]);
    nodes[0].node.poll_transport_discovery().await;
    assert!(!nodes[0].node.is_connecting_to_peer_on_path(&b, t2(), &b2));
    assert!(sources_at(&nodes[0], &b, t2(), &b2).is_some());
    // The capability probe and its answer; A, capable now, admits the pair.
    assert_eq!(deliver(&mut nodes[1]).await, 1, "the capability probe");
    assert_eq!(deliver(&mut nodes[0]).await, 1, "its answer");
    assert!(capable_at(&nodes[0], &b));
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), Some(PathState::Probing));
    super::rekey_parity::pump(&mut nodes).await;
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), Some(PathState::Live));
    assert_eq!(nodes[0].node.peer_count(), 1);
    assert_eq!(nodes[1].node.peer_count(), 1);
    assert!(
        !nodes[1]
            .node
            .peer_machines
            .values()
            .any(|m| m.leg().is_some())
            && !nodes[0]
                .node
                .peer_machines
                .values()
                .any(|m| m.leg().is_some()),
        "no handshake is in flight at either end"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Ported from the earlier multipath branch, as the machine now does it: a
/// beaconed pair of a capable peer is admitted and probed in the step that
/// takes the beacon, and a Probing path keeps one probe outstanding, so a
/// path tick after its next probe falls due but before the first probe's
/// timeout sends nothing more on it. Mutation: let a Probing path keep the
/// ring outstanding.
#[tokio::test]
async fn a_beaconed_path_is_probed_at_once_and_keeps_one_probe_in_flight() {
    let (mut nodes, b, _a2, _b2) = two_transports(1280).await;
    let t3 = TransportId::new(3);
    second_transport(&mut nodes[0], t3, 1280);
    let b3 = second_transport(&mut nodes[1], t3, 1280);
    take_queued(&mut nodes[1]);
    beacon(&nodes[0], t3, &b3, &nodes[1]);
    nodes[0].node.poll_transport_discovery().await;
    let on_t3 =
        |seen: &[(TransportId, TransportAddr)]| seen.iter().filter(|(t, _)| *t == t3).count();
    assert_eq!(
        on_t3(&take_queued(&mut nodes[1])),
        1,
        "one probe on the beaconed pair, in the step that took the beacon"
    );
    assert_eq!(state_at(&nodes[0], &b, t3, &b3), Some(PathState::Probing));
    let (next, timeout) = {
        let paths = nodes[0]
            .node
            .get_peer(&b)
            .unwrap()
            .bundle()
            .unwrap()
            .paths();
        let live = paths.get(paths.find(t3, &b3).unwrap()).unwrap().live();
        let next = live.next_at().expect("a next probe is scheduled");
        let timeout = live
            .earliest_due()
            .expect("the first probe is outstanding with a deadline");
        (next, timeout)
    };
    assert!(
        next < timeout,
        "precondition: the next probe falls due before the first times out"
    );
    advance_to(next, Duration::ZERO);
    nodes[0].node.path_tick().await;
    assert!(
        crate::peer::peer_now() < timeout,
        "precondition: the first probe has not timed out"
    );
    assert_eq!(
        on_t3(&take_queued(&mut nodes[1])),
        0,
        "a second probe went out while the first was in flight"
    );
    assert_eq!(state_at(&nodes[0], &b, t3, &b3), Some(PathState::Probing));
    cleanup_nodes(&mut nodes).await;
}

/// A won crossed handshake starts the link's path machine again with an
/// empty candidate table, so the node forgets what its sources listed for
/// the old one: the peer's next beacon, well inside the beacon silence,
/// offers the pair to the new machine. Checked at the smaller node, the one
/// whose link moves, with the peer quiet past link-dead so the dial goes
/// out. Mutation: no forget when the machine starts again.
#[tokio::test]
async fn a_won_cross_connection_is_offered_its_peers_beaconed_pair_again() {
    let mut nodes = linked_pair(enabled(), enabled()).await;
    let (s, l, l_addr) = smaller_first(&nodes);
    let ts = nodes[s].transport_id;
    let l2 = add_loopback_alias(&nodes[l].addr, nodes[l].transport_id);
    beacon(&nodes[s], ts, &l2, &nodes[l]);
    nodes[s].node.poll_transport_discovery().await;
    super::rekey_parity::pump(&mut nodes).await;
    assert_eq!(
        state_at(&nodes[s], &l_addr, ts, &l2),
        Some(PathState::Live),
        "precondition: the beaconed pair is a path"
    );

    cross_move_dead(&mut nodes, s, l).await;
    assert_eq!(
        sources_at(&nodes[s], &l_addr, ts, &l2),
        None,
        "precondition: the new machine's table is empty"
    );
    assert_eq!(state_at(&nodes[s], &l_addr, ts, &l2), None);

    beacon(&nodes[s], ts, &l2, &nodes[l]);
    nodes[s].node.poll_transport_discovery().await;
    assert!(
        sources_at(&nodes[s], &l_addr, ts, &l2).is_some_and(|s| s.has(Source::Discovery)),
        "the next beacon offers the pair to the new machine"
    );
    cleanup_nodes(&mut nodes).await;
}

/// The switching milestone: with multipath enabled, a linked pair finds its
/// second path by discovery, proves it, and moves the link to it when the
/// first path's carrier is lost. Mutation: no candidate from discovery.
#[tokio::test]
async fn a_linked_pair_finds_its_second_path_by_discovery_and_moves_to_it_on_carrier_loss() {
    let (mut nodes, b, b2) = plain_pair().await;
    let t1 = nodes[0].transport_id;
    beacon(&nodes[0], t2(), &b2, &nodes[1]);
    nodes[0].node.poll_transport_discovery().await;
    super::rekey_parity::pump(&mut nodes).await;
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), Some(PathState::Live));
    assert_eq!(
        active_of(&nodes[0], &b).0,
        t1,
        "precondition: the link is on t1"
    );
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    carrier(&mut nodes, t1, true).await;
    carrier(&mut nodes, t1, false).await;
    let switched = logs.lines_with("Path switched");
    drop(guard);
    assert_eq!(switched.len(), 1, "{switched:?}");
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2));
    cleanup_nodes(&mut nodes).await;
}

/// Nodes A (0) built from `a` and B (1) built from `b`, where `who`'s
/// configuration names the other, connected manually, at its address and
/// at `extra` more addresses of its on its one transport; then A dials B.
/// Returns the nodes and the extra addresses.
async fn configured_pair(
    a: Config,
    b: Config,
    who: usize,
    extra: usize,
) -> (Vec<TestNode>, Vec<TransportAddr>) {
    let mut nodes = vec![
        make_test_node_with_config(a, 1280).await,
        make_test_node_with_config(b, 1280).await,
    ];
    let other = 1 - who;
    let aliases: Vec<TransportAddr> = (0..extra)
        .map(|_| add_loopback_alias(&nodes[other].addr, nodes[other].transport_id))
        .collect();
    configure(&mut nodes, who, &aliases).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let other_addr = *nodes[other].node.node_addr();
    assert!(
        nodes[who].node.get_peer(&other_addr).is_some(),
        "precondition: the pair is linked"
    );
    (nodes, aliases)
}

/// Set `who`'s configured peers to the other node, connected manually, at
/// its address and at `aliases`.
pub(super) async fn configure(nodes: &mut [TestNode], who: usize, aliases: &[TransportAddr]) {
    let other = 1 - who;
    let mut addresses = vec![crate::config::PeerAddress::new(
        "loopback",
        nodes[other].addr.to_string(),
    )];
    addresses.extend(
        aliases
            .iter()
            .map(|a| crate::config::PeerAddress::new("loopback", a.to_string())),
    );
    let peer = crate::config::PeerConfig {
        npub: nodes[other].node.npub(),
        alias: None,
        addresses,
        connect_policy: crate::config::ConnectPolicy::Manual,
        auto_reconnect: false,
        via_nostr: false,
    };
    nodes[who]
        .node
        .update_peers(vec![peer])
        .await
        .expect("the peer list is accepted");
}

/// A linked peer's configured addresses are path candidates from the
/// moment the link is promoted: a second configured address of a capable
/// peer is admitted and proven. Mutation: no offer of configured addresses
/// at promotion or on the discovery tick.
#[tokio::test]
async fn a_configured_second_address_of_a_linked_peer_becomes_a_path() {
    let (mut nodes, aliases) = configured_pair(enabled(), enabled(), 0, 1).await;
    let b = *nodes[1].node.node_addr();
    let t1 = nodes[0].transport_id;
    super::rekey_parity::pump(&mut nodes).await;
    assert!(
        sources_at(&nodes[0], &b, t1, &aliases[0]).is_some_and(|s| s.has(Source::Config)),
        "the configured address is a candidate from configuration"
    );
    assert_eq!(
        state_at(&nodes[0], &b, t1, &aliases[0]),
        Some(PathState::Live),
        "the configured second address is proven as a path"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A won crossed handshake starts the link's path machine again with an
/// empty candidate table; the configured second address is offered to the
/// new machine at once, and admitted and probed once the peer shows it is
/// capable again. Checked at the smaller node, whose link moves, with the
/// peer quiet past link-dead so the dial goes out. Mutation: no forget when
/// the machine starts again.
#[tokio::test]
async fn a_configured_second_address_is_offered_to_the_bundle_of_a_won_cross_connection() {
    let mut nodes = vec![
        make_test_node_with_config(enabled(), 1280).await,
        make_test_node_with_config(enabled(), 1280).await,
    ];
    let (s, l, l_addr) = smaller_first(&nodes);
    let l2 = add_loopback_alias(&nodes[l].addr, nodes[l].transport_id);
    configure(&mut nodes, s, std::slice::from_ref(&l2)).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    super::rekey_parity::pump(&mut nodes).await;
    let ts = nodes[s].transport_id;
    assert_eq!(
        state_at(&nodes[s], &l_addr, ts, &l2),
        Some(PathState::Live),
        "precondition: the configured address is a path"
    );

    cross_move_dead(&mut nodes, s, l).await;
    assert!(
        !capable_at(&nodes[s], &l_addr),
        "precondition: a new machine"
    );
    assert!(
        sources_at(&nodes[s], &l_addr, ts, &l2).is_some_and(|s| s.has(Source::Config)),
        "the new machine holds the configured address as a candidate"
    );
    super::rekey_parity::pump(&mut nodes).await;
    assert!(capable_at(&nodes[s], &l_addr));
    assert!(
        state_at(&nodes[s], &l_addr, ts, &l2).is_some(),
        "the configured address is admitted once the peer is capable again"
    );
    cleanup_nodes(&mut nodes).await;
}

/// When the configuration no longer lists a peer's second address, the
/// address is unlisted, and with no candidate left the link stops probing a
/// peer not known to be capable (multipath v1 draft, Section 5.2).
/// Mutation: never unlist from a whole list.
#[tokio::test]
async fn dropping_a_peers_only_candidate_from_the_configuration_stops_capability_probing() {
    let (mut nodes, aliases) = configured_pair(enabled(), disabled(), 0, 1).await;
    let b = *nodes[1].node.node_addr();
    let t1 = nodes[0].transport_id;
    let sent = |nodes: &[TestNode]| {
        nodes[0]
            .node
            .get_peer(&b)
            .unwrap()
            .bundle()
            .unwrap()
            .capability()
            .sent()
    };
    assert!(sent(&nodes) >= 1, "precondition: A is probing capability");
    assert!(sources_at(&nodes[0], &b, t1, &aliases[0]).is_some());

    configure(&mut nodes, 0, &[]).await;
    assert_eq!(
        sources_at(&nodes[0], &b, t1, &aliases[0]),
        None,
        "the dropped address is no longer a candidate"
    );
    let before = sent(&nodes);
    for _ in 0..40 {
        crate::time::advance(Duration::from_secs(1));
        nodes[0].node.path_tick().await;
        take_queued(&mut nodes[1]);
    }
    assert_eq!(
        sent(&nodes),
        before,
        "a capability probe went out with no candidate left"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Linked nodes A (0) and B (1), A with multipath enabled and B with it
/// when `capable`, each with a second loopback transport `t2()`. With
/// `capable`, A has proven a second address of B's on its first transport,
/// so B is capable at A and A holds nothing on `t2()`. Returns the nodes,
/// B's address, and A's and B's second addresses.
async fn heard_pair(capable: bool) -> (Vec<TestNode>, NodeAddr, TransportAddr, TransportAddr) {
    let b_cfg = if capable { enabled() } else { disabled() };
    let mut nodes = linked_pair(enabled(), b_cfg).await;
    let a2 = second_transport(&mut nodes[0], t2(), 1280);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    let b = *nodes[1].node.node_addr();
    if capable {
        let t1 = nodes[0].transport_id;
        let q = add_loopback_alias(&nodes[1].addr, nodes[1].transport_id);
        nodes[0].node.offer_path(&b, t1, q).await;
        super::rekey_parity::pump(&mut nodes).await;
    }
    assert_eq!(
        capable_at(&nodes[0], &b),
        capable,
        "precondition: B's capability"
    );
    take_queued(&mut nodes[1]);
    (nodes, b, a2, b2)
}

/// B's heartbeat sent to A's second address, from B's second transport.
async fn heartbeat_on_t2(nodes: &mut [TestNode], a2: &TransportAddr) {
    let a = *nodes[0].node.node_addr();
    let to = PathRef {
        transport: t2(),
        addr: a2.clone(),
    };
    nodes[1]
        .node
        .send_via(
            &a,
            &[LinkMessageType::Heartbeat.to_byte()],
            false,
            Some(&to),
        )
        .await
        .expect("B's heartbeat goes out on its second transport");
}

/// An authentic frame from a pair the link holds no path at makes the pair a
/// candidate the peer is heard from, and creates no path by itself
/// (multipath v1 draft, Section 5.3). For a peer not known to be capable
/// the candidate is held and nothing more; on a capable link it is admitted
/// as a Probing path in the step that takes the frame, and probed once.
/// Mutation: no report of a pair heard from on no path.
#[tokio::test]
async fn an_authentic_frame_from_a_second_transport_offers_its_pair_and_creates_no_path_by_itself()
{
    for capable in [false, true] {
        let (mut nodes, b, a2, b2) = heard_pair(capable).await;
        let held = nodes[0].node.get_peer(&b).unwrap().paths().len();
        heartbeat_on_t2(&mut nodes, &a2).await;
        assert_eq!(
            handle_one(&mut nodes[0]).await,
            Some(t2()),
            "precondition: B's frame reached A on its second transport"
        );
        assert!(
            sources_at(&nodes[0], &b, t2(), &b2).is_some_and(|s| s.has(Source::Heard)),
            "the pair is a candidate the peer is heard from (capable: {capable})"
        );
        let on_t2 = take_queued(&mut nodes[1])
            .iter()
            .filter(|(t, _)| *t == t2())
            .count();
        if capable {
            assert_eq!(
                state_at(&nodes[0], &b, t2(), &b2),
                Some(PathState::Probing),
                "admitted as a Probing path in the frame's step"
            );
            assert_eq!(on_t2, 1, "one probe on the heard pair");
        } else {
            assert_eq!(
                nodes[0].node.get_peer(&b).unwrap().paths().len(),
                held,
                "no path for a peer not known to be capable"
            );
            assert_eq!(on_t2, 0, "nothing sent on the heard pair");
        }
        cleanup_nodes(&mut nodes).await;
    }
}

/// Handle the one packet queued at `tn`, and return the transport it came
/// on; `None` if none was queued.
async fn handle_one(tn: &mut TestNode) -> Option<TransportId> {
    let packet = tn.packet_rx.try_recv().ok()?;
    let on = packet.transport_id;
    tn.node.handle_encrypted_frame(packet).await;
    assert!(tn.packet_rx.try_recv().is_err(), "one packet was queued");
    Some(on)
}

/// A path probe from a pair the link holds no path at, on a transport that
/// does not accept, creates no path and lists no candidate: the frame that
/// carries a path message is never reported as heard, so the probe's own
/// rules decide (multipath v1 draft, Sections 5.1 and 5.5). Green before
/// the heard-from intake too. Mutation: report a path message's frame as
/// heard (the pair is then admitted).
#[tokio::test]
async fn a_probe_from_no_path_on_a_transport_that_does_not_accept_creates_no_path() {
    let (mut nodes, b, a2, b2) = heard_pair(true).await;
    loopback(&nodes[0], t2()).set_accepts(false);
    let a = *nodes[0].node.node_addr();
    let to = PathRef {
        transport: t2(),
        addr: a2.clone(),
    };
    nodes[1]
        .node
        .send_via(&a, &probe(0x3456, 64), false, Some(&to))
        .await
        .expect("B's probe goes out on its second transport");
    assert_eq!(handle_one(&mut nodes[0]).await, Some(t2()));
    assert_eq!(
        state_at(&nodes[0], &b, t2(), &b2),
        None,
        "no path at the pair"
    );
    assert_eq!(
        sources_at(&nodes[0], &b, t2(), &b2),
        None,
        "no candidate at the pair"
    );
    assert_eq!(
        take_queued(&mut nodes[1])
            .iter()
            .filter(|(t, _)| *t == t2())
            .count(),
        0,
        "the probe is refused, not answered"
    );
    cleanup_nodes(&mut nodes).await;
}
