//! The msg1 back-off for an identity whose sessions end without one
//! authenticated frame.
//!
//! A crafted msg1 (`craft_msg1_wire`) models a peer that completes msg1 and
//! then sends nothing: the sender's handshake state is discarded, so nothing
//! it could send would ever authenticate. Each crafted msg1 uses a fresh
//! sender index, so each is a distinct attempt, as a real redial is. The
//! link-dead reaper is driven by a 0 s timeout and `check_link_heartbeats`.

use super::establish_chartests::{craft_msg1_wire, register_udp_with_peer_socket};
use super::heartbeat::set_link_dead_timeout;
use super::spanning_tree::{TestNode, cleanup_nodes, drain_all_packets, initiate_handshake};
use super::*;
use crate::config::Config;
use crate::testutil::{capture_logs_scoped, log_field};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// The epoch the silent sessions run at.
pub(super) const EPOCH: [u8; 8] = [7u8; 8];

/// The same peer after a restart.
const NEW_EPOCH: [u8; 8] = [8u8; 8];

/// The line each refused msg1 logs.
const REFUSAL: &str =
    "Msg1 from a peer whose recent sessions carried no frame, refusing during its back-off";

/// How long ago `Rig::idle` puts the silent session's promotion and its
/// last-seen time. A never-heard peering is replaceable by a same-epoch msg1
/// once its age since promotion reaches `UNHEARD_PEERING_MIN_AGE_MS`; this is
/// well past that.
const IDLE_MS: u64 = 16_000;

/// A node with one UDP transport, and a socket playing the silent peer.
pub(super) struct Rig {
    pub(super) node: Node,
    transport_id: TransportId,
    sock: UdpSocket,
    from: TransportAddr,
    sender: Identity,
    next_index: u32,
}

impl Rig {
    /// A fresh node and a fresh silent identity, with the reaper armed.
    pub(super) async fn new() -> Self {
        let mut node = make_node();
        let transport_id = TransportId::new(1);
        let (sock, from) = register_udp_with_peer_socket(&mut node, transport_id).await;
        set_link_dead_timeout(&mut node, 0);
        Self {
            node,
            transport_id,
            sock,
            from,
            sender: Identity::generate(),
            next_index: 0x100,
        }
    }

    /// The silent identity's address.
    pub(super) fn peer(&self) -> NodeAddr {
        *PeerIdentity::from_pubkey_full(self.sender.pubkey_full()).node_addr()
    }

    /// A new msg1 from the silent identity at `epoch`.
    pub(super) fn msg1(&mut self, epoch: [u8; 8]) -> Vec<u8> {
        self.next_index += 1;
        craft_msg1_wire(
            &self.node,
            &self.sender,
            epoch,
            SessionIndex::new(self.next_index),
            Node::now_ms(),
        )
    }

    /// Deliver `data` as a msg1 from the peer socket.
    pub(super) async fn deliver(&mut self, data: Vec<u8>) {
        let packet = ReceivedPacket {
            transport_id: self.transport_id,
            remote_addr: self.from.clone(),
            data,
            timestamp_ms: Node::now_ms(),
        };
        self.node.handle_msg1(packet).await;
    }

    /// The silent identity's current link, if it is a peer.
    pub(super) fn link(&self) -> Option<LinkId> {
        self.node.get_peer(&self.peer()).map(|p| p.link_id())
    }

    /// Deliver a new msg1 at `epoch` and assert it was promoted, returning
    /// the new link.
    async fn promote(&mut self, epoch: [u8; 8]) -> LinkId {
        let before = self.link();
        let data = self.msg1(epoch);
        self.deliver(data).await;
        let link = self.link().expect("the msg1 was promoted");
        assert_ne!(Some(link), before, "the msg1 promoted a new session");
        link
    }

    /// Run the link-dead reaper and assert it removed the silent identity.
    pub(super) async fn reap(&mut self) {
        self.node.check_link_heartbeats().await;
        assert!(self.link().is_none(), "the reaper removed the silent peer");
    }

    /// Make the silent identity's session replaceable: idle past the
    /// liveness interval without a frame, promoted that long ago (a peering
    /// never heard from is aged from its promotion), and no dampener stamp.
    fn idle(&mut self, idle_ms: u64) {
        let peer = self.peer();
        let session = self
            .node
            .get_peer_mut(&peer)
            .expect("the silent peer is present");
        session.test_set_last_seen(Node::now_ms() - idle_ms);
        session.test_set_authenticated_at(Node::now_ms() - idle_ms);
        self.node.restart_dampener.clear();
    }

    /// Discard whatever the node has sent the peer socket so far, and return
    /// how many packets that was.
    pub(super) async fn drain(&self) -> usize {
        let mut buf = [0u8; 2048];
        let mut n = 0;
        while timeout(Duration::from_millis(100), self.sock.recv_from(&mut buf))
            .await
            .is_ok()
        {
            n += 1;
        }
        n
    }

    pub(super) fn silent_rejects(&self) -> u64 {
        self.node.stats().handshake.silent_backoff
    }

    fn bad_state(&self) -> u64 {
        self.node.stats().handshake.bad_state
    }
}

/// Three silent sessions at [`EPOCH`], each promoted and reaped.
async fn three_reaped(rig: &mut Rig) {
    for _ in 0..3 {
        rig.promote(EPOCH).await;
        rig.reap().await;
    }
    rig.drain().await;
}

/// Four sessions at [`EPOCH`], each replacing the last after it went idle
/// without a frame, which ends three of them silent. Leaves the fourth
/// present.
async fn three_replaced(rig: &mut Rig) {
    rig.promote(EPOCH).await;
    for _ in 0..3 {
        rig.idle(IDLE_MS);
        rig.promote(EPOCH).await;
    }
    rig.drain().await;
}

#[tokio::test]
async fn three_silent_sessions_ended_by_link_dead_refuse_the_next_same_epoch_msg1_with_its_own_counter()
 {
    let mut rig = Rig::new().await;
    three_reaped(&mut rig).await;
    let (refused, bad) = (rig.silent_rejects(), rig.bad_state());

    let data = rig.msg1(EPOCH);
    rig.deliver(data).await;

    assert!(rig.link().is_none(), "the fourth msg1 was promoted");
    assert_eq!(rig.silent_rejects(), refused + 1);
    assert_eq!(
        rig.bad_state(),
        bad,
        "the refusal is not counted as bad state"
    );
    assert_eq!(rig.drain().await, 0, "a refused msg1 is not answered");
}

#[tokio::test]
async fn refused_msg1s_during_a_back_off_log_three_lines_then_one_suppression_notice() {
    let mut rig = Rig::new().await;
    three_reaped(&mut rig).await;
    let refused = rig.silent_rejects();

    let (logs, guard) = capture_logs_scoped();
    for _ in 0..8 {
        let data = rig.msg1(EPOCH);
        rig.deliver(data).await;
    }
    drop(guard);

    assert_eq!(logs.lines_with(REFUSAL).len(), 3, "{:#?}", logs.lines());
    let notices = logs.lines_with("Suppressing repeated handshake lines for this peer");
    assert_eq!(notices.len(), 1, "{:#?}", logs.lines());
    assert_eq!(log_field(&notices[0], "kind"), Some("refused"));
    assert_eq!(
        rig.silent_rejects(),
        refused + 8,
        "every refusal is counted"
    );
    assert!(rig.link().is_none(), "nothing was promoted");
}

#[tokio::test]
async fn three_silent_sessions_ended_by_replacement_refuse_the_next_same_epoch_msg1() {
    let mut rig = Rig::new().await;
    three_replaced(&mut rig).await;
    let link = rig.link();
    let refused = rig.silent_rejects();

    rig.idle(IDLE_MS);
    let data = rig.msg1(EPOCH);
    rig.deliver(data).await;

    assert_eq!(rig.link(), link, "the fifth msg1 replaced the session");
    assert_eq!(rig.silent_rejects(), refused + 1);
}

#[tokio::test]
async fn a_replayed_msg1_counts_once_however_often_its_sessions_end_silent() {
    // One captured msg1, replayed after each reap, promotes sessions that can
    // never carry a frame. They must not refuse the identity's genuine msg1s.
    let mut rig = Rig::new().await;
    let captured = rig.msg1(EPOCH);
    for _ in 0..3 {
        rig.deliver(captured.clone()).await;
        assert!(rig.link().is_some(), "the replay was promoted");
        rig.reap().await;
    }
    rig.drain().await;
    let refused = rig.silent_rejects();

    rig.promote(EPOCH).await;

    assert_eq!(rig.silent_rejects(), refused);
}

#[tokio::test]
async fn a_new_epoch_msg1_is_promoted_during_the_back_off_when_no_session_is_left() {
    let mut rig = Rig::new().await;
    three_reaped(&mut rig).await;
    rig.promote(NEW_EPOCH).await;
    assert_eq!(
        rig.node.get_peer(&rig.peer()).unwrap().remote_epoch(),
        Some(NEW_EPOCH)
    );
}

#[tokio::test]
async fn a_new_epoch_msg1_from_a_peer_idle_15_s_restarts_it_during_the_back_off() {
    let mut rig = Rig::new().await;
    three_replaced(&mut rig).await;
    let data = rig.msg1(EPOCH);
    rig.idle(IDLE_MS);
    rig.deliver(data).await;
    assert!(
        rig.silent_rejects() > 0,
        "precondition: the back-off is running"
    );

    rig.idle(15_000);
    rig.promote(NEW_EPOCH).await;
    assert_eq!(
        rig.node.get_peer(&rig.peer()).unwrap().remote_epoch(),
        Some(NEW_EPOCH)
    );
}

/// Discard everything queued at `tn` without processing it.
fn discard(tn: &mut TestNode) {
    while tn.packet_rx.try_recv().is_ok() {}
}

/// Deliver a crafted msg1 carrying node 0's identity and epoch to node 1, as
/// if node 0 had sent it and then never sent a frame. Returns whether node 1
/// promoted it.
async fn silent_session_of_node0(nodes: &mut [TestNode], index: u32) -> bool {
    let a = *nodes[0].node.node_addr();
    let data = craft_msg1_wire(
        &nodes[1].node,
        nodes[0].node.identity(),
        nodes[0].node.startup_epoch(),
        SessionIndex::new(index),
        Node::now_ms(),
    );
    let packet = ReceivedPacket {
        transport_id: nodes[1].transport_id,
        remote_addr: nodes[0].addr.clone(),
        data,
        timestamp_ms: Node::now_ms(),
    };
    nodes[1].node.handle_msg1(packet).await;
    discard(&mut nodes[0]);
    nodes[1].node.get_peer(&a).is_some()
}

/// Reap node 1's silent session with node 0's identity.
async fn reap_node0(nodes: &mut [TestNode]) {
    let a = *nodes[0].node.node_addr();
    nodes[1].node.check_link_heartbeats().await;
    discard(&mut nodes[0]);
    assert!(
        nodes[1].node.get_peer(&a).is_none(),
        "the reaper removed it"
    );
}

#[tokio::test]
async fn one_authenticated_frame_clears_the_count_so_three_more_silent_sessions_are_needed() {
    let mut nodes = vec![
        spanning_tree::make_test_node_with_config(Config::new(), 1280).await,
        spanning_tree::make_test_node_with_config(Config::new(), 1280).await,
    ];
    let a = *nodes[0].node.node_addr();
    set_link_dead_timeout(&mut nodes[1].node, 0);

    for index in 1..=3 {
        assert!(silent_session_of_node0(&mut nodes, index).await);
        reap_node0(&mut nodes).await;
    }
    assert!(
        !silent_session_of_node0(&mut nodes, 4).await,
        "precondition: node 0's msg1s are refused"
    );

    // Node 1 dials node 0 while it refuses node 0's msg1s: its own dial
    // completes, and node 0's first frame on it clears the record.
    initiate_handshake(&mut nodes, 1, 0).await;
    drain_all_packets(&mut nodes, false).await;
    let peer = nodes[1].node.get_peer(&a).expect("node 1's dial completed");
    assert!(peer.heard(), "node 0's frames reached node 1");
    assert_eq!(nodes[1].node.silent_sessions.count(&a), None);

    // A session that carried frames is not counted when it ends.
    nodes[1].node.remove_active_peer(&a);
    discard(&mut nodes[0]);
    assert_eq!(nodes[1].node.silent_sessions.count(&a), None);

    // Two more silent sessions do not reach the limit again.
    for index in 5..=6 {
        assert!(silent_session_of_node0(&mut nodes, index).await);
        reap_node0(&mut nodes).await;
    }
    assert!(
        silent_session_of_node0(&mut nodes, 7).await,
        "the count went on from before the authenticated frame"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn the_first_frame_after_a_back_off_reports_how_many_refusal_lines_were_suppressed() {
    let mut nodes = vec![
        spanning_tree::make_test_node_with_config(Config::new(), 1280).await,
        spanning_tree::make_test_node_with_config(Config::new(), 1280).await,
    ];
    let a = *nodes[0].node.node_addr();
    set_link_dead_timeout(&mut nodes[1].node, 0);
    for index in 1..=3 {
        assert!(silent_session_of_node0(&mut nodes, index).await);
        reap_node0(&mut nodes).await;
    }
    for index in 4..=8 {
        assert!(!silent_session_of_node0(&mut nodes, index).await);
    }

    // Node 1's own dial completes, and node 0's first frame on it clears
    // the record that refused five msg1s.
    let (logs, guard) = capture_logs_scoped();
    initiate_handshake(&mut nodes, 1, 0).await;
    drain_all_packets(&mut nodes, false).await;
    drop(guard);
    assert!(nodes[1].node.get_peer(&a).is_some_and(|p| p.heard()));

    let summaries = logs.lines_with("Suppressed repeated handshake lines");
    assert_eq!(summaries.len(), 1, "{:#?}", logs.lines());
    assert_eq!(log_field(&summaries[0], "refused"), Some("2"));

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn sessions_that_carried_a_frame_never_count_toward_the_back_off() {
    let mut nodes = vec![
        spanning_tree::make_test_node_with_config(Config::new(), 1280).await,
        spanning_tree::make_test_node_with_config(Config::new(), 1280).await,
    ];
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();

    for round in 0..4 {
        initiate_handshake(&mut nodes, 0, 1).await;
        drain_all_packets(&mut nodes, false).await;
        let at_b = nodes[1].node.get_peer(&a);
        assert!(
            at_b.is_some(),
            "round {round}: node 1 promoted node 0's msg1"
        );
        assert!(at_b.unwrap().heard(), "round {round}: node 1 heard node 0");
        assert!(
            nodes[0].node.get_peer(&b).is_some_and(|p| p.heard()),
            "round {round}: node 0 heard node 1"
        );
        nodes[0].node.remove_active_peer(&b);
        nodes[1].node.remove_active_peer(&a);
        discard(&mut nodes[0]);
        discard(&mut nodes[1]);
    }
    assert_eq!(nodes[1].node.silent_sessions.count(&a), None);
    assert_eq!(nodes[0].node.silent_sessions.count(&b), None);
    assert_eq!(nodes[1].node.stats().handshake.silent_backoff, 0);

    cleanup_nodes(&mut nodes).await;
}
