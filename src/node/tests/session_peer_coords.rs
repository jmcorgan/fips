//! A session peer's own authenticated coordinates against verified
//! precedence, and the endpoint's write of them.
//!
//! FRC-1404 Section 4.5.2: a node must not refuse under verified precedence
//! the hint write a session endpoint makes, under the address of the
//! session's peer, from the coordinates the peer states for itself in a
//! message of the session that has authenticated, when those coordinates
//! differ from the entry's. There are two such writes: the initiator's write
//! of a `SessionAck`'s source coordinates once msg2 authenticates, and the
//! endpoint's write of an established message's source coordinates once it
//! authenticates. The endpoint makes the second only after authentication;
//! before it, an established message's coordinates are not read.
//!
//! The case: this node looked the peer up, so it holds a verified entry with
//! the coordinates the lookup proved; the peer has since moved, and its
//! session messages state where it now is. The pair fixture is two linked
//! nodes, the initiator `A` at the root and the peer `B` under it. `B`'s
//! former position is under a node `X` that is not in the mesh, below the
//! same root.

use super::*;
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, populate_all_coord_caches, process_available_packets, run_tree_test,
    verify_tree_convergence,
};
use crate::proto::fsp::SessionMessageType;
use crate::proto::fsp::wire::{FSP_FLAG_CP, build_fsp_header};
use crate::proto::link::SessionDatagram;
use crate::proto::stp::{TreeCoordinate, encode_coords};

/// Wall-clock milliseconds, the clock the warm write and the cache read.
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// The node addresses of `coords`, from the node to the root.
fn path(coords: &TreeCoordinate) -> Vec<NodeAddr> {
    coords.node_addrs().copied().collect()
}

/// The two nodes, with `a` the root of the tree they form.
struct Pair {
    nodes: Vec<TestNode>,
    a: usize,
    b: usize,
}

impl Pair {
    fn addr(&self, i: usize) -> NodeAddr {
        *self.nodes[i].node.node_addr()
    }

    /// `B`'s coordinates as `B` states them on the wire: the path of node
    /// addresses, without the per-entry metadata its own tree state keeps.
    fn b_now(&self) -> Vec<NodeAddr> {
        path(self.nodes[self.b].node.tree_state().my_coords())
    }

    /// `B`'s former position: under `X`, below the same root.
    fn b_before(&self) -> TreeCoordinate {
        let x = make_node_addr(0x77);
        TreeCoordinate::from_addrs(vec![self.addr(self.b), x, self.addr(self.a)]).unwrap()
    }

    /// The coordinates `A` holds for `B`, and whether they are verified.
    fn held_at_a(&self) -> (TreeCoordinate, bool) {
        let entry = self.nodes[self.a]
            .node
            .coord_cache()
            .get_entry(&self.addr(self.b))
            .expect("A holds an entry for B");
        (entry.coords().clone(), entry.is_verified(wall_ms()))
    }

    /// Frames `A` has authenticated on its session with `B`.
    fn authenticated_at_a(&self) -> u64 {
        self.nodes[self.a]
            .node
            .get_session(&self.addr(self.b))
            .and_then(|s| s.mmp())
            .map_or(0, |m| m.receiver.cumulative_packets_recv())
    }

    /// Give `A` a verified entry for `B` at `B`'s former position.
    fn verify_former_position(&mut self) {
        let (b, before) = (self.addr(self.b), self.b_before());
        self.nodes[self.a]
            .node
            .coord_cache_mut()
            .insert_verified(b, before.clone(), wall_ms());
        assert_eq!(
            self.held_at_a(),
            (before, true),
            "precondition: A holds B's former position, verified"
        );
    }

    /// The path of the entry `A` holds for `B`, if any.
    fn held_path(&self) -> Option<Vec<NodeAddr>> {
        self.nodes[self.a]
            .node
            .coord_cache()
            .get_entry(&self.addr(self.b))
            .map(|entry| path(entry.coords()))
    }

    /// Hand `A` a `SessionDatagram` from `B` to `A` carrying `fsp_payload`,
    /// arriving over its link with `B`.
    async fn deliver(&mut self, fsp_payload: Vec<u8>) {
        let (a, b) = (self.addr(self.a), self.addr(self.b));
        let encoded = SessionDatagram::new(b, a, fsp_payload).encode();
        self.nodes[self.a]
            .node
            .handle_session_datagram(&b, &encoded[1..], false)
            .await;
    }

    /// A `CoordsWarmup` that `B` seals on its session with `A`, carrying
    /// `src` in the cleartext source-coordinate slot. The coordinate block
    /// is outside the AEAD, so the frame authenticates whatever it holds, as
    /// it would after a node on the path rewrote it.
    fn warmup_stating(&mut self, src: &TreeCoordinate) -> Vec<u8> {
        let a = self.addr(self.a);
        let a_coords = self.nodes[self.a].node.tree_state().my_coords().clone();
        let frame = self.nodes[self.b]
            .node
            .sessions
            .get_mut(&a)
            .expect("B holds the session")
            .seal_frame(
                Node::session_now(),
                FSP_FLAG_CP,
                SessionMessageType::CoordsWarmup.to_byte(),
                &[],
            )
            .expect("B seals a CoordsWarmup");
        let mut payload = frame.header.to_vec();
        encode_coords(src, &mut payload);
        encode_coords(&a_coords, &mut payload);
        payload.extend_from_slice(&frame.ciphertext);
        payload
    }

    /// Run the XK handshake from `A` to `B` to completion on both sides.
    async fn establish(&mut self) {
        let (a, b) = (self.addr(self.a), self.addr(self.b));
        let b_key = self.nodes[self.b].node.identity().pubkey_full();
        self.nodes[self.a]
            .node
            .initiate_session(b, b_key)
            .await
            .expect("A starts a session with B");
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            process_available_packets(&mut self.nodes).await;
        }
        assert!(
            self.nodes[self.a]
                .node
                .get_session(&b)
                .is_some_and(|s| s.is_established())
                && self.nodes[self.b]
                    .node
                    .get_session(&a)
                    .is_some_and(|s| s.is_established()),
            "precondition: the session is established at both ends"
        );
    }
}

/// Two linked nodes, converged, with `a` the root.
async fn pair() -> Pair {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    let root = *nodes[0].node.tree_state().my_coords().root_id();
    let a = if *nodes[0].node.node_addr() == root {
        0
    } else {
        1
    };
    let pair = Pair { nodes, a, b: 1 - a };
    assert_ne!(
        pair.b_now(),
        path(&pair.b_before()),
        "precondition: B's position has changed"
    );
    pair
}

#[tokio::test]
async fn a_hint_from_anyone_but_the_session_peer_still_leaves_a_verified_entry_in_place() {
    // Healthy half: precedence keeps its defence against every other writer.
    let mut p = pair().await;
    p.establish().await;
    p.verify_former_position();

    let b = p.addr(p.b);
    let now = TreeCoordinate::from_addrs(p.b_now()).unwrap();
    let placed = p.nodes[p.a]
        .node
        .insert_coord_hint(b, now, wall_ms(), crate::cache::Funding::Uncharged)
        .expect("same root");
    assert_eq!(placed.outcome, crate::cache::HintOutcome::Rejected);
    assert_eq!(
        p.held_at_a(),
        (p.b_before(), true),
        "a plain hint write must not displace a verified entry within its window"
    );
    cleanup_nodes(&mut p.nodes).await;
}

#[tokio::test]
async fn an_unauthenticated_frame_claiming_the_session_peer_does_not_write_its_coordinates() {
    let mut p = pair().await;
    p.establish().await;
    assert_eq!(
        p.held_path(),
        Some(p.b_now()),
        "precondition: A holds B's current position"
    );
    let authenticated = p.authenticated_at_a();

    // A frame claiming to come from B, carrying another position for B in
    // front of a ciphertext no key of the session opens.
    let a_coords = p.nodes[p.a].node.tree_state().my_coords().clone();
    let mut payload = build_fsp_header(1 << 20, FSP_FLAG_CP, 20).to_vec();
    encode_coords(&p.b_before(), &mut payload);
    encode_coords(&a_coords, &mut payload);
    payload.extend_from_slice(&[0xCC; 36]);
    p.deliver(payload).await;

    assert_eq!(
        p.authenticated_at_a(),
        authenticated,
        "precondition: the frame did not authenticate"
    );
    assert_eq!(
        p.held_path(),
        Some(p.b_now()),
        "a frame no key of the session opens must not write coordinates at its destination"
    );
    cleanup_nodes(&mut p.nodes).await;
}

#[tokio::test]
async fn an_authenticated_message_whose_source_coordinates_are_under_another_root_is_refused_and_counted()
 {
    let mut p = pair().await;
    p.establish().await;
    let b = p.addr(p.b);
    let foreign_root = make_node_addr(0xF0);
    assert_ne!(
        &foreign_root,
        p.nodes[p.a].node.tree_state().my_coords().root_id(),
        "fixture: the root must be foreign"
    );
    let held = p.held_path();
    let authenticated = p.authenticated_at_a();
    let refused = p.nodes[p.a]
        .node
        .metrics()
        .forwarding
        .coord_warm_foreign_root
        .get();

    let foreign = TreeCoordinate::from_addrs(vec![b, foreign_root]).unwrap();
    let payload = p.warmup_stating(&foreign);
    p.deliver(payload).await;

    assert!(
        p.authenticated_at_a() > authenticated,
        "precondition: the CoordsWarmup authenticated at A"
    );
    assert_eq!(
        p.nodes[p.a]
            .node
            .metrics()
            .forwarding
            .coord_warm_foreign_root
            .get(),
        refused + 1,
        "the endpoint's write must be offered once and refused for its foreign root"
    );
    assert_eq!(
        p.held_path(),
        held,
        "a foreign-root coordinate must not be written"
    );
    cleanup_nodes(&mut p.nodes).await;
}
