//! The FSP receive envelope: what a session endpoint discards, and what a
//! transit still reads.
//!
//! FRC-1501 Section 5.1 requires a receiver to discard silently a message
//! whose `payload_len` is not the length its phase gives, that sets a reserved
//! bit, or that is a handshake message or routing signal with bytes after its
//! body; Section 5.6 adds an inner plaintext shorter than its 6-byte header.
//! Section 4.7 names what a transit reads from the same messages and requires
//! none of those checks of it.
//!
//! FRC-2501 keeps those discards with two differences this branch follows:
//! every bit of `inner_flags` is reserved, bit 0 included (Section 5.9), and a
//! source ignores a routing signal's body flags (FRC-2201 Section 6.3).
//!
//! Each endpoint test hands `handle_session_payload` a message that fails one
//! check and passes every other, then the conforming message as a control, and
//! asserts what the endpoint does: whether it opens a session, answers,
//! completes the handshake, delivers the message, writes the sender's
//! coordinates or admits a routing signal. The transit tests hand the middle
//! node of a three-node chain messages the endpoint discards, and show it still
//! warms its cache from them.
//!
//! Coordinates are read only through `Node::cached_dest_coords`, on whichever
//! clock the cache uses, so an assertion that nothing was written cannot pass
//! because every entry reads as expired; each is paired with a control that
//! does write, read the same way.

use super::*;
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, run_tree_test, verify_tree_convergence,
};
use crate::proto::fmp::wire::{EncryptedHeader, strip_inner_header};
use crate::proto::fsp::SessionMessageType;
use crate::proto::fsp::wire::{
    FSP_FLAG_CP, FSP_FLAG_U, FSP_PHASE_MSG1, FSP_PHASE_MSG2, FSP_PHASE_MSG3, build_fsp_header,
};
use crate::proto::fsp::{SessionAck, SessionSetup};
use crate::proto::link::{LinkMessageType, SessionDatagram};
use crate::proto::routing::CoordsRequired;
use crate::proto::stp::{TreeCoordinate, encode_coords};

/// The initiator of the pair's session.
const I: usize = 0;
/// The responder of the pair's session.
const R: usize = 1;

/// A reserved bit of the prefix `flags` of an established message or routing
/// signal (bits 3 to 7).
const RESERVED_PREFIX_BIT: u8 = 0x08;

/// The node addresses of `coords`, from the node to the root: what a
/// coordinate states on the wire, without the metadata a tree state keeps.
fn path(coords: &TreeCoordinate) -> Vec<NodeAddr> {
    coords.node_addrs().copied().collect()
}

/// The phase nibble of an FSP message.
fn phase(payload: &[u8]) -> u8 {
    payload[0] & 0x0F
}

/// Rewrite the prefix `payload_len` of an FSP message.
fn set_payload_len(payload: &mut [u8], len: usize) {
    payload[2..4].copy_from_slice(&(len as u16).to_le_bytes());
}

/// Append one byte after the body of a handshake message, keeping its prefix
/// `payload_len` equal to the bytes after the prefix, so the trailing byte is
/// the message's only fault.
fn with_trailing_byte(payload: &[u8]) -> Vec<u8> {
    let mut longer = payload.to_vec();
    longer.push(0);
    let len = longer.len() - 4;
    set_payload_len(&mut longer, len);
    longer
}

/// A handshake message with its body flags byte (the first byte after the
/// prefix) set to `0x01`.
fn with_body_flag(payload: &[u8]) -> Vec<u8> {
    let mut flagged = payload.to_vec();
    flagged[4] = 0x01;
    flagged
}

/// A handshake message carrying every fault the endpoint discards it for: a
/// body flag bit, a byte after its Noise message, a prefix flag bit and a
/// `payload_len` that is not the bytes after the prefix.
fn with_every_handshake_fault(payload: &[u8]) -> Vec<u8> {
    let mut faulty = with_trailing_byte(&with_body_flag(payload));
    faulty[1] = 0x01;
    let len = faulty.len() - 4 + 1;
    set_payload_len(&mut faulty, len);
    faulty
}

/// Open every frame queued at `nodes[to]` from its link peer `from`, deliver
/// each that is not a session datagram, and return the FSP payload of each
/// that is, undelivered. Frames are opened without moving the link session's
/// replay window, so the frames after a withheld one are still accepted.
async fn withhold_session_payloads(
    nodes: &mut [TestNode],
    to: usize,
    from: &NodeAddr,
) -> Vec<Vec<u8>> {
    tokio::time::sleep(Duration::from_millis(20)).await;
    let packets: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[to].packet_rx.try_recv().ok()).collect();
    let mut held = Vec::new();
    for packet in packets {
        let opened = EncryptedHeader::parse(&packet.data).and_then(|header| {
            nodes[to]
                .node
                .get_peer(from)?
                .noise_session()?
                .open_unmarked(
                    &packet.data[header.ciphertext_offset()..],
                    header.counter,
                    &header.header_bytes,
                )
                .ok()
        });
        if let Some(plaintext) = opened
            && let Some((_, message)) = strip_inner_header(&plaintext)
            && message.first() == Some(&LinkMessageType::SessionDatagram.to_byte())
        {
            let datagram = SessionDatagram::decode(&message[1..]).expect("a session datagram");
            held.push(datagram.payload);
            continue;
        }
        nodes[to].node.handle_encrypted_frame(packet).await;
    }
    held
}

/// The first payload of `phase_wanted` among `payloads`.
fn of_phase(payloads: &[Vec<u8>], phase_wanted: u8) -> Option<Vec<u8>> {
    payloads.iter().find(|p| phase(p) == phase_wanted).cloned()
}

/// Two linked, converged nodes: `I` opens a session to `R`, and each of its
/// handshake messages is withheld from the link and handed to the receiver's
/// session layer by the test.
struct Pair {
    nodes: Vec<TestNode>,
}

impl Pair {
    async fn new() -> Self {
        let nodes = run_tree_test(2, &[(0, 1)], false).await;
        verify_tree_convergence(&nodes);
        Self { nodes }
    }

    fn addr(&self, n: usize) -> NodeAddr {
        *self.nodes[n].node.node_addr()
    }

    /// Hand `payload` to `nodes[to]`'s session layer as the other node's,
    /// arriving over its link with it.
    async fn hand(&mut self, to: usize, payload: &[u8]) {
        let from = self.addr(1 - to);
        self.nodes[to]
            .node
            .handle_session_payload(&from, &from, payload, 1280, false)
            .await;
    }

    /// The session payloads queued at `nodes[to]` from the other node,
    /// withheld from it.
    async fn withheld_at(&mut self, to: usize) -> Vec<Vec<u8>> {
        let from = self.addr(1 - to);
        withhold_session_payloads(&mut self.nodes, to, &from).await
    }

    /// `I` starts its session; returns the `SessionSetup` it sends.
    async fn setup(&mut self) -> Vec<u8> {
        let (r, r_key) = (self.addr(R), self.nodes[R].node.identity().pubkey_full());
        self.nodes[I]
            .node
            .initiate_session(r, r_key)
            .await
            .expect("I starts a session with R");
        let held = self.withheld_at(R).await;
        of_phase(&held, FSP_PHASE_MSG1).expect("I sends a SessionSetup")
    }

    /// `R` takes `setup`; returns the `SessionAck` it answers with.
    async fn ack(&mut self, setup: &[u8]) -> Vec<u8> {
        self.hand(R, setup).await;
        let held = self.withheld_at(I).await;
        of_phase(&held, FSP_PHASE_MSG2).expect("R answers the setup with a SessionAck")
    }

    /// `I` takes `ack`; returns the msg3 it sends.
    async fn msg3(&mut self, ack: &[u8]) -> Vec<u8> {
        self.hand(I, ack).await;
        let held = self.withheld_at(R).await;
        of_phase(&held, FSP_PHASE_MSG3).expect("I completes with a msg3")
    }

    /// Run the handshake to completion at both ends.
    async fn establish(&mut self) {
        let setup = self.setup().await;
        let ack = self.ack(&setup).await;
        let msg3 = self.msg3(&ack).await;
        self.hand(R, &msg3).await;
        assert!(
            self.established(I) && self.established(R),
            "precondition: the session is established at both ends"
        );
    }

    fn established(&self, n: usize) -> bool {
        let peer = self.addr(1 - n);
        self.nodes[n]
            .node
            .get_session(&peer)
            .is_some_and(|s| s.is_established())
    }

    /// Data packets `R` has delivered on its session with `I`.
    fn delivered_at_r(&self) -> u64 {
        self.nodes[R]
            .node
            .get_session(&self.addr(I))
            .map_or(0, |s| s.traffic_counters().1)
    }

    /// The path of the coordinates `R` holds for `I`, read on the cache's
    /// own clock.
    fn coords_at_r(&self) -> Option<Vec<NodeAddr>> {
        self.nodes[R]
            .node
            .cached_dest_coords(&self.addr(I))
            .map(|c| path(&c))
    }

    /// Forget whatever `R` holds for `I`, so a write shows.
    fn forget_at_r(&mut self) {
        let i = self.addr(I);
        self.nodes[R].node.coord_cache_mut().remove(&i);
        assert!(
            self.coords_at_r().is_none(),
            "precondition: R holds nothing for I"
        );
    }

    /// An established message from `I` to `R` carrying `plaintext`, sealed
    /// under `header`, both as `edit` leaves them after `I` built a
    /// `DataPacket` with `flags`. With `FSP_FLAG_CP` the coordinate block
    /// states `I`'s and `R`'s coordinates.
    fn sealed(&mut self, flags: u8, edit: impl FnOnce(&mut [u8; 12], &mut Vec<u8>)) -> Vec<u8> {
        let r = self.addr(R);
        let body = [0x34, 0x12, 0x78, 0x56, 0xAB];
        let reserved = self.nodes[I]
            .node
            .sessions
            .get_mut(&r)
            .expect("I holds the session")
            .reserve_send(
                Node::session_now(),
                flags,
                SessionMessageType::DataPacket.to_byte(),
                &body,
            )
            .expect("I reserves a counter")
            .expect("I's keys hand out a send key");
        let (mut header, mut plaintext) = (reserved.header, reserved.plaintext);
        edit(&mut header, &mut plaintext);
        let ciphertext =
            fips_core::noise::seal(Some(&reserved.key), reserved.counter, &header, &plaintext)
                .expect("the message seals");
        let mut payload = header.to_vec();
        if flags & FSP_FLAG_CP != 0 {
            encode_coords(self.nodes[I].node.tree_state().my_coords(), &mut payload);
            encode_coords(self.nodes[R].node.tree_state().my_coords(), &mut payload);
        }
        payload.extend_from_slice(&ciphertext);
        payload
    }

    /// A conforming established message from `I` to `R`.
    fn conforming(&mut self, flags: u8) -> Vec<u8> {
        self.sealed(flags, |_, _| {})
    }
}

// ============================================================================
// Handshake messages at the endpoint
// ============================================================================

/// `R` takes the setup `faulty`, then the conforming `setup`: the first must
/// open no session, hold no candidate and draw no SessionAck, and the second
/// must do all three.
async fn assert_setup_refused_then_answered(p: &mut Pair, faulty: &[u8], setup: &[u8], what: &str) {
    let i = p.addr(I);
    p.hand(R, faulty).await;
    let answered = of_phase(&p.withheld_at(I).await, FSP_PHASE_MSG2).is_some();
    let session = p.nodes[R].node.get_session(&i);
    assert!(
        session.is_none() && !answered,
        "a SessionSetup with {what} must open no session and draw no SessionAck \
         (session: {}, candidates: {}, answered: {answered})",
        session.is_some(),
        session.map_or(0, |s| s.candidate_count()),
    );

    p.hand(R, setup).await;
    let answered = of_phase(&p.withheld_at(I).await, FSP_PHASE_MSG2).is_some();
    assert!(
        p.nodes[R]
            .node
            .get_session(&i)
            .is_some_and(|s| s.candidate_count() == 1)
            && answered,
        "control: the conforming SessionSetup is held as a candidate and answered"
    );
}

#[tokio::test]
async fn a_session_setup_with_a_body_flag_bit_set_opens_no_session() {
    let mut p = Pair::new().await;
    let setup = p.setup().await;
    assert_setup_refused_then_answered(&mut p, &with_body_flag(&setup), &setup, "a body flag bit")
        .await;
    cleanup_nodes(&mut p.nodes).await;
}

#[tokio::test]
async fn a_session_setup_with_a_byte_after_its_noise_message_opens_no_session() {
    let mut p = Pair::new().await;
    let setup = p.setup().await;
    assert_setup_refused_then_answered(
        &mut p,
        &with_trailing_byte(&setup),
        &setup,
        "a byte after its Noise message",
    )
    .await;
    cleanup_nodes(&mut p.nodes).await;
}

#[tokio::test]
async fn a_session_setup_with_a_prefix_flag_bit_set_opens_no_session() {
    let mut p = Pair::new().await;
    let setup = p.setup().await;
    let mut flagged = setup.clone();
    flagged[1] = 0x01;
    assert_setup_refused_then_answered(&mut p, &flagged, &setup, "a prefix flag bit").await;
    cleanup_nodes(&mut p.nodes).await;
}

#[tokio::test]
async fn a_session_setup_whose_payload_len_disagrees_with_its_length_opens_no_session() {
    let mut p = Pair::new().await;
    let setup = p.setup().await;
    let mut wrong = setup.clone();
    set_payload_len(&mut wrong, setup.len() - 4 + 1);
    assert_setup_refused_then_answered(&mut p, &wrong, &setup, "a payload_len one too large").await;
    cleanup_nodes(&mut p.nodes).await;
}

/// `I` takes the ack `faulty`, then the conforming `ack`: the first must
/// leave its session initiating and send no msg3, the second must complete
/// it.
async fn assert_ack_refused_then_completed(p: &mut Pair, faulty: &[u8], ack: &[u8], what: &str) {
    p.hand(I, faulty).await;
    let sent = of_phase(&p.withheld_at(R).await, FSP_PHASE_MSG3).is_some();
    assert!(
        !p.established(I) && !sent,
        "a SessionAck with {what} must not complete the handshake \
         (established: {}, msg3 sent: {sent})",
        p.established(I),
    );

    p.hand(I, ack).await;
    let sent = of_phase(&p.withheld_at(R).await, FSP_PHASE_MSG3).is_some();
    assert!(
        p.established(I) && sent,
        "control: the conforming SessionAck completes the handshake and draws a msg3"
    );
}

#[tokio::test]
async fn a_session_ack_with_a_body_flag_bit_set_does_not_complete_the_handshake() {
    let mut p = Pair::new().await;
    let setup = p.setup().await;
    let ack = p.ack(&setup).await;
    assert_ack_refused_then_completed(&mut p, &with_body_flag(&ack), &ack, "a body flag bit").await;
    cleanup_nodes(&mut p.nodes).await;
}

#[tokio::test]
async fn a_session_ack_with_a_byte_after_its_noise_message_does_not_complete_the_handshake() {
    let mut p = Pair::new().await;
    let setup = p.setup().await;
    let ack = p.ack(&setup).await;
    assert_ack_refused_then_completed(
        &mut p,
        &with_trailing_byte(&ack),
        &ack,
        "a byte after its Noise message",
    )
    .await;
    cleanup_nodes(&mut p.nodes).await;
}

/// `R` takes the msg3 `faulty`, then the conforming `msg3`: the first must
/// leave its session unestablished, the second must establish it.
async fn assert_msg3_refused_then_completed(p: &mut Pair, faulty: &[u8], msg3: &[u8], what: &str) {
    p.hand(R, faulty).await;
    assert!(
        !p.established(R),
        "a SessionMsg3 with {what} must not establish the session"
    );
    p.hand(R, msg3).await;
    assert!(
        p.established(R),
        "control: the conforming SessionMsg3 establishes the session"
    );
}

#[tokio::test]
async fn a_session_msg3_with_a_body_flag_bit_set_does_not_establish_the_session() {
    let mut p = Pair::new().await;
    let setup = p.setup().await;
    let ack = p.ack(&setup).await;
    let msg3 = p.msg3(&ack).await;
    assert_msg3_refused_then_completed(&mut p, &with_body_flag(&msg3), &msg3, "a body flag bit")
        .await;
    cleanup_nodes(&mut p.nodes).await;
}

#[tokio::test]
async fn a_session_msg3_with_a_byte_after_its_noise_message_does_not_establish_the_session() {
    let mut p = Pair::new().await;
    let setup = p.setup().await;
    let ack = p.ack(&setup).await;
    let msg3 = p.msg3(&ack).await;
    assert_msg3_refused_then_completed(
        &mut p,
        &with_trailing_byte(&msg3),
        &msg3,
        "a byte after its Noise message",
    )
    .await;
    cleanup_nodes(&mut p.nodes).await;
}

// ============================================================================
// Established messages at the endpoint
// ============================================================================

/// `R` takes the established message `faulty`, then a conforming one: the
/// first must not be delivered, the second must.
async fn assert_message_refused_then_delivered(p: &mut Pair, faulty: &[u8], what: &str) {
    let before = p.delivered_at_r();
    p.hand(R, faulty).await;
    assert_eq!(
        p.delivered_at_r(),
        before,
        "an established message with {what} must not be delivered"
    );
    let control = p.conforming(0);
    p.hand(R, &control).await;
    assert_eq!(
        p.delivered_at_r(),
        before + 1,
        "control: the conforming message is delivered"
    );
}

#[tokio::test]
async fn an_established_message_with_a_wrong_payload_len_is_not_delivered() {
    let mut p = Pair::new().await;
    p.establish().await;
    // The wrong length is sealed into the additional data, so the message
    // authenticates: only the length check can refuse it.
    let faulty = p.sealed(0, |header, plaintext| {
        let len = plaintext.len() + 1;
        header[2..4].copy_from_slice(&(len as u16).to_le_bytes());
    });
    assert_message_refused_then_delivered(&mut p, &faulty, "a payload_len one too large").await;
    cleanup_nodes(&mut p.nodes).await;
}

#[tokio::test]
async fn an_established_message_with_a_reserved_prefix_bit_set_is_not_delivered() {
    let mut p = Pair::new().await;
    p.establish().await;
    let faulty = p.sealed(0, |header, _| header[1] |= RESERVED_PREFIX_BIT);
    assert_message_refused_then_delivered(&mut p, &faulty, "a reserved prefix bit").await;
    cleanup_nodes(&mut p.nodes).await;
}

/// `R` takes the authenticated message `faulty`, which states `I`'s
/// coordinates, then a conforming one that states them: the first must be
/// neither delivered nor write the coordinates, the second must do both.
async fn assert_unprocessed_then_processed(p: &mut Pair, faulty: &[u8], what: &str) {
    p.forget_at_r();
    let before = p.delivered_at_r();
    p.hand(R, faulty).await;
    assert!(
        p.delivered_at_r() == before && p.coords_at_r().is_none(),
        "an authenticated message with {what} must be neither delivered nor write \
         the coordinates it states (delivered: {}, coordinates written: {})",
        p.delivered_at_r() - before,
        p.coords_at_r().is_some(),
    );

    let control = p.conforming(FSP_FLAG_CP);
    p.hand(R, &control).await;
    assert_eq!(
        p.coords_at_r(),
        Some(path(p.nodes[I].node.tree_state().my_coords())),
        "control: the conforming message writes the coordinates it states"
    );
    assert_eq!(
        p.delivered_at_r(),
        before + 1,
        "control: the conforming message is delivered"
    );
}

#[tokio::test]
async fn an_established_message_with_a_reserved_inner_flag_is_not_processed() {
    let mut p = Pair::new().await;
    p.establish().await;
    let faulty = p.sealed(FSP_FLAG_CP, |_, plaintext| plaintext[5] |= 0x02);
    assert_unprocessed_then_processed(&mut p, &faulty, "inner_flags bit 1 set").await;
    cleanup_nodes(&mut p.nodes).await;
}

#[tokio::test]
async fn an_established_message_with_inner_flags_bit_0_set_is_not_processed() {
    let mut p = Pair::new().await;
    p.establish().await;
    let faulty = p.sealed(FSP_FLAG_CP, |_, plaintext| plaintext[5] |= 0x01);
    assert_unprocessed_then_processed(&mut p, &faulty, "inner_flags bit 0 set").await;
    cleanup_nodes(&mut p.nodes).await;
}

/// Not a defect today: the session's rekey machine delivers no plaintext
/// shorter than the inner header (`Profile::FLOOR`), so the coordinate write
/// after delivery is never reached. A guard, so that it stays so.
#[tokio::test]
async fn an_established_message_too_short_for_its_inner_header_writes_no_coordinates() {
    let mut p = Pair::new().await;
    p.establish().await;
    let faulty = p.sealed(FSP_FLAG_CP, |header, plaintext| {
        plaintext.truncate(3);
        header[2..4].copy_from_slice(&3u16.to_le_bytes());
    });
    assert_unprocessed_then_processed(&mut p, &faulty, "an inner plaintext of 3 bytes").await;
    cleanup_nodes(&mut p.nodes).await;
}

// ============================================================================
// Routing signals at the endpoint
// ============================================================================

/// A node takes the `CoordsRequired` `faulty`, naming a destination it holds
/// no session with, then the conforming signal: the first must be discarded
/// before it is judged, so it is not counted as naming an unknown session;
/// the second is judged and counted.
async fn assert_signal_discarded_then_judged(faulty: &[u8], what: &str) {
    let mut node = make_node();
    let (dest, reporter) = (make_node_addr(0xCC), make_node_addr(0xBB));
    node.handle_session_payload(&reporter, &reporter, faulty, 1280, false)
        .await;
    assert_eq!(
        node.stats().session.unknown_session,
        0,
        "a CoordsRequired with {what} must be discarded before it is judged"
    );
    let conforming = CoordsRequired::new(dest, reporter).encode();
    node.handle_session_payload(&reporter, &reporter, &conforming, 1280, false)
        .await;
    assert_eq!(
        node.stats().session.unknown_session,
        1,
        "control: the conforming CoordsRequired is judged"
    );
}

/// A `CoordsRequired` naming a destination with no session.
fn coords_required() -> Vec<u8> {
    CoordsRequired::new(make_node_addr(0xCC), make_node_addr(0xBB)).encode()
}

#[tokio::test]
async fn a_coords_required_with_a_reserved_body_bit_is_judged_all_the_same() {
    let mut flagged = coords_required();
    flagged[5] = 0x01;
    let mut node = make_node();
    let reporter = make_node_addr(0xBB);
    node.handle_session_payload(&reporter, &reporter, &flagged, 1280, false)
        .await;
    assert_eq!(
        node.stats().session.unknown_session,
        1,
        "a source ignores sig_flags, so the signal is judged"
    );
}

#[tokio::test]
async fn a_routing_signal_whose_payload_len_disagrees_with_its_length_is_discarded() {
    let mut faulty = coords_required();
    let len = faulty.len() - 4 + 1;
    set_payload_len(&mut faulty, len);
    assert_signal_discarded_then_judged(&faulty, "a payload_len one too large").await;
}

#[tokio::test]
async fn a_routing_signal_with_a_reserved_prefix_bit_set_is_discarded() {
    let mut faulty = coords_required();
    faulty[1] = FSP_FLAG_U | RESERVED_PREFIX_BIT;
    assert_signal_discarded_then_judged(&faulty, "a reserved prefix bit").await;
}

// ============================================================================
// Transit cache warming is unchanged
// ============================================================================

/// A three-node chain `0 - 1 - 2`, its middle node the transit.
struct Chain {
    nodes: Vec<TestNode>,
}

/// The transit's index in the chain.
const T: usize = 1;

impl Chain {
    async fn new() -> Self {
        let nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
        verify_tree_convergence(&nodes);
        Self { nodes }
    }

    fn addr(&self, n: usize) -> NodeAddr {
        *self.nodes[n].node.node_addr()
    }

    fn coords(&self, n: usize) -> TreeCoordinate {
        self.nodes[n].node.tree_state().my_coords().clone()
    }

    /// Hand the transit a datagram from node 0 to node 2 carrying `payload`,
    /// over its link with node 0, after it forgets both ends; returns the
    /// path of the coordinates it then holds for each.
    async fn warmed_by(&mut self, payload: Vec<u8>) -> [Option<Vec<NodeAddr>>; 2] {
        let (src, dest) = (self.addr(0), self.addr(2));
        let transit = &mut self.nodes[T].node;
        transit.coord_cache_mut().remove(&src);
        transit.coord_cache_mut().remove(&dest);
        let encoded = SessionDatagram::new(src, dest, payload).encode();
        transit
            .handle_session_datagram(&src, &encoded[1..], false)
            .await;
        [src, dest].map(|end| transit.cached_dest_coords(&end).map(|c| path(&c)))
    }

    fn warm_malformed(&self) -> u64 {
        self.nodes[T]
            .node
            .metrics()
            .forwarding
            .warm_malformed_packets
            .get()
    }

    /// Assert the transit warms both ends from `conforming` and from
    /// `faulty` alike, and counts neither as malformed.
    async fn assert_warms_from_both(&mut self, conforming: Vec<u8>, faulty: Vec<u8>, what: &str) {
        let expected = [Some(path(&self.coords(0))), Some(path(&self.coords(2)))];
        let malformed = self.warm_malformed();
        assert_eq!(
            self.warmed_by(conforming).await,
            expected,
            "control: the transit warms both ends from the conforming {what}"
        );
        assert_eq!(
            self.warmed_by(faulty).await,
            expected,
            "the transit must still warm both ends from a {what} the endpoint discards"
        );
        assert_eq!(
            self.warm_malformed(),
            malformed,
            "neither {what} is counted as malformed"
        );
    }
}

/// A handshake body's Noise message, as a transit sees it: bytes it does not
/// read.
fn noise_bytes(len: usize) -> Vec<u8> {
    vec![0x5A; len]
}

#[tokio::test]
async fn a_transit_still_warms_from_a_session_setup_the_endpoint_discards() {
    let mut c = Chain::new().await;
    let setup = SessionSetup::new(c.coords(0), c.coords(2))
        .with_handshake(noise_bytes(crate::noise::HANDSHAKE_MSG1_SIZE))
        .encode();
    let faulty = with_every_handshake_fault(&setup);
    c.assert_warms_from_both(setup, faulty, "SessionSetup")
        .await;
    cleanup_nodes(&mut c.nodes).await;
}

#[tokio::test]
async fn a_transit_still_warms_from_a_session_ack_the_endpoint_discards() {
    let mut c = Chain::new().await;
    let ack = SessionAck::new(c.coords(0), c.coords(2))
        .with_handshake(noise_bytes(crate::noise::HANDSHAKE_MSG2_SIZE))
        .encode();
    let faulty = with_every_handshake_fault(&ack);
    c.assert_warms_from_both(ack, faulty, "SessionAck").await;
    cleanup_nodes(&mut c.nodes).await;
}

#[tokio::test]
async fn a_transit_still_warms_from_an_established_message_the_endpoint_discards() {
    let mut c = Chain::new().await;
    // The faulty message sets a reserved prefix bit and states a
    // payload_len one more than its ciphertext less the tag.
    let message = |flags: u8, payload_len: u16| {
        let ciphertext = noise_bytes(6 + crate::noise::TAG_SIZE);
        let mut payload = build_fsp_header(7, flags, payload_len).to_vec();
        encode_coords(&c.coords(0), &mut payload);
        encode_coords(&c.coords(2), &mut payload);
        payload.extend_from_slice(&ciphertext);
        payload
    };
    let (conforming, faulty) = (
        message(FSP_FLAG_CP, 6),
        message(FSP_FLAG_CP | RESERVED_PREFIX_BIT, 7),
    );
    c.assert_warms_from_both(conforming, faulty, "established message")
        .await;
    cleanup_nodes(&mut c.nodes).await;
}
