//! A dial made by hand from one node's identity to another node, keeping
//! its handshake state, so a test can read the answer and then send frames
//! under the session it opens: what a genuine peer holds and a replayer of
//! the same msg1 does not.
//!
//! A redial is replaced into the peering only at the first frame under its
//! session, so a test that drives msg1s into a node with no transport, or
//! from an address no node holds, needs a dialer that can follow its msg1
//! with that frame.

use super::*;
use crate::noise::NoiseSession;
use crate::proto::fmp::wire::{
    Msg2Header, build_encrypted, build_established_header, build_msg1, prepend_inner_header,
};

/// A dial of one node by another's identity, with its handshake state.
pub(super) struct Dialer {
    machine: PeerMachine,
    /// The session the answer opened, and the responder's index for it.
    session: Option<(NoiseSession, SessionIndex)>,
}

impl Dialer {
    /// A dial of `responder` by `initiator`'s identity, naming sender index
    /// `sidx`: the dialer, and its msg1 on the wire. Each call is a new
    /// handshake, with its own ephemeral.
    pub(super) fn new(initiator: &Node, responder: &Node, sidx: u32) -> (Dialer, Vec<u8>) {
        let identity = PeerIdentity::from_pubkey_full(responder.identity().pubkey_full());
        let mut machine = outbound_leg(LinkId::new(0x0D1A_1E00 + u64::from(sidx)), identity, 1_000);
        let noise = machine
            .start_handshake(
                initiator.identity().keypair(),
                initiator.startup_epoch(),
                LegStamp::at(1_000),
            )
            .expect("the initiator side of a real msg1 builds");
        (
            Dialer {
                machine,
                session: None,
            },
            build_msg1(SessionIndex::new(sidx), &noise),
        )
    }

    /// Read `msg2`, the responder's answer on the wire, completing the
    /// handshake. Panics if it does not answer this dial's msg1.
    pub(super) fn answered(&mut self, msg2: &[u8]) {
        let header = Msg2Header::parse(msg2).expect("a msg2 on the wire");
        self.machine
            .complete_handshake(&msg2[header.noise_msg2_offset..], LegStamp::at(1_000))
            .expect("the answer completes this dial's handshake");
        let session = self.machine.take_session().expect("a completed session");
        self.session = Some((session, header.sender_idx));
    }

    /// The next frame under the session the answer opened: a heartbeat
    /// link message, addressed by the responder's index.
    pub(super) fn frame(&mut self) -> Vec<u8> {
        let (session, receiver) = self.session.as_mut().expect("a frame follows the answer");
        let inner = prepend_inner_header(0, &[0x51]);
        let counter = session.current_send_counter();
        let header = build_established_header(*receiver, counter, 0, inner.len() as u16);
        let ciphertext = session
            .encrypt_with_aad(&inner, &header)
            .expect("a frame encrypts");
        build_encrypted(&header, &ciphertext)
    }
}
