//! Shared test helpers for the FMP connection-lifecycle unit tests.

use crate::proto::fmp::{
    ConnSnapshot, EstablishSnapshot, PeerSnapshot, RekeyResendSnapshot, WireOutcome,
};
use crate::testutil::make_node_addr;
use crate::transport::LinkId;

/// Build a `RekeyResendSnapshot` for the given peer byte, prior retransmission
/// count, due-flag, and opaque msg1 bytes.
pub(super) fn rekey_resend_snapshot(
    peer_byte: u8,
    resend_count: u32,
    needs_resend: bool,
    msg1: Vec<u8>,
) -> RekeyResendSnapshot {
    RekeyResendSnapshot {
        peer: make_node_addr(peer_byte),
        resend_count,
        needs_resend,
        msg1,
    }
}

/// Build a quiescent `PeerSnapshot` for `addr`: session-healthy but with no
/// pending cutover, no drain, no dampening, zero ages/counter/jitter. Tests set
/// only the fields the case exercises.
pub(super) fn peer_snapshot(addr_byte: u8) -> PeerSnapshot {
    PeerSnapshot {
        addr: make_node_addr(addr_byte),
        has_pending: false,
        rekey_in_progress: false,
        is_draining: false,
        drain_expired: false,
        is_dampened: false,
        rekey_msg3_pending: false,
        elapsed_secs: 0,
        counter: 0,
        jitter_secs: 0,
    }
}

/// Build a `ConnSnapshot` for the teardown path with the given link, direction,
/// and retry target. Fields the teardown decision ignores are left at their
/// natural defaults.
pub(super) fn stale_snapshot(
    link: LinkId,
    is_outbound: bool,
    retry_addr: Option<crate::NodeAddr>,
) -> ConnSnapshot {
    ConnSnapshot {
        link,
        is_outbound,
        retry_addr,
        resend_count: 0,
        msg1: Vec::new(),
    }
}

/// Build a `ConnSnapshot` for the msg1-resend path with the given link, prior
/// resend count, and opaque msg1 bytes. Fields the resend decision ignores are
/// left at their natural defaults.
pub(super) fn resend_snapshot(link: LinkId, resend_count: u32, msg1: Vec<u8>) -> ConnSnapshot {
    ConnSnapshot {
        link,
        is_outbound: true,
        retry_addr: None,
        resend_count,
        msg1,
    }
}

/// Build an `EstablishSnapshot` describing an existing, healthy, same-epoch peer
/// with a rekey-enabled config and a rekey age floor of 100s, owned by node
/// `our_byte`. The default is a quiescent, still-fresh session (age 0, same
/// link, no in-flight rekey / pending). Tests override only the fields their
/// branch exercises. `existing_peer_epoch` defaults to `[0x01; 8]`.
pub(super) fn establish_snapshot(our_byte: u8) -> EstablishSnapshot {
    EstablishSnapshot {
        has_existing_peer: true,
        existing_peer_epoch: Some([0x01; 8]),
        existing_session_age_secs: 0,
        has_session: true,
        is_healthy: true,
        pending_new_session: false,
        rekey_in_progress: false,
        existing_msg2: None,
        different_link: false,
        rekey_enabled: true,
        rekey_age_floor_secs: 100,
        our_node_addr: make_node_addr(our_byte),
    }
}

/// Build a `WireOutcome` naming the initiator `peer_byte` and its captured
/// startup epoch. `[0x01; 8]` matches the `establish_snapshot` default (a
/// same-epoch handshake); a different epoch models a restart.
pub(super) fn wire_outcome(peer_byte: u8, epoch: [u8; 8]) -> WireOutcome {
    WireOutcome {
        peer_node_addr: make_node_addr(peer_byte),
        remote_epoch: Some(epoch),
    }
}
