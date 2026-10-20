//! Shared test helpers for the FMP connection-lifecycle unit tests.

use crate::proto::fmp::{ConnSnapshot, EstablishSnapshot, RekeyClaim, WireOutcome};
use crate::testutil::make_node_addr;
use crate::transport::LinkId;
use alloc::vec::Vec;

/// Build a `ConnSnapshot` for the teardown path with the given link, direction,
/// and retry target. Fields the teardown decision ignores are left at their
/// natural defaults.
pub(super) fn stale_snapshot(
    link: LinkId,
    is_outbound: bool,
    retry_addr: Option<crate::identity::NodeAddr>,
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

/// Build an `EstablishSnapshot` describing an existing, same-epoch
/// peer owned by node `our_byte`.
/// The default is a session on the same link with no rekey declared by the
/// sender. Tests override
/// only the fields their branch exercises. `existing_peer_epoch` defaults to
/// `[0x01; 8]`.
pub(super) fn establish_snapshot(our_byte: u8) -> EstablishSnapshot {
    EstablishSnapshot {
        has_existing_peer: true,
        existing_peer_epoch: Some([0x01; 8]),
        has_session: true,
        stored_msg2: None,
        different_link: false,
        rekey_claim: RekeyClaim::None,
        // Idle by default, so the epoch-restart gate does not fire unless a
        // test sets it: the pre-0161 behaviour every other branch expects.
        peering_idle_ms: u64::MAX,
        epoch_restart_dampened: false,
        our_node_addr: make_node_addr(our_byte),
        silent_backoff: None,
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
