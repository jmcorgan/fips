//! Shared test helpers for the FMP connection-lifecycle unit tests.

use crate::proto::fmp::{
    ConnSnapshot, EstablishSnapshot, PeerSnapshot, RekeyResendSnapshot, WireOutcome,
};
use crate::testutil::make_node_addr;
use crate::transport::LinkId;
use crate::utils::index::SessionIndex;
use crate::{Identity, PeerIdentity};

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

/// Build a quiescent `EstablishSnapshot` for a net-new inbound msg1: no existing
/// peer, not at cap, rekey enabled, our node addr fixed. Tests override only the
/// fields the case exercises.
pub(super) fn establish_snapshot() -> EstablishSnapshot {
    EstablishSnapshot {
        has_existing_peer: false,
        existing_peer_epoch: None,
        existing_session_age_secs: 0,
        has_session: false,
        is_healthy: false,
        pending_new_session: false,
        rekey_in_progress: false,
        existing_msg2: None,
        at_max_peers: false,
        has_pending_outbound_to_peer: false,
        rekey_enabled: true,
        our_node_addr: make_node_addr(0x10),
    }
}

/// Build a `WireOutcome` carrying a freshly generated peer identity and the
/// given remote epoch (empty msg2 payload, fixed sender index). Callers read the
/// peer's NodeAddr back via `wire.peer_identity.node_addr()` when they need it
/// for the tie-break.
pub(super) fn wire_outcome(remote_epoch: Option<[u8; 8]>) -> WireOutcome {
    WireOutcome {
        peer_identity: PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full()),
        remote_epoch,
        their_index: SessionIndex::new(0x1234),
        msg2_payload: Vec::new(),
    }
}
