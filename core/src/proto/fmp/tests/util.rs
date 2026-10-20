//! Shared test helpers for the FMP connection-lifecycle unit tests.

use crate::identity::PeerIdentity;
use crate::proto::fmp::{ConnSnapshot, EstablishSnapshot, Msg1Digest, WireOutcome};
use crate::testutil::make_keypair;
use crate::transport::LinkId;
use crate::utils::index::SessionIndex;
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

/// Build a quiescent `EstablishSnapshot` for a net-new inbound msg1: no existing
/// peer, not at cap. Tests override only the fields the case exercises.
pub(super) fn establish_snapshot() -> EstablishSnapshot {
    EstablishSnapshot {
        has_existing_peer: false,
        existing_peer_epoch: None,
        replace: false,
        at_max_peers: false,
        has_pending_outbound_to_peer: false,
        silent_backoff: None,
    }
}

/// Build a `WireOutcome` carrying a freshly generated peer identity and the
/// given remote epoch (empty msg2 payload, fixed sender index). Callers read the
/// peer's NodeAddr back via `wire.peer_identity.node_addr()` when they need it
/// for the tie-break.
pub(super) fn wire_outcome(remote_epoch: Option<[u8; 8]>) -> WireOutcome {
    WireOutcome {
        peer_identity: PeerIdentity::from_pubkey_full(make_keypair().public_key()),
        remote_epoch,
        their_index: SessionIndex::new(0x1234),
        msg2_payload: Vec::new(),
        msg1_digest: Msg1Digest::of(b"msg1"),
    }
}
