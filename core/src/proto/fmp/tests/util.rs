//! Shared test helpers for the FMP connection-lifecycle unit tests.

use crate::proto::fmp::ConnSnapshot;
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
