//! Shared test helpers for the FMP connection-lifecycle unit tests.

use crate::proto::fmp::ConnSnapshot;
use crate::transport::LinkId;

/// Build a `ConnSnapshot` for the teardown path with the given link, direction,
/// and retry target.
pub(super) fn stale_snapshot(
    link: LinkId,
    is_outbound: bool,
    retry_addr: Option<crate::identity::NodeAddr>,
) -> ConnSnapshot {
    ConnSnapshot {
        link,
        is_outbound,
        retry_addr,
    }
}
