//! Reading this node's interface prefixes from the system.
//!
//! The set itself, [`OnLinkPrefixes`], is `fips_core::utils::onlink`'s and is
//! re-exported here at its old path; this module adds only the system read,
//! which needs `getifaddrs` and logging.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use tracing::{debug, warn};

pub use fips_core::utils::onlink::{OnLinkPrefixes, read_suspect};

/// Set once the first failed interface read has been logged at warn level.
static READ_FAILED_WARNED: AtomicBool = AtomicBool::new(false);

/// Set once the first unusable interface read has been logged at warn level.
static READ_SUSPECT_WARNED: AtomicBool = AtomicBool::new(false);

/// Read this node's interface prefixes from the system.
///
/// Loopback interfaces are skipped, and so are interfaces the platform
/// reports as down (`Down`, `NotPresent` and `LowerLayerDown`, which only
/// Windows reports); any other status counts, since the POSIX platforms
/// report only `Up` or `Unknown`. A failed read returns an empty set,
/// which refuses every candidate gated with it, marked so a caller holding
/// state can tell it from a read that found nothing.
///
/// Read at each use and never cached, because interfaces change under
/// DHCP and VPNs. The cost is one `getifaddrs` call (a netlink dump on
/// Linux), plus one `if_nametoindex` call per address on the POSIX
/// platforms. LAN discovery reads once a second while it holds
/// candidates, including ticks on which the in-flight cap leaves nothing
/// to dial, so a sender on the link who keeps candidates held keeps this
/// read running once a second.
pub fn read_system() -> OnLinkPrefixes {
    let interfaces = match if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces,
        Err(err) => {
            if !READ_FAILED_WARNED.swap(true, Ordering::Relaxed) {
                warn!(
                    error = %err,
                    "interface read failed; private traversal candidates and mDNS targets other than IPv6 link-local will be refused"
                );
            } else {
                debug!(error = %err, "interface read failed");
            }
            return OnLinkPrefixes::failed();
        }
    };
    let entries: Vec<(IpAddr, u8, Option<u32>)> = interfaces
        .iter()
        .filter(|iface| !iface.is_loopback())
        .filter(|iface| {
            !matches!(
                iface.oper_status,
                if_addrs::IfOperStatus::Down
                    | if_addrs::IfOperStatus::NotPresent
                    | if_addrs::IfOperStatus::LowerLayerDown
            )
        })
        .map(|iface| match &iface.addr {
            if_addrs::IfAddr::V4(v4) => (IpAddr::V4(v4.ip), v4.prefixlen, iface.index),
            if_addrs::IfAddr::V6(v6) => (IpAddr::V6(v6.ip), v6.prefixlen, iface.index),
        })
        .collect();
    let considered = entries.len();
    let set = OnLinkPrefixes::from_indexed(entries);
    if read_suspect(considered, &set) {
        if !READ_SUSPECT_WARNED.swap(true, Ordering::Relaxed) {
            warn!(
                considered,
                discarded = set.discarded(),
                "interface prefixes unreadable; private traversal candidates and mDNS targets other than IPv6 link-local will be refused"
            );
        } else {
            debug!(
                considered,
                discarded = set.discarded(),
                "interface prefixes unreadable"
            );
        }
    }
    set
}

#[cfg(test)]
#[path = "tests/onlink.rs"]
mod tests;
