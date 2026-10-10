//! The address prefixes of this node's own network interfaces.
//!
//! [`OnLinkPrefixes`] answers one question: whether an address lies on one of
//! this node's own links, judged by the prefixes (address and prefix length)
//! its interfaces hold. Discovery code uses it to decide whether an address a
//! remote party named is one this node can reach directly, whether it lies on
//! the particular interface something arrived on, and whether two addresses
//! share a link.
//!
//! A set is built for each use and never cached, because interfaces change
//! under DHCP renumbering and VPNs coming and going. An empty set holds no
//! address, so a caller that gates candidates with it refuses every one.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use tracing::{debug, warn};

/// The interface prefixes of this node, each an address, a prefix length and
/// the index of the interface that holds it.
#[derive(Clone, Debug, Default)]
pub struct OnLinkPrefixes {
    entries: Vec<Prefix>,
    /// Entries dropped for a zero prefix length.
    discarded: usize,
    /// Set when the system read failed, as opposed to finding no prefix.
    failed: bool,
}

/// One interface prefix.
#[derive(Clone, Copy, Debug)]
struct Prefix {
    net: IpAddr,
    len: u8,
    /// The OS index of the interface holding the prefix, when known.
    index: Option<u32>,
}

/// Set once the first failed interface read has been logged at warn level.
static READ_FAILED_WARNED: AtomicBool = AtomicBool::new(false);

/// Set once the first unusable interface read has been logged at warn level.
static READ_SUSPECT_WARNED: AtomicBool = AtomicBool::new(false);

/// Map an IPv4-mapped IPv6 address to its IPv4 form, so one host is never
/// judged twice under two spellings.
fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Whether `ip` lies inside the prefix `net`/`len`. Both are canonical and of
/// the same family, or the answer is `false`.
fn prefix_holds(net: IpAddr, len: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from(net) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            u128::from(net) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}

impl OnLinkPrefixes {
    /// Build a set from `(address, prefix length)` pairs.
    ///
    /// IPv4-mapped IPv6 addresses are taken as IPv4. A prefix length of 0 is
    /// discarded rather than kept: it would put every address on-link, and it
    /// is what a platform netmask the reader could not decode turns into.
    /// Lengths beyond the family's width are clamped to it.
    /// The interface of each pair is unknown, so the set answers
    /// [`Self::contains_on`] with `false`.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (IpAddr, u8)>) -> Self {
        Self::from_indexed(pairs.into_iter().map(|(ip, len)| (ip, len, None)))
    }

    /// Build a set from `(address, prefix length, interface index)` triples,
    /// with the same rules as [`Self::from_pairs`].
    pub fn from_indexed(entries: impl IntoIterator<Item = (IpAddr, u8, Option<u32>)>) -> Self {
        let mut discarded = 0;
        let entries = entries
            .into_iter()
            .filter_map(|(ip, len, index)| {
                let net = canonical(ip);
                let width = if net.is_ipv4() { 32 } else { 128 };
                if len == 0 {
                    discarded += 1;
                    return None;
                }
                Some(Prefix {
                    net,
                    len: len.min(width),
                    index,
                })
            })
            .collect();
        Self {
            entries,
            discarded,
            failed: false,
        }
    }

    /// The set a failed system read yields: it holds nothing, and
    /// [`Self::read_failed`] tells it apart from a read that found nothing.
    pub fn failed() -> Self {
        Self {
            failed: true,
            ..Self::default()
        }
    }

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
    pub fn read_system() -> Self {
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
                return Self::failed();
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
        let set = Self::from_indexed(entries);
        if read_suspect(considered, &set) {
            if !READ_SUSPECT_WARNED.swap(true, Ordering::Relaxed) {
                warn!(
                    considered,
                    discarded = set.discarded,
                    "interface prefixes unreadable; private traversal candidates and mDNS targets other than IPv6 link-local will be refused"
                );
            } else {
                debug!(
                    considered,
                    discarded = set.discarded,
                    "interface prefixes unreadable"
                );
            }
        }
        set
    }

    /// How many pairs were dropped for a zero prefix length.
    pub fn discarded(&self) -> usize {
        self.discarded
    }

    /// Whether this set stands for a failed system read.
    pub fn read_failed(&self) -> bool {
        self.failed
    }

    /// Whether `ip` lies inside any prefix of the set.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        self.entries.iter().any(|p| prefix_holds(p.net, p.len, ip))
    }

    /// Whether `ip` lies inside a prefix held by one of the interfaces whose
    /// indexes are in `interfaces`. A prefix whose interface is unknown never
    /// matches, so an empty `interfaces` matches nothing.
    pub fn contains_on(&self, ip: IpAddr, interfaces: &[u32]) -> bool {
        let ip = canonical(ip);
        self.entries.iter().any(|p| {
            p.index.is_some_and(|index| interfaces.contains(&index))
                && prefix_holds(p.net, p.len, ip)
        })
    }

    /// Whether one prefix of the set holds both `a` and `b`.
    pub fn share_link(&self, a: IpAddr, b: IpAddr) -> bool {
        let (a, b) = (canonical(a), canonical(b));
        self.entries
            .iter()
            .any(|p| prefix_holds(p.net, p.len, a) && prefix_holds(p.net, p.len, b))
    }

    /// Whether the set holds no prefix at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Whether an interface read produced a set that cannot be trusted: some
/// entry was discarded for a zero prefix length, or `considered` interface
/// addresses passed the filters and none of them survived.
pub fn read_suspect(considered: usize, set: &OnLinkPrefixes) -> bool {
    set.discarded > 0 || (considered > 0 && set.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    fn set(pairs: &[(&str, u8)]) -> OnLinkPrefixes {
        OnLinkPrefixes::from_pairs(pairs.iter().map(|(a, l)| (ip(a), *l)))
    }

    #[test]
    fn ipv4_prefixes_hold_exactly_their_range() {
        let s24 = set(&[("192.168.1.10", 24)]);
        assert!(s24.contains(ip("192.168.1.200")));
        assert!(!s24.contains(ip("192.168.2.1")));

        let s25 = set(&[("192.168.1.10", 25)]);
        assert!(s25.contains(ip("192.168.1.127")));
        assert!(!s25.contains(ip("192.168.1.128")));

        let s16 = set(&[("10.20.1.1", 16)]);
        assert!(s16.contains(ip("10.20.7.8")));
        assert!(!s16.contains(ip("10.21.0.1")));

        let s32 = set(&[("203.0.113.5", 32)]);
        assert!(s32.contains(ip("203.0.113.5")));
        assert!(!s32.contains(ip("203.0.113.6")));
    }

    #[test]
    fn ipv6_prefixes_hold_exactly_their_range() {
        let s64 = set(&[("fd00::2", 64)]);
        assert!(s64.contains(ip("fd00::1")));
        assert!(!s64.contains(ip("fd01::1")));

        let s128 = set(&[("2001:db8::1", 128)]);
        assert!(s128.contains(ip("2001:db8::1")));
        assert!(!s128.contains(ip("2001:db8::2")));
    }

    #[test]
    fn ipv4_mapped_addresses_are_judged_as_ipv4() {
        let s = set(&[("::ffff:192.168.1.10", 24)]);
        assert!(s.contains(ip("192.168.1.7")));
        assert!(s.contains(ip("::ffff:192.168.1.7")));
        assert!(!s.contains(ip("::ffff:192.168.2.7")));
    }

    #[test]
    fn a_zero_length_prefix_is_discarded_and_holds_nothing() {
        let s = set(&[("192.168.1.1", 0)]);
        assert!(s.is_empty());
        assert!(!s.contains(ip("8.8.8.8")));
    }

    #[test]
    fn families_never_match_each_other() {
        let s = set(&[("192.168.1.1", 24)]);
        assert!(!s.contains(ip("fd00::1")));
    }

    #[test]
    fn share_link_needs_one_prefix_holding_both_addresses() {
        let s = set(&[("192.168.1.1", 24), ("10.0.0.1", 8)]);
        assert!(s.share_link(ip("192.168.1.5"), ip("192.168.1.50")));
        assert!(!s.share_link(ip("192.168.1.5"), ip("10.9.8.7")));
        assert!(!s.share_link(ip("192.168.1.5"), ip("192.168.2.5")));
        assert!(OnLinkPrefixes::default().is_empty());
        assert!(!OnLinkPrefixes::default().share_link(ip("10.0.0.1"), ip("10.0.0.2")));
    }

    #[test]
    fn contains_on_holds_only_the_named_interfaces_prefixes() {
        let s = OnLinkPrefixes::from_indexed([
            (ip("192.168.1.10"), 24, Some(2)),
            (ip("10.8.0.2"), 24, Some(3)),
            (ip("172.17.0.1"), 16, None),
        ]);
        assert!(s.contains_on(ip("192.168.1.7"), &[2]));
        assert!(!s.contains_on(ip("10.8.0.5"), &[2]));
        assert!(s.contains_on(ip("10.8.0.5"), &[2, 3]));
        assert!(
            !s.contains_on(ip("172.17.0.9"), &[2, 3]),
            "unknown interface"
        );
        assert!(!s.contains_on(ip("192.168.1.7"), &[]));
        assert!(s.contains(ip("172.17.0.9")));
        assert!(!set(&[("192.168.1.10", 24)]).contains_on(ip("192.168.1.7"), &[2]));
    }

    #[test]
    fn a_discarded_zero_length_prefix_or_an_empty_read_is_reported() {
        let partly = set(&[("192.168.1.1", 0), ("10.0.0.1", 8)]);
        assert_eq!(partly.discarded(), 1);
        assert!(read_suspect(2, &partly));
        assert!(read_suspect(2, &OnLinkPrefixes::default()));
        assert!(!read_suspect(0, &OnLinkPrefixes::default()));
        let healthy = set(&[("10.0.0.1", 8)]);
        assert!(!read_suspect(1, &healthy));
    }

    #[test]
    fn the_system_read_holds_every_up_non_loopback_ipv4_interface_prefix() {
        let interfaces = if_addrs::get_if_addrs().expect("getifaddrs failed");
        let up_v4: Vec<(std::net::Ipv4Addr, u8)> = interfaces
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
            .filter_map(|iface| match &iface.addr {
                if_addrs::IfAddr::V4(v4) => Some((v4.ip, v4.prefixlen)),
                if_addrs::IfAddr::V6(_) => None,
            })
            .collect();
        let read = OnLinkPrefixes::read_system();
        assert!(!read.contains(ip("127.0.0.1")));
        if up_v4.is_empty() {
            // A loopback-only host has nothing to compare.
            return;
        }
        assert!(
            up_v4.iter().all(|(_, len)| *len > 0),
            "an interface reported prefix length 0: {up_v4:?}"
        );
        assert!(!read.is_empty());
        assert_eq!(read.discarded(), 0);
        for (addr, _) in &up_v4 {
            assert!(
                read.contains(IpAddr::V4(*addr)),
                "{addr} missing from the read"
            );
        }
    }
}
