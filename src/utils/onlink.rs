//! The address prefixes of this node's own network interfaces.
//!
//! [`OnLinkPrefixes`] answers one question: whether an address lies on one of
//! this node's own links, judged by the prefixes (address and prefix length)
//! its interfaces hold. Discovery code uses it to decide whether an address a
//! remote party named is one this node can reach directly, and whether two
//! addresses share a link.
//!
//! A set is built for each use and never cached, because interfaces change
//! under DHCP renumbering and VPNs coming and going. An empty set holds no
//! address, so a caller that gates candidates with it refuses every one.

use std::net::IpAddr;

/// The interface prefixes of this node, as `(address, prefix length)` pairs.
#[derive(Clone, Debug, Default)]
pub struct OnLinkPrefixes {
    entries: Vec<(IpAddr, u8)>,
}

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
    pub fn from_pairs(pairs: impl IntoIterator<Item = (IpAddr, u8)>) -> Self {
        let entries = pairs
            .into_iter()
            .filter_map(|(ip, len)| {
                let ip = canonical(ip);
                let width = if ip.is_ipv4() { 32 } else { 128 };
                (len != 0).then_some((ip, len.min(width)))
            })
            .collect();
        Self { entries }
    }

    /// Whether `ip` lies inside any prefix of the set.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        self.entries
            .iter()
            .any(|(net, len)| prefix_holds(*net, *len, ip))
    }

    /// Whether one prefix of the set holds both `a` and `b`.
    pub fn share_link(&self, a: IpAddr, b: IpAddr) -> bool {
        let (a, b) = (canonical(a), canonical(b));
        self.entries
            .iter()
            .any(|(net, len)| prefix_holds(*net, *len, a) && prefix_holds(*net, *len, b))
    }

    /// Whether the set holds no prefix at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
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
}
