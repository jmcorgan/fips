//! The address prefixes of this node's own network interfaces.
//!
//! [`OnLinkPrefixes`] answers one question: whether an address lies on one of
//! this node's own links, judged by the prefixes (address and prefix length)
//! its interfaces hold. Discovery code uses it to decide whether an address a
//! remote party named is one this node can reach directly, whether it lies on
//! the particular interface something arrived on, and whether two addresses
//! share a link.
//!
//! The root crate reads a set from the system, with
//! `fips::utils::onlink::read_system`. A set is built for each use and never
//! cached, because interfaces change under DHCP renumbering and VPNs coming
//! and going. An empty set holds no address, so a caller that gates
//! candidates with it refuses every one.

use alloc::vec::Vec;
use core::net::IpAddr;

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
#[path = "tests/onlink.rs"]
mod tests;
