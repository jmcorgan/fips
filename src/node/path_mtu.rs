//! Per-destination path MTU state, published to the IPv6 adapter.
//!
//! Every writer, the release paths and the expiry pass live in the node.
//! The map records, beside each entry, the key of the peer it describes, and
//! every change to it is pushed to the adapter while one is attached, so the
//! adapter's copy follows the map without reading it.

use crate::Ipv6Address;
use crate::ipv6tun::link::{FromMesh, HostLink, PeerKey};
pub(crate) use crate::proto::framing::payload_limit;
use std::collections::HashMap;
use std::collections::hash_map::Iter;

/// One `path_mtu_lookup` entry: the MTU the TCP MSS clamp reads, plus how
/// the entry is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathMtuEntry {
    /// Path MTU in bytes.
    pub mtu: u16,
    /// Unix ms at which a discovery `LookupResponse` supplied this value, or
    /// `None` for an entry that some event releases instead of a timer.
    ///
    /// The discovery carrier is the one with no release path: it writes an
    /// entry for a destination this node may never open a session with, and
    /// all three callers of `path_mtu_lookup_release` fire on session state.
    /// A link MTU this node derived from its own transport, and a value
    /// learned inside a session, are both released by an event that says the
    /// thing they describe is gone, so they carry no deadline.
    pub learned_ms: Option<u64>,
}

impl PathMtuEntry {
    /// An entry released by an event rather than a timer: a locally derived
    /// link MTU, or a value learned inside a session.
    pub fn held(mtu: u16) -> Self {
        Self {
            mtu,
            learned_ms: None,
        }
    }

    /// A remote party's claim stored at `at_ms` for a destination with no
    /// other release path. Expires.
    pub fn learned(mtu: u16, at_ms: u64) -> Self {
        Self {
            mtu,
            learned_ms: Some(at_ms),
        }
    }
}

/// The per-destination path MTU map, keyed by [`Ipv6Address`] (the IPv6
/// form of a peer's node address).
///
/// Every insert and every removal goes through here. An insert normally
/// names the peer's key, and while an adapter is attached each change to a
/// keyed entry reaches it as a [`FromMesh::PathMtu`] in the order the map
/// saw it. An entry stored without a key (`insert_unkeyed`) is never
/// published.
#[derive(Default)]
pub(crate) struct PathMtuMap {
    /// The entries themselves.
    entries: HashMap<Ipv6Address, PathMtuEntry>,
    /// The key of the peer each entry describes.
    keys: HashMap<Ipv6Address, PeerKey>,
    /// Where changes go while the adapter wants the path MTU feed.
    feed: Option<HostLink>,
}

impl PathMtuMap {
    /// The entry for `addr`.
    pub(crate) fn get(&self, addr: &Ipv6Address) -> Option<&PathMtuEntry> {
        self.entries.get(addr)
    }

    /// How many entries the map holds.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Every entry.
    pub(crate) fn iter(&self) -> Iter<'_, Ipv6Address, PathMtuEntry> {
        self.entries.iter()
    }

    /// Store `entry` for `addr`, the address of the peer whose key is `key`,
    /// and publish it. Returns the entry it replaced.
    pub(crate) fn insert(
        &mut self,
        addr: Ipv6Address,
        key: PeerKey,
        entry: PathMtuEntry,
    ) -> Option<PathMtuEntry> {
        debug_assert_eq!(
            key.address(),
            addr,
            "a path MTU entry under another peer's key"
        );
        self.keys.insert(addr, key);
        self.publish(key, Some(entry));
        self.entries.insert(addr, entry)
    }

    /// Store `entry` for `addr` with no key and without publishing it.
    ///
    /// Only for an entry whose peer key is unknown, which no production
    /// writer reaches: the session writers fall back to it only if their
    /// session has no key, and their admission rules exclude that. Tests
    /// that seed the map by address use it. A key-less entry never reaches
    /// the adapter, so one that replaces a keyed entry releases it there.
    pub(crate) fn insert_unkeyed(
        &mut self,
        addr: Ipv6Address,
        entry: PathMtuEntry,
    ) -> Option<PathMtuEntry> {
        if let Some(key) = self.keys.remove(&addr) {
            self.publish(key, None);
        }
        self.entries.insert(addr, entry)
    }

    /// Drop the entry for `addr` and publish the release. Returns it.
    pub(crate) fn remove(&mut self, addr: &Ipv6Address) -> Option<PathMtuEntry> {
        let removed = self.entries.remove(addr);
        if let Some(key) = self.keys.remove(addr) {
            self.publish(key, None);
        }
        removed
    }

    /// Start publishing to `feed`, first replaying every entry.
    pub(crate) fn attach(&mut self, feed: HostLink) {
        for (addr, entry) in &self.entries {
            if let Some(key) = self.keys.get(addr) {
                feed.send(FromMesh::PathMtu {
                    peer: *key,
                    payload_limit: Some(payload_limit(entry.mtu)),
                });
            }
        }
        self.feed = Some(feed);
    }

    /// Stop publishing.
    pub(crate) fn detach(&mut self) {
        self.feed = None;
    }

    /// Send one change to the adapter, if one is attached.
    fn publish(&self, key: PeerKey, entry: Option<PathMtuEntry>) {
        if let Some(feed) = &self.feed {
            feed.send(FromMesh::PathMtu {
                peer: key,
                payload_limit: entry.map(|e| payload_limit(e.mtu)),
            });
        }
    }
}
