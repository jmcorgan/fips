//! The identity cache: the keys of the nodes this node can name by address.
//!
//! Entries are keyed by bytes 1 to 15 of a node's IPv6 address, the prefix a
//! host packet names its destination by, and hold the node address, the full
//! public key and the time of the last use.
//!
//! While the IPv6 adapter is attached with the identity feed, the cache also
//! tells it which keys the node can route to: every key an insert adds, and,
//! once a removed key is neither cached again nor held by a session, that it
//! is gone. A removed key stays with the adapter while a session holds it,
//! because a session that has proven its peer's key answers for the cache
//! (`Node::lookup_by_fips_prefix`). The adapter's copy is therefore never
//! narrower than what the node can resolve, apart from the one channel hop a
//! new key takes to reach it.

use std::collections::{HashMap, HashSet};

use secp256k1::{PublicKey, XOnlyPublicKey};

use crate::NodeAddr;
use crate::ipv6tun::link::{FromMesh, HostLink, PeerKey};

/// Bytes 1 to 15 of a node's IPv6 address.
pub(crate) type Prefix = [u8; 15];

/// One cached identity: the node address, its key, and when it was last used,
/// in milliseconds.
pub(crate) type Entry = (NodeAddr, PublicKey, u64);

/// What the adapter has been told, while it is attached.
struct Feed {
    /// The adapter's end of the link.
    link: HostLink,
    /// Every key the adapter has been told of and not told to forget, with
    /// the node address it hashes to.
    told: HashMap<PeerKey, NodeAddr>,
    /// Keys the adapter holds that are not cached, to check on the next
    /// sweep: keys removed from the cache, and keys the attach told only
    /// because a session held them.
    removed: HashSet<PeerKey>,
}

/// The identity cache and the adapter's identity feed.
#[derive(Default)]
pub(crate) struct IdentityCache {
    /// The entries, by prefix.
    entries: HashMap<Prefix, Entry>,
    /// The feed, while the adapter is attached and asked for it.
    feed: Option<Feed>,
    /// The number of the last key the adapter's DNS responder reported that
    /// the node has handled.
    learned: u64,
}

impl IdentityCache {
    /// An empty cache with no feed.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Store `entry` under `prefix`, returning the entry it replaces, and
    /// tell the adapter of its key if it has not been told already.
    pub(crate) fn insert(&mut self, prefix: Prefix, entry: Entry) -> Option<Entry> {
        let key = PeerKey::new(entry.1.x_only_public_key().0);
        let addr = entry.0;
        let old = self.entries.insert(prefix, entry);
        if let Some(old) = &old {
            let old_key = PeerKey::new(old.1.x_only_public_key().0);
            if old_key != key {
                self.removed(old_key);
            }
        }
        if let Some(feed) = &mut self.feed {
            feed.removed.remove(&key);
            if feed.told.insert(key, addr).is_none() {
                feed.link.send(FromMesh::KnownKey { peer: key });
            }
        }
        old
    }

    /// Remove the entry under `prefix`, returning it. The adapter keeps the
    /// key until a sweep finds it neither cached again nor held by a session.
    pub(crate) fn remove(&mut self, prefix: &Prefix) -> Option<Entry> {
        let old = self.entries.remove(prefix)?;
        self.removed(PeerKey::new(old.1.x_only_public_key().0));
        Some(old)
    }

    /// Mark `key`, whose entry left the cache, for the next sweep if the
    /// adapter holds it.
    fn removed(&mut self, key: PeerKey) {
        if let Some(feed) = &mut self.feed
            && feed.told.contains_key(&key)
        {
            feed.removed.insert(key);
        }
    }

    /// The entry under `prefix`, stamped as used at `now`.
    pub(crate) fn touch(&mut self, prefix: &Prefix, now: u64) -> Option<(NodeAddr, PublicKey)> {
        let entry = self.entries.get_mut(prefix)?;
        entry.2 = now;
        Some((entry.0, entry.1))
    }

    /// Whether an entry is stored under `prefix`.
    pub(crate) fn contains_key(&self, prefix: &Prefix) -> bool {
        self.entries.contains_key(prefix)
    }

    /// The number of entries.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds no entry.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every entry with its prefix.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&Prefix, &Entry)> {
        self.entries.iter()
    }

    /// Every entry.
    pub(crate) fn values(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    /// Start the feed on `link`: tell the adapter of every cached key and of
    /// every key in `held`, the keys sessions hold.
    ///
    /// A key told only because a session holds it is marked for the sweep
    /// as a removed key is, so the adapter forgets it once the session ends.
    pub(crate) fn attach(
        &mut self,
        link: HostLink,
        held: impl IntoIterator<Item = (XOnlyPublicKey, NodeAddr)>,
    ) {
        let mut told: HashMap<PeerKey, NodeAddr> = self
            .entries
            .values()
            .map(|entry| (PeerKey::new(entry.1.x_only_public_key().0), entry.0))
            .collect();
        let mut removed = HashSet::new();
        for (key, addr) in held {
            let key = PeerKey::new(key);
            if let std::collections::hash_map::Entry::Vacant(slot) = told.entry(key) {
                slot.insert(addr);
                removed.insert(key);
            }
        }
        for key in told.keys() {
            link.send(FromMesh::KnownKey { peer: *key });
        }
        self.feed = Some(Feed {
            link,
            told,
            removed,
        });
    }

    /// Stop the feed.
    pub(crate) fn detach(&mut self) {
        self.feed = None;
    }

    /// Note that the node has handled the adapter's report number `seq`.
    pub(crate) fn handled(&mut self, seq: u64) {
        self.learned = self.learned.max(seq);
    }

    /// Tell the adapter to forget each removed key that is not cached again
    /// and that `held` says no session holds.
    pub(crate) fn sweep(&mut self, held: impl Fn(&NodeAddr, &PeerKey) -> bool) {
        let learned = self.learned;
        let Some(feed) = &mut self.feed else {
            return;
        };
        let entries = &self.entries;
        // Cached again: an entry for the key's prefix holds the key.
        let cached = |key: &PeerKey, addr: &NodeAddr| {
            let mut prefix = [0u8; 15];
            prefix.copy_from_slice(&addr.as_bytes()[0..15]);
            entries
                .get(&prefix)
                .is_some_and(|entry| PeerKey::new(entry.1.x_only_public_key().0) == *key)
        };
        let told = &feed.told;
        feed.removed
            .retain(|key| !told.get(key).is_some_and(|addr| cached(key, addr)));
        let gone: Vec<PeerKey> = feed
            .removed
            .iter()
            .filter(|key| !told.get(key).is_some_and(|addr| held(addr, key)))
            .copied()
            .collect();
        for key in gone {
            feed.removed.remove(&key);
            feed.told.remove(&key);
            feed.link.send(FromMesh::ForgotKey { peer: key, learned });
        }
    }

    /// The node address `key` hashes to, if the adapter has been told of
    /// it: the feed keeps it from when the key was told.
    pub(crate) fn address(&self, key: &PeerKey) -> Option<NodeAddr> {
        self.feed.as_ref()?.told.get(key).copied()
    }

    /// Whether the adapter has been told of `key`, or no feed runs.
    pub(crate) fn told(&self, key: &PeerKey) -> bool {
        self.feed
            .as_ref()
            .is_none_or(|feed| feed.told.contains_key(key))
    }
}
