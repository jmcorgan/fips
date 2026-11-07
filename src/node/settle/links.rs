//! The link table: the node's links and the address index over them.

use std::collections::HashMap;

use crate::node::AddrKey;
use crate::transport::{Link, LinkId};

/// The node's links, keyed by `LinkId`, and the index from a
/// `(transport, address)` pair to the link at it.
///
/// The index is a reverse lookup from `(transport, address)` to link. It is
/// **not** a packet-dispatch path: `find_link_by_addr` has no callers outside
/// its own tests, and encrypted frames are dispatched by session index. Its
/// live readers are the `should_admit_msg1` fast path and the
/// duplicate-inbound-handshake check in `handle_msg1`.
///
/// **Do not key a peer-identity question on it.** The address form is not
/// canonical: an outbound dial registers the literal configured string, which
/// may be a hostname (`"node-b:2121"`), while an inbound packet carries the
/// resolved form (`"10.128.2.4:2121"`). `TransportAddr` compares byte-wise, so
/// those never match, and a lookup keyed on an inbound address silently returns
/// "no such link" for every hostname-configured peer rather than failing. The
/// entry is also single-valued per key, so an inbound handshake overwrites an
/// outbound dial's entry for the same address. The readers above tolerate this
/// because each compares a key written in the same form it reads; a new reader
/// that does not will be quietly wrong.
///
/// The links are reached by `Deref` for reads, and by `get_mut` for a change
/// to a link that leaves the table as it is; the index by `index`. Every
/// write to either goes through a writer named for its event, and each writer
/// is the statements its sites wrote, so the index keeps its single-valued
/// keys and its gaps.
#[derive(Default)]
pub(in crate::node) struct LinkTable {
    links: HashMap<LinkId, Link>,
    index: HashMap<AddrKey, LinkId>,
    #[cfg(test)]
    planted: bool,
}

reads!(LinkTable, links, HashMap<LinkId, Link>);

impl LinkTable {
    /// A new link: the link is added, and its own pair in the index names
    /// it, whatever link the pair named before.
    pub(in crate::node) fn open(&mut self, link: Link) {
        let id = link.link_id();
        let key = (link.transport_id(), link.remote_addr().clone());
        self.links.insert(id, link);
        self.index.insert(key, id);
    }

    /// The link is closed: it is taken out, with every index entry that
    /// names it. Entries another link has claimed are left alone.
    pub(in crate::node) fn close(&mut self, id: &LinkId) -> Option<Link> {
        let link = self.links.remove(id)?;
        self.index.retain(|_, mapped| *mapped != *id);
        Some(link)
    }

    /// A dial is abandoned: its link is dropped, and so is the index entry
    /// at `key`, whichever link that entry names.
    pub(in crate::node) fn forget(&mut self, id: &LinkId, key: &AddrKey) {
        self.links.remove(id);
        self.index.remove(key);
    }

    /// The link's path moved from `from` to `to`. Only if `from` names the
    /// link is its entry dropped, and then `to` names the link unless
    /// another link holds it.
    pub(in crate::node) fn follow(&mut self, id: LinkId, from: &AddrKey, to: AddrKey) {
        if self.index.get(from) == Some(&id) {
            self.index.remove(from);
            self.index.entry(to).or_insert(id);
        }
    }

    /// The link switched to a path at `to`, which names the link unless
    /// another link holds it.
    pub(in crate::node) fn claim(&mut self, id: LinkId, to: AddrKey) {
        self.index.entry(to).or_insert(id);
    }

    /// The link released its path at `key`, whose entry goes only if it
    /// names the link.
    pub(in crate::node) fn unclaim(&mut self, id: LinkId, key: &AddrKey) {
        if self.index.get(key) == Some(&id) {
            self.index.remove(key);
        }
    }

    /// The link, to update.
    pub(in crate::node) fn get_mut(&mut self, id: &LinkId) -> Option<&mut Link> {
        self.links.get_mut(id)
    }

    /// The index: each `(transport, address)` pair and the link it names.
    pub(in crate::node) fn index(&self) -> &HashMap<AddrKey, LinkId> {
        &self.index
    }

    /// The index, for a test that writes it itself. Marks the table
    /// planted.
    #[cfg(test)]
    pub(in crate::node) fn raw_index(&mut self) -> &mut HashMap<AddrKey, LinkId> {
        self.planted = true;
        &mut self.index
    }
}
