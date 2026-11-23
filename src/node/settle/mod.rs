//! One owner for each of the node's per-peer maps, in [`table`] what each
//! change to a held peer does to each piece of its state, and in [`exec`]
//! what the node runs for a change, in its order.
//!
//! Each map is a field of `Node` whose type is a wrapper with a private
//! inner map. The wrapper derefs to the map for every read, and `&wrapper`
//! iterates it, but there is no `DerefMut`: a write goes through one of the
//! wrapper's named methods, one per event that changes the map, each
//! transcribing the statements the event's sites wrote before. A field
//! borrow stays a field borrow, so two maps can still be borrowed at once.
//!
//! Under `cfg(test)` each wrapper also hands a test its inner map through
//! `raw`, which marks the map as written past its writers.

/// The read side every map wrapper shares: `Deref` to the inner map named
/// by `$field`, iteration over `&wrapper` (a `for` loop over a reference
/// does not reach `Deref`), and under `cfg(test)` the `raw` way past the
/// writers, which sets the wrapper's `planted` flag. There is no `DerefMut`.
macro_rules! reads {
    ($wrapper:ident, $field:ident, $map:ty) => {
        impl std::ops::Deref for $wrapper {
            type Target = $map;

            fn deref(&self) -> &$map {
                &self.$field
            }
        }

        impl<'a> IntoIterator for &'a $wrapper {
            type Item = <&'a $map as IntoIterator>::Item;
            type IntoIter = <&'a $map as IntoIterator>::IntoIter;

            fn into_iter(self) -> Self::IntoIter {
                self.$field.iter()
            }
        }

        impl $wrapper {
            /// The inner map, for a test that writes it itself. Marks the
            /// map planted: the state is one no writer built.
            #[cfg(test)]
            pub(in crate::node) fn raw(&mut self) -> &mut $map {
                self.planted = true;
                &mut self.$field
            }

            /// Whether a test has written this map past its writers.
            #[cfg(test)]
            pub(in crate::node) fn planted(&self) -> bool {
                self.planted
            }
        }
    };
}

#[cfg(any(test, debug_assertions))]
pub(in crate::node) mod audit;
pub(in crate::node) mod decide;
pub(in crate::node) mod exec;
mod links;
mod maps;
pub(in crate::node) mod params;
pub(crate) mod table;
#[cfg(test)]
mod tests;

pub(in crate::node) use links::LinkTable;
pub(in crate::node) use maps::{BindMap, DialMap, Leg, LegMap, MachineMap, PeerMap};

/// The settlement core's table the node holds: its link records, its
/// handshake legs and its restart gates, running the XX flow.
pub(in crate::node) type Core =
    crate::proto::settle::table::Table<crate::peer::PeerInstant, crate::proto::fmp::flow::Xx>;

/// The settlement core's table for a node `me` configured as `config`,
/// holding nothing, with the XX flow's parameters ([`params::xx_params`]).
pub(in crate::node) fn core(me: crate::NodeAddr, config: &crate::config::Config) -> Core {
    let leaf = config.node_profile() == crate::proto::fmp::NodeProfile::Leaf;
    Core::flowing(
        me,
        params::xx_params(&config.node),
        crate::proto::fmp::flow::Xx::new(leaf),
    )
}

impl crate::node::Node {
    /// The settlement core's handshake legs, the table's.
    pub(in crate::node) fn legs(
        &self,
    ) -> &crate::proto::settle::legs::Legs<crate::peer::PeerInstant> {
        self.core.parts().1
    }

    /// The settlement core's handshake legs, to write.
    #[cfg(test)]
    pub(in crate::node) fn legs_mut(
        &mut self,
    ) -> &mut crate::proto::settle::legs::Legs<crate::peer::PeerInstant> {
        self.core.parts_mut().1
    }

    /// The settlement core's restart gates, the table's.
    pub(in crate::node) fn gates(
        &self,
    ) -> &crate::proto::settle::gates::Gates<crate::peer::PeerInstant> {
        self.core.parts().2
    }

    /// The settlement core's restart gates, to write.
    #[cfg(test)]
    pub(in crate::node) fn gates_mut(
        &mut self,
    ) -> &mut crate::proto::settle::gates::Gates<crate::peer::PeerInstant> {
        self.core.parts_mut().2
    }

    /// The parameters of the node's handshake legs
    /// ([`params::leg_params`]), for a test that writes a leg itself.
    #[cfg(test)]
    pub(in crate::node) fn leg_params(&self) -> crate::proto::settle::params::Params {
        params::leg_params(&self.config().node)
    }

    /// The session index the handshake on `link` holds: its leg's in the
    /// settlement core's legs, or else its machine's.
    #[cfg(test)]
    pub(in crate::node) fn handshake_index(
        &self,
        link: crate::transport::LinkId,
    ) -> Option<crate::utils::index::SessionIndex> {
        self.core_no(link)
            .and_then(|no| self.legs().get(no))
            .map(|leg| crate::utils::index::SessionIndex::new(leg.index()))
            .or_else(|| self.peer_machines.get(&link)?.our_index())
    }

    /// When the dial on `link` next resends its msg1, on the interval
    /// clock, if it is in the settlement core's legs and has one scheduled.
    #[cfg(test)]
    pub(in crate::node) fn resend_at(&self, link: crate::transport::LinkId) -> Option<u64> {
        self.core_no(link)
            .and_then(|no| self.legs().get(no))
            .and_then(crate::proto::settle::legs::Leg::next_resend)
            .map(crate::time::mono_ms_at)
    }

    /// The parameters the node's restart gates read: the XX flow's, whose
    /// interval is next's restart interval and whose silent-session bounds
    /// are the node's.
    #[cfg(test)]
    pub(in crate::node) fn gate_params(&self) -> crate::proto::settle::params::Params {
        params::xx_params(&self.config().node)
    }

    /// Audit the per-peer maps as the node entry `site` returns, panicking
    /// on a breach, in a debug build; nothing in a release build. Every
    /// node entry that can change one of the maps calls it on its way out.
    #[inline]
    pub(in crate::node) fn audit_live(&self, site: &str) {
        #[cfg(debug_assertions)]
        audit::live(self, site);
        #[cfg(not(debug_assertions))]
        let _ = site;
    }

    /// Mark the node as built past its writers, for a test helper that makes
    /// a state no production path makes. The live audit skips the node for
    /// the rest of the test.
    #[cfg(test)]
    pub(in crate::node) fn plant(&mut self) {
        self.links.plant();
    }

    /// Write into the node's link records what a test changed past the
    /// writers, before the node next reads them: a record for each link a
    /// test put in the link map, and for the link of each peer it planted on
    /// a link the map lacks, at the pair the peer is at, each held by the
    /// peer on its link; and each entry it wrote in the index, named in the
    /// index through its link's record, or opening one
    /// ([`LinkTable::resync`]). The node resyncs at the head of each msg1; a
    /// test that reads the msg1 predicates itself resyncs first. With
    /// nothing planted it writes nothing (test builds only).
    #[cfg(test)]
    pub(in crate::node) fn resync(&mut self) {
        if node_fault!(ResyncSkipped) {
            return;
        }
        let holders: std::collections::HashMap<crate::transport::LinkId, crate::NodeAddr> = self
            .peers
            .iter()
            .map(|(addr, peer)| (peer.link_id(), *addr))
            .collect();
        // A peer a test planted on a link the map lacks gets a record at
        // the pair it is at.
        let unrecorded = self
            .peers
            .iter()
            .filter(|(_, peer)| {
                self.links.no(&peer.link_id()).is_none()
                    && !self.links.contains_key(&peer.link_id())
            })
            .map(|(addr, peer)| (peer.link_id(), *addr, links::current(peer)))
            .collect();
        self.links
            .resync(self.core.parts_mut().0, unrecorded, &holders);
    }

    /// Whether a test has written any of the node's per-peer maps past its
    /// writers, or marked the node so.
    #[cfg(test)]
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub(in crate::node) fn planted(&self) -> bool {
        self.links.planted()
            || self.peers.planted()
            || self.peers_by_index.planted()
            || self.pending_outbound.planted()
            || self.pending_inbound.planted()
            || self.peer_machines.planted()
    }
}
