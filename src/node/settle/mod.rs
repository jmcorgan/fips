//! One owner for each of the node's per-peer maps.
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
mod links;
mod maps;
#[cfg(test)]
mod tests;

pub(in crate::node) use links::LinkTable;
pub(in crate::node) use maps::{BindMap, DialMap, LegMap, MachineMap, PeerMap};

#[cfg(any(test, debug_assertions))]
pub(in crate::node) use links::Waiver;

impl crate::node::Node {
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
