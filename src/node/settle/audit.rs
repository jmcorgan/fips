//! The coherence of the node's per-peer maps, each rule stated once.
//!
//! Each clause reads the maps as they stand and names what breaks it. The
//! quiescent audit of the node tests (`node/tests/settle/audit.rs` and
//! `node/tests/link_index_audit.rs`) calls the clauses it shares with this
//! module rather than restating them, and [`live`] runs every clause, in a
//! debug build, panicking on the first that fails. Every clause here holds in
//! every state between two node entries, not only once a test has gone
//! quiet: the checks that hold only at quiescence (the peer's link record at
//! the peer's pair, every open connection in use, every current session on a
//! worker) stay with the quiescent audit. The last clause, [`links_mirror`],
//! holds the settlement core's link records, which nothing reads yet, to the
//! bundles they are fed from.

// A release test build compiles this module for the quiescent audit, but
// not `live`, the one caller of the clauses the quiescent audit does not
// share.
#![cfg_attr(not(debug_assertions), allow(dead_code))]

use std::collections::{HashMap, HashSet};

use fips_core::proto::path::PathRef;

#[cfg(test)]
use crate::NodeAddr;
use crate::node::{AddrKey, Node};
use crate::proto::settle::join;
use crate::proto::settle::links::{LinkNo, Pair, Proven};
use crate::transport::LinkId;

/// `peer-link`: every peer's link is in the link map. The links of the peers
/// that break it.
pub(in crate::node) fn peer_link(node: &Node) -> Vec<LinkId> {
    node.peers
        .values()
        .map(|peer| peer.link_id())
        .filter(|link| !node.links.contains_key(link))
        .collect()
}

/// `link-cache`: every held peer's link, which the send path reads on every
/// frame, is the link the settlement core holds it on. The peers that break
/// it.
pub(in crate::node) fn link_cache(node: &Node) -> Vec<crate::NodeAddr> {
    node.peers
        .iter()
        .filter(|(addr, peer)| {
            let held = node.core.held(addr).and_then(|h| node.links.id(h.link));
            held != Some(peer.link_id())
        })
        .map(|(addr, _)| *addr)
        .collect()
}

/// `held-cache`: every held peer's facts the node keeps beside the
/// settlement core's record of it, which the send path and the removal
/// read, are the core's: its epoch, whether it is heard, the pair it is at
/// and the instant of its last frame. The peers that break it.
pub(in crate::node) fn held_cache(node: &Node) -> Vec<(crate::NodeAddr, &'static str)> {
    use super::decide::{current, last};
    node.peers
        .iter()
        .filter_map(|(addr, peer)| {
            // A peer a test changed past the core is written into it at the
            // next resync, not before.
            #[cfg(test)]
            if peer.past_feed() {
                return None;
            }
            let Some(h) = node.core.held(addr) else {
                return Some((*addr, "held"));
            };
            let stale = if h.epoch != peer.remote_epoch().unwrap_or_default() {
                "epoch"
            } else if h.heard != peer.is_heard() {
                "heard"
            } else if h.current != current(peer) {
                "current"
            } else if h.last != last(peer) {
                "last"
            } else {
                return None;
            };
            Some((*addr, stale))
        })
        .collect()
}

/// `link-named`: every link is named by a peer, a handshake entry or a
/// handshake leg. The links no one names.
pub(in crate::node) fn link_named(node: &Node) -> Vec<LinkId> {
    let mut named: HashSet<LinkId> = node.peers.values().map(|p| p.link_id()).collect();
    named.extend(node.handshakes.keys().copied());
    named.extend(
        node.legs()
            .iter()
            .filter_map(|leg| node.links.id(leg.link())),
    );
    node.links
        .keys()
        .filter(|link| !named.contains(link))
        .copied()
        .collect()
}

/// `dial-link`: every handshake leg's link is in the link map. The core's
/// numbers of the legs that break it.
pub(in crate::node) fn dial_link(node: &Node) -> Vec<LinkNo> {
    node.legs()
        .iter()
        .map(|leg| leg.link())
        .filter(|no| {
            node.links
                .id(*no)
                .is_none_or(|link| !node.links.contains_key(&link))
        })
        .collect()
}

/// `entry-live`: every index entry names a live link. The entries that name
/// none.
pub(in crate::node) fn entry_live(node: &Node) -> Vec<(AddrKey, LinkId)> {
    node.links
        .index()
        .iter()
        .filter(|(_, link)| !node.links.contains_key(link))
        .map(|(key, link)| (key.clone(), *link))
        .collect()
}

/// `entry-pair`: every index entry naming a live link is at that link's
/// setup pair or at a path the link's peer holds, in any state. The entries
/// at neither.
pub(in crate::node) fn entry_pair(node: &Node) -> Vec<(AddrKey, LinkId)> {
    let mut bad = Vec::new();
    for ((tid, addr), link) in node.links.index().iter() {
        let Some(at) = node.links.get(link) else {
            continue;
        };
        let setup = at.transport_id() == *tid && at.remote_addr() == addr;
        let path = node.peers.values().any(|peer| {
            peer.link_id() == *link
                && peer
                    .bundle()
                    .is_some_and(|b| b.paths().find(*tid, addr).is_some())
        });
        if !setup && !path {
            bad.push(((*tid, addr.clone()), *link));
        }
    }
    bad
}

/// `held-entry`: every link a peer is held on is named by at least one index
/// entry, or its own pair names another live link. The held links that break
/// it.
pub(in crate::node) fn held_entry(node: &Node) -> Vec<LinkId> {
    let held: HashSet<LinkId> = node.peers.values().map(|p| p.link_id()).collect();
    let mut bad = Vec::new();
    for link in held {
        let Some(at) = node.links.get(&link) else {
            continue;
        };
        let index = node.links.index();
        let some = index.values().any(|named| *named == link);
        let key = (at.transport_id(), at.remote_addr().clone());
        let other = index
            .get(&key)
            .is_some_and(|named| node.links.contains_key(named));
        if !some && !other {
            bad.push(link);
        }
    }
    bad
}

/// `leg-entry`: every handshake leg's link has its own pair in the index, or
/// that pair names another live link. The legs' links that break it.
pub(in crate::node) fn leg_entry(node: &Node) -> Vec<LinkId> {
    let mut bad = Vec::new();
    for (link, entry) in node.handshakes.iter() {
        if entry.leg().is_none() {
            continue;
        }
        let Some(at) = node.links.get(link) else {
            continue;
        };
        let key = (at.transport_id(), at.remote_addr().clone());
        let ok = node
            .links
            .index()
            .get(&key)
            .is_some_and(|named| named == link || node.links.contains_key(named));
        if !ok {
            bad.push(*link);
        }
    }
    bad
}

/// `redial-leg`: each pending redial the settlement core marks names a leg:
/// the answer's leg in the core's legs on that link, for that peer, holding
/// an index no peer is bound to, on a link that is open, with a handshake
/// entry on it that still holds its crypto, for a msg1 this node answered,
/// whose identity is the redial's peer; and the node's cache of the redials
/// holds that link and index for the peer. The identities whose mark breaks
/// it.
pub(in crate::node) fn redial_leg(node: &Node) -> Vec<crate::NodeAddr> {
    let mut bad = Vec::new();
    for (peer, no) in node.core.redials() {
        let leg = node.core.legs().get(no).filter(|leg| {
            matches!(leg.kind(), crate::proto::settle::legs::Kind::Answer { .. })
                && leg.peer() == Some(*peer)
        });
        let link = node.links.id(no);
        let ok = match (leg, link) {
            (Some(leg), Some(link)) => {
                node.handshakes.get(&link).is_some_and(|e| {
                    e.leg().is_some()
                        && e.conn_is_inbound()
                        && e.conn_expected_identity().map(|id| *id.node_addr()) == Some(*peer)
                }) && node.peers_by_index.get(&leg.index()).is_none()
                    && node.links.contains_key(&link)
                    && node
                        .redials
                        .of(peer)
                        .is_some_and(|r| r.link == link && r.index.as_u32() == leg.index())
            }
            _ => false,
        };
        if !ok {
            bad.push(*peer);
        }
    }
    bad
}

/// `index-cache`: the index the link table keeps is the one its link
/// records give now. The pairs where the two differ, each with the link the
/// cache names there and the link the records do.
pub(in crate::node) fn index_cache(node: &Node) -> Vec<(AddrKey, Option<LinkId>, Option<LinkId>)> {
    let cache = node.links.index();
    let derived = node.links.derived(node.core.links());
    let keys: HashSet<&AddrKey> = cache.keys().chain(derived.keys()).collect();
    keys.into_iter()
        .filter(|key| cache.get(*key) != derived.get(*key))
        .map(|key| {
            (
                key.clone(),
                cache.get(key).copied(),
                derived.get(key).copied(),
            )
        })
        .collect()
}

/// `index`: `peers_by_index` maps exactly the indices the peers' link
/// machines bind, each to the peer that binds it, whatever transport each
/// binding recorded; the allocator holds those indices and the shell's own
/// leases (a handshake carrier or leg) and nothing else; and, with a decrypt-worker
/// pool, the workers hold exactly the sessions the machines recorded as
/// handed to them. Panics, prefixed by `step`, on the first that fails.
///
/// The workers need not hold every current session: the pool refuses a
/// session on a full queue or a lost worker, and the machine then keeps it.
pub(in crate::node) fn index(node: &Node, step: &str) {
    let mut bound = HashMap::new();
    let mut onworker = HashSet::new();
    let mut leased = 0;
    for (addr, peer) in node.peers.iter() {
        for ((_, key), held) in peer.link_bindings() {
            assert!(
                bound.insert(key, *addr).is_none(),
                "{step}: index {key:?} bound twice"
            );
            if held {
                onworker.insert(key);
            }
        }
        leased += peer.link_bindings().len();
    }
    leased += node
        .handshakes
        .values()
        .filter(|entry| entry.our_index().is_some())
        .count();
    leased += node.legs().iter().count();
    let mapped: HashMap<_, _> = node
        .peers_by_index
        .iter()
        .map(|(key, addr)| (*key, *addr))
        .collect();
    assert_eq!(
        mapped, bound,
        "{step}: peers_by_index must map exactly the indices the link machines bind"
    );
    assert_eq!(
        node.index_allocator.count(),
        leased,
        "{step}: the allocator must hold exactly the leased indices"
    );
    #[cfg(unix)]
    if node.supervisor.decrypt_workers.is_some() {
        assert_eq!(
            node.decrypt_registered_sessions, onworker,
            "{step}: the workers must hold exactly the sessions the machines delegated"
        );
    }
    #[cfg(not(unix))]
    let _ = onworker;
}

/// `carrier`: every handshake entry has a live carrier, its own pending
/// connection, an active peer on its link whose promotion has not yet
/// dropped it, or a pending connect still resolving toward it. An entry with
/// none is unreachable by every teardown path and has leaked. The links of
/// the entries that break it.
pub(in crate::node) fn carrier(node: &Node) -> Vec<LinkId> {
    node.handshakes
        .iter()
        .filter(|(link, entry)| {
            entry.leg().is_none()
                && !node.peers.values().any(|peer| peer.link_id() == **link)
                && !node
                    .peering
                    .pending_connects
                    .iter()
                    .any(|pending| pending.link_id == **link)
        })
        .map(|(link, _)| *link)
        .collect()
}

/// What `links-mirror` found over a node's held peers.
#[derive(Debug, Default)]
pub(in crate::node) struct Mirror {
    /// The peers whose link's record breaks the clause, each with what the
    /// record and the bundle hold.
    pub(in crate::node) bad: Vec<String>,
    /// The peers not read, since a test changed their bundle past the feed
    /// (test builds only).
    #[cfg(test)]
    pub(in crate::node) unmirrored: Vec<NodeAddr>,
}

/// `paths` in one order, for a comparison that sets order aside.
fn sorted(mut paths: Vec<(Pair, Proven)>) -> Vec<(Pair, Proven)> {
    let rank = |p: &Proven| match p {
        Proven::Live => 0,
        Proven::Acked => 1,
        Proven::Probing => 2,
    };
    paths.sort_by(|(a, p), (b, q)| a.cmp(b).then(rank(p).cmp(&rank(q))));
    paths
}

/// `links-mirror`: the settlement core's record of each held peer's link
/// holds the link capable exactly when the peer's bundle does, and exactly
/// the paths of the peer's bundle, order aside, each in the state the core
/// is told of it (Live for a Live path, acknowledged for another
/// acknowledged one, probing otherwise), and a peer with no bundle neither,
/// as the joint world's `Mirrored` oracle holds it. A peer a test changed
/// past the feed is not read.
pub(in crate::node) fn links_mirror(node: &Node) -> Mirror {
    let mut found = Mirror::default();
    for (addr, peer) in node.peers.iter() {
        #[cfg(test)]
        if peer.past_feed() {
            found.unmirrored.push(*addr);
            continue;
        }
        let link = peer.link_id();
        let Some(rec) = node
            .links
            .no(&link)
            .and_then(|no| node.core.links().get(no))
        else {
            found.bad.push(format!("{addr}: link {link} has no record"));
            continue;
        };
        let held: Vec<(Pair, Proven)> = peer
            .bundle()
            .map(|b| {
                b.paths()
                    .paths()
                    .iter()
                    .map(|p| {
                        let at = PathRef {
                            transport: p.transport_id(),
                            addr: p.addr().clone(),
                        };
                        (join::pair(&at), join::proven(b, &at))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let capable = peer.bundle().is_some_and(|b| b.capable());
        if rec.capable != capable {
            found.bad.push(format!(
                "{addr}: link {link}'s record holds it capable {}, its bundle {capable}",
                rec.capable
            ));
            continue;
        }
        let (core, held) = (sorted(rec.paths.clone()), sorted(held));
        if core != held {
            found.bad.push(format!(
                "{addr}: link {link}'s record holds {core:?}, its bundle {held:?}"
            ));
        }
    }
    found
}

/// Run every clause on `node`, which has just left the node entry `site`,
/// and panic, naming the site and the clause, on the first that fails.
///
/// In a test, the clauses skip a node written past its writers, since its
/// state is one no production path builds, and each audit is counted on the
/// node and, when `FIPS_AUDIT_REACH` names a file, recorded there.
#[cfg(debug_assertions)]
pub(in crate::node) fn live(node: &Node, site: &str) {
    #[cfg(test)]
    if node.planted() {
        reach::row(node, "planted");
        return;
    }
    fail(site, "peer-link", &peer_link(node));
    fail(site, "link-named", &link_named(node));
    fail(site, "dial-link", &dial_link(node));
    fail(site, "entry-live", &entry_live(node));
    fail(site, "entry-pair", &entry_pair(node));
    fail(site, "held-entry", &held_entry(node));
    fail(site, "leg-entry", &leg_entry(node));
    fail(site, "redial-leg", &redial_leg(node));
    fail(site, "index-cache", &index_cache(node));
    fail(site, "link-cache", &link_cache(node));
    fail(site, "held-cache", &held_cache(node));
    index(node, &format!("audit_live: {site}: index"));
    fail(site, "carrier", &carrier(node));
    let mirror = links_mirror(node);
    fail(site, "links-mirror", &mirror.bad);
    #[cfg(test)]
    {
        node.links.count_audit();
        reach::row(node, "audited");
        if !mirror.unmirrored.is_empty() {
            reach::row(node, "unmirrored");
        }
    }
}

/// The audit's reach over a test run: one row per test thread, node and
/// outcome, appended to the file `FIPS_AUDIT_REACH` names: `audited <thread>
/// <node>` or `planted <thread> <node>`, and beside an audited row
/// `unmirrored` where `links-mirror` skipped a peer a test changed past the
/// feed. `testing/check-audit-reach.py` counts the pairs. A test runs on a
/// thread named for it when the suite runs as threads in one process.
#[cfg(all(test, debug_assertions))]
mod reach {
    use std::collections::HashSet;
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};

    use crate::node::Node;

    /// The environment variable naming the file the rows go to.
    const VAR: &str = "FIPS_AUDIT_REACH";

    /// Append the row for `node` and `outcome` on this thread, once.
    pub(super) fn row(node: &Node, outcome: &str) {
        static FILE: OnceLock<Option<String>> = OnceLock::new();
        static SEEN: Mutex<Option<HashSet<String>>> = Mutex::new(None);
        let Some(path) = FILE.get_or_init(|| std::env::var(VAR).ok()) else {
            return;
        };
        let thread = std::thread::current();
        let row = format!(
            "{outcome} {} {}\n",
            thread.name().unwrap_or("unnamed"),
            node.node_addr()
        );
        let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
        if !seen.get_or_insert_with(HashSet::new).insert(row.clone()) {
            return;
        }
        let written = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| f.write_all(row.as_bytes()));
        if let Err(e) = written {
            panic!("{VAR}: cannot append to {path}: {e}");
        }
    }
}

/// Panic if `bad` names anything, naming the site and the clause.
#[cfg(debug_assertions)]
fn fail<T: std::fmt::Debug>(site: &str, clause: &str, bad: &[T]) {
    assert!(bad.is_empty(), "audit_live: {site}: {clause}: {bad:?}");
}
