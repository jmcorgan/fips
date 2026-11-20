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

/// `link-named`: every link is named by a peer, a handshake machine or a
/// handshake leg. The links no one names.
pub(in crate::node) fn link_named(node: &Node) -> Vec<LinkId> {
    let mut named: HashSet<LinkId> = node.peers.values().map(|p| p.link_id()).collect();
    named.extend(node.peer_machines.keys().copied());
    named.extend(node.legs.iter().filter_map(|leg| node.links.id(leg.link())));
    node.links
        .keys()
        .filter(|link| !named.contains(link))
        .copied()
        .collect()
}

/// `dial-link`: every handshake leg's link is in the link map. The core's
/// numbers of the legs that break it.
pub(in crate::node) fn dial_link(node: &Node) -> Vec<LinkNo> {
    node.legs
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
    for (link, machine) in node.peer_machines.iter() {
        if machine.leg().is_none() {
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

/// `redial-leg`: each pending redial names a leg: a registered machine on its
/// link, still at `Handshaking{ReceivedMsg1}`, whose identity is the
/// redial's peer, and the answer's leg in the settlement core's legs on that
/// link, for that peer and holding the redial's index, an index no peer is
/// bound to, on a link that is open. The identities whose entry breaks it.
pub(in crate::node) fn redial_leg(node: &Node) -> Vec<crate::NodeAddr> {
    use crate::peer::machine::{HandshakePhase, PeerState};
    let mut bad = Vec::new();
    for (peer, redial) in node.redials.iter() {
        let ok = node.peer_machines.get(&redial.link).is_some_and(|m| {
            matches!(
                m.state(),
                PeerState::Handshaking {
                    phase: HandshakePhase::ReceivedMsg1,
                    ..
                }
            ) && m.conn_expected_identity().map(|id| *id.node_addr()) == Some(*peer)
        }) && node.leg(redial.link).is_some_and(|leg| {
            matches!(leg.kind(), crate::proto::settle::legs::Kind::Answer { .. })
                && leg.peer() == Some(*peer)
                && leg.index() == redial.index.as_u32()
        }) && node.peers_by_index.get(&redial.index.as_u32()).is_none()
            && node.links.contains_key(&redial.link);
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
    let derived = node.links.derived();
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
        .peer_machines
        .values()
        .filter(|machine| machine.our_index().is_some())
        .count();
    leased += node.legs.iter().count();
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

/// `carrier`: every handshake machine has a live carrier, its own pending
/// connection, an active peer on its link, or a pending connect still
/// resolving toward it. A machine with none is unreachable by every teardown
/// path and has leaked. The links of the machines that break it.
pub(in crate::node) fn carrier(node: &Node) -> Vec<LinkId> {
    node.peer_machines
        .iter()
        .filter(|(link, machine)| {
            machine.leg().is_none()
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
            .and_then(|no| node.links.core().get(no))
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

/// `core-agrees`: what the node did since the last audit is what the shadow
/// core decided, in the words they share
/// ([`Did`](crate::node::settle::exec::Did)), order aside. Takes both
/// records, so the next audit compares what follows. The difference, if
/// any, as one line.
#[cfg(test)]
pub(in crate::node) fn core_agrees(node: &Node) -> Vec<String> {
    let logs = node.shadow.take();
    let words = |did: &[crate::node::settle::exec::Did]| {
        let mut words: Vec<String> = did.iter().map(|d| format!("{d:?}")).collect();
        words.sort();
        words
    };
    let (did, decided) = (words(&logs.node), words(&logs.core));
    if did == decided {
        return Vec::new();
    }
    vec![format!(
        "the node did {did:?}, the core decided {decided:?}"
    )]
}

/// `closes-agree`: the connections the node closed since the last audit,
/// at the close sites its decisions reach, are the ones the shadow core
/// decided to close, in its `Retire`, `Release` and `Close` outputs, each
/// pair once, order aside. A close the node asks only of the transport (a
/// connect that opened for a path no longer held, or an unproven BLE
/// channel), and the drain's second look at a queued close, are not
/// decisions the core makes. Takes both records, so the next audit compares
/// what follows. The difference, if any, as one line.
#[cfg(test)]
pub(in crate::node) fn closes_agree(node: &Node) -> Vec<String> {
    let closes = node.shadow.closes();
    let once = |mut pairs: Vec<Pair>| {
        pairs.sort();
        pairs.dedup();
        pairs
    };
    let (closed, decided) = (once(closes.node), once(closes.core));
    if closed == decided {
        return Vec::new();
    }
    vec![format!(
        "the node closed {closed:?}, the core decided {decided:?}"
    )]
}

/// `links-agree`: each link the shadow numbers has the same record in the
/// shadow as in the node's link table: setup pair, direction, holder,
/// paths (order aside) and capability; and each of the node's links has a
/// record in the shadow. A link a test planted past the node's table, in
/// its link map unrecorded, named only by a planted peer, or recorded by
/// the node from a planted index entry with no link in its map, is passed
/// over.
/// The links that break it, each with both records.
#[cfg(test)]
pub(in crate::node) fn links_agree(node: &Node) -> Vec<String> {
    let Some(table) = node.shadow.table() else {
        return Vec::new();
    };
    let mut bad = Vec::new();
    let mut ids: Vec<(&LinkId, &crate::proto::settle::links::LinkNo)> =
        node.shadow.numbered().collect();
    ids.sort_by_key(|(id, _)| id.as_u64());
    for (id, no) in ids {
        // A link a test put in the link map past its writers has no record
        // of the node's until the node's own resync adopts it: there is
        // nothing of the node's to compare yet.
        if node.links.contains_key(id) && node.links.no(id).is_none() {
            continue;
        }
        // Nor has a link a test's planted peer names that is not in the
        // link map at all: the shadow holds the peer on a record of its
        // own, which no record of the node's can match. Nor one the node
        // records with no link in its map, which only the node's resync of
        // an index entry a test planted builds: its record keeps the
        // plant's holder whatever the decisions do, since no removal
        // reaches a link the map lacks.
        if !node.links.contains_key(id)
            && (node.links.no(id).is_some() || node.peers.values().any(|p| p.link_id() == *id))
        {
            continue;
        }
        // Nor has the link of a peer a test changed past the feed: the
        // shadow takes the change at its resync and the node's records only
        // at the node's, so until then the link is not read, as
        // `links-mirror` does not read the peer.
        if node
            .peers
            .values()
            .any(|p| p.link_id() == *id && p.past_feed())
        {
            continue;
        }
        let mine = node.links.no(id).and_then(|n| node.links.core().get(n));
        let theirs = table.links().get(*no);
        let shape = |r: &crate::proto::settle::links::LinkRec| {
            (
                r.setup.clone(),
                r.dir,
                r.holder,
                sorted(r.paths.clone()),
                r.capable,
            )
        };
        if mine.map(shape) != theirs.map(shape) {
            bad.push(format!(
                "link {id}: the node's record {:?}, the core's {:?}",
                mine.map(shape),
                theirs.map(shape)
            ));
        }
    }
    let mut unknown: Vec<&LinkId> = node
        .links
        .keys()
        .filter(|id| node.links.no(id).is_some() && node.shadow.no(**id).is_none())
        .collect();
    unknown.sort_by_key(|id| id.as_u64());
    for id in unknown {
        bad.push(format!("link {id}: the core has no record"));
    }
    bad
}

/// `gates-agree`: for each identity either remembers, the shadow core's
/// restart gates and the node's agree on whether a restart or replacement
/// stamped the dampener within the interval, how many ephemerals the replay
/// memory holds, and how many silent sessions are counted. The identities
/// that break it, each with both.
#[cfg(test)]
pub(in crate::node) fn gates_agree(node: &Node) -> Vec<String> {
    let Some(table) = node.shadow.table() else {
        return Vec::new();
    };
    let theirs = table.gates();
    let mine = &node.gates;
    let interval = crate::proto::settle::params::Params::default().interval;
    let now = crate::peer::peer_now();
    let mut peers: Vec<NodeAddr> = theirs.known().copied().collect();
    peers.extend(mine.known().copied());
    peers.sort();
    peers.dedup();
    let read = |gates: &crate::proto::settle::gates::Gates<crate::peer::PeerInstant>,
                peer: &NodeAddr| {
        (
            gates.stamp(peer).is_some_and(|t| {
                fips_core::time::Instant::saturating_duration_since(now, t) < interval
            }),
            gates.replays(peer),
            gates.silent(peer),
        )
    };
    let mut bad = Vec::new();
    for peer in peers {
        let (mine, theirs) = (read(mine, &peer), read(theirs, &peer));
        if mine != theirs {
            bad.push(format!(
                "{peer}: the node's (stamped, replays, silent) {mine:?}, the core's {theirs:?}"
            ));
        }
    }
    bad
}

/// How far apart the node's and the shadow core's instants for one leg may
/// read and still agree. The node stamps a leg's deadline and resends on its
/// interval clock, in whole milliseconds, at its site. The core opens a
/// dial's or an answer's leg at that same instant
/// ([`Node::decide_stamped`](crate::node::Node::decide_stamped)), and
/// stamps any other instant of a leg on the peer clock when the site's
/// input reaches it, a little later in the same call path; with the clock
/// frozen the two read the same.
/// A quarter of the shortest resend interval any test configures (the
/// default 1 s; no test lowers it), so a resend or reap scheduled a step
/// apart is still a difference.
#[cfg(test)]
pub(super) const LEG_SKEW_MS: u64 = 250;

/// Whether two millisecond readings, either absent, agree within
/// [`LEG_SKEW_MS`].
#[cfg(test)]
fn near(a: Option<u64>, b: Option<u64>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.abs_diff(b) <= LEG_SKEW_MS,
        (a, b) => a.is_none() && b.is_none(),
    }
}

/// What the node's machine holds of the handshake `m` carries, on the
/// interval clock's milliseconds, for a handshake whose leg is not in the
/// node's legs (an answer, or a handshake a test seeded on a machine): when
/// its reaper finds it idle past the handshake timeout of `timeout` ms
/// (`conn_is_timed_out`), and whether resends may follow under a cap of
/// `max`. Such a handshake resends nothing. `legs-agree` holds the shadow
/// core's leg to these, and the shadow takes them for a handshake a test
/// planted past the node's writers.
#[cfg(test)]
pub(in crate::node) fn leg_times(
    max: u32,
    timeout: u64,
    m: &crate::peer::machine::PeerMachine,
) -> (u64, bool) {
    let more = m.conn_is_outbound() && 0 < m.dial_origin().resend_limit(max);
    (m.conn_active_at().saturating_add(timeout), more)
}

/// What the node holds of the handshake on its link `id`, if it carries
/// one: whether it is a dial, for which identity, how many resends it has
/// sent and whether more may follow, and, on the interval clock's
/// milliseconds, its deadline, whether a resend is due at `now`, and when
/// the next is. A handshake's leg in the node's legs gives these; one a
/// machine carries with no leg there gives its machine's ([`leg_times`]).
#[cfg(test)]
#[allow(clippy::type_complexity)]
fn node_leg(
    node: &Node,
    max: u32,
    timeout: u64,
    id: LinkId,
    now: crate::peer::PeerInstant,
) -> Option<(
    (bool, Option<crate::NodeAddr>, u32, bool),
    (Option<u64>, bool, Option<u64>),
    Option<u64>,
)> {
    if let Some(leg) = node.leg(id) {
        let due = leg.resend_due(now);
        let next = leg.next_resend().map(crate::time::mono_ms_at);
        return Some((
            (
                matches!(leg.kind(), crate::proto::settle::legs::Kind::Dial),
                leg.peer(),
                leg.sent(),
                leg.sent() < leg.resends(),
            ),
            (
                Some(crate::time::mono_ms_at(leg.deadline())),
                due,
                next.filter(|_| !due),
            ),
            next,
        ));
    }
    let m = node.peer_machines.get(&id).filter(|m| m.leg().is_some())?;
    let (deadline, more) = leg_times(max, timeout, m);
    Some((
        (
            m.conn_is_outbound(),
            m.conn_expected_identity().map(|i| *i.node_addr()),
            0,
            more,
        ),
        (Some(deadline), false, None),
        None,
    ))
}

/// `legs-agree`: each handshake leg the shadow core holds is a handshake
/// the node carries on the same link, of the same end, for the same
/// identity, with the same count of resends sent, the same answer to
/// whether more may follow, the same deadline, the same answer to whether a
/// resend is due at the next tick, and, when none is due, the same time for
/// the next (a resend due on one side only agrees while its two times are
/// within the skew, the instant compared at falling between them); and
/// each handshake the node carries has a leg in the shadow. The node's
/// handshake is its leg in the node's legs, or one a machine carries with
/// no leg there ([`node_leg`]). Instants are compared on the interval
/// clock's milliseconds, within [`LEG_SKEW_MS`], and as of the instant the
/// shadow decides at ([`Shadow::now`](super::decide::Shadow::now)), which
/// is the one a test drove the node's timers at while they run. The legs
/// that break it, each with both.
#[cfg(test)]
pub(in crate::node) fn legs_agree(node: &Node) -> Vec<String> {
    let Some(table) = node.shadow.table() else {
        return Vec::new();
    };
    let rate = &node.config().node.rate_limit;
    let (max, timeout) = (
        rate.handshake_max_resends,
        rate.handshake_timeout_secs * 1000,
    );
    let now = node.shadow.now();
    let mut bad = Vec::new();
    let mut seen = HashSet::new();
    for leg in table.legs().iter() {
        let Some(id) = node.shadow.id(leg.link()) else {
            bad.push(format!("leg {:?}: no link of the node's", leg.link()));
            continue;
        };
        seen.insert(id);
        let due = leg.resend_due(now);
        let their_next = leg.next_resend().map(crate::time::mono_ms_at);
        let theirs = (
            matches!(leg.kind(), crate::proto::settle::legs::Kind::Dial),
            leg.peer(),
            leg.sent(),
            leg.sent() < leg.resends(),
        );
        let their_times = (
            Some(crate::time::mono_ms_at(leg.deadline())),
            due,
            leg.next_resend()
                .filter(|_| !due)
                .map(crate::time::mono_ms_at),
        );
        let mine = node_leg(node, max, timeout, id, now);
        // A resend due on one side only, at an instant between the two
        // sides' times for it, agrees while those times are within the
        // skew: each side stamped its own at its site, a little apart.
        let agree = mine.is_some_and(|(what, (deadline, due, next), timer)| {
            let times = if due == their_times.1 {
                near(next, their_times.2)
            } else {
                near(timer, their_next)
            };
            what == theirs && near(deadline, their_times.0) && times
        });
        if !agree {
            let mine = mine.map(|(what, times, _)| (what, times));
            bad.push(format!(
                "link {id}: the node's ((dial, peer, sent, more), (deadline, due, next)) \
                 {mine:?}, the core's ({theirs:?}, {their_times:?})"
            ));
        }
    }
    let mut carried: Vec<LinkId> = node
        .peer_machines
        .iter()
        .filter(|(_, m)| m.leg().is_some())
        .map(|(id, _)| *id)
        .chain(node.legs.iter().filter_map(|leg| node.links.id(leg.link())))
        .filter(|id| !seen.contains(id))
        .collect();
    carried.sort_by_key(|id| id.as_u64());
    carried.dedup();
    for id in carried {
        bad.push(format!("link {id}: the core holds no leg"));
    }
    bad
}

/// The node's answer to a question it asks of a msg1's source before any
/// Diffie-Hellman by its own reading, not the core's records', which
/// [`placement_agrees`] compares with the answer of the core's link records.
/// The others (`is_established_link_msg1`, `msg1_waiver` and
/// `link_arrival`) are the records' answers ([`Node::placement`]).
#[cfg(test)]
#[derive(Debug)]
pub(in crate::node) enum Asked {
    /// The link of an unanswered inbound leg a msg1 from the pair is a
    /// resend to: the duplicate check's read of the index.
    Unanswered(Option<LinkId>),
}

/// `placement-agrees`: the node's answer `asked` to a question of a packet
/// from `key` is the one `Links::placement` gives over the node's own link
/// records (`Placement::unanswered`). Compared at the question, since what
/// the node asks it of moves before the next audit. The difference, if
/// any, as one line.
#[cfg(test)]
pub(in crate::node) fn placement_agrees(node: &Node, key: &AddrKey, asked: &Asked) -> Vec<String> {
    let place = node.placement(key);
    let agrees = match asked {
        Asked::Unanswered(link) => place.unanswered().and_then(|no| node.links.id(no)) == *link,
    };
    if agrees {
        return Vec::new();
    }
    vec![format!(
        "from {key:?} the node answered {asked:?}, the core's records {place:?}"
    )]
}

/// Compare the node's answer `asked` to a question of a packet from `key`,
/// which `site` just gave, with the core's link records'
/// ([`placement_agrees`]), and report a first difference as the shadow's
/// clauses do.
#[cfg(all(test, debug_assertions))]
pub(in crate::node) fn placed(node: &Node, site: &str, key: &AddrKey, asked: Asked) {
    if node.shadow.diverged() {
        return;
    }
    let bad = placement_agrees(node, key, &asked);
    if !bad.is_empty() {
        first(node, site, "placement-agrees", &bad);
    }
}

/// Run the shadow core's clauses on `node`, which has just left the node
/// entry `site`: `core-agrees` and `closes-agree`, then `links-agree`,
/// `gates-agree` and `legs-agree`. Each audit takes what was recorded since
/// the last, so `core-agrees` and `closes-agree` run even on a node already
/// diverged. Until a node's first
/// difference, the first clause to find one gives the test's one line,
/// written to the file `FIPS_CORE_SHADOW` names, if any, with the test's
/// thread, the node, the site and the clause; the node is marked diverged,
/// with a reach row `diverged`, and nothing more of it is compared. A first
/// difference [`SHADOW_KNOWN`] does not list fails the test when the node
/// is dropped ([`Shadow::fail`](super::decide::Shadow::fail)), unless the
/// test has failed already or a switch that breaks the node and not the
/// core is on, other than one the comparison is to catch
/// ([`node_broken`](super::decide::node_broken)).
#[cfg(all(test, debug_assertions))]
fn shadow(node: &Node, site: &str) {
    /// A clause of the shadow's: what breaks it on a node.
    type Clause = fn(&Node) -> Vec<String>;
    let agrees = core_agrees(node);
    let closes = closes_agree(node);
    if node.shadow.diverged() {
        return;
    }
    let clauses: [(&str, Clause); 3] = [
        ("links-agree", links_agree),
        ("gates-agree", gates_agree),
        ("legs-agree", legs_agree),
    ];
    let found = std::iter::once(("core-agrees", agrees))
        .chain(std::iter::once(("closes-agree", closes)))
        .chain(clauses.iter().map(|(name, clause)| (*name, clause(node))))
        .find(|(_, bad)| !bad.is_empty());
    let Some((clause, bad)) = found else {
        return;
    };
    first(node, site, clause, &bad);
}

/// Report `bad`, the first difference of the shadow core from the node,
/// which the clause `clause` found at `site`: one line to the file
/// `FIPS_CORE_SHADOW` names, a reach row `diverged`, the node compared no
/// further, and, unless `shadow.txt` lists it or a switch that breaks the
/// node alone is on, the test failed when the node is dropped.
#[cfg(all(test, debug_assertions))]
fn first(node: &Node, site: &str, clause: &str, bad: &[String]) {
    node.shadow.diverge();
    reach::row(node, "diverged");
    let thread = std::thread::current();
    let test = thread.name().unwrap_or("unnamed");
    crate::node::settle::decide::line(&format!(
        "{test} {} {site}: {clause}: {}",
        node.node_addr(),
        bad.join("; ")
    ));
    if !known(SHADOW_KNOWN, test, site, clause) && !crate::node::settle::decide::node_broken() {
        node.shadow.fail(format!(
            "audit_live: {site}: {clause}: the shadow core decided otherwise than the node, \
             and shadow.txt does not list it: {}",
            bad.join("; ")
        ));
    }
}

/// The first differences of the shadow core from the node that are known,
/// one per line, `<test>\t<site>\t<clause>`, after the reach gaps its
/// header records: `src/node/settle/tests/shadow.txt`.
#[cfg(all(test, debug_assertions))]
pub(in crate::node) const SHADOW_KNOWN: &str = include_str!("tests/shadow.txt");

/// Whether `list`, in the form of [`SHADOW_KNOWN`], names the first
/// difference a node in the test `test` found at the entry `site` by the
/// clause `clause`. Blank lines and lines starting `#` name nothing.
#[cfg(all(test, debug_assertions))]
pub(in crate::node) fn known(list: &str, test: &str, site: &str, clause: &str) -> bool {
    list.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .any(|l| l.split('\t').eq([test, site, clause]))
}

/// Run every clause on `node`, which has just left the node entry `site`,
/// and panic, naming the site and the clause, on the first that fails.
///
/// In a test, the node's own clauses skip a node written past its writers,
/// since its state is one no production path builds, and each audit is
/// counted on the node and, when `FIPS_AUDIT_REACH` names a file, recorded
/// there. The shadow core's clauses, after `index-cache`, run on every
/// node, a planted one included, and fail the test at its node's drop on
/// a first difference `shadow.txt` does not list ([`shadow`]).
#[cfg(debug_assertions)]
pub(in crate::node) fn live(node: &Node, site: &str) {
    #[cfg(test)]
    if node.planted() {
        reach::row(node, "planted");
        shadow(node, site);
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
    #[cfg(test)]
    shadow(node, site);
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
/// feed.
/// A node the shadow core's comparison found a first difference on gets a
/// `diverged` row. `testing/check-audit-reach.py` counts the pairs. A test runs on a thread named for it when the suite
/// runs as threads in one process.
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
