//! The transition table checked on real nodes: what a site does to every row
//! of a peer's state, read whole before and after, against what
//! `node::settle::table::cell` says it does.
//!
//! This file is the harness the column files share. [`Seen::of`] reads every
//! [`Row`] of one peer on one node through the existing accessors and maps;
//! [`dirty`] makes every row it can reach differ from a fresh peering's;
//! [`assert_cells`] holds each row of a before and an after reading against
//! the row's cell at the transition the test ran, and fails, at a message
//! starting `defect:`, on a row the site changed that its cell keeps or kept
//! that its cell changes. `check_decided` holds the rows the same way with
//! each row's outcome decided by its caller, for a test whose own script
//! does not state it; next builds it only with the real-node explorer, which
//! it does not build. `src/node/tests/settle/table/README.md` says what a
//! test here must do.
//!
//! A reading leaves out what any authenticated frame moves, since a frame is
//! not a transition: `last_seen`, the link and per-path statistics, the
//! instant last heard, and every MMP counter but the highest seen, which
//! [`dirty`] puts out of a frame's reach.

mod crossing;
mod paths;
mod promote;
mod rekey;
mod remove;
mod replace;

use super::super::spanning_tree::{TestNode, cleanup_nodes, drain_all_packets, initiate_handshake};
use super::super::*;
use super::{heartbeat_reaches, loopback_node};
use crate::node::handlers::path_intake::Feed;
use crate::node::settle::table::{Cell, DataCell, DataRow, Row, Transition, cell};
use crate::peer::ActivePeer;
use crate::proto::rekey::Role;
use crate::proto::settle::output::Why;
use crate::transport::{LinkDirection, TransportAddr, TransportHandle, TransportId};
use fips_core::proto::path::PathRef;

/// One row as read: `None` where the row is not read on this node, which is
/// the BLE mark off a BLE transport or where no link is pooled, and the
/// connected socket off the platforms that have one.
pub(super) type Reading = Option<String>;

/// Every row of one peer's state on one node, read at one instant.
pub(super) struct Seen {
    rows: Vec<(Row, Reading)>,
    /// The peer's running total of refused replays, held so that a total
    /// allocated after this reading cannot take its address and read as the
    /// same one.
    #[cfg(unix)]
    #[allow(dead_code)] // held, never read
    total: Option<std::sync::Arc<portable_atomic::AtomicU64>>,
}

impl Seen {
    /// Read every row of `peer`'s state on `node`. The pairs read per
    /// address are the peer's paths and `also`, which names the pairs a
    /// transition may leave, since a pair that a move, a roam or a removal
    /// leaves is on no path afterwards.
    pub(super) async fn of(node: &Node, peer: &NodeAddr, also: &[PathRef]) -> Seen {
        let held = node.get_peer(peer);
        let pairs = pairs(held, also);
        let mut rows = Vec::new();
        for row in Row::all() {
            let reading = match row {
                Row::BleMark => ble_mark(node, &pairs).await,
                _ => read(node, peer, held, &pairs, row),
            };
            rows.push((row, reading));
        }
        Seen {
            rows,
            #[cfg(unix)]
            total: held.map(ActivePeer::replay_total),
        }
    }

    /// The reading of `row`.
    pub(super) fn get(&self, row: Row) -> &Reading {
        &self
            .rows
            .iter()
            .find(|(r, _)| *r == row)
            .expect("precondition: every row is read")
            .1
    }

    /// The rows whose reading differs between `self` and `other`, a row not
    /// read on both sides apart.
    pub(super) fn differing(&self, other: &Seen) -> Vec<Row> {
        self.rows
            .iter()
            .filter(|(row, reading)| {
                let theirs = other.get(*row);
                !(reading.is_none() && theirs.is_none()) && reading != theirs
            })
            .map(|(row, _)| *row)
            .collect()
    }
}

/// What a cell says a row's reading does across its transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Expect {
    /// The reading stays as it was.
    Kept,
    /// The reading changes from a record [`dirty`] wrote, or from a peer not
    /// yet held.
    Changed,
    /// Whether it changes turns on a condition the test's own script decides,
    /// such as whether the pair moved or the peering was heard; the test
    /// states the outcome in `others`.
    Stated,
    /// No site reaches the transition's cause.
    NoSite,
}

/// The outcome of a cell the test states, for a [`Expect::Stated`] row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// The reading stays.
    Kept,
    /// The reading changes.
    Changed,
}

/// What `cell` says of a row's reading. Only a cell whose effect on the
/// reading does not turn on the test's script is [`Expect::Kept`] or
/// [`Expect::Changed`]; every other cell is [`Expect::Stated`].
pub(super) fn expect(cell: Cell) -> Expect {
    match cell {
        Cell::NoSite => Expect::NoSite,
        Cell::Data(DataCell::Keep)
        | Cell::Keep
        | Cell::NotApplicable
        | Cell::NotRun
        | Cell::NotReseeded
        | Cell::NotStamped => Expect::Kept,
        Cell::Data(
            DataCell::Reset
            | DataCell::Roll
            | DataCell::Base
            | DataCell::Clear
            | DataCell::New
            | DataCell::Drop,
        )
        | Cell::Empty
        | Cell::Zero
        | Cell::Gone
        | Cell::Dropped
        | Cell::Closed
        | Cell::Removed
        | Cell::Cleared => Expect::Changed,
        Cell::New
        | Cell::HandshakeLink
        | Cell::OldClosedNewAdopted
        | Cell::DialClosed
        | Cell::FromDial
        | Cell::FromLeg
        | Cell::OldDroppedFromDial
        | Cell::OldDroppedFromLeg
        | Cell::ReleasedUnclaimedDialDropped
        | Cell::ReleasedUnclaimedLegDropped
        | Cell::DialDropped
        | Cell::LegDropped
        | Cell::Followed
        | Cell::Claimed
        | Cell::UnclaimedOffRecord
        | Cell::NewAtSource
        | Cell::OldClosedNew
        | Cell::Renewed
        | Cell::OnePathReaddressed
        | Cell::PathReaddressed
        | Cell::ActiveChanged
        | Cell::PathGone
        | Cell::ResetByRenew
        | Cell::HeldBackOrForgotten
        | Cell::PinEnds
        | Cell::HoldStarts
        | Cell::KeptIfHeld
        | Cell::GoneWithPath
        | Cell::ReleasedClearedActiveIfChanged
        | Cell::ClearedIfChanged
        | Cell::MovedCleared
        | Cell::OldActiveCleared
        | Cell::PathCleared
        | Cell::NewEmptyRecord
        | Cell::OldClosedNewEmptyRecord
        | Cell::ClosedRebuilt
        | Cell::LeaseReleased
        | Cell::DialLeaseFreed
        | Cell::LegLeaseFreed
        | Cell::Stepped
        | Cell::KeptBindingsFollow
        | Cell::Carried
        | Cell::LegSurvives
        | Cell::OldRemovedLegSurvives
        | Cell::DialRemovedPeerStepped
        | Cell::LegRemoved
        | Cell::SteppedThenRemoved
        | Cell::UnkeptQueued
        | Cell::UnkeptQueuedCurrentClosed
        | Cell::DialClosedUnlessProven
        | Cell::DialClosedReleasedQueued
        | Cell::ReleasedQueued
        | Cell::QueuedDrained
        | Cell::Marked
        | Cell::MarkedAtFirstFrame
        | Cell::OldClearedMarked
        | Cell::OldClearedMarkedAtFirstFrame
        | Cell::Relinked
        | Cell::ClearedIfDrained
        | Cell::Checked
        | Cell::AnsweredRemoved
        | Cell::Seeded
        | Cell::ReleasedThenSeeded
        | Cell::ReseededIfMoved
        | Cell::ReleasedReseeded
        | Cell::ReseededTightened
        | Cell::Released
        | Cell::RemovedOthersMarkedThenMarked
        | Cell::RemovedOthersMarked
        | Cell::ForgottenAllMarked
        | Cell::Announced
        | Cell::CleanedOthersPendingAnnounced
        | Cell::CleanedOthersPending
        | Cell::Stamped
        | Cell::NotedIfNoFrame
        | Cell::NotedDead
        | Cell::NotedDeadThenRemoved
        | Cell::Registered
        | Cell::BackoffReset
        | Cell::Forgotten
        | Cell::Queued
        | Cell::QueuedDrainedIfMoved
        | Cell::ForgottenOffered
        | Cell::GoneAtDiscovery
        | Cell::GoneAtNextRead => Expect::Stated,
    }
}

/// What [`check_cells`] found.
#[derive(Debug, Default)]
pub(super) struct Checked {
    /// Each row whose reading did not do what its cell says, as a line
    /// naming the row, the cell, and the two readings.
    pub(super) breaches: Vec<String>,
    /// The rows read on neither side, which are not checked and are never
    /// counted as kept.
    pub(super) unread: Vec<Row>,
}

/// Hold every row of `before` and `after` against its cell at `t`. A row
/// whose cell is [`Expect::Stated`] takes its outcome from `others`, which
/// must name it; `others` may name no other row. A row read on neither side
/// is reported unread. Panics, at `precondition:`, on a cause no site
/// reaches or on `others` that does not match the table.
pub(super) fn check_cells(
    before: &Seen,
    after: &Seen,
    t: &Transition,
    others: &[(Row, Outcome)],
) -> Checked {
    let mut checked = Checked::default();
    for row in Row::all() {
        let c = cell(row, t);
        let stated = others.iter().find(|(r, _)| *r == row).map(|(_, o)| *o);
        let want = match (expect(c), stated) {
            (Expect::NoSite, _) => {
                panic!("precondition: no site reaches {t:?}, so it has no cell at {row:?}")
            }
            (Expect::Stated, None) => panic!(
                "precondition: {row:?} at {t:?} is {c:?}, which turns on the test's script; the test states it"
            ),
            (Expect::Kept | Expect::Changed, Some(_)) => panic!(
                "precondition: {row:?} at {t:?} is {c:?}, which the table decides; the test may not state it"
            ),
            (Expect::Stated, Some(Outcome::Kept)) | (Expect::Kept, None) => Outcome::Kept,
            (Expect::Stated, Some(Outcome::Changed)) | (Expect::Changed, None) => Outcome::Changed,
        };
        let (b, a) = (before.get(row), after.get(row));
        if b.is_none() && a.is_none() {
            checked.unread.push(row);
            continue;
        }
        let got = if b == a {
            Outcome::Kept
        } else {
            Outcome::Changed
        };
        if got != want {
            checked.breaches.push(format!(
                "{row:?} at {t:?} is {c:?}, so {want:?}, but {got:?}: before {b:?}, after {a:?}"
            ));
        }
    }
    checked
}

/// [`check_cells`], failing the test at a `defect:` message on any breach.
pub(super) fn assert_cells(
    before: &Seen,
    after: &Seen,
    t: &Transition,
    others: &[(Row, Outcome)],
) -> Checked {
    let checked = check_cells(before, after, t, others);
    assert!(
        checked.breaches.is_empty(),
        "defect: the site does not do what the table says: {:#?}",
        checked.breaches
    );
    checked
}

/// What [`check_decided`] found.
// Built only with the real-node explorer, its one caller, which next does
// not build (`../mod.rs`).
#[cfg(any())]
#[derive(Debug, Default)]
pub(super) struct Decided {
    /// Each row whose reading did not do what its decided outcome says, as
    /// [`Checked`] names one.
    pub(super) breaches: Vec<String>,
    /// How many rows were held to an outcome.
    pub(super) held: usize,
    /// The rows the decision gave no outcome, which are not checked.
    pub(super) undecided: Vec<Row>,
}

/// Hold every row of `before` and `after` against its cell at `t`, as
/// [`check_cells`] does, but with each row's outcome given by `decide` from
/// the row, its cell and what the cell says of it, in place of a test's own
/// statement. So a [`Expect::Stated`] row takes its outcome from whatever
/// `decide` reads, a reference model among them. A row `decide` gives no
/// outcome, or read on neither side, is not checked.
// Built only with the real-node explorer, as `Decided` is.
#[cfg(any())]
pub(super) fn check_decided(
    before: &Seen,
    after: &Seen,
    t: &Transition,
    decide: impl Fn(Row, Cell, Expect) -> Option<Outcome>,
) -> Decided {
    let mut decided = Decided::default();
    for row in Row::all() {
        let c = cell(row, t);
        let (b, a) = (before.get(row), after.get(row));
        let Some(want) = decide(row, c, expect(c)).filter(|_| b.is_some() || a.is_some()) else {
            decided.undecided.push(row);
            continue;
        };
        decided.held += 1;
        let got = if b == a {
            Outcome::Kept
        } else {
            Outcome::Changed
        };
        if got != want {
            decided.breaches.push(format!(
                "{row:?} at {t:?} is {c:?}, so {want:?}, but {got:?}: before {b:?}, after {a:?}"
            ));
        }
    }
    decided
}

/// The pairs a reading covers: the peer's paths and `also`, each once, in
/// the order of their names, so that a path re-addressed from one pair to
/// another reads the pairs in the same order before and after.
fn pairs(held: Option<&ActivePeer>, also: &[PathRef]) -> Vec<PathRef> {
    let mut pairs: Vec<PathRef> = held
        .and_then(ActivePeer::bundle)
        .map(|b| {
            b.paths()
                .paths()
                .iter()
                .map(|p| PathRef {
                    transport: p.transport_id(),
                    addr: p.addr().clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    for to in also {
        if !pairs.contains(to) {
            pairs.push(to.clone());
        }
    }
    pairs.sort_by_key(named);
    pairs
}

/// A pair as a reading names it.
fn named(to: &PathRef) -> String {
    format!("{}/{}", to.transport.as_u32(), to.addr)
}

/// Every feed of the path intake's listings.
fn feeds() -> [Feed; 5] {
    // Fails to compile when a feed is added, so that the list grows with it.
    match Feed::Beacon {
        Feed::Beacon | Feed::Config | Feed::Nostr | Feed::Mdns | Feed::Heard => {}
    }
    [
        Feed::Beacon,
        Feed::Config,
        Feed::Nostr,
        Feed::Mdns,
        Feed::Heard,
    ]
}

/// The links no held peer names: a dial's, a handshake's, or one a removal
/// left behind.
fn orphans(node: &Node) -> Vec<LinkId> {
    let mut ids: Vec<LinkId> = node
        .links
        .keys()
        .filter(|id| !node.peers.values().any(|p| p.link_id() == **id))
        .copied()
        .collect();
    ids.sort_by_key(|id| id.as_u64());
    ids
}

/// The links a reading of `peer` covers: its own, if held, and the orphans.
fn covered(node: &Node, held: Option<&ActivePeer>) -> Vec<LinkId> {
    let mut ids: Vec<LinkId> = held.map(ActivePeer::link_id).into_iter().collect();
    ids.extend(orphans(node));
    ids
}

/// Read one row other than the BLE mark.
fn read(
    node: &Node,
    peer: &NodeAddr,
    held: Option<&ActivePeer>,
    pairs: &[PathRef],
    row: Row,
) -> Reading {
    let bundle = held.and_then(ActivePeer::bundle);
    Some(match row {
        Row::Data(data) => match held {
            Some(p) => record(p, data),
            None => "no peer".to_string(),
        },
        Row::Link => {
            let own = held.map(|p| {
                let id = p.link_id();
                let link = node.links.get(&id).map(|l| {
                    (
                        l.transport_id().as_u32(),
                        l.remote_addr().to_string(),
                        l.direction(),
                        l.state(),
                    )
                });
                (id, link)
            });
            format!("{own:?}; links no peer names {:?}", orphans(node))
        }
        Row::Index => {
            let ids = covered(node, held);
            let mut entries: Vec<String> = node
                .links
                .index()
                .iter()
                .filter(|(_, id)| ids.contains(id))
                .map(|(key, id)| format!("{}/{} -> {id:?}", key.0.as_u32(), key.1))
                .collect();
            entries.sort();
            format!("{entries:?}")
        }
        Row::Paths => format!(
            "{:?}",
            bundle.map(|b| {
                let set = b.paths();
                let paths: Vec<_> = set
                    .paths()
                    .iter()
                    .map(|p| {
                        let to = PathRef {
                            transport: p.transport_id(),
                            addr: p.addr().clone(),
                        };
                        (named(&to), p.path_id(), p.state(), p.acked())
                    })
                    .collect();
                (paths, set.active_index())
            })
        ),
        Row::Capability => format!(
            "{:?}",
            bundle.map(|b| (b.capable(), *b.capability(), b.candidates().clone()))
        ),
        Row::Pin => format!("{:?}", bundle.map(|b| (b.pin().cloned(), b.holding()))),
        // By the path's own identifier, which a roam or a moved path keeps
        // as its pair changes.
        Row::PathFailures => format!(
            "{:?}",
            bundle.map(|b| {
                b.paths()
                    .paths()
                    .iter()
                    .map(|p| (p.path_id(), p.live().fails()))
                    .collect::<Vec<_>>()
            })
        ),
        Row::ConnectedUdp => return sockets(held),
        Row::RekeyMachine => {
            let indices = held.map(|p| {
                (
                    p.our_index(),
                    p.their_index(),
                    p.pending_our_index(),
                    p.previous_our_index(),
                    p.remote_epoch(),
                )
            });
            let mut bound: Vec<u32> = node
                .peers_by_index
                .iter()
                .filter(|(_, addr)| *addr == peer)
                .map(|(index, _)| *index)
                .collect();
            bound.sort_unstable();
            format!("{indices:?}; bound {bound:?}")
        }
        Row::SetupRecord => format!(
            "{:?}",
            held.and_then(ActivePeer::link_anchors)
                .map(|a| a.record.len())
        ),
        Row::Identity => format!(
            "{:?}",
            held.map(|p| (*p.node_addr(), p.npub_str().to_string()))
        ),
        Row::ControlMachine => {
            let machines: Vec<_> = covered(node, held)
                .into_iter()
                .filter(|id| node.peer_machines.contains_key(id))
                .map(|id| {
                    let mut timers: Vec<String> = node
                        .peer_machines
                        .timers()
                        .get(&id)
                        .map(|t| t.iter().map(|(k, at)| format!("{k:?}@{at}")).collect())
                        .unwrap_or_default();
                    timers.sort();
                    (id, timers)
                })
                .collect();
            format!("{machines:?}")
        }
        Row::Connection => {
            let seen: Vec<String> = pairs
                .iter()
                .map(|to| {
                    let state = match node.transports.get(&to.transport) {
                        Some(TransportHandle::Loopback(t)) => format!(
                            "closes asked {}",
                            t.closed().iter().filter(|a| **a == to.addr).count()
                        ),
                        Some(TransportHandle::Tcp(t)) => {
                            let s = t.stats().snapshot();
                            format!("pool {} in, {} out", s.pool_inbound, s.pool_outbound)
                        }
                        #[cfg(ble_available)]
                        Some(TransportHandle::Ble(t)) => {
                            format!("{:?}", t.connection_state_sync(&to.addr))
                        }
                        Some(_) => "not read on this transport".to_string(),
                        None => "no transport".to_string(),
                    };
                    format!("{}: {state}", named(to))
                })
                .collect();
            format!("{seen:?}")
        }
        Row::BleMark => unreachable!("the BLE mark is read by `ble_mark`"),
        Row::Bootstrap => {
            let mut transports: Vec<TransportId> = pairs.iter().map(|to| to.transport).collect();
            transports.sort_by_key(TransportId::as_u32);
            transports.dedup();
            let seen: Vec<_> = transports
                .into_iter()
                .map(|t| {
                    (
                        t.as_u32(),
                        node.supervisor.nostr_rendezvous.is_bootstrap_transport(&t),
                        node.transports.contains_key(&t),
                    )
                })
                .collect();
            format!("{seen:?}")
        }
        Row::Dials => {
            let mut dials: Vec<String> = node
                .pending_outbound
                .iter()
                .map(|((t, index), id)| format!("{}/{index} -> {id:?}", t.as_u32()))
                .collect();
            dials.sort();
            format!("{dials:?}")
        }
        Row::PathMtu => {
            let addr = crate::Ipv6Address::from_node_addr(peer);
            format!(
                "{:?}; seeded by {:?}",
                node.path_mtu_lookup.get(&addr),
                node.path_mtu_seeded_by.get(&addr).map(TransportId::as_u32)
            )
        }
        Row::FilterSend => {
            let bloom = &node.bloom_state;
            format!(
                "{:?}",
                (
                    bloom.needs_update(peer),
                    bloom.last_update_sent(peer),
                    bloom.sent_history(peer).count(),
                    bloom.outstanding_counter(peer),
                )
            )
        }
        Row::Tree => {
            let tree = &node.tree_state;
            format!(
                "{:?}",
                (
                    tree.peer_declaration(peer),
                    tree.peer_coords(peer),
                    tree.outstanding_seq(peer),
                    tree.outstanding_counter(peer),
                )
            )
        }
        Row::Session => format!(
            "{:?}",
            node.sessions.get(peer).map(|e| (
                e.is_established(),
                e.is_initiating(),
                e.is_initiator()
            ))
        ),
        Row::Dampener => format!("{:?}", node.restart_dampener.get(peer)),
        Row::Silent => format!("{:?}", node.silent_sessions.count(peer)),
        Row::Reconnect => format!(
            "{:?}",
            node.peering.reconciler.retry_pending.get(peer).map(|r| (
                r.retry_count,
                r.reconnect,
                r.retry_after,
                r.expires_at
            ))
        ),
        Row::IdentityCache => {
            let mut entries: Vec<_> = node
                .identity_cache
                .iter()
                .filter(|(_, e)| e.0 == *peer)
                .map(|(_, e)| e.2)
                .collect();
            entries.sort_unstable();
            format!("{entries:?}")
        }
        Row::LookupBackoff => format!(
            "{:?}",
            (
                node.lookup.backoff.failure_count(peer),
                node.lookup
                    .backoff
                    .entries
                    .get(peer)
                    .map(|e| e.suppress_until_ms),
            )
        ),
        Row::PathConnects => {
            let connects: Vec<String> = node.paths.connects(peer).iter().map(named).collect();
            format!("{connects:?}")
        }
        Row::PathCloses => {
            let closes: Vec<String> = node
                .paths
                .closes(peer)
                .iter()
                .map(|(to, removed)| format!("{} removed {removed}", named(to)))
                .collect();
            format!("{closes:?}")
        }
        Row::PathListings => {
            let listed: Vec<Vec<String>> = feeds()
                .into_iter()
                .map(|feed| {
                    node.paths
                        .listings
                        .listed(peer, feed)
                        .into_iter()
                        .map(|(transport, addr)| named(&PathRef { transport, addr }))
                        .collect()
                })
                .collect();
            format!("{listed:?}")
        }
        Row::PathCarrier => {
            let kept: Vec<_> = covered(node, held)
                .into_iter()
                .map(|id| (id, node.paths.carried(id)))
                .filter(|(_, t)| !t.is_empty())
                .map(|(id, t)| (id, t.iter().map(TransportId::as_u32).collect::<Vec<_>>()))
                .collect();
            format!("{kept:?}")
        }
    })
}

/// Read one row of the peer's record.
fn record(p: &ActivePeer, row: DataRow) -> String {
    match row {
        DataRow::Mmp => format!(
            "{:?}",
            p.mmp()
                .map(|m| (m.receiver.highest_counter(), m.metrics.rr_counters()))
        ),
        DataRow::PeerFilter => format!(
            "{:?}",
            (
                p.inbound_filter().is_some(),
                p.filter_sequence(),
                p.filter_received_at()
            )
        ),
        DataRow::FilterPending => format!("{}", p.needs_filter_update()),
        DataRow::TreePosition => format!("{:?}", (p.declaration(), p.coords())),
        DataRow::TreePending => format!("{}", p.has_pending_tree_announce()),
        DataRow::TreeStamp => format!("{:?}", p.last_tree_announce_sent_ms()),
        DataRow::TreeInterval => format!("{}", p.tree_announce_min_interval_ms()),
        // `heard_at` moves with every frame, so only whether one arrived.
        DataRow::Heard => format!("{}", p.heard()),
        DataRow::StoredSetup => format!("{:?}", p.handshake_msg2()),
        DataRow::Stats => format!(
            "{:?}",
            (
                p.authenticated_at(),
                p.last_heartbeat_sent(),
                p.last_heartbeat_attempt(),
                p.last_failed()
            )
        ),
        DataRow::Profile => format!("{:?}", (p.peer_profile(), p.send_sr(), p.send_rr())),
        DataRow::PrevFrames => format!("{}", p.prev_frames()),
        DataRow::HsLines => format!("{:?}", p.hs_lines()),
        DataRow::ReplayBase => format!("{}", p.replay_base()),
        DataRow::ReplayTotal => total(p),
    }
}

/// The running total of refused replays: which allocation, and its value.
#[cfg(unix)]
fn total(p: &ActivePeer) -> String {
    format!(
        "{:p} at {}",
        std::sync::Arc::as_ptr(&p.replay_total()),
        p.replay_suppressed_total()
    )
}

/// The running total's value; which allocation is not read here, since only
/// the decrypt workers' platforms hand it out.
#[cfg(not(unix))]
fn total(p: &ActivePeer) -> String {
    format!("at {}", p.replay_suppressed_total())
}

/// Whether each of the peer's paths holds a connected socket.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sockets(held: Option<&ActivePeer>) -> Reading {
    Some(format!(
        "{:?}",
        held.and_then(|p| {
            let paths = p.bundle()?.paths().paths();
            Some(
                paths
                    .iter()
                    .enumerate()
                    .map(|(i, path)| {
                        let to = PathRef {
                            transport: path.transport_id(),
                            addr: path.addr().clone(),
                        };
                        (named(&to), p.socket_at(i))
                    })
                    .collect::<Vec<_>>(),
            )
        })
    ))
}

/// No platform here has a connected socket, so the row is not read.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn sockets(_held: Option<&ActivePeer>) -> Reading {
    None
}

/// The BLE mark at each pair on a BLE transport with a pooled link, or
/// `None` where no pair has one.
#[cfg(ble_available)]
async fn ble_mark(node: &Node, pairs: &[PathRef]) -> Reading {
    let mut marks = Vec::new();
    for to in pairs {
        if let Some(TransportHandle::Ble(t)) = node.transports.get(&to.transport)
            && let Some(mark) = t.is_verified(&to.addr).await
        {
            marks.push(format!("{}: {mark}", named(to)));
        }
    }
    (!marks.is_empty()).then(|| format!("{marks:?}"))
}

/// No BLE transport is built here, so the mark is not read.
#[cfg(not(ble_available))]
async fn ble_mark(_node: &Node, _pairs: &[PathRef]) -> Reading {
    None
}

/// An address on the peer's first transport that no path holds, which
/// [`dirty`] and the plants write state for.
fn spare(node: &Node, peer: &NodeAddr) -> PathRef {
    let transport = node
        .get_peer(peer)
        .and_then(ActivePeer::transport_id)
        .unwrap_or_else(|| TransportId::new(1));
    PathRef {
        transport,
        addr: TransportAddr::from_string("spare:1"),
    }
}

/// The milliseconds the record's own writers take.
fn now_ms() -> u64 {
    crate::time::mono_ms()
}

/// Make every row of `peer`'s state on `node` that [`dirty_misses`] does not
/// list differ from what a fresh peering holds, through the accessors and
/// map writers, never `raw`, so the node stays audited. Run it after peering:
/// the record's rows are written only while the peer is held, and the
/// node's per-peer state either way. The peering still carries frames each
/// way afterwards.
pub(super) async fn dirty(node: &mut Node, peer: &NodeAddr) {
    for row in Row::all() {
        dirty_row(node, peer, row).await;
    }
}

/// The rows [`dirty`] does not reach with multipath set as `on`, each with
/// why. The BLE mark is reached on a BLE pair and is not read elsewhere.
pub(super) fn dirty_misses(on: bool) -> Vec<(Row, &'static str)> {
    let mut misses = vec![
        (
            Row::Identity,
            "never written after construction: a different value is a different peer",
        ),
        (
            Row::RekeyMachine,
            "written only by stepping the machine, which is a transition of its own",
        ),
        (
            Row::Link,
            "a link record no machine or peer names breaches the live audit, and the peer's own is the one a transition acts on",
        ),
        (
            Row::Data(DataRow::Heard),
            "a frame marks a peer heard and nothing clears it, and the peering has carried frames; when it was heard moves with every frame, which a reading leaves out",
        ),
    ];
    if !on {
        misses.push((
            Row::Capability,
            "a bundle with multipath off discards candidates and sends no capability probe",
        ));
    }
    misses
}

/// Make `row` differ from a fresh peering's, if [`dirty`] reaches it.
pub(super) async fn dirty_row(node: &mut Node, peer: &NodeAddr, row: Row) {
    let spare = spare(node, peer);
    match row {
        Row::Data(data) => {
            if let Some(p) = node.get_peer_mut(peer) {
                dirty_record(p, data);
            }
        }
        // A link record no machine or peer names breaches the node's live
        // audit, so the row is planted, not dirtied.
        Row::Link => {}
        Row::Index => {
            if let Some(id) = node.get_peer(peer).map(ActivePeer::link_id) {
                node.links.claim(id, (spare.transport, spare.addr.clone()));
            }
        }
        Row::Paths => {
            if let Some(p) = node.get_peer_mut(peer) {
                p.admit_path(spare.transport, spare.addr.clone());
            }
        }
        Row::Pin => {
            if let Some(to) = node
                .get_peer(peer)
                .and_then(ActivePeer::current_addr)
                .cloned()
            {
                let transport = spare.transport;
                node.step_path(
                    peer,
                    fips_core::proto::path::Input::Pin {
                        transport,
                        addr: Some(to),
                    },
                )
                .await;
            }
        }
        Row::PathFailures => {
            if let Some(p) = node.get_peer_mut(peer)
                && let (Some(t), Some(addr)) = (p.transport_id(), p.current_addr().cloned())
            {
                p.charge(crate::peer::peer_now(), t, &addr);
            }
        }
        Row::ConnectedUdp => dirty_socket(node, peer),
        Row::SetupRecord => {
            if let Some(p) = node.get_peer_mut(peer) {
                p.test_note_setup(fips_core::proto::rekey::Record::setup(
                    fips_core::proto::rekey::Digest([0xd1; 32]),
                    fips_core::proto::rekey::Digest([0xd2; 32]),
                    None,
                ));
            }
        }
        Row::ControlMachine => {
            if let Some(id) = node.get_peer(peer).map(ActivePeer::link_id) {
                node.peer_machines
                    .arm(id, crate::peer::machine::TimerKind::Liveness, u64::MAX / 2);
            }
        }
        Row::Connection => {
            // Only a loopback transport records a close without closing a
            // connection the peering needs.
            if let Some(addr) = node.get_peer(peer).and_then(|p| p.current_addr().cloned())
                && let Some(t @ TransportHandle::Loopback(_)) =
                    node.transports.get(&spare.transport)
            {
                t.close_connection(&addr).await;
            }
        }
        Row::Bootstrap => {
            let npub = node
                .get_peer(peer)
                .map(ActivePeer::npub)
                .unwrap_or_default();
            node.supervisor.nostr_rendezvous.insert_bootstrap_transport(
                spare.transport,
                npub,
                *peer,
                "127.0.0.1:9".parse().expect("precondition: an address"),
            );
        }
        Row::Dials => {
            if let Some(id) = node.get_peer(peer).map(ActivePeer::link_id) {
                node.pending_outbound
                    .note((spare.transport, 0x0dd_d1a1), id);
            }
        }
        Row::PathMtu => {
            let addr = crate::Ipv6Address::from_node_addr(peer);
            node.path_mtu_lookup
                .insert_unkeyed(addr, crate::node::path_mtu::PathMtuEntry::held(1111));
            node.path_mtu_seeded_by.insert(addr, spare.transport);
        }
        Row::FilterSend => {
            node.bloom_state.record_update_sent(*peer, 4242);
            node.bloom_state
                .record_sent_filter(*peer, crate::proto::bloom::BloomFilter::new());
        }
        Row::Tree => {
            let declaration = crate::proto::stp::ParentDeclaration::new(*peer, *peer, 4242, 4242);
            let coords = crate::proto::stp::TreeCoordinate::from_addrs(vec![*peer])
                .expect("precondition: a one-entry coordinate");
            node.tree_state.update_peer(declaration, coords);
        }
        Row::Session => {
            if let Some(key) = node.get_peer(peer).map(|p| p.identity().pubkey_full()) {
                let _ = node.initiate_session(*peer, key).await;
            }
        }
        Row::Dampener => {
            let past = std::time::Instant::now()
                .checked_sub(Duration::from_secs(3600))
                .unwrap_or_else(std::time::Instant::now);
            node.restart_dampener.insert(*peer, past);
        }
        Row::Silent => {
            node.silent_sessions.ended(*peer, None, None, now_ms());
        }
        Row::Reconnect => {
            let npub = node
                .get_peer(peer)
                .map(ActivePeer::npub)
                .unwrap_or_default();
            let config = crate::config::PeerConfig::new(npub, "udp", "127.0.0.1:9");
            let retry = crate::node::peering::retry::RetryState::new(config);
            node.peering.reconciler.retry_pending.insert(*peer, retry);
        }
        Row::IdentityCache => {
            node.identity_cache.touch(&peer.prefix(), now_ms() + 4242);
        }
        Row::LookupBackoff => {
            // The default configuration disables the backoff, which then
            // holds nothing; it is enabled here so the row has state.
            if !node.lookup.backoff.is_enabled() {
                node.lookup.backoff = fips_core::proto::lookup::LookupBackoff::with_params(1, 60);
            }
            node.lookup.backoff.record_failure(peer, now_ms());
        }
        Row::PathConnects => node.paths.wait(*peer, spare),
        Row::PathCloses => {
            // Another spare pair: a release unclaims its pair's index entry.
            let to = PathRef {
                transport: spare.transport,
                addr: TransportAddr::from_string("spare:2"),
            };
            if let Some(id) = node.get_peer(peer).map(ActivePeer::link_id) {
                node.release_path(peer, id, to, Default::default(), false, false);
            }
        }
        Row::PathListings => {
            let pairs = [(spare.transport, spare.addr.clone())];
            node.paths
                .listings
                .list(*peer, Feed::Config, &pairs, now_ms());
        }
        Row::PathCarrier => {
            if let Some(id) = node.get_peer(peer).map(ActivePeer::link_id) {
                node.paths.plant_reading(id, spare.transport);
            }
        }
        Row::BleMark => dirty_mark(node, peer).await,
        Row::Capability => {
            let to = spare;
            node.step_path(
                peer,
                fips_core::proto::path::Input::Candidate {
                    transport: to.transport,
                    addr: to.addr,
                    source: fips_core::proto::path::Source::Request,
                },
            )
            .await;
        }
        Row::Identity | Row::RekeyMachine => {}
    }
}

/// Make one row of the record differ from a fresh one's.
pub(super) fn dirty_record(p: &mut ActivePeer, row: DataRow) {
    match row {
        DataRow::Mmp => {
            if let Some(m) = p.mmp_mut() {
                // Past any counter a frame of this session carries, so the
                // highest seen stays here until a reset.
                m.receiver.record_recv(1 << 40, 0, 64, false, now_ms());
            }
        }
        DataRow::PeerFilter => p.update_filter(crate::proto::bloom::BloomFilter::new(), 4242, 4242),
        DataRow::FilterPending => {
            if p.needs_filter_update() {
                p.clear_filter_update_needed();
            } else {
                p.mark_filter_update_needed();
            }
        }
        DataRow::TreePosition => {
            let addr = *p.node_addr();
            let declaration = crate::proto::stp::ParentDeclaration::new(addr, addr, 4242, 4242);
            let coords = crate::proto::stp::TreeCoordinate::from_addrs(vec![addr])
                .expect("precondition: a one-entry coordinate");
            p.update_tree_position(declaration, coords, 4242);
        }
        DataRow::TreePending => p.mark_tree_announce_pending(),
        DataRow::TreeStamp => p.set_last_tree_announce_sent_ms(Some(4242)),
        DataRow::TreeInterval => p.set_tree_announce_min_interval_ms(4242),
        // A frame marks a promoted peer heard, and nothing clears it.
        DataRow::Heard => p.touch(now_ms()),
        DataRow::StoredSetup => p.set_handshake_msg2(vec![0xd5; 48]),
        DataRow::Stats => {
            p.mark_heartbeat_attempt(std::time::Instant::now());
            p.record_failed(SessionIndex::new(0x0dd_fa11));
        }
        DataRow::Profile => p.test_take_profile(crate::proto::fmp::NodeProfile::Leaf),
        DataRow::PrevFrames => p.count_previous(),
        DataRow::HsLines => {
            p.hs_lines_mut().count(crate::node::diag::HsLine::Resend);
        }
        DataRow::ReplayBase => {
            p.increment_replay_suppressed();
            p.reset_replay_suppressed();
        }
        DataRow::ReplayTotal => {
            p.increment_replay_suppressed();
        }
    }
}

/// Clear the BLE mark at the peer's current pair, on a BLE transport.
#[cfg(ble_available)]
async fn dirty_mark(node: &mut Node, peer: &NodeAddr) {
    let Some(p) = node.get_peer(peer) else {
        return;
    };
    if let (Some(t), Some(addr)) = (p.transport_id(), p.current_addr())
        && let Some(TransportHandle::Ble(ble)) = node.transports.get(&t)
    {
        ble.clear_verified(addr, peer, false).await;
    }
}

/// No BLE transport is built here.
#[cfg(not(ble_available))]
async fn dirty_mark(_node: &mut Node, _peer: &NodeAddr) {}

/// Seat a real connected socket, aimed at the loopback discard port, on the
/// peer's active path, as `install_connected_udp` does but through the
/// per-path writer.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn dirty_socket(node: &mut Node, peer: &NodeAddr) {
    use crate::transport::udp::{ConnectedPeerSocket, PeerRecvDrain, UdpStats, open_connected_fd};
    let Some(p) = node.get_peer_mut(peer) else {
        return;
    };
    let (Some(t), Some(index)) = (
        p.transport_id(),
        p.bundle().and_then(|b| b.paths().active_index()),
    ) else {
        return;
    };
    let local: std::net::SocketAddr = "0.0.0.0:0".parse().expect("precondition: an address");
    let target: std::net::SocketAddr = "127.0.0.1:9".parse().expect("precondition: an address");
    let fd = open_connected_fd(local, target, 65_536, 65_536, None)
        .expect("precondition: a connected UDP socket opens");
    let socket = std::sync::Arc::new(ConnectedPeerSocket::from_fd(fd, target, local));
    let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
    let drain = PeerRecvDrain::spawn(
        socket.clone(),
        t,
        target,
        packet_tx,
        std::sync::Arc::new(UdpStats::new()),
    )
    .expect("precondition: the socket's recv drain starts");
    p.seat_socket(index, socket, drain);
}

/// No platform here has a connected socket.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn dirty_socket(_node: &mut Node, _peer: &NodeAddr) {}

/// Open a link record no machine or peer names, which the node's live audit
/// reports at its next entry.
fn orphan_link(node: &mut Node, spare: PathRef) {
    let id = node.allocate_link_id();
    node.links.open(crate::transport::Link::new(
        id,
        spare.transport,
        spare.addr,
        LinkDirection::Outbound,
        Duration::from_millis(50),
    ));
}

/// Change `row` of `peer`'s state on `node` by any means, `raw` included,
/// for the test that the harness reads it. Returns whether it planted
/// through `raw`, which costs the node its audit.
async fn plant(node: &mut Node, peer: &NodeAddr, row: Row) -> bool {
    match row {
        Row::Identity => {
            let old = node
                .peers
                .raw()
                .remove(peer)
                .expect("precondition: the peer is held");
            let other = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
            let replaced = ActivePeer::new(other, old.link_id(), old.authenticated_at());
            node.peers.raw().insert(*peer, replaced);
            true
        }
        Row::RekeyMachine => {
            node.peers_by_index.raw().insert(0x0dd_b1d, *peer);
            true
        }
        Row::Data(DataRow::Heard) => {
            let old = node
                .peers
                .raw()
                .remove(peer)
                .expect("precondition: the peer is held");
            let unheard = ActivePeer::new(*old.identity(), old.link_id(), old.authenticated_at());
            node.peers.raw().insert(*peer, unheard);
            true
        }
        Row::Link => {
            let spare = spare(node, peer);
            orphan_link(node, spare);
            false
        }
        _ => {
            dirty_row(node, peer, row).await;
            false
        }
    }
}

/// Two loopback nodes with multipath set as `on`, node 0 having dialled
/// node 1 and each holding the other.
pub(super) async fn peered(on: bool) -> Vec<TestNode> {
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let (a, b) = (*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    assert!(
        nodes[0].node.get_peer(&b).is_some() && nodes[1].node.get_peer(&a).is_some(),
        "precondition: the loopback pair peered"
    );
    nodes
}

/// Transitions for which some row's cell is [`Expect::Kept`], to find one at
/// which a planted change of that row must red.
fn samples() -> Vec<Transition> {
    let link = LinkId::new(1);
    vec![
        Transition::Follow,
        Transition::Switch,
        Transition::Release { keep: true },
        Transition::Roam,
        Transition::Keep {
            dial: link,
            inbound: false,
        },
        Transition::Cutover {
            role: Role::Initiator,
        },
        Transition::Restarted,
        Transition::Move {
            dial: link,
            own: false,
            built: true,
            inbound: false,
        },
        Transition::Promote {
            link,
            initiator: true,
        },
        Transition::Remove { why: Why::Dead },
    ]
}

/// Plant a change of each row but the BLE mark, one at a time, each on a
/// fresh pair, the capability state with multipath on only. Require that the
/// harness reads it at that row, and that [`check_cells`] calls it a breach
/// at a transition whose cell keeps the row, where the unchanged reading
/// passes [`assert_cells`].
async fn reds_a_planted_change_of_each_row(on: bool) {
    let mut unseen = Vec::new();
    let mut unflagged = Vec::new();
    for row in Row::all() {
        if row == Row::BleMark {
            continue;
        }
        let mut nodes = peered(on).await;
        let b = *nodes[1].node.node_addr();
        let before = Seen::of(&nodes[0].node, &b, &[]).await;
        plant(&mut nodes[0].node, &b, row).await;
        let after = Seen::of(&nodes[0].node, &b, &[]).await;
        cleanup_nodes(&mut nodes).await;
        if after.get(row).is_none() {
            // Not read on this platform: the connected socket off Linux and
            // macOS.
            continue;
        }
        if !on && row == Row::Capability {
            // With multipath off a bundle discards candidates and sends no
            // capability probe, so the row has no state to plant. That it
            // stays as built is checked here; the sibling plants it.
            assert_eq!(
                before.get(row),
                after.get(row),
                "precondition: with multipath off the capability state cannot be planted"
            );
            continue;
        }
        if !before.differing(&after).contains(&row) {
            unseen.push(format!(
                "{row:?}: before {:?}, after {:?}",
                before.get(row),
                after.get(row)
            ));
            continue;
        }
        let keeping = samples()
            .into_iter()
            .find(|t| expect(cell(row, t)) == Expect::Kept)
            .unwrap_or_else(|| panic!("precondition: some sample keeps {row:?}"));
        let others: Vec<(Row, Outcome)> = Row::all()
            .into_iter()
            .filter(|r| expect(cell(*r, &keeping)) == Expect::Stated)
            .map(|r| (r, Outcome::Kept))
            .collect();
        assert_cells(&before, &before, &keeping, &others);
        let checked = check_cells(&before, &after, &keeping, &others);
        if !checked
            .breaches
            .iter()
            .any(|b| b.starts_with(&format!("{row:?} ")))
        {
            unflagged.push(format!("{row:?} at {keeping:?}: {:?}", checked.breaches));
        }
    }
    assert!(
        unseen.is_empty(),
        "defect: the harness does not read a planted change of {unseen:#?}"
    );
    assert!(
        unflagged.is_empty(),
        "defect: a planted change the harness reads is not a breach where the cell keeps it: {unflagged:#?}"
    );
}

/// A change planted in any row but the BLE mark, with multipath off, is read
/// at that row and is a breach where the row's cell keeps it.
#[tokio::test]
async fn the_harness_reds_a_planted_change_of_each_row() {
    reds_a_planted_change_of_each_row(false).await;
}

/// [`the_harness_reds_a_planted_change_of_each_row`] with multipath on.
#[tokio::test]
async fn the_harness_reds_a_planted_change_of_each_row_with_multipath_on() {
    reds_a_planted_change_of_each_row(true).await;
}

/// On a loopback pair the BLE mark is not read: the harness reports it unread
/// on both sides at a cell that changes it, and never calls it kept.
#[tokio::test]
async fn the_harness_does_not_call_the_ble_mark_kept_on_another_transport() {
    let mut nodes = peered(false).await;
    let b = *nodes[1].node.node_addr();
    let also = [PathRef {
        transport: nodes[0].transport_id,
        addr: nodes[1].addr.clone(),
    }];
    let before = Seen::of(&nodes[0].node, &b, &also).await;
    let after = Seen::of(&nodes[0].node, &b, &also).await;
    cleanup_nodes(&mut nodes).await;
    let t = Transition::Remove { why: Why::Dead };
    assert_eq!(
        expect(cell(Row::BleMark, &t)),
        Expect::Changed,
        "precondition: a dead peer's BLE mark is cleared"
    );
    let others: Vec<(Row, Outcome)> = Row::all()
        .into_iter()
        .filter(|r| expect(cell(*r, &t)) == Expect::Stated)
        .map(|r| (r, Outcome::Kept))
        .collect();
    let checked = check_cells(&before, &after, &t, &others);
    let flagged: Vec<&String> = checked
        .breaches
        .iter()
        .filter(|b| b.starts_with("BleMark "))
        .collect();
    assert!(
        flagged.is_empty() && checked.unread.contains(&Row::BleMark),
        "defect: on loopback the BLE mark is read as {:?}; unread {:?}, breaches {flagged:?}",
        after.get(Row::BleMark),
        checked.unread
    );
}

/// After peering, [`dirty`] leaves every row but those [`dirty_misses`]
/// lists different from what the fresh peering held, the listed ones as
/// they were, the node still audited, and the peering still carrying a
/// heartbeat each way.
async fn dirtying_leaves_every_row_different(on: bool) {
    let mut nodes = peered(on).await;
    let b = *nodes[1].node.node_addr();
    let fresh = Seen::of(&nodes[0].node, &b, &[]).await;
    dirty(&mut nodes[0].node, &b).await;
    let after = Seen::of(&nodes[0].node, &b, &[]).await;
    let differing = fresh.differing(&after);
    let mut wrong = Vec::new();
    for row in Row::all() {
        let missed = dirty_misses(on).iter().any(|(r, _)| *r == row);
        let unread = fresh.get(row).is_none() && after.get(row).is_none();
        if unread {
            // The BLE mark off BLE, and the connected socket off the
            // platforms that have one.
            if !matches!(row, Row::BleMark | Row::ConnectedUdp) {
                wrong.push(format!("{row:?} is not read"));
            }
            continue;
        }
        if differing.contains(&row) == missed {
            wrong.push(format!(
                "{row:?}: listed as missed {missed}; fresh {:?}, dirtied {:?}",
                fresh.get(row),
                after.get(row)
            ));
        }
    }
    #[cfg(debug_assertions)]
    let audited = nodes[0].node.links.audits();
    let carried = [
        heartbeat_reaches(&mut nodes, 0, 1).await,
        heartbeat_reaches(&mut nodes, 1, 0).await,
    ];
    // The writers `dirty` uses leave the node audited: its live audit runs
    // again on the heartbeats, and finds nothing.
    #[cfg(debug_assertions)]
    let audits = (audited, nodes[0].node.links.audits());
    cleanup_nodes(&mut nodes).await;
    #[cfg(debug_assertions)]
    assert!(
        audits.1 > audits.0,
        "defect: the dirtied node is no longer audited: audits before the heartbeats {}, after {}",
        audits.0,
        audits.1
    );
    assert!(
        wrong.is_empty(),
        "defect: dirtying does not leave the rows as its list says: {wrong:#?}"
    );
    assert!(
        carried.iter().all(Result::is_ok),
        "defect: the dirtied peering no longer carries a heartbeat each way: {carried:?}"
    );
}

/// [`dirty`] with multipath off, on loopback, and on the BLE pair for the
/// BLE mark.
#[tokio::test]
async fn dirtying_leaves_every_row_different_from_fresh() {
    dirtying_leaves_every_row_different(false).await;
    #[cfg(ble_available)]
    dirtying_reaches_the_ble_mark(false).await;
}

/// [`dirtying_leaves_every_row_different_from_fresh`] with multipath on.
#[tokio::test]
async fn dirtying_leaves_every_row_different_from_fresh_with_multipath_on() {
    dirtying_leaves_every_row_different(true).await;
    #[cfg(ble_available)]
    dirtying_reaches_the_ble_mark(true).await;
}

/// The BLE mock transport.
#[cfg(ble_available)]
type BleOf = crate::transport::ble::BleTransport<crate::transport::ble::io::MockBleIo>;

/// The BLE transport of `tn`'s first transport.
#[cfg(ble_available)]
fn ble_of(tn: &TestNode) -> &BleOf {
    match tn.node.transports.get(&tn.transport_id) {
        Some(TransportHandle::Ble(t)) => t,
        _ => panic!("precondition: the node's first transport is BLE"),
    }
}

/// The BLE mark node 0 holds for its link to node 1.
#[cfg(ble_available)]
async fn initiator_mark(nodes: &[TestNode]) -> Option<bool> {
    ble_of(&nodes[0]).is_verified(&nodes[1].addr).await
}

/// Two nodes on the BLE mock, multipath set as `on`, node 0 the smaller
/// address having dialled node 1 over a genuine link and each holding the
/// other. Both ends key the link at node 1's address. The bank must be kept
/// alive, or the link closes.
#[cfg(ble_available)]
pub(super) async fn ble_pair(on: bool) -> (Vec<TestNode>, super::super::ble::StreamBank) {
    ble_built(super::with_path(Config::new(), on)).await
}

/// [`ble_pair`] on nodes built from `config`.
#[cfg(ble_available)]
async fn ble_built(config: Config) -> (Vec<TestNode>, super::super::ble::StreamBank) {
    use super::super::ble::{base_config, larger_second, link_genuinely, make_test_node_ble_from};
    let mut nodes = vec![
        make_test_node_ble_from(1, base_config(), config.clone()).await,
        make_test_node_ble_from(2, base_config(), config).await,
    ];
    larger_second(&mut nodes);
    let bank = link_genuinely(&nodes).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let (a, b) = (*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    assert!(
        nodes[0].node.get_peer(&b).is_some() && nodes[1].node.get_peer(&a).is_some(),
        "precondition: the BLE pair peered"
    );
    (nodes, bank)
}

/// [`ble_pair`] with multipath on and paths of mixed kinds allowed, plus a
/// loopback transport on each node, `t2`, at a tapped address, and node 0
/// offered node 1's: node 0 holds a BLE path and a loopback path to node 1,
/// both Live. Frames on the loopback transport reach a node only through
/// [`BlePaths::shuttle`].
#[cfg(ble_available)]
pub(super) struct BlePaths {
    /// The two nodes, node 0 the dialler.
    pub(super) nodes: Vec<TestNode>,
    /// Holds the BLE link open.
    #[allow(dead_code)] // held, never read
    pub(super) bank: super::super::ble::StreamBank,
    /// The loopback transport on each node.
    pub(super) t2: TransportId,
    /// Node 0's address on `t2`.
    pub(super) a2: TransportAddr,
    /// Node 1's address on `t2`.
    pub(super) b2: TransportAddr,
    a_rx: tokio::sync::mpsc::UnboundedReceiver<crate::transport::ReceivedPacket>,
    b_rx: tokio::sync::mpsc::UnboundedReceiver<crate::transport::ReceivedPacket>,
}

#[cfg(ble_available)]
impl BlePaths {
    /// Deliver on both transports until eight rounds 5 ms apart move nothing,
    /// or 200 rounds pass.
    pub(super) async fn shuttle(&mut self) {
        use super::super::spanning_tree::process_available_packets;
        let mut idle = 0;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            let mut moved = process_available_packets(&mut self.nodes).await;
            while let Ok(p) = self.a_rx.try_recv() {
                self.nodes[0].node.handle_encrypted_frame(p).await;
                moved += 1;
            }
            while let Ok(p) = self.b_rx.try_recv() {
                self.nodes[1].node.handle_encrypted_frame(p).await;
                moved += 1;
            }
            if moved == 0 {
                idle += 1;
                if idle >= 8 {
                    return;
                }
            } else {
                idle = 0;
            }
        }
    }
}

/// Build [`BlePaths`].
#[cfg(ble_available)]
pub(super) async fn ble_paths() -> BlePaths {
    use super::super::paths::state_at;
    use super::super::spanning_tree::LOOPBACK_REGISTRY;
    use crate::peer::PathState;
    use crate::transport::loopback::LoopbackTransport;
    let mut config = super::with_path(Config::new(), true);
    config.node.path.mix_kinds = true;
    let (mut nodes, bank) = ble_built(config).await;
    let t2 = TransportId::new(2);
    let (a2, a_rx) = super::tap(t2);
    let (b2, b_rx) = super::tap(t2);
    for (i, addr) in [(0, a2.clone()), (1, b2.clone())] {
        let lo = LoopbackTransport::new(t2, addr, LOOPBACK_REGISTRY.clone());
        nodes[i]
            .node
            .transports
            .insert(t2, TransportHandle::Loopback(lo));
    }
    let b = *nodes[1].node.node_addr();
    nodes[0].node.offer_path(&b, t2, b2.clone()).await;
    let mut pair = BlePaths {
        nodes,
        bank,
        t2,
        a2,
        b2,
        a_rx,
        b_rx,
    };
    pair.shuttle().await;
    let t1 = pair.nodes[0].transport_id;
    let p = pair.nodes[1].addr.clone();
    assert_eq!(
        (
            state_at(&pair.nodes[0], &b, t1, &p),
            state_at(&pair.nodes[0], &b, pair.t2, &pair.b2)
        ),
        (Some(PathState::Live), Some(PathState::Live)),
        "precondition: node 0 holds a Live BLE path and a Live loopback path to node 1"
    );
    pair
}

/// On the BLE pair a cleared mark is read at the mark's row, and is a breach
/// where the mark's cell keeps it.
#[cfg(ble_available)]
async fn reds_a_planted_change_of_the_ble_mark(on: bool) {
    let (mut nodes, _bank) = ble_pair(on).await;
    let b = *nodes[1].node.node_addr();
    let also = [PathRef {
        transport: nodes[0].transport_id,
        addr: nodes[1].addr.clone(),
    }];
    assert_eq!(
        initiator_mark(&nodes).await,
        Some(true),
        "precondition: the initiator's link is verified"
    );
    let before = Seen::of(&nodes[0].node, &b, &also).await;
    ble_of(&nodes[0])
        .clear_verified(&nodes[1].addr, &b, false)
        .await;
    let planted = initiator_mark(&nodes).await;
    let after = Seen::of(&nodes[0].node, &b, &also).await;
    cleanup_nodes(&mut nodes).await;
    assert_eq!(planted, Some(false), "precondition: the mark is cleared");
    let keeping = Transition::Keep {
        dial: LinkId::new(1),
        inbound: false,
    };
    assert_eq!(
        expect(cell(Row::BleMark, &keeping)),
        Expect::Kept,
        "precondition: a lost crossing keeps the mark"
    );
    let others: Vec<(Row, Outcome)> = Row::all()
        .into_iter()
        .filter(|r| expect(cell(*r, &keeping)) == Expect::Stated)
        .map(|r| (r, Outcome::Kept))
        .collect();
    let checked = check_cells(&before, &after, &keeping, &others);
    assert!(
        before.differing(&after).contains(&Row::BleMark)
            && checked.breaches.iter().any(|b| b.starts_with("BleMark ")),
        "defect: the harness does not read the cleared BLE mark: before {:?}, after {:?}, breaches {:?}",
        before.get(Row::BleMark),
        after.get(Row::BleMark),
        checked.breaches
    );
}

/// A cleared BLE mark, multipath off, is read and is a breach where kept.
#[cfg(ble_available)]
#[tokio::test]
async fn the_harness_reds_a_planted_change_of_the_ble_mark() {
    reds_a_planted_change_of_the_ble_mark(false).await;
}

/// [`the_harness_reds_a_planted_change_of_the_ble_mark`] with multipath on.
#[cfg(ble_available)]
#[tokio::test]
async fn the_harness_reds_a_planted_change_of_the_ble_mark_with_multipath_on() {
    reds_a_planted_change_of_the_ble_mark(true).await;
}

/// On the BLE pair, [`dirty`] leaves the BLE mark different from fresh.
#[cfg(ble_available)]
async fn dirtying_reaches_the_ble_mark(on: bool) {
    let (mut nodes, _bank) = ble_pair(on).await;
    let b = *nodes[1].node.node_addr();
    let also = [PathRef {
        transport: nodes[0].transport_id,
        addr: nodes[1].addr.clone(),
    }];
    let fresh = Seen::of(&nodes[0].node, &b, &also).await;
    dirty(&mut nodes[0].node, &b).await;
    let after = Seen::of(&nodes[0].node, &b, &also).await;
    cleanup_nodes(&mut nodes).await;
    assert!(
        fresh.get(Row::BleMark).is_some() && fresh.differing(&after).contains(&Row::BleMark),
        "defect: dirtying does not reach the BLE mark: fresh {:?}, dirtied {:?}",
        fresh.get(Row::BleMark),
        after.get(Row::BleMark)
    );
}

/// [`ble_paths`] holds a Live BLE path and a Live loopback path to the peer,
/// a frame sent on the loopback one reaches node 0, and the harness reads the
/// mark at the BLE one.
#[cfg(ble_available)]
#[tokio::test]
async fn the_ble_paths_pair_holds_both_paths_and_reads_the_mark() {
    let mut pair = ble_paths().await;
    let (a, b) = (
        *pair.nodes[0].node.node_addr(),
        *pair.nodes[1].node.node_addr(),
    );
    let before = super::received(&pair.nodes, 0, 1);
    let heartbeat = [crate::proto::link::LinkMessageType::Heartbeat.to_byte()];
    let on_loopback = PathRef {
        transport: pair.t2,
        addr: pair.a2.clone(),
    };
    let sent = pair.nodes[1]
        .node
        .send_via(&a, &heartbeat, false, Some(&on_loopback))
        .await;
    pair.shuttle().await;
    let after = super::received(&pair.nodes, 0, 1);
    let seen = Seen::of(&pair.nodes[0].node, &b, &[]).await;
    let mark = seen.get(Row::BleMark).clone();
    cleanup_nodes(&mut pair.nodes).await;
    assert!(
        sent.is_ok() && matches!((before, after), (Some((x, _)), Some((y, 0))) if y > x),
        "precondition: a heartbeat on the loopback path authenticates: sent {sent:?}, before {before:?}, after {after:?}"
    );
    assert!(
        mark.as_deref().is_some_and(|m| m.contains(": true")),
        "defect: the harness does not read the BLE path's mark on the two-path pair: {mark:?}"
    );
}
