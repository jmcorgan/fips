//! A removal: the one routine that takes a peer out of the node, told why,
//! and what the node runs once the peer is out of its maps, by the table's
//! cells for the cause.
//!
//! [`Node::remove`] is synchronous, since a removal is reached where the
//! node cannot await. What follows it, [`Node::removed`], runs the plan of
//! [`Transition::Remove`]: each effect reads its row's cell at the cause,
//! so the causes differ only where the table says they do.

use super::{Facts as Of, Run};
use crate::NodeAddr;
use crate::node::diag::OrNone;
use crate::node::settle::table::{Cell, Row, Transition, cell};
use crate::node::{AddrKey, Node};
use crate::proto::settle::output::Why;
use tracing::debug;

/// What a removal hands the statements that follow it: why the peer went,
/// the pair it was sending over just before, and whether the loss is noted
/// for a reconnect where the removal was decided.
#[derive(Debug)]
pub(in crate::node) struct Removed {
    /// Why the peer was removed.
    pub(in crate::node) why: Why,
    /// The transport and address the peer sent over, read before the
    /// removal.
    pub(in crate::node) held: Option<AddrKey>,
    /// Whether the loss is noted for a reconnect by whoever decided the
    /// removal: the peer's control machine, as its next action, or the
    /// Disconnect handler, which cannot await. A cell that notes it then
    /// runs nothing here.
    pub(in crate::node) noted: bool,
}

/// What a removal's effects read beyond the transition: the removal.
#[derive(Debug)]
pub(in crate::node) struct Facts {
    removed: Removed,
}

impl Node {
    /// Remove the peer at `node_addr`, for `why`, and clean up all the state
    /// held for it: its machines are closed, its record ended, its session
    /// indices freed, and its link and address mappings removed, with the
    /// end-to-end session with the node.
    ///
    /// Also handles tree state cleanup: if the removed peer was our parent,
    /// selects an alternative or becomes root, and marks remaining peers
    /// for pending tree announce (delivered on next tick).
    ///
    /// Returns `None`, having changed nothing, when no peer is held there.
    pub(in crate::node) fn remove(&mut self, node_addr: &NodeAddr, why: Why) -> Option<Removed> {
        let held = self.peer_link(node_addr);
        let Some(mut peer) = self.peers.take(node_addr) else {
            debug!(peer = %self.peer_display_name(node_addr), "Peer already removed");
            return None;
        };
        let link_id = peer.link_id();
        // Read while the machines are open: the transport for the bootstrap
        // cleanup below, and the startup epoch the silent-session note files
        // the refusal under.
        let transport_id = peer.transport_id();
        let epoch = peer.remote_epoch();
        let peer_name = self
            .peer_aliases
            .get(node_addr)
            .cloned()
            .unwrap_or_else(|| peer.identity().short_npub());
        // Close the peer's machines, then end its record. Closing changes
        // nothing outside the peer: what it returns is carried out below,
        // after the session and path MTU cleanup, as it always was.
        let (paths, out) = peer.stop();
        let departed = peer.depart();

        if !departed.frame_heard {
            self.note_silent_session(node_addr, epoch);
        }

        // Log suppressed replay detection summary before teardown
        if departed.suppressed > 0 {
            debug!(
                peer = %self.peer_display_name(node_addr),
                count = departed.suppressed,
                "Suppressed replay detections during link transition"
            );
        }
        if let Some(withheld) = &departed.withheld {
            self.log_withheld(node_addr, withheld);
        }

        // MMP teardown log
        if let Some(mmp) = &departed.mmp {
            Self::log_mmp_teardown(&peer_name, mmp);
        }

        // Remove any end-to-end session associated with this peer.
        //
        // Sessions are tracked separately from peers (self.sessions vs self.peers).
        // Leaving a stale session alive after removing the peer causes:
        //   1. check_session_mmp_reports() keeps logging stale "MMP session metrics"
        //      with frozen counters until purge_idle_sessions() eventually fires.
        //   2. initiate_session() finds is_established() == true on the stale entry
        //      and silently returns Ok(()), preventing a new session from being
        //      established even after the link layer reconnects successfully.
        //
        // The IPv6 adapter's packets held for the node stay. The node may
        // still be reachable through another peer, or be back at once when
        // this removal is a replacement or a restart, so the next session to
        // it sends them; the held-packet backstop answers them with no route
        // if nothing can reach it.
        if let Some(session_entry) = self.sessions.remove(node_addr)
            && let Some(mmp) = session_entry.mmp()
        {
            Self::log_session_mmp_teardown(&peer_name, mmp);
        }

        // Release the path MTU state this peer's promotion seeded: the link it
        // measured has just gone. The other callers all fire on session state,
        // so without this a peer that never opened an FSP session leaves both
        // its `path_mtu_lookup` entry and its seeding-transport record behind
        // for the life of the process. The peer is already out of `self.peers`
        // above, so no reseed follows and the two go together, which is what
        // keeps a peer returning over a wider link from being clamped to the
        // one it left.
        if !node_fault!(RestartKeepsClamp) {
            self.path_mtu_lookup_release(node_addr);
        }

        // Hand back every path's driver slot.
        for out in paths {
            if let fips_core::proto::path::Output::Released { to, driver, keep } = out {
                self.release_path(node_addr, link_id, to, driver, keep, true);
            }
        }
        self.forget_connects(node_addr);

        // Free session indices (current, rekey, pending, previous): unbind
        // them from `peers_by_index` by index, whichever transport the peer
        // is on now, revoke them from the decrypt workers that hold them,
        // and free them.
        self.run_link_outputs(node_addr, out);

        // Remove link and address mapping
        if !node_fault!(RemoveKeepsLink) {
            self.remove_link(&link_id);
        }
        // Drop this peer's inert machine, keyed by the link_id
        // derived above (a peer's link_id is immutable, so the key never
        // moved). Keeps peers <-> peer_machines in exact correspondence on
        // teardown. NEUTRAL: nothing reads peer_machines yet.
        self.remove_peer_machine(link_id);
        if let Some(transport_id) = transport_id {
            self.cleanup_bootstrap_transport_if_unused(transport_id);
        }

        // Tree state cleanup
        let tree_changed = self.handle_peer_removal_tree_cleanup(node_addr);
        if tree_changed {
            // Mark all remaining peers for pending tree announce.
            // These will be sent on the next tick via check_tree_state().
            for peer in self.peers.values_mut() {
                peer.mark_tree_announce_pending();
            }
        }

        // Bloom filter cleanup: remove dependent (non-routing/leaf peers), clear state
        self.bloom_state.remove_leaf_dependent(node_addr);
        self.bloom_state.remove_peer_state(node_addr);
        let remaining_peers: Vec<NodeAddr> = self.peers.keys().copied().collect();
        self.bloom_state.mark_all_updates_needed(remaining_peers);

        debug!(
            peer = %self.peer_display_name(node_addr),
            link_id = %link_id,
            tree_changed = tree_changed,
            "Peer removed and state cleaned up"
        );
        Some(Removed {
            why,
            held,
            noted: false,
        })
    }

    /// Run what follows the removal `r` of the peer at `node_addr`, as the
    /// table's cells for its cause say: the transport's mark cleared at the
    /// pair the peer was on, its connection there closed, and the reconnect
    /// noted or dropped.
    pub(in crate::node) async fn removed(&mut self, node_addr: &NodeAddr, r: Removed) {
        let mut run = Run::new(*node_addr, Transition::Remove { why: r.why });
        run.facts = Of::Remove(Facts { removed: r });
        self.run(&mut run).await;
    }

    /// The removal a test makes: the routine for a link its rekey machine
    /// ended, the one cause whose table runs nothing after the removal, so
    /// a test that leaves out what follows a removal leaves out nothing.
    #[cfg(test)]
    pub(in crate::node) fn remove_active_peer(&mut self, node_addr: &NodeAddr) -> Option<Removed> {
        self.remove(node_addr, Why::Ended)
    }

    /// Count the session of the peer at `node_addr`, removed without having
    /// carried one authenticated frame, toward its identity's silent-session
    /// back-off at its startup `epoch`, and log the refusal this starts or
    /// extends, with how many handshakes the identity's previous refusal
    /// refused.
    fn note_silent_session(&mut self, node_addr: &NodeAddr, epoch: Option<[u8; 8]>) {
        // No setup digest: on XX a session is promoted only on a msg3 bound
        // to this node's fresh msg2, so a replayed msg1 cannot promote one
        // and every silent session counts.
        let refusal = self
            .silent_sessions
            .ended(*node_addr, epoch, None, crate::time::mono_ms());
        if let Some(refusal) = refusal {
            debug!(
                peer = %self.peer_display_name(node_addr),
                startup_epoch = %OrNone(epoch.map(hex::encode)),
                silent = refusal.backoff.silent,
                refuse_s = refusal.backoff.remaining_ms / 1000,
                prior_refused = refusal.prior_refused,
                "Session ended without a frame, refusing the peer's handshakes at this epoch"
            );
        }
    }
}

/// The removal `r` runs the tail of: a removal's, or the one a replacement
/// starts with.
fn removal(r: &Run) -> Option<&Removed> {
    let removed = match &r.facts {
        Of::Remove(facts) => Some(&facts.removed),
        Of::Install(facts) => facts.removed(),
        Of::None | Of::Cross(_) | Of::Paths(_) => None,
    };
    debug_assert!(removed.is_some(), "a removal's effect ran with no removal");
    removed
}

/// Clear the transport's mark at the pair the peer was on, by the table's
/// cell. Where the cell clears it only if the drain closes the connection,
/// the removal's own release of the paths has done that. A replacement's
/// cell marks the new peering too, which its promotion does.
pub(super) async fn unmark_held(node: &mut Node, r: &mut Run) {
    let Some(removed) = removal(r) else {
        return;
    };
    // An orphaned link has no active path left, so there is no pair to
    // clear, which is why the table reads its mark as the drain leaves it.
    debug_assert!(
        removed.why != Why::Orphaned || removed.held.is_none(),
        "an orphaned peer held a pair at its removal"
    );
    let c = cell(Row::BleMark, &r.t);
    if c == Cell::Cleared || c == Cell::OldClearedMarked || c == Cell::OldClearedMarkedAtFirstFrame
    {
        if removed.why == Why::Disconnect && node_fault!(DisconnectKeepsVerified) {
            return;
        }
        let held = removed.held.clone();
        node.relink(&r.peer, held, None).await;
    } else {
        debug_assert!(c == Cell::ClearedIfDrained, "a removal's mark is {c:?}");
    }
}

/// Close the transport's connection at the pair the peer was on, by the
/// table's cell. Where the cell queues only the unkept paths, the removal's
/// own release of the paths has done that.
pub(super) async fn close_held(node: &mut Node, r: &mut Run) {
    let Some(removed) = removal(r) else {
        return;
    };
    let c = cell(Row::Connection, &r.t);
    if c != Cell::UnkeptQueuedCurrentClosed {
        debug_assert!(c == Cell::UnkeptQueued, "a removal's connection is {c:?}");
        return;
    }
    // The removal frees every node-side structure but never touches the
    // transport, so on a connection-oriented transport the pool entry, the
    // socket and its inbound-slot accounting would otherwise survive the
    // peer the node has just forgotten: an operator who disconnects a peer
    // to free a slot would not free the slot. This mirrors
    // `cleanup_stale_connection`, and the reasoning there applies verbatim:
    // closing twice is harmless, because every `close_connection`
    // implementation is `if let Some(conn) = pool.remove(addr)` and the
    // connectionless default is a no-op.
    if !node_fault!(AdminKeepsConnection)
        && let Some((transport_id, addr)) = &removed.held
        && let Some(transport) = node.transports.get(transport_id)
    {
        transport.close_connection(addr).await;
    }
}

/// Note the link dead for a reconnect, or drop a pending one, by the
/// table's cell. A loss noted where the removal was decided is not noted
/// again. A replacement's retry is dropped by its promotion's install.
pub(super) async fn reconnect(node: &mut Node, r: &mut Run) {
    let Some(removed) = removal(r) else {
        return;
    };
    let c = cell(Row::Reconnect, &r.t);
    if c == Cell::NotedDeadThenRemoved {
        debug_assert!(
            removed.noted,
            "a replacement's loss is noted by the old peer's control machine"
        );
    } else if c == Cell::NotedDead {
        if !removed.noted {
            node.note_link_dead(r.peer, Node::peering_now());
        }
    } else if c == Cell::Removed {
        node.peering.reconciler.retry_pending.remove(&r.peer);
    } else {
        debug_assert!(c == Cell::Keep, "a removal's reconnect is {c:?}");
        if removed.why == Why::Ended && node_fault!(EndedSchedulesRetry) {
            node.note_link_dead(r.peer, Node::peering_now());
        }
    }
}
