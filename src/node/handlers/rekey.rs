//! The executors of the link and end-to-end session rekey machines.
//!
//! Each link's rekey machine decides its link's rekeys: it is polled on the
//! tick, starts and resends this node's rekeys, answers the peer's msg1,
//! completes on its msg2, cuts over and ends the drain, and the outputs it
//! returns there or from a msg1, msg2 or frame are carried out here.
//!
//! Each session's rekey machine runs its first handshake and decides its own
//! rekeys: it is polled on the tick, and the outputs it returns there or
//! from a session handshake message or frame are carried out here.

use crate::NodeAddr;
use crate::node::Node;
use crate::node::diag::{self, OrNone};
use crate::node::reject::{RejectReason, SessionReject};
use crate::node::session::{SessionInstant, SessionOutput, SessionOutputs};
use crate::peer::{LinkOutput, LinkOutputs, LinkProfile, peer_now};
use crate::proto::fsp::{SessionAck, SessionMsg3, SessionSetup};
use crate::proto::link::SessionDatagram;
use crate::proto::stp::{TreeCoordinate, coords_wire_size, encode_coords};
use crate::utils::index::SessionIndex;
use fips_core::proto::rekey::{
    Abandon, Config, DEPLOYED_SESSION_FLOOR, EpochTag, Input, MAX_AFTER, MsgKind, NodeKeys, Params,
    Purpose, Reason, RecordStore, RecvCopy, Role, Slot, msg1_span,
};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{debug, info, trace, warn};

/// The span of a link rekey's msg1 resend ladder, in milliseconds: the
/// offset of its last configured rung (31 s at the default five resends),
/// whether or not the rung falls inside the attempt's budget. A link rekey
/// is given up at the smaller of this span plus one tick and the handshake
/// timeout, so the span plus two ticks bounds how long one is in flight.
/// The handshake resend interval and backoff do not shape it.
fn ladder_ms(rate_limit: &crate::config::RateLimitConfig) -> u64 {
    let resends = u8::try_from(rate_limit.handshake_max_resends).unwrap_or(u8::MAX);
    u64::try_from(msg1_span(resends).as_millis()).unwrap_or(u64::MAX)
}

/// The longest silence, in milliseconds, the node tolerates on a link it
/// keeps.
///
/// A link rekey's msg1 resend ladder, three ticks of scheduling slack, and
/// the longer of one heartbeat interval and the link-dead timeout. The
/// link-dead reap is suppressed while this node's own rekey is in flight,
/// which the ladder term and two of the ticks cover. 64 s at stock
/// settings.
pub(in crate::node) fn link_silence_ms(node: &crate::config::NodeConfig) -> u64 {
    let after_ms = node
        .heartbeat_interval_secs
        .max(node.link_dead_timeout_secs)
        .saturating_mul(1000);
    ladder_ms(&node.rate_limit)
        .saturating_add(node.tick_interval_secs.saturating_mul(3000))
        .saturating_add(after_ms)
}

/// The inbound idle deadline for stream transports: how long an accepted
/// connection may go without delivering a complete frame once it has
/// delivered one.
///
/// Set to `link_silence_ms`, so a connection carrying a link the node would
/// keep is never dropped by it, whatever the heartbeat, link-dead, tick and
/// resend settings are; a connection carrying no live link is reclaimed.
pub(in crate::node) fn inbound_idle_timeout(
    node: &crate::config::NodeConfig,
) -> std::time::Duration {
    std::time::Duration::from_millis(link_silence_ms(node))
}

/// The parameters each link's rekey machine is built with, from the node's
/// configuration.
///
/// The rekey thresholds (`node.rekey.after_secs` and `after_messages`)
/// start the machine's own rekeys, none before the link is one tick past
/// the 30 s link age at which a peer answers a msg1 as a rekey and the
/// session one tick past the 30 s after its last cutover below which a
/// 0.5.0 to 0.5.2 peer does not; the resend count
/// (`node.rate_limit.handshake_max_resends`) sets the rungs its msg1 may be
/// resent at, 1, 3, 7, 15 and 31 s at the defaults, of which only those
/// before the attempt's end are sent: the attempt ends at the smaller of
/// one tick after the last rung and the handshake timeout, 30 s at the
/// defaults, and the next waits a back-off; the tick and the handshake
/// timeout bound the timers; the pending hold outlasts the drain ceiling, a
/// peer's retry after a lost answer and the link-silence bound
/// ([`Config::with_hold`]). The resend interval and backoff do not shape a
/// link rekey's msg1 ladder. A time trigger below the jitter plus the 30 s
/// link age at which a peer answers a msg1 as a rekey is raised to that
/// sum, and timers the machine refuses fall back to the link defaults,
/// each with a warning once.
pub(crate) fn link_params(node: &crate::config::NodeConfig) -> Params {
    static TIMERS_WARNED: AtomicBool = AtomicBool::new(false);
    static AFTER_WARNED: AtomicBool = AtomicBool::new(false);
    let base = Config::fmp();
    let configured = Config {
        handshake: Duration::from_secs(node.rate_limit.handshake_timeout_secs),
        check: Duration::from_secs(node.tick_interval_secs),
        resends: u8::try_from(node.rate_limit.handshake_max_resends).unwrap_or(u8::MAX),
        ..base
    }
    .with_hold(Duration::from_millis(link_silence_ms(node)));
    let timers = match Params::new(configured) {
        Ok(_) => configured,
        Err(e) => {
            if !TIMERS_WARNED.swap(true, Ordering::Relaxed) {
                warn!(
                    error = %e,
                    handshake_timeout_secs = node.rate_limit.handshake_timeout_secs,
                    tick_interval_secs = node.tick_interval_secs,
                    "Link rekey timers use the defaults: the configured handshake timeout and tick do not fit"
                );
            }
            base
        }
    };
    let floor = Duration::from_secs(u64::from(timers.jitter)).saturating_add(timers.link_age);
    let configured_after = Duration::from_secs(node.rekey.after_secs.min(MAX_AFTER));
    if configured_after < floor && !AFTER_WARNED.swap(true, Ordering::Relaxed) {
        warn!(
            after_secs = node.rekey.after_secs,
            used_secs = floor.as_secs(),
            "Link rekeys start no sooner than the jitter plus the 30 s link age at which a peer answers them"
        );
    }
    let triggered = Config {
        after: configured_after.max(floor),
        messages: node.rekey.after_messages.min(timers.soft),
        floor_link: timers.link_age.saturating_add(timers.check),
        floor_session: DEPLOYED_SESSION_FLOOR.saturating_add(timers.check),
        ..timers
    };
    // The configuration's validation refuses an interval at or below the
    // jitter and a message trigger of zero, so only a configuration built
    // without it reaches the fallback.
    Params::new(triggered).unwrap_or_else(|e| {
        warn!(error = %e, "Link rekeys use the default thresholds");
        Params::new(timers).expect("the link defaults are valid")
    })
}

/// The node's store of closed links' replay records, keeping twice as
/// many as the node may hold peers (twice the default peer cap when the
/// cap is off), so a peering re-formed with the same peer epoch while its
/// entry is kept recognises the msg1s the closed link saw.
pub(in crate::node) fn link_records(limits: &crate::config::LimitsConfig) -> RecordStore {
    let cap = match limits.max_peers {
        0 => crate::config::LimitsConfig::default().max_peers,
        n => n,
    };
    RecordStore::new(cap.saturating_mul(2))
}

/// What carrying out a link machine's outputs found, for the caller's own
/// counting and logging.
#[derive(Debug, Default)]
pub(in crate::node) struct LinkReport {
    /// The step bound a new pending session's index: the machine answered
    /// the peer's msg1, or completed this node's own rekey on its msg2.
    pub(in crate::node) pending: bool,
    /// The machine asked for the restart gates on the msg1 it was given.
    pub(in crate::node) replace: bool,
    /// The msg2s the machine asked to send in answer to the msg1 it was
    /// given, in order, for the caller to route as the msg1 arrived.
    pub(in crate::node) replies: Vec<Vec<u8>>,
    /// The slot a frame authenticated under and where its plaintext is.
    pub(in crate::node) delivered: Option<(Slot, Range<usize>)>,
    /// Why the input changed nothing (or only what its row names), in order.
    pub(in crate::node) rejects: Vec<Reason>,
    /// The peer was removed on the machine's teardown.
    pub(in crate::node) removed: bool,
}

impl Node {
    /// Poll every link's rekey machine now, and carry out what each asks
    /// for: its own rekey's start and msg1 resends and the abandon at the
    /// attempt deadline, the cutover to a pending session it completed, the
    /// drain's end, and the retirement of a pending session the peer never
    /// adopted. Each machine is polled on its own; the expiry pass inside
    /// one machine runs before its start pass, so its frees come before its
    /// allocations.
    pub(in crate::node) async fn poll_link_rekeys(&mut self) {
        let addrs: Vec<NodeAddr> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.has_session())
            .map(|(addr, _)| *addr)
            .collect();
        for addr in addrs {
            if let Some(out) = self.step_link(&addr, Input::Poll) {
                self.run_link_step(&addr, out).await;
            }
        }
    }

    /// Step `node_addr`'s link rekey machine with `input` now, lending it
    /// the node's index allocator and keys and the decrypt-worker fact.
    /// `None` when no such peer is held.
    pub(in crate::node) fn step_link(
        &mut self,
        node_addr: &NodeAddr,
        input: Input<'_, LinkProfile>,
    ) -> Option<LinkOutputs> {
        let local = self.session_node_keys();
        let workers = self.link_workers();
        let peer = self.peers.get_mut(node_addr)?;
        Some(peer.step_link(
            peer_now(),
            input,
            &mut self.index_allocator,
            &local,
            workers,
        ))
    }

    /// Whether a decrypt-worker pool exists now, to which a link's new
    /// current session is offered at a cutover.
    pub(in crate::node) fn link_workers(&self) -> bool {
        #[cfg(unix)]
        return self.supervisor.decrypt_workers.is_some();
        #[cfg(not(unix))]
        return false;
    }

    /// Carry out the outputs a step of `node_addr`'s link rekey machine
    /// returned, front to back, and report what the caller still has to
    /// act on: the msg2s answering a msg1, which go where the msg1 came
    /// from, a frame's delivery, the rejects, and a request for the restart
    /// gates. A send the transport refuses is loss: the machine is never
    /// told, and its deadlines bound what the loss costs.
    pub(in crate::node) async fn run_link_step(
        &mut self,
        node_addr: &NodeAddr,
        out: LinkOutputs,
    ) -> LinkReport {
        let mut report = LinkReport::default();
        let started = out.iter().any(|o| {
            matches!(
                o,
                LinkOutput::Bind {
                    purpose: Purpose::Attempt,
                    ..
                }
            )
        });
        let mut last_release = None;
        for output in out {
            match output {
                LinkOutput::Send { msg, kind, .. } => match kind {
                    MsgKind::Msg1 => self.send_link_msg1(node_addr, &msg, started).await,
                    MsgKind::Msg2 => report.replies.push(msg),
                    MsgKind::Setup | MsgKind::Ack | MsgKind::Msg3 => {
                        debug_assert!(false, "a link machine sent {kind:?}");
                    }
                },
                LinkOutput::Prompt { tag } => self.send_link_prompt(node_addr, tag).await,
                LinkOutput::Deliver { slot, range, .. } => report.delivered = Some((slot, range)),
                LinkOutput::Installed { role, .. } => self.link_cutover(node_addr, role),
                LinkOutput::Retired { .. } => {
                    if let Some(index) = last_release.take() {
                        trace!(
                            peer = %self.peer_display_name(node_addr),
                            index = %index,
                            "Rekey session retired, its index released"
                        );
                    }
                }
                // Reported after the cutover's `Installed`, so the
                // announces the reset sends are sealed under the session
                // the restarted peer holds.
                LinkOutput::PeerRestarted { epoch, .. } => {
                    self.reset_restarted(node_addr, epoch).await;
                }
                LinkOutput::ReplaceRequested { .. } => report.replace = true,
                LinkOutput::Reject(reason) => report.rejects.push(reason),
                LinkOutput::Abandoned(cause) => self.log_link_abandon(node_addr, cause),
                LinkOutput::Teardown(why) => {
                    warn!(
                        peer = %self.peer_display_name(node_addr),
                        reason = ?why,
                        "Link rekey machine ended the link"
                    );
                    self.remove_active_peer(node_addr);
                    report.removed = true;
                    return report;
                }
                // A msg1 this node answered may be the peer's redial after it
                // dropped the old peering and this node's filter with it,
                // which the record of the filter last sent cannot show, so
                // the filter goes again on the session the peer now holds.
                LinkOutput::Rekeyed {
                    role: Role::Responder,
                } => self.bloom_state.mark_update_needed(*node_addr),
                LinkOutput::Rekeyed {
                    role: Role::Initiator,
                } => {}
                LinkOutput::Reverted { .. } => {}
                LinkOutput::Bind { purpose, .. } => {
                    report.pending |= purpose == Purpose::Pending;
                    self.run_link_outputs(node_addr, vec![output]);
                }
                LinkOutput::Release(ref lease) => {
                    last_release = Some(SessionIndex::new(lease.index()));
                    self.run_link_outputs(node_addr, vec![output]);
                }
                LinkOutput::Unbind { .. }
                | LinkOutput::Delegate { .. }
                | LinkOutput::Revoke { .. } => {
                    self.run_link_outputs(node_addr, vec![output]);
                }
            }
        }
        report
    }

    /// The link layer's routine for a peer restart its rekey revealed: the
    /// link is kept, on the session the restarted peer already holds, and
    /// everything held about the process that has gone is dropped. The
    /// end-to-end session with the peer is closed, with the clamp entry it
    /// tightened; the peer's tree declaration and filter are forgotten, so
    /// its announces, whose sequence numbers began again, are accepted; and
    /// this node's tree and filter are announced to it again, since it holds
    /// neither. The link's MMP was reset by the cutover that reported the
    /// restart, as at every cutover.
    async fn reset_restarted(&mut self, node_addr: &NodeAddr, epoch: [u8; 8]) {
        info!(
            peer = %self.peer_display_name(node_addr),
            epoch = %hex::encode(epoch),
            "Peer restart detected during FMP rekey, resetting what was held for its previous run"
        );
        if self.close_session(node_addr) {
            debug!(
                peer = %self.peer_display_name(node_addr),
                "Closed stale FSP session after peer restart during FMP rekey"
            );
        }
        if let Some(peer) = self.peers.get_mut(node_addr) {
            peer.clear_tree_position();
            peer.clear_filter();
        }
        if self.handle_peer_removal_tree_cleanup(node_addr) {
            for (addr, peer) in self.peers.iter_mut() {
                if addr != node_addr {
                    peer.mark_tree_announce_pending();
                }
            }
        }
        // The forgotten filter may have been part of what this node
        // announces to every peer, and the restarted peer holds none of
        // its filters.
        self.bloom_state.forget_sent(node_addr);
        let peers: Vec<NodeAddr> = self.peers.keys().copied().collect();
        self.bloom_state.mark_all_updates_needed(peers);
        if let Err(e) = self.send_tree_announce_to_peer(node_addr).await {
            debug!(
                peer = %self.peer_display_name(node_addr),
                error = %e,
                "Failed to send TreeAnnounce after peer restart"
            );
        }
    }

    /// Close the end-to-end session with `addr` and what describes it: its
    /// queued packets and the path MTU learned for `addr`, which gives way
    /// to the link seed when `addr` is a direct peer. Returns whether a
    /// session was held.
    pub(in crate::node) fn close_session(&mut self, addr: &NodeAddr) -> bool {
        let entry = self.sessions.remove(addr);
        if let Some(mmp) = entry.as_ref().and_then(|e| e.mmp()) {
            Self::log_session_mmp_teardown(&self.peer_display_name(addr), mmp);
        }
        self.pending_tun_packets.remove(addr);
        self.path_mtu_lookup_release(addr);
        entry.is_some()
    }

    /// Send `node_addr`'s rekey msg1 on its link, without dialing: the first
    /// copy of an attempt when `first`, else a resend. A copy the transport
    /// refuses is lost, as one the network drops would be.
    async fn send_link_msg1(&mut self, node_addr: &NodeAddr, msg1: &[u8], first: bool) {
        let Some(peer) = self.peers.get(node_addr) else {
            return;
        };
        let (Some(transport_id), Some(remote_addr)) =
            (peer.transport_id(), peer.current_addr().cloned())
        else {
            return;
        };
        let link_id = peer.link_id();
        let Some(transport) = self.transports.get(&transport_id) else {
            return;
        };
        match self
            .send_nowait(transport, link_id, &remote_addr, msg1)
            .await
        {
            Ok(_) if first => debug!(
                peer = %self.peer_display_name(node_addr),
                "Rekey initiated, sent msg1 on existing link"
            ),
            Ok(_) => trace!(
                peer = %self.peer_display_name(node_addr),
                "Resent rekey msg1"
            ),
            Err(e) if e.is_transient() => debug!(
                peer = %self.peer_display_name(node_addr),
                error = %e,
                "Deferred rekey msg1: the transport is between interfaces"
            ),
            Err(e) => warn!(
                peer = %self.peer_display_name(node_addr),
                error = %e,
                first,
                "Failed to send rekey msg1"
            ),
        }
    }

    /// Seal the link prompt (a heartbeat) under `node_addr`'s session `tag`
    /// and send it on the link, without dialing. A prompt the machine
    /// refuses to seal, or the transport refuses to send, is logged and
    /// lost.
    async fn send_link_prompt(&mut self, node_addr: &NodeAddr, tag: EpochTag) {
        use crate::proto::fmp::wire::{FLAG_KEY_EPOCH, build_encrypted, build_established_header};
        let Some(peer) = self.peers.get_mut(node_addr) else {
            return;
        };
        let (Some(transport_id), Some(remote_addr)) =
            (peer.transport_id(), peer.current_addr().cloned())
        else {
            return;
        };
        let link_id = peer.link_id();
        let prompt = match peer.seal_prompt(peer_now(), tag) {
            Ok(p) => p,
            Err(e) => {
                debug!(
                    peer = %self.peer_display_name(node_addr),
                    refusal = ?e,
                    "Link rekey prompt not sealed"
                );
                return;
            }
        };
        let sealed = prompt.sealed;
        let theirs = SessionIndex::new(sealed.theirs.unwrap_or_default());
        let flags = if sealed.k { FLAG_KEY_EPOCH } else { 0 };
        let header =
            build_established_header(theirs, sealed.counter, flags, prompt.plaintext.len() as u16);
        let Ok(ciphertext) =
            fips_core::noise::seal(sealed.key.key(), sealed.counter, &header, &prompt.plaintext)
        else {
            return;
        };
        let wire = build_encrypted(&header, &ciphertext);
        let Some(transport) = self.transports.get(&transport_id) else {
            return;
        };
        if let Err(e) = self
            .send_nowait(transport, link_id, &remote_addr, &wire)
            .await
        {
            debug!(
                peer = %self.peer_display_name(node_addr),
                error = %e,
                "Failed to send link rekey prompt"
            );
        }
    }

    /// Run the shell's part of a cutover `node_addr`'s link machine made as
    /// `role`, and log it.
    fn link_cutover(&mut self, node_addr: &NodeAddr, role: Role) {
        let name = self.peer_display_name(node_addr);
        let Some(peer) = self.peers.get_mut(node_addr) else {
            return;
        };
        peer.after_cutover();
        let epoch = OrNone(peer.noise_session().map(diag::epoch_tag));
        let kbit_ours = peer.current_k_bit();
        match role {
            Role::Initiator => debug!(
                peer = %name,
                epoch = %epoch,
                kbit_ours,
                "Rekey cutover complete (initiator), K-bit flipped"
            ),
            // The adopting frame's K-bit is the one the new session takes.
            Role::Responder => debug!(
                peer = %name,
                epoch = %epoch,
                kbit_frame = kbit_ours,
                kbit_ours,
                "Peer new-epoch frame authenticated, K-bit flip promoting new session"
            ),
        }
    }

    /// Log an attempt or held session `node_addr`'s link machine gave up.
    fn log_link_abandon(&self, node_addr: &NodeAddr, cause: Abandon) {
        let peer = self.peer_display_name(node_addr);
        match cause {
            Abandon::Unanswered => debug!(
                peer = %peer,
                "FMP rekey aborted: msg1 unconfirmed after max retransmissions, abandoning cycle"
            ),
            Abandon::Yielded => debug!(
                peer = %peer,
                "Dual rekey initiation: we lose (larger addr), abandoning ours"
            ),
            Abandon::Unadopted => debug!(
                peer = %peer,
                "Rekey pending session retired: the initiator never adopted it"
            ),
            other => debug!(peer = %peer, cause = ?other, "Link rekey abandoned"),
        }
    }

    /// Carry out the outputs of `node_addr`'s link rekey machine that change
    /// the node's index maps and worker registrations, front to back: bind
    /// and unbind its indices in `peers_by_index` by index alone, offer receive halves to the decrypt workers and tell
    /// the machine which ones a worker accepted, revoke them, and free
    /// released indices. The one place a link's index maps and worker
    /// registrations change. The outputs of a `close`, a link's promotion
    /// and a cross-connection move are all of this kind.
    pub(in crate::node) fn run_link_outputs(&mut self, node_addr: &NodeAddr, out: LinkOutputs) {
        for output in out {
            match output {
                LinkOutput::Bind { index, .. } => {
                    self.peers_by_index.insert(index, *node_addr);
                }
                LinkOutput::Unbind { index, .. } => {
                    self.peers_by_index.remove(&index);
                }
                LinkOutput::Delegate {
                    tag, index, recv, ..
                } => self.delegate_link_epoch(node_addr, tag, index, recv),
                LinkOutput::Revoke { index, .. } => {
                    #[cfg(unix)]
                    self.unregister_decrypt_worker_session(index);
                    #[cfg(not(unix))]
                    let _ = index;
                }
                LinkOutput::Release(lease) => {
                    let _ = self
                        .index_allocator
                        .free(SessionIndex::new(lease.release()));
                }
                // None of these comes from a close, a promotion or a move;
                // a step's are carried out by `run_link_step`.
                LinkOutput::Retired { .. }
                | LinkOutput::Installed { .. }
                | LinkOutput::Reverted { .. }
                | LinkOutput::Rekeyed { .. }
                | LinkOutput::PeerRestarted { .. }
                | LinkOutput::Reject(_)
                | LinkOutput::Abandoned(_)
                | LinkOutput::Teardown(_)
                | LinkOutput::Send { .. }
                | LinkOutput::Prompt { .. }
                | LinkOutput::Deliver { .. }
                | LinkOutput::ReplaceRequested { .. } => {}
            }
        }
    }

    /// Hand the receive half `recv` of `node_addr`'s session `tag` to a
    /// shard of the decrypt worker pool under `cache_key`, and step the
    /// peer's machine with the acceptance when the worker accepts it, before
    /// any other input reaches it. A `TrySendError::Full` on the per-worker
    /// channel leaves the session with the machine, so it is not
    /// black-holed. A no-op without a worker pool.
    #[cfg_attr(not(unix), allow(unused_variables))]
    fn delegate_link_epoch(
        &mut self,
        node_addr: &NodeAddr,
        tag: EpochTag,
        cache_key: u32,
        recv: RecvCopy,
    ) {
        #[cfg(unix)]
        {
            let Some(workers) = self.supervisor.decrypt_workers.as_ref().cloned() else {
                return;
            };
            let Some(fmp_cipher) = recv.key else {
                return;
            };
            let state = crate::node::decrypt_worker::OwnedSessionState {
                fmp_cipher,
                fmp_replay: recv.window,
                source_npub: None,
            };
            if workers.register_session(cache_key, state) {
                self.decrypt_registered_sessions.insert(cache_key);
                let accepted = Input::Delegated { tag, only: () };
                for output in self.step_link(node_addr, accepted).unwrap_or_default() {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        output = ?output,
                        "Link rekey machine refused a decrypt worker's acceptance"
                    );
                }
            }
        }
    }

    /// Poll every session's rekey machine at `now`, and carry out what each
    /// asks for: its first setup's resends and its retained msg3's, the
    /// end of an unanswered first attempt or of a session whose candidates
    /// all expired, its rekey msg3 resends with their probes, its keepalives
    /// and prompt repeats, and the cutover, revert and drain end it reports.
    pub(in crate::node) async fn poll_session_rekeys(&mut self, now: SessionInstant) {
        if self.sessions.is_empty() {
            return;
        }
        let local = self.session_node_keys();
        let addrs: Vec<NodeAddr> = self.sessions.keys().copied().collect();
        for addr in addrs {
            self.poll_session(&addr, now, &local).await;
        }
    }

    /// Poll `addr`'s session rekey machine at `now` if one of its deadlines
    /// or start instants has already come, before a SessionSetup is admitted
    /// and stepped into it. The 1 s tick can process a deadline up to a
    /// second late, and a setup judged in that second meets a state the
    /// deadline has ended: the smaller node, its completed rekey past its
    /// confirmation deadline or its final msg3 rung, would refuse the setup
    /// to keep a completed handshake the deadline gives up. A deployed peer
    /// sends its rekey setup once, so the refusal costs the rotation it
    /// starts. A start instant that has come starts this node's own rekey
    /// before the setup is judged, as a shell polling at the machine's next
    /// wake would have done before the setup arrived; the poll is all of the
    /// machine's due work or none of it, so it cannot take the deadlines
    /// alone.
    pub(in crate::node) async fn poll_overdue(&mut self, addr: &NodeAddr, now: SessionInstant) {
        if self.sessions.get(addr).is_some_and(|e| e.wake_due(now)) {
            let local = self.session_node_keys();
            self.poll_session(addr, now, &local).await;
        }
    }

    /// Poll `addr`'s session rekey machine at `now` and carry out what it
    /// asks for, telling it first whether a next hop toward the peer exists.
    async fn poll_session(&mut self, addr: &NodeAddr, now: SessionInstant, local: &NodeKeys) {
        let reachable = self.find_next_hop(addr).is_some();
        let Some(entry) = self.sessions.get_mut(addr) else {
            return;
        };
        let opening = !entry.is_established();
        let out = entry.poll_rekey(now, reachable, local);
        self.run_session_outputs(addr, out, opening).await;
    }

    /// Carry out the outputs of `addr`'s session rekey machine, front to
    /// back; `opening` says the session's first handshake was still open
    /// when the call that produced them began. A send the transport refuses
    /// is loss: the machine is never told, and its deadlines bound what the
    /// loss costs.
    pub(in crate::node) async fn run_session_outputs(
        &mut self,
        addr: &NodeAddr,
        out: SessionOutputs,
        opening: bool,
    ) {
        self.run_session_outputs_answering(addr, out, opening, None)
            .await;
    }

    /// Carry out the outputs of `addr`'s session rekey machine as
    /// [`Node::run_session_outputs`] does, where a SessionAck answers a
    /// setup that carried the initiator's coordinates `answering`.
    pub(in crate::node) async fn run_session_outputs_answering(
        &mut self,
        addr: &NodeAddr,
        out: SessionOutputs,
        opening: bool,
        answering: Option<&TreeCoordinate>,
    ) {
        for output in out {
            self.run_session_output(addr, output, opening, answering)
                .await;
        }
    }

    /// Carry out one output of `addr`'s session rekey machine, from a call
    /// that began with the first handshake open when `opening`; a
    /// SessionAck carries `answering` as the initiator's coordinates.
    async fn run_session_output(
        &mut self,
        addr: &NodeAddr,
        output: SessionOutput,
        opening: bool,
        answering: Option<&TreeCoordinate>,
    ) {
        use fips_core::proto::rekey::{Abandon, EvidenceKind, Output, Reason, Role};
        match output {
            Output::Send { msg, kind, .. } => {
                if opening
                    && kind == MsgKind::Setup
                    && let Some(entry) = self.sessions.get_mut(addr)
                {
                    entry.note_setup_sent();
                }
                // A send the transport refuses is loss, which the
                // machine's resends and deadlines recover.
                let _ = self.send_rekey_message(addr, msg, kind, answering).await;
            }
            Output::Prompt { tag } => self.send_session_prompt(addr, tag).await,
            // The handler that completed the first handshake logs the
            // session's establishment, after the packets held for it go.
            Output::Installed {
                evidence: EvidenceKind::First,
                ..
            } => {}
            Output::Installed {
                tag,
                role,
                evidence,
            } => {
                // The wording is the one operators' log searches and the
                // rekey and interop suites count cutovers by.
                let peer = self.peer_display_name(addr);
                match role {
                    Role::Initiator => debug!(
                        %peer,
                        epoch = tag.get(),
                        ?evidence,
                        "FSP rekey cutover complete (initiator), new session keys current"
                    ),
                    Role::Responder => debug!(
                        %peer,
                        epoch = tag.get(),
                        ?evidence,
                        "FSP rekey cutover complete (responder), new session keys current"
                    ),
                }
            }
            Output::Retired { tag } => {
                trace!(
                    peer = %self.peer_display_name(addr),
                    epoch = tag.get(),
                    "FSP session keys erased"
                );
            }
            Output::Reverted { tag } => {
                info!(
                    peer = %self.peer_display_name(addr),
                    epoch = tag.get(),
                    "FSP peer heard under the previous keys after an assumed cutover, new keys back to waiting"
                );
            }
            Output::Abandoned(Abandon::Unanswered) if opening => {
                debug!(
                    peer = %self.peer_display_name(addr),
                    "Session setup got no answer within the handshake timeout"
                );
            }
            Output::Abandoned(Abandon::Yielded) if opening => {
                debug!(
                    peer = %self.peer_display_name(addr),
                    "Simultaneous session initiation: our attempt gave way to the peer's completed one"
                );
            }
            Output::Abandoned(Abandon::Unanswered) => {
                self.stats_mut().session.rekey_unanswered += 1;
                info!(
                    peer = %self.peer_display_name(addr),
                    "FSP rekey we initiated got no answer within the handshake timeout, session retained"
                );
            }
            Output::Abandoned(Abandon::Yielded) => {
                self.stats_mut()
                    .record_reject(RejectReason::Session(SessionReject::RekeyYielded));
                debug!(
                    peer = %self.peer_display_name(addr),
                    "FSP rekey we initiated yielded to the peer's completed rekey"
                );
            }
            Output::Abandoned(why) => {
                debug!(
                    peer = %self.peer_display_name(addr),
                    ?why,
                    "FSP rekey given up"
                );
            }
            Output::Reject(Reason::CandidateExpired) if opening => {
                debug!(
                    peer = %self.peer_display_name(addr),
                    "Session setup answered for the peer expired without msg3"
                );
            }
            Output::Reject(Reason::KeyMismatch) if opening => {
                // A session the peer's setups opened is bonded to the address
                // they claimed: a msg3 authenticating a key that address is
                // not derived from proves only that its candidate was forged,
                // and only it goes. A forger reaches this once per candidate,
                // so it logs at debug.
                self.stats_mut()
                    .record_reject(RejectReason::Session(SessionReject::AddrMismatch));
                debug!(
                    src = %self.peer_display_name(addr),
                    reason = "addr-mismatch",
                    "SessionMsg3 source address does not match the authenticated static key, dropping its candidate"
                );
            }
            Output::Reject(Reason::CandidateExpired) => {
                self.stats_mut().session.rekey_expired += 1;
                info!(
                    peer = %self.peer_display_name(addr),
                    "FSP rekey setup answered for the peer expired without msg3, session retained"
                );
            }
            Output::Reject(reason) => {
                if let Some(counted) = session_reject(reason, opening) {
                    self.stats_mut()
                        .record_reject(RejectReason::Session(counted));
                }
                if reason == Reason::KeyMismatch {
                    warn!(
                        peer = %self.peer_display_name(addr),
                        "FSP rekey: initiator static key differs from the established peer key"
                    );
                }
                trace!(
                    peer = %self.peer_display_name(addr),
                    ?reason,
                    "FSP rekey input changed nothing"
                );
            }
            // The rekey that reported the restart has already repaired the
            // session: the old keys are retired and the session MMP is
            // per epoch, so only the count and the log are left to do.
            Output::PeerRestarted { epoch, .. } => {
                self.stats_mut().session.peer_restarted += 1;
                info!(
                    peer = %self.peer_display_name(addr),
                    epoch = %hex::encode(epoch),
                    "FSP peer restarted, session rekeyed under its new startup epoch"
                );
            }
            Output::Teardown(why) => {
                let name = self.peer_display_name(addr);
                self.close_session(addr);
                if opening {
                    info!(dest = %name, ?why, "Session handshake timed out, removing");
                } else {
                    info!(dest = %name, ?why, "FSP session closed by its rekey machine");
                }
            }
            // A session cutover carries nothing other layers resend, a
            // frame's delivery is the receive path's, and a session machine
            // holds no index, worker copy or link-setup msg1.
            Output::Rekeyed { .. }
            | Output::Deliver { .. }
            | Output::Bind { .. }
            | Output::Unbind { .. }
            | Output::Delegate { .. }
            | Output::Revoke { .. }
            | Output::Release(_)
            | Output::ReplaceRequested { .. } => {}
        }
    }

    /// Send the session handshake message `msg` the rekey machine of `addr`
    /// asked for, wrapped in its session message with the coordinates of
    /// now: a SessionSetup toward the coordinates cached for `addr` (a direct
    /// peer's announced ones on a miss, as the dial does), a SessionAck
    /// toward the setup's own coordinates `answering`, a SessionMsg3 bare.
    /// Returns whether it left, for the one caller that keeps a session
    /// only if its first setup did.
    pub(in crate::node) async fn send_rekey_message(
        &mut self,
        addr: &NodeAddr,
        msg: Vec<u8>,
        kind: MsgKind,
        answering: Option<&TreeCoordinate>,
    ) -> Result<(), crate::node::NodeError> {
        let our_coords = self.tree_state.my_coords().clone();
        let payload = match kind {
            MsgKind::Msg3 => SessionMsg3::new(msg).encode(),
            MsgKind::Setup => {
                // The wire needs non-empty destination coordinates, and on a
                // cache miss our own would be filed under the destination's
                // address by every node on the path. Routing never refreshes
                // a direct peer's cache entry, so fall back to the
                // coordinates a direct peer announced. Only a destination
                // that is neither cached nor an announced direct peer gets
                // ours, as a first setup always has; the destination answers
                // with its own.
                let dest_coords = self
                    .cached_dest_coords(addr)
                    .or_else(|| self.tree_state.peer_coords(addr).cloned())
                    .unwrap_or_else(|| our_coords.clone());
                SessionSetup::new(our_coords, dest_coords)
                    .with_handshake(msg)
                    .encode()
            }
            MsgKind::Ack => {
                let Some(dest_coords) = answering.cloned() else {
                    debug!(
                        peer = %self.peer_display_name(addr),
                        "FSP SessionAck with no setup to answer, dropping"
                    );
                    return Ok(());
                };
                SessionAck::new(our_coords, dest_coords)
                    .with_handshake(msg)
                    .encode()
            }
            MsgKind::Msg1 | MsgKind::Msg2 => {
                debug!(
                    peer = %self.peer_display_name(addr),
                    ?kind,
                    "FSP session machine asked for a link handshake message, dropping"
                );
                return Ok(());
            }
        };
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *addr, payload)
            .with_ttl(self.config().node.session.default_ttl);
        let sent = self.send_session_datagram(&mut datagram).await;
        match &sent {
            Ok(()) => {
                trace!(peer = %self.peer_display_name(addr), ?kind, "Sent FSP handshake message")
            }
            Err(e) => debug!(
                peer = %self.peer_display_name(addr),
                ?kind,
                error = %e,
                "FSP handshake message not sent, counted as lost"
            ),
        }
        sent
    }

    /// Seal and send the prompt the rekey machine of `addr` asked for under
    /// the epoch `tag`: a CoordsWarmup, carrying the destination's cached
    /// coordinates, or else the ones the peer's own handshake message
    /// carried, or else the ones a direct peer announced.
    async fn send_session_prompt(&mut self, addr: &NodeAddr, tag: EpochTag) {
        let now = Self::session_now();
        let Some(entry) = self.sessions.get_mut(addr) else {
            return;
        };
        let prompt = match entry.seal_prompt(now, tag) {
            Ok(prompt) => prompt,
            Err(e) => {
                debug!(
                    peer = %self.peer_display_name(addr),
                    error = ?e,
                    "FSP rekey prompt not sealed"
                );
                return;
            }
        };
        let dest_coords = self
            .cached_dest_coords(addr)
            .or_else(|| prompt.route.clone())
            .or_else(|| self.tree_state.peer_coords(addr).cloned());
        let Some(dest_coords) = dest_coords else {
            debug!(
                peer = %self.peer_display_name(addr),
                "FSP rekey prompt has no destination coordinates, counted as lost"
            );
            return;
        };
        let my_coords = self.tree_state.my_coords().clone();
        let coords_size = coords_wire_size(&my_coords) + coords_wire_size(&dest_coords);
        let mut fsp_payload =
            Vec::with_capacity(prompt.header.len() + coords_size + prompt.ciphertext.len());
        fsp_payload.extend_from_slice(&prompt.header);
        encode_coords(&my_coords, &mut fsp_payload);
        encode_coords(&dest_coords, &mut fsp_payload);
        fsp_payload.extend_from_slice(&prompt.ciphertext);
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *addr, fsp_payload)
            .with_ttl(self.config().node.session.default_ttl);
        if let Err(e) = self.send_session_datagram(&mut datagram).await {
            debug!(
                peer = %self.peer_display_name(addr),
                error = %e,
                "FSP rekey prompt not sent, counted as lost"
            );
            return;
        }
        if prompt.measured
            && let Some(entry) = self.sessions.get_mut(addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            mmp.sender
                .record_sent(prompt.counter, prompt.timestamp, prompt.ciphertext.len());
        }
        trace!(peer = %self.peer_display_name(addr), "Sent FSP rekey prompt");
    }
}

/// The session reject counter a machine refusal is counted under, for the
/// refusals one input alone can produce, from a call that began with the
/// first handshake open when `opening`. A tie-break refusal is counted by
/// the handler that knows which message met it, and the first handshake's
/// refusals of setups count nothing, as its candidates' expiries do not.
fn session_reject(reason: fips_core::proto::rekey::Reason, opening: bool) -> Option<SessionReject> {
    use fips_core::proto::rekey::Reason;
    match reason {
        Reason::CandidatesFull if !opening => Some(SessionReject::RekeyHeld),
        Reason::ReplyUnauthenticated => Some(SessionReject::AckHandshakeFailed),
        Reason::UnknownAttempt | Reason::LateReply => Some(SessionReject::BadState),
        Reason::KeyMismatch if !opening => Some(SessionReject::RekeyKeyMismatch),
        _ => None,
    }
}
