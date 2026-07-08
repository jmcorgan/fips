//! Sans-IO MMP (metrics protocol) reporting decision core.
//!
//! Pure, runtime-agnostic report-fan-out / liveness / heartbeat decisions,
//! migrated out of the async node shell. The async I/O adapters in
//! `node::handlers::mmp` build the per-entity snapshots over live node state
//! (pre-computing every clock read into plain `bool` snapshot fields, and
//! resolving the rekey-suppression predicate shell-side), call the `plan_*`
//! decisions, and drive the returned [`MmpAction`]s — the actual sends,
//! registry mutations, `proto/mmp/` primitive calls, metrics, and logging. No
//! I/O, no clock, no metrics, no logging here.
//!
//! Unlike routing/discovery (whose cores do live cross-table reads through a
//! `RoutingView`), MMP's decisions are per-entity over data the shell's collect
//! loop already snapshots, so the read-seam is the **snapshot vector** (the
//! FMP-style injected-snapshot form), not a live trait.

use alloc::collections::BTreeMap;

use super::MmpMode;
use super::state::Mmp;
use crate::NodeAddr;

/// A snapshot of one active peer's liveness/heartbeat-relevant state, taken by
/// the shell so the core decides without touching live `Node` state or reading
/// a clock.
///
/// Every clock read is resolved shell-side into a plain `bool` before the
/// snapshot reaches the core: `time_dead` is the pre-evaluated dead-timeout
/// predicate (monotonic `Instant` delta since last receive or session start),
/// `heartbeat_due` is the pre-evaluated heartbeat-interval predicate, and
/// `rekey_active` is the pre-evaluated FMP rekey-suppression predicate. The
/// core applies only the reap-vs-heartbeat precedence with **no** clock read.
pub(crate) struct PeerLivenessSnapshot {
    /// The peer's node address (reap / heartbeat target).
    pub peer: NodeAddr,
    /// The peer has not sent a frame within the link dead timeout
    /// (`now - (last_recv | session_start) >= dead_timeout`).
    pub time_dead: bool,
    /// An FMP rekey handshake is genuinely in flight with retransmission budget
    /// left; suppresses teardown of an otherwise-silent rekey link.
    pub rekey_active: bool,
    /// A heartbeat is due (`last_heartbeat_sent` is none, or elapsed since it is
    /// >= the heartbeat interval).
    pub heartbeat_due: bool,
}

/// A snapshot of one active peer's link-layer report-gating state, taken by the
/// shell so the core decides the report fan-out without touching live `Node`
/// state or reading a clock.
///
/// Every timing read is resolved shell-side into a plain `bool`: `sr_due` /
/// `rr_due` are the pre-evaluated `should_send_report` gates on the peer's
/// `proto/mmp/` sender/receiver primitives, and `log_due` is the pre-evaluated
/// `should_log` gate. `send_sr`/`send_rr` are the profile provide/want flags:
/// on the master (IK) line there is no profile negotiation, so the shell sets
/// them to the behavior-neutral constant `true` (ANDing a runtime `true` is a
/// no-op); the forward-merge to `-next` wires them to `peer.send_sr()`/
/// `peer.send_rr()` (plan §7.3 spot c).
pub(crate) struct LinkReportSnapshot {
    /// The peer's node address (report target).
    pub peer: NodeAddr,
    /// The peer's MMP reporting mode (gates which reports are eligible).
    pub mode: MmpMode,
    /// The peer's profile provides/wants a SenderReport. Constant `true` on the
    /// master line (no profile negotiation); the forward-merge wires this to the
    /// profile predicate.
    pub send_sr: bool,
    /// The peer's profile provides/wants a ReceiverReport. See `send_sr`.
    pub send_rr: bool,
    /// A SenderReport is due (`mmp.sender.should_send_report(now)`).
    pub sr_due: bool,
    /// A ReceiverReport is due (`mmp.receiver.should_send_report(now)`).
    pub rr_due: bool,
    /// A periodic operator log is due (`mmp.should_log(now)`).
    pub log_due: bool,
}

/// A snapshot of one active session's report-gating state, taken by the shell
/// so the core decides the session fan-out without touching live `Node` state or
/// reading a clock.
///
/// Every timing read is resolved shell-side into a plain `bool`: `sr_due` /
/// `rr_due` are the pre-evaluated `should_send_report` gates on the session's
/// `proto/mmp/` sender/receiver primitives, `mtu_due` is the pre-evaluated
/// `path_mtu.should_send_notification` gate, and `log_due` is the pre-evaluated
/// `should_log` gate. Unlike the link path there is **no** `send_sr`/`send_rr`
/// profile flag — the session handler has never gated on a profile, so no
/// forward-merge fold applies here.
pub(crate) struct SessionReportSnapshot {
    /// The session peer's node address (report target).
    pub dest: NodeAddr,
    /// The session's MMP reporting mode (gates which reports are eligible).
    pub mode: MmpMode,
    /// A SenderReport is due (`mmp.sender.should_send_report(now)`).
    pub sr_due: bool,
    /// A ReceiverReport is due (`mmp.receiver.should_send_report(now)`).
    pub rr_due: bool,
    /// A PathMtuNotification is due
    /// (`mmp.path_mtu.should_send_notification(now)`). Gated in **all** modes.
    pub mtu_due: bool,
    /// A periodic operator log is due (`mmp.should_log(now)`).
    pub log_due: bool,
}

/// Which link-layer report the shell should build/encode/send for a
/// [`SendLinkReport`](MmpAction::SendLinkReport) action.
pub(crate) enum LinkReportKind {
    /// A SenderReport (Full mode only): `mmp.sender.build_report(now)`.
    Sender,
    /// A ReceiverReport (Full and Lightweight modes):
    /// `mmp.receiver.build_report(now)`.
    Receiver,
}

/// Which session-layer report the shell should build/encode/send for a
/// [`SendSessionReport`](MmpAction::SendSessionReport) action.
pub(crate) enum SessionReportKind {
    /// A SessionSenderReport (Full mode only): `mmp.sender.build_report(now)`.
    Sender,
    /// A SessionReceiverReport (Full and Lightweight modes):
    /// `mmp.receiver.build_report(now)`.
    Receiver,
    /// A PathMtuNotification (all modes): `mmp.path_mtu.build_notification(now)`.
    PathMtu,
}

/// The outcome of one session-report send, collected by the shell while driving
/// the [`SendSessionReport`](MmpAction::SendSessionReport) actions, and fed back
/// into [`Mmp::plan_backoff`] for the per-destination backoff dedup.
pub(crate) struct SendResult {
    /// The destination the report was sent to.
    pub dest: NodeAddr,
    /// Whether `send_session_msg` succeeded.
    pub ok: bool,
}

/// The per-destination backoff decision produced by [`Mmp::plan_backoff`] from a
/// tick's [`SendResult`]s, deduplicating multiple reports to the same
/// destination into a single success/failure verdict.
///
/// The core carries no failure count: the pre-refactor "Resumed session MMP
/// reporting" log fires on the `prev` value **returned by** `record_send_success`
/// (the previous consecutive-failure count), which is shell-owned mutation state.
/// So `Success` carries no field — the shell calls `record_send_success`, reads
/// its returned `prev`, and emits the resume log iff `prev > 3`, exactly as the
/// original did.
pub(crate) enum BackoffUpdate {
    /// The destination had at least one successful report this cycle → the shell
    /// runs `record_send_success` (and the `prev > 3` resume log).
    Success { dest: NodeAddr },
    /// Every report to the destination failed this cycle → the shell runs
    /// `record_send_failure`.
    Failure { dest: NodeAddr },
}

/// A registry/transport effect the async shell performs on the core's behalf.
///
/// The heartbeat/liveness decision emits [`ReapPeer`]/[`Heartbeat`]; the
/// link-report fan-out emits [`SendLinkReport`]/[`LogLink`]; the session-report
/// fan-out emits [`SendSessionReport`]/[`LogSession`].
///
/// [`ReapPeer`]: MmpAction::ReapPeer
/// [`Heartbeat`]: MmpAction::Heartbeat
/// [`SendLinkReport`]: MmpAction::SendLinkReport
/// [`LogLink`]: MmpAction::LogLink
/// [`SendSessionReport`]: MmpAction::SendSessionReport
/// [`LogSession`]: MmpAction::LogSession
pub(crate) enum MmpAction {
    /// Reap a dead peer: the shell runs `remove_active_peer` +
    /// `schedule_reconnect` (with its wall-clock `now_ms`).
    ReapPeer { peer: NodeAddr },
    /// Send a heartbeat to `peer`: the shell runs `mark_heartbeat_sent` and the
    /// encrypted link send.
    Heartbeat { peer: NodeAddr },
    /// Build (shell: `proto/mmp/` `build_report` + `encode`) and send the given
    /// link report over the encrypted link. The interval-advancing
    /// `build_report` mutation happens **only** while driving this action, so an
    /// ungated report never advances its interval.
    SendLinkReport {
        peer: NodeAddr,
        kind: LinkReportKind,
    },
    /// Emit the periodic link operator log for `peer` (shell owns the `tracing`
    /// call and runs `mark_logged`).
    LogLink { peer: NodeAddr },
    /// Build (shell: `proto/mmp/` `build_report`/`build_notification` + the
    /// `Session*`/`PathMtuNotification` codec) and send the given session report
    /// over the encrypted session. The interval/notification-advancing build
    /// mutation happens **only** while driving this action.
    SendSessionReport {
        dest: NodeAddr,
        kind: SessionReportKind,
    },
    /// Emit the periodic session operator log for `dest` (shell owns the
    /// `tracing` call and runs `mark_logged`).
    LogSession { dest: NodeAddr },
}

impl Mmp {
    /// Decide the per-tick reap/heartbeat choreography for the peers the shell
    /// snapshotted. Reproduces the pre-refactor `check_link_heartbeats` logic
    /// exactly:
    ///
    /// - A peer past the dead timeout with no rekey in flight
    ///   (`time_dead && !rekey_active`) is reaped and considered for nothing
    ///   else — it is **not** also sent a heartbeat (the pre-refactor
    ///   `continue`, plus the "skip just-reaped peers" guard).
    /// - Otherwise, a peer whose heartbeat is due gets a heartbeat.
    ///
    /// Actions are returned phase-grouped (all reaps, then all heartbeats) to
    /// preserve the pre-refactor two-loop global execution order (every dead
    /// peer removed + reconnect-scheduled before any heartbeat is sent). Pure
    /// over the snapshots.
    pub(crate) fn plan_heartbeats(&self, peers: &[PeerLivenessSnapshot]) -> Vec<MmpAction> {
        let mut reaps = Vec::new();
        let mut heartbeats = Vec::new();
        for snap in peers {
            if snap.time_dead && !snap.rekey_active {
                reaps.push(MmpAction::ReapPeer { peer: snap.peer });
                continue;
            }
            if snap.heartbeat_due {
                heartbeats.push(MmpAction::Heartbeat { peer: snap.peer });
            }
        }
        reaps.extend(heartbeats);
        reaps
    }

    /// Decide the per-tick link-layer report fan-out for the peers the shell
    /// snapshotted. Reproduces the pre-refactor `check_mmp_reports` gating
    /// exactly:
    ///
    /// - A SenderReport is emitted for a `Full`-mode peer whose profile provides
    ///   it and whose sender interval is due (`mode == Full && send_sr &&
    ///   sr_due`).
    /// - A ReceiverReport is emitted for any non-`Minimal`-mode peer whose
    ///   profile provides it and whose receiver interval is due (`mode !=
    ///   Minimal && send_rr && rr_due`).
    /// - A `LogLink` marker is emitted for any peer whose operator-log interval
    ///   is due (`log_due`).
    ///
    /// Actions are returned phase-grouped — all SenderReport sends (in peer
    /// order), then all ReceiverReport sends (in peer order), then all log
    /// markers — to preserve the pre-refactor collect-then-send order (every
    /// SenderReport sent before any ReceiverReport). Logs come last: the shell
    /// runs `build_report` while driving the send actions, so a peer's log
    /// (which reads that peer's post-build cumulative counters, unaffected by any
    /// other peer's build) reads the same state it did when the original emitted
    /// it inline. Pure over the snapshots; the interval/log mutations happen
    /// shell-side while driving.
    pub(crate) fn plan_link_reports(&self, peers: &[LinkReportSnapshot]) -> Vec<MmpAction> {
        let mut actions = Vec::new();
        // Logs first: the operator log reads `cumulative_packets_sent`, which the
        // report sends advance (send_encrypted_link_message -> sender.record_sent).
        // The pre-refactor handler logged during its collect pass, before any
        // send, so the logged tx_pkts excludes this tick's reports. Emitting the
        // log markers ahead of the sends preserves that (build_report touches no
        // log-read field, so ordering the logs before the builds is neutral).
        for snap in peers {
            if snap.log_due {
                actions.push(MmpAction::LogLink { peer: snap.peer });
            }
        }
        for snap in peers {
            if snap.mode == MmpMode::Full && snap.send_sr && snap.sr_due {
                actions.push(MmpAction::SendLinkReport {
                    peer: snap.peer,
                    kind: LinkReportKind::Sender,
                });
            }
        }
        for snap in peers {
            if snap.mode != MmpMode::Minimal && snap.send_rr && snap.rr_due {
                actions.push(MmpAction::SendLinkReport {
                    peer: snap.peer,
                    kind: LinkReportKind::Receiver,
                });
            }
        }
        actions
    }

    /// Decide the per-tick session-layer report fan-out for the sessions the
    /// shell snapshotted. Reproduces the pre-refactor `check_session_mmp_reports`
    /// collect-pass gating exactly:
    ///
    /// - A SessionSenderReport is emitted for a `Full`-mode session whose sender
    ///   interval is due (`mode == Full && sr_due`).
    /// - A SessionReceiverReport is emitted for any non-`Minimal`-mode session
    ///   whose receiver interval is due (`mode != Minimal && rr_due`).
    /// - A PathMtuNotification is emitted for any session whose notification is
    ///   due, in **all** modes (`mtu_due`) — the MTU gate is mode-independent.
    /// - A `LogSession` marker is emitted for any session whose operator-log
    ///   interval is due (`log_due`).
    ///
    /// Ordering: all `LogSession` markers (in session order) come **first**, then
    /// the sends. The pre-refactor handler logged inline during its collect pass,
    /// before any `send_session_msg`; the session operator log reads
    /// `cumulative_packets_sent`, which each send advances (`send_session_msg` ->
    /// `sender.record_sent`), while `build_report`/`build_notification` touch no
    /// log-read field — so emitting the logs ahead of the sends reproduces the
    /// original logged counters byte-identically. The sends preserve the
    /// pre-refactor per-session emission order (Sender, then Receiver, then
    /// PathMtu, interleaved by session), matching the order reports were pushed
    /// into the collect vector. Pure over the snapshots; every build/log mutation
    /// happens shell-side while driving.
    pub(crate) fn plan_session_reports(
        &self,
        sessions: &[SessionReportSnapshot],
    ) -> Vec<MmpAction> {
        let mut actions = Vec::new();
        // Logs first (see the ordering note above): they read the pre-send
        // cumulative_packets_sent the original captured during its collect pass.
        for snap in sessions {
            if snap.log_due {
                actions.push(MmpAction::LogSession { dest: snap.dest });
            }
        }
        // Sends in the pre-refactor per-session push order: SR, RR, MTU.
        for snap in sessions {
            if snap.mode == MmpMode::Full && snap.sr_due {
                actions.push(MmpAction::SendSessionReport {
                    dest: snap.dest,
                    kind: SessionReportKind::Sender,
                });
            }
            if snap.mode != MmpMode::Minimal && snap.rr_due {
                actions.push(MmpAction::SendSessionReport {
                    dest: snap.dest,
                    kind: SessionReportKind::Receiver,
                });
            }
            if snap.mtu_due {
                actions.push(MmpAction::SendSessionReport {
                    dest: snap.dest,
                    kind: SessionReportKind::PathMtu,
                });
            }
        }
        actions
    }

    /// Deduplicate a tick's session-report [`SendResult`]s into one
    /// [`BackoffUpdate`] per distinct destination. Reproduces the pre-refactor
    /// `check_session_mmp_reports` backoff reduction exactly:
    ///
    /// - A destination counts as **success if ANY** of its reports succeeded.
    /// - A destination counts as **failure only if ALL** of its reports failed.
    ///
    /// One `BackoffUpdate::Success`/`Failure` is emitted per distinct dest. The
    /// original accumulated into a `HashMap<NodeAddr, bool>` (success OR-fold,
    /// initialized `false`) with nondeterministic iteration order; a `BTreeMap`
    /// is used here for a deterministic (address-sorted) emission order — no test
    /// depends on the old order (the backoff chartest exercises a single dest),
    /// and stage 6's no_std pass requires the ordered map regardless.
    pub(crate) fn plan_backoff(&self, results: &[SendResult]) -> Vec<BackoffUpdate> {
        let mut dest_success: BTreeMap<NodeAddr, bool> = BTreeMap::new();
        for res in results {
            let entry = dest_success.entry(res.dest).or_insert(false);
            *entry |= res.ok;
        }
        dest_success
            .into_iter()
            .map(|(dest, success)| {
                if success {
                    BackoffUpdate::Success { dest }
                } else {
                    BackoffUpdate::Failure { dest }
                }
            })
            .collect()
    }
}
