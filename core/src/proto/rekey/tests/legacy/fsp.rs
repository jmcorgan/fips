//! The session rekey and first handshake of the deployed releases, and the
//! session traces a new node runs against each.
//!
//! [`FspPeer`] is one deployed node's `SessionEntry` for one remote address,
//! with the handlers that drive it: the first handshake (a single half-open
//! entry before v0.5.3, responder candidates beside the initiator leg at
//! v0.5.3), the established entry's current, pending and previous sessions,
//! the rekey handshake state and its 30 s expiries, the 2 s initiator
//! cutover, the msg3 resend ladders, the sliding drain and the idle purge.
//! Each rule cites the lines it implements as `tag:path:line`, `tag` being
//! `v0.5.0` (identical at `v0.5.1` in every file cited), `v0.5.2` or
//! `v0.5.3`; where they agree the earliest is cited. The tick runs the
//! deployed steps in the deployed order
//! (`v0.5.0:src/node/dataplane/rx_loop.rs:450-476`): handshake resends and
//! the half-open reap, rekey msg3 resends, the idle purge, the rekey check.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::new::{Jit, NewFsp, is_packet, session_data};
use super::ship::ShipFsp;
use super::{Class, Duo, E, End, Expect, Got, Out, Pkt, Rel, Rule, all, boxed};
use crate::identity::NodeAddr;
use crate::noise::{HandshakeState, NoiseSession};
use crate::proto::fsp::wire::{FSP_FLAG_K, FSP_HEADER_SIZE, FspEncryptedHeader, build_fsp_header};
use crate::proto::rekey::keys::pinned;
use crate::proto::rekey::{NodeKeys, Params, PeerKey};
use crate::testutil::{seed_entropy, seeded_keypair};
use crate::time::Duration;

/// The handshake timeout: a peer-armed or own rekey handshake, and a
/// half-open entry, expire after it
/// (`v0.5.2:src/node/handlers/rekey.rs:796-840`, `handshake_timeout_secs`).
const HANDSHAKE_MS: u64 = 30_000;
/// The initiator's cutover delay after completing (`FSP_CUTOVER_DELAY_MS`,
/// `v0.5.0:src/proto/fsp/core.rs` `cutover_timer_elapsed`).
const CUTOVER_MS: u64 = 2_000;
/// The sliding drain and its ceiling at the defaults
/// (`v0.5.0:src/node/session/mod.rs:774-790`, `DRAIN_WINDOW_SECS` and
/// `drain_max_retention_ms`).
const DRAIN_MS: u64 = 10_000;
/// See [`DRAIN_MS`].
const DRAIN_CEILING: u64 = 120_000;
/// No own rekey for this long after arming a peer's
/// (`v0.5.0:src/node/session/mod.rs:469-475`, `REKEY_DAMPENING_SECS`).
const DAMPEN_MS: u64 = 30_000;
/// A pending older than the idle timeout stops refusing setups
/// (`v0.5.0:src/node/session/mod.rs:819-826`, 90 s at the defaults).
const STALE_MS: u64 = 90_000;
/// The idle purge (`v0.5.0:src/node/handlers/timeout.rs:483-510`).
const IDLE_MS: u64 = 90_000;
/// The resend interval and count of every handshake ladder.
const RESEND_MS: u64 = 1_000;
/// See [`RESEND_MS`].
const MAX_RESENDS: u32 = 5;
/// v0.5.3's minimum age of an own first-handshake leg before it yields
/// (`v0.5.3:src/node/session/mod.rs:76-79`).
const YOUNG_MS: u64 = 5_000;
/// v0.5.3's bound on responder candidates per entry
/// (`v0.5.3:src/node/session/mod.rs:62`).
const MAX_CANDIDATES: usize = 4;
/// The rekey time trigger at the defaults.
const AFTER_MS: u64 = 120_000;

/// The state of an entry (`EndToEndState`).
// `allow`, not `expect`: whether the lint fires depends on the features fips-core is built with.
#[allow(
    clippy::large_enum_variant,
    reason = "a test model holding one entry per run; an established session is its usual state"
)]
enum St {
    /// This node's first-handshake attempt (the initiator leg).
    Initiating(HandshakeState<E>),
    /// Before v0.5.3: the single half-open responder awaiting msg3.
    Awaiting(HandshakeState<E>),
    /// v0.5.3: only responder candidates are held.
    Responding,
    /// The session is established under this current session.
    Established(NoiseSession),
}

/// A v0.5.3 responder candidate (`ResponderCandidate`).
struct Cand {
    hs: HandshakeState<E>,
    msg1: Vec<u8>,
    ack: Vec<u8>,
    at: u64,
}

/// One `SessionEntry`.
struct Entry {
    st: St,
    created: u64,
    last_activity: u64,
    /// The stored handshake message the resend ladders send: the setup of
    /// an initiator leg, the ack of a half-open responder before v0.5.3, or
    /// the initial msg3 of an established initiator from v0.5.2 on.
    payload: Option<Pkt>,
    next_resend: u64,
    resends: u32,
    k: bool,
    pending: Option<NoiseSession>,
    prev: Option<NoiseSession>,
    drain_started: Option<u64>,
    prev_used: Option<u64>,
    rekey: Option<HandshakeState<E>>,
    rekey_initiator: bool,
    initiated: u64,
    peer_armed: Option<u64>,
    completed: Option<u64>,
    msg3: Option<Vec<u8>>,
    msg3_next: u64,
    msg3_count: u32,
    session_start: u64,
    jitter: i64,
    cands: Vec<Cand>,
    opened: Option<u64>,
    paused: bool,
}

impl Entry {
    /// An entry in state `st`, created at `now`
    /// (`v0.5.0:src/node/session/mod.rs` `SessionEntry::new`).
    fn new(st: St, now: u64, jitter: i64) -> Self {
        Self {
            st,
            created: now,
            last_activity: now,
            payload: None,
            next_resend: 0,
            resends: 0,
            k: false,
            pending: None,
            prev: None,
            drain_started: None,
            prev_used: None,
            rekey: None,
            rekey_initiator: false,
            initiated: 0,
            peer_armed: None,
            completed: None,
            msg3: None,
            msg3_next: 0,
            msg3_count: 0,
            session_start: now,
            jitter,
            cands: Vec::new(),
            opened: None,
            paused: false,
        }
    }

    /// Store a handshake message for the resend ladder
    /// (`v0.5.2:src/node/session/mod.rs:427-431`).
    fn store(&mut self, pkt: Pkt, now: u64) {
        self.payload = Some(pkt);
        self.resends = 0;
        self.next_resend = now + RESEND_MS;
    }

    /// Whether the entry is established.
    fn established(&self) -> bool {
        matches!(self.st, St::Established(_))
    }

    /// Whether this node's own first-handshake leg is in flight.
    fn leg(&self) -> bool {
        matches!(self.st, St::Initiating(_))
    }

    /// v0.5.3: a setup opened a hold on the entry no longer ago than the
    /// handshake timeout (`v0.5.3:src/node/session/mod.rs:511-515`).
    fn hold_open(&self, now: u64) -> bool {
        self.opened
            .is_some_and(|t| now.saturating_sub(t) <= HANDSHAKE_MS)
    }
}

/// A deployed node's session to one peer.
pub(crate) struct FspPeer {
    rel: Rel,
    local: NodeKeys,
    addr: NodeAddr,
    peer_key: PeerKey,
    entry: Option<Entry>,
    /// The jitter draws taken at each new or promoted session, in seconds,
    /// the last repeated.
    pub(crate) jitter: Vec<i64>,
    /// The rekey message trigger: 65 536 at the defaults.
    pub(crate) after_messages: u64,
    notes: Vec<String>,
    label: String,
}

impl FspPeer {
    /// A deployed node of release `rel` with no session to the peer yet.
    pub(crate) fn new(
        label: &str,
        rel: Rel,
        local: NodeKeys,
        peer_key: PeerKey,
        jitter: Vec<i64>,
    ) -> Self {
        let addr = PeerKey::from_xonly(&local.keypair().x_only_public_key().0).addr();
        Self {
            rel,
            local,
            addr,
            peer_key,
            entry: None,
            jitter,
            after_messages: 1 << 16,
            notes: Vec::new(),
            label: String::from(label),
        }
    }

    /// A deployed node holding a session established at `now`.
    pub(crate) fn established(
        label: &str,
        rel: Rel,
        local: NodeKeys,
        peer_key: PeerKey,
        session: NoiseSession,
        now: u64,
        jitter: Vec<i64>,
    ) -> Self {
        let mut p = Self::new(label, rel, local, peer_key, jitter);
        let jitter = p.draw();
        p.entry = Some(Entry::new(St::Established(session), now, jitter));
        p
    }

    /// The next jitter draw.
    fn draw(&mut self) -> i64 {
        if self.jitter.len() > 1 {
            self.jitter.remove(0)
        } else {
            self.jitter.first().copied().unwrap_or(0)
        }
    }

    /// Whether this node's address is the smaller, which keeps its
    /// initiation (`v0.5.0:src/proto/fsp/core.rs` `initiation_winner`).
    fn wins(&self) -> bool {
        self.addr < self.peer_key.addr()
    }

    /// A fresh XK responder handshake that has read `msg1` and written its
    /// ack, or `None` when the msg1 does not read.
    fn answer(&self, msg1: &[u8]) -> Option<(HandshakeState<E>, Vec<u8>)> {
        let mut hs = HandshakeState::<E>::new_xk_responder(self.local.keypair());
        hs.set_local_epoch(self.local.epoch());
        hs.read_xk_message_1(msg1).ok()?;
        let ack = hs.write_xk_message_2().ok()?;
        Some((hs, ack))
    }

    /// A fresh XK initiator handshake toward the peer and its setup.
    fn setup(&self) -> (HandshakeState<E>, Vec<u8>) {
        let pk = pinned(&self.peer_key).expect("a valid key");
        let mut hs = HandshakeState::<E>::new_xk_initiator(self.local.keypair(), pk);
        hs.set_local_epoch(self.local.epoch());
        let m = hs.write_xk_message_1().expect("msg1");
        (hs, m)
    }

    /// Promote the pending session: current to previous over whatever that
    /// held, pending to current, K flipped, the rekey clock restarted
    /// (`v0.5.0:src/node/session/mod.rs:689-725`, `promote_pending`).
    fn promote(&mut self, now: u64) {
        let jitter = self.draw();
        let e = self.entry.as_mut().expect("an entry");
        let Some(new) = e.pending.take() else {
            return;
        };
        if let St::Established(old) = core::mem::replace(&mut e.st, St::Established(new)) {
            e.prev = Some(old);
        }
        e.drain_started = Some(now);
        e.prev_used = None;
        e.k = !e.k;
        e.session_start = now;
        e.rekey = None;
        e.rekey_initiator = false;
        e.completed = None;
        e.jitter = jitter;
        self.notes.push(format!("promoted k={}", e.k));
    }

    /// Clear a rekey: the handshake, the pending, the retained msg3
    /// (`v0.5.0:src/node/session/mod.rs:847-856`, `abandon_rekey`).
    fn abandon_rekey(e: &mut Entry) {
        e.rekey = None;
        e.pending = None;
        e.rekey_initiator = false;
        e.completed = None;
        e.msg3 = None;
    }

    /// A setup at an established entry: the rekey arm
    /// (`v0.5.0:src/node/handlers/session.rs:680-790`; `v0.5.3` adds the
    /// unconfirmed-msg3 resend and the `RekeyHeld` drop,
    /// `v0.5.3:src/node/handlers/session.rs:930-985`).
    fn arm(&mut self, now: u64, msg1: &[u8], out: &mut Vec<Out>) {
        let rel = self.rel;
        let wins = self.wins();
        let e = self.entry.as_mut().expect("an entry");
        if rel == Rel::V053 {
            if let Some(Pkt::Msg3(m)) = &e.payload {
                out.push(Out::new(Pkt::Msg3(m.clone()), Class::Msg3));
                self.notes
                    .push(String::from("resent unconfirmed msg3 for a setup"));
                return;
            }
            if e.rekey.is_some() && !e.rekey_initiator {
                self.notes.push(String::from("dropped setup RekeyHeld"));
                return;
            }
        }
        if e.rekey.is_some() {
            if wins {
                self.notes.push(String::from("dropped setup RekeyTiebreak"));
                return;
            }
            e.rekey = None;
            self.notes.push(String::from("yielded rekey to a setup"));
        } else if e.pending.is_some()
            && e.completed
                .is_none_or(|c| now.saturating_sub(c) <= STALE_MS)
        {
            self.notes.push(String::from("dropped setup RekeyPending"));
            return;
        }
        let Some((hs, ack)) = self.answer(msg1) else {
            return;
        };
        out.push(Out::new(Pkt::Ack(ack), Class::Ack));
        let e = self.entry.as_mut().expect("an entry");
        e.rekey = Some(hs);
        e.rekey_initiator = false;
        e.peer_armed = Some(now);
        self.notes.push(String::from("armed a rekey setup"));
    }

    /// A setup with no established entry (the first handshake).
    fn first_setup(&mut self, now: u64, msg1: &[u8], out: &mut Vec<Out>) {
        let rel = self.rel;
        let wins = self.wins();
        if rel < Rel::V053 {
            // `v0.5.2:src/node/handlers/session.rs:610-650`: an initiating
            // entry keeps its attempt at the smaller node and is replaced by
            // a responder at the larger; a half-open responder answers a
            // duplicate with its stored ack.
            if let Some(e) = &self.entry {
                match &e.st {
                    St::Initiating(_) if wins => {
                        self.notes
                            .push(String::from("dropped crossing setup: we win"));
                        return;
                    }
                    St::Initiating(_) => self.notes.push(String::from("yielded first handshake")),
                    St::Awaiting(_) => {
                        if let Some(p) = &e.payload {
                            out.push(Out::new(p.clone(), Class::Ack));
                        }
                        return;
                    }
                    St::Responding | St::Established(_) => {}
                }
            }
            let Some((hs, ack)) = self.answer(msg1) else {
                return;
            };
            out.push(Out::new(Pkt::Ack(ack.clone()), Class::Ack));
            let jitter = self.draw();
            let mut e = Entry::new(St::Awaiting(hs), now, jitter);
            e.store(Pkt::Ack(ack), now);
            self.entry = Some(e);
            self.notes.push(String::from("answered first setup"));
            return;
        }
        // v0.5.3 (`v0.5.3:src/node/handlers/session.rs:1100-1245`).
        let mut yield_leg = false;
        let mut pause = false;
        if let Some(e) = &self.entry {
            if let Some(c) = e.cands.iter().find(|c| c.msg1 == msg1) {
                out.push(Out::new(Pkt::Ack(c.ack.clone()), Class::Ack));
                return;
            }
            if e.leg() {
                if wins && now.saturating_sub(e.created) < YOUNG_MS {
                    self.notes
                        .push(String::from("dropped crossing setup: we win"));
                    return;
                }
                if wins {
                    yield_leg = true;
                } else {
                    pause = true;
                }
            }
            if e.cands.len() >= MAX_CANDIDATES
                && !e.cands.iter().any(|c| now.saturating_sub(c.at) >= YOUNG_MS)
            {
                self.notes
                    .push(String::from("refused setup: candidates young"));
                return;
            }
        }
        let Some((hs, ack)) = self.answer(msg1) else {
            return;
        };
        out.push(Out::new(Pkt::Ack(ack.clone()), Class::Ack));
        let jitter = self.draw();
        let e = self
            .entry
            .get_or_insert_with(|| Entry::new(St::Responding, now, jitter));
        if pause {
            e.paused = true;
        }
        if yield_leg {
            e.st = St::Responding;
            e.payload = None;
            e.paused = false;
        }
        if e.cands.len() >= MAX_CANDIDATES {
            e.cands.remove(0);
        }
        e.opened.get_or_insert(now);
        e.cands.push(Cand {
            hs,
            msg1: msg1.to_vec(),
            ack,
            at: now,
        });
        self.notes.push(String::from("added a candidate"));
    }

    /// An ack (`v0.5.0:src/node/handlers/session.rs:861-1070`; v0.5.2 keeps
    /// a rekey whose ack does not read, `v0.5.2:src/node/handlers/session.rs:905-912`).
    fn ack(&mut self, now: u64, bytes: &[u8], out: &mut Vec<Out>) {
        let rel = self.rel;
        let wins = self.wins();
        let jitter = self.draw();
        let Some(e) = self.entry.as_mut() else {
            self.notes.push(String::from("ack for no session"));
            return;
        };
        if e.established() && e.rekey.is_some() && e.rekey_initiator {
            let hs = e.rekey.as_ref().expect("a rekey");
            let mut hs = match hs.fork_xk2(bytes) {
                Ok(hs) => hs,
                Err(_) if rel >= Rel::V052 => {
                    self.notes.push(String::from("rekey ack unreadable, kept"));
                    return;
                }
                Err(_) => {
                    Self::abandon_rekey(e);
                    self.notes
                        .push(String::from("rekey ack unreadable, abandoned"));
                    return;
                }
            };
            let Ok(m3) = hs.write_xk_message_3() else {
                return;
            };
            let Ok(session) = hs.into_session() else {
                return;
            };
            out.push(Out::new(Pkt::Msg3(m3.clone()), Class::Msg3));
            e.pending = Some(session);
            e.rekey = None;
            e.completed = Some(now);
            e.msg3 = Some(m3);
            e.msg3_next = now + RESEND_MS;
            e.msg3_count = 0;
            self.notes
                .push(String::from("completed rekey as initiator"));
            return;
        }
        let St::Initiating(hs) = &e.st else {
            self.notes.push(String::from("ack dropped BadState"));
            return;
        };
        let Ok(mut hs) = hs.fork_xk2(bytes) else {
            self.notes.push(String::from("first ack unreadable, kept"));
            return;
        };
        let Ok(m3) = hs.write_xk_message_3() else {
            return;
        };
        let Ok(session) = hs.into_session() else {
            return;
        };
        out.push(Out::new(Pkt::Msg3(m3.clone()), Class::Msg3));
        e.st = St::Established(session);
        e.session_start = now;
        e.last_activity = now;
        e.k = false;
        e.jitter = jitter;
        e.paused = false;
        e.payload = None;
        if rel >= Rel::V052 {
            e.store(Pkt::Msg3(m3), now);
        }
        if rel == Rel::V053 && wins {
            e.cands.clear();
        }
        self.notes.push(String::from("established as initiator"));
    }

    /// A msg3 (`v0.5.0:src/node/handlers/session.rs:1072-1290`; v0.5.3 keeps
    /// a rekey whose msg3 does not read and completes candidates,
    /// `v0.5.3:src/node/handlers/session.rs:1590-1760`).
    fn msg3(&mut self, now: u64, bytes: &[u8]) {
        let rel = self.rel;
        let jitter = self.draw();
        let peer_key = self.peer_key;
        let peer_addr = peer_key.addr();
        let Some(e) = self.entry.as_mut() else {
            self.notes.push(String::from("msg3 for no session"));
            return;
        };
        if e.established() && e.rekey.is_some() && !e.rekey_initiator {
            let hs = e.rekey.as_ref().expect("a rekey");
            let hs = match hs.fork_xk3(bytes) {
                Ok(hs) => hs,
                Err(_) if rel == Rel::V053 => {
                    self.notes.push(String::from("rekey msg3 unreadable, kept"));
                    return;
                }
                Err(_) => {
                    e.rekey = None;
                    self.notes
                        .push(String::from("rekey msg3 unreadable, abandoned"));
                    return;
                }
            };
            let key = hs
                .remote_static()
                .map(|k| PeerKey::from_xonly(&k.x_only_public_key().0));
            if key != Some(peer_key) {
                e.rekey = None;
                self.notes.push(String::from("rekey msg3 from another key"));
                return;
            }
            let Ok(session) = hs.into_session() else {
                return;
            };
            if e.pending.is_some() {
                self.notes.push(String::from("pending replaced"));
            }
            e.pending = Some(session);
            e.rekey = None;
            e.completed = Some(now);
            self.notes
                .push(String::from("completed rekey as responder"));
            return;
        }
        let hs = if rel < Rel::V053 {
            let St::Awaiting(hs) = &e.st else {
                self.notes.push(String::from("msg3 dropped BadState"));
                return;
            };
            match hs.fork_xk3(bytes) {
                Ok(hs) => hs,
                Err(_) => {
                    self.entry = None;
                    self.notes
                        .push(String::from("half-open removed: msg3 unreadable"));
                    return;
                }
            }
        } else {
            let Some(i) = e.cands.iter().position(|c| c.hs.fork_xk3(bytes).is_ok()) else {
                self.notes.push(String::from("msg3 matched no candidate"));
                return;
            };
            let c = e.cands.remove(i);
            c.hs.fork_xk3(bytes).expect("read above")
        };
        let key = hs
            .remote_static()
            .map(|k| PeerKey::from_xonly(&k.x_only_public_key().0));
        if key.map(|k| k.addr()) != Some(peer_addr) {
            self.notes.push(String::from("msg3 address mismatch"));
            return;
        }
        let Ok(session) = hs.into_session() else {
            return;
        };
        self.entry = Some(Entry::new(St::Established(session), now, jitter));
        self.notes.push(String::from("established as responder"));
    }

    /// An encrypted session message: the trial over current, pending and
    /// previous, the pending first when K differs
    /// (`v0.5.0:src/node/session/mod.rs:623-660`), then the post-decrypt
    /// reaction (`v0.5.0:src/proto/fsp/core.rs:304-330`; any frame clears a
    /// retained initial msg3 from v0.5.2, `v0.5.2:src/node/handlers/session.rs:342`).
    fn frame(&mut self, now: u64, bytes: &[u8]) -> Got {
        let rel = self.rel;
        let Some(h) = FspEncryptedHeader::parse(bytes) else {
            return Got::Refused;
        };
        let Some(e) = self.entry.as_mut() else {
            return Got::Refused;
        };
        if !e.established() {
            return Got::Refused;
        }
        let k = h.flags & FSP_FLAG_K != 0;
        let ct = &bytes[FSP_HEADER_SIZE..];
        let order = if k != e.k && e.pending.is_some() {
            [1, 0, 2]
        } else {
            [0, 1, 2]
        };
        let mut hit = None;
        for slot in order {
            let s = match slot {
                0 => match &mut e.st {
                    St::Established(s) => Some(s),
                    St::Initiating(_) | St::Awaiting(_) | St::Responding => None,
                },
                1 => e.pending.as_mut(),
                _ => e.prev.as_mut(),
            };
            if let Some(s) = s
                && let Ok(p) = s.decrypt_with_replay_check_and_aad(ct, h.counter, &h.header_bytes)
            {
                hit = Some((slot, p));
                break;
            }
        }
        let Some((slot, p)) = hit else {
            return Got::Refused;
        };
        if slot == 2 && e.drain_started.is_some() {
            e.prev_used = Some(now);
        }
        if rel >= Rel::V052 {
            e.payload = None;
        }
        match slot {
            1 => {
                e.msg3 = None;
                self.promote(now);
            }
            0 if e.msg3.is_some() && e.pending.is_none() => {
                e.msg3 = None;
                self.notes.push(String::from("rekey msg3 confirmed"));
            }
            _ => {}
        }
        if is_packet(&p) {
            if let Some(e) = self.entry.as_mut() {
                e.last_activity = now;
            }
            Got::Data { current: slot != 2 }
        } else {
            Got::Frame
        }
    }

    /// The handshake resend ladders and the half-open reap
    /// (`v0.5.2:src/node/handlers/timeout.rs:411-560`;
    /// `v0.5.3:src/node/handlers/timeout.rs:417-610`).
    fn handshakes(&mut self, now: u64, out: &mut Vec<Out>) {
        let rel = self.rel;
        let Some(e) = self.entry.as_mut() else {
            return;
        };
        if rel == Rel::V053 {
            e.cands.retain(|c| now.saturating_sub(c.at) <= HANDSHAKE_MS);
            if e.cands.is_empty() && !e.hold_open(now) {
                e.opened = None;
            }
            if !e.established()
                && e.leg()
                && now.saturating_sub(e.last_activity) > HANDSHAKE_MS
                && (!e.cands.is_empty() || e.hold_open(now))
            {
                e.st = St::Responding;
                e.payload = None;
                e.paused = false;
            }
            if !e.established()
                && e.cands.is_empty()
                && !e.hold_open(now)
                && (!e.leg() || now.saturating_sub(e.last_activity) > HANDSHAKE_MS)
            {
                self.entry = None;
                self.notes.push(String::from("half-open reaped"));
                return;
            }
            let aged = e.opened.is_some_and(|t| now.saturating_sub(t) >= YOUNG_MS);
            if e.leg() && e.paused && (e.cands.is_empty() || aged) {
                e.paused = false;
                e.next_resend = now;
            }
        } else if !e.established() && now.saturating_sub(e.last_activity) > HANDSHAKE_MS {
            self.entry = None;
            self.notes.push(String::from("half-open reaped"));
            return;
        }
        let e = self.entry.as_mut().expect("an entry");
        let resend_first = !e.established()
            && !(rel == Rel::V053 && (!e.leg() || e.paused))
            && e.payload.is_some()
            && e.resends < MAX_RESENDS
            && now >= e.next_resend;
        if resend_first && let Some(p) = &e.payload {
            let class = match p {
                Pkt::Setup(_) => Class::Setup,
                Pkt::Link(_) | Pkt::Ack(_) | Pkt::Msg3(_) | Pkt::Frame(_) => Class::Ack,
            };
            out.push(Out::new(p.clone(), class));
            e.resends += 1;
            e.next_resend = now + RESEND_MS * (1 << e.resends);
        }
        // The initial msg3 resends, from v0.5.2
        // (`v0.5.2:src/node/handlers/timeout.rs:495-560`).
        if rel >= Rel::V052
            && e.established()
            && matches!(e.payload, Some(Pkt::Msg3(_)))
            && now >= e.next_resend
        {
            if e.resends >= MAX_RESENDS {
                e.payload = None;
            } else if let Some(p) = &e.payload {
                out.push(Out::new(p.clone(), Class::Msg3));
                e.resends += 1;
                e.next_resend = now + RESEND_MS * (1 << e.resends);
            }
        }
    }

    /// The rekey msg3 ladder and its abandon at the budget
    /// (`v0.5.0:src/node/handlers/rekey.rs:537-630`, decided by
    /// `v0.5.0:src/proto/fsp/core.rs:274-300`).
    fn rekey_msg3(&mut self, now: u64, out: &mut Vec<Out>) {
        let Some(e) = self.entry.as_mut() else {
            return;
        };
        if e.msg3.is_none() || e.msg3_next == 0 || now < e.msg3_next {
            return;
        }
        if e.msg3_count >= MAX_RESENDS {
            Self::abandon_rekey(e);
            self.notes
                .push(String::from("rekey abandoned at the msg3 budget"));
            return;
        }
        let m = e.msg3.clone().expect("a msg3");
        out.push(Out::new(Pkt::Msg3(m), Class::Msg3));
        e.msg3_count += 1;
        e.msg3_next = now + RESEND_MS * (1 << e.msg3_count);
    }

    /// The rekey check (`v0.5.0:src/proto/fsp/core.rs:214-272`,
    /// `v0.5.2:src/proto/fsp/core.rs:253-320` with the initiator's expiry,
    /// over the snapshot of `v0.5.2:src/node/handlers/rekey.rs:796-846`).
    fn rekey(&mut self, now: u64, out: &mut Vec<Out>) {
        let rel = self.rel;
        let after_messages = self.after_messages;
        let Some(e) = self.entry.as_mut() else {
            return;
        };
        if !e.established() {
            return;
        }
        if e.pending.is_some()
            && e.rekey.is_none()
            && e.rekey_initiator
            && e.completed
                .is_some_and(|c| now.saturating_sub(c) >= CUTOVER_MS)
        {
            self.promote(now);
            return;
        }
        if let Some(t) = e.drain_started {
            let anchor = t.max(e.prev_used.unwrap_or(0));
            if now.saturating_sub(t) >= DRAIN_CEILING || now.saturating_sub(anchor) >= DRAIN_MS {
                e.prev = None;
                e.drain_started = None;
                e.prev_used = None;
            }
        }
        if !e.rekey_initiator
            && e.rekey.is_some()
            && e.peer_armed
                .is_some_and(|t| now.saturating_sub(t) > HANDSHAKE_MS)
        {
            e.rekey = None;
            self.notes.push(String::from("armed rekey expired"));
            return;
        }
        if rel >= Rel::V052
            && e.rekey_initiator
            && e.rekey.is_some()
            && now.saturating_sub(e.initiated) > HANDSHAKE_MS
        {
            e.rekey = None;
            self.notes.push(String::from("own rekey expired"));
            return;
        }
        let dampened = e
            .peer_armed
            .is_some_and(|t| now.saturating_sub(t) < DAMPEN_MS);
        if e.rekey.is_some() || e.pending.is_some() || e.msg3.is_some() || dampened {
            return;
        }
        let St::Established(cur) = &e.st else {
            return;
        };
        let after = AFTER_MS.saturating_add_signed(e.jitter * 1_000) / 1_000;
        if now.saturating_sub(e.session_start) / 1_000 >= after
            || cur.current_send_counter() >= after_messages
        {
            let (hs, m) = self.setup();
            out.push(Out::new(Pkt::Setup(m), Class::Setup));
            let e = self.entry.as_mut().expect("an entry");
            e.rekey = Some(hs);
            e.rekey_initiator = true;
            e.initiated = now;
            self.notes.push(String::from("initiated rekey"));
        }
    }
}

impl End for FspPeer {
    fn tick(&mut self, now: u64, out: &mut Vec<Out>) {
        self.handshakes(now, out);
        self.rekey_msg3(now, out);
        if let Some(e) = &self.entry
            && e.established()
            && now.saturating_sub(e.last_activity) > IDLE_MS
        {
            self.entry = None;
            self.notes.push(String::from("idle purge"));
        }
        self.rekey(now, out);
    }

    fn recv(&mut self, now: u64, pkt: &Pkt, out: &mut Vec<Out>) -> Got {
        match pkt {
            Pkt::Setup(m) => {
                if m.len() != crate::noise::XK_HANDSHAKE_MSG1_SIZE {
                    return Got::Other;
                }
                if self.entry.as_ref().is_some_and(Entry::established) {
                    self.arm(now, m, out);
                } else {
                    self.first_setup(now, m, out);
                }
                Got::Other
            }
            Pkt::Ack(m) => {
                self.ack(now, m, out);
                Got::Other
            }
            Pkt::Msg3(m) => {
                self.msg3(now, m);
                Got::Other
            }
            Pkt::Frame(f) => self.frame(now, f),
            Pkt::Link(_) => Got::Other,
        }
    }

    fn data(&mut self, now: u64, seq: u64, out: &mut Vec<Out>) -> bool {
        let Some(e) = self.entry.as_mut() else {
            return false;
        };
        let k = e.k;
        let St::Established(cur) = &mut e.st else {
            return false;
        };
        let p = session_data(Duration::from_millis(now), seq);
        let counter = cur.current_send_counter();
        let header = build_fsp_header(counter, if k { FSP_FLAG_K } else { 0 }, p.len() as u16);
        let Ok(ct) = cur.encrypt_with_aad(&p, &header) else {
            return false;
        };
        let mut f = header.to_vec();
        f.extend_from_slice(&ct);
        e.last_activity = now;
        out.push(Out::new(Pkt::Frame(f), Class::Data));
        true
    }

    fn wake(&self) -> Option<u64> {
        None
    }

    fn alive(&self) -> bool {
        self.entry.as_ref().is_some_and(Entry::established)
    }

    fn quiet(&self) -> bool {
        self.entry
            .as_ref()
            .is_some_and(|e| e.rekey.is_none() && e.pending.is_none())
    }

    fn take_notes(&mut self) -> Vec<String> {
        core::mem::take(&mut self.notes)
    }

    fn name(&self) -> String {
        self.label.clone()
    }

    /// Every session state is lost and a new startup epoch drawn: the next
    /// setup it sends or answers carries the new epoch.
    fn restart(&mut self, epoch: [u8; 8]) {
        self.local = NodeKeys::new(self.local.keypair(), epoch);
        self.entry = None;
        self.notes.push(String::from("restarted"));
    }

    /// A session to the peer is wanted: a first attempt, replacing a
    /// half-open responder before v0.5.3 (`v0.5.2:src/node/handlers/session.rs:2245-2300`),
    /// or attached beside the candidates at v0.5.3
    /// (`v0.5.3:src/node/session/mod.rs` `attach_initiator`).
    fn open(&mut self, now: u64, out: &mut Vec<Out>) {
        let rel = self.rel;
        let busy = self.entry.as_ref().is_some_and(|e| {
            e.established() || e.leg() || (rel == Rel::V053 && !matches!(e.st, St::Responding))
        });
        if busy {
            return;
        }
        let (hs, m) = self.setup();
        out.push(Out::new(Pkt::Setup(m.clone()), Class::Setup));
        let jitter = self.draw();
        match self.entry.as_mut() {
            Some(e) if rel == Rel::V053 => {
                e.st = St::Initiating(hs);
                e.created = now;
                e.last_activity = now;
                e.paused = false;
                e.store(Pkt::Setup(m), now);
            }
            Some(_) | None => {
                let mut e = Entry::new(St::Initiating(hs), now, jitter);
                e.store(Pkt::Setup(m), now);
                self.entry = Some(e);
            }
        }
        self.notes.push(String::from("opened"));
    }
}

/// Two node keys whose addresses order as `new_smaller` asks: the new node's
/// first.
fn keys(seed: u64, new_smaller: bool) -> (NodeKeys, NodeKeys) {
    let a = seeded_keypair(seed);
    let b = seeded_keypair(seed + 1);
    let addr = |k: &secp256k1::Keypair| PeerKey::from_xonly(&k.x_only_public_key().0).addr();
    let (s, l) = if addr(&a) < addr(&b) { (a, b) } else { (b, a) };
    let (n, o) = if new_smaller { (s, l) } else { (l, s) };
    (NodeKeys::new(n, [0x11; 8]), NodeKeys::new(o, [0x22; 8]))
}

/// How a session trace starts.
#[derive(Clone)]
pub(crate) struct Setup {
    /// The deployed release of the other node.
    pub(crate) rel: Rel,
    /// The new node has the smaller address.
    pub(crate) new_smaller: bool,
    /// The new node's jitter draw (0 is -15 s, 30 is +15 s).
    pub(crate) new_jitter: u16,
    /// The deployed node's jitter, in seconds.
    pub(crate) old_jitter: i64,
    /// The session is set up before the trace (at 0); otherwise the trace
    /// opens it.
    pub(crate) established: bool,
    /// The deployed node's rekey message trigger, when not the default.
    pub(crate) old_messages: Option<u64>,
    /// The new node is the one this release ships: the machine polled on
    /// the shell's tick.
    pub(crate) shipped: bool,
}

/// The new node of a session set up at 0 with `session`, shipped or not.
fn new_end(
    label: &str,
    shipped: bool,
    local: NodeKeys,
    peer: PeerKey,
    peer_epoch: [u8; 8],
    session: NoiseSession,
    jitter: u16,
) -> Box<dyn End> {
    let n = NewFsp::established(
        label,
        local,
        peer,
        peer_epoch,
        session,
        0,
        Params::fsp(),
        Jit::Fixed(jitter),
    );
    if shipped {
        boxed(ShipFsp::new(n))
    } else {
        boxed(n)
    }
}

/// A session between a new node (node 0) and a deployed one (node 1).
pub(crate) fn session(s: &Setup, seed: u64) -> Duo {
    seed_entropy(seed);
    let (nk, ok) = keys(seed, s.new_smaller);
    let npub = PeerKey::from_xonly(&nk.keypair().x_only_public_key().0);
    let opub = PeerKey::from_xonly(&ok.keypair().x_only_public_key().0);
    if !s.established {
        let new = NewFsp::new(
            &format!("new({:?})", s.rel),
            nk,
            opub,
            Params::fsp(),
            Jit::Fixed(s.new_jitter),
        );
        let new: Box<dyn End> = if s.shipped {
            boxed(ShipFsp::new(new))
        } else {
            boxed(new)
        };
        let mut old = FspPeer::new(
            &format!("{:?}", s.rel),
            s.rel,
            ok,
            npub,
            alloc::vec![s.old_jitter],
        );
        if let Some(m) = s.old_messages {
            old.after_messages = m;
        }
        return Duo::new(new, boxed(old), 0);
    }
    let mut hi = HandshakeState::<E>::new_xk_initiator(nk.keypair(), pinned(&opub).expect("a key"));
    hi.set_local_epoch(nk.epoch());
    let mut hr = HandshakeState::<E>::new_xk_responder(ok.keypair());
    hr.set_local_epoch(ok.epoch());
    hr.read_xk_message_1(&hi.write_xk_message_1().expect("msg1"))
        .expect("reads");
    hi.read_xk_message_2(&hr.write_xk_message_2().expect("msg2"))
        .expect("reads");
    hr.read_xk_message_3(&hi.write_xk_message_3().expect("msg3"))
        .expect("reads");
    let new = new_end(
        &format!("new({:?})", s.rel),
        s.shipped,
        nk,
        opub,
        [0x22; 8],
        hi.into_session().expect("done"),
        s.new_jitter,
    );
    let mut old = FspPeer::established(
        &format!("{:?}", s.rel),
        s.rel,
        ok,
        npub,
        hr.into_session().expect("done"),
        0,
        alloc::vec![s.old_jitter],
    );
    if let Some(m) = s.old_messages {
        old.after_messages = m;
    }
    Duo::new(new, boxed(old), 0)
}

/// A session between two new nodes, set up at 0 or opened by both: the
/// production profile against itself. With `shipped`, both are the node
/// this release ships.
pub(crate) fn new_session(seed: u64, jitter: [u16; 2], established: bool, shipped: bool) -> Duo {
    seed_entropy(seed);
    let (ak, bk) = keys(seed, true);
    let apub = PeerKey::from_xonly(&ak.keypair().x_only_public_key().0);
    let bpub = PeerKey::from_xonly(&bk.keypair().x_only_public_key().0);
    if !established {
        let a = NewFsp::new("new a", ak, bpub, Params::fsp(), Jit::Fixed(jitter[0]));
        let b = NewFsp::new("new b", bk, apub, Params::fsp(), Jit::Fixed(jitter[1]));
        if shipped {
            return Duo::new(boxed(ShipFsp::new(a)), boxed(ShipFsp::new(b)), 0);
        }
        return Duo::new(boxed(a), boxed(b), 0);
    }
    let mut hi = HandshakeState::<E>::new_xk_initiator(ak.keypair(), pinned(&bpub).expect("a key"));
    hi.set_local_epoch(ak.epoch());
    let mut hr = HandshakeState::<E>::new_xk_responder(bk.keypair());
    hr.set_local_epoch(bk.epoch());
    hr.read_xk_message_1(&hi.write_xk_message_1().expect("msg1"))
        .expect("reads");
    hi.read_xk_message_2(&hr.write_xk_message_2().expect("msg2"))
        .expect("reads");
    hr.read_xk_message_3(&hi.write_xk_message_3().expect("msg3"))
        .expect("reads");
    let a = new_end(
        "new a",
        shipped,
        ak,
        bpub,
        [0x22; 8],
        hi.into_session().expect("done"),
        jitter[0],
    );
    let b = new_end(
        "new b",
        shipped,
        bk,
        apub,
        [0x11; 8],
        hr.into_session().expect("done"),
        jitter[1],
    );
    Duo::new(a, b, 0)
}

/// A session trace.
pub(crate) struct Trace {
    name: &'static str,
    setup: Setup,
    rules: Vec<Rule>,
    /// Each end's data period; `None` for a silent end.
    period: [Option<u64>; 2],
    /// A window in which each end sends no data.
    hush: [Option<(u64, u64)>; 2],
    /// One-way latency each way.
    lat: [u64; 2],
    /// Each end's tick phase within the second.
    phase: [u64; 2],
    /// Scripted actions: at an instant, an end opens the session.
    opens: Vec<(u64, usize)>,
    /// Scripted setups from third parties to the new node: instant and
    /// stranger.
    strangers: Vec<(u64, u8)>,
    /// The deployed node restarts at this instant.
    restart: Option<u64>,
    run: u64,
    expect: Expect,
}

impl Trace {
    /// A trace against `rel`: an established session, the new node's
    /// trigger at 105 s and the deployed node's at 135 s, both sending a
    /// data frame a second, the new node the smaller.
    fn new(name: &'static str, rel: Rel) -> Self {
        Self {
            name,
            setup: Setup {
                rel,
                new_smaller: true,
                new_jitter: 0,
                old_jitter: 15,
                established: true,
                old_messages: None,
                shipped: false,
            },
            rules: Vec::new(),
            period: [Some(1_000), Some(1_000)],
            hush: [None, None],
            lat: [50, 50],
            phase: [0, 500],
            opens: Vec::new(),
            strangers: Vec::new(),
            restart: None,
            run: 260_000,
            expect: Expect::lossless(),
        }
    }

    /// The deployed node initiates: its trigger at 105 s, the new node's
    /// at 135 s.
    fn old_first(mut self) -> Self {
        self.setup.new_jitter = 30;
        self.setup.old_jitter = -15;
        self
    }

    /// Both start in the same tick, at 105 s.
    fn crossing(mut self) -> Self {
        self.setup.old_jitter = -15;
        self.phase = [0, 0];
        self
    }

    /// The deployed node falls silent at 100 s (session MMP mode Minimal
    /// and no application data). It sends before, so the new node's
    /// silence rule, which a peer silent from the start would set off every
    /// doubling interval, does not move the scheduled rekey the trace's
    /// faults are aimed at.
    fn silent_old(mut self) -> Self {
        self.hush[1] = Some((100_000, u64::MAX));
        self
    }

    /// The new node has the larger address.
    fn larger(mut self) -> Self {
        self.setup.new_smaller = false;
        self
    }

    /// The new node is the one this release ships: the machine polled on
    /// the shell's tick.
    fn shipped(mut self) -> Self {
        self.setup.shipped = true;
        self
    }

    /// No session yet: the trace opens it.
    fn opening(mut self) -> Self {
        self.setup.established = false;
        self
    }

    /// Add a fault.
    fn rule(mut self, r: Rule) -> Self {
        self.rules.push(r);
        self
    }

    /// Set what must hold.
    fn expect(mut self, e: Expect) -> Self {
        self.expect = e;
        self
    }

    /// Run until `t` before healing.
    fn until(mut self, t: u64) -> Self {
        self.run = t;
        self
    }
}

/// A scripted action of a session trace.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Act {
    /// The end opens the session.
    Open,
    /// A third party's setup reaches the new node.
    Stranger(u8),
    /// The deployed node restarts.
    Restart,
}

/// Run one session trace and check it.
fn run(t: Trace, seed: u64) -> Result<(), String> {
    let name = if t.setup.shipped && !t.name.starts_with("shipped") {
        format!("shipped node, {} against {:?}", t.name, t.setup.rel)
    } else {
        format!("{} against {:?}", t.name, t.setup.rel)
    };
    let mut duo = session(&t.setup, seed);
    duo.rules = t.rules;
    duo.period = t.period;
    duo.hush = t.hush;
    duo.lat = t.lat;
    duo.phase = t.phase;
    let mut acts: Vec<(u64, usize, Act)> =
        t.opens.iter().map(|&(at, x)| (at, x, Act::Open)).collect();
    acts.extend(t.strangers.iter().map(|&(at, n)| (at, 0, Act::Stranger(n))));
    acts.extend(t.restart.map(|at| (at, 1, Act::Restart)));
    acts.sort_unstable();
    for (at, x, act) in acts {
        duo.run_until(at);
        match act {
            Act::Stranger(n) => duo.act(x, |end, now, out| end.stranger(now, n, out)),
            Act::Open => duo.act(x, |end, now, out| end.open(now, out)),
            Act::Restart => duo.act(x, |end, _, _| end.restart([0x33; 8])),
        }
    }
    duo.run_until(t.run);
    t.expect.check(&name, &mut duo, 300_000)
}

/// Lossless, with the new node installing an epoch of `role` on `evidence`.
fn installs(role: &'static str) -> Expect {
    Expect::lossless().must(0, role)
}

/// The session rekey traces a new node runs against each release: rekeys
/// it initiates and rekeys the deployed node initiates, under the losses
/// that matter, simultaneous initiation, and the schedules that hold the
/// machine's guards to their interop consequences: the
/// keepalives against a silent responder (with one lost while the new node
/// is idle), the confirmation window's extra check, Karn's kept backoff,
/// the larger node keeping an acknowledged setup at an assumed cutover, and
/// the setup refused in `PendI` at the smaller address.
#[test]
fn session_rekey_traces_hold_against_every_deployed_release() {
    let mut cases = Vec::new();
    for rel in Rel::ALL {
        // The responder promotes on the probe; its next frame under
        // the new epoch is the new node's evidence.
        cases.push(
            Trace::new("new node initiates", rel).expect(
                installs("Installed { tag: EpochTag(1), role: Initiator, evidence: Frame }")
                    .must(1, "promoted"),
            ),
        );
        // A silent responder: the new node assumes at its deadline,
        // and its keepalives under the old epoch, never more than 4 s apart,
        // keep the responder's use-refreshed drain alive while its own data
        // pauses past the drain window, even with the 7 s rung's keepalive
        // lost.
        let mut t = Trace::new("silent responder, initiator idle, one keepalive lost", rel)
            .silent_old()
            .rule(Rule::first(0, Class::Prompt, 111_000, 1))
            .expect(installs(
                "Installed { tag: EpochTag(1), role: Initiator, evidence: Assumed }",
            ));
        t.hush[0] = Some((106_000, 125_000));
        cases.push(t);
        // A frame the responder sealed under the old epoch
        // delayed past the new node's cutover: the current key fails it,
        // the drained one delivers it, each trial opening the unmodified
        // ciphertext.
        cases.push(
            Trace::new("old-epoch frame delayed past the cutover", rel)
                .rule(Rule::delay(1, Class::Data, 104_500, 105_000, 2_000))
                .expect(
                    installs("Installed { tag: EpochTag(1), role: Initiator, evidence: Frame }")
                        .delivers_previous(0),
                ),
        );
        // Every msg3 copy lost, the responder sending: the new node
        // sees the peer staying, retires at its deadline and repairs at
        // once; the repair setup reaches the responder after its armed
        // handshake expired (the confirmation window's extra check), so it
        // is armed, not dropped.
        cases.push(
            Trace::new("every msg3 lost, responder sending", rel)
                .rule(Rule::drop(0, Class::Msg3, 100_000, 140_000))
                .expect(
                    Expect::lossless()
                        .must(0, "Retired { tag: EpochTag(1) }")
                        .must(1, "armed rekey expired")
                        .never(1, "RekeyHeld")
                        .must(
                            0,
                            "Installed { tag: EpochTag(2), role: Initiator, evidence: Frame }",
                        ),
                ),
        );
        // Every msg3 copy lost with a silent responder: the assumed cutover is wrong, and the
        // new node's frames are lost until its silence rule repairs it and
        // the repair is assumed (accepted residual: about 60 s).
        cases.push(
            Trace::new("every msg3 lost, responder silent", rel)
                .silent_old()
                .rule(Rule::drop(0, Class::Msg3, 100_000, 140_000))
                .until(330_000)
                .expect(Expect::lossless().outage(0, 62_000).must(0, "Assumed")),
        );
        // The ack is lost; the resend is dropped (or, by a 0.5.0 to
        // 0.5.2 responder at the larger address, re-armed and answered), and
        // either way the rekey completes with nothing lost.
        cases.push(
            Trace::new("ack lost", rel)
                .rule(Rule::first(1, Class::Ack, 100_000, 1))
                .until(330_000)
                .expect(Expect::lossless().must(1, "promoted")),
        );
        // msg3 delivered, every probe lost, the responder sending: it
        // holds the pending and keeps the old epoch, the new node retires at
        // its deadline, its repairs are refused behind the pending until it
        // is stale, and rotation resumes; nothing is lost.
        cases.push(
            Trace::new("every probe lost, responder sending", rel)
                .rule(Rule::drop(0, Class::Probe, 100_000, 140_000))
                .until(400_000)
                .expect(
                    Expect::lossless()
                        .must(1, "dropped setup RekeyPending")
                        .must(0, "Retired { tag: EpochTag(1) }"),
                ),
        );
        // The deployed node initiates; the new node completes at msg3,
        // cuts over and prompts, and the initiator promotes on the prompt.
        cases.push(
            Trace::new("deployed node initiates", rel)
                .old_first()
                .expect(installs(
                    "Installed { tag: EpochTag(1), role: Responder, evidence: Proof }",
                )),
        );
        // The deployed node initiates and its first three msg3 copies are lost: the candidate lives 40
        // s, the 7 s copy completes it, and the initiator's frames sealed
        // after its 2 s timer cutover are lost only until then.
        cases.push(
            Trace::new("deployed node initiates, first three msg3 copies lost", rel)
                .old_first()
                .rule(Rule::first(1, Class::Msg3, 100_000, 3))
                .expect(
                    installs("Installed { tag: EpochTag(1), role: Responder, evidence: Proof }")
                        .outage(1, 6_000),
                ),
        );
        // Every copy of the deployed initiator's msg3 lost: it cuts
        // over on its timer to keys the new node never completed; the new
        // node's silence rule repairs (accepted: the deployed initiator's
        // frames are lost until then).
        cases.push(
            Trace::new("every msg3 of a deployed initiator lost", rel)
                .old_first()
                .rule(Rule::drop(1, Class::Msg3, 100_000, 170_000))
                .until(330_000)
                .expect(Expect::lossless().outage(1, 36_000).outage(0, 2_000)),
        );
        // Crossing rekeys, the new node smaller: the deployed node
        // abandons its own and answers; both settle on the new node's.
        cases.push(
            Trace::new("crossing rekeys, new node smaller", rel)
                .crossing()
                .expect(Expect::lossless().must(1, "yielded rekey to a setup").must(
                    0,
                    "Installed { tag: EpochTag(1), role: Initiator, evidence: Frame }",
                )),
        );
        // Crossing rekeys, the new node larger: it acknowledges the
        // deployed node's setup and yields at its msg3.
        cases.push(
            Trace::new("crossing rekeys, new node larger", rel)
                .crossing()
                .larger()
                .expect(
                    Expect::lossless()
                        .must(1, "dropped setup RekeyTiebreak")
                        .must(0, "Abandoned(Yielded)")
                        .must(
                            0,
                            "Installed { tag: EpochTag(1), role: Responder, evidence: Proof }",
                        ),
                ),
        );
        // The new node, smaller, has completed when the deployed
        // node's setup arrives (its armed copy expired with every msg3
        // lost): the setup is refused, the new node decides at its deadline
        // on the peer staying and repairs, and the larger deployed node
        // abandons its own for the repair.
        cases.push(
            Trace::new("setup meets a completed attempt at the smaller node", rel)
                .rule(Rule::drop(0, Class::Msg3, 100_000, 140_000))
                .rule(Rule::delay(1, Class::Ack, 100_000, 106_000, 900))
                .until(330_000)
                .expect(
                    Expect::lossless()
                        .must(1, "initiated rekey")
                        .must(0, "Reject(TieBreakKept)")
                        .must(1, "yielded rekey to a setup"),
                ),
        );
        // The larger node keeps an acknowledged setup at its assumed
        // cutover: the deployed smaller node's rekey, acknowledged while the
        // new node waited for evidence with every msg3 and probe lost and
        // the deployed node silent, completes after the assumed cutover.
        cases.push(
            Trace::new(
                "larger node keeps an acknowledged setup at an assumed cutover",
                rel,
            )
            .larger()
            .silent_old()
            .rule(Rule::drop(0, Class::Msg3, 100_000, 140_000))
            .rule(Rule::drop(0, Class::Probe, 100_000, 140_000))
            .rule(Rule::delay(1, Class::Ack, 100_000, 106_000, 800))
            .rule(Rule::first(1, Class::Msg3, 130_000, 1))
            .expect(
                Expect::lossless()
                    .outage(0, 3_000)
                    .must(0, "evidence: Assumed")
                    .must(
                        0,
                        "Installed { tag: EpochTag(2), role: Responder, evidence: Proof }",
                    ),
            ),
        );
    }
    // No eviction in an established session: the deployed initiator's
    // candidate, past its protection age, outlives a burst of strangers'
    // setups (one over its own link, which fills that link's quota, then
    // others that fill the table) while its first msg3 copies are lost, and
    // its next copy completes it; the deployed initiator's frames are lost
    // only between its 2 s timer cutover and that copy.
    let mut t = Trace::new("rekey candidate kept through strangers' setups", Rel::V053)
        .old_first()
        .rule(Rule::first(1, Class::Msg3, 100_000, 3))
        .expect(
            installs("Installed { tag: EpochTag(1), role: Responder, evidence: Proof }")
                .outage(1, 7_000),
        );
    t.strangers = alloc::vec![(112_000, 0), (112_000, 7), (112_000, 8), (112_000, 9)];
    cases.push(t);
    // Karn's kept backoff: a 0.5.0 to 0.5.2 responder at the larger
    // address re-arms on the resent setup when the round trip (1.5 s)
    // exceeds the first rung and no session SRTT is known. The first attempt
    // fails; the backed-off rung Karn's rule keeps lets the repair complete,
    // so the pair converges with nothing lost (without it, every attempt
    // fails the same way and rotation stops while the responder sends).
    for rel in [Rel::V050, Rel::V052] {
        let mut t = Trace::new("slow ack re-arms a 0.5.0 to 0.5.2 responder", rel)
            .until(330_000)
            .expect(Expect::lossless().must(1, "yielded rekey to a setup").must(
                0,
                "Installed { tag: EpochTag(2), role: Initiator, evidence: Frame }",
            ));
        t.lat = [750, 750];
        cases.push(t);
    }
    cases.extend(shipped_traces());
    cases.extend(shipped_slow_acks());
    all(cases.into_iter().map(|t| run(t, 11)).collect());
}

/// S-3 for the node this release ships: a 0.5.0 to 0.5.2 responder at the
/// larger address re-arms on a resent setup when the round trip (1.5 s)
/// exceeds the first rung and no session SRTT is known. The first attempt
/// fails, and Karn's kept backoff lets the next complete.
fn shipped_slow_acks() -> Vec<Trace> {
    let mut cases = Vec::new();
    for rel in [Rel::V050, Rel::V052] {
        // The responder sending: the shipped node sees it stay on the old
        // epoch, retires at its deadline and repairs at once, with its first
        // rung backed off; nothing is lost.
        let mut t = Trace::new("shipped node, slow ack re-arms the responder", rel)
            .shipped()
            .until(330_000)
            .expect(Expect::lossless().must(1, "yielded rekey to a setup").must(
                0,
                "Installed { tag: EpochTag(2), role: Initiator, evidence: Frame }",
            ));
        t.lat = [750, 750];
        cases.push(t);
        // The responder silent is swept over round trips and tick phases
        // in its own test below.
    }
    cases
}

/// S-3 with the responder silent, swept over the round trip and both ends'
/// tick phases. A 0.5.0 to 0.5.2 responder at the larger address re-arms on
/// the resent setup and drops the msg3 of the first attempt, so the new
/// node's assumed cutover at its confirmation deadline is wrong. The
/// responder's own rekey, held by its dampening until 30 s after that
/// re-arm, sends its setup at the responder's first tick after the
/// dampening ends, so the setup reaches the new node at or after the new
/// node's confirmation deadline and within a tick of it. The shell polls
/// the machine before it takes a setup whenever a deadline is due, so the
/// setup is judged after that deadline: it is answered, and the new node
/// cuts over at its msg3. The new node's frames are lost from the assumed
/// cutover to that msg3, at most the round trip plus the responder's tick,
/// in whole data frames: 3 s at a 900 ms one-way latency, which is why the
/// bound is not a flat 2 s. Judged against the passed deadline, the setup
/// was refused at the smaller address, the responder's only copy was lost,
/// and the frames stayed lost until the new node's silence rule repaired
/// the session and that repair was assumed a confirmation window later,
/// about 60 s.
#[test]
fn slow_ack_against_a_silent_responder_loses_at_most_a_round_trip_and_a_tick_at_every_phase() {
    let mut cases = Vec::new();
    for rel in [Rel::V050, Rel::V052] {
        for lat in [600u64, 750, 900] {
            let bound = (2 * lat + 1_000).div_ceil(1_000) * 1_000;
            for p0 in [0, 500] {
                for p1 in [0, 250, 500, 750] {
                    let mut t = Trace::new("slow ack re-arms a silent responder", rel)
                        .shipped()
                        .silent_old()
                        .until(330_000)
                        .expect(
                            Expect::lossless()
                                .outage(0, bound)
                                .must(0, "Assumed")
                                .must(1, "completed rekey as initiator"),
                        );
                    t.lat = [lat, lat];
                    t.phase = [p0, p1];
                    cases.push((t, lat, [p0, p1]));
                }
            }
        }
        // The new node polled at its next wake: the responder's setup
        // arrives at the very instant of the confirmation deadline.
        let mut t = Trace::new("slow ack re-arms a silent responder", rel)
            .silent_old()
            .until(330_000)
            .expect(
                Expect::lossless()
                    .outage(0, 3_000)
                    .must(0, "Assumed")
                    .must(1, "completed rekey as initiator"),
            );
        t.lat = [750, 750];
        t.phase = [0, 750];
        cases.push((t, 750, [0, 750]));
    }
    all(cases
        .into_iter()
        .map(|(t, lat, phase)| {
            run(t, 11).map_err(|e| format!("latency {lat} ms, tick phases {phase:?}: {e}"))
        })
        .collect());
}

/// The session rekey traces of the node this release ships against each
/// release: the machine takes every setup, ack, msg3 and frame and starts
/// its own rekeys, scheduled or after silence, polled on the shell's tick.
/// Each states what it costs against what the deployed initiator (a 2 s
/// timer cutover) would have lost.
fn shipped_traces() -> Vec<Trace> {
    let mut cases = Vec::new();
    for rel in Rel::ALL {
        // S-1: the responder promotes on the probe, and its next frame is
        // the evidence.
        cases.push(
            Trace::new("shipped node initiates", rel).shipped().expect(
                installs("Installed { tag: EpochTag(1), role: Initiator, evidence: Frame }")
                    .must(1, "promoted"),
            ),
        );
        // S-1 with a silent responder: assumed at the deadline, the
        // keepalives under the old epoch keeping the responder's drain
        // alive through a pause in the shipped node's own data.
        let mut t = Trace::new("shipped node, silent responder, initiator idle", rel)
            .shipped()
            .silent_old()
            .rule(Rule::first(0, Class::Prompt, 111_000, 1))
            .expect(installs(
                "Installed { tag: EpochTag(1), role: Initiator, evidence: Assumed }",
            ));
        t.hush[0] = Some((106_000, 125_000));
        cases.push(t);
        // S-2, responder sending: retired at the deadline with a repair
        // due, which starts at once; the responder's armed copy has
        // expired, so it arms the repair. Nothing is lost, where a deployed
        // initiator lost its frames until a later rekey.
        cases.push(
            Trace::new("shipped node, every msg3 lost, responder sending", rel)
                .shipped()
                .rule(Rule::drop(0, Class::Msg3, 100_000, 140_000))
                .expect(
                    Expect::lossless()
                        .must(0, "Retired { tag: EpochTag(1) }")
                        .must(1, "armed rekey expired")
                        .never(1, "RekeyHeld")
                        .must(
                            0,
                            "Installed { tag: EpochTag(2), role: Initiator, evidence: Frame }",
                        ),
                ),
        );
        // S-2, responder silent: the assumed cutover at 137 s is wrong, and
        // the shipped node's frames are lost until its silence rule, 30 s
        // later, starts a repair, which the responder answers (yielding the
        // attempt it started at 136.5 s, which the shipped node refused
        // while it waited for evidence) and which is assumed at its own
        // deadline: 62 s,
        // against every release, as for the new node (12.1 item 2). A
        // deployed initiator (the 0.5.3 model) loses 108 s here against every
        // release, from its 2 s timer cutover.
        cases.push(
            Trace::new("shipped node, every msg3 lost, responder silent", rel)
                .shipped()
                .silent_old()
                .rule(Rule::drop(0, Class::Msg3, 100_000, 140_000))
                .until(330_000)
                .expect(Expect::lossless().outage(0, 62_000).must(0, "Assumed")),
        );
        // S-4: the setup is resent at 1 s. A 0.5.0 to 0.5.2 responder at
        // the larger address re-arms on the copy and answers it, and the
        // rekey completes at once. At the smaller address it drops the copy
        // at its tie-break, and 0.5.3 drops it as held, so the attempt ends
        // at its 30 s deadline, the responder's armed copy expires with it,
        // and the next attempt completes. Nothing is lost either way.
        for larger in [false, true] {
            let mut t = Trace::new("shipped node, ack lost", rel)
                .shipped()
                .rule(Rule::first(1, Class::Ack, 100_000, 1))
                .until(330_000);
            if larger {
                t = t.larger();
            }
            let expect = Expect::lossless().must(1, "promoted");
            t = t.expect(match (rel, larger) {
                (Rel::V053, _) => expect
                    .must(1, "dropped setup RekeyHeld")
                    .must(0, "Abandoned(Unanswered)"),
                (_, true) => expect
                    .must(1, "dropped setup RekeyTiebreak")
                    .must(0, "Abandoned(Unanswered)"),
                (_, false) => expect
                    .must(1, "yielded rekey to a setup")
                    .never(0, "Abandoned(Unanswered)"),
            });
            cases.push(t);
        }
        // S-7: the responder holds the pending and keeps the old epoch, the
        // shipped node retires at its deadline and its next attempts are
        // refused behind the pending until it is stale; nothing is lost.
        cases.push(
            Trace::new("shipped node, every probe lost, responder sending", rel)
                .shipped()
                .rule(Rule::drop(0, Class::Probe, 100_000, 140_000))
                .until(400_000)
                .expect(
                    Expect::lossless()
                        .must(1, "dropped setup RekeyPending")
                        .must(0, "Retired { tag: EpochTag(1) }"),
                ),
        );
        // S-5: the shipped node holds the deployed node's setup as a
        // candidate, cuts over at its msg3 and prompts; the initiator
        // promotes on the prompt.
        cases.push(
            Trace::new("deployed node initiates toward a shipped node", rel)
                .shipped()
                .old_first()
                .expect(installs(
                    "Installed { tag: EpochTag(1), role: Responder, evidence: Proof }",
                )),
        );
        // S-5 with the first three msg3 copies lost: the candidate waits
        // for the 7 s copy; the initiator's frames after its 2 s timer are
        // lost only until then.
        cases.push(
            Trace::new(
                "deployed node initiates toward a shipped node, first three msg3 copies lost",
                rel,
            )
            .shipped()
            .old_first()
            .rule(Rule::first(1, Class::Msg3, 100_000, 3))
            .expect(
                installs("Installed { tag: EpochTag(1), role: Responder, evidence: Proof }")
                    .outage(1, 6_000),
            ),
        );
        // S-6: every copy of the deployed initiator's msg3 lost; it cuts
        // over on its timer to keys the shipped node never completed, and
        // its frames are lost until the shipped node's own trigger, at
        // 135 s, as between two deployed nodes.
        cases.push(
            Trace::new("every msg3 of a deployed initiator lost, shipped node", rel)
                .shipped()
                .old_first()
                .rule(Rule::drop(1, Class::Msg3, 100_000, 170_000))
                .until(330_000)
                .expect(Expect::lossless().outage(1, 36_000).outage(0, 2_000)),
        );
        // 7.6 case A: the deployed node, larger, yields at the shipped
        // node's setup; the shipped node acknowledges the deployed node's
        // setup too, and the cutover on its peer's frame drops that
        // candidate.
        cases.push(
            Trace::new("crossing rekeys, shipped node smaller", rel)
                .shipped()
                .crossing()
                .expect(Expect::lossless().must(1, "yielded rekey to a setup").must(
                    0,
                    "Installed { tag: EpochTag(1), role: Initiator, evidence: Frame }",
                )),
        );
        // 7.6 case B: the shipped node, larger, acknowledges the deployed
        // node's setup beside its own attempt and yields at its msg3.
        cases.push(
            Trace::new("crossing rekeys, shipped node larger", rel)
                .shipped()
                .crossing()
                .larger()
                .expect(
                    Expect::lossless()
                        .must(1, "dropped setup RekeyTiebreak")
                        .must(0, "Abandoned(Yielded)")
                        .must(
                            0,
                            "Installed { tag: EpochTag(1), role: Responder, evidence: Proof }",
                        ),
                ),
        );
        // 7.6 case D: the shipped node, smaller, has completed when the
        // deployed node's setup arrives, and refuses it (S1-0); at its
        // deadline it retires on the peer staying and repairs, and the
        // larger deployed node yields its own to that setup.
        cases.push(
            Trace::new("setup meets a completed rekey at a shipped node", rel)
                .shipped()
                .rule(Rule::drop(0, Class::Msg3, 100_000, 140_000))
                .rule(Rule::delay(1, Class::Ack, 100_000, 106_000, 900))
                .until(330_000)
                .expect(
                    Expect::lossless()
                        .must(1, "initiated rekey")
                        .must(0, "Reject(TieBreakKept)")
                        .must(1, "yielded rekey to a setup"),
                ),
        );
        // The deployed node restarts at 40 s and, holding no session, sends
        // nothing. The shipped node keeps sending; 30 s after it last heard
        // the peer its silence rule starts a rekey, which the restarted node
        // answers as a first handshake. The ack carries the new startup
        // epoch, so the shipped node cuts over at its msg3, retiring the old
        // epoch, and reports the restart. Its frames are lost from the
        // restart to that cutover, 30 s; with no silence start they were
        // lost until its scheduled rekey at 105 s, and then until the peer's
        // first frame under the new keys.
        let mut t = Trace::new(
            "deployed node restarts, shipped node's silence reveals it",
            rel,
        )
        .shipped()
        .expect(
            installs("Installed { tag: EpochTag(1), role: Initiator, evidence: Restart }")
                .outage(0, 30_000)
                .must(0, "PeerRestarted"),
        );
        t.restart = Some(40_000);
        cases.push(t);
        // The deployed node restarts at 100 s and opens a session at
        // 100.5 s. Its setup is a candidate beside the running session, and
        // its msg3, carrying the new startup epoch, completes it: the old
        // epoch is retired and the restart reported. Only the shipped
        // node's frames sent between the restart and that msg3 are lost.
        let mut t = Trace::new(
            "deployed node restarts and opens toward a shipped node",
            rel,
        )
        .shipped()
        .expect(
            installs("Installed { tag: EpochTag(1), role: Responder, evidence: Proof }")
                .outage(0, 1_000)
                .must(0, "PeerRestarted"),
        );
        t.restart = Some(100_000);
        t.opens = alloc::vec![(100_500, 1)];
        cases.push(t);
        // A frame the responder sealed under the old epoch delayed past
        // the cutover still opens in the drain.
        cases.push(
            Trace::new("old-epoch frame delayed past a shipped node's cutover", rel)
                .shipped()
                .rule(Rule::delay(1, Class::Data, 104_500, 105_000, 2_000))
                .expect(
                    installs("Installed { tag: EpochTag(1), role: Initiator, evidence: Frame }")
                        .delivers_previous(0),
                ),
        );
    }
    // Strangers' setups naming the deployed peer neither stop the shipped
    // node's rotation nor evict the deployed initiator's candidate: its
    // first msg3 copies lost, the candidate outlives a burst of setups that
    // fills its link's quota and the table, and the next copy completes it.
    // Before the machine took setups, each such setup armed a handshake
    // that vetoed the node's own rekey and refused the peer's.
    let mut t = Trace::new(
        "shipped node keeps a rekey candidate through strangers' setups",
        Rel::V053,
    )
    .shipped()
    .old_first()
    .rule(Rule::first(1, Class::Msg3, 100_000, 3))
    .expect(
        installs("Installed { tag: EpochTag(1), role: Responder, evidence: Proof }")
            .outage(1, 7_000)
            .must(0, "Reject(CandidatesFull)"),
    );
    t.strangers = alloc::vec![(112_000, 0), (112_000, 7), (112_000, 8), (112_000, 9)];
    cases.push(t);
    cases
}

/// The first-handshake traces a new node runs against each release: either
/// end opening, crossing openings at both addresses, the deployed peer's
/// rekey while the first-handshake msg3 is unconfirmed at both addresses,
/// and a 0.5.0 to 0.5.2 peer
/// that lost the first msg3 and replaced its half-open entry with its own
/// attempt, against the releases each names. Each runs with the new node
/// polled at its next wake and as the node this release ships, polled on
/// the shell's tick.
#[test]
fn session_first_handshake_traces_hold_against_every_deployed_release() {
    let mut cases = Vec::new();
    for t in first_handshake_traces() {
        cases.push(t);
    }
    for t in first_handshake_traces() {
        cases.push(t.shipped());
    }
    all(cases.into_iter().map(|t| run(t, 13)).collect());
}

/// The cases of the first-handshake traces, for the new node.
fn first_handshake_traces() -> Vec<Trace> {
    let mut cases = Vec::new();
    for rel in Rel::ALL {
        // The new node opens; any release answers.
        let mut t = Trace::new("new node opens", rel).opening().expect(installs(
            "Installed { tag: EpochTag(0), role: Initiator, evidence: First }",
        ));
        t.opens = alloc::vec![(1_000, 0)];
        cases.push(t);
        // The deployed node opens; the new node's prompt confirms its
        // msg3.
        let mut t = Trace::new("deployed node opens", rel)
            .opening()
            .expect(installs(
                "Installed { tag: EpochTag(0), role: Responder, evidence: First }",
            ));
        t.opens = alloc::vec![(1_000, 1)];
        cases.push(t);
        // Crossing openings with the new node smaller: both settle on the
        // new node's handshake. With the new node
        // larger; both settle on the deployed node's.
        for new_smaller in [true, false] {
            let name = if new_smaller {
                "crossing openings, new node smaller"
            } else {
                "crossing openings, new node larger"
            };
            let mut t = Trace::new(name, rel).opening().expect(if new_smaller {
                installs("Installed { tag: EpochTag(0), role: Initiator, evidence: First }")
            } else {
                installs("Installed { tag: EpochTag(0), role: Responder, evidence: First }")
                    .must(0, "Abandoned(Yielded)")
            });
            t.setup.new_smaller = new_smaller;
            t.opens = alloc::vec![(1_000, 0), (1_000, 1)];
            cases.push(t);
        }
        // A deployed peer's count-triggered rekey at the larger address: every frame of the deployed peer is
        // lost until its count-triggered rekey; its setup, acknowledged
        // while the first msg3 is unconfirmed, completes.
        let mut t = Trace::new(
            "deployed rekey before the first handshake is confirmed, new node larger",
            rel,
        )
        .opening()
        .larger()
        .rule(Rule::until_sent(1, Class::Data, Class::Setup))
        .expect(installs(
            "Installed { tag: EpochTag(1), role: Responder, evidence: Proof }",
        ));
        t.setup.old_messages = Some(20);
        t.lat = [200, 200];
        t.opens = alloc::vec![(1_000, 0)];
        cases.push(t);
        // A deployed peer's count-triggered rekey at the smaller address: the setup is refused while the
        // first msg3 is unconfirmed, so the deployed peer never commits; the
        // pair rotates later with nothing lost.
        let mut t = Trace::new(
            "deployed rekey setup while the first msg3 is unconfirmed, new node smaller",
            rel,
        )
        .opening()
        .rule(Rule::until_sent(1, Class::Data, Class::Setup))
        .until(330_000)
        .expect(Expect::lossless().must(0, "Reject(TieBreakKept)"));
        t.setup.old_messages = Some(20);
        t.lat = [200, 200];
        t.opens = alloc::vec![(1_000, 0)];
        cases.push(t);
    }
    // Crossing openings against a smaller 0.5.2 peer whose first msg3 is lost: the new node, the
    // larger, holds back its 1 s and 3 s setup rungs while it holds the
    // peer's candidate, so the peer's 1 s msg3 copy reaches it unanswered
    // and it yields.
    let mut t = Trace::new(
        "crossing openings, new node larger, first msg3 lost",
        Rel::V052,
    )
    .opening()
    .larger()
    .rule(Rule::first(1, Class::Msg3, 0, 1))
    .expect(
        installs("Installed { tag: EpochTag(0), role: Responder, evidence: First }")
            .must(0, "Abandoned(Yielded)")
            // The peer's data sealed between its establishment on the
            // ack and the msg3 copy that arrives is lost, as it is
            // between two deployed nodes.
            .outage(1, 1_500),
    );
    t.opens = alloc::vec![(1_000, 0), (1_000, 1)];
    cases.push(t);
    // A 0.5.0 to 0.5.2 peer lost the new node's first msg3 and a
    // lookup replaced its half-open entry with its own attempt. At the
    // smaller address the new node refuses that attempt and its msg3 ladder's
    // repair completes the session; at the larger it yields to the peer's
    // msg3.
    for rel in [Rel::V050, Rel::V052] {
        for new_smaller in [true, false] {
            let mut t = Trace::new("first msg3 lost, deployed peer opens its own", rel)
                .opening()
                .rule(Rule::first(0, Class::Msg3, 0, 1))
                .until(200_000)
                .expect(if new_smaller {
                    Expect::lossless().outage(0, 34_000)
                } else {
                    Expect::lossless()
                        .outage(0, 3_000)
                        .must(0, "Installed { tag: EpochTag(1), role: Responder")
                });
            t.setup.new_smaller = new_smaller;
            t.opens = alloc::vec![(1_000, 0), (1_500, 1)];
            cases.push(t);
        }
    }
    cases
}

/// Seeded lossy runs of a new node against every release, and between two
/// new nodes (the production profile against itself), the node this release
/// ships in place of the new node in some of each: sessions opened by
/// either end or set up before the run, each end's trigger first, the
/// deployed end sending or silent from 100 s. Whatever the loss did, nothing
/// panics, and once it stops the session converges (against 0.5.0 and
/// 0.5.1, possibly with rotation stopped by the deployed node's own stuck
/// rekey).
#[test]
fn lossy_session_runs_converge_against_every_deployed_release() {
    let mut results = Vec::new();
    for rel in Rel::ALL {
        for seed in 0..10u64 {
            let mut t = Trace::new("lossy session run", rel);
            if seed % 2 == 1 {
                t = t.old_first();
            }
            if seed % 3 == 1 {
                t = t.silent_old();
            }
            if seed % 4 >= 2 {
                t = t.larger();
            }
            if seed % 5 == 4 {
                t = t.opening();
                t.opens = alloc::vec![(1_000, 0), (1_000 + 400 * (seed % 3), 1)];
                if seed >= 5 {
                    t = t.shipped();
                }
            } else if seed % 5 == 3 {
                t = t.shipped();
            }
            let name = format!("lossy session run {seed} against {rel:?}");
            let mut duo = session(&t.setup, 300 + seed);
            duo.period = t.period;
            duo.hush = t.hush;
            let mut duo = duo.seeded(400 + seed, 150);
            for (at, x) in t.opens {
                duo.run_until(at);
                duo.act(x, |end, now, out| end.open(now, out));
            }
            duo.run_until(600_000);
            let mut expect = Expect::lossless().outage(0, 600_000).outage(1, 600_000);
            if rel == Rel::V050 {
                // A 0.5.0 or 0.5.1 node's own rekey never retires, and at the
                // smaller address it drops every setup from the new node, so
                // rotation on the pair can stop while data keeps flowing
                // (accepted, the table of what a new node cannot
                // repair).
                expect = expect.stall_ok();
            }
            results.push(expect.check(&name, &mut duo, 300_000));
        }
    }
    for seed in 0..10u64 {
        let jitter = [[0, 30], [30, 0], [15, 15]][(seed % 3) as usize];
        let established = !(4..6).contains(&seed) && seed < 8;
        let shipped = seed >= 6;
        let mut duo = new_session(700 + seed, jitter, established, shipped).seeded(800 + seed, 150);
        if seed % 3 == 1 {
            duo.hush[1] = Some((100_000, 400_000));
        }
        if !established {
            duo.run_until(1_000);
            duo.act(0, |end, now, out| end.open(now, out));
            duo.act(1, |end, now, out| end.open(now, out));
        }
        duo.run_until(600_000);
        let name = format!("lossy session run {seed} between new nodes");
        let expect = Expect::lossless().outage(0, 600_000).outage(1, 600_000);
        results.push(expect.check(&name, &mut duo, 300_000));
    }
    all(results);
}
