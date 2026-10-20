//! The link rekey of the deployed releases, and the link traces a new node
//! runs against each.
//!
//! [`FmpPeer`] is one deployed node's view of one link peer, as its shell
//! and `ActivePeer` hold it: the current, pending and previous sessions with
//! their indices, the K bit, the rekey attempt and its msg1 ladder, the
//! responder's pending hold, the fixed drain and the heartbeat and
//! link-dead timers. Each rule cites the lines it implements as
//! `tag:path:line`, where `tag` is `v0.5.0` (identical at `v0.5.1` in every
//! file cited), `v0.5.2` or `v0.5.3`; where the three agree the earliest is
//! cited. The model's tick runs the deployed tick's steps in the deployed
//! order (`v0.5.0:src/node/dataplane/rx_loop.rs:448-476`): msg1 resends,
//! then heartbeats and the link-dead reap, then the rekey check.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest as _, Sha256};

use super::new::{Jit, NewFmp, is_datagram, link_data};
use super::{Class, E, End, Expect, Got, Out, Pkt, Rel, Rule, all, boxed};
use crate::identity::NodeAddr;
use crate::noise::{HandshakeState, NoiseSession};
use crate::proto::fmp::rekey::ik::setup_record;
use crate::proto::fmp::wire::{
    EncryptedHeader, Msg1Header, Msg2Header, build_established_header, build_msg1, build_msg2,
    strip_inner_header,
};
use crate::proto::link::LinkMessageType;
use crate::proto::rekey::{NodeKeys, Params, PeerKey, allocate};
use crate::testutil::{seed_entropy, seeded_keypair};
use crate::utils::index::{IndexAllocator, SessionIndex};

/// Seconds after the own switch that the previous session is kept
/// (`v0.5.0:src/node/handlers/rekey.rs:26`, the same at every tag).
const DRAIN_MS: u64 = 10_000;
/// Seconds after answering a peer's msg1 that no own rekey starts
/// (`v0.5.0:src/node/handlers/rekey.rs:30`).
const DAMPEN_MS: u64 = 30_000;
/// The session age below which a same-epoch msg1 is a duplicate, not a
/// rekey, measured from the last cutover or adoption
/// (`v0.5.0:src/proto/fmp/core.rs:429`, `v0.5.2:src/proto/fmp/core.rs:453`).
const SESSION_FLOOR: u64 = 30_000;
/// v0.5.3's two floors: the link age from promotion
/// (`v0.5.3:src/proto/fmp/core.rs:630`) and the time since the last cutover
/// (`v0.5.3:src/proto/fmp/core.rs:638`).
const LINK_FLOOR: u64 = 30_000;
/// See [`LINK_FLOOR`].
const CUTOVER_FLOOR: u64 = 10_000;
/// The responder's hold on an unadopted pending at the defaults
/// (`v0.5.2:src/node/handlers/rekey.rs:98-107`: the larger of the 120 s drain
/// ceiling and a 64 s floor).
const HOLD_MS: u64 = 120_000;
/// The msg1 resend interval and count (`v0.5.0:src/proto/fmp/core.rs:555-580`
/// with the rate-limit defaults: 1 s doubling, five resends).
const RESEND_MS: u64 = 1_000;
/// See [`RESEND_MS`].
const MAX_RESENDS: u32 = 5;
/// The heartbeat interval and the link-dead timeout at the defaults
/// (`v0.5.2:src/config/node.rs:1396-1401`).
const HEARTBEAT_MS: u64 = 10_000;
/// See [`HEARTBEAT_MS`].
const DEAD_MS: u64 = 30_000;
/// Consecutive decrypt failures that remove a peer before v0.5.3
/// (`v0.5.0:src/node/dataplane/encrypted.rs:12`, `:522-530`); v0.5.3 keeps
/// the peer (`v0.5.3:src/node/dataplane/encrypted.rs:684-697`).
const FAILURES: u32 = 20;
/// The rekey time trigger and message trigger at the defaults
/// (`v0.5.2:src/config/node.rs:1165-1170`).
const AFTER_MS: u64 = 120_000;
/// See [`AFTER_MS`].
const AFTER_MESSAGES: u64 = 1 << 16;

/// Which side of a rekey produced a pending session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

/// A completed rekey not yet switched to.
struct Pending {
    session: NoiseSession,
    ours: u32,
    theirs: u32,
    role: Role,
    since: u64,
    /// v0.5.3: the msg2 revealed a peer restart, so the cutover sets K 0
    /// (`v0.5.3:src/peer/active.rs:1356-1380`).
    restart: bool,
    /// v0.5.3: the msg1 that armed a responder pending, by digest, and the
    /// msg2 sent for it (`v0.5.3:src/proto/fmp/core.rs:163-175`).
    answer: Option<([u8; 32], Vec<u8>)>,
}

/// An own rekey in flight (`v0.5.0:src/peer/active.rs` `set_rekey_state`).
struct Attempt {
    hs: HandshakeState<E>,
    ours: u32,
    msg1: Vec<u8>,
    next: u64,
    count: u32,
}

/// One established link peer, as `ActivePeer` holds it.
struct Link {
    remote_epoch: [u8; 8],
    cur: NoiseSession,
    ours: u32,
    theirs: u32,
    k: bool,
    prev: Option<(NoiseSession, u32)>,
    drain_started: Option<u64>,
    pending: Option<Pending>,
    attempt: Option<Attempt>,
    /// The last cutover or adoption, or the promotion.
    established: u64,
    /// The promotion, or a restart our rekey revealed (v0.5.3's link age).
    linked: u64,
    answered: Option<u64>,
    jitter: i64,
    failures: u32,
    setup_msg2: Option<Vec<u8>>,
    setup_msg1: [u8; 32],
    /// v0.5.3: digests of msg1s whose answered cycle ended
    /// (`v0.5.3:src/proto/fmp/core.rs:184-254`).
    ended: VecDeque<[u8; 32]>,
    last_rx: u64,
    last_hb: u64,
}

/// A deployed node's link to one peer.
pub(crate) struct FmpPeer {
    rel: Rel,
    local: NodeKeys,
    addr: NodeAddr,
    peer_key: PeerKey,
    alloc: IndexAllocator<E>,
    link: Option<Link>,
    /// The jitter draws this node takes at each new session, in seconds
    /// within `[-15, 15]`, the last repeated (`v0.5.0:src/peer/active.rs:21`).
    pub(crate) jitter: Vec<i64>,
    notes: Vec<String>,
    label: String,
}

/// The digest of a whole msg1, as `Msg1Digest::of` takes it
/// (`v0.5.3:src/proto/fmp/core.rs:153-160`).
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

impl FmpPeer {
    /// A deployed node of release `rel` holding a link set up with
    /// `session`.
    #[expect(clippy::too_many_arguments, reason = "the facts a link setup leaves")]
    pub(crate) fn established(
        label: &str,
        rel: Rel,
        local: NodeKeys,
        peer_key: PeerKey,
        remote_epoch: [u8; 8],
        session: NoiseSession,
        ours: u32,
        alloc: IndexAllocator<E>,
        theirs: u32,
        setup: (&[u8], Option<Vec<u8>>),
        now: u64,
        jitter: Vec<i64>,
    ) -> Self {
        let addr = PeerKey::from_xonly(&local.keypair().x_only_public_key().0).addr();
        let mut p = Self {
            rel,
            local,
            addr,
            peer_key,
            alloc,
            link: None,
            jitter,
            notes: Vec::new(),
            label: String::from(label),
        };
        let jitter = p.draw();
        p.link = Some(Link {
            remote_epoch,
            cur: session,
            ours,
            theirs,
            k: false,
            prev: None,
            drain_started: None,
            pending: None,
            attempt: None,
            established: now,
            linked: now,
            answered: None,
            jitter,
            failures: 0,
            setup_msg2: setup.1,
            setup_msg1: digest(setup.0),
            ended: VecDeque::from([digest(setup.0)]),
            last_rx: now,
            last_hb: now,
        });
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

    /// Whether this node's address is the smaller of the two, which wins
    /// the dual-initiation tie-break (`v0.5.0:src/proto/fmp/core.rs:636-650`,
    /// `cross_connection_winner` with `this_is_outbound`).
    fn wins(&self) -> bool {
        self.addr < self.peer_key.addr()
    }

    /// Seal `plaintext` under the current session, framed as the deployed
    /// sender frames it (`v0.5.0:src/node/mod.rs` `send_encrypted_link_message`).
    fn seal(link: &mut Link, plaintext: &[u8]) -> Vec<u8> {
        let counter = link.cur.current_send_counter();
        let header = build_established_header(
            SessionIndex::new(link.theirs),
            counter,
            u8::from(link.k),
            plaintext.len() as u16,
        );
        let ct = link
            .cur
            .encrypt_with_aad(plaintext, &header)
            .expect("a frame this size seals");
        let mut f = header.to_vec();
        f.extend_from_slice(&ct);
        f
    }

    /// The deployed cutover (initiator) and adoption (responder): the
    /// current session becomes the previous one over whatever that held, the
    /// pending becomes current, the K bit flips, and the rekey clock and
    /// jitter restart (`v0.5.0:src/peer/active.rs:1086-1155`;
    /// `v0.5.3:src/peer/active.rs:1356-1456`: K 0 after a revealed restart,
    /// and the frame's K at an adoption).
    fn switch(&mut self, now: u64, frame_k: Option<bool>) {
        let rel = self.rel;
        let jitter = self.draw();
        let link = self.link.as_mut().expect("a link");
        let Some(p) = link.pending.take() else {
            return;
        };
        if let Some(answer) = p.answer {
            link.ended.push_back(answer.0);
        }
        let old = core::mem::replace(&mut link.cur, p.session);
        link.prev = Some((old, link.ours));
        link.drain_started = Some(now);
        link.ours = p.ours;
        link.theirs = p.theirs;
        link.k = match (rel, p.restart, frame_k) {
            (Rel::V053, true, _) => false,
            (Rel::V053, false, Some(k)) => k,
            (Rel::V050 | Rel::V052 | Rel::V053, _, _) => !link.k,
        };
        link.established = now;
        link.jitter = jitter;
        link.attempt = None;
        // The MMP reset at the switch restarts the liveness fallback
        // (`v0.5.2:src/node/handlers/mmp.rs:503-516`).
        link.last_rx = link.last_rx.max(now);
        self.notes.push(format!("switched k={}", link.k));
    }

    /// Respond to a peer's rekey msg1: answer into a responder pending and
    /// open dampening (`v0.5.0:src/node/handlers/handshake.rs:645-730`).
    fn respond(
        &mut self,
        now: u64,
        hs: HandshakeState<E>,
        theirs: u32,
        digest: [u8; 32],
        out: &mut Vec<Out>,
    ) {
        let Some(ours) = allocate(&mut self.alloc) else {
            return;
        };
        let ours = ours.release();
        let mut hs = hs;
        let Ok(noise) = hs.write_message_2() else {
            return;
        };
        let Ok(session) = hs.into_session() else {
            return;
        };
        let msg2 = build_msg2(SessionIndex::new(ours), SessionIndex::new(theirs), &noise);
        out.push(Out::new(Pkt::Link(msg2.clone()), Class::Msg2));
        let rel = self.rel;
        let link = self.link.as_mut().expect("a link");
        link.pending = Some(Pending {
            session,
            ours,
            theirs,
            role: Role::Responder,
            since: now,
            restart: false,
            answer: (rel == Rel::V053).then_some((digest, msg2)),
        });
        link.answered = Some(now);
        self.notes.push(String::from("answered msg1"));
    }

    /// Abandon the own attempt (`v0.5.0:src/peer/active.rs:1184-1210`).
    fn abandon(&mut self) {
        if let Some(link) = self.link.as_mut()
            && let Some(a) = link.attempt.take()
        {
            let _ = self.alloc.free(SessionIndex::new(a.ours));
            self.notes.push(String::from("abandoned attempt"));
        }
    }

    /// A msg1 from the peer (`v0.5.0:src/node/handlers/handshake.rs:323-730`
    /// and the classification `establish_inbound`,
    /// `v0.5.0:src/proto/fmp/core.rs:598-655`,
    /// `v0.5.2:src/proto/fmp/core.rs:636-693`,
    /// `v0.5.3:src/proto/fmp/core.rs:830-937`).
    fn msg1(&mut self, now: u64, bytes: &[u8], out: &mut Vec<Out>) {
        let Some(header) = Msg1Header::parse(bytes) else {
            return;
        };
        let mut hs = HandshakeState::<E>::new_responder(self.local.keypair());
        hs.set_local_epoch(self.local.epoch());
        if hs
            .read_message_1(&bytes[header.noise_msg1_offset..])
            .is_err()
        {
            return;
        }
        let Some(remote) = hs
            .remote_static()
            .map(|k| PeerKey::from_xonly(&k.x_only_public_key().0))
        else {
            return;
        };
        let epoch = hs.remote_epoch().unwrap_or_default();
        let theirs = header.sender_idx.as_u32();
        let d = digest(bytes);
        if remote != self.peer_key {
            return;
        }
        let Some(link) = self.link.as_ref() else {
            // No peer for the identity: promote it as a fresh link
            // (`InboundDecision::Promote`).
            self.promote(now, hs, epoch, theirs, d, out);
            return;
        };
        if link.remote_epoch != epoch {
            // A restart: the old peer goes and the fresh one is promoted
            // (`RestartThenPromote`).
            self.link = None;
            self.promote(now, hs, epoch, theirs, d, out);
            return;
        }
        let session_age = now.saturating_sub(link.established);
        let link_age = now.saturating_sub(link.linked);
        let eligible = match self.rel {
            Rel::V050 | Rel::V052 => session_age >= SESSION_FLOOR,
            Rel::V053 => link_age >= LINK_FLOOR && session_age >= CUTOVER_FLOOR,
        };
        let answered = self.rel == Rel::V053 && link.ended.contains(&d);
        if !eligible {
            match self.rel {
                // A duplicate: resend the stored setup msg2, whatever the
                // msg1 (`v0.5.0:src/proto/fmp/core.rs:620-629`).
                Rel::V050 | Rel::V052 => {
                    if let Some(m) = link.setup_msg2.clone() {
                        out.push(Out::new(Pkt::Link(m), Class::Msg2));
                        self.notes.push(String::from("resent setup msg2"));
                    }
                }
                Rel::V053 => {
                    if d == link.setup_msg1 {
                        if let Some(m) = link.setup_msg2.clone() {
                            out.push(Out::new(Pkt::Link(m), Class::Msg2));
                        }
                    } else if answered {
                        self.notes.push(String::from("refused AnsweredBefore"));
                    } else {
                        // A fresh dial from a peer that lost its side: the
                        // link is replaced (`ReplaceThenPromote`).
                        self.link = None;
                        self.promote(now, hs, epoch, theirs, d, out);
                    }
                }
            }
            return;
        }
        if let Some(p) = &link.pending {
            if let (Rel::V053, Some((armed, msg2))) = (self.rel, &p.answer)
                && *armed == d
            {
                out.push(Out::new(Pkt::Link(msg2.clone()), Class::Msg2));
                self.notes.push(String::from("resent held msg2"));
                return;
            }
            self.notes.push(String::from("refused PendingSession"));
            return;
        }
        if answered {
            self.notes.push(String::from("refused AnsweredBefore"));
            return;
        }
        if link.attempt.is_some() {
            if self.wins() {
                self.notes.push(String::from("refused DualRekeyWon"));
                return;
            }
            self.abandon();
        }
        self.respond(now, hs, theirs, d, out);
    }

    /// Promote a fresh inbound link from a msg1: a new session at K 0, its
    /// setup msg2 stored for duplicates
    /// (`v0.5.0:src/node/handlers/handshake.rs` `promote_connection`).
    fn promote(
        &mut self,
        now: u64,
        mut hs: HandshakeState<E>,
        epoch: [u8; 8],
        theirs: u32,
        d: [u8; 32],
        out: &mut Vec<Out>,
    ) {
        let Some(ours) = allocate(&mut self.alloc) else {
            return;
        };
        let ours = ours.release();
        let Ok(noise) = hs.write_message_2() else {
            return;
        };
        let Ok(session) = hs.into_session() else {
            return;
        };
        let msg2 = build_msg2(SessionIndex::new(ours), SessionIndex::new(theirs), &noise);
        out.push(Out::new(Pkt::Link(msg2.clone()), Class::Msg2));
        let jitter = self.draw();
        self.link = Some(Link {
            remote_epoch: epoch,
            cur: session,
            ours,
            theirs,
            k: false,
            prev: None,
            drain_started: None,
            pending: None,
            attempt: None,
            established: now,
            linked: now,
            answered: None,
            jitter,
            failures: 0,
            setup_msg2: Some(msg2),
            setup_msg1: d,
            ended: VecDeque::from([d]),
            last_rx: now,
            last_hb: now,
        });
        self.notes.push(String::from("promoted a fresh link"));
    }

    /// A msg2 for the own attempt (`v0.5.0:src/node/handlers/handshake.rs:1133-1260`;
    /// `v0.5.2:src/node/handlers/handshake.rs:1240-1250`: a msg2 that does
    /// not read keeps the cycle; before v0.5.2 it abandons it). At v0.5.3 a
    /// restart the msg2 reveals restarts the link age
    /// (`v0.5.3:src/proto/fmp/core.rs:621-630`).
    fn msg2(&mut self, now: u64, bytes: &[u8]) {
        let Some(header) = Msg2Header::parse(bytes) else {
            return;
        };
        let rel = self.rel;
        let Some(link) = self.link.as_mut() else {
            return;
        };
        let Some(a) = link.attempt.as_ref() else {
            self.notes.push(String::from("msg2 for no attempt"));
            return;
        };
        if a.ours != header.receiver_idx.as_u32() {
            self.notes.push(String::from("msg2 for no attempt"));
            return;
        }
        let noise = &bytes[header.noise_msg2_offset..];
        match a.hs.fork_msg2(noise) {
            Ok(hs) => {
                let a = link.attempt.take().expect("the attempt");
                let epoch = hs.remote_epoch().unwrap_or_default();
                let restart = epoch != link.remote_epoch;
                link.remote_epoch = epoch;
                let Ok(session) = hs.into_session() else {
                    return;
                };
                if restart && rel == Rel::V053 {
                    link.linked = now;
                }
                link.pending = Some(Pending {
                    session,
                    ours: a.ours,
                    theirs: header.sender_idx.as_u32(),
                    role: Role::Initiator,
                    since: 0,
                    restart,
                    answer: None,
                });
                self.notes.push(format!("completed restart={restart}"));
            }
            Err(_) if rel >= Rel::V052 => {
                self.notes.push(String::from("msg2 unreadable, cycle kept"))
            }
            Err(_) => {
                self.abandon();
                self.notes
                    .push(String::from("msg2 unreadable, cycle abandoned"));
            }
        }
    }

    /// An established frame (`v0.5.0:src/node/dataplane/encrypted.rs:24-300`;
    /// the pending trial on a flipped K at `:75-160`, extended at v0.5.3 to a
    /// frame naming the pending index, `v0.5.3:src/node/dataplane/encrypted.rs:107-118`;
    /// the current then previous decrypt at `v0.5.0:...:211-250`; v0.5.3
    /// keeps previous-session frames out of liveness,
    /// `v0.5.3:src/node/dataplane/encrypted.rs:300-318`).
    fn frame(&mut self, now: u64, bytes: &[u8]) -> Got {
        let Some(h) = EncryptedHeader::parse(bytes) else {
            return Got::Refused;
        };
        let rel = self.rel;
        let Some(link) = self.link.as_mut() else {
            return Got::Refused;
        };
        let idx = h.receiver_idx.as_u32();
        let known = idx == link.ours
            || link.prev.as_ref().is_some_and(|p| p.1 == idx)
            || link.pending.as_ref().is_some_and(|p| p.ours == idx);
        if !known {
            return Got::Refused;
        }
        let k = h.flags & 1 != 0;
        let ct = &bytes[h.ciphertext_offset()..];
        let try_pending = link.pending.is_some()
            && (k != link.k
                || (rel == Rel::V053 && link.pending.as_ref().is_some_and(|p| p.ours == idx)));
        if try_pending {
            let ok = link
                .pending
                .as_mut()
                .expect("a pending")
                .session
                .decrypt_with_replay_check_and_aad(ct, h.counter, &h.header_bytes);
            if let Ok(p) = ok {
                self.switch(now, Some(k));
                let link = self.link.as_mut().expect("a link");
                link.failures = 0;
                link.last_rx = now;
                return Self::deliver(&p, true);
            }
        }
        let link = self.link.as_mut().expect("a link");
        if let Ok(p) = link
            .cur
            .decrypt_with_replay_check_and_aad(ct, h.counter, &h.header_bytes)
        {
            link.failures = 0;
            link.last_rx = now;
            return Self::deliver(&p, true);
        }
        if let Some((prev, _)) = link.prev.as_mut()
            && let Ok(p) = prev.decrypt_with_replay_check_and_aad(ct, h.counter, &h.header_bytes)
        {
            link.failures = 0;
            if rel < Rel::V053 {
                link.last_rx = now;
            }
            return Self::deliver(&p, false);
        }
        link.failures += 1;
        if rel < Rel::V053 && link.failures >= FAILURES {
            self.link = None;
            self.notes.push(String::from("removed: decrypt failures"));
        }
        Got::Refused
    }

    /// What an accepted frame was.
    fn deliver(plaintext: &[u8], current: bool) -> Got {
        match strip_inner_header(plaintext) {
            Some(_) if is_datagram(plaintext) => Got::Data { current },
            Some(_) | None => Got::Frame,
        }
    }

    /// Start a rekey: a fresh index, an IK initiator handshake, msg1 on the
    /// link and its ladder armed (`v0.5.0:src/node/handlers/rekey.rs:312-400`).
    fn initiate(&mut self, now: u64, out: &mut Vec<Out>) {
        let Some(ours) = allocate(&mut self.alloc) else {
            return;
        };
        let ours = ours.release();
        let pk = crate::proto::rekey::keys::pinned(&self.peer_key).expect("a valid key");
        let mut hs = HandshakeState::<E>::new_initiator(self.local.keypair(), pk);
        hs.set_local_epoch(self.local.epoch());
        let Ok(noise) = hs.write_message_1() else {
            return;
        };
        let msg1 = build_msg1(SessionIndex::new(ours), &noise);
        out.push(Out::new(Pkt::Link(msg1.clone()), Class::Msg1));
        if let Some(link) = self.link.as_mut() {
            link.attempt = Some(Attempt {
                hs,
                ours,
                msg1,
                next: now + RESEND_MS,
                count: 0,
            });
        }
        self.notes.push(String::from("initiated"));
    }
}

impl End for FmpPeer {
    fn tick(&mut self, now: u64, out: &mut Vec<Out>) {
        // msg1 resends and the abandon at the budget
        // (`v0.5.0:src/node/handlers/rekey.rs:403-470`, decided by
        // `v0.5.0:src/proto/fmp/core.rs:555-580`).
        if let Some(link) = self.link.as_mut()
            && let Some(a) = link.attempt.as_mut()
        {
            if a.count >= MAX_RESENDS {
                self.abandon();
            } else if now >= a.next {
                out.push(Out::new(Pkt::Link(a.msg1.clone()), Class::Msg1));
                a.count += 1;
                a.next = now + RESEND_MS * (1 << a.count);
            }
        }
        // Heartbeats and the link-dead reap, suppressed while an attempt has
        // budget left (`v0.5.2:src/node/handlers/mmp.rs:479-580`).
        if let Some(link) = self.link.as_mut() {
            let active = link.attempt.as_ref().is_some_and(|a| a.count < MAX_RESENDS);
            if now.saturating_sub(link.last_rx) >= DEAD_MS && !active {
                self.link = None;
                self.notes.push(String::from("link dead"));
                return;
            }
            if now.saturating_sub(link.last_hb) >= HEARTBEAT_MS {
                link.last_hb = now;
                let mut p = (now as u32).to_le_bytes().to_vec();
                p.push(LinkMessageType::Heartbeat.to_byte());
                let f = Self::seal(link, &p);
                out.push(Out::new(Pkt::Link(f), Class::Ctl));
            }
        }
        // The rekey check (`v0.5.0:src/proto/fmp/core.rs:518-550`,
        // `v0.5.2:src/proto/fmp/core.rs:547-590`): an initiator pending cuts
        // over (before v0.5.2 any pending does: the role gate arrived with
        // v0.5.2), a responder pending past its hold is retired (v0.5.2 on),
        // a drain ends after 10 s, and the trigger fires when no attempt is
        // in flight, dampening has passed and (v0.5.2 on) no pending is held.
        let rel = self.rel;
        let Some(link) = self.link.as_mut() else {
            return;
        };
        if let Some(p) = &link.pending
            && link.attempt.is_none()
            && (rel == Rel::V050 || p.role == Role::Initiator)
        {
            self.switch(now, None);
            return;
        }
        if let Some(p) = &link.pending
            && rel >= Rel::V052
            && p.role == Role::Responder
            && now.saturating_sub(p.since) >= HOLD_MS
        {
            let p = link.pending.take().expect("a pending");
            if let Some(answer) = p.answer {
                link.ended.push_back(answer.0);
            }
            let _ = self.alloc.free(SessionIndex::new(p.ours));
            self.notes.push(String::from("retired unadopted pending"));
        }
        let link = self.link.as_mut().expect("a link");
        if let Some(t) = link.drain_started
            && now.saturating_sub(t) >= DRAIN_MS
        {
            if let Some((_, idx)) = link.prev.take() {
                let _ = self.alloc.free(SessionIndex::new(idx));
            }
            link.drain_started = None;
        }
        let dampened = link
            .answered
            .is_some_and(|t| now.saturating_sub(t) < DAMPEN_MS);
        if link.attempt.is_some() || dampened || (rel >= Rel::V052 && link.pending.is_some()) {
            return;
        }
        let after = AFTER_MS.saturating_add_signed(link.jitter * 1_000);
        if now.saturating_sub(link.established) >= after
            || link.cur.current_send_counter() >= AFTER_MESSAGES
        {
            self.initiate(now, out);
        }
    }

    fn recv(&mut self, now: u64, pkt: &Pkt, out: &mut Vec<Out>) -> Got {
        let Pkt::Link(bytes) = pkt else {
            return Got::Other;
        };
        match bytes.first().map(|b| b & 0x0f) {
            Some(1) => {
                self.msg1(now, bytes, out);
                Got::Other
            }
            Some(2) => {
                self.msg2(now, bytes);
                Got::Other
            }
            Some(0) => self.frame(now, bytes),
            Some(_) | None => Got::Other,
        }
    }

    fn data(&mut self, now: u64, seq: u64, out: &mut Vec<Out>) -> bool {
        let Some(link) = self.link.as_mut() else {
            return false;
        };
        let p = link_data(crate::time::Duration::from_millis(now), seq);
        let f = Self::seal(link, &p);
        out.push(Out::new(Pkt::Link(f), Class::Data));
        true
    }

    fn wake(&self) -> Option<u64> {
        None
    }

    fn alive(&self) -> bool {
        self.link.is_some()
    }

    fn quiet(&self) -> bool {
        self.link
            .as_ref()
            .is_some_and(|l| l.attempt.is_none() && l.pending.is_none())
    }

    fn take_notes(&mut self) -> Vec<String> {
        core::mem::take(&mut self.notes)
    }

    fn name(&self) -> String {
        self.label.clone()
    }

    /// Every peer state is lost and a new startup epoch drawn (FRC-1201
    /// section 5.5).
    fn restart(&mut self, epoch: [u8; 8]) {
        self.local = NodeKeys::new(self.local.keypair(), epoch);
        self.link = None;
        self.alloc = IndexAllocator::new();
        self.notes.push(String::from("restarted"));
    }
}

/// How a link trace starts: which node is new, and the jitter each draws.
pub(crate) struct Setup {
    /// The deployed release of the other node.
    pub(crate) rel: Rel,
    /// The new node is node 0 when true, node 1 otherwise.
    pub(crate) new_first: bool,
    /// The new node's jitter draw (0 is -15 s, 15 is 0 s).
    pub(crate) new_jitter: u16,
    /// The deployed node's jitter, in seconds.
    pub(crate) old_jitter: i64,
    /// The new node has the smaller address.
    pub(crate) new_smaller: bool,
    /// The K bit of the new node's first epoch: 1 stands for a link whose
    /// two ends' parities fell out of step before (a cross-connection
    /// move carries the replaced epoch's K), the deployed end being at 0.
    pub(crate) new_k: bool,
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

/// A link between a new node and a deployed one, set up at time 0 by a
/// link handshake the new node initiated.
pub(crate) fn link(s: &Setup, seed: u64) -> (super::Duo, usize) {
    seed_entropy(seed);
    let (nk, ok) = keys(seed, s.new_smaller);
    let npub = PeerKey::from_xonly(&nk.keypair().x_only_public_key().0);
    let opub = PeerKey::from_xonly(&ok.keypair().x_only_public_key().0);
    let mut nalloc = IndexAllocator::<E>::new();
    let mut oalloc = IndexAllocator::<E>::new();
    let nlease = allocate(&mut nalloc).expect("an index");
    let olease = allocate(&mut oalloc).expect("an index");
    let (ni, oi) = (nlease.index(), olease.index());
    let mut hi = HandshakeState::<E>::new_initiator(
        nk.keypair(),
        crate::proto::rekey::keys::pinned(&opub).expect("a key"),
    );
    hi.set_local_epoch(nk.epoch());
    let m1 = build_msg1(SessionIndex::new(ni), &hi.write_message_1().expect("msg1"));
    let mut hr = HandshakeState::<E>::new_responder(ok.keypair());
    hr.set_local_epoch(ok.epoch());
    hr.read_message_1(&m1[8..]).expect("reads");
    let m2 = build_msg2(
        SessionIndex::new(oi),
        SessionIndex::new(ni),
        &hr.write_message_2().expect("msg2"),
    );
    hi.read_message_2(&m2[12..]).expect("reads");
    let (ns, os) = (
        hi.into_session().expect("done"),
        hr.into_session().expect("done"),
    );
    let record = setup_record(&m1, None).expect("a record");
    let new = NewFmp::established(
        &format!("new({:?})", s.rel),
        nk,
        opub,
        [0x22; 8],
        ns,
        nlease,
        nalloc,
        oi,
        record,
        s.new_k,
        0,
        Params::fmp(),
        Jit::Fixed(s.new_jitter),
    );
    let old_lease = olease.release();
    let old = FmpPeer::established(
        &format!("{:?}", s.rel),
        s.rel,
        ok,
        npub,
        [0x11; 8],
        os,
        old_lease,
        oalloc,
        ni,
        (&m1, Some(m2)),
        0,
        alloc::vec![s.old_jitter],
    );
    let (a, b, x) = if s.new_first {
        (boxed(new), boxed(old), 0)
    } else {
        (boxed(old), boxed(new), 1)
    };
    (super::Duo::new(a, b, 0), x)
}

/// A link between two new nodes, set up at time 0 by a link handshake the
/// first initiated: the production profile against itself.
pub(crate) fn new_link(seed: u64, jitter: [u16; 2]) -> super::Duo {
    seed_entropy(seed);
    let (ak, bk) = keys(seed, true);
    let apub = PeerKey::from_xonly(&ak.keypair().x_only_public_key().0);
    let bpub = PeerKey::from_xonly(&bk.keypair().x_only_public_key().0);
    let mut aalloc = IndexAllocator::<E>::new();
    let mut balloc = IndexAllocator::<E>::new();
    let alease = allocate(&mut aalloc).expect("an index");
    let blease = allocate(&mut balloc).expect("an index");
    let (ai, bi) = (alease.index(), blease.index());
    let mut hi = HandshakeState::<E>::new_initiator(
        ak.keypair(),
        crate::proto::rekey::keys::pinned(&bpub).expect("a key"),
    );
    hi.set_local_epoch(ak.epoch());
    let m1 = build_msg1(SessionIndex::new(ai), &hi.write_message_1().expect("msg1"));
    let mut hr = HandshakeState::<E>::new_responder(bk.keypair());
    hr.set_local_epoch(bk.epoch());
    hr.read_message_1(&m1[8..]).expect("reads");
    let m2 = build_msg2(
        SessionIndex::new(bi),
        SessionIndex::new(ai),
        &hr.write_message_2().expect("msg2"),
    );
    hi.read_message_2(&m2[12..]).expect("reads");
    let (asess, bsess) = (
        hi.into_session().expect("done"),
        hr.into_session().expect("done"),
    );
    let a = NewFmp::established(
        "new a",
        ak,
        bpub,
        [0x22; 8],
        asess,
        alease,
        aalloc,
        bi,
        setup_record(&m1, None).expect("a record"),
        false,
        0,
        Params::fmp(),
        Jit::Fixed(jitter[0]),
    );
    let b = NewFmp::established(
        "new b",
        bk,
        apub,
        [0x11; 8],
        bsess,
        blease,
        balloc,
        ai,
        setup_record(&m1, Some(&m2)).expect("a record"),
        false,
        0,
        Params::fmp(),
        Jit::Fixed(jitter[1]),
    );
    super::Duo::new(boxed(a), boxed(b), 0)
}

/// A trace: its name, how it starts, its faults, how long it runs before
/// the heal, and what must hold.
struct Trace {
    name: &'static str,
    setup: Setup,
    rules: Vec<Rule>,
    run: u64,
    expect: Expect,
    /// The deployed node restarts at this instant, before the new node's
    /// rekey.
    restart: Option<u64>,
}

/// Run one trace and check it, with the new node's index conservation.
fn run(t: Trace, seed: u64) -> Result<(), String> {
    let name = format!("{} against {:?}", t.name, t.setup.rel);
    let (mut duo, x) = link(&t.setup, seed);
    duo.rules = t.rules;
    if let Some(at) = t.restart {
        duo.run_until(at);
        duo.n[1 - x].restart([0x33; 8]);
    }
    duo.run_until(t.run);
    t.expect.check(&name, &mut duo, 300_000)
}

/// The new node's jitter draw for a trigger at 105 s, the band's low end.
const EARLY: u16 = 0;
/// The new node's jitter draw for a trigger at 135 s, the band's high end.
const LATE: u16 = 30;
/// The new node's jitter draw for a trigger at 120 s, so two new nodes at
/// it start in the same poll.
const MID: u16 = 15;

/// A trace against `rel`: the new node first (ticking at the second's
/// start), its trigger at 105 s and the deployed node's at 135 s, so the new
/// node initiates; `f` adjusts it.
fn trace(name: &'static str, rel: Rel, f: impl FnOnce(&mut Trace)) -> Trace {
    let mut t = Trace {
        name,
        setup: Setup {
            rel,
            new_first: true,
            new_jitter: EARLY,
            old_jitter: 15,
            new_smaller: true,
            new_k: false,
        },
        rules: Vec::new(),
        run: 200_000,
        expect: Expect::lossless(),
        restart: None,
    };
    f(&mut t);
    t
}

/// The link traces a new node runs against each release: a rekey started
/// by either end with no loss, a lost msg2, a lost cutover prompt, a
/// restart the rekey reveals, and the schedules that hold the machine's
/// guards to their interop consequences: the dual initiation in both
/// address orders (the larger node abandons its own attempt for a fresh
/// eligible msg1), every msg2 lost against a deployed initiator (no
/// responder cutover on a timer), and the K parity mismatch against v0.5.2
/// (a new epoch takes the inverse of the peer's last K).
#[test]
fn link_traces_hold_against_every_deployed_release() {
    let mut cases = Vec::new();
    for rel in Rel::ALL {
        // The new node initiates with no loss; every release adopts
        // the new epoch on the new node's cutover prompt.
        cases.push(trace("new node initiates", rel, |t| {
            t.expect = Expect::lossless()
                .must(
                    0,
                    "Installed { tag: EpochTag(1), role: Initiator, evidence: Proof }",
                )
                .must(1, "switched");
        }));
        // The msg2 is lost.
        cases.push(trace("msg2 lost", rel, |t| {
            t.rules = alloc::vec![Rule::first(1, Class::Msg2, 100_000, 1)];
            t.run = 330_000;
            t.expect = match rel {
                // The held answer draws the same msg2 for the resend.
                Rel::V053 => Expect::lossless().must(1, "resent held msg2"),
                // Every resend is refused behind the pending, the attempt
                // ends at 30 s, the pending is retired at 120 s and the next
                // attempt completes; data stays on the old epoch.
                Rel::V052 => Expect::lossless()
                    .must(1, "refused PendingSession")
                    .must(0, "Abandoned(Unanswered)")
                    .must(1, "retired unadopted pending")
                    .must(1, "switched"),
                // The responder cuts over on its own tick to keys the new
                // node never installed, and the link splits until link-dead
                // removes it (accepted residual, the deployed defect the
                // table of what a new node cannot repair in a deployed peer lists
                // first): the new node reaps it about 31 s after the lost
                // msg2, and the deployed node, whose frames are lost from its
                // self-cutover, reaps it 30 s after its 10 s drain ends.
                Rel::V050 => Expect::lossless()
                    .outage(0, 32_000)
                    .outage(1, 41_000)
                    .split()
                    .must(0, "link dead"),
            };
        }));
        // The new node's cutover prompt is lost; the elicit rung
        // adopts, and the drain held until evidence keeps the link alive.
        cases.push(trace("cutover prompt lost", rel, |t| {
            t.rules = alloc::vec![Rule::first(0, Class::Prompt, 100_000, 1)];
            t.expect = Expect::lossless().never(0, "link dead").must(1, "switched");
        }));
        // The deployed node initiates and the new node answers.
        cases.push(trace("deployed node initiates", rel, |t| {
            t.setup.new_jitter = LATE;
            t.setup.old_jitter = -15;
            t.expect = Expect::lossless().must(1, "initiated").must(
                0,
                "Installed { tag: EpochTag(1), role: Responder, evidence: Frame }",
            );
        }));
        // The deployed node initiates and the first msg2 is lost: the resend draws the stored msg2.
        cases.push(trace(
            "deployed node initiates, first msg2 lost",
            rel,
            |t| {
                t.setup.new_jitter = LATE;
                t.setup.old_jitter = -15;
                t.rules = alloc::vec![Rule::first(0, Class::Msg2, 100_000, 1)];
                t.expect = Expect::lossless().must(
                    0,
                    "Installed { tag: EpochTag(1), role: Responder, evidence: Frame }",
                );
            },
        ));
        // Every msg2 lost: the deployed initiator abandons, the new node
        // holds its pending for the hold and never cuts over on a timer;
        // nothing is lost, and the next rekey completes.
        cases.push(trace(
            "every msg2 lost against a deployed initiator",
            rel,
            |t| {
                t.setup.new_jitter = LATE;
                t.setup.old_jitter = -15;
                t.rules = alloc::vec![Rule::drop(0, Class::Msg2, 100_000, 140_000)];
                t.run = 400_000;
                t.expect = Expect::lossless()
                    .must(1, "abandoned attempt")
                    .must(0, "Retired { tag: EpochTag(1) }");
            },
        ));
        // Dual initiation: both start in the same tick; the smaller keeps its attempt,
        // the larger abandons its own and answers, in both orders.
        for new_smaller in [true, false] {
            cases.push(trace("dual initiation", rel, |t| {
                t.setup.new_first = false;
                t.setup.old_jitter = -15;
                t.setup.new_smaller = new_smaller;
                t.expect = if new_smaller {
                    Expect::lossless()
                        .must(1, "Reject(DualInitWon)")
                        .must(0, "abandoned attempt")
                } else {
                    Expect::lossless()
                        .must(1, "Abandoned(Yielded)")
                        .must(0, "refused DualRekeyWon")
                };
            }));
        }
        // The deployed node restarted; the new node's rekey reveals it
        // and cuts over at K 0 with the restart reported, losing only the
        // frames sent between the restart and the cutover.
        cases.push(trace("restart revealed by the rekey", rel, |t| {
            t.restart = Some(100_000);
            t.expect = Expect::lossless()
                .outage(0, 6_000)
                .must(0, "PeerRestarted")
                .must(1, "promoted a fresh link");
        }));
    }
    // The K rule: the two ends' parities are out of step (the new end at
    // 1, the deployed end at 0); a v0.5.2 peer trials its pending only on a
    // K that differs from its own, so the new epoch must take the inverse
    // of the K the peer was last seen sending.
    cases.push(trace(
        "K parity mismatch with a K-flip-only peer",
        Rel::V052,
        |t| {
            t.setup.new_k = true;
            t.expect = Expect::lossless().must(1, "switched k=true");
        },
    ));
    all(cases.into_iter().map(|t| run(t, 7)).collect());
}

/// Seeded lossy runs of a new node against every release, in both roles of
/// link setup and with each one's trigger first, and between two new nodes
/// (the production profile against itself, crossing included): whatever the loss did,
/// nothing panics, the new node's index map stays equal to its bindings and
/// its pool, and once the loss stops the link converges, or, against a
/// release whose own defects split a link (the 0.5.0 and 0.5.1 responder's
/// self-cutover on a lost msg2), ends removed at one end.
#[test]
fn lossy_link_runs_converge_against_every_deployed_release() {
    let mut results = Vec::new();
    for rel in Rel::ALL {
        for seed in 0..10u64 {
            let s = Setup {
                rel,
                new_first: seed % 2 == 0,
                new_jitter: if seed % 3 == 0 { EARLY } else { LATE },
                old_jitter: if seed % 3 == 0 { 15 } else { -15 },
                new_smaller: seed % 4 < 2,
                new_k: false,
            };
            let (duo, _) = link(&s, 100 + seed);
            let mut duo = duo.seeded(200 + seed, 150);
            duo.run_until(600_000);
            let name = format!("lossy link run {seed} against {rel:?}");
            let expect = if rel == Rel::V050 {
                Expect::lossless()
                    .outage(0, 600_000)
                    .outage(1, 600_000)
                    .maybe_split()
            } else {
                Expect::lossless().outage(0, 600_000).outage(1, 600_000)
            };
            results.push(expect.check(&name, &mut duo, 300_000));
        }
    }
    for seed in 0..6u64 {
        let jitter = [[EARLY, LATE], [LATE, EARLY], [MID, MID]][(seed % 3) as usize];
        let mut duo = new_link(500 + seed, jitter).seeded(600 + seed, 150);
        duo.run_until(600_000);
        let name = format!("lossy link run {seed} between new nodes");
        let expect = Expect::lossless().outage(0, 600_000).outage(1, 600_000);
        results.push(expect.check(&name, &mut duo, 300_000));
    }
    all(results);
}
