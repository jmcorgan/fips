//! Node identities on stub keys, handshake names and their IK
//! ephemerals, and what an abstract far end's messages are on the wire.
//!
//! The world names a handshake by a number ([`Hs`]); a joint node runs
//! the stub IK profile, whose ephemerals are drawn from a counter in the
//! node's [`Local`]. Naming the counter before each call that may write an
//! ephemeral makes every ephemeral a function of a world name: a msg1's of
//! its handshake ([`opener`]), a msg2's of the handshake it answers
//! ([`answerer`]). So the order a node answers two msg1s in does not
//! change any later key, and a resend is the same bytes.
//!
//! The model and the models of deployed nodes send no bytes. What such an
//! end's message is on the wire is written here from the name alone, as
//! that node's `Local` would write it: a msg1 by `Ik::initiate`, a msg2 by
//! `Msg1Read::answer`, a frame by `seal_as`. This is stub crypto, with no
//! decision in it.
//!
//! The machine orders peers by their keys' node addresses and the core by
//! `NodeAddr`; the world orders its identities by number. Each world
//! identity's stub key is chosen so the three orders agree.

use alloc::vec::Vec;
use std::sync::OnceLock;

use crate::identity::NodeAddr;
use crate::proto::rekey::tests::stub::{Ik, Kid, Local, kid, read_msg1, seal_as};
use crate::proto::rekey::{Msg1Read, PeerKey, Profile, Role, Wire};

use super::super::super::model::history::{Epoch, Hs, Node};
use super::super::drive::epoch as wire;
use super::super::explore::THIRD;
use super::super::starts::{A, B, C};

/// The seed of each world identity's stub key, so that their node
/// addresses order as the identities do: `A < B < C < THIRD`.
const SEEDS: [(Node, u8); 4] = [(A, 2), (B, 4), (C, 9), (THIRD, 17)];

/// The seed of identity `n`'s stub key.
fn seed(n: Node) -> u8 {
    SEEDS
        .iter()
        .find(|(m, _)| *m == n)
        .map(|(_, s)| *s)
        .unwrap_or_else(|| panic!("{n:?} is a world identity with a stub key"))
}

/// Identity `n` in its life of epoch `epoch`: its stub key, and the
/// epoch's wire bytes as the world's drivers write them.
pub fn local(n: Node, epoch: Epoch) -> Local {
    let mut l = Local::new(seed(n), 0);
    l.epoch = wire(epoch);
    l
}

/// Each world identity with its static key and node address, made once:
/// both are hashes, and a shell asks for them at nearly every call.
fn identities() -> &'static [(Node, PeerKey, NodeAddr); 4] {
    static IDS: OnceLock<[(Node, PeerKey, NodeAddr); 4]> = OnceLock::new();
    IDS.get_or_init(|| {
        SEEDS.map(|(n, _)| {
            let k = Local::new(seed(n), 0).key;
            (n, k, k.addr())
        })
    })
}

/// Identity `n`'s entry in [`identities`].
fn identity(n: Node) -> &'static (Node, PeerKey, NodeAddr) {
    identities()
        .iter()
        .find(|(m, ..)| *m == n)
        .unwrap_or_else(|| panic!("{n:?} is a world identity with a stub key"))
}

/// Identity `n`'s static key.
pub fn key(n: Node) -> PeerKey {
    identity(n).1
}

/// Identity `n`'s node address.
pub fn addr(n: Node) -> NodeAddr {
    identity(n).2
}

/// The world identity whose key is `k`, if any.
pub fn node(k: &PeerKey) -> Option<Node> {
    identities()
        .iter()
        .find(|(_, m, _)| m == k)
        .map(|(n, ..)| *n)
}

/// The spacing of names. A named counter draws its ephemeral from the
/// name plus one and an unnamed draw takes the next, so names one apart,
/// as the world's consecutive handshakes would be, would make a draw that
/// was never named equal a named one. Spaced, a missed name always draws
/// an ephemeral no name gives.
const SPACING: u64 = 1 << 8;

/// The name the ephemeral of handshake `hs`'s msg1 is drawn from.
pub fn opener(hs: Hs) -> u64 {
    u64::from(hs.0) * SPACING
}

/// The name the ephemeral of the msg2 answering handshake `hs` is drawn
/// from: never a msg1's name.
pub fn answerer(hs: Hs) -> u64 {
    (1 << 40) | (u64::from(hs.0) * SPACING)
}

/// The session index an abstract end puts in its messages of handshake
/// `hs`. Each end's indices are its own, and an abstract end demultiplexes
/// nothing, so the name serves.
pub fn index(hs: Hs) -> u32 {
    hs.0
}

/// The msg1 of handshake `hs` that node `from`, in epoch `epoch`, writes
/// to node `to`, carrying its index `ours`.
pub fn msg1(from: Node, epoch: Epoch, to: Node, hs: Hs, ours: u32) -> Wire {
    let me = local(from, epoch);
    me.name(opener(hs));
    Ik::initiate(&me, &key(to), Some(ours))
        .expect("the stub IK msg1 always writes")
        .1
}

/// The msg2 that node `from`, in epoch `epoch`, writes in answer to
/// `msg1`, the msg1 of handshake `hs`, carrying its index `ours`, and the
/// identity of the session it makes; `None` when `msg1` is not a msg1 to
/// `from`.
pub fn msg2(from: Node, epoch: Epoch, hs: Hs, msg1: &[u8], ours: u32) -> Option<(Wire, Kid)> {
    let me = local(from, epoch);
    let tok = read_msg1(&me, msg1)?;
    me.name(answerer(hs));
    let (done, m) = tok.get().answer(&me, Some(ours)).ok()?;
    Some((m, kid(&done.session)))
}

/// The identity of the session node `from`, in epoch `epoch`, makes when it
/// reads `msg2` as the answer to its msg1 of handshake `hs` to node `to`,
/// carrying `ours`; `None` when `msg2` is not that answer.
pub fn opened(from: Node, epoch: Epoch, to: Node, hs: Hs, ours: u32, msg2: &[u8]) -> Option<Kid> {
    let me = local(from, epoch);
    me.name(opener(hs));
    let (state, _) = Ik::initiate(&me, &key(to), Some(ours)).ok()?;
    let read = Ik::reply(&state, &me, msg2).ok()?;
    Some(kid(&read.done.session))
}

/// A frame of the exchange `msg1`, `msg2`, sealed by the end that took
/// `role` in it, toward the receiver's index `index`, at `counter`, with
/// key-epoch bit `k`.
pub fn frame(
    role: Role,
    exchange: (&[u8], &[u8]),
    index: u32,
    counter: u64,
    k: bool,
    plaintext: &[u8],
) -> Wire {
    seal_as(role, exchange.0, exchange.1, index, counter, k, plaintext)
}

/// The world's handshake names and the stub sessions they made, one to
/// one, so that what a machine holds can be read as world names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Names {
    pairs: Vec<(Hs, Kid)>,
}

impl Names {
    /// Record that handshake `hs` made the session `id`. A name makes one
    /// session and a session has one name.
    pub fn note(&mut self, hs: Hs, id: Kid) {
        if let Some(&(_, was)) = self.pairs.iter().find(|(h, _)| *h == hs) {
            assert_eq!(was, id, "{hs:?} names one session");
            return;
        }
        assert!(
            self.name(id).is_none(),
            "the session of {hs:?} already has the name {:?}",
            self.name(id)
        );
        self.pairs.push((hs, id));
    }

    /// The session handshake `hs` made, if it is known.
    pub fn kid(&self, hs: Hs) -> Option<Kid> {
        self.pairs.iter().find(|(h, _)| *h == hs).map(|(_, k)| *k)
    }

    /// The handshake that made session `id`, if it is known.
    pub fn name(&self, id: Kid) -> Option<Hs> {
        self.pairs.iter().find(|(_, k)| *k == id).map(|(h, _)| *h)
    }
}

use crate::proto::rekey::SessionKeys;
use crate::proto::rekey::tests::stub::hint;

/// Whether the session `done` opens `frame`.
fn opens(done: &crate::proto::rekey::Completed<Ik>, frame: &[u8]) -> bool {
    let mut out = Vec::new();
    done.session.open(&hint(frame), frame, &mut out)
}

/// Node `from`'s completion as the responder of `msg1`, handshake `hs`.
fn answered(from: Node, epoch: Epoch, hs: Hs, msg1: &[u8]) -> crate::proto::rekey::Completed<Ik> {
    let me = local(from, epoch);
    let tok = read_msg1(&me, msg1).expect("the msg1 reads");
    me.name(answerer(hs));
    tok.get().answer(&me, Some(index(hs))).expect("answers").0
}

/// Node `from`'s completion as the initiator of handshake `hs` to `to`,
/// reading `msg2`.
fn initiated(
    from: Node,
    epoch: Epoch,
    to: Node,
    hs: Hs,
    msg2: &[u8],
) -> Option<crate::proto::rekey::Completed<Ik>> {
    let me = local(from, epoch);
    me.name(opener(hs));
    let (state, _) = Ik::initiate(&me, &key(to), Some(index(hs))).ok()?;
    Ik::reply(&state, &me, msg2).ok().map(|r| r.done)
}

const E: Epoch = Epoch(0x0101);
const H: Hs = Hs(0x0101_0001);
const OTHER: Hs = Hs(0x0101_0002);
const DATA: &[u8] = &[0x10, 1, 2, 3, 4, 5, 6, 7];

#[test]
fn the_stub_keys_keep_the_worlds_address_order_in_both_flips() {
    let ids = [A, B, C, THIRD];
    for x in ids {
        for y in ids {
            if x == y {
                continue;
            }
            assert_eq!(
                x < y,
                addr(x) < addr(y),
                "{x:?} before {y:?} in the world's order exactly when its key's address is the smaller, in either order of the pair"
            );
        }
        assert_eq!(node(&key(x)), Some(x), "{x:?}'s key names it back");
        assert_eq!(
            local(x, E).addr(),
            addr(x),
            "{x:?}'s address is its key's in every life"
        );
        assert_eq!(local(x, E).epoch, wire(E), "{x:?}'s epoch is the world's");
    }
}

#[test]
fn an_abstract_msg1_reads_as_the_ik_msg1_of_its_handshake() {
    let m = msg1(A, E, B, H, index(H));
    let joint = local(A, E);
    joint.name(99);
    Ik::initiate(&joint, &key(B), Some(5)).expect("writes");
    joint.name(opener(H));
    let written = Ik::initiate(&joint, &key(B), Some(index(H)))
        .expect("writes")
        .1;
    assert_eq!(
        m, written,
        "an abstract end's msg1 is the bytes a joint end writes for that handshake, whatever it drew before"
    );
    let tok = read_msg1(&local(B, E), &m).expect("the receiver reads it");
    assert_eq!(tok.get().remote(), key(A), "it is from its sender's key");
    assert_eq!(
        tok.get().epoch(),
        wire(E),
        "it carries its sender's world epoch"
    );
    assert!(
        read_msg1(&local(C, E), &m).is_none(),
        "it is to its receiver alone"
    );
    let other = msg1(A, E, B, OTHER, index(H));
    assert_ne!(
        read_msg1(&local(B, E), &other)
            .expect("reads")
            .get()
            .ephemeral(),
        tok.get().ephemeral(),
        "another handshake's msg1 carries another ephemeral"
    );
    let done = answered(B, E, H, &m);
    let (reply, _) = msg2(B, E, H, &m, index(H)).expect("answers");
    let sealed = frame(Role::Initiator, (&m, &reply), index(H), 0, false, DATA);
    assert!(
        opens(&done, &sealed),
        "the session it makes opens its sender's frames of that handshake"
    );
}

#[test]
fn an_abstract_msg2_reads_as_the_ik_msg2_of_its_handshake() {
    let m = msg1(A, E, B, H, index(H));
    let (reply, id) = msg2(B, E, H, &m, index(H)).expect("answers");
    let joint = local(B, E);
    joint.name(99);
    let tok = read_msg1(&joint, &m).expect("reads");
    tok.get().answer(&joint, Some(5)).expect("answers");
    joint.name(answerer(H));
    let (_, written) = tok.get().answer(&joint, Some(index(H))).expect("answers");
    assert_eq!(
        reply, written,
        "an abstract end's msg2 is the bytes a joint end writes for that handshake, whatever it drew before"
    );
    let done = initiated(A, E, B, H, &reply).expect("the initiator reads it");
    assert_eq!(done.remote, key(B), "it is from its sender's key");
    assert_eq!(done.epoch, wire(E), "it carries its sender's world epoch");
    assert_eq!(
        opened(A, E, B, H, index(H), &reply),
        Some(id),
        "both ends hold one session"
    );
    assert!(
        initiated(A, E, B, OTHER, &reply).is_none(),
        "it answers its own handshake and no other"
    );
    let mut names = Names::default();
    names.note(H, id);
    assert_eq!(names.name(id), Some(H), "the session reads as its name");
    assert_eq!(names.kid(H), Some(id), "the name reads as its session");
    let sealed = frame(Role::Responder, (&m, &reply), index(H), 0, false, DATA);
    assert!(
        opens(&done, &sealed),
        "the session it makes opens its sender's frames of that handshake"
    );
}

#[test]
fn an_abstract_frame_opens_only_under_its_handshake() {
    let m = msg1(A, E, B, H, index(H));
    let (reply, _) = msg2(B, E, H, &m, index(H)).expect("answers");
    let at_b = answered(B, E, H, &m);
    let at_a = initiated(A, E, B, H, &reply).expect("reads");
    let n = msg1(A, E, B, OTHER, index(OTHER));
    let (other, _) = msg2(B, E, OTHER, &n, index(OTHER)).expect("answers");
    let elsewhere = answered(B, E, OTHER, &n);
    let from_a = frame(Role::Initiator, (&m, &reply), index(H), 3, false, DATA);
    let from_b = frame(Role::Responder, (&m, &reply), index(H), 3, false, DATA);
    assert_eq!(hint(&from_a).counter, 3, "the frame carries its counter");
    assert!(
        opens(&at_b, &from_a),
        "the initiator's frame opens at the responder"
    );
    assert!(
        opens(&at_a, &from_b),
        "the responder's frame opens at the initiator"
    );
    assert!(
        !opens(&at_a, &from_a),
        "a frame does not open in its own sender's direction"
    );
    assert!(
        !opens(&elsewhere, &from_a),
        "a frame does not open under another handshake's session"
    );
    let stray = frame(Role::Initiator, (&n, &other), index(H), 3, false, DATA);
    assert!(
        !opens(&at_b, &stray),
        "another handshake's frame does not open under this one"
    );
}

#[test]
fn the_stub_profile_selects_the_rows_the_link_profile_does() {
    use crate::proto::fmp::rekey::FmpProfile;
    type Link = FmpProfile<crate::testutil::SeededEntropy>;
    assert_eq!(Ik::LAYER, Link::LAYER, "LAYER");
    assert_eq!(Ik::MESSAGES, Link::MESSAGES, "MESSAGES");
    assert_eq!(Ik::COMMIT, Link::COMMIT, "COMMIT");
    assert_eq!(
        Ik::INITIATOR_CUTOVER,
        Link::INITIATOR_CUTOVER,
        "INITIATOR_CUTOVER"
    );
    assert_eq!(
        Ik::RESPONDER_CUTOVER,
        Link::RESPONDER_CUTOVER,
        "RESPONDER_CUTOVER"
    );
    assert_eq!(Ik::CANDIDATES, Link::CANDIDATES, "CANDIDATES");
    assert_eq!(Ik::PER_CARRIER, Link::PER_CARRIER, "PER_CARRIER");
    assert_eq!(Ik::DAMPEN_AT, Link::DAMPEN_AT, "DAMPEN_AT");
    assert_eq!(Ik::SELECT, Link::SELECT, "SELECT");
    assert_eq!(Ik::SILENCE, Link::SILENCE, "SILENCE");
    assert_eq!(Ik::SETUP_RTT, Link::SETUP_RTT, "SETUP_RTT");
    assert_eq!(Ik::INDEXED, Link::INDEXED, "INDEXED");
    assert_eq!(Ik::FLOOR, Link::FLOOR, "FLOOR");
}
