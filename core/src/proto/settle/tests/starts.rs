//! The named starts the explorer runs from, each with the scripted
//! schedule that reaches its target state and the depth it is explored to.
//!
//! Every start begins mid-history: a fresh start explored to the depth a
//! crossing with a restart needs is out of reach. A start's depth is its
//! script's length plus two events (one fault, one restart or advance).
//! Its state cap is the number of states that depth was measured to reach
//! with headroom; one depth more reaches more than three times as many
//! states, past the cap, so a start that grew is seen.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::super::model::history::{Addr, Node};
use super::explore::{Act, Budget, SMALL};
use super::party::{Configured, ModelParty};
use super::world::{Input, Kind, Net, Party, PathEv, Pkt, State, World};

/// The smaller and the larger node of a pair, and a third node.
pub const A: Node = Node(1);
/// See [`A`].
pub const B: Node = Node(2);
/// See [`A`].
pub const C: Node = Node(3);

/// The transports: one of each model.
pub const UDP: u8 = 0;
/// See [`UDP`].
pub const TCP: u8 = 1;
/// See [`UDP`].
pub const BLE: u8 = 2;

/// Address `n` on transport `t`.
pub fn at(t: u8, n: u16) -> Addr {
    Addr {
        transport: t,
        at: n,
    }
}

/// Node index `i`'s home address on transport `t`: `10 (i + 1)`; its
/// second address is one more.
pub fn home(i: usize, t: u8) -> Addr {
    at(t, 10 * (i as u16 + 1))
}

/// Node index `i`'s second address on transport `t`.
pub fn second(i: usize, t: u8) -> Addr {
    at(t, 10 * (i as u16 + 1) + 1)
}

/// Builds one node of a world: its index, identity and configured peers.
pub type Maker = fn(usize, Node, Vec<Configured>) -> Box<dyn Party>;

/// The reference model as a node.
pub fn model(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    Box::new(ModelParty::new(ix, me, configured))
}

/// Builds a start's world from its nodes' maker.
pub type Build = fn(Maker) -> World;

/// One named start.
pub struct Start {
    /// The start's number in the plan's list.
    pub number: u8,
    /// Its name.
    pub name: &'static str,
    /// Its world.
    pub build: Build,
    /// What its nodes are.
    pub maker: Maker,
    /// The scripted schedule from the start to its target state.
    pub script: fn(&mut World) -> Vec<Act>,
    /// The depth it is explored to.
    pub depth: usize,
    /// The most states that depth may reach.
    pub cap: usize,
    /// The event budgets.
    pub budget: Budget,
    /// Whether the wall clock may step.
    pub wall: bool,
    /// Whether third-party msg1s and forged msg2s are injected.
    pub forged: bool,
}

/// Which packet a script step delivers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Want {
    /// A msg1.
    Msg1,
    /// A msg2.
    Msg2,
}

/// One step of a script.
#[derive(Clone, Copy, Debug)]
pub enum Do {
    /// Deliver the first deliverable packet of this kind to node `x`, sent
    /// by node index `from` if given.
    Get(usize, Want, Option<usize>),
    /// Resolve node `x`'s first connecting connection, open.
    Open(usize),
    /// An event as it is.
    Then(Act),
}

/// Run `steps` on `w` and return them as the explorer's events.
pub fn run(w: &mut World, steps: &[Do]) -> Vec<Act> {
    let mut out = Vec::new();
    for s in steps {
        let a = match *s {
            Do::Get(x, want, from) => {
                let id = w
                    .net
                    .flight
                    .iter()
                    .find(|f| {
                        f.to == x
                            && w.net.deliverable(f)
                            && match (want, f.pkt) {
                                (Want::Msg1, Pkt::Msg1 { id, .. })
                                | (Want::Msg2, Pkt::Msg2 { id, .. }) => {
                                    from.is_none_or(|y| w.ids[y] == id)
                                }
                                _ => false,
                            }
                    })
                    .map(|f| f.id)
                    .unwrap_or_else(|| panic!("the script finds {want:?} for n{x}"));
                Act::Deliver(id)
            }
            Do::Open(x) => {
                let c = w
                    .net
                    .conns
                    .iter()
                    .find(|c| c.state == State::Connecting && c.ends[0].node == x)
                    .map(|c| c.id)
                    .unwrap_or_else(|| panic!("the script finds a connect window of n{x}"));
                Act::Connect(c, true)
            }
            Do::Then(a) => a,
        };
        super::explore::apply(w, a);
        out.push(a);
    }
    out
}

/// A world of model nodes `ids` on every transport, node `i` redialing
/// `dials[i]` (peer index, transport) whenever it holds none.
pub fn world(ids: &[Node], dials: &[&[(usize, u8)]]) -> World {
    world_of(model, ids, dials)
}

/// As [`world`], with nodes made by `mk`.
pub fn world_of(mk: Maker, ids: &[Node], dials: &[&[(usize, u8)]]) -> World {
    let kinds = [(UDP, Kind::Datagram), (TCP, Kind::Stream), (BLE, Kind::Ble)];
    let addrs = (0..ids.len())
        .map(|i| {
            kinds
                .iter()
                .flat_map(|&(t, _)| [home(i, t), second(i, t)])
                .collect()
        })
        .collect();
    let net = Net::new(&kinds, addrs);
    let parties = (0..ids.len())
        .map(|i| {
            let configured = dials
                .get(i)
                .copied()
                .unwrap_or(&[])
                .iter()
                .map(|&(y, t)| Configured {
                    peer: ids[y],
                    to: home(y, t),
                    from: None,
                })
                .collect();
            mk(i, ids[i], configured)
        })
        .collect();
    World::new(parties, ids.to_vec(), net)
}

/// Node `x` dials node `y` at `to` from `from`.
pub fn dial(w: &mut World, x: usize, y: usize, to: Addr, from: Option<Addr>) {
    let peer = w.ids[y];
    w.input(x, Input::Dial { peer, to, from });
}

/// Node `x` dials node `y` at its home on transport `t`.
pub fn dial_home(w: &mut World, x: usize, y: usize, t: u8) {
    dial(w, x, y, home(y, t), None);
}

/// Deliver everything and open every connect window until nothing moves.
pub fn settle(w: &mut World) {
    for _ in 0..64 {
        let connecting: Vec<u32> = w
            .net
            .conns
            .iter()
            .filter(|c| c.state == State::Connecting)
            .map(|c| c.id)
            .collect();
        for c in &connecting {
            w.connected(*c, true);
        }
        if w.net.flight.is_empty() && connecting.is_empty() {
            return;
        }
        w.drain(256);
    }
}

/// Let `ms` pass in steps of one second, delivering everything after each.
pub fn age(w: &mut World, ms: u64) {
    let end = w.net.now + ms;
    while w.net.now < end {
        let t = (w.net.now + 1_000).min(end);
        w.run_until(t);
        settle(w);
    }
}

/// Nodes 0 and 1, node 0 the identity `first`.
fn pair(mk: Maker, first: Node, dials: &[&[(usize, u8)]]) -> World {
    let other = if first == A { B } else { A };
    world_of(mk, &[first, other], dials)
}

// The starts. Node 0 is the smaller node unless a name says otherwise.

fn crossing(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, UDP)], &[(0, UDP)]]);
    dial_home(&mut w, 0, 1, UDP);
    dial_home(&mut w, 1, 0, UDP);
    w
}

fn crossing_script(w: &mut World) -> Vec<Act> {
    run(
        w,
        &[
            Do::Get(1, Want::Msg1, None),
            Do::Get(0, Want::Msg1, None),
            Do::Get(0, Want::Msg2, None),
            Do::Get(1, Want::Msg2, None),
        ],
    )
}

fn crossing_mixed(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, UDP)], &[(0, TCP)]]);
    dial_home(&mut w, 0, 1, UDP);
    dial_home(&mut w, 1, 0, TCP);
    w
}

fn crossing_mixed_script(w: &mut World) -> Vec<Act> {
    run(
        w,
        &[
            Do::Open(1),
            Do::Get(0, Want::Msg1, None),
            Do::Get(1, Want::Msg1, None),
            Do::Get(1, Want::Msg2, None),
            Do::Get(0, Want::Msg2, None),
        ],
    )
}

fn crossing_stream(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, TCP)], &[(0, TCP)]]);
    dial_home(&mut w, 0, 1, TCP);
    dial_home(&mut w, 1, 0, TCP);
    let c = w.net.conns[0].id;
    w.connected(c, true);
    w
}

fn crossing_stream_script(w: &mut World) -> Vec<Act> {
    run(
        w,
        &[
            Do::Get(1, Want::Msg1, None),
            Do::Open(1),
            Do::Get(0, Want::Msg1, None),
            Do::Get(0, Want::Msg2, None),
            Do::Get(1, Want::Msg2, None),
        ],
    )
}

fn crossing_ble(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, BLE)], &[(0, BLE)]]);
    dial_home(&mut w, 0, 1, BLE);
    dial_home(&mut w, 1, 0, BLE);
    let c = w.net.conns[0].id;
    w.connected(c, true);
    w
}

/// Node 0 dials node 1, which answers, and node 0 reads the msg2; then node
/// 0 dials again, one second later, by which time what was in flight is
/// lost.
fn late_order<const LARGER: bool>(mk: Maker) -> World {
    let mut w = pair(mk, if LARGER { B } else { A }, &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    run(
        &mut w,
        &[Do::Get(1, Want::Msg1, None), Do::Get(0, Want::Msg2, None)],
    );
    w.run_until(1_000);
    dial_home(&mut w, 0, 1, UDP);
    w
}

fn late_order_script(w: &mut World) -> Vec<Act> {
    run(
        w,
        &[Do::Get(1, Want::Msg1, None), Do::Get(0, Want::Msg2, None)],
    )
}

/// Node 0 dials node 1 twice, and node 1 has read the first msg1; one
/// resend interval later, what was in flight is lost and both msg1s are
/// resent.
fn late_reordered<const LARGER: bool>(mk: Maker) -> World {
    let mut w = pair(mk, if LARGER { B } else { A }, &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    dial_home(&mut w, 0, 1, UDP);
    run(
        &mut w,
        &[Do::Get(1, Want::Msg1, None), Do::Then(Act::Advance)],
    );
    w
}

/// The packet in flight to node `to` of handshake `n` of its sender's
/// life, a msg1 or a msg2.
fn nth(w: &World, to: usize, want: Want, n: u32) -> Act {
    w.net
        .flight
        .iter()
        .find(|f| {
            f.to == to
                && match (want, f.pkt) {
                    (Want::Msg1, Pkt::Msg1 { hs, .. }) | (Want::Msg2, Pkt::Msg2 { hs, .. }) => {
                        hs.0 & 0xffff == n
                    }
                    _ => false,
                }
        })
        .map(|f| Act::Deliver(f.id))
        .unwrap_or_else(|| panic!("the script finds {want:?} {n} for n{to}"))
}

/// Node 1 answers the first dial's resend with its stored msg2, then
/// replaces at the second dial's resend; node 0 reads the second msg2
/// before the first.
fn late_reordered_script(w: &mut World) -> Vec<Act> {
    let mut out = Vec::new();
    for (to, want, n) in [
        (1, Want::Msg1, 1),
        (1, Want::Msg1, 2),
        (0, Want::Msg2, 2),
        (0, Want::Msg2, 1),
    ] {
        let a = nth(w, to, want, n);
        out.extend(run(w, &[Do::Then(a)]));
    }
    out
}

/// Node 0 (the smaller) dialed node 1 (the larger) long enough ago that the
/// link is old enough to rekey; node 1 dials again from its usual source to
/// node 0's second address.
fn aged(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    settle(&mut w);
    age(&mut w, 40_000);
    dial(&mut w, 1, 0, second(0, UDP), None);
    w
}

fn aged_script(w: &mut World) -> Vec<Act> {
    run(
        w,
        &[
            Do::Get(0, Want::Msg1, Some(1)),
            Do::Get(1, Want::Msg2, Some(0)),
            Do::Then(Act::Rekey(1, 0)),
            Do::Get(0, Want::Msg1, Some(1)),
        ],
    )
}

/// Node 0 dials node 1; either may restart at any point.
fn restart(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    w
}

fn restart_script(w: &mut World) -> Vec<Act> {
    run(
        w,
        &[
            Do::Get(1, Want::Msg1, None),
            Do::Get(0, Want::Msg2, None),
            Do::Then(Act::Restart(0)),
        ],
    )
}

/// An aged pair; node 0 has started its own rekey and both nodes dial each
/// other's second address from their own; with `DRAIN`, node 0's rekey has
/// completed and it has cut over first.
fn rekeying<const DRAIN: bool>(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    settle(&mut w);
    age(&mut w, 40_000);
    w.input(0, Input::Rekey { peer: B });
    if DRAIN {
        settle(&mut w);
        w.run_until(w.net.now + 1_000);
    }
    dial(&mut w, 0, 1, second(1, UDP), Some(second(0, UDP)));
    dial(&mut w, 1, 0, second(0, UDP), Some(second(1, UDP)));
    w
}

fn rekeying_script(w: &mut World) -> Vec<Act> {
    run(
        w,
        &[
            Do::Get(1, Want::Msg1, Some(0)),
            Do::Get(1, Want::Msg1, Some(0)),
            Do::Get(0, Want::Msg1, Some(1)),
            Do::Get(0, Want::Msg2, Some(1)),
        ],
    )
}

fn drain_script(w: &mut World) -> Vec<Act> {
    run(
        w,
        &[
            Do::Get(1, Want::Msg1, Some(0)),
            Do::Get(0, Want::Msg1, Some(1)),
        ],
    )
}

/// Node 0 dials node 1, whose first send of the msg2 fails.
fn stored(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    w.net.failing.push(1);
    w
}

fn stored_script(w: &mut World) -> Vec<Act> {
    run(
        w,
        &[
            Do::Get(1, Want::Msg1, None),
            Do::Then(Act::Advance),
            Do::Get(1, Want::Msg1, None),
            Do::Get(0, Want::Msg2, None),
        ],
    )
}

/// Nodes 0 and 1 cross; node 2 dials node 0.
fn three(mk: Maker) -> World {
    let mut w = world_of(mk, &[A, B, C], &[&[(1, UDP)], &[(0, UDP)], &[(0, UDP)]]);
    dial_home(&mut w, 0, 1, UDP);
    dial_home(&mut w, 1, 0, UDP);
    dial_home(&mut w, 2, 0, UDP);
    w
}

fn three_script(w: &mut World) -> Vec<Act> {
    run(
        w,
        &[
            Do::Get(1, Want::Msg1, Some(0)),
            Do::Get(0, Want::Msg1, Some(1)),
            Do::Get(0, Want::Msg1, Some(2)),
            Do::Get(0, Want::Msg2, Some(1)),
        ],
    )
}

/// Nodes 0 and 1 cross on BLE, node 1 dialing from its second address,
/// which node 0's dialed link already holds as a second live path; the
/// bundles' other path events are available.
fn paths(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, BLE)], &[(0, BLE)]]);
    dial_home(&mut w, 0, 1, BLE);
    dial(&mut w, 1, 0, home(0, BLE), Some(second(1, BLE)));
    let ids: Vec<u32> = w.net.conns.iter().map(|c| c.id).collect();
    for c in ids {
        w.connected(c, true);
    }
    w.input(
        0,
        Input::Path(PathEv::State {
            peer: B,
            at: second(1, BLE),
            live: true,
        }),
    );
    w.paths = alloc::vec![
        (
            0,
            PathEv::Released {
                peer: B,
                at: second(1, BLE),
                keep: false,
            },
        ),
        (
            1,
            PathEv::Switched {
                peer: A,
                from: home(0, BLE),
                to: second(0, BLE),
            },
        ),
        (
            1,
            PathEv::Moved {
                peer: A,
                from: second(0, BLE),
                to: at(BLE, 12),
            },
        ),
    ];
    w.used = alloc::vec![false; w.paths.len()];
    w
}

fn paths_script(w: &mut World) -> Vec<Act> {
    run(
        w,
        &[
            Do::Get(1, Want::Msg1, None),
            Do::Get(0, Want::Msg1, None),
            Do::Get(0, Want::Msg2, None),
            Do::Get(1, Want::Msg2, None),
        ],
    )
}

/// An established pair whose setup msg1 an attacker captured.
fn replayed(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    settle(&mut w);
    w
}

fn replayed_script(w: &mut World) -> Vec<Act> {
    let mut out = run(w, &[Do::Then(Act::Replay(0))]);
    out.extend(run(w, &[Do::Get(1, Want::Msg1, None)]));
    out
}

/// Node 0's dial in flight, forged msg2s about.
fn sprayed(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    w
}

fn sprayed_script(w: &mut World) -> Vec<Act> {
    let mut out = run(w, &[Do::Then(Act::Garbage(0))]);
    out.extend(run(
        w,
        &[
            Do::Get(0, Want::Msg2, None),
            Do::Get(1, Want::Msg1, None),
            Do::Get(0, Want::Msg2, None),
        ],
    ));
    out
}

/// Node 0 dialed node 1, which has heard it; node 0 dials again.
fn walled(mk: Maker) -> World {
    let mut w = pair(mk, A, &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    settle(&mut w);
    w.run_until(2_000);
    settle(&mut w);
    dial_home(&mut w, 0, 1, UDP);
    w
}

fn walled_script(w: &mut World) -> Vec<Act> {
    run(w, &[Do::Then(Act::Wall), Do::Get(1, Want::Msg1, None)])
}

/// Every named start.
pub fn starts() -> Vec<Start> {
    let s = |number, name, build: Build, script: fn(&mut World) -> Vec<Act>, depth, cap| Start {
        number,
        name,
        build,
        script,
        depth,
        cap,
        maker: model,
        budget: SMALL,
        wall: false,
        forged: false,
    };
    let mut v = alloc::vec![
        s(
            1,
            "crossing, connectionless",
            crossing,
            crossing_script,
            6,
            14_600
        ),
        s(
            2,
            "crossing, two transports",
            crossing_mixed,
            crossing_mixed_script,
            7,
            65_000
        ),
        s(
            3,
            "crossing, connection-oriented",
            crossing_stream,
            crossing_stream_script,
            7,
            111_400
        ),
        s(4, "crossing, BLE", crossing_ble, crossing_script, 6, 27_600),
        s(
            5,
            "late second dial in order, larger dialer",
            late_order::<true>,
            late_order_script,
            4,
            1_000
        ),
        s(
            5,
            "late second dial in order, smaller dialer",
            late_order::<false>,
            late_order_script,
            4,
            1_000
        ),
        s(
            6,
            "late second dial, second msg2 first, larger dialer",
            late_reordered::<true>,
            late_reordered_script,
            6,
            10_100
        ),
        s(
            6,
            "late second dial, second msg2 first, smaller dialer",
            late_reordered::<false>,
            late_reordered_script,
            6,
            10_100
        ),
        s(
            7,
            "dial on the peer's aged link, then own rekey",
            aged,
            aged_script,
            6,
            18_100
        ),
        s(
            8,
            "restart at each point",
            restart,
            restart_script,
            5,
            1_400
        ),
        s(
            9,
            "crossing during a rekey",
            rekeying::<false>,
            rekeying_script,
            6,
            30_400
        ),
        s(
            9,
            "crossing during a rekey's drain",
            rekeying::<true>,
            drain_script,
            4,
            2_400
        ),
        s(
            10,
            "stored msg2 whose send failed, then a resend",
            stored,
            stored_script,
            6,
            1_400
        ),
        s(11, "three nodes", three, three_script, 6, 54_800),
        s(12, "two paths", paths, paths_script, 6, 58_500),
        s(13, "replayed msg1", replayed, replayed_script, 4, 1_400),
        s(
            13,
            "forged msg2 spray against a pending dial",
            sprayed,
            sprayed_script,
            6,
            28_000
        ),
        s(
            14,
            "wall step inside the heard floor",
            walled,
            walled_script,
            4,
            900
        ),
    ];
    for st in &mut v {
        if st.number == 13 {
            st.forged = true;
        }
        if st.number == 14 {
            st.wall = true;
        }
    }
    v
}
