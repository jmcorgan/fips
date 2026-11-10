//! The schedules a real node and the joint world both run, as data, and
//! what each end holds after each step of them, as one committed trace.
//!
//! A root test cannot build the joint world, which is compiled for this
//! crate's tests alone, so the two do not meet in one run. Each runs the
//! scripts of [`SCRIPTS`] and compares what its ends hold with the trace in
//! `parity.txt`, which says what the node does; a `core` line there states
//! a field the settlement core gives differently at one step, and names the
//! defect of the node it comes from ([`Cause`]). The trace is the third
//! party: a difference in either side's wiring reds that side, and a change
//! to both has to edit the trace, which shows in its diff.
//!
//! A step names its nodes by index and its packets by kind and handshake,
//! never by an index value or an address, since a node sends frames the
//! world does not and draws its own indices. What an end holds is a
//! [`Mark`], whose fields each side reads from its own state.
//!
//! It also states the link rekey and path settings a node derives at the
//! default configuration, at each multipath setting ([`rekey`], [`path`]),
//! which a root test ties to the node's own derivation: the joint world's
//! nodes run with these, so the schedules compare nodes that run alike.
//!
//! Compiled for tests and the `test-hooks` feature, so the root crate's
//! tests read it too.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use crate::proto::path as paths;
use crate::proto::rekey as rekeys;
use crate::time::Duration;

/// The path machine's settings a node derives at the default configuration
/// with multipath `on`: the draft's values, enabled by the setting, with
/// the 10 s heartbeat.
pub fn path(on: bool) -> paths::Params {
    paths::Params::new(paths::Config {
        enabled: on,
        heartbeat: Duration::from_secs(10),
        ..paths::Config::draft()
    })
    .expect("the draft's values with a 10 s heartbeat are valid")
}

/// The link rekey settings a node derives at the default configuration
/// with multipath `on`: the FMP defaults with the 1 s check, five resends
/// and the 30 s handshake timeout; the pending hold the link's longest
/// silence needs, which is the msg1 resend ladder of five resends, three
/// 1 s ticks and the longer of the 10 s heartbeat and the 30 s link-dead
/// timeout; and the answer on a msg1's arrival path when multipath is on.
/// At the defaults the time trigger (120 s, above the 15 s jitter plus the
/// 30 s link age), the message trigger and both start floors (31 s) are
/// the FMP defaults'.
pub fn rekey(on: bool) -> rekeys::Params {
    let silence = rekeys::msg1_span(5)
        .saturating_add(Duration::from_secs(3))
        .saturating_add(Duration::from_secs(30));
    let base = rekeys::Config {
        arrival: on,
        check: Duration::from_secs(1),
        resends: 5,
        handshake: Duration::from_secs(30),
        ..rekeys::Config::fmp()
    };
    rekeys::Params::new(base.with_hold(silence)).expect("the link defaults are valid")
}

/// The trace both sides compare with, one block per script.
pub const TRACE: &str = include_str!("parity.txt");

/// A transport, by its model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Connectionless: UDP, or a node's loopback transport in its place.
    Udp,
    /// Connection-oriented, a connection per dial.
    Tcp,
    /// BLE: one connection per address pair.
    Ble,
}

impl Transport {
    /// Every transport, in the order the trace's words list them.
    pub const ALL: [Self; 3] = [Self::Udp, Self::Tcp, Self::Ble];

    /// Its word in the trace.
    pub fn name(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Ble => "ble",
        }
    }
}

/// A node's multipath setting, `node.path.enabled`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setting {
    /// Multipath disabled.
    Off,
    /// Multipath enabled.
    On,
}

impl Setting {
    /// Whether multipath is enabled.
    pub fn enabled(self) -> bool {
        self == Self::On
    }

    /// Its word in the trace.
    pub fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// The setting a word names.
    fn read(word: &str) -> Option<Self> {
        [Self::Off, Self::On].into_iter().find(|s| s.name() == word)
    }
}

/// A handshake message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Packet {
    /// The dialer's msg1.
    Msg1,
    /// The responder's msg2.
    Msg2,
}

/// One step of a script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Node `from` dials node `to` at that node's home address on
    /// `transport`.
    Dial {
        /// The dialer.
        from: usize,
        /// The node dialed.
        to: usize,
        /// The transport.
        transport: Transport,
    },
    /// Node `node`'s first connection still connecting opens.
    Connected {
        /// The node whose connection opens.
        node: usize,
    },
    /// Node `to` reads the `kind` of its pair's handshake `nth`, counted
    /// from 1 in its dialer's life: for a msg1 the sender's handshake, for
    /// a msg2 the reader's own.
    Handshake {
        /// The node that reads it.
        to: usize,
        /// The message.
        kind: Packet,
        /// The handshake, in its dialer's life.
        nth: u32,
    },
    /// Everything in flight is delivered, every connection opens, and the
    /// clocks run for a minute with no fault.
    Heal,
    /// The clocks run this many milliseconds, each timer due on the way
    /// firing; nothing is delivered meanwhile, and what is in flight when
    /// they move is lost.
    Advance(u64),
    /// Node `node` restarts.
    Restart {
        /// The node.
        node: usize,
    },
    /// Node `node` starts its own rekey of its peer.
    Rekey {
        /// The node.
        node: usize,
    },
}

/// One schedule both sides run. A node that dials a peer in it redials
/// that peer at the same address whenever it holds none, as a node redials
/// a peer it is configured with.
#[derive(Clone, Copy, Debug)]
pub struct Script {
    /// Its name, which its block in the trace carries.
    pub name: &'static str,
    /// Each node's setting, by index; its length is the number of nodes.
    pub settings: &'static [Setting],
    /// The node whose address is the smaller: the address order.
    pub smaller: usize,
    /// The transports its nodes hold.
    pub transports: &'static [Transport],
    /// The steps, numbered from 1 in the trace.
    pub steps: &'static [Step],
}

/// Both nodes at Off.
const OFF: &[Setting] = &[Setting::Off, Setting::Off];

/// Both nodes at On.
const ON: &[Setting] = &[Setting::On, Setting::On];

/// Crossed dials on one connectionless transport: node 0's msg1 is read
/// first, then node 1's, then node 0's msg2, then node 1's.
const CROSSING_UDP: &[Step] = &[
    Step::Dial {
        from: 0,
        to: 1,
        transport: Transport::Udp,
    },
    Step::Dial {
        from: 1,
        to: 0,
        transport: Transport::Udp,
    },
    Step::Handshake {
        to: 1,
        kind: Packet::Msg1,
        nth: 1,
    },
    Step::Handshake {
        to: 0,
        kind: Packet::Msg1,
        nth: 1,
    },
    Step::Handshake {
        to: 0,
        kind: Packet::Msg2,
        nth: 1,
    },
    Step::Handshake {
        to: 1,
        kind: Packet::Msg2,
        nth: 1,
    },
    Step::Heal,
];

/// Crossed dials on one connection-oriented transport: node 0's connection
/// opens and its msg1 is read; then node 1's connection opens, its msg1 is
/// read, and the two msg2s in the same order.
const CROSSING_TCP: &[Step] = &[
    Step::Dial {
        from: 0,
        to: 1,
        transport: Transport::Tcp,
    },
    Step::Dial {
        from: 1,
        to: 0,
        transport: Transport::Tcp,
    },
    Step::Connected { node: 0 },
    Step::Handshake {
        to: 1,
        kind: Packet::Msg1,
        nth: 1,
    },
    Step::Connected { node: 1 },
    Step::Handshake {
        to: 0,
        kind: Packet::Msg1,
        nth: 1,
    },
    Step::Handshake {
        to: 0,
        kind: Packet::Msg2,
        nth: 1,
    },
    Step::Handshake {
        to: 1,
        kind: Packet::Msg2,
        nth: 1,
    },
    Step::Heal,
];

/// Node `from` dials node `to`'s home on `transport`.
const fn dial(from: usize, to: usize, transport: Transport) -> Step {
    Step::Dial {
        from,
        to,
        transport,
    }
}

/// Node `to` reads the msg1 of its peer's handshake `nth`.
const fn msg1(to: usize, nth: u32) -> Step {
    Step::Handshake {
        to,
        kind: Packet::Msg1,
        nth,
    }
}

/// Node `to` reads the msg2 answering its own handshake `nth`.
const fn msg2(to: usize, nth: u32) -> Step {
    Step::Handshake {
        to,
        kind: Packet::Msg2,
        nth,
    }
}

/// Crossed dials over two transports, node 0 dialing on UDP and node 1 on
/// TCP: node 1's connection opens, node 0 reads node 1's msg1, node 1
/// reads node 0's, and node 1 reads its msg2 before node 0 does (start 2).
const CROSSING_MIXED: &[Step] = &[
    dial(0, 1, Transport::Udp),
    dial(1, 0, Transport::Tcp),
    Step::Connected { node: 1 },
    msg1(0, 1),
    msg1(1, 1),
    msg2(1, 1),
    msg2(0, 1),
    Step::Heal,
];

/// Crossed dials on BLE, which share the pair's one connection: it opens,
/// and the four messages are read as on a connectionless crossing (start
/// 4).
const CROSSING_BLE: &[Step] = &[
    dial(0, 1, Transport::Ble),
    dial(1, 0, Transport::Ble),
    Step::Connected { node: 0 },
    msg1(1, 1),
    msg1(0, 1),
    msg2(0, 1),
    msg2(1, 1),
    Step::Heal,
];

/// Node 0 dials node 1 and reads the answer; a second later it dials again,
/// and node 1's answer to that is read in order (start 5).
const LATE_ORDER: &[Step] = &[
    dial(0, 1, Transport::Udp),
    msg1(1, 1),
    msg2(0, 1),
    Step::Advance(1_000),
    dial(0, 1, Transport::Udp),
    msg1(1, 2),
    msg2(0, 2),
    Step::Heal,
];

/// Node 0 dials node 1 twice; node 1 reads the first msg1, then, a resend
/// interval later, the first msg1's resend and the second's, and node 0
/// reads the second msg2 before the first (start 6).
const LATE_REORDERED: &[Step] = &[
    dial(0, 1, Transport::Udp),
    dial(0, 1, Transport::Udp),
    msg1(1, 1),
    Step::Advance(1_000),
    msg1(1, 1),
    msg1(1, 2),
    msg2(0, 2),
    msg2(0, 1),
    Step::Heal,
];

/// Node 0 dials node 1, which answers; node 0 restarts after reading the
/// answer, and redials (start 8).
const RESTART: &[Step] = &[
    dial(0, 1, Transport::Udp),
    msg1(1, 1),
    msg2(0, 1),
    Step::Restart { node: 0 },
    Step::Heal,
];

/// Node 0 dials node 1, which answers, and the pair settles; node 0
/// starts its own rekey, which node 1 answers.
const REKEY_OWN: &[Step] = &[
    dial(0, 1, Transport::Udp),
    msg1(1, 1),
    msg2(0, 1),
    Step::Heal,
    Step::Rekey { node: 0 },
    msg1(1, 2),
    msg2(0, 2),
    Step::Heal,
];

/// As [`REKEY_OWN`], with the rekey node 1's, the responder of the dial.
const REKEY_PEER: &[Step] = &[
    dial(0, 1, Transport::Udp),
    msg1(1, 1),
    msg2(0, 1),
    Step::Heal,
    Step::Rekey { node: 1 },
    msg1(0, 1),
    msg2(1, 1),
    Step::Heal,
];

/// [`CROSSING_TCP`], then node 0, which moved when node 0 is the smaller
/// node, starts its own rekey.
const CROSSING_TCP_REKEY: &[Step] = &[
    dial(0, 1, Transport::Tcp),
    dial(1, 0, Transport::Tcp),
    Step::Connected { node: 0 },
    msg1(1, 1),
    Step::Connected { node: 1 },
    msg1(0, 1),
    msg2(0, 1),
    msg2(1, 1),
    Step::Heal,
    Step::Rekey { node: 0 },
    msg1(1, 2),
    msg2(0, 2),
    Step::Heal,
];

/// Node 0 dials node 1 on BLE, and five seconds later again over the same
/// connection; everything either sends is lost until the first dial's
/// handshake deadline has passed, which reaps its leg while the second is
/// still out (start 18).
const BLE_REAPED: &[Step] = &[
    dial(0, 1, Transport::Ble),
    Step::Connected { node: 0 },
    Step::Advance(5_000),
    dial(0, 1, Transport::Ble),
    Step::Advance(25_000),
    Step::Heal,
];

/// Every shared schedule. The two first crossings' names say whose msg1 is
/// read first: node 0's, and node 0 is the smaller node or the larger.
/// Every other name says whether node 0 is the smaller node or the larger,
/// and ends with the setting. The named starts of the settlement tests
/// they run are 1 (`crossing-udp`), 2 and 15 (`crossing-mixed`, the same
/// schedule), 3 (`crossing-tcp`), 4 (`crossing-ble`), 5
/// (`late-dial-in-order`), 6 (`late-dial-reordered`), 8 (`restart`) and
/// 18 (`ble-reaped`); [`UNSHARED`] says why each other start is not here.
pub const SCRIPTS: &[Script] = &[
    Script {
        name: "crossing-udp-smaller-first-off",
        settings: OFF,
        smaller: 0,
        transports: &[Transport::Udp],
        steps: CROSSING_UDP,
    },
    Script {
        name: "crossing-udp-larger-first-off",
        settings: OFF,
        smaller: 1,
        transports: &[Transport::Udp],
        steps: CROSSING_UDP,
    },
    Script {
        name: "crossing-udp-smaller-first-on",
        settings: ON,
        smaller: 0,
        transports: &[Transport::Udp],
        steps: CROSSING_UDP,
    },
    Script {
        name: "crossing-udp-larger-first-on",
        settings: ON,
        smaller: 1,
        transports: &[Transport::Udp],
        steps: CROSSING_UDP,
    },
    Script {
        name: "crossing-tcp-smaller-first-off",
        settings: OFF,
        smaller: 0,
        transports: &[Transport::Tcp],
        steps: CROSSING_TCP,
    },
    Script {
        name: "crossing-tcp-larger-first-off",
        settings: OFF,
        smaller: 1,
        transports: &[Transport::Tcp],
        steps: CROSSING_TCP,
    },
    Script {
        name: "crossing-tcp-smaller-first-on",
        settings: ON,
        smaller: 0,
        transports: &[Transport::Tcp],
        steps: CROSSING_TCP,
    },
    Script {
        name: "crossing-tcp-larger-first-on",
        settings: ON,
        smaller: 1,
        transports: &[Transport::Tcp],
        steps: CROSSING_TCP,
    },
    Script {
        name: "crossing-mixed-smaller-off",
        settings: OFF,
        smaller: 0,
        transports: &[Transport::Udp, Transport::Tcp],
        steps: CROSSING_MIXED,
    },
    Script {
        name: "crossing-mixed-larger-off",
        settings: OFF,
        smaller: 1,
        transports: &[Transport::Udp, Transport::Tcp],
        steps: CROSSING_MIXED,
    },
    Script {
        name: "crossing-mixed-smaller-on",
        settings: ON,
        smaller: 0,
        transports: &[Transport::Udp, Transport::Tcp],
        steps: CROSSING_MIXED,
    },
    Script {
        name: "crossing-mixed-larger-on",
        settings: ON,
        smaller: 1,
        transports: &[Transport::Udp, Transport::Tcp],
        steps: CROSSING_MIXED,
    },
    Script {
        name: "crossing-ble-smaller-off",
        settings: OFF,
        smaller: 0,
        transports: &[Transport::Ble],
        steps: CROSSING_BLE,
    },
    Script {
        name: "crossing-ble-larger-off",
        settings: OFF,
        smaller: 1,
        transports: &[Transport::Ble],
        steps: CROSSING_BLE,
    },
    Script {
        name: "crossing-ble-smaller-on",
        settings: ON,
        smaller: 0,
        transports: &[Transport::Ble],
        steps: CROSSING_BLE,
    },
    Script {
        name: "crossing-ble-larger-on",
        settings: ON,
        smaller: 1,
        transports: &[Transport::Ble],
        steps: CROSSING_BLE,
    },
    Script {
        name: "late-dial-in-order-smaller-off",
        settings: OFF,
        smaller: 0,
        transports: &[Transport::Udp],
        steps: LATE_ORDER,
    },
    Script {
        name: "late-dial-in-order-larger-off",
        settings: OFF,
        smaller: 1,
        transports: &[Transport::Udp],
        steps: LATE_ORDER,
    },
    Script {
        name: "late-dial-in-order-smaller-on",
        settings: ON,
        smaller: 0,
        transports: &[Transport::Udp],
        steps: LATE_ORDER,
    },
    Script {
        name: "late-dial-in-order-larger-on",
        settings: ON,
        smaller: 1,
        transports: &[Transport::Udp],
        steps: LATE_ORDER,
    },
    Script {
        name: "late-dial-reordered-smaller-off",
        settings: OFF,
        smaller: 0,
        transports: &[Transport::Udp],
        steps: LATE_REORDERED,
    },
    Script {
        name: "late-dial-reordered-larger-off",
        settings: OFF,
        smaller: 1,
        transports: &[Transport::Udp],
        steps: LATE_REORDERED,
    },
    Script {
        name: "late-dial-reordered-smaller-on",
        settings: ON,
        smaller: 0,
        transports: &[Transport::Udp],
        steps: LATE_REORDERED,
    },
    Script {
        name: "late-dial-reordered-larger-on",
        settings: ON,
        smaller: 1,
        transports: &[Transport::Udp],
        steps: LATE_REORDERED,
    },
    Script {
        name: "restart-smaller-off",
        settings: OFF,
        smaller: 0,
        transports: &[Transport::Udp],
        steps: RESTART,
    },
    Script {
        name: "restart-larger-off",
        settings: OFF,
        smaller: 1,
        transports: &[Transport::Udp],
        steps: RESTART,
    },
    Script {
        name: "restart-smaller-on",
        settings: ON,
        smaller: 0,
        transports: &[Transport::Udp],
        steps: RESTART,
    },
    Script {
        name: "restart-larger-on",
        settings: ON,
        smaller: 1,
        transports: &[Transport::Udp],
        steps: RESTART,
    },
    Script {
        name: "rekey-own-smaller-off",
        settings: OFF,
        smaller: 0,
        transports: &[Transport::Udp],
        steps: REKEY_OWN,
    },
    Script {
        name: "rekey-own-larger-off",
        settings: OFF,
        smaller: 1,
        transports: &[Transport::Udp],
        steps: REKEY_OWN,
    },
    Script {
        name: "rekey-own-smaller-on",
        settings: ON,
        smaller: 0,
        transports: &[Transport::Udp],
        steps: REKEY_OWN,
    },
    Script {
        name: "rekey-own-larger-on",
        settings: ON,
        smaller: 1,
        transports: &[Transport::Udp],
        steps: REKEY_OWN,
    },
    Script {
        name: "rekey-peer-smaller-off",
        settings: OFF,
        smaller: 0,
        transports: &[Transport::Udp],
        steps: REKEY_PEER,
    },
    Script {
        name: "rekey-peer-larger-off",
        settings: OFF,
        smaller: 1,
        transports: &[Transport::Udp],
        steps: REKEY_PEER,
    },
    Script {
        name: "rekey-peer-smaller-on",
        settings: ON,
        smaller: 0,
        transports: &[Transport::Udp],
        steps: REKEY_PEER,
    },
    Script {
        name: "rekey-peer-larger-on",
        settings: ON,
        smaller: 1,
        transports: &[Transport::Udp],
        steps: REKEY_PEER,
    },
    Script {
        name: "crossing-tcp-rekey-smaller-off",
        settings: OFF,
        smaller: 0,
        transports: &[Transport::Tcp],
        steps: CROSSING_TCP_REKEY,
    },
    Script {
        name: "crossing-tcp-rekey-larger-off",
        settings: OFF,
        smaller: 1,
        transports: &[Transport::Tcp],
        steps: CROSSING_TCP_REKEY,
    },
    Script {
        name: "crossing-tcp-rekey-smaller-on",
        settings: ON,
        smaller: 0,
        transports: &[Transport::Tcp],
        steps: CROSSING_TCP_REKEY,
    },
    Script {
        name: "crossing-tcp-rekey-larger-on",
        settings: ON,
        smaller: 1,
        transports: &[Transport::Tcp],
        steps: CROSSING_TCP_REKEY,
    },
    Script {
        name: "ble-reaped-smaller-on",
        settings: ON,
        smaller: 0,
        transports: &[Transport::Ble],
        steps: BLE_REAPED,
    },
    Script {
        name: "ble-reaped-larger-on",
        settings: ON,
        smaller: 1,
        transports: &[Transport::Ble],
        steps: BLE_REAPED,
    },
];

/// The named starts of the settlement tests that no script runs, each with
/// why: what it needs that no step names, or that no mark shows.
pub const UNSHARED: &[(&str, &str)] = &[
    (
        "7, a dial on the peer's aged link, then an own rekey",
        "its dial goes to the peer's second address, and a step dials only a home",
    ),
    (
        "9, a crossing during a rekey and during its drain",
        "its dials go from and to second addresses, and a step dials only from and to a home",
    ),
    (
        "10, a stored msg2 whose first send failed",
        "a send that fails, which no step names",
    ),
    (
        "11, three nodes",
        "a mark holds what an end holds of one peer",
    ),
    (
        "12, two paths",
        "its second dial goes from a second address, and on joint nodes the link's second path comes from the capability exchange",
    ),
    (
        "13, a replayed msg1 and a forged msg2 spray",
        "a copy of a captured msg1 and a forged message, which no node sends",
    ),
    (
        "14, a wall step inside the heard floor",
        "the wall clock stepping apart from the monotonic one",
    ),
    (
        "16, 17, 20 and 23, a two-path link",
        "the link's second path comes from the capability exchange, started by a feed's candidate, and 20 and 23 add a carrier loss and a transport's removal",
    ),
    (
        "21, the only path's transport removed",
        "a transport's removal, which no step names",
    ),
    (
        "22, a NAT rebound of the second path",
        "a NAT's rebinding of a source address, after the capability exchange",
    ),
];

/// What in `script` names a node or a transport the script does not hold,
/// one entry each; empty for a script both sides can run.
pub fn strays(script: &Script) -> Vec<String> {
    let nodes = script.settings.len();
    let mut out = Vec::new();
    if script.smaller >= nodes {
        out.push(format!("the smaller node n{} is not held", script.smaller));
    }
    for (i, step) in script.steps.iter().enumerate() {
        let at = i + 1;
        let named: Vec<usize> = match *step {
            Step::Dial {
                from,
                to,
                transport,
            } => {
                if !script.transports.contains(&transport) {
                    out.push(format!(
                        "step {at} dials on {}, which is not held",
                        transport.name()
                    ));
                }
                if from == to {
                    out.push(format!("step {at} has n{from} dial itself"));
                }
                alloc::vec![from, to]
            }
            Step::Connected { node } | Step::Restart { node } | Step::Rekey { node } => {
                alloc::vec![node]
            }
            Step::Handshake { to, .. } => alloc::vec![to],
            Step::Heal | Step::Advance(_) => Vec::new(),
        };
        for n in named {
            if n >= nodes {
                out.push(format!("step {at} names n{n}, which is not held"));
            }
        }
    }
    out
}

/// Whose dial an end's current session came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// This end sent the msg1 of that session's handshake.
    Own,
    /// The peer sent it.
    Peer,
}

/// A link record's direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// Set up by the peer's msg1.
    In,
    /// Set up by this end's own dial.
    Out,
}

/// Which of the peer's addresses a pair reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    /// The peer's home address, which a dial goes to.
    Home,
    /// The peer's second address.
    Second,
    /// An address the peer did not bind: the source of a connection the
    /// peer opened.
    Accepted,
}

impl At {
    /// Its word in the trace.
    fn name(self) -> &'static str {
        match self {
            Self::Home => "home",
            Self::Second => "second",
            Self::Accepted => "accepted",
        }
    }
}

/// A pair, by the transport and which of the peer's addresses it reaches:
/// `tcp-home`, `udp-second`, `tcp-accepted`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Place {
    /// The transport.
    pub transport: Transport,
    /// The peer's address.
    pub at: At,
}

impl Place {
    /// The place a word names.
    fn read(word: &str) -> Option<Self> {
        let (t, a) = word.split_once('-')?;
        let transport = Transport::ALL.into_iter().find(|x| x.name() == t)?;
        let at = [At::Home, At::Second, At::Accepted]
            .into_iter()
            .find(|x| x.name() == a)?;
        Some(Self { transport, at })
    }
}

impl fmt::Display for Place {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.transport.name(), self.at.name())
    }
}

/// What an end holds of a peer it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Holding {
    /// Whose dial its current session came from.
    pub session: Side,
    /// Its link record's direction.
    pub dir: Dir,
    /// The pair its link record was set up at.
    pub setup: Place,
    /// The pair it sends to the peer on.
    pub active: Place,
    /// Whether it counts the peering heard.
    pub heard: bool,
}

/// What one end holds of its peer after a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    /// It holds no peering of it.
    Unheld,
    /// It holds the peer.
    Held(Holding),
}

/// A word of a mark, by the field it fills.
fn word(field: Field, value: &str) -> Option<Value> {
    match field {
        Field::Held => match value {
            "yes" => Some(Value::Held(true)),
            "no" => Some(Value::Held(false)),
            _ => None,
        },
        Field::Session => match value {
            "own" => Some(Value::Session(Side::Own)),
            "peer" => Some(Value::Session(Side::Peer)),
            _ => None,
        },
        Field::Dir => match value {
            "in" => Some(Value::Dir(Dir::In)),
            "out" => Some(Value::Dir(Dir::Out)),
            _ => None,
        },
        Field::Setup => Place::read(value).map(Value::Setup),
        Field::Active => Place::read(value).map(Value::Active),
        Field::Heard => match value {
            "heard" => Some(Value::Heard(true)),
            "unheard" => Some(Value::Heard(false)),
            _ => None,
        },
    }
}

impl Mark {
    /// The mark its words name: `none`, or `held` and the five fields in
    /// their order, `held own out tcp-home tcp-home heard`.
    pub fn read(text: &str) -> Result<Self, String> {
        let words: Vec<&str> = text.split_whitespace().collect();
        match words.as_slice() {
            ["none"] => Ok(Self::Unheld),
            ["held", rest @ ..] if rest.len() == FIELDS.len() => {
                let mut fields = Fields::default();
                for (field, value) in FIELDS.into_iter().zip(rest) {
                    let v = word(field, value)
                        .ok_or_else(|| format!("{value:?} is no {}", field.name()))?;
                    fields.set(v);
                }
                fields.mark()
            }
            _ => Err(format!(
                "a mark is `none`, or `held` and {} fields: {text:?}",
                FIELDS.len()
            )),
        }
    }
}

impl fmt::Display for Mark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unheld => f.write_str("none"),
            Self::Held(h) => write!(
                f,
                "held {} {} {} {} {}",
                Value::Session(h.session),
                Value::Dir(h.dir),
                h.setup,
                h.active,
                Value::Heard(h.heard)
            ),
        }
    }
}

/// A field of a mark a `core` line may state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// Whether the end holds the peer.
    Held,
    /// [`Holding::session`].
    Session,
    /// [`Holding::dir`].
    Dir,
    /// [`Holding::setup`].
    Setup,
    /// [`Holding::active`].
    Active,
    /// [`Holding::heard`].
    Heard,
}

/// The fields of a held mark, in the order a line writes them.
const FIELDS: [Field; 5] = [
    Field::Session,
    Field::Dir,
    Field::Setup,
    Field::Active,
    Field::Heard,
];

impl Field {
    /// Its name in a `core` line.
    fn name(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Session => "session",
            Self::Dir => "dir",
            Self::Setup => "setup",
            Self::Active => "active",
            Self::Heard => "heard",
        }
    }
}

/// A value of one field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    /// Whether the end holds the peer.
    Held(bool),
    /// [`Holding::session`].
    Session(Side),
    /// [`Holding::dir`].
    Dir(Dir),
    /// [`Holding::setup`].
    Setup(Place),
    /// [`Holding::active`].
    Active(Place),
    /// [`Holding::heard`].
    Heard(bool),
}

impl Value {
    /// The field it fills.
    pub fn field(self) -> Field {
        match self {
            Self::Held(_) => Field::Held,
            Self::Session(_) => Field::Session,
            Self::Dir(_) => Field::Dir,
            Self::Setup(_) => Field::Setup,
            Self::Active(_) => Field::Active,
            Self::Heard(_) => Field::Heard,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Held(true) => f.write_str("yes"),
            Self::Held(false) => f.write_str("no"),
            Self::Session(Side::Own) => f.write_str("own"),
            Self::Session(Side::Peer) => f.write_str("peer"),
            Self::Dir(Dir::In) => f.write_str("in"),
            Self::Dir(Dir::Out) => f.write_str("out"),
            Self::Setup(p) | Self::Active(p) => p.fmt(f),
            Self::Heard(true) => f.write_str("heard"),
            Self::Heard(false) => f.write_str("unheard"),
        }
    }
}

/// A mark's fields as they are filled, from words or from a mark and the
/// values a `core` line states.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Fields {
    held: Option<bool>,
    session: Option<Side>,
    dir: Option<Dir>,
    setup: Option<Place>,
    active: Option<Place>,
    heard: Option<bool>,
}

impl Fields {
    /// The fields of `mark`.
    fn of(mark: Mark) -> Self {
        match mark {
            Mark::Unheld => Self {
                held: Some(false),
                ..Self::default()
            },
            Mark::Held(h) => Self {
                held: Some(true),
                session: Some(h.session),
                dir: Some(h.dir),
                setup: Some(h.setup),
                active: Some(h.active),
                heard: Some(h.heard),
            },
        }
    }

    /// Fill one field.
    fn set(&mut self, v: Value) {
        match v {
            Value::Held(x) => self.held = Some(x),
            Value::Session(x) => self.session = Some(x),
            Value::Dir(x) => self.dir = Some(x),
            Value::Setup(x) => self.setup = Some(x),
            Value::Active(x) => self.active = Some(x),
            Value::Heard(x) => self.heard = Some(x),
        }
    }

    /// The mark the fields make: a held one needs all five, an unheld one
    /// takes none.
    fn mark(self) -> Result<Mark, String> {
        if self.held == Some(false) {
            return Ok(Mark::Unheld);
        }
        match (self.session, self.dir, self.setup, self.active, self.heard) {
            (Some(session), Some(dir), Some(setup), Some(active), Some(heard)) => {
                Ok(Mark::Held(Holding {
                    session,
                    dir,
                    setup,
                    active,
                    heard,
                }))
            }
            _ => Err(String::from("a held mark with a field missing")),
        }
    }
}

/// A defect of the node that makes the settlement core differ from it,
/// the closed list a `core` line may name: the three the model of the
/// node shows (`legacy/findings.rs` in the settlement tests).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// Crossed dials leave the smaller node on the link the larger dialed.
    CrossingWrongLink,
    /// A late second dial answered in the other order splits the session.
    LateDialSplit,
    /// A dial on the peer's aged link leaves a pending the peer cannot
    /// adopt.
    AgedPending,
}

impl Cause {
    /// Every cause.
    pub const ALL: [Self; 3] = [
        Self::CrossingWrongLink,
        Self::LateDialSplit,
        Self::AgedPending,
    ];

    /// Its name in a `core` line.
    pub fn name(self) -> &'static str {
        match self {
            Self::CrossingWrongLink => "crossing-wrong-link",
            Self::LateDialSplit => "late-dial-split",
            Self::AgedPending => "aged-link-pending",
        }
    }
}

/// What one end holds after one step, as the node holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    /// The step, from 1.
    pub step: usize,
    /// The end, by node index.
    pub node: usize,
    /// What it holds.
    pub mark: Mark,
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} n{} {}", self.step, self.node, self.mark)
    }
}

/// The fields the core gives differently from the node at one end after
/// one step, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Differs {
    /// The step, from 1.
    pub step: usize,
    /// The end, by node index.
    pub node: usize,
    /// The core's value of each field it gives differently.
    pub values: Vec<Value>,
    /// The node's defect the difference comes from.
    pub cause: Cause,
}

impl fmt::Display for Differs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "core {} n{}", self.step, self.node)?;
        for v in &self.values {
            write!(f, " {}={v}", v.field().name())?;
        }
        write!(f, " cause={}", self.cause.name())
    }
}

/// One script's block of the trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    /// The script's name.
    pub name: String,
    /// Each node's setting, as the block's header states it.
    pub settings: Vec<Setting>,
    /// What the node holds, one line per step and end.
    pub lines: Vec<Line>,
    /// Where the core differs.
    pub core: Vec<Differs>,
}

impl Trace {
    /// What end `node` holds after `step`, as the node holds it.
    pub fn mark(&self, step: usize, node: usize) -> Option<Mark> {
        self.lines
            .iter()
            .find(|l| l.step == step && l.node == node)
            .map(|l| l.mark)
    }

    /// The lines with every `core` line applied: what the settlement core
    /// holds. A `core` line on no line, or one that leaves a held mark
    /// short of a field, is an error.
    pub fn cored(&self) -> Result<Vec<Line>, String> {
        let mut out = self.lines.clone();
        for d in &self.core {
            let line = out
                .iter_mut()
                .find(|l| l.step == d.step && l.node == d.node)
                .ok_or_else(|| format!("`{d}` is beside no line"))?;
            let mut fields = Fields::of(line.mark);
            for v in &d.values {
                fields.set(*v);
            }
            line.mark = fields.mark().map_err(|e| format!("`{d}`: {e}"))?;
        }
        Ok(out)
    }
}

/// A step and node index, `<step> n<node>`.
fn place(step: &str, node: &str) -> Result<(usize, usize), String> {
    let s = step
        .parse()
        .map_err(|_| format!("{step:?} is no step number"))?;
    let n = node
        .strip_prefix('n')
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("{node:?} is no node"))?;
    Ok((s, n))
}

/// One line of the trace, `<step> n<node> <mark>`.
pub fn line(text: &str) -> Result<Line, String> {
    let mut words = text.splitn(3, ' ');
    let (step, node, mark) = match (words.next(), words.next(), words.next()) {
        (Some(s), Some(n), Some(m)) => (s, n, m),
        _ => return Err(format!("a line is `<step> n<node> <mark>`: {text:?}")),
    };
    let (step, node) = place(step, node)?;
    Ok(Line {
        step,
        node,
        mark: Mark::read(mark)?,
    })
}

/// One `core` line, `core <step> n<node> <field>=<value>... cause=<cause>`.
pub fn differs(text: &str) -> Result<Differs, String> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let (step, node, rest) = match words.as_slice() {
        ["core", s, n, rest @ ..] => (*s, *n, rest),
        _ => return Err(format!("a core line opens `core <step> n<node>`: {text:?}")),
    };
    let (step, node) = place(step, node)?;
    let (last, pairs) = rest
        .split_last()
        .ok_or_else(|| format!("a core line names its cause: {text:?}"))?;
    let cause = last
        .strip_prefix("cause=")
        .ok_or_else(|| format!("a core line ends with its cause: {text:?}"))?;
    let cause = Cause::ALL
        .into_iter()
        .find(|c| c.name() == cause)
        .ok_or_else(|| format!("{cause:?} is no listed cause: {text:?}"))?;
    let mut values = Vec::new();
    for pair in pairs {
        let (name, value) = pair
            .split_once('=')
            .ok_or_else(|| format!("{pair:?} is no `<field>=<value>`"))?;
        let field = [Field::Held]
            .into_iter()
            .chain(FIELDS)
            .find(|f| f.name() == name)
            .ok_or_else(|| format!("{name:?} is no field"))?;
        let v = word(field, value).ok_or_else(|| format!("{value:?} is no {name}"))?;
        if values.iter().any(|x: &Value| x.field() == field) {
            return Err(format!("{name} is stated twice: {text:?}"));
        }
        values.push(v);
    }
    if values.is_empty() {
        return Err(format!("a core line states a field: {text:?}"));
    }
    Ok(Differs {
        step,
        node,
        values,
        cause,
    })
}

/// The blocks of a trace. A line opening `#` and a blank line are
/// comments; every other line belongs to the block a `script <name>
/// <setting>...` header opened.
pub fn read(text: &str) -> Result<Vec<Trace>, String> {
    let mut out: Vec<Trace> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let at = i + 1;
        let text = raw.trim_end();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        if let Some(header) = text.strip_prefix("script ") {
            let mut words = header.split_whitespace();
            let name = words
                .next()
                .ok_or_else(|| format!("line {at}: a script header names it"))?;
            let settings = words
                .map(|w| Setting::read(w).ok_or_else(|| format!("line {at}: {w:?} is no setting")))
                .collect::<Result<Vec<_>, _>>()?;
            out.push(Trace {
                name: name.to_string(),
                settings,
                lines: Vec::new(),
                core: Vec::new(),
            });
            continue;
        }
        let block = out
            .last_mut()
            .ok_or_else(|| format!("line {at} is before any script header"))?;
        if text.starts_with("core ") {
            block
                .core
                .push(differs(text).map_err(|e| format!("line {at}: {e}"))?);
        } else {
            block
                .lines
                .push(line(text).map_err(|e| format!("line {at}: {e}"))?);
        }
    }
    Ok(out)
}

/// The block of script `name` in the committed trace.
pub fn expected(name: &str) -> Option<Trace> {
    read(TRACE)
        .expect("the committed trace reads")
        .into_iter()
        .find(|t| t.name == name)
}

/// What does not match between `scripts` and `traces`, one entry each:
/// a script with no block or a block with no script, two blocks of one
/// name, a header whose settings are not the script's, a step and end with
/// no line or with two, a line past the script's steps or nodes, and a
/// `core` line beside no line or stating a value the line already holds.
pub fn unmatched(scripts: &[Script], traces: &[Trace]) -> Vec<String> {
    let mut out = Vec::new();
    for t in traces {
        if traces.iter().filter(|u| u.name == t.name).count() > 1 {
            out.push(format!("{} has two blocks", t.name));
        }
        if !scripts.iter().any(|s| s.name == t.name) {
            out.push(format!("{} has lines and no script", t.name));
        }
    }
    for s in scripts {
        let Some(t) = traces.iter().find(|t| t.name == s.name) else {
            out.push(format!("{} has no lines", s.name));
            continue;
        };
        if t.settings != s.settings {
            out.push(format!(
                "{}'s header states {:?}, its script {:?}",
                s.name, t.settings, s.settings
            ));
        }
        let nodes = s.settings.len();
        for step in 1..=s.steps.len() {
            for node in 0..nodes {
                let n = t
                    .lines
                    .iter()
                    .filter(|l| l.step == step && l.node == node)
                    .count();
                if n != 1 {
                    out.push(format!("{} has {n} lines for step {step} n{node}", s.name));
                }
            }
        }
        for l in &t.lines {
            if l.step == 0 || l.step > s.steps.len() || l.node >= nodes {
                out.push(format!("{}: `{l}` is past its script", s.name));
            }
        }
        for d in &t.core {
            let Some(mark) = t.mark(d.step, d.node) else {
                out.push(format!("{}: `{d}` is beside no line", s.name));
                continue;
            };
            let held = Fields::of(mark);
            let restated = d.values.iter().any(|v| {
                let mut one = held;
                one.set(*v);
                one == held
            });
            if restated {
                out.push(format!(
                    "{}: `{d}` states a value the node's line holds",
                    s.name
                ));
            }
        }
        if let Err(e) = t.cored() {
            out.push(format!("{}: {e}", s.name));
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/parity.rs"]
mod tests;
