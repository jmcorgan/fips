//! The named starts a real pair runs, the map from each pinned defect of the
//! node to the start that reaches it, and the core's starts no real pair
//! runs, each with its reason.
//!
//! A start is the core's named start (`fips-core`,
//! `proto::settle::tests::starts`) written in the world's steps: a `build`
//! that brings the nodes to the start's state, and a `script`, the
//! schedule from there to its target, whose handshake packets the
//! explorer varies. Node 0 is the smaller node as the start is written;
//! [`Order::Larger`] runs it with nodes 0 and 1 exchanged, so the larger
//! node does what the script gives node 0, as the core's `flipped` does.

use super::script::{Kind, Step};
use super::world::Medium;

/// Which node of the world a start's node 0 is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Order {
    /// As written: node 0 is the smaller node.
    Smaller,
    /// Nodes 0 and 1 exchanged: node 0 of the script is the larger node.
    Larger,
}

impl Order {
    /// Both orders, as written first.
    pub(super) const BOTH: [Order; 2] = [Order::Smaller, Order::Larger];

    /// The world's index of the script's node `i`.
    pub(super) fn node(self, i: usize) -> usize {
        match (self, i) {
            (Order::Larger, 0) => 1,
            (Order::Larger, 1) => 0,
            _ => i,
        }
    }

    /// `step` with its nodes taken to the world's indices.
    pub(super) fn step(self, step: Step) -> Step {
        let n = |i| self.node(i);
        match step {
            Step::Dial {
                from,
                to,
                transport,
            } => Step::Dial {
                from: n(from),
                to: n(to),
                transport,
            },
            Step::Connected { node } => Step::Connected { node: n(node) },
            Step::Handshake { to, kind, nth } => Step::Handshake {
                to: n(to),
                kind,
                nth,
            },
            Step::Drop { to, kind, nth } => Step::Drop {
                to: n(to),
                kind,
                nth,
            },
            Step::Duplicate { to, kind, nth } => Step::Duplicate {
                to: n(to),
                kind,
                nth,
            },
            Step::Swap { to, kind, nth } => Step::Swap {
                to: n(to),
                kind,
                nth,
            },
            Step::Heal => Step::Heal,
            Step::Advance(ms) => Step::Advance(ms),
            Step::Restart { node } => Step::Restart { node: n(node) },
            Step::Rekey { node } => Step::Rekey { node: n(node) },
        }
    }
}

/// A waiver of the shell audit a start may need, by the script's nodes: the
/// node that holds the breach and its peer. It is passed at every leaf of
/// the start's paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Waive {
    /// `Exempt::CrossedInbound`.
    CrossedInbound(usize, usize),
    /// `Exempt::MovedOwnDial`.
    MovedOwnDial(usize, usize),
}

/// What an oracle reads at a leaf: whether each pair settled, a breach of
/// the shell audit's, or the leaf's heal itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Clause {
    /// The two nodes of each pair hold each other on one session that
    /// carries a heartbeat each way (`settle::settled`).
    Settled,
    /// The shell audit's `OneSession` first clause: `Breach::Split` or
    /// `Breach::OneSided`.
    Split,
    /// The shell audit's `OneSession` second clause: `Breach::Unadoptable`.
    Unadoptable,
    /// The shell audit's `RightLink`: `Breach::RightLink`.
    RightLink,
    /// The shell audit's `MapsAgree`: `Breach::MapsAgree`.
    MapsAgree,
    /// The shell audit's `ConnectionsInUse`: `Breach::ConnectionsInUse` or
    /// `Breach::Unconnected`.
    ConnectionsInUse,
    /// The leaf's heal: the nodes went quiet and every pair came to hold
    /// each other on one session within the heal's time.
    Quiet,
}

/// One named start on real nodes.
#[derive(Clone, Copy)]
pub(super) struct Start {
    /// The core's number for the start.
    pub(super) number: u8,
    /// Its name, unique among the starts here.
    pub(super) name: &'static str,
    /// The transport its nodes run.
    pub(super) medium: Medium,
    /// How many nodes its world holds.
    pub(super) nodes: usize,
    /// How many transports each node has: a second is a second loopback
    /// transport (`World::add_transport`).
    pub(super) transports: usize,
    /// Whether each node runs a decrypt-worker pool, started before the
    /// start's first step. Only Unix builds have the pool.
    #[cfg(unix)]
    pub(super) workers: bool,
    /// The steps that bring the world to the start's state. Run as written,
    /// never varied.
    pub(super) build: &'static [Step],
    /// The schedule from the start to its target. The explorer varies each
    /// of its handshake packets.
    pub(super) script: &'static [Step],
    /// The waivers a leaf passes.
    pub(super) waivers: &'static [Waive],
    /// How many paths the explorer walks: the scripted path and each
    /// variation that applies, in either order and at either setting, as
    /// first measured. A swap applies only where a second packet of its
    /// class is held, so a script of `n` handshake steps has between
    /// `1 + 2n` and `1 + 3n`.
    pub(super) reach: usize,
    /// The clauses not asserted on any of the start's paths, because a
    /// pinned defect breaks them on its scripted path; the map names the
    /// pin, and `the_explorer_finds_each_pinned_defect_at_its_oracle`
    /// asserts it there.
    pub(super) pinned: &'static [Clause],
}

impl Start {
    /// The dials the start makes, in the world's indices for `order`: each
    /// dialer's (node, peer, transport). A leaf's heal redials each one
    /// whose dialer holds neither the peer nor a dial in progress.
    pub(super) fn dials(&self, order: Order) -> Vec<(usize, usize, usize)> {
        let mut out = Vec::new();
        for step in self.build.iter().chain(self.script) {
            if let Step::Dial {
                from,
                to,
                transport,
            } = order.step(*step)
                && !out.iter().any(|&(f, t, _)| f == from && t == to)
            {
                out.push((from, to, transport));
            }
        }
        out
    }

    /// The pairs the start's dials make, each once, in the world's indices.
    pub(super) fn pairs(&self, order: Order) -> Vec<(usize, usize)> {
        let mut out: Vec<(usize, usize)> = Vec::new();
        for (from, to, _) in self.dials(order) {
            let pair = (from.min(to), from.max(to));
            if !out.contains(&pair) {
                out.push(pair);
            }
        }
        out
    }
}

const fn dial(from: usize, to: usize, transport: usize) -> Step {
    Step::Dial {
        from,
        to,
        transport,
    }
}

const fn msg1(to: usize, nth: usize) -> Step {
    Step::Handshake {
        to,
        kind: Kind::Msg1,
        nth,
    }
}

const fn msg2(to: usize, nth: usize) -> Step {
    Step::Handshake {
        to,
        kind: Kind::Msg2,
        nth,
    }
}

/// Past the 1 s floor below which an unheard peering is not replaced.
const PAST_UNHEARD: u64 = 1_500;

// The starts' steps. Node 0 is the smaller node as written.

/// Start 1: nodes 0 and 1 dial each other on transport 0.
const CROSSED: &[Step] = &[dial(0, 1, 0), dial(1, 0, 0)];

/// Starts 3 and 4: the crossed dials over a connection each, both connects
/// resolved before either msg1 is read, as `settle::crossed_tcp` does.
const CROSSED_ORIENTED: &[Step] = &[
    dial(0, 1, 0),
    dial(1, 0, 0),
    Step::Connected { node: 0 },
    Step::Connected { node: 1 },
];

/// The core's crossing script: node 1 reads node 0's msg1, node 0 reads
/// node 1's, then each reads the answer to its own dial.
const CROSSING: &[Step] = &[msg1(1, 0), msg1(0, 0), msg2(0, 0), msg2(1, 0)];

/// Start 2: node 0 dials on transport 0, node 1 on transport 1.
const CROSSED_TWICE: &[Step] = &[dial(0, 1, 0), dial(1, 0, 1)];

/// Start 2's script, the core's: node 0 reads first.
const CROSSING_TWICE: &[Step] = &[msg1(0, 0), msg1(1, 0), msg2(1, 0), msg2(0, 0)];

/// Starts 5 and 6: node 0 dials node 1 twice before either msg1 is read.
const DIALED_TWICE: &[Step] = &[dial(0, 1, 0), dial(0, 1, 0)];

/// Start 5 on real nodes: node 1 reads the first msg1 and node 0 its
/// answer; node 0's frames wait behind its second msg1, so node 1 has not
/// heard it when, past the unheard floor, it reads that msg1; node 0 then
/// reads the second answer. The shape of `settle::crossing`'s
/// `second_msg1_late` in order.
const IN_ORDER: &[Step] = &[
    msg1(1, 0),
    msg2(0, 0),
    Step::Advance(PAST_UNHEARD),
    msg1(1, 0),
    msg2(0, 0),
];

/// Start 6 on real nodes: as start 5, but node 0 reads neither answer
/// until both are out, and then the second dial's first.
const LATE_REORDERED: &[Step] = &[
    msg1(1, 0),
    Step::Advance(PAST_UNHEARD),
    msg1(1, 0),
    msg2(0, 1),
    msg2(0, 0),
];

/// Start 8: node 0's dial of node 1.
const DIALED: &[Step] = &[dial(0, 1, 0)];

/// Start 8's script, the core's: the dial completes and node 0 restarts.
const RESTARTED: &[Step] = &[msg1(1, 0), msg2(0, 0), Step::Restart { node: 0 }];

/// Start 9: a pair settled on transport 0; node 0 starts its own rekey,
/// with node 1's end of the session past the floor below which a msg1 is a
/// fresh dial; then each dials the other on transport 1, the second
/// address the core's start dials.
const REKEYING: &[Step] = &[
    dial(0, 1, 0),
    msg1(1, 0),
    msg2(0, 0),
    Step::Heal,
    Step::Rekey { node: 0 },
    dial(0, 1, 1),
    dial(1, 0, 1),
];

/// Start 9's script, the core's: node 1 reads node 0's rekey msg1 and then
/// its dial's, node 0 reads node 1's dial and then the first answer.
const CROSSING_REKEY: &[Step] = &[msg1(1, 0), msg1(1, 0), msg1(0, 0), msg2(0, 0)];

/// Start 11: nodes 0 and 1 cross, and node 2 dials node 0.
const THREE: &[Step] = &[dial(0, 1, 0), dial(1, 0, 0), dial(2, 0, 0)];

/// Start 11's script, the core's: node 1 reads node 0's msg1, node 0 reads
/// node 1's and then node 2's, then node 0 reads node 1's answer.
const THREE_SCRIPT: &[Step] = &[msg1(1, 0), msg1(0, 0), msg1(0, 0), msg2(0, 0)];

/// A crossing's waiver at its smaller node, whichever of the script's two
/// nodes that is in the order run.
const CROSSING_WAIVERS: &[Waive] = &[Waive::CrossedInbound(0, 1), Waive::CrossedInbound(1, 0)];

/// A dialer's later dial moving its held peer: node 0 dials.
const LATE_WAIVERS: &[Waive] = &[Waive::MovedOwnDial(0, 1)];

/// Every named start a real pair runs on this build.
pub(super) fn starts() -> Vec<Start> {
    let s = |number, name, medium, build, script, waivers, reach| Start {
        number,
        name,
        medium,
        nodes: 2,
        transports: 1,
        #[cfg(unix)]
        workers: false,
        build,
        script,
        waivers,
        reach,
        pinned: &[],
    };
    #[cfg_attr(not(ble_available), allow(unused_mut))]
    let mut v = vec![
        s(
            1,
            "crossing, connectionless",
            Medium::Loopback,
            CROSSED,
            CROSSING,
            CROSSING_WAIVERS,
            9,
        ),
        Start {
            transports: 2,
            ..s(
                2,
                "crossing, two transports",
                Medium::Loopback,
                CROSSED_TWICE,
                CROSSING_TWICE,
                CROSSING_WAIVERS,
                9,
            )
        },
        s(
            3,
            "crossing, connection-oriented",
            Medium::Tcp,
            CROSSED_ORIENTED,
            CROSSING,
            CROSSING_WAIVERS,
            9,
        ),
        s(
            5,
            "late second dial in order",
            Medium::Loopback,
            DIALED_TWICE,
            IN_ORDER,
            LATE_WAIVERS,
            11,
        ),
        // The scripted path leaves the two ends on different sessions,
        // which the leaf's heal does not mend in its time: the pinned
        // second msg2 first.
        Start {
            pinned: &[Clause::Settled, Clause::Split, Clause::Quiet],
            ..s(
                6,
                "late second dial, second msg2 first",
                Medium::Loopback,
                DIALED_TWICE,
                LATE_REORDERED,
                LATE_WAIVERS,
                11,
            )
        },
        s(
            8,
            "restart at each point",
            Medium::Loopback,
            DIALED,
            RESTARTED,
            &[],
            5,
        ),
        Start {
            transports: 2,
            ..s(
                9,
                "crossing during a rekey",
                Medium::Loopback,
                REKEYING,
                CROSSING_REKEY,
                CROSSING_WAIVERS,
                10,
            )
        },
        Start {
            nodes: 3,
            ..s(
                11,
                "three nodes",
                Medium::Loopback,
                THREE,
                THREE_SCRIPT,
                CROSSING_WAIVERS,
                10,
            )
        },
    ];
    #[cfg(ble_available)]
    v.push(s(
        4,
        "crossing, BLE",
        Medium::Ble,
        CROSSED_ORIENTED,
        CROSSING,
        CROSSING_WAIVERS,
        9,
    ));
    v
}

/// Start 1 with a decrypt-worker pool at each node, started before either
/// dial: the crossing moves one node's peer onto the session of its own
/// dial, whose rebuilt machine offers that session to the workers. It is
/// not among [`starts`], which run with no pool; its own test walks it.
#[cfg(unix)]
pub(super) fn pooled() -> Start {
    Start {
        number: 1,
        name: "crossing, decrypt workers",
        medium: Medium::Loopback,
        nodes: 2,
        transports: 1,
        workers: true,
        build: CROSSED,
        script: CROSSING,
        waivers: CROSSING_WAIVERS,
        reach: 9,
        pinned: &[],
    }
}

/// The core's named starts no real pair runs here, by number, each with its
/// reason. With [`starts`] they cover every number from 1 to 14.
pub(super) const NOT_RUN: &[(u8, &str)] = &[
    (
        7,
        "dial on the peer's aged link: the world dials a second address of the peer only as a second transport, and ages a link only by starting its node's rekey, while the start dials a second address on the link's own transport after both ends aged with no rekey",
    ),
    (
        10,
        "stored msg2 whose send failed: the world has no failing send; a dropped msg2 is a variation of the other starts",
    ),
    (
        12,
        "two paths: the core runs it on a BLE link of two paths, and the world's BLE nodes have one address each; the crossing on two transports is start 2",
    ),
    (
        13,
        "replayed msg1 and forged msg2s: the world forges nothing, and a msg1 kept past the established frames behind it holds those frames back; the variations' duplicates read a copy before them, and `settle::bounds` covers the forged msg2s",
    ),
    (
        14,
        "wall step inside the heard floor: the world has no step of the wall clock; `settle::clock` covers it",
    ),
];

/// Where the explorer finds a pinned defect of the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reach {
    /// On the scripted path of the start named, in the order given, with
    /// every waiver lifted: the clause given breaks, at the node given (in
    /// the world's indices) or at any node.
    Start {
        name: &'static str,
        order: Order,
        clause: Clause,
        node: Option<usize>,
    },
    /// No start reaches it, for the reason given.
    None(&'static str),
}

/// The reason the crossed TCP redial pins reach no start.
const REDIAL: &str = "the world has no step that closes an established connection, so no redial is driven; its cause, the smaller node's inbound link record, is what the four crossed TCP record pins map to, and is found there";

/// The reason the aged-link pins reach no start.
const AGED: &str = "the dial is to a second address of the peer on the link's own transport, after both ends aged past the rekey trigger with no rekey started; the world dials a second address only as a second transport, and ages a session only by starting a rekey (start 7 is not run)";

/// The reason the heard-floor crossing pins reach no start.
const SILENT: &str = "the smaller node reads the crossed msg1 16 s after it last heard the larger, past the heard floor; the explorer varies packets and not time, and the pins backdate the heard time where a world would have to stay silent";

/// The reason the aged rekey pins reach no start.
const AGED_REKEY: &str = "the dial follows the smaller node's own completed rekey, with the larger node's frames after the cutover lost and the dial made to a second address on the link's own transport; the world loses no established frame and dials a second address only as a second transport";

/// Every `fips-mesh` known-defect line of `testing/ignored-tests.txt`, by
/// the test's path and its multipath setting, and where the explorer finds
/// its defect. Written before the explorer's first run, so a miss cannot
/// be reclassified afterwards.
pub(super) const PINS: &[(&str, bool, Reach)] = &[
    (
        "transport::ethernet::io::tests::blocking_send_parks_past_a_shutdown_request_when_the_channel_is_full",
        false,
        Reach::None(
            "a defect of the Ethernet transport's blocking send, not of settlement: no start runs that transport",
        ),
    ),
    (
        "node::tests::settle::crossing::crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_smaller_first",
        false,
        Reach::Start {
            name: "crossing, connection-oriented",
            order: Order::Smaller,
            clause: Clause::RightLink,
            node: Some(0),
        },
    ),
    (
        "node::tests::settle::crossing::crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_smaller_first_with_multipath_on",
        true,
        Reach::Start {
            name: "crossing, connection-oriented",
            order: Order::Smaller,
            clause: Clause::RightLink,
            node: Some(0),
        },
    ),
    (
        "node::tests::settle::crossing::crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_larger_first",
        false,
        Reach::Start {
            name: "crossing, connection-oriented",
            order: Order::Larger,
            clause: Clause::RightLink,
            node: Some(0),
        },
    ),
    (
        "node::tests::settle::crossing::crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_larger_first_with_multipath_on",
        true,
        Reach::Start {
            name: "crossing, connection-oriented",
            order: Order::Larger,
            clause: Clause::RightLink,
            node: Some(0),
        },
    ),
    (
        "node::tests::settle::crossing::after_crossed_tcp_dials_a_send_from_the_smaller_node_redials_a_dropped_connection_smaller_first",
        false,
        Reach::None(REDIAL),
    ),
    (
        "node::tests::settle::crossing::after_crossed_tcp_dials_a_send_from_the_smaller_node_redials_a_dropped_connection_smaller_first_with_multipath_on",
        true,
        Reach::None(REDIAL),
    ),
    (
        "node::tests::settle::crossing::after_crossed_tcp_dials_a_send_from_the_smaller_node_redials_a_dropped_connection_larger_first",
        false,
        Reach::None(REDIAL),
    ),
    (
        "node::tests::settle::crossing::after_crossed_tcp_dials_a_send_from_the_smaller_node_redials_a_dropped_connection_larger_first_with_multipath_on",
        true,
        Reach::None(REDIAL),
    ),
    (
        "node::tests::settle::crossing::a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_a_working_peering_larger_dialer",
        false,
        Reach::Start {
            name: "late second dial, second msg2 first",
            order: Order::Larger,
            clause: Clause::Settled,
            node: None,
        },
    ),
    (
        "node::tests::settle::crossing::a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_a_working_peering_larger_dialer_with_multipath_on",
        true,
        Reach::Start {
            name: "late second dial, second msg2 first",
            order: Order::Larger,
            clause: Clause::Settled,
            node: None,
        },
    ),
    (
        "node::tests::settle::crossing::a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_a_working_peering_smaller_dialer",
        false,
        Reach::Start {
            name: "late second dial, second msg2 first",
            order: Order::Smaller,
            clause: Clause::Settled,
            node: None,
        },
    ),
    (
        "node::tests::settle::crossing::a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_a_working_peering_smaller_dialer_with_multipath_on",
        true,
        Reach::Start {
            name: "late second dial, second msg2 first",
            order: Order::Smaller,
            clause: Clause::Settled,
            node: None,
        },
    ),
    (
        "node::tests::settle::crossing::a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_one_session_by_the_audit_larger_dialer",
        false,
        Reach::Start {
            name: "late second dial, second msg2 first",
            order: Order::Larger,
            clause: Clause::Split,
            node: None,
        },
    ),
    (
        "node::tests::settle::crossing::a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_one_session_by_the_audit_larger_dialer_with_multipath_on",
        true,
        Reach::Start {
            name: "late second dial, second msg2 first",
            order: Order::Larger,
            clause: Clause::Split,
            node: None,
        },
    ),
    (
        "node::tests::settle::crossing::a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_one_session_by_the_audit_smaller_dialer",
        false,
        Reach::Start {
            name: "late second dial, second msg2 first",
            order: Order::Smaller,
            clause: Clause::Split,
            node: None,
        },
    ),
    (
        "node::tests::settle::crossing::a_second_msg1_more_than_1s_later_with_its_msg2_first_leaves_one_session_by_the_audit_smaller_dialer_with_multipath_on",
        true,
        Reach::Start {
            name: "late second dial, second msg2 first",
            order: Order::Smaller,
            clause: Clause::Split,
            node: None,
        },
    ),
    (
        "node::tests::settle::crossing::a_larger_dialers_rekey_after_its_dial_on_the_peers_aged_link_is_answered",
        false,
        Reach::None(AGED),
    ),
    (
        "node::tests::settle::crossing::a_larger_dialers_rekey_after_its_dial_on_the_peers_aged_link_is_answered_with_multipath_on",
        true,
        Reach::None(AGED),
    ),
    (
        "node::tests::settle::crossing::a_larger_dialers_dial_on_the_peers_aged_link_leaves_no_pending_the_peer_cannot_adopt",
        false,
        Reach::None(AGED),
    ),
    (
        "node::tests::settle::crossing::a_larger_dialers_dial_on_the_peers_aged_link_leaves_no_pending_the_peer_cannot_adopt_with_multipath_on",
        true,
        Reach::None(AGED),
    ),
    (
        "node::tests::settle::crossing::a_crossed_msg1_from_another_transport_read_past_the_heard_floor_leaves_one_session",
        false,
        Reach::None(SILENT),
    ),
    (
        "node::tests::settle::crossing::a_crossed_msg1_from_another_transport_read_past_the_heard_floor_leaves_one_session_with_multipath_on",
        true,
        Reach::None(SILENT),
    ),
    (
        "node::tests::settle::crossing::a_crossed_msg1_on_the_same_transport_read_past_the_heard_floor_leaves_one_session",
        false,
        Reach::None(SILENT),
    ),
    (
        "node::tests::settle::crossing::a_crossed_msg1_on_the_same_transport_read_past_the_heard_floor_leaves_one_session_with_multipath_on",
        true,
        Reach::None(SILENT),
    ),
    (
        "node::tests::settle::crossing::a_larger_dialers_dial_on_the_aged_link_after_the_smaller_nodes_rekey_leaves_one_session",
        false,
        Reach::None(AGED_REKEY),
    ),
    (
        "node::tests::settle::crossing::a_larger_dialers_dial_on_the_aged_link_after_the_smaller_nodes_rekey_leaves_one_session_with_multipath_on",
        true,
        Reach::None(AGED_REKEY),
    ),
    (
        "node::tests::settle::restart::a_rekey_msg1_of_the_peers_previous_run_read_late_by_the_restarted_node_leaves_one_session",
        false,
        Reach::None(
            "the restarted node must read the late rekey msg1 with its new peering about 1 s old, so not eligible as a rekey; the world's rekey step ages the peer's end of the session past the 30 s floor, which makes that msg1 an eligible rekey, and a rekey reached by time alone starts at a jittered moment no schedule names",
        ),
    ),
];
