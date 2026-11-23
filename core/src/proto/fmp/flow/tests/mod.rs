//! Tests of the XX flow on a table, by file: the flow's state and hooks
//! (`slot.rs`), msg1 (`msg1.rs`), msg2 and this node's dials (`msg2.rs`),
//! msg3 (`msg3.rs`), the characterisations against next's code
//! (`chars.rs`), the transcription of next's rules as a node of the
//! settlement world (`next.rs`) and its check against the judge
//! (`judged.rs`), the flow as a node of that world held to next's nodes and
//! the judge (`joint.rs`), and the switches' rows and meta-test
//! (`faults.rs`). The helpers here
//! build a table of the smaller or the larger node and step it, and the
//! scans below hold the flow's sources to the settlement core's rules.

mod chars;
mod faults;
mod joint;
mod judged;
mod msg1;
mod msg2;
mod msg3;
mod next;
mod slot;

use alloc::string::String;
use alloc::vec::Vec;

use super::{Anon, AnonDial, In, Out, Xx};
use crate::identity::NodeAddr;
use crate::proto::fmp::{EphemeralDigest, RekeyClaim};
use crate::proto::rekey::IndexLease;
use crate::proto::settle::flow::Outs;
use crate::proto::settle::gates::Epoch;
use crate::proto::settle::input::{Dial, Input};
use crate::proto::settle::links::{LinkNo, Pair};
use crate::proto::settle::output::Output;
use crate::proto::settle::params::Params;
use crate::proto::settle::table::Table;
use crate::proto::settle::tests::{faults as settle_faults, fenced, files, tests_in};
use crate::testutil::TestInstant;
use crate::transport::{TransportAddr, TransportId};

/// A table running the XX flow.
type T = Table<TestInstant, Xx>;

/// One output of it.
type O = Outs<TestInstant, Xx>;

/// The pair at `port`.
fn pair(port: u16) -> Pair {
    Pair {
        transport: TransportId::new(1),
        addr: TransportAddr::from_string(&alloc::format!("10.0.0.1:{port}")),
    }
}

/// The smaller node.
fn small() -> NodeAddr {
    NodeAddr::from_bytes([1; 16])
}

/// The larger node.
fn large() -> NodeAddr {
    NodeAddr::from_bytes([2; 16])
}

/// A third node, larger than both.
fn third() -> NodeAddr {
    NodeAddr::from_bytes([3; 16])
}

/// The instant `ms` milliseconds in.
fn t(ms: u64) -> TestInstant {
    TestInstant(ms)
}

/// The ephemeral of msg1 `n`.
fn eph(n: u32) -> EphemeralDigest {
    let mut key = [0u8; 33];
    key[..4].copy_from_slice(&n.to_be_bytes());
    EphemeralDigest::of_noise_msg1(&key).expect("33 bytes carry an ephemeral")
}

/// A peer's first epoch.
const E1: Epoch = [1; 8];

/// The epoch of a peer that restarted.
const E2: Epoch = [2; 8];

/// The XX table of `me` with the node's default parameters, `leaf` saying
/// whether it is a leaf.
fn node(me: NodeAddr, leaf: bool) -> T {
    Table::flowing(me, super::params(Params::default()), Xx::new(leaf))
}

/// The XX table of `me` with parameters `params`.
fn node_with(me: NodeAddr, params: Params) -> T {
    Table::flowing(me, super::params(params), Xx::new(false))
}

/// Take `input` at `at` milliseconds.
fn go(table: &mut T, input: Input<In>, at: u64) -> Vec<O> {
    table.step(input, t(at))
}

/// Take the flow's own `input` at `at` milliseconds.
fn xx(table: &mut T, input: In, at: u64) -> Vec<O> {
    go(table, Input::Flow(input), at)
}

/// An identified dial of `peer` with msg1 `n` to `port`.
fn dial(peer: NodeAddr, n: u32, port: u16) -> Input<In> {
    Input::Dial(Dial {
        peer,
        to: pair(port),
        msg1: n.to_be_bytes().to_vec(),
        lease: IndexLease::for_test(n),
        resends: None,
        link: None,
    })
}

/// An anonymous dial with msg1 `n` to `port`.
fn anon_dial(n: u32, port: u16) -> In {
    In::AnonDial(AnonDial {
        to: pair(port),
        msg1: n.to_be_bytes().to_vec(),
        lease: IndexLease::for_test(n),
        resends: None,
        link: None,
    })
}

/// Anonymous msg1 `n` from `port`, its source's established link
/// `rekey_of`.
fn anon(n: u32, port: u16, rekey_of: Option<LinkNo>) -> In {
    In::Anon(Anon {
        from: pair(port),
        bytes: n.to_be_bytes().to_vec(),
        ephemeral: eph(n),
        rekey_of,
    })
}

/// The msg2 answering msg1 `n`.
fn answer(n: u32) -> Vec<u8> {
    [&[2u8][..], &n.to_be_bytes()].concat()
}

/// The answer the shell builds for anonymous msg1 `n` asked on `link`.
fn hello(link: LinkNo, n: u32) -> In {
    In::Hello {
        link,
        msg2: answer(n),
        lease: IndexLease::for_test(n),
    }
}

/// The link of the ask in `out`.
fn asked(out: &[O]) -> LinkNo {
    out.iter()
        .find_map(|o| {
            if let Output::Flow(Out::Ask { link }) = o {
                Some(*link)
            } else {
                None
            }
        })
        .expect("precondition: the flow asked for an answer")
}

/// Anonymous msg1 `n` from `port` at `at`, answered: its link.
fn answered(table: &mut T, n: u32, port: u16, rekey_of: Option<LinkNo>, at: u64) -> LinkNo {
    let link = asked(&xx(table, anon(n, port, rekey_of), at));
    xx(table, hello(link, n), at);
    link
}

/// The link a dial opened.
fn opened(out: &[O]) -> LinkNo {
    out.iter()
        .find_map(|o| {
            if let Output::Opened { link } = o {
                Some(*link)
            } else {
                None
            }
        })
        .expect("precondition: the dial opened a link")
}

/// The msg2 of `peer` at `epoch` from `port` on the dial on `link`.
fn msg2(link: LinkNo, peer: NodeAddr, epoch: Epoch, port: u16) -> In {
    In::Msg2 {
        link,
        epoch,
        from: pair(port),
        peer,
    }
}

/// Hold `peer` at `epoch` on this node's dial to `port` with msg1 `n`,
/// completed at `at`: its link.
fn held_by_dial(table: &mut T, peer: NodeAddr, epoch: Epoch, n: u32, port: u16, at: u64) -> LinkNo {
    let link = opened(&go(table, dial(peer, n, port), at));
    xx(table, msg2(link, peer, epoch, port), at);
    let out = xx(table, In::FinalSent { link }, at);
    assert!(installs(&out, peer), "precondition: the dial installs");
    link
}

/// The msg3 of `peer` at `epoch` claiming `claim`, from `port`, on the
/// answer on `link`.
fn msg3(link: LinkNo, peer: NodeAddr, epoch: Epoch, claim: RekeyClaim, port: u16) -> In {
    In::Msg3 {
        link,
        peer,
        epoch,
        claim,
        from: pair(port),
    }
}

/// Hold `peer` at `epoch` on the answer to its anonymous msg1 `n` from
/// `port`, completed by its msg3 at `at`: its link.
fn held_by_answer(
    table: &mut T,
    peer: NodeAddr,
    epoch: Epoch,
    n: u32,
    port: u16,
    at: u64,
) -> LinkNo {
    let link = answered(table, n, port, None, at);
    let out = xx(table, msg3(link, peer, epoch, RekeyClaim::None, port), at);
    assert!(installs(&out, peer), "precondition: the msg3 installs");
    link
}

/// Whether `out` asks for the msg3 of the dial on `link`.
fn finals(out: &[O], link: LinkNo) -> bool {
    out.iter()
        .any(|o| matches!(o, Output::Flow(Out::Final { link: l }) if *l == link))
}

/// Whether `out` installs `peer`.
fn installs(out: &[O], peer: NodeAddr) -> bool {
    out.iter()
        .any(|o| matches!(o, Output::Install(i) if i.peer == peer))
}

/// Whether `out` retires `link`, closing nothing.
fn retires_quietly(out: &[O], link: LinkNo) -> bool {
    out.iter()
        .any(|o| matches!(o, Output::Retire { link: l, closes } if *l == link && closes.is_empty()))
}

/// The flow's directory on disk, or `rel` below it.
fn dir(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/proto/fmp/flow")
        .join(rel)
}

#[test]
fn the_wildcard_arm_fence_is_declared_at_the_flows_root() {
    let root = include_str!("../mod.rs");
    let unfenced = root.replace("#![deny(clippy::wildcard_enum_match_arm)]", "");
    assert!(!fenced(&unfenced), "the scan finds a root without the deny");
    assert!(
        fenced(root),
        "every match over the flow's states stays exhaustive only while the lint is denied at its root"
    );
}

#[test]
fn every_flow_test_is_named_by_a_switch_or_listed_and_the_scan_finds_a_planted_one() {
    let sources = files(&dir(""), false);
    assert!(!sources.is_empty(), "precondition: the flow's sources read");
    for source in &sources {
        assert!(
            tests_in(source).is_empty(),
            "a flow source holds a test; the flow's tests go in its tests directory"
        );
    }
    let tests: Vec<String> = files(&dir("tests"), true)
        .iter()
        .flat_map(|text| tests_in(text))
        .collect();
    assert!(!tests.is_empty(), "precondition: the flow's tests read");
    let missing =
        settle_faults::uncovered(&tests, faults::ROWS, &[], &[], faults::CHARACTERISATION);
    assert!(
        missing.is_empty(),
        "each flow test is named by a switch's row or listed with why: {missing:?}"
    );
    let rowless: Vec<_> = super::faults::Fault::ALL
        .iter()
        .filter(|f| !faults::ROWS.iter().any(|(r, _)| r == *f))
        .collect();
    assert!(rowless.is_empty(), "every switch has a row: {rowless:?}");
    let planted = [String::from("a_planted_test_no_row_names")];
    assert_eq!(
        settle_faults::uncovered(&planted, faults::ROWS, &[], &[], faults::CHARACTERISATION),
        ["a_planted_test_no_row_names"],
        "the scan finds a planted test"
    );
}
