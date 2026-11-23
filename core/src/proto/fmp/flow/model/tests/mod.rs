//! Table tests of the XX judge, one per FRC-2201 rule and local rule, by
//! file: msg1 (`msg1.rs`), the initiator's msg2 (`msg2.rs`), the
//! responder's msg3 (`msg3.rs`), frames, rekeys and removal
//! (`session.rs`), and the local rules (`rules.rs`). The helpers here build
//! a judge of the smaller or the larger node and its events, and the scans
//! below hold the judge apart from the flow and the settlement core.

mod msg1;
mod msg2;
mod msg3;
mod rules;
mod session;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::history::{Addr, Binding, Claim, Epoch, Event, Hs, LinkId, Named, Node};
use super::judge::{Judge, Params, Step, Transition};
use crate::proto::rekey::code_idents;
use crate::proto::settle::tests::{core_reaches, files, model_reaches};

/// The smaller node.
const SMALL: Node = Node(1);

/// The larger node.
const LARGE: Node = Node(2);

/// The peer's first epoch.
const E1: Epoch = Epoch(1);

/// The epoch of a peer that restarted.
const E2: Epoch = Epoch(2);

/// The address `n` on a connection-oriented transport.
fn at(n: u16) -> Addr {
    Addr {
        transport: 1,
        at: n,
    }
}

/// A judge of `me` holding nothing of the other node, with the FRC's
/// rules.
fn judge(me: Node) -> Judge {
    judge_with(me, Params::default())
}

/// A judge of `me` holding nothing of the other node, with `params`.
fn judge_with(me: Node, params: Params) -> Judge {
    let peer = if me == SMALL { LARGE } else { SMALL };
    Judge::new(me, peer, params)
}

/// This node's dial `hs` on link `link` to `port`, naming the peer.
fn dial(hs: u32, link: u32, port: u16) -> Event {
    dial_naming(hs, link, port, Named::Peer)
}

/// This node's dial `hs` on link `link` to `port`, naming `named`.
fn dial_naming(hs: u32, link: u32, port: u16, named: Named) -> Event {
    Event::Dial {
        hs: Hs(hs),
        link: LinkId(link),
        to: at(port),
        binding: Binding::Connected,
        named,
    }
}

/// The peer's msg1 `hs` from `port`, on link `link` if it opens one.
fn hello(hs: u32, link: u32, port: u16) -> Event {
    Event::Msg1 {
        hs: Hs(hs),
        link: LinkId(link),
        from: at(port),
        binding: Binding::Connected,
    }
}

/// The msg2 of this node's dial `hs` at `epoch`, passing every check
/// before classification.
fn answer(hs: u32, epoch: Epoch) -> Event {
    Event::Msg2 {
        hs: Hs(hs),
        epoch,
        refused: false,
    }
}

/// The msg3 of the peer's handshake `hs` at `epoch` declaring `claim`,
/// passing every check before classification.
fn last(hs: u32, epoch: Epoch, claim: Claim) -> Event {
    Event::Msg3 {
        hs: Hs(hs),
        epoch,
        claim,
        refused: false,
    }
}

/// A frame of the peer's under the session of `hs`, from `port`.
fn frame(hs: u32, port: u16) -> Event {
    Event::Frame {
        hs: Hs(hs),
        from: at(port),
    }
}

/// Hold the peer at `epoch` on this node's dial `hs`, link `link`, to
/// `port`.
fn held_by_dial(j: &mut Judge, hs: u32, link: u32, port: u16, epoch: Epoch) {
    j.step(dial(hs, link, port));
    let s = j.step(answer(hs, epoch));
    assert_eq!(
        s.change,
        Some(Transition::Promote),
        "precondition: the dial installs"
    );
}

/// Hold the peer at `epoch` on its handshake `hs`, link `link`, from
/// `port`, answered here.
fn held_by_answer(j: &mut Judge, hs: u32, link: u32, port: u16, epoch: Epoch) {
    j.step(hello(hs, link, port));
    let s = j.step(last(hs, epoch, Claim::None));
    assert_eq!(
        s.change,
        Some(Transition::Promote),
        "precondition: the msg3 installs"
    );
}

/// What the judge holds: the current handshake and its link.
fn holds(j: &Judge) -> Option<(Hs, LinkId)> {
    j.settled().map(|(hs, link, _)| (hs, link))
}

/// A step's closes.
fn closes(s: &Step) -> &[Addr] {
    &s.closes
}

/// The judge's directory on disk, or `rel` below it.
fn dir(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/proto/fmp/flow/model")
        .join(rel)
}

/// The flow's directory on disk.
fn flow() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/proto/fmp/flow")
}

/// Every source file of the judge, its tests included.
const MODEL: &[(&str, &str)] = &[
    ("mod.rs", include_str!("../mod.rs")),
    ("history.rs", include_str!("../history.rs")),
    ("judge.rs", include_str!("../judge.rs")),
    ("tests/mod.rs", include_str!("mod.rs")),
    ("tests/msg1.rs", include_str!("msg1.rs")),
    ("tests/msg2.rs", include_str!("msg2.rs")),
    ("tests/msg3.rs", include_str!("msg3.rs")),
    ("tests/rules.rs", include_str!("rules.rs")),
    ("tests/session.rs", include_str!("session.rs")),
];

/// The modules no judge source may name by a path through `super` or
/// `settle`: the settlement core's and the flow's own.
const FORBIDDEN: &[&str] = &[
    "links", "legs", "gates", "table", "input", "output", "params", "flow", "msg1", "msg2", "msg3",
    "faults",
];

/// The one line of the flow that names the judge: its declaration.
const DECLARATION: &str = "pub mod model;";

/// The lines of judge source `source` that name the crate root, through
/// which any item of the flow or the core is reached.
fn crate_paths(source: &str) -> Vec<usize> {
    code_idents(source)
        .into_iter()
        .filter(|(_, w)| w == "crate")
        .map(|(n, _)| n)
        .collect()
}

#[test]
fn no_judge_source_reaches_into_the_flow_or_the_core_and_the_scan_finds_a_planted_path() {
    let judge = include_str!("../judge.rs");
    for plant in [
        "use super::super::msg3::rule;",
        "use crate::proto::settle::{links::Links, table};",
    ] {
        let planted = format!("{judge}\n{plant}\n");
        assert!(
            !model_reaches(&planted, FORBIDDEN).is_empty(),
            "the scan finds {plant} planted in judge.rs"
        );
    }
    for (name, source) in MODEL.iter().filter(|(n, _)| !n.starts_with("tests/")) {
        let hits = model_reaches(source, FORBIDDEN);
        assert!(
            hits.is_empty(),
            "{name} names the flow or the core through {hits:?}; the judge stands without them"
        );
    }
    let planted = format!("{judge}\nuse crate::proto::fmp::flow::Xx;\n");
    assert!(
        !crate_paths(&planted).is_empty(),
        "the scan finds a crate path planted in judge.rs"
    );
    for (name, source) in MODEL.iter().filter(|(n, _)| !n.starts_with("tests/")) {
        let hits = crate_paths(source);
        assert!(
            hits.is_empty(),
            "{name} names the crate at lines {hits:?}; the judge reads nothing outside itself"
        );
    }
}

#[test]
fn the_judges_tests_reach_only_the_scan_helpers_outside_it() {
    for (name, source) in MODEL.iter().filter(|(n, _)| n.starts_with("tests/")) {
        let hits = model_reaches(source, FORBIDDEN);
        assert!(
            hits.is_empty(),
            "{name} names the flow or the core through {hits:?}"
        );
        for line in source
            .lines()
            .filter(|l| l.trim_start().starts_with("use crate::"))
        {
            assert!(
                line.contains("rekey::code_idents") || line.contains("settle::tests::"),
                "{name} imports {line}; the judge's tests take only the scan helpers from outside"
            );
        }
    }
}

/// Each `.rs` file directly in the flow's directory, by name.
fn flow_sources() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = std::fs::read_dir(flow())
        .expect("the flow's directory reads")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .map(|p| {
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .map(String::from)
                .expect("a file name");
            (name, std::fs::read_to_string(&p).expect("the file reads"))
        })
        .collect();
    out.sort();
    out
}

#[test]
fn no_flow_source_names_the_judge_but_its_declaration_and_the_scan_finds_a_planted_path() {
    let sources = flow_sources();
    assert!(
        sources.iter().any(|(n, _)| n == "mod.rs"),
        "precondition: the flow's sources read"
    );
    let (_, root) = sources
        .iter()
        .find(|(n, _)| n == "mod.rs")
        .expect("the flow's root");
    assert!(
        root.lines().any(|l| l.trim() == DECLARATION),
        "precondition: the flow declares the judge on a line of its own"
    );
    for plant in [
        "use super::model::judge::Judge;",
        "use crate::proto::fmp::flow::{model, input};",
    ] {
        let planted = format!("{root}\n{plant}\n");
        assert!(
            !core_reaches("mod.rs", &planted, DECLARATION).is_empty(),
            "the scan finds {plant} planted in the flow's root"
        );
    }
    for (name, source) in &sources {
        let hits = core_reaches(name, source, DECLARATION);
        assert!(
            hits.is_empty(),
            "{name} names the judge at lines {hits:?}; the flow must stand without it"
        );
    }
}

#[test]
fn every_judge_source_file_is_scanned() {
    assert_eq!(
        files(&dir(""), true).len(),
        MODEL.len(),
        "every source file of the judge is in the scans' list"
    );
}
