//! The transition table stated a second time, as data, and the scan that holds
//! the rule to total matches.
//!
//! Each line of `GOLDEN` is one cell's value. A line that disagrees with `cell`
//! names the row and the case, and a missing line is its own failure. The table
//! says what the code does today, so a cell that a later change alters has its
//! line altered in that change.

use super::*;

/// One way each transition is reached: each column of the table, and each cause
/// inside it that a cell tells apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    PromoteInitiator,
    PromoteResponder,
    ReplaceRestart,
    ReplaceOwnRestart,
    MoveCrossing,
    MoveInbound,
    MoveCrossingRefused,
    MoveInboundRefused,
    Keep,
    KeepInbound,
    CutoverInitiator,
    CutoverResponder,
    Restarted,
    Roam,
    Follow,
    Switch,
    ReleaseKept,
    ReleaseUnkept,
    RemoveEnded,
    RemoveOrphaned,
    RemoveDisconnect,
    RemoveDead,
    RemoveAdmin,
}

/// Every case, in the table's column order.
const CASES: &[Case] = &[
    Case::PromoteInitiator,
    Case::PromoteResponder,
    Case::ReplaceRestart,
    Case::ReplaceOwnRestart,
    Case::MoveCrossing,
    Case::MoveInbound,
    Case::MoveCrossingRefused,
    Case::MoveInboundRefused,
    Case::Keep,
    Case::KeepInbound,
    Case::CutoverInitiator,
    Case::CutoverResponder,
    Case::Restarted,
    Case::Roam,
    Case::Follow,
    Case::Switch,
    Case::ReleaseKept,
    Case::ReleaseUnkept,
    Case::RemoveEnded,
    Case::RemoveOrphaned,
    Case::RemoveDisconnect,
    Case::RemoveDead,
    Case::RemoveAdmin,
];

/// Every cause, whether or not a transition reaches it.
const WHYS: &[Why] = &[
    Why::Restart,
    Why::Replacement,
    Why::OwnRestart,
    Why::Ended,
    Why::Orphaned,
    Why::Disconnect,
    Why::Dead,
    Why::Admin,
    Why::Closed,
];

/// A link for the transitions that name one; no cell reads it.
fn link() -> LinkId {
    LinkId::new(1)
}

/// The transition `case` stands for.
fn transition(case: Case) -> Transition {
    let replace = |initiator, why| Transition::Replace {
        link: link(),
        initiator,
        why,
    };
    let moved = |built, inbound| Transition::Move {
        dial: link(),
        own: false,
        built,
        inbound,
    };
    match case {
        Case::PromoteInitiator => Transition::Promote {
            link: link(),
            initiator: true,
        },
        Case::PromoteResponder => Transition::Promote {
            link: link(),
            initiator: false,
        },
        Case::ReplaceRestart => replace(false, Why::Restart),
        Case::ReplaceOwnRestart => replace(true, Why::OwnRestart),
        Case::MoveCrossing => moved(true, false),
        Case::MoveInbound => moved(true, true),
        Case::MoveCrossingRefused => moved(false, false),
        Case::MoveInboundRefused => moved(false, true),
        Case::Keep => Transition::Keep {
            dial: link(),
            inbound: false,
        },
        Case::KeepInbound => Transition::Keep {
            dial: link(),
            inbound: true,
        },
        Case::CutoverInitiator => Transition::Cutover {
            role: Role::Initiator,
        },
        Case::CutoverResponder => Transition::Cutover {
            role: Role::Responder,
        },
        Case::Restarted => Transition::Restarted,
        Case::Roam => Transition::Roam,
        Case::Follow => Transition::Follow,
        Case::Switch => Transition::Switch,
        Case::ReleaseKept => Transition::Release { keep: true },
        Case::ReleaseUnkept => Transition::Release { keep: false },
        Case::RemoveEnded => Transition::Remove { why: Why::Ended },
        Case::RemoveOrphaned => Transition::Remove { why: Why::Orphaned },
        Case::RemoveDisconnect => Transition::Remove {
            why: Why::Disconnect,
        },
        Case::RemoveDead => Transition::Remove { why: Why::Dead },
        Case::RemoveAdmin => Transition::Remove { why: Why::Admin },
    }
}

/// The case `t` falls under, or `None` for a cause no code reaches. A new
/// transition or cause does not compile here until it is given a case.
fn case_of(t: &Transition) -> Option<Case> {
    Some(match t {
        Transition::Promote { initiator, .. } => {
            if *initiator {
                Case::PromoteInitiator
            } else {
                Case::PromoteResponder
            }
        }
        Transition::Replace { initiator, why, .. } => match (initiator, why) {
            (false, Why::Restart) => Case::ReplaceRestart,
            (true, Why::OwnRestart) => Case::ReplaceOwnRestart,
            (true, Why::Restart)
            | (false, Why::OwnRestart)
            | (
                true | false,
                Why::Replacement
                | Why::Ended
                | Why::Orphaned
                | Why::Disconnect
                | Why::Dead
                | Why::Admin
                | Why::Closed,
            ) => return None,
        },
        Transition::Move {
            own,
            built,
            inbound,
            ..
        } => match (own, built, inbound) {
            (false, true, false) => Case::MoveCrossing,
            (false, true, true) => Case::MoveInbound,
            (false, false, false) => Case::MoveCrossingRefused,
            (false, false, true) => Case::MoveInboundRefused,
            (true, _, _) => return None,
        },
        Transition::Keep { inbound, .. } => {
            if *inbound {
                Case::KeepInbound
            } else {
                Case::Keep
            }
        }
        Transition::Cutover { role } => match role {
            Role::Initiator => Case::CutoverInitiator,
            Role::Responder => Case::CutoverResponder,
        },
        Transition::Restarted => Case::Restarted,
        Transition::Roam => Case::Roam,
        Transition::Follow => Case::Follow,
        Transition::Switch => Case::Switch,
        Transition::Release { keep } => {
            if *keep {
                Case::ReleaseKept
            } else {
                Case::ReleaseUnkept
            }
        }
        Transition::Remove { why } => match why {
            Why::Ended => Case::RemoveEnded,
            Why::Orphaned => Case::RemoveOrphaned,
            Why::Disconnect => Case::RemoveDisconnect,
            Why::Dead => Case::RemoveDead,
            Why::Admin => Case::RemoveAdmin,
            Why::Restart | Why::Replacement | Why::OwnRestart | Why::Closed => return None,
        },
    })
}

/// Every transition: each variant with each value of each field a cell can read.
fn every_transition() -> Vec<Transition> {
    let mut all = Vec::new();
    for flag in [false, true] {
        all.push(Transition::Promote {
            link: link(),
            initiator: flag,
        });
        all.push(Transition::Release { keep: flag });
        all.push(Transition::Keep {
            dial: link(),
            inbound: flag,
        });
        for built in [false, true] {
            for inbound in [false, true] {
                all.push(Transition::Move {
                    dial: link(),
                    own: flag,
                    built,
                    inbound,
                });
            }
        }
        for why in WHYS {
            all.push(Transition::Replace {
                link: link(),
                initiator: flag,
                why: *why,
            });
        }
    }
    for why in WHYS {
        all.push(Transition::Remove { why: *why });
    }
    for role in [Role::Initiator, Role::Responder] {
        all.push(Transition::Cutover { role });
    }
    all.push(Transition::Restarted);
    all.push(Transition::Roam);
    all.push(Transition::Follow);
    all.push(Transition::Switch);
    all
}

/// Each `(row, case)` pair not covered by exactly one line of `lines`, with how
/// many lines it has.
fn uncovered(lines: &[(Row, Case, Cell)]) -> Vec<(Row, Case, usize)> {
    let mut wrong = Vec::new();
    for row in Row::all() {
        for case in CASES {
            let count = lines
                .iter()
                .filter(|(r, c, _)| *r == row && c == case)
                .count();
            if count != 1 {
                wrong.push((row, *case, count));
            }
        }
    }
    wrong
}

/// Each line of `source` holding a catch-all match arm, as `line: text`, past
/// any comment: a bare `_` or a lone lower-case binding before `=>`. For a
/// file that denies wildcard arms, whose scan and planted test call it.
pub(crate) fn wildcard_arms(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let code = line.split("//").next().unwrap_or_default();
        let Some((pattern, _)) = code.split_once("=>") else {
            continue;
        };
        let last = pattern.rsplit('|').next().unwrap_or_default();
        let last = last.split(" if ").next().unwrap_or_default().trim();
        let binding = !last.is_empty()
            && last.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
            && last.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if binding {
            found.push(format!("{}: {}", index + 1, line.trim()));
        }
    }
    found
}

/// Whether `source` denies wildcard arms at its head, before any item.
pub(crate) fn denies_wildcards(source: &str) -> bool {
    source
        .lines()
        .find(|line| !line.is_empty() && !line.starts_with("//!"))
        .is_some_and(|line| line == "#![deny(clippy::wildcard_enum_match_arm)]")
}

#[test]
fn every_cell_of_the_table_is_the_rule_the_golden_table_states() {
    let wrong: Vec<String> = GOLDEN
        .iter()
        .filter_map(|(row, case, want)| {
            let got = cell(*row, &transition(*case));
            (got != *want).then(|| format!("{row:?} at {case:?}: {got:?}, golden {want:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "defect: the rule and the golden table disagree:\n{}",
        wrong.join("\n")
    );
    assert!(
        GOLDEN
            .iter()
            .any(|(_, _, want)| *want != Cell::Keep && *want != Cell::Data(DataCell::Keep)),
        "precondition: the golden table has a cell other than keep"
    );
}

#[test]
fn the_golden_table_has_a_line_for_every_row_and_transition() {
    let wrong = uncovered(GOLDEN);
    assert!(
        wrong.is_empty(),
        "defect: not one line per row and case: {wrong:?}"
    );
    assert_eq!(
        GOLDEN.len(),
        Row::all().len() * CASES.len(),
        "defect: a line for no row or case"
    );

    // Every case is reached from the transitions, each transition's case maps
    // back to one that stands for it, and what remains has no site.
    let cases: Vec<Case> = every_transition().iter().filter_map(case_of).collect();
    for case in CASES {
        assert_eq!(
            cases.iter().filter(|c| *c == case).count(),
            1,
            "defect: {case:?} is not one transition's case"
        );
        assert_eq!(
            case_of(&transition(*case)),
            Some(*case),
            "defect: {case:?} stands for a transition of another case"
        );
    }
    assert_eq!(cases.len(), CASES.len(), "defect: a case is not listed");

    // The check above is able to fail: a table short of a line is not covered.
    assert_eq!(
        uncovered(&GOLDEN[1..]),
        [(GOLDEN[0].0, GOLDEN[0].1, 0)],
        "defect: the check does not see a missing line"
    );
}

#[test]
fn a_cause_no_code_reaches_has_no_cell_outside_the_record() {
    for t in every_transition() {
        if case_of(&t).is_some() {
            continue;
        }
        for row in Row::all() {
            let got = cell(row, &t);
            let want = if let Row::Data(data) = row {
                Cell::Data(data_cell(data, &t))
            } else {
                Cell::NoSite
            };
            assert_eq!(got, want, "defect: {row:?} at {t:?}");
        }
    }
    assert_eq!(
        cell(Row::Session, &Transition::Remove { why: Why::Closed }),
        Cell::NoSite,
        "precondition: closing the core has no site at a removal"
    );
}

#[test]
fn a_row_of_the_record_reads_the_same_through_either_function() {
    for t in every_transition() {
        for row in DataRow::ALL {
            assert_eq!(
                cell(Row::Data(*row), &t),
                Cell::Data(data_cell(*row, &t)),
                "defect: {row:?} at {t:?}"
            );
        }
    }
}

#[test]
fn every_row_names_the_owner_that_holds_it() {
    for row in Row::all() {
        let lines = OWNERS.iter().filter(|(r, _)| *r == row).count();
        assert_eq!(lines, 1, "defect: {row:?} has {lines} owner lines");
    }
    for (row, want) in OWNERS {
        assert_eq!(owner(*row), *want, "defect: the owner of {row:?}");
    }
    for facet in Facet::ALL {
        assert!(
            OWNERS.iter().any(|(_, o)| *o == Owner::Facet(*facet)),
            "defect: no row is held by {facet:?}"
        );
    }
}

#[test]
fn the_table_denies_wildcard_arms_and_the_scan_finds_a_planted_one() {
    let source = include_str!("../table.rs");
    assert!(
        denies_wildcards(source),
        "defect: table.rs does not deny wildcard arms at its head"
    );
    assert_eq!(
        wildcard_arms(source),
        Vec::<String>::new(),
        "defect: a catch-all arm in table.rs"
    );

    let planted = "\
        // _ => a comment,\n\
        Row::Data(_) => Cell::Keep,\n\
        Why::Dead | Why::Admin => Cell::Keep,\n\
        T::Move { built: true, .. } => Cell::Renewed,\n\
        Row::Mmp if *built => DataCell::Reset,\n\
        _ => Cell::Keep,\n\
        Why::Dead | _ => Cell::Keep,\n\
        other => Cell::Keep,\n\
        _ if *built => Cell::Keep,\n";
    assert_eq!(
        wildcard_arms(planted),
        [
            "6: _ => Cell::Keep,",
            "7: Why::Dead | _ => Cell::Keep,",
            "8: other => Cell::Keep,",
            "9: _ if *built => Cell::Keep,",
        ],
        "defect: the scan misses a planted arm or names a total one"
    );
    assert!(
        !denies_wildcards("//! A module.\n\nuse crate::x;\n"),
        "defect: the head scan passes a file with no deny"
    );
}

/// Who holds each row.
const OWNERS: &[(Row, Owner)] = &[
    (Row::Data(DataRow::Mmp), Owner::Data),
    (Row::Data(DataRow::PeerFilter), Owner::Data),
    (Row::Data(DataRow::FilterPending), Owner::Data),
    (Row::Data(DataRow::TreePosition), Owner::Data),
    (Row::Data(DataRow::TreePending), Owner::Data),
    (Row::Data(DataRow::TreeStamp), Owner::Data),
    (Row::Data(DataRow::TreeInterval), Owner::Data),
    (Row::Data(DataRow::Heard), Owner::Data),
    (Row::Data(DataRow::StoredSetup), Owner::Data),
    (Row::Data(DataRow::Stats), Owner::Data),
    (Row::Data(DataRow::Profile), Owner::Data),
    (Row::Data(DataRow::PrevFrames), Owner::Data),
    (Row::Data(DataRow::HsLines), Owner::Data),
    (Row::Data(DataRow::ReplayBase), Owner::Data),
    (Row::Data(DataRow::ReplayTotal), Owner::Data),
    (Row::Link, Owner::Table),
    (Row::Index, Owner::Table),
    (Row::Paths, Owner::Bundle),
    (Row::Capability, Owner::Bundle),
    (Row::Pin, Owner::Bundle),
    (Row::PathFailures, Owner::Bundle),
    (Row::ConnectedUdp, Owner::Bundle),
    (Row::RekeyMachine, Owner::Rekey),
    (Row::SetupRecord, Owner::Rekey),
    (Row::Identity, Owner::Identity),
    (Row::ControlMachine, Owner::Table),
    (Row::Connection, Owner::Facet(Facet::Connection)),
    (Row::BleMark, Owner::Facet(Facet::Verified)),
    (Row::Bootstrap, Owner::Facet(Facet::Bootstrap)),
    (Row::Dials, Owner::Table),
    (Row::PathMtu, Owner::Facet(Facet::PathMtu)),
    (Row::FilterSend, Owner::Facet(Facet::Bloom)),
    (Row::Tree, Owner::Facet(Facet::Tree)),
    (Row::Session, Owner::Facet(Facet::Session)),
    (Row::Dampener, Owner::Facet(Facet::Dampener)),
    (Row::Silent, Owner::Facet(Facet::Silent)),
    (Row::Reconnect, Owner::Facet(Facet::Reconnect)),
    (Row::IdentityCache, Owner::Facet(Facet::Identity)),
    (Row::LookupBackoff, Owner::Facet(Facet::LookupBackoff)),
    (Row::PathConnects, Owner::Facet(Facet::PathConnects)),
    (Row::PathCloses, Owner::Facet(Facet::PathCloses)),
    (Row::PathListings, Owner::Facet(Facet::PathListings)),
    (Row::PathCarrier, Owner::Facet(Facet::PathCarrier)),
];

/// One line per row and case: the cell's value alone. A line stays on one line,
/// so that a diff of a cell is one line.
#[rustfmt::skip]
const GOLDEN: &[(Row, Case, Cell)] = &[
    (Row::Data(DataRow::Mmp), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Mmp), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Mmp), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Mmp), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Mmp), Case::MoveCrossing, Cell::Data(DataCell::Reset)),
    (Row::Data(DataRow::Mmp), Case::MoveInbound, Cell::Data(DataCell::Reset)),
    (Row::Data(DataRow::Mmp), Case::MoveCrossingRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Mmp), Case::MoveInboundRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Mmp), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Mmp), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Mmp), Case::CutoverInitiator, Cell::Data(DataCell::Reset)),
    (Row::Data(DataRow::Mmp), Case::CutoverResponder, Cell::Data(DataCell::Reset)),
    (Row::Data(DataRow::Mmp), Case::Restarted, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Mmp), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Mmp), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Mmp), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Mmp), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Mmp), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Mmp), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Mmp), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Mmp), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Mmp), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Mmp), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::PeerFilter), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::PeerFilter), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::PeerFilter), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::PeerFilter), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::PeerFilter), Case::MoveCrossing, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PeerFilter), Case::MoveInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PeerFilter), Case::MoveCrossingRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PeerFilter), Case::MoveInboundRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PeerFilter), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PeerFilter), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PeerFilter), Case::CutoverInitiator, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PeerFilter), Case::CutoverResponder, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PeerFilter), Case::Restarted, Cell::Data(DataCell::Clear)),
    (Row::Data(DataRow::PeerFilter), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PeerFilter), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PeerFilter), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PeerFilter), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PeerFilter), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PeerFilter), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::PeerFilter), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::PeerFilter), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::PeerFilter), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::PeerFilter), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::FilterPending), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::FilterPending), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::FilterPending), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::FilterPending), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::FilterPending), Case::MoveCrossing, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::FilterPending), Case::MoveInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::FilterPending), Case::MoveCrossingRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::FilterPending), Case::MoveInboundRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::FilterPending), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::FilterPending), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::FilterPending), Case::CutoverInitiator, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::FilterPending), Case::CutoverResponder, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::FilterPending), Case::Restarted, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::FilterPending), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::FilterPending), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::FilterPending), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::FilterPending), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::FilterPending), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::FilterPending), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::FilterPending), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::FilterPending), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::FilterPending), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::FilterPending), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreePosition), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreePosition), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreePosition), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreePosition), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreePosition), Case::MoveCrossing, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePosition), Case::MoveInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePosition), Case::MoveCrossingRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePosition), Case::MoveInboundRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePosition), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePosition), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePosition), Case::CutoverInitiator, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePosition), Case::CutoverResponder, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePosition), Case::Restarted, Cell::Data(DataCell::Clear)),
    (Row::Data(DataRow::TreePosition), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePosition), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePosition), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePosition), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePosition), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePosition), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreePosition), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreePosition), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreePosition), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreePosition), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreePending), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreePending), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreePending), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreePending), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreePending), Case::MoveCrossing, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePending), Case::MoveInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePending), Case::MoveCrossingRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePending), Case::MoveInboundRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePending), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePending), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePending), Case::CutoverInitiator, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePending), Case::CutoverResponder, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePending), Case::Restarted, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePending), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePending), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePending), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePending), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePending), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreePending), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreePending), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreePending), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreePending), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreePending), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreeStamp), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreeStamp), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreeStamp), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreeStamp), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreeStamp), Case::MoveCrossing, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeStamp), Case::MoveInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeStamp), Case::MoveCrossingRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeStamp), Case::MoveInboundRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeStamp), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeStamp), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeStamp), Case::CutoverInitiator, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeStamp), Case::CutoverResponder, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeStamp), Case::Restarted, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeStamp), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeStamp), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeStamp), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeStamp), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeStamp), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeStamp), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreeStamp), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreeStamp), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreeStamp), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreeStamp), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreeInterval), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreeInterval), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreeInterval), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreeInterval), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::TreeInterval), Case::MoveCrossing, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeInterval), Case::MoveInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeInterval), Case::MoveCrossingRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeInterval), Case::MoveInboundRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeInterval), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeInterval), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeInterval), Case::CutoverInitiator, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeInterval), Case::CutoverResponder, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeInterval), Case::Restarted, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeInterval), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeInterval), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeInterval), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeInterval), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeInterval), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::TreeInterval), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreeInterval), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreeInterval), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreeInterval), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::TreeInterval), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Heard), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Heard), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Heard), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Heard), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Heard), Case::MoveCrossing, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Heard), Case::MoveInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Heard), Case::MoveCrossingRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Heard), Case::MoveInboundRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Heard), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Heard), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Heard), Case::CutoverInitiator, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Heard), Case::CutoverResponder, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Heard), Case::Restarted, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Heard), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Heard), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Heard), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Heard), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Heard), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Heard), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Heard), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Heard), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Heard), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Heard), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::StoredSetup), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::StoredSetup), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::StoredSetup), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::StoredSetup), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::StoredSetup), Case::MoveCrossing, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::StoredSetup), Case::MoveInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::StoredSetup), Case::MoveCrossingRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::StoredSetup), Case::MoveInboundRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::StoredSetup), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::StoredSetup), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::StoredSetup), Case::CutoverInitiator, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::StoredSetup), Case::CutoverResponder, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::StoredSetup), Case::Restarted, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::StoredSetup), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::StoredSetup), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::StoredSetup), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::StoredSetup), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::StoredSetup), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::StoredSetup), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::StoredSetup), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::StoredSetup), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::StoredSetup), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::StoredSetup), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Stats), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Stats), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Stats), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Stats), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Stats), Case::MoveCrossing, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Stats), Case::MoveInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Stats), Case::MoveCrossingRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Stats), Case::MoveInboundRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Stats), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Stats), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Stats), Case::CutoverInitiator, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Stats), Case::CutoverResponder, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Stats), Case::Restarted, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Stats), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Stats), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Stats), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Stats), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Stats), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Stats), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Stats), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Stats), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Stats), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Stats), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Profile), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Profile), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Profile), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Profile), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::Profile), Case::MoveCrossing, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Profile), Case::MoveInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Profile), Case::MoveCrossingRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Profile), Case::MoveInboundRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Profile), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Profile), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Profile), Case::CutoverInitiator, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Profile), Case::CutoverResponder, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Profile), Case::Restarted, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Profile), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Profile), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Profile), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Profile), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Profile), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::Profile), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Profile), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Profile), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Profile), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::Profile), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::PrevFrames), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::PrevFrames), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::PrevFrames), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::PrevFrames), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::PrevFrames), Case::MoveCrossing, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PrevFrames), Case::MoveInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PrevFrames), Case::MoveCrossingRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PrevFrames), Case::MoveInboundRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PrevFrames), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PrevFrames), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PrevFrames), Case::CutoverInitiator, Cell::Data(DataCell::Reset)),
    (Row::Data(DataRow::PrevFrames), Case::CutoverResponder, Cell::Data(DataCell::Reset)),
    (Row::Data(DataRow::PrevFrames), Case::Restarted, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PrevFrames), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PrevFrames), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PrevFrames), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PrevFrames), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PrevFrames), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::PrevFrames), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::PrevFrames), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::PrevFrames), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::PrevFrames), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::PrevFrames), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::HsLines), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::HsLines), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::HsLines), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::HsLines), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::HsLines), Case::MoveCrossing, Cell::Data(DataCell::Roll)),
    (Row::Data(DataRow::HsLines), Case::MoveInbound, Cell::Data(DataCell::Roll)),
    (Row::Data(DataRow::HsLines), Case::MoveCrossingRefused, Cell::Data(DataCell::Roll)),
    (Row::Data(DataRow::HsLines), Case::MoveInboundRefused, Cell::Data(DataCell::Roll)),
    (Row::Data(DataRow::HsLines), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::HsLines), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::HsLines), Case::CutoverInitiator, Cell::Data(DataCell::Roll)),
    (Row::Data(DataRow::HsLines), Case::CutoverResponder, Cell::Data(DataCell::Roll)),
    (Row::Data(DataRow::HsLines), Case::Restarted, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::HsLines), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::HsLines), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::HsLines), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::HsLines), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::HsLines), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::HsLines), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::HsLines), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::HsLines), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::HsLines), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::HsLines), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::ReplayBase), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::ReplayBase), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::ReplayBase), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::ReplayBase), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::ReplayBase), Case::MoveCrossing, Cell::Data(DataCell::Base)),
    (Row::Data(DataRow::ReplayBase), Case::MoveInbound, Cell::Data(DataCell::Base)),
    (Row::Data(DataRow::ReplayBase), Case::MoveCrossingRefused, Cell::Data(DataCell::Base)),
    (Row::Data(DataRow::ReplayBase), Case::MoveInboundRefused, Cell::Data(DataCell::Base)),
    (Row::Data(DataRow::ReplayBase), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayBase), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayBase), Case::CutoverInitiator, Cell::Data(DataCell::Base)),
    (Row::Data(DataRow::ReplayBase), Case::CutoverResponder, Cell::Data(DataCell::Base)),
    (Row::Data(DataRow::ReplayBase), Case::Restarted, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayBase), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayBase), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayBase), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayBase), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayBase), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayBase), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::ReplayBase), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::ReplayBase), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::ReplayBase), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::ReplayBase), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::ReplayTotal), Case::PromoteInitiator, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::ReplayTotal), Case::PromoteResponder, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::ReplayTotal), Case::ReplaceRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::ReplayTotal), Case::ReplaceOwnRestart, Cell::Data(DataCell::New)),
    (Row::Data(DataRow::ReplayTotal), Case::MoveCrossing, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayTotal), Case::MoveInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayTotal), Case::MoveCrossingRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayTotal), Case::MoveInboundRefused, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayTotal), Case::Keep, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayTotal), Case::KeepInbound, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayTotal), Case::CutoverInitiator, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayTotal), Case::CutoverResponder, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayTotal), Case::Restarted, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayTotal), Case::Roam, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayTotal), Case::Follow, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayTotal), Case::Switch, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayTotal), Case::ReleaseKept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayTotal), Case::ReleaseUnkept, Cell::Data(DataCell::Keep)),
    (Row::Data(DataRow::ReplayTotal), Case::RemoveEnded, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::ReplayTotal), Case::RemoveOrphaned, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::ReplayTotal), Case::RemoveDisconnect, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::ReplayTotal), Case::RemoveDead, Cell::Data(DataCell::Drop)),
    (Row::Data(DataRow::ReplayTotal), Case::RemoveAdmin, Cell::Data(DataCell::Drop)),
    (Row::Link, Case::PromoteInitiator, Cell::HandshakeLink),
    (Row::Link, Case::PromoteResponder, Cell::HandshakeLink),
    (Row::Link, Case::ReplaceRestart, Cell::OldClosedNewAdopted),
    (Row::Link, Case::ReplaceOwnRestart, Cell::OldClosedNewAdopted),
    (Row::Link, Case::MoveCrossing, Cell::DialClosed),
    (Row::Link, Case::MoveInbound, Cell::DialClosed),
    (Row::Link, Case::MoveCrossingRefused, Cell::DialClosed),
    (Row::Link, Case::MoveInboundRefused, Cell::DialClosed),
    (Row::Link, Case::Keep, Cell::DialClosed),
    (Row::Link, Case::KeepInbound, Cell::DialClosed),
    (Row::Link, Case::CutoverInitiator, Cell::Keep),
    (Row::Link, Case::CutoverResponder, Cell::Keep),
    (Row::Link, Case::Restarted, Cell::Keep),
    (Row::Link, Case::Roam, Cell::Keep),
    (Row::Link, Case::Follow, Cell::Keep),
    (Row::Link, Case::Switch, Cell::Keep),
    (Row::Link, Case::ReleaseKept, Cell::Keep),
    (Row::Link, Case::ReleaseUnkept, Cell::Keep),
    (Row::Link, Case::RemoveEnded, Cell::Closed),
    (Row::Link, Case::RemoveOrphaned, Cell::Closed),
    (Row::Link, Case::RemoveDisconnect, Cell::Closed),
    (Row::Link, Case::RemoveDead, Cell::Closed),
    (Row::Link, Case::RemoveAdmin, Cell::Closed),
    (Row::Index, Case::PromoteInitiator, Cell::FromDial),
    (Row::Index, Case::PromoteResponder, Cell::FromLeg),
    (Row::Index, Case::ReplaceRestart, Cell::OldDroppedFromLeg),
    (Row::Index, Case::ReplaceOwnRestart, Cell::OldDroppedFromDial),
    (Row::Index, Case::MoveCrossing, Cell::ReleasedUnclaimedDialDropped),
    (Row::Index, Case::MoveInbound, Cell::ReleasedUnclaimedLegDropped),
    (Row::Index, Case::MoveCrossingRefused, Cell::DialDropped),
    (Row::Index, Case::MoveInboundRefused, Cell::LegDropped),
    (Row::Index, Case::Keep, Cell::DialDropped),
    (Row::Index, Case::KeepInbound, Cell::LegDropped),
    (Row::Index, Case::CutoverInitiator, Cell::Keep),
    (Row::Index, Case::CutoverResponder, Cell::Keep),
    (Row::Index, Case::Restarted, Cell::Keep),
    (Row::Index, Case::Roam, Cell::Keep),
    (Row::Index, Case::Follow, Cell::Followed),
    (Row::Index, Case::Switch, Cell::Claimed),
    (Row::Index, Case::ReleaseKept, Cell::UnclaimedOffRecord),
    (Row::Index, Case::ReleaseUnkept, Cell::UnclaimedOffRecord),
    (Row::Index, Case::RemoveEnded, Cell::Dropped),
    (Row::Index, Case::RemoveOrphaned, Cell::Dropped),
    (Row::Index, Case::RemoveDisconnect, Cell::Dropped),
    (Row::Index, Case::RemoveDead, Cell::Dropped),
    (Row::Index, Case::RemoveAdmin, Cell::Dropped),
    (Row::Paths, Case::PromoteInitiator, Cell::NewAtSource),
    (Row::Paths, Case::PromoteResponder, Cell::NewAtSource),
    (Row::Paths, Case::ReplaceRestart, Cell::OldClosedNew),
    (Row::Paths, Case::ReplaceOwnRestart, Cell::OldClosedNew),
    (Row::Paths, Case::MoveCrossing, Cell::Renewed),
    (Row::Paths, Case::MoveInbound, Cell::Renewed),
    (Row::Paths, Case::MoveCrossingRefused, Cell::Keep),
    (Row::Paths, Case::MoveInboundRefused, Cell::Keep),
    (Row::Paths, Case::Keep, Cell::Keep),
    (Row::Paths, Case::KeepInbound, Cell::Keep),
    (Row::Paths, Case::CutoverInitiator, Cell::Keep),
    (Row::Paths, Case::CutoverResponder, Cell::Keep),
    (Row::Paths, Case::Restarted, Cell::Keep),
    (Row::Paths, Case::Roam, Cell::OnePathReaddressed),
    (Row::Paths, Case::Follow, Cell::PathReaddressed),
    (Row::Paths, Case::Switch, Cell::ActiveChanged),
    (Row::Paths, Case::ReleaseKept, Cell::PathGone),
    (Row::Paths, Case::ReleaseUnkept, Cell::PathGone),
    (Row::Paths, Case::RemoveEnded, Cell::Closed),
    (Row::Paths, Case::RemoveOrphaned, Cell::Closed),
    (Row::Paths, Case::RemoveDisconnect, Cell::Closed),
    (Row::Paths, Case::RemoveDead, Cell::Closed),
    (Row::Paths, Case::RemoveAdmin, Cell::Closed),
    (Row::Capability, Case::PromoteInitiator, Cell::New),
    (Row::Capability, Case::PromoteResponder, Cell::New),
    (Row::Capability, Case::ReplaceRestart, Cell::New),
    (Row::Capability, Case::ReplaceOwnRestart, Cell::New),
    (Row::Capability, Case::MoveCrossing, Cell::ResetByRenew),
    (Row::Capability, Case::MoveInbound, Cell::ResetByRenew),
    (Row::Capability, Case::MoveCrossingRefused, Cell::Keep),
    (Row::Capability, Case::MoveInboundRefused, Cell::Keep),
    (Row::Capability, Case::Keep, Cell::Keep),
    (Row::Capability, Case::KeepInbound, Cell::Keep),
    (Row::Capability, Case::CutoverInitiator, Cell::Keep),
    (Row::Capability, Case::CutoverResponder, Cell::Keep),
    (Row::Capability, Case::Restarted, Cell::Keep),
    (Row::Capability, Case::Roam, Cell::Keep),
    (Row::Capability, Case::Follow, Cell::Keep),
    (Row::Capability, Case::Switch, Cell::Keep),
    (Row::Capability, Case::ReleaseKept, Cell::HeldBackOrForgotten),
    (Row::Capability, Case::ReleaseUnkept, Cell::HeldBackOrForgotten),
    (Row::Capability, Case::RemoveEnded, Cell::Gone),
    (Row::Capability, Case::RemoveOrphaned, Cell::Gone),
    (Row::Capability, Case::RemoveDisconnect, Cell::Gone),
    (Row::Capability, Case::RemoveDead, Cell::Gone),
    (Row::Capability, Case::RemoveAdmin, Cell::Gone),
    (Row::Pin, Case::PromoteInitiator, Cell::Empty),
    (Row::Pin, Case::PromoteResponder, Cell::Empty),
    (Row::Pin, Case::ReplaceRestart, Cell::Empty),
    (Row::Pin, Case::ReplaceOwnRestart, Cell::Empty),
    (Row::Pin, Case::MoveCrossing, Cell::Keep),
    (Row::Pin, Case::MoveInbound, Cell::Keep),
    (Row::Pin, Case::MoveCrossingRefused, Cell::Keep),
    (Row::Pin, Case::MoveInboundRefused, Cell::Keep),
    (Row::Pin, Case::Keep, Cell::Keep),
    (Row::Pin, Case::KeepInbound, Cell::Keep),
    (Row::Pin, Case::CutoverInitiator, Cell::Keep),
    (Row::Pin, Case::CutoverResponder, Cell::Keep),
    (Row::Pin, Case::Restarted, Cell::PinEnds),
    (Row::Pin, Case::Roam, Cell::Keep),
    (Row::Pin, Case::Follow, Cell::Keep),
    (Row::Pin, Case::Switch, Cell::HoldStarts),
    (Row::Pin, Case::ReleaseKept, Cell::Keep),
    (Row::Pin, Case::ReleaseUnkept, Cell::Keep),
    (Row::Pin, Case::RemoveEnded, Cell::Gone),
    (Row::Pin, Case::RemoveOrphaned, Cell::Gone),
    (Row::Pin, Case::RemoveDisconnect, Cell::Gone),
    (Row::Pin, Case::RemoveDead, Cell::Gone),
    (Row::Pin, Case::RemoveAdmin, Cell::Gone),
    (Row::PathFailures, Case::PromoteInitiator, Cell::Zero),
    (Row::PathFailures, Case::PromoteResponder, Cell::Zero),
    (Row::PathFailures, Case::ReplaceRestart, Cell::Zero),
    (Row::PathFailures, Case::ReplaceOwnRestart, Cell::Zero),
    (Row::PathFailures, Case::MoveCrossing, Cell::KeptIfHeld),
    (Row::PathFailures, Case::MoveInbound, Cell::KeptIfHeld),
    (Row::PathFailures, Case::MoveCrossingRefused, Cell::Keep),
    (Row::PathFailures, Case::MoveInboundRefused, Cell::Keep),
    (Row::PathFailures, Case::Keep, Cell::Keep),
    (Row::PathFailures, Case::KeepInbound, Cell::Keep),
    (Row::PathFailures, Case::CutoverInitiator, Cell::Keep),
    (Row::PathFailures, Case::CutoverResponder, Cell::Keep),
    (Row::PathFailures, Case::Restarted, Cell::Keep),
    (Row::PathFailures, Case::Roam, Cell::Keep),
    (Row::PathFailures, Case::Follow, Cell::Keep),
    (Row::PathFailures, Case::Switch, Cell::Keep),
    (Row::PathFailures, Case::ReleaseKept, Cell::GoneWithPath),
    (Row::PathFailures, Case::ReleaseUnkept, Cell::GoneWithPath),
    (Row::PathFailures, Case::RemoveEnded, Cell::Gone),
    (Row::PathFailures, Case::RemoveOrphaned, Cell::Gone),
    (Row::PathFailures, Case::RemoveDisconnect, Cell::Gone),
    (Row::PathFailures, Case::RemoveDead, Cell::Gone),
    (Row::PathFailures, Case::RemoveAdmin, Cell::Gone),
    (Row::ConnectedUdp, Case::PromoteInitiator, Cell::Empty),
    (Row::ConnectedUdp, Case::PromoteResponder, Cell::Empty),
    (Row::ConnectedUdp, Case::ReplaceRestart, Cell::Dropped),
    (Row::ConnectedUdp, Case::ReplaceOwnRestart, Cell::Dropped),
    (Row::ConnectedUdp, Case::MoveCrossing, Cell::ReleasedClearedActiveIfChanged),
    (Row::ConnectedUdp, Case::MoveInbound, Cell::ReleasedClearedActiveIfChanged),
    (Row::ConnectedUdp, Case::MoveCrossingRefused, Cell::Keep),
    (Row::ConnectedUdp, Case::MoveInboundRefused, Cell::Keep),
    (Row::ConnectedUdp, Case::Keep, Cell::Keep),
    (Row::ConnectedUdp, Case::KeepInbound, Cell::Keep),
    (Row::ConnectedUdp, Case::CutoverInitiator, Cell::Keep),
    (Row::ConnectedUdp, Case::CutoverResponder, Cell::Keep),
    (Row::ConnectedUdp, Case::Restarted, Cell::Keep),
    (Row::ConnectedUdp, Case::Roam, Cell::ClearedIfChanged),
    (Row::ConnectedUdp, Case::Follow, Cell::MovedCleared),
    (Row::ConnectedUdp, Case::Switch, Cell::OldActiveCleared),
    (Row::ConnectedUdp, Case::ReleaseKept, Cell::PathCleared),
    (Row::ConnectedUdp, Case::ReleaseUnkept, Cell::PathCleared),
    (Row::ConnectedUdp, Case::RemoveEnded, Cell::Dropped),
    (Row::ConnectedUdp, Case::RemoveOrphaned, Cell::Dropped),
    (Row::ConnectedUdp, Case::RemoveDisconnect, Cell::Dropped),
    (Row::ConnectedUdp, Case::RemoveDead, Cell::Dropped),
    (Row::ConnectedUdp, Case::RemoveAdmin, Cell::Dropped),
    (Row::RekeyMachine, Case::PromoteInitiator, Cell::NewEmptyRecord),
    (Row::RekeyMachine, Case::PromoteResponder, Cell::NewEmptyRecord),
    (Row::RekeyMachine, Case::ReplaceRestart, Cell::OldClosedNewEmptyRecord),
    (Row::RekeyMachine, Case::ReplaceOwnRestart, Cell::OldClosedNewEmptyRecord),
    (Row::RekeyMachine, Case::MoveCrossing, Cell::ClosedRebuilt),
    (Row::RekeyMachine, Case::MoveInbound, Cell::ClosedRebuilt),
    (Row::RekeyMachine, Case::MoveCrossingRefused, Cell::LeaseReleased),
    (Row::RekeyMachine, Case::MoveInboundRefused, Cell::LeaseReleased),
    (Row::RekeyMachine, Case::Keep, Cell::DialLeaseFreed),
    (Row::RekeyMachine, Case::KeepInbound, Cell::LegLeaseFreed),
    (Row::RekeyMachine, Case::CutoverInitiator, Cell::Stepped),
    (Row::RekeyMachine, Case::CutoverResponder, Cell::Stepped),
    (Row::RekeyMachine, Case::Restarted, Cell::Stepped),
    (Row::RekeyMachine, Case::Roam, Cell::Keep),
    (Row::RekeyMachine, Case::Follow, Cell::Keep),
    (Row::RekeyMachine, Case::Switch, Cell::KeptBindingsFollow),
    (Row::RekeyMachine, Case::ReleaseKept, Cell::Keep),
    (Row::RekeyMachine, Case::ReleaseUnkept, Cell::Keep),
    (Row::RekeyMachine, Case::RemoveEnded, Cell::Closed),
    (Row::RekeyMachine, Case::RemoveOrphaned, Cell::Closed),
    (Row::RekeyMachine, Case::RemoveDisconnect, Cell::Closed),
    (Row::RekeyMachine, Case::RemoveDead, Cell::Closed),
    (Row::RekeyMachine, Case::RemoveAdmin, Cell::Closed),
    (Row::SetupRecord, Case::PromoteInitiator, Cell::Empty),
    (Row::SetupRecord, Case::PromoteResponder, Cell::Empty),
    (Row::SetupRecord, Case::ReplaceRestart, Cell::Empty),
    (Row::SetupRecord, Case::ReplaceOwnRestart, Cell::Empty),
    (Row::SetupRecord, Case::MoveCrossing, Cell::Carried),
    (Row::SetupRecord, Case::MoveInbound, Cell::Carried),
    (Row::SetupRecord, Case::MoveCrossingRefused, Cell::Keep),
    (Row::SetupRecord, Case::MoveInboundRefused, Cell::Keep),
    (Row::SetupRecord, Case::Keep, Cell::Keep),
    (Row::SetupRecord, Case::KeepInbound, Cell::Keep),
    (Row::SetupRecord, Case::CutoverInitiator, Cell::Keep),
    (Row::SetupRecord, Case::CutoverResponder, Cell::Keep),
    (Row::SetupRecord, Case::Restarted, Cell::Keep),
    (Row::SetupRecord, Case::Roam, Cell::Keep),
    (Row::SetupRecord, Case::Follow, Cell::Keep),
    (Row::SetupRecord, Case::Switch, Cell::Keep),
    (Row::SetupRecord, Case::ReleaseKept, Cell::Keep),
    (Row::SetupRecord, Case::ReleaseUnkept, Cell::Keep),
    (Row::SetupRecord, Case::RemoveEnded, Cell::Gone),
    (Row::SetupRecord, Case::RemoveOrphaned, Cell::Gone),
    (Row::SetupRecord, Case::RemoveDisconnect, Cell::Gone),
    (Row::SetupRecord, Case::RemoveDead, Cell::Gone),
    (Row::SetupRecord, Case::RemoveAdmin, Cell::Gone),
    (Row::Identity, Case::PromoteInitiator, Cell::New),
    (Row::Identity, Case::PromoteResponder, Cell::New),
    (Row::Identity, Case::ReplaceRestart, Cell::New),
    (Row::Identity, Case::ReplaceOwnRestart, Cell::New),
    (Row::Identity, Case::MoveCrossing, Cell::Keep),
    (Row::Identity, Case::MoveInbound, Cell::Keep),
    (Row::Identity, Case::MoveCrossingRefused, Cell::Keep),
    (Row::Identity, Case::MoveInboundRefused, Cell::Keep),
    (Row::Identity, Case::Keep, Cell::Keep),
    (Row::Identity, Case::KeepInbound, Cell::Keep),
    (Row::Identity, Case::CutoverInitiator, Cell::Keep),
    (Row::Identity, Case::CutoverResponder, Cell::Keep),
    (Row::Identity, Case::Restarted, Cell::Keep),
    (Row::Identity, Case::Roam, Cell::Keep),
    (Row::Identity, Case::Follow, Cell::Keep),
    (Row::Identity, Case::Switch, Cell::Keep),
    (Row::Identity, Case::ReleaseKept, Cell::Keep),
    (Row::Identity, Case::ReleaseUnkept, Cell::Keep),
    (Row::Identity, Case::RemoveEnded, Cell::Dropped),
    (Row::Identity, Case::RemoveOrphaned, Cell::Dropped),
    (Row::Identity, Case::RemoveDisconnect, Cell::Dropped),
    (Row::Identity, Case::RemoveDead, Cell::Dropped),
    (Row::Identity, Case::RemoveAdmin, Cell::Dropped),
    (Row::ControlMachine, Case::PromoteInitiator, Cell::LegSurvives),
    (Row::ControlMachine, Case::PromoteResponder, Cell::LegSurvives),
    (Row::ControlMachine, Case::ReplaceRestart, Cell::OldRemovedLegSurvives),
    (Row::ControlMachine, Case::ReplaceOwnRestart, Cell::OldRemovedLegSurvives),
    (Row::ControlMachine, Case::MoveCrossing, Cell::DialRemovedPeerStepped),
    (Row::ControlMachine, Case::MoveInbound, Cell::LegRemoved),
    (Row::ControlMachine, Case::MoveCrossingRefused, Cell::DialRemovedPeerStepped),
    (Row::ControlMachine, Case::MoveInboundRefused, Cell::LegRemoved),
    (Row::ControlMachine, Case::Keep, Cell::DialRemovedPeerStepped),
    (Row::ControlMachine, Case::KeepInbound, Cell::LegRemoved),
    (Row::ControlMachine, Case::CutoverInitiator, Cell::Keep),
    (Row::ControlMachine, Case::CutoverResponder, Cell::Keep),
    (Row::ControlMachine, Case::Restarted, Cell::Keep),
    (Row::ControlMachine, Case::Roam, Cell::Keep),
    (Row::ControlMachine, Case::Follow, Cell::Keep),
    (Row::ControlMachine, Case::Switch, Cell::Keep),
    (Row::ControlMachine, Case::ReleaseKept, Cell::Keep),
    (Row::ControlMachine, Case::ReleaseUnkept, Cell::Keep),
    (Row::ControlMachine, Case::RemoveEnded, Cell::Removed),
    (Row::ControlMachine, Case::RemoveOrphaned, Cell::Removed),
    (Row::ControlMachine, Case::RemoveDisconnect, Cell::Removed),
    (Row::ControlMachine, Case::RemoveDead, Cell::SteppedThenRemoved),
    (Row::ControlMachine, Case::RemoveAdmin, Cell::Removed),
    (Row::Connection, Case::PromoteInitiator, Cell::Keep),
    (Row::Connection, Case::PromoteResponder, Cell::Keep),
    (Row::Connection, Case::ReplaceRestart, Cell::UnkeptQueued),
    (Row::Connection, Case::ReplaceOwnRestart, Cell::UnkeptQueued),
    (Row::Connection, Case::MoveCrossing, Cell::DialClosedReleasedQueued),
    (Row::Connection, Case::MoveInbound, Cell::ReleasedQueued),
    (Row::Connection, Case::MoveCrossingRefused, Cell::DialClosedUnlessProven),
    (Row::Connection, Case::MoveInboundRefused, Cell::Keep),
    (Row::Connection, Case::Keep, Cell::DialClosedUnlessProven),
    (Row::Connection, Case::KeepInbound, Cell::Keep),
    (Row::Connection, Case::CutoverInitiator, Cell::Keep),
    (Row::Connection, Case::CutoverResponder, Cell::Keep),
    (Row::Connection, Case::Restarted, Cell::Keep),
    (Row::Connection, Case::Roam, Cell::Keep),
    (Row::Connection, Case::Follow, Cell::Keep),
    (Row::Connection, Case::Switch, Cell::Keep),
    (Row::Connection, Case::ReleaseKept, Cell::Keep),
    (Row::Connection, Case::ReleaseUnkept, Cell::QueuedDrained),
    (Row::Connection, Case::RemoveEnded, Cell::UnkeptQueued),
    (Row::Connection, Case::RemoveOrphaned, Cell::UnkeptQueued),
    (Row::Connection, Case::RemoveDisconnect, Cell::UnkeptQueued),
    (Row::Connection, Case::RemoveDead, Cell::UnkeptQueued),
    (Row::Connection, Case::RemoveAdmin, Cell::UnkeptQueuedCurrentClosed),
    (Row::BleMark, Case::PromoteInitiator, Cell::Marked),
    (Row::BleMark, Case::PromoteResponder, Cell::MarkedAtFirstFrame),
    (Row::BleMark, Case::ReplaceRestart, Cell::OldClearedMarkedAtFirstFrame),
    (Row::BleMark, Case::ReplaceOwnRestart, Cell::OldClearedMarked),
    (Row::BleMark, Case::MoveCrossing, Cell::Relinked),
    (Row::BleMark, Case::MoveInbound, Cell::Relinked),
    (Row::BleMark, Case::MoveCrossingRefused, Cell::Keep),
    (Row::BleMark, Case::MoveInboundRefused, Cell::Keep),
    (Row::BleMark, Case::Keep, Cell::Keep),
    (Row::BleMark, Case::KeepInbound, Cell::Keep),
    (Row::BleMark, Case::CutoverInitiator, Cell::Keep),
    (Row::BleMark, Case::CutoverResponder, Cell::Keep),
    (Row::BleMark, Case::Restarted, Cell::Keep),
    (Row::BleMark, Case::Roam, Cell::Relinked),
    (Row::BleMark, Case::Follow, Cell::Keep),
    (Row::BleMark, Case::Switch, Cell::Keep),
    (Row::BleMark, Case::ReleaseKept, Cell::Keep),
    (Row::BleMark, Case::ReleaseUnkept, Cell::ClearedIfDrained),
    (Row::BleMark, Case::RemoveEnded, Cell::ClearedIfDrained),
    (Row::BleMark, Case::RemoveOrphaned, Cell::ClearedIfDrained),
    (Row::BleMark, Case::RemoveDisconnect, Cell::Cleared),
    (Row::BleMark, Case::RemoveDead, Cell::Cleared),
    (Row::BleMark, Case::RemoveAdmin, Cell::ClearedIfDrained),
    (Row::Bootstrap, Case::PromoteInitiator, Cell::NotApplicable),
    (Row::Bootstrap, Case::PromoteResponder, Cell::NotApplicable),
    (Row::Bootstrap, Case::ReplaceRestart, Cell::Checked),
    (Row::Bootstrap, Case::ReplaceOwnRestart, Cell::Checked),
    (Row::Bootstrap, Case::MoveCrossing, Cell::NotRun),
    (Row::Bootstrap, Case::MoveInbound, Cell::NotRun),
    (Row::Bootstrap, Case::MoveCrossingRefused, Cell::NotRun),
    (Row::Bootstrap, Case::MoveInboundRefused, Cell::NotRun),
    (Row::Bootstrap, Case::Keep, Cell::NotRun),
    (Row::Bootstrap, Case::KeepInbound, Cell::NotRun),
    (Row::Bootstrap, Case::CutoverInitiator, Cell::NotApplicable),
    (Row::Bootstrap, Case::CutoverResponder, Cell::NotApplicable),
    (Row::Bootstrap, Case::Restarted, Cell::NotApplicable),
    (Row::Bootstrap, Case::Roam, Cell::NotRun),
    (Row::Bootstrap, Case::Follow, Cell::NotRun),
    (Row::Bootstrap, Case::Switch, Cell::NotRun),
    (Row::Bootstrap, Case::ReleaseKept, Cell::NotRun),
    (Row::Bootstrap, Case::ReleaseUnkept, Cell::NotRun),
    (Row::Bootstrap, Case::RemoveEnded, Cell::Checked),
    (Row::Bootstrap, Case::RemoveOrphaned, Cell::Checked),
    (Row::Bootstrap, Case::RemoveDisconnect, Cell::Checked),
    (Row::Bootstrap, Case::RemoveDead, Cell::Checked),
    (Row::Bootstrap, Case::RemoveAdmin, Cell::Checked),
    (Row::Dials, Case::PromoteInitiator, Cell::AnsweredRemoved),
    (Row::Dials, Case::PromoteResponder, Cell::Keep),
    (Row::Dials, Case::ReplaceRestart, Cell::Keep),
    (Row::Dials, Case::ReplaceOwnRestart, Cell::AnsweredRemoved),
    (Row::Dials, Case::MoveCrossing, Cell::AnsweredRemoved),
    (Row::Dials, Case::MoveInbound, Cell::Keep),
    (Row::Dials, Case::MoveCrossingRefused, Cell::AnsweredRemoved),
    (Row::Dials, Case::MoveInboundRefused, Cell::Keep),
    (Row::Dials, Case::Keep, Cell::AnsweredRemoved),
    (Row::Dials, Case::KeepInbound, Cell::Keep),
    (Row::Dials, Case::CutoverInitiator, Cell::Keep),
    (Row::Dials, Case::CutoverResponder, Cell::Keep),
    (Row::Dials, Case::Restarted, Cell::Keep),
    (Row::Dials, Case::Roam, Cell::Keep),
    (Row::Dials, Case::Follow, Cell::Keep),
    (Row::Dials, Case::Switch, Cell::Keep),
    (Row::Dials, Case::ReleaseKept, Cell::Keep),
    (Row::Dials, Case::ReleaseUnkept, Cell::Keep),
    (Row::Dials, Case::RemoveEnded, Cell::Keep),
    (Row::Dials, Case::RemoveOrphaned, Cell::Keep),
    (Row::Dials, Case::RemoveDisconnect, Cell::Keep),
    (Row::Dials, Case::RemoveDead, Cell::Keep),
    (Row::Dials, Case::RemoveAdmin, Cell::Keep),
    (Row::PathMtu, Case::PromoteInitiator, Cell::Seeded),
    (Row::PathMtu, Case::PromoteResponder, Cell::Seeded),
    (Row::PathMtu, Case::ReplaceRestart, Cell::ReleasedThenSeeded),
    (Row::PathMtu, Case::ReplaceOwnRestart, Cell::ReleasedThenSeeded),
    (Row::PathMtu, Case::MoveCrossing, Cell::ReseededIfMoved),
    (Row::PathMtu, Case::MoveInbound, Cell::ReseededIfMoved),
    (Row::PathMtu, Case::MoveCrossingRefused, Cell::Keep),
    (Row::PathMtu, Case::MoveInboundRefused, Cell::Keep),
    (Row::PathMtu, Case::Keep, Cell::Keep),
    (Row::PathMtu, Case::KeepInbound, Cell::Keep),
    (Row::PathMtu, Case::CutoverInitiator, Cell::Keep),
    (Row::PathMtu, Case::CutoverResponder, Cell::Keep),
    (Row::PathMtu, Case::Restarted, Cell::ReleasedReseeded),
    (Row::PathMtu, Case::Roam, Cell::NotReseeded),
    (Row::PathMtu, Case::Follow, Cell::NotReseeded),
    (Row::PathMtu, Case::Switch, Cell::ReseededTightened),
    (Row::PathMtu, Case::ReleaseKept, Cell::Keep),
    (Row::PathMtu, Case::ReleaseUnkept, Cell::Keep),
    (Row::PathMtu, Case::RemoveEnded, Cell::Released),
    (Row::PathMtu, Case::RemoveOrphaned, Cell::Released),
    (Row::PathMtu, Case::RemoveDisconnect, Cell::Released),
    (Row::PathMtu, Case::RemoveDead, Cell::Released),
    (Row::PathMtu, Case::RemoveAdmin, Cell::Released),
    (Row::FilterSend, Case::PromoteInitiator, Cell::Marked),
    (Row::FilterSend, Case::PromoteResponder, Cell::Marked),
    (Row::FilterSend, Case::ReplaceRestart, Cell::RemovedOthersMarkedThenMarked),
    (Row::FilterSend, Case::ReplaceOwnRestart, Cell::RemovedOthersMarkedThenMarked),
    (Row::FilterSend, Case::MoveCrossing, Cell::Marked),
    (Row::FilterSend, Case::MoveInbound, Cell::Keep),
    (Row::FilterSend, Case::MoveCrossingRefused, Cell::Marked),
    (Row::FilterSend, Case::MoveInboundRefused, Cell::Keep),
    (Row::FilterSend, Case::Keep, Cell::Marked),
    (Row::FilterSend, Case::KeepInbound, Cell::Keep),
    (Row::FilterSend, Case::CutoverInitiator, Cell::Keep),
    (Row::FilterSend, Case::CutoverResponder, Cell::Keep),
    (Row::FilterSend, Case::Restarted, Cell::ForgottenAllMarked),
    (Row::FilterSend, Case::Roam, Cell::Keep),
    (Row::FilterSend, Case::Follow, Cell::Keep),
    (Row::FilterSend, Case::Switch, Cell::Keep),
    (Row::FilterSend, Case::ReleaseKept, Cell::Keep),
    (Row::FilterSend, Case::ReleaseUnkept, Cell::Keep),
    (Row::FilterSend, Case::RemoveEnded, Cell::RemovedOthersMarked),
    (Row::FilterSend, Case::RemoveOrphaned, Cell::RemovedOthersMarked),
    (Row::FilterSend, Case::RemoveDisconnect, Cell::RemovedOthersMarked),
    (Row::FilterSend, Case::RemoveDead, Cell::RemovedOthersMarked),
    (Row::FilterSend, Case::RemoveAdmin, Cell::RemovedOthersMarked),
    (Row::Tree, Case::PromoteInitiator, Cell::Announced),
    (Row::Tree, Case::PromoteResponder, Cell::Announced),
    (Row::Tree, Case::ReplaceRestart, Cell::CleanedOthersPendingAnnounced),
    (Row::Tree, Case::ReplaceOwnRestart, Cell::CleanedOthersPendingAnnounced),
    (Row::Tree, Case::MoveCrossing, Cell::Announced),
    (Row::Tree, Case::MoveInbound, Cell::Keep),
    (Row::Tree, Case::MoveCrossingRefused, Cell::Announced),
    (Row::Tree, Case::MoveInboundRefused, Cell::Keep),
    (Row::Tree, Case::Keep, Cell::Announced),
    (Row::Tree, Case::KeepInbound, Cell::Keep),
    (Row::Tree, Case::CutoverInitiator, Cell::Keep),
    (Row::Tree, Case::CutoverResponder, Cell::Keep),
    (Row::Tree, Case::Restarted, Cell::CleanedOthersPendingAnnounced),
    (Row::Tree, Case::Roam, Cell::Keep),
    (Row::Tree, Case::Follow, Cell::Keep),
    (Row::Tree, Case::Switch, Cell::Keep),
    (Row::Tree, Case::ReleaseKept, Cell::Keep),
    (Row::Tree, Case::ReleaseUnkept, Cell::Keep),
    (Row::Tree, Case::RemoveEnded, Cell::CleanedOthersPending),
    (Row::Tree, Case::RemoveOrphaned, Cell::CleanedOthersPending),
    (Row::Tree, Case::RemoveDisconnect, Cell::CleanedOthersPending),
    (Row::Tree, Case::RemoveDead, Cell::CleanedOthersPending),
    (Row::Tree, Case::RemoveAdmin, Cell::CleanedOthersPending),
    (Row::Session, Case::PromoteInitiator, Cell::Keep),
    (Row::Session, Case::PromoteResponder, Cell::Keep),
    (Row::Session, Case::ReplaceRestart, Cell::Closed),
    (Row::Session, Case::ReplaceOwnRestart, Cell::Closed),
    (Row::Session, Case::MoveCrossing, Cell::Keep),
    (Row::Session, Case::MoveInbound, Cell::Keep),
    (Row::Session, Case::MoveCrossingRefused, Cell::Keep),
    (Row::Session, Case::MoveInboundRefused, Cell::Keep),
    (Row::Session, Case::Keep, Cell::Keep),
    (Row::Session, Case::KeepInbound, Cell::Keep),
    (Row::Session, Case::CutoverInitiator, Cell::Keep),
    (Row::Session, Case::CutoverResponder, Cell::Keep),
    (Row::Session, Case::Restarted, Cell::Closed),
    (Row::Session, Case::Roam, Cell::Keep),
    (Row::Session, Case::Follow, Cell::Keep),
    (Row::Session, Case::Switch, Cell::Keep),
    (Row::Session, Case::ReleaseKept, Cell::Keep),
    (Row::Session, Case::ReleaseUnkept, Cell::Keep),
    (Row::Session, Case::RemoveEnded, Cell::Closed),
    (Row::Session, Case::RemoveOrphaned, Cell::Closed),
    (Row::Session, Case::RemoveDisconnect, Cell::Closed),
    (Row::Session, Case::RemoveDead, Cell::Closed),
    (Row::Session, Case::RemoveAdmin, Cell::Closed),
    (Row::Dampener, Case::PromoteInitiator, Cell::NotApplicable),
    (Row::Dampener, Case::PromoteResponder, Cell::NotApplicable),
    (Row::Dampener, Case::ReplaceRestart, Cell::Stamped),
    (Row::Dampener, Case::ReplaceOwnRestart, Cell::NotStamped),
    (Row::Dampener, Case::MoveCrossing, Cell::NotApplicable),
    (Row::Dampener, Case::MoveInbound, Cell::NotApplicable),
    (Row::Dampener, Case::MoveCrossingRefused, Cell::NotApplicable),
    (Row::Dampener, Case::MoveInboundRefused, Cell::NotApplicable),
    (Row::Dampener, Case::Keep, Cell::NotApplicable),
    (Row::Dampener, Case::KeepInbound, Cell::NotApplicable),
    (Row::Dampener, Case::CutoverInitiator, Cell::NotApplicable),
    (Row::Dampener, Case::CutoverResponder, Cell::NotApplicable),
    (Row::Dampener, Case::Restarted, Cell::NotStamped),
    (Row::Dampener, Case::Roam, Cell::NotApplicable),
    (Row::Dampener, Case::Follow, Cell::NotApplicable),
    (Row::Dampener, Case::Switch, Cell::NotApplicable),
    (Row::Dampener, Case::ReleaseKept, Cell::NotApplicable),
    (Row::Dampener, Case::ReleaseUnkept, Cell::NotApplicable),
    (Row::Dampener, Case::RemoveEnded, Cell::NotApplicable),
    (Row::Dampener, Case::RemoveOrphaned, Cell::NotApplicable),
    (Row::Dampener, Case::RemoveDisconnect, Cell::NotApplicable),
    (Row::Dampener, Case::RemoveDead, Cell::NotApplicable),
    (Row::Dampener, Case::RemoveAdmin, Cell::NotApplicable),
    (Row::Silent, Case::PromoteInitiator, Cell::NotApplicable),
    (Row::Silent, Case::PromoteResponder, Cell::NotApplicable),
    (Row::Silent, Case::ReplaceRestart, Cell::NotedIfNoFrame),
    (Row::Silent, Case::ReplaceOwnRestart, Cell::NotedIfNoFrame),
    (Row::Silent, Case::MoveCrossing, Cell::NotApplicable),
    (Row::Silent, Case::MoveInbound, Cell::NotApplicable),
    (Row::Silent, Case::MoveCrossingRefused, Cell::NotApplicable),
    (Row::Silent, Case::MoveInboundRefused, Cell::NotApplicable),
    (Row::Silent, Case::Keep, Cell::NotApplicable),
    (Row::Silent, Case::KeepInbound, Cell::NotApplicable),
    (Row::Silent, Case::CutoverInitiator, Cell::NotApplicable),
    (Row::Silent, Case::CutoverResponder, Cell::NotApplicable),
    (Row::Silent, Case::Restarted, Cell::NotApplicable),
    (Row::Silent, Case::Roam, Cell::NotApplicable),
    (Row::Silent, Case::Follow, Cell::NotApplicable),
    (Row::Silent, Case::Switch, Cell::NotApplicable),
    (Row::Silent, Case::ReleaseKept, Cell::NotApplicable),
    (Row::Silent, Case::ReleaseUnkept, Cell::NotApplicable),
    (Row::Silent, Case::RemoveEnded, Cell::NotedIfNoFrame),
    (Row::Silent, Case::RemoveOrphaned, Cell::NotedIfNoFrame),
    (Row::Silent, Case::RemoveDisconnect, Cell::NotedIfNoFrame),
    (Row::Silent, Case::RemoveDead, Cell::NotedIfNoFrame),
    (Row::Silent, Case::RemoveAdmin, Cell::NotedIfNoFrame),
    (Row::Reconnect, Case::PromoteInitiator, Cell::Removed),
    (Row::Reconnect, Case::PromoteResponder, Cell::Removed),
    (Row::Reconnect, Case::ReplaceRestart, Cell::NotedDeadThenRemoved),
    (Row::Reconnect, Case::ReplaceOwnRestart, Cell::NotedDeadThenRemoved),
    (Row::Reconnect, Case::MoveCrossing, Cell::Keep),
    (Row::Reconnect, Case::MoveInbound, Cell::Keep),
    (Row::Reconnect, Case::MoveCrossingRefused, Cell::Keep),
    (Row::Reconnect, Case::MoveInboundRefused, Cell::Keep),
    (Row::Reconnect, Case::Keep, Cell::Keep),
    (Row::Reconnect, Case::KeepInbound, Cell::Keep),
    (Row::Reconnect, Case::CutoverInitiator, Cell::Keep),
    (Row::Reconnect, Case::CutoverResponder, Cell::Keep),
    (Row::Reconnect, Case::Restarted, Cell::Keep),
    (Row::Reconnect, Case::Roam, Cell::Keep),
    (Row::Reconnect, Case::Follow, Cell::Keep),
    (Row::Reconnect, Case::Switch, Cell::Keep),
    (Row::Reconnect, Case::ReleaseKept, Cell::Keep),
    (Row::Reconnect, Case::ReleaseUnkept, Cell::Keep),
    (Row::Reconnect, Case::RemoveEnded, Cell::Keep),
    (Row::Reconnect, Case::RemoveOrphaned, Cell::NotedDead),
    (Row::Reconnect, Case::RemoveDisconnect, Cell::NotedDead),
    (Row::Reconnect, Case::RemoveDead, Cell::NotedDead),
    (Row::Reconnect, Case::RemoveAdmin, Cell::Removed),
    (Row::IdentityCache, Case::PromoteInitiator, Cell::Registered),
    (Row::IdentityCache, Case::PromoteResponder, Cell::Registered),
    (Row::IdentityCache, Case::ReplaceRestart, Cell::Registered),
    (Row::IdentityCache, Case::ReplaceOwnRestart, Cell::Registered),
    (Row::IdentityCache, Case::MoveCrossing, Cell::Keep),
    (Row::IdentityCache, Case::MoveInbound, Cell::Keep),
    (Row::IdentityCache, Case::MoveCrossingRefused, Cell::Keep),
    (Row::IdentityCache, Case::MoveInboundRefused, Cell::Keep),
    (Row::IdentityCache, Case::Keep, Cell::Keep),
    (Row::IdentityCache, Case::KeepInbound, Cell::Keep),
    (Row::IdentityCache, Case::CutoverInitiator, Cell::Keep),
    (Row::IdentityCache, Case::CutoverResponder, Cell::Keep),
    (Row::IdentityCache, Case::Restarted, Cell::Keep),
    (Row::IdentityCache, Case::Roam, Cell::Keep),
    (Row::IdentityCache, Case::Follow, Cell::Keep),
    (Row::IdentityCache, Case::Switch, Cell::Keep),
    (Row::IdentityCache, Case::ReleaseKept, Cell::Keep),
    (Row::IdentityCache, Case::ReleaseUnkept, Cell::Keep),
    (Row::IdentityCache, Case::RemoveEnded, Cell::Keep),
    (Row::IdentityCache, Case::RemoveOrphaned, Cell::Keep),
    (Row::IdentityCache, Case::RemoveDisconnect, Cell::Keep),
    (Row::IdentityCache, Case::RemoveDead, Cell::Keep),
    (Row::IdentityCache, Case::RemoveAdmin, Cell::Keep),
    (Row::LookupBackoff, Case::PromoteInitiator, Cell::BackoffReset),
    (Row::LookupBackoff, Case::PromoteResponder, Cell::BackoffReset),
    (Row::LookupBackoff, Case::ReplaceRestart, Cell::BackoffReset),
    (Row::LookupBackoff, Case::ReplaceOwnRestart, Cell::BackoffReset),
    (Row::LookupBackoff, Case::MoveCrossing, Cell::BackoffReset),
    (Row::LookupBackoff, Case::MoveInbound, Cell::Keep),
    (Row::LookupBackoff, Case::MoveCrossingRefused, Cell::BackoffReset),
    (Row::LookupBackoff, Case::MoveInboundRefused, Cell::Keep),
    (Row::LookupBackoff, Case::Keep, Cell::BackoffReset),
    (Row::LookupBackoff, Case::KeepInbound, Cell::Keep),
    (Row::LookupBackoff, Case::CutoverInitiator, Cell::Keep),
    (Row::LookupBackoff, Case::CutoverResponder, Cell::Keep),
    (Row::LookupBackoff, Case::Restarted, Cell::Keep),
    (Row::LookupBackoff, Case::Roam, Cell::Keep),
    (Row::LookupBackoff, Case::Follow, Cell::Keep),
    (Row::LookupBackoff, Case::Switch, Cell::Keep),
    (Row::LookupBackoff, Case::ReleaseKept, Cell::Keep),
    (Row::LookupBackoff, Case::ReleaseUnkept, Cell::Keep),
    (Row::LookupBackoff, Case::RemoveEnded, Cell::Keep),
    (Row::LookupBackoff, Case::RemoveOrphaned, Cell::Keep),
    (Row::LookupBackoff, Case::RemoveDisconnect, Cell::Keep),
    (Row::LookupBackoff, Case::RemoveDead, Cell::Keep),
    (Row::LookupBackoff, Case::RemoveAdmin, Cell::Keep),
    (Row::PathConnects, Case::PromoteInitiator, Cell::Keep),
    (Row::PathConnects, Case::PromoteResponder, Cell::Keep),
    (Row::PathConnects, Case::ReplaceRestart, Cell::Forgotten),
    (Row::PathConnects, Case::ReplaceOwnRestart, Cell::Forgotten),
    (Row::PathConnects, Case::MoveCrossing, Cell::Keep),
    (Row::PathConnects, Case::MoveInbound, Cell::Keep),
    (Row::PathConnects, Case::MoveCrossingRefused, Cell::Keep),
    (Row::PathConnects, Case::MoveInboundRefused, Cell::Keep),
    (Row::PathConnects, Case::Keep, Cell::Keep),
    (Row::PathConnects, Case::KeepInbound, Cell::Keep),
    (Row::PathConnects, Case::CutoverInitiator, Cell::Keep),
    (Row::PathConnects, Case::CutoverResponder, Cell::Keep),
    (Row::PathConnects, Case::Restarted, Cell::Keep),
    (Row::PathConnects, Case::Roam, Cell::Keep),
    (Row::PathConnects, Case::Follow, Cell::Keep),
    (Row::PathConnects, Case::Switch, Cell::Keep),
    (Row::PathConnects, Case::ReleaseKept, Cell::Keep),
    (Row::PathConnects, Case::ReleaseUnkept, Cell::Keep),
    (Row::PathConnects, Case::RemoveEnded, Cell::Forgotten),
    (Row::PathConnects, Case::RemoveOrphaned, Cell::Forgotten),
    (Row::PathConnects, Case::RemoveDisconnect, Cell::Forgotten),
    (Row::PathConnects, Case::RemoveDead, Cell::Forgotten),
    (Row::PathConnects, Case::RemoveAdmin, Cell::Forgotten),
    (Row::PathCloses, Case::PromoteInitiator, Cell::Keep),
    (Row::PathCloses, Case::PromoteResponder, Cell::Keep),
    (Row::PathCloses, Case::ReplaceRestart, Cell::Queued),
    (Row::PathCloses, Case::ReplaceOwnRestart, Cell::Queued),
    (Row::PathCloses, Case::MoveCrossing, Cell::QueuedDrainedIfMoved),
    (Row::PathCloses, Case::MoveInbound, Cell::Queued),
    (Row::PathCloses, Case::MoveCrossingRefused, Cell::Keep),
    (Row::PathCloses, Case::MoveInboundRefused, Cell::Keep),
    (Row::PathCloses, Case::Keep, Cell::Keep),
    (Row::PathCloses, Case::KeepInbound, Cell::Keep),
    (Row::PathCloses, Case::CutoverInitiator, Cell::Keep),
    (Row::PathCloses, Case::CutoverResponder, Cell::Keep),
    (Row::PathCloses, Case::Restarted, Cell::Keep),
    (Row::PathCloses, Case::Roam, Cell::Keep),
    (Row::PathCloses, Case::Follow, Cell::Keep),
    (Row::PathCloses, Case::Switch, Cell::Keep),
    (Row::PathCloses, Case::ReleaseKept, Cell::Keep),
    (Row::PathCloses, Case::ReleaseUnkept, Cell::Queued),
    (Row::PathCloses, Case::RemoveEnded, Cell::Queued),
    (Row::PathCloses, Case::RemoveOrphaned, Cell::Queued),
    (Row::PathCloses, Case::RemoveDisconnect, Cell::Queued),
    (Row::PathCloses, Case::RemoveDead, Cell::Queued),
    (Row::PathCloses, Case::RemoveAdmin, Cell::Queued),
    (Row::PathListings, Case::PromoteInitiator, Cell::ForgottenOffered),
    (Row::PathListings, Case::PromoteResponder, Cell::ForgottenOffered),
    (Row::PathListings, Case::ReplaceRestart, Cell::ForgottenOffered),
    (Row::PathListings, Case::ReplaceOwnRestart, Cell::ForgottenOffered),
    (Row::PathListings, Case::MoveCrossing, Cell::ForgottenOffered),
    (Row::PathListings, Case::MoveInbound, Cell::ForgottenOffered),
    (Row::PathListings, Case::MoveCrossingRefused, Cell::ForgottenOffered),
    (Row::PathListings, Case::MoveInboundRefused, Cell::ForgottenOffered),
    (Row::PathListings, Case::Keep, Cell::Keep),
    (Row::PathListings, Case::KeepInbound, Cell::Keep),
    (Row::PathListings, Case::CutoverInitiator, Cell::Keep),
    (Row::PathListings, Case::CutoverResponder, Cell::Keep),
    (Row::PathListings, Case::Restarted, Cell::Keep),
    (Row::PathListings, Case::Roam, Cell::Keep),
    (Row::PathListings, Case::Follow, Cell::Keep),
    (Row::PathListings, Case::Switch, Cell::Keep),
    (Row::PathListings, Case::ReleaseKept, Cell::Keep),
    (Row::PathListings, Case::ReleaseUnkept, Cell::Keep),
    (Row::PathListings, Case::RemoveEnded, Cell::GoneAtDiscovery),
    (Row::PathListings, Case::RemoveOrphaned, Cell::GoneAtDiscovery),
    (Row::PathListings, Case::RemoveDisconnect, Cell::GoneAtDiscovery),
    (Row::PathListings, Case::RemoveDead, Cell::GoneAtDiscovery),
    (Row::PathListings, Case::RemoveAdmin, Cell::GoneAtDiscovery),
    (Row::PathCarrier, Case::PromoteInitiator, Cell::Keep),
    (Row::PathCarrier, Case::PromoteResponder, Cell::Keep),
    (Row::PathCarrier, Case::ReplaceRestart, Cell::GoneAtNextRead),
    (Row::PathCarrier, Case::ReplaceOwnRestart, Cell::GoneAtNextRead),
    (Row::PathCarrier, Case::MoveCrossing, Cell::Keep),
    (Row::PathCarrier, Case::MoveInbound, Cell::Keep),
    (Row::PathCarrier, Case::MoveCrossingRefused, Cell::Keep),
    (Row::PathCarrier, Case::MoveInboundRefused, Cell::Keep),
    (Row::PathCarrier, Case::Keep, Cell::Keep),
    (Row::PathCarrier, Case::KeepInbound, Cell::Keep),
    (Row::PathCarrier, Case::CutoverInitiator, Cell::Keep),
    (Row::PathCarrier, Case::CutoverResponder, Cell::Keep),
    (Row::PathCarrier, Case::Restarted, Cell::Keep),
    (Row::PathCarrier, Case::Roam, Cell::Keep),
    (Row::PathCarrier, Case::Follow, Cell::Keep),
    (Row::PathCarrier, Case::Switch, Cell::Keep),
    (Row::PathCarrier, Case::ReleaseKept, Cell::Keep),
    (Row::PathCarrier, Case::ReleaseUnkept, Cell::Keep),
    (Row::PathCarrier, Case::RemoveEnded, Cell::GoneAtNextRead),
    (Row::PathCarrier, Case::RemoveOrphaned, Cell::GoneAtNextRead),
    (Row::PathCarrier, Case::RemoveDisconnect, Cell::GoneAtNextRead),
    (Row::PathCarrier, Case::RemoveDead, Cell::GoneAtNextRead),
    (Row::PathCarrier, Case::RemoveAdmin, Cell::GoneAtNextRead),
];
