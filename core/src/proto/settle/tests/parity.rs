//! The unit tests of `../parity.rs` and its trace, `../parity.txt`, attached
//! from that file with `#[path]`: the trace reads back as written, every script names only what it holds,
//! scripts and blocks match one to one, and a `core` line names a listed
//! cause. Each test plants its own bad input and shows it is found.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{
    Cause, Mark, SCRIPTS, Script, Setting, Step, TRACE, Transport, differs, expected, line, read,
    strays, unmatched,
};

/// The committed trace's lines that are not comments or blank, as written.
fn written() -> Vec<&'static str> {
    TRACE
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

#[test]
fn a_trace_reads_back_as_it_was_written() {
    let traces = read(TRACE).expect("the committed trace reads");
    let mut again = Vec::new();
    for t in &traces {
        let settings: Vec<&str> = t.settings.iter().map(|s| s.name()).collect();
        again.push(format!("script {} {}", t.name, settings.join(" ")));
        again.extend(t.lines.iter().map(ToString::to_string));
        again.extend(t.core.iter().map(ToString::to_string));
    }
    assert_eq!(
        again,
        written(),
        "each line written back from what was read is the line as written"
    );
    let held = written()
        .into_iter()
        .find(|l| l.contains(" held "))
        .expect("the trace holds a held line");
    let words: Vec<&str> = held.split(' ').collect();
    for gone in 3..words.len() {
        let short: Vec<&str> = words
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != gone)
            .map(|(_, w)| *w)
            .collect();
        let short = short.join(" ");
        assert!(
            line(&short).is_err(),
            "a line with its field {gone} removed does not read back: {short:?}"
        );
    }
    let mut swapped = words.clone();
    swapped.swap(3, 4);
    let swapped = swapped.join(" ");
    assert!(
        line(&swapped).is_err(),
        "a line with two fields exchanged does not read back: {swapped:?}"
    );
    assert_eq!(Mark::read("none"), Ok(Mark::Unheld), "an unheld mark reads");
    assert!(
        Mark::read("none heard").is_err(),
        "an unheld mark takes no field"
    );
}

/// A script on two nodes over UDP, its steps given.
fn planted(steps: &'static [Step], smaller: usize) -> Script {
    Script {
        name: "planted",
        settings: &[Setting::Off, Setting::Off],
        smaller,
        transports: &[Transport::Udp],
        steps,
    }
}

#[test]
fn a_script_names_no_node_or_transport_it_does_not_hold() {
    for s in SCRIPTS {
        let found = strays(s);
        assert!(
            found.is_empty(),
            "{} names what it does not hold: {found:?}",
            s.name
        );
    }
    let bad: [(&'static [Step], usize, &str); 6] = [
        (
            &[Step::Dial {
                from: 0,
                to: 2,
                transport: Transport::Udp,
            }],
            0,
            "n2",
        ),
        (
            &[Step::Dial {
                from: 0,
                to: 1,
                transport: Transport::Tcp,
            }],
            0,
            "tcp",
        ),
        (
            &[Step::Dial {
                from: 1,
                to: 1,
                transport: Transport::Udp,
            }],
            0,
            "itself",
        ),
        (&[Step::Connected { node: 3 }], 0, "n3"),
        (&[Step::Restart { node: 2 }], 0, "n2"),
        (&[Step::Heal], 2, "n2"),
    ];
    for (steps, smaller, what) in bad {
        let found = strays(&planted(steps, smaller));
        assert!(
            found.iter().any(|f| f.contains(what)),
            "the scan finds a planted script naming {what}: {found:?} for {steps:?}"
        );
    }
    let good: &'static [Step] = &[
        Step::Dial {
            from: 0,
            to: 1,
            transport: Transport::Udp,
        },
        Step::Handshake {
            to: 1,
            kind: super::Packet::Msg1,
            nth: 1,
        },
        Step::Advance(1_000),
        Step::Rekey { node: 1 },
    ];
    assert!(
        strays(&planted(good, 1)).is_empty(),
        "and finds nothing in a script that names only what it holds"
    );
}

/// The committed trace with the lines `drop` matches removed.
fn without(drop: impl Fn(&str) -> bool) -> String {
    TRACE
        .lines()
        .filter(|l| !drop(l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The first script's line at step 5, node 0, the first line of the
/// committed trace that holds the peer `out`.
const FIFTH: &str = "5 n0 held own out udp-home udp-home heard";

/// A `core` line of a listed cause stating a field the line [`FIFTH`]
/// holds otherwise.
const PLANTED: &str = "core 5 n0 dir=in cause=late-dial-split";

/// The committed trace with `core` added to the first script's block
/// beside [`FIFTH`]: the fixture the reader's plants go on, since the
/// committed trace holds no `core` line.
fn with_core(core: &str) -> String {
    TRACE.replacen(FIFTH, &format!("{FIFTH}\n{core}"), 1)
}

#[test]
fn every_script_has_its_lines_and_every_line_its_script() {
    let traces = read(TRACE).expect("the committed trace reads");
    let found = unmatched(SCRIPTS, &traces);
    assert!(
        found.is_empty(),
        "the scripts and the trace do not match: {found:?}"
    );
    for s in SCRIPTS {
        assert!(
            expected(s.name).is_some(),
            "{} has its block in the committed trace",
            s.name
        );
    }
    let first = SCRIPTS[0].name;
    let removed = read(&without(|l| {
        l == "3 n1 held peer in udp-home udp-home unheard"
    }))
    .expect("the trace with a line removed reads");
    assert!(
        unmatched(SCRIPTS, &removed)
            .iter()
            .any(|f| f.contains("0 lines for step 3 n1")),
        "the scan finds a step whose line was removed"
    );
    let mut more: Vec<Script> = SCRIPTS.to_vec();
    more.push(Script {
        name: "planted-with-no-lines",
        ..SCRIPTS[0]
    });
    assert_eq!(
        unmatched(&more, &traces),
        ["planted-with-no-lines has no lines"],
        "the scan finds a script added with no lines"
    );
    let header = format!("script {first} off off");
    let mut orphan = String::from(TRACE);
    orphan.push_str("\nscript planted-with-no-script off off\n1 n0 none\n");
    let orphan = read(&orphan).expect("the trace with a block added reads");
    assert!(
        unmatched(SCRIPTS, &orphan)
            .iter()
            .any(|f| f.contains("planted-with-no-script has lines and no script")),
        "the scan finds a block added with no script"
    );
    let twice = read(&format!("{TRACE}\n{header}\n")).expect("the trace reads");
    assert!(
        unmatched(SCRIPTS, &twice)
            .iter()
            .any(|f| f.contains("has two blocks")),
        "the scan finds a script's block written twice"
    );
    let resettled = read(&TRACE.replacen(&header, &format!("script {first} on on"), 1))
        .expect("the trace reads");
    assert!(
        unmatched(SCRIPTS, &resettled)
            .iter()
            .any(|f| f.contains("header states")),
        "the scan finds a header whose settings are not its script's"
    );
    let fixture = read(&with_core(PLANTED)).expect("the trace with a core line reads");
    assert!(
        unmatched(SCRIPTS, &fixture).is_empty(),
        "precondition: a core line stating a difference is no mismatch"
    );
    let restated =
        read(&with_core("core 5 n0 dir=out cause=late-dial-split")).expect("the trace reads");
    assert!(
        unmatched(SCRIPTS, &restated)
            .iter()
            .any(|f| f.contains("states a value the node's line holds")),
        "the scan finds a core line that states no difference"
    );
}

#[test]
fn a_core_line_names_a_listed_cause() {
    let traces = read(&with_core(PLANTED)).expect("the trace with a core line reads");
    let core: usize = traces.iter().map(|t| t.core.len()).sum();
    assert_eq!(core, 1, "precondition: the fixture holds its one core line");
    for t in &traces {
        for d in &t.core {
            assert!(
                Cause::ALL.contains(&d.cause),
                "{}: `{d}` names a listed cause",
                t.name
            );
        }
    }
    for cause in Cause::ALL {
        let text = format!("core 5 n0 dir=out cause={}", cause.name());
        assert_eq!(
            differs(&text).map(|d| d.cause),
            Ok(cause),
            "a core line naming {} reads",
            cause.name()
        );
    }
    for planted in [
        "core 5 n0 dir=out cause=the-node-is-wrong",
        "core 5 n0 dir=out",
        "core 5 n0 dir=out cause=",
        "core 5 n0 cause=late-dial-split",
    ] {
        assert!(
            differs(planted).is_err(),
            "a planted core line with no listed cause, or no field, does not read: {planted:?}"
        );
        let text = with_core(planted);
        assert!(
            read(&text).is_err(),
            "nor does the trace it is planted in: {planted:?}"
        );
    }
}
