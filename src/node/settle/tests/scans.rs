//! The scans that hold every call of a peer's machines to the settlement
//! core's join and the executor, and every step of the settlement core to
//! the node's one file that decides through it: no code of the root crate
//! outside its tests builds, renews or closes a link's rekey or path
//! machine itself, only the active peer asks the join to build, move or
//! close them, only the executor, or the move's site, asks the active peer,
//! and only `src/node/settle/decide.rs` steps the core's table. A last scan
//! keeps the inputs of those decisions in `fips-core`: the settlement core's
//! gate constants, the rekey machine's parameters and the node-address
//! ordering appear in the root crate only on an exempt list, each with its
//! reason.
use crate::node::tests::survivors::{label, sources};
use std::path::Path;

/// One token of a source's code: an identifier or one character of
/// punctuation, with its line.
type Token = (usize, String);

/// The code of `source` as tokens, leaving out comments and literals as
/// `code_text` does, so prose and strings may name what the code may not.
fn tokens(source: &str) -> Vec<Token> {
    let code = fips_core::proto::rekey::code_text(source);
    let mut out = Vec::new();
    for (n, line) in code.lines().enumerate() {
        let mut word = String::new();
        for c in line.chars() {
            if c.is_ascii_alphanumeric() || c == '_' {
                word.push(c);
                continue;
            }
            if !word.is_empty() {
                out.push((n + 1, std::mem::take(&mut word)));
            }
            if !c.is_whitespace() {
                out.push((n + 1, c.to_string()));
            }
        }
        if !word.is_empty() {
            out.push((n + 1, word));
        }
    }
    out
}

/// For each token of [`tokens`]' list of `source`, whether whitespace or a
/// line's start comes right before it, so a comparison's spaced operator
/// can be told from a generic's brackets, which rustfmt writes unspaced.
fn gaps(source: &str) -> Vec<bool> {
    let code = fips_core::proto::rekey::code_text(source);
    let mut out = Vec::new();
    for line in code.lines() {
        let mut word = false;
        let mut gap = true;
        for c in line.chars() {
            if c.is_ascii_alphanumeric() || c == '_' {
                if !word {
                    out.push(gap);
                    word = true;
                }
                gap = false;
                continue;
            }
            word = false;
            if c.is_whitespace() {
                gap = true;
            } else {
                out.push(gap);
                gap = false;
            }
        }
    }
    out
}

/// Whether the tokens from `at` on read `want`.
fn reads(toks: &[Token], at: usize, want: &[&str]) -> bool {
    want.iter()
        .enumerate()
        .all(|(i, w)| toks.get(at + i).is_some_and(|(_, t)| t == w))
}

/// Whether the token before `at` is `want`.
fn after(toks: &[Token], at: usize, want: &str) -> bool {
    at.checked_sub(1)
        .and_then(|i| toks.get(i))
        .is_some_and(|(_, t)| t == want)
}

/// The function each token is in: the name after the last `fn` before it,
/// or empty before the first.
fn within(toks: &[Token]) -> Vec<String> {
    let mut name = String::new();
    let mut out = Vec::with_capacity(toks.len());
    for (i, (_, t)) in toks.iter().enumerate() {
        out.push(name.clone());
        if t == "fn"
            && let Some((_, next)) = toks.get(i + 1)
        {
            name.clone_from(next);
        }
    }
    out
}

/// The helpers that build or close a machine for the code that calls them,
/// so a call of one is a call of the machine.
const WRAPPERS: &[&str] = &["new_bundle", "link_machine", "close_paths"];

/// The index of the token after the path separator that follows the token
/// at `at`, past a turbofish if one comes first: for `Bundle::new` and
/// `Bundle::<P, C, S>::new` alike, the index of `new`.
fn past_turbofish(toks: &[Token], at: usize) -> Option<usize> {
    if !reads(toks, at + 1, &[":", ":"]) {
        return None;
    }
    let mut i = at + 3;
    if reads(toks, i, &["<"]) {
        let mut depth = 0usize;
        while let Some((_, t)) = toks.get(i) {
            match t.as_str() {
                "<" => depth += 1,
                ">" => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        if !reads(toks, i + 1, &[":", ":"]) {
            return None;
        }
        i += 3;
    }
    Some(i)
}

/// Each call of a link's or a session's machines in the code of `source`
/// that is not the settlement core's join, as `(line, function, what)`:
/// a rekey machine built (`<..>Rekey::established`); a path machine built,
/// renewed or closed by its path (`PeerBundle::new`, `renew`, `close`); a
/// `.renew(` method call; a `.close(` method call taking a `Close` by
/// either path; and a call of one of [`WRAPPERS`].
fn machine_calls(source: &str) -> Vec<(usize, String, String)> {
    let toks = tokens(source);
    let fns = within(&toks);
    let mut found = Vec::new();
    for (i, (n, t)) in toks.iter().enumerate() {
        let what = if t.ends_with("Rekey") && reads(&toks, i + 1, &[":", ":", "established"]) {
            Some(format!("{t}::established"))
        } else if t == "PeerBundle" && reads(&toks, i + 1, &[":", ":"]) {
            toks.get(i + 3)
                .map(|(_, m)| m.as_str())
                .filter(|m| ["new", "renew", "close"].contains(m))
                .map(|m| format!("PeerBundle::{m}"))
        } else if t == "." && reads(&toks, i + 1, &["renew", "("]) {
            Some(".renew(".to_string())
        } else if t == "." && reads(&toks, i + 1, &["close", "("]) {
            // The argument's path, up to the first token that is not an
            // identifier or a `::`.
            let path: Vec<&str> = toks[i + 3..]
                .iter()
                .map(|(_, w)| w.as_str())
                .take_while(|w| *w == ":" || w.chars().all(|c| c.is_alphanumeric() || c == '_'))
                .collect();
            path.contains(&"Close").then(|| ".close(Close".to_string())
        } else if WRAPPERS.contains(&t.as_str())
            && reads(&toks, i + 1, &["("])
            && !after(&toks, i, "fn")
        {
            Some(format!("{t}("))
        } else {
            None
        };
        if let Some(what) = what {
            found.push((*n, fns[i].clone(), what));
        }
    }
    found
}

/// The functions outside the settlement core's join that call a machine,
/// as `(file, function, test builds only, why)`.
const EXEMPT: &[(&str, &str, bool, &str)] = &[
    (
        "node/session/mod.rs",
        "keyed",
        true,
        "a test's session machine: FSP's, which the settlement core does not join",
    ),
    (
        "peer/active.rs",
        "new_bundle",
        false,
        "the path machine of a link bound outside its setup, for `bind` and \
         `with_test_session` alone, which this scan holds it to",
    ),
    (
        "peer/active.rs",
        "bind",
        false,
        "reached only by a peer `ActivePeer::new` built, which only a test builds",
    ),
    (
        "peer/active.rs",
        "link_machine",
        true,
        "a test's peer's rekey machine, for `with_test_session`",
    ),
    ("peer/active.rs", "with_test_session", true, "a test's peer"),
    (
        "peer/active.rs",
        "close_paths",
        true,
        "a test's re-pointing of a peer, for `repin`",
    ),
    (
        "peer/active.rs",
        "repin",
        true,
        "a test's re-pointing of a peer",
    ),
];

/// Whether `function` in `source` carries `#[cfg(test)]`, or is a test
/// (`#[test]`, `#[tokio::test]`), among the attributes and comments
/// directly above its `fn` line.
fn test_only(source: &str, function: &str) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    let at = lines.iter().position(|l| {
        let l = l.trim_start();
        l.split("fn ")
            .nth(1)
            .is_some_and(|rest| rest.starts_with(&format!("{function}(")))
            && !l.starts_with("//")
    });
    at.is_some_and(|at| {
        lines[..at]
            .iter()
            .rev()
            .map(|l| l.trim())
            .take_while(|l| l.starts_with("#[") || l.starts_with("//"))
            .any(|l| ["#[cfg(test)]", "#[test]", "#[tokio::test]"].contains(&l))
    })
}

/// No code of the root crate outside its tests builds, renews or closes a
/// link's rekey or path machine but through the settlement core's join,
/// beyond the listed exemptions, each with its reason; each exemption still
/// names a call, and each one listed for test builds only is
/// `#[cfg(test)]`. The planted lines show the scan finds each shape of
/// call, in code and in its function, and not a name in a comment, a
/// string, or a `.close()` of something else.
#[test]
fn the_machines_are_built_and_closed_only_through_join_and_the_executor() {
    let planted = "impl ActivePeer {\n\
                   \x20   fn shortcut(&mut self, s: Completed) {\n\
                   \x20       // self.rekey.renew(s) in a comment calls nothing.\n\
                   \x20       let m = LinkRekey::established(p, b, me, s, ids, f, now, env);\n\
                   \x20       let b = PeerBundle::new(now, t, a, params, &env);\n\
                   \x20       self.rekey.as_mut().map(|r| r.renew(s, now));\n\
                   \x20       r.close(Close::Admin, now, env);\n\
                   \x20       r.close(\n\
                   \x20           fips_core::proto::rekey::Close::Admin,\n\
                   \x20           now,\n\
                   \x20       );\n\
                   \x20       self.send.bundle.take().map(PeerBundle::close);\n\
                   \x20       flow.close();\n\
                   \x20       let note = \"PeerBundle::new\";\n\
                   \x20   }\n\
                   \x20   fn helper(&mut self) { self.close_paths(); }\n\
                   }\n";
    let at = |n: usize, f: &str, w: &str| (n, f.to_string(), w.to_string());
    assert_eq!(
        machine_calls(planted),
        [
            at(4, "shortcut", "LinkRekey::established"),
            at(5, "shortcut", "PeerBundle::new"),
            at(6, "shortcut", ".renew("),
            at(7, "shortcut", ".close(Close"),
            at(8, "shortcut", ".close(Close"),
            at(12, "shortcut", "PeerBundle::close"),
            at(16, "helper", "close_paths("),
        ],
        "the scan finds each shape of machine call in code, in its function, \
         and not one in a comment or a string, or another `.close()`"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    let mut exempt = Vec::new();
    let mut found = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path).expect("the source file reads");
        let file = label(&root, path);
        for (n, function, what) in machine_calls(&source) {
            let at = format!("{file}:{n}: {function}: {what}");
            match EXEMPT
                .iter()
                .find(|(f, w, ..)| *f == file && *w == function)
            {
                Some(&(_, _, gated, _)) => {
                    assert!(
                        !gated || test_only(&source, &function),
                        "{file}'s `{function}` is exempt as test-only code, and is not \
                         `#[cfg(test)]`"
                    );
                    exempt.push((file.to_string(), function));
                }
                None => found.push(at),
            }
        }
    }
    assert!(
        found.is_empty(),
        "a machine is built, renewed or closed outside the settlement core's join: {found:?}"
    );
    for (f, w, ..) in EXEMPT {
        assert!(
            exempt
                .iter()
                .any(|(file, function)| file == f && function == w),
            "the exemption of {f}'s `{w}` names no call any more"
        );
    }
    // The scan reaches the active peer, the session table, the executor and
    // the sites that run changes through it, and leaves the tests out.
    for want in [
        "peer/active.rs",
        "node/session/mod.rs",
        "node/settle/exec/install.rs",
        "node/settle/exec/remove.rs",
        "node/handlers/handshake.rs",
        "node/handlers/rekey.rs",
    ] {
        assert!(files.iter().any(|p| p.ends_with(want)), "{want} is scanned");
    }
    assert!(
        !files
            .iter()
            .any(|p| p.starts_with(root.join("node").join("tests"))),
        "the node's tests are not scanned"
    );
}

/// The settlement core's table's functions that decide: `step` takes one
/// input, `poll` runs the handshake legs' timers, `reap_leg` reaps one leg
/// and `close` gives everything back.
const DECIDERS: &[&str] = &["step", "poll", "reap_leg", "close"];

/// The one file of the node that steps, polls, reaps and closes the
/// settlement core's table: its `decide_at` hands the core an input and
/// gives the outputs back to the decision sites, which run them in order;
/// `tend` and `core_pathed` hand it a resend's outcome or a path input the
/// bundle already decided and carry out only the leases; `quiet` hands it
/// a dial's quiet at its msg2 and carries out nothing; and `core_reap`
/// reaps one leg.
const DECIDES: &str = "node/settle/decide.rs";

/// Each call of the settlement core table's [`DECIDERS`] in the code of
/// `source`, as `(line, function, what)`: a method call on a receiver named
/// `core` (`self.core.step(`, `node.core.poll(`, `core.reap_leg(`), the
/// name the node and the link table give the table; and a call by the
/// type's path, `Table::` or the node's `Core::`, a turbofish allowed. The
/// node's own `reap_leg`, which runs a reaped leg's outputs, is not one.
fn core_calls(source: &str) -> Vec<(usize, String, String)> {
    let toks = tokens(source);
    let fns = within(&toks);
    let mut found = Vec::new();
    for (i, (n, t)) in toks.iter().enumerate() {
        let what = if t == "." {
            toks.get(i + 1)
                .map(|(_, m)| m.as_str())
                .filter(|m| DECIDERS.contains(m) && reads(&toks, i + 2, &["("]))
                .filter(|_| i.checked_sub(1).is_some_and(|b| toks[b].1 == "core"))
                .map(|m| format!(".{m}("))
        } else if t == "Table" || t == "Core" {
            past_turbofish(&toks, i)
                .and_then(|m| toks.get(m))
                .map(|(_, m)| m.as_str())
                .filter(|m| DECIDERS.contains(m))
                .map(|m| format!("{t}::{m}"))
        } else {
            None
        };
        if let Some(what) = what {
            found.push((*n, fns[i].clone(), what));
        }
    }
    found
}

/// The settlement core's table is stepped, polled, reaped and closed only
/// from `src/node/settle/decide.rs`, whose `decide_at` hands the outputs
/// back to the decision sites to run in order, and whose other steps run
/// only their leases: a resend's outcome, a path input, a dial's quiet at
/// its msg2, and a leg's reap. `decide.rs` steps and reaps it;
/// `Table::poll` and `Table::close` have no caller in the root crate. The
/// planted lines show the scan finds each of the four by a receiver named
/// `core` and by a call of the type's path, and not the link table's
/// `close`, the node's own `reap_leg`, another machine's `step`, or a name
/// in a comment or a string.
#[test]
fn the_settlement_core_is_stepped_polled_reaped_and_closed_only_from_decide() {
    let planted = "impl Node {\n\
                   \x20   fn shortcut(&mut self, input: Input, now: PeerInstant) {\n\
                   \x20       // self.core.step(input, now) in a comment steps nothing.\n\
                   \x20       let out = self.core.step(input, now);\n\
                   \x20       let due = node.core.poll(now);\n\
                   \x20       let reaped = core.reap_leg(link, now);\n\
                   \x20       self.reap_leg(link, dial, closes, lease).await;\n\
                   \x20       let all = self.core.close(now);\n\
                   \x20       let out = Table::step(&mut self.core, input, now);\n\
                   \x20       let due = settle::Core::poll(&mut self.core, now);\n\
                   \x20       let all = Table::<PeerInstant>::close(&mut self.core, now);\n\
                   \x20       let _ = self.links.close(&mut self.core, &id);\n\
                   \x20       let _ = machine.step(input, now);\n\
                   \x20       let note = \"self.core.poll(now)\";\n\
                   \x20   }\n\
                   }\n";
    let at = |n: usize, f: &str, w: &str| (n, f.to_string(), w.to_string());
    assert_eq!(
        core_calls(planted),
        [
            at(4, "shortcut", ".step("),
            at(5, "shortcut", ".poll("),
            at(6, "shortcut", ".reap_leg("),
            at(8, "shortcut", ".close("),
            at(9, "shortcut", "Table::step"),
            at(10, "shortcut", "Core::poll"),
            at(11, "shortcut", "Table::close"),
        ],
        "the scan finds each of the core's deciders called in code, in its \
         function, by each shape, and not the link table's close, the node's \
         own reap, another machine's step, a comment or a string"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    let mut decides = Vec::new();
    let mut found = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path).expect("the source file reads");
        let file = label(&root, path);
        for (n, function, what) in core_calls(&source) {
            if file == DECIDES {
                decides.push(what);
            } else {
                found.push(format!("{file}:{n}: {function}: {what}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "the settlement core is stepped, polled, reaped or closed outside {DECIDES}: \
         {found:?}"
    );
    for want in [".step(", ".reap_leg("] {
        assert!(
            decides.iter().any(|w| w == want),
            "{DECIDES} calls the core's `{want}`: {decides:?}"
        );
    }
}

/// The changes of a peer's machines the settlement core's join takes.
const CHANGES: &[&str] = &["Start", "Shift", "Stop"];

/// Each change of machines the code of `source` asks the join for, as
/// `(line, function, change)`: an `Event::Shift` anywhere, since no other
/// event has that variant, and an `Event::Start` or `Event::Stop` in a
/// function that calls the join or in a file that names its module. A call
/// of the join is `join(` or `join::<` not after a `.`, so a thread's or a
/// path's `.join(` is not one.
fn join_changes(source: &str) -> Vec<(usize, String, String)> {
    let toks = tokens(source);
    let fns = within(&toks);
    let names_join = (0..toks.len()).any(|i| reads(&toks, i, &["settle", ":", ":", "join"]));
    let calls: Vec<&String> = (0..toks.len())
        .filter(|&i| {
            toks[i].1 == "join"
                && !after(&toks, i, ".")
                && (reads(&toks, i + 1, &["("]) || reads(&toks, i + 1, &[":", ":", "<"]))
        })
        .map(|i| &fns[i])
        .collect();
    let mut found = Vec::new();
    for (i, (n, t)) in toks.iter().enumerate() {
        if t != "Event" || !reads(&toks, i + 1, &[":", ":"]) {
            continue;
        }
        let Some((_, change)) = toks
            .get(i + 3)
            .filter(|(_, c)| CHANGES.contains(&c.as_str()))
        else {
            continue;
        };
        if change == "Shift" || names_join || calls.contains(&&fns[i]) {
            found.push((*n, fns[i].clone(), change.clone()));
        }
    }
    found
}

/// The one function of `peer/active.rs` that asks the join for each change
/// of a peer's machines.
const ACTIVE: &[(&str, &str)] = &[
    ("with_session", "Start"),
    ("rebuild", "Shift"),
    ("stop", "Stop"),
];

/// The functions outside the executor that call the active peer's
/// functions which ask for a change of machines, as `(file, function,
/// callee, why)`.
const SITES: &[(&str, &str, &str, &str)] = &[
    (
        "node/handlers/handshake.rs",
        "msg2_body",
        "adopt_dial",
        "a crossing's move at this node's dial's msg2, whose machine part a test may \
         run alone: the site calls it, then runs the rest of the move through the \
         executor",
    ),
    (
        "node/dataplane/establish.rs",
        "cross_inbound",
        "adopt_dial",
        "a crossing's move at the peer's msg3: the site calls it, then runs the \
         rest of the move through the executor",
    ),
];

/// Each call in the code of `source` of the active peer's functions that
/// ask the join for a change of machines, as `(line, function, callee)`:
/// `with_session(`, `adopt_dial(`, and a `.stop()` that is not awaited,
/// which the node's and the transports' own stops are.
fn change_calls(source: &str) -> Vec<(usize, String, String)> {
    let toks = tokens(source);
    let fns = within(&toks);
    let mut found = Vec::new();
    for (i, (n, t)) in toks.iter().enumerate() {
        let after_fn = after(&toks, i, "fn");
        let called =
            (t == "with_session" || t == "adopt_dial") && reads(&toks, i + 1, &["("]) && !after_fn;
        let stopped = t == "stop"
            && after(&toks, i, ".")
            && reads(&toks, i + 1, &["(", ")"])
            && !reads(&toks, i + 3, &[".", "await"]);
        if called || stopped {
            found.push((*n, fns[i].clone(), t.clone()));
        }
    }
    found
}

/// Only the active peer asks the settlement core's join to build, move or
/// close a peer's machines, each change from its one function, and only
/// the executor calls those functions in the node's code, but for the move,
/// which its two sites call before running the rest through the executor,
/// and the listed site no handshake reaches. The
/// planted lines show the scan finds an `Event::Shift` built anywhere and a
/// start or a stop in a function that calls the join, and not the
/// supervisor's own start and stop, a thread's `.join()`, or a change named
/// in a comment.
#[test]
fn only_active_calls_join_for_a_change_of_machines() {
    let planted = "impl Node {\n\
                   \x20   fn shortcut(&mut self, addr: NodeAddr) {\n\
                   \x20       // join(addr, Event::Start { .. }) in a comment asks nothing.\n\
                   \x20       let event = Event::Shift { rekey, bundle, setup, caps, to, env };\n\
                   \x20       let _ = join(addr, event);\n\
                   \x20   }\n\
                   \x20   fn closing(&mut self, addr: NodeAddr) {\n\
                   \x20       let _ = join::<P, C, E, D>(addr, Event::Stop { rekey, bundle, why });\n\
                   \x20   }\n\
                   \x20   fn supervise(&mut self) {\n\
                   \x20       let _ = self.supervisor.fsm.step(Event::Stop);\n\
                   \x20       let _ = handle.join();\n\
                   \x20   }\n\
                   \x20   fn bring_up(&mut self) {\n\
                   \x20       let peer = ActivePeer::with_session(identity, link, caps);\n\
                   \x20       peer.stop();\n\
                   \x20       self.stop().await;\n\
                   \x20   }\n\
                   }\n";
    let at = |n: usize, f: &str, w: &str| (n, f.to_string(), w.to_string());
    assert_eq!(
        join_changes(planted),
        [at(4, "shortcut", "Shift"), at(8, "closing", "Stop")],
        "the scan finds a planted shift anywhere and a stop where the join is called, \
         and not the supervisor's stop, a thread's join, or a comment"
    );
    assert_eq!(
        change_calls(planted),
        [
            at(15, "bring_up", "with_session"),
            at(16, "bring_up", "stop")
        ],
        "the scan finds a planted build and close of a peer's machines, and not an \
         awaited stop"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let exec = root.join("node").join("settle").join("exec");
    let mut files = Vec::new();
    sources(&root, &mut files);
    let mut changes = Vec::new();
    let mut outside = Vec::new();
    let mut sites = Vec::new();
    let mut executor = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path).expect("the source file reads");
        let file = label(&root, path);
        for (n, function, change) in join_changes(&source) {
            if file == "peer/active.rs" {
                changes.push((function, change));
            } else {
                outside.push(format!("{file}:{n}: {function}: Event::{change}"));
            }
        }
        if !path.starts_with(root.join("node")) {
            continue;
        }
        for (n, function, callee) in change_calls(&source) {
            if path.starts_with(&exec) {
                executor.push(callee);
            } else if SITES
                .iter()
                .any(|(f, w, c, _)| *f == file && *w == function && *c == callee)
            {
                sites.push(callee);
            } else {
                outside.push(format!("{file}:{n}: {function}: {callee}"));
            }
        }
    }
    assert!(
        outside.is_empty(),
        "a change of a peer's machines is asked for outside the active peer and the \
         executor: {outside:?}"
    );
    let want: Vec<(String, String)> = ACTIVE
        .iter()
        .map(|(f, c)| (f.to_string(), c.to_string()))
        .collect();
    assert_eq!(
        changes, want,
        "the active peer asks the join for each change of machines once, from its one function"
    );
    for callee in ["with_session", "stop"] {
        assert!(
            executor.iter().any(|c| c == callee),
            "the executor calls `{callee}`: {executor:?}"
        );
    }
    assert_eq!(
        sites.len(),
        SITES.len(),
        "each listed site still calls its function: {sites:?} against {SITES:?}"
    );
    for want in [
        "peer/active.rs",
        "node/handlers/handshake.rs",
        "node/handlers/rekey.rs",
        "node/lifecycle/mod.rs",
        "node/settle/exec/links.rs",
    ] {
        assert!(files.iter().any(|p| p.ends_with(want)), "{want} is scanned");
    }
}

/// The item each token is in: the innermost function by its name; else a
/// `const` or `static` item as `const NAME` or `static NAME`; else a `use`
/// statement, as `use`, or as `pub use` for a re-export at any visibility;
/// else empty. Unlike [`within`], an item after a function's body is not
/// put in that function.
fn scope(toks: &[Token]) -> Vec<String> {
    let mut out = Vec::with_capacity(toks.len());
    let mut depth = 0usize;
    // The open functions, by the depth their body opened at.
    let mut fns: Vec<(usize, String)> = Vec::new();
    // A function named and not yet opened, which a `;` drops.
    let mut pending: Option<String> = None;
    // The `const`, `static` or `use` item open, and the depth it ends at.
    let mut item: Option<(usize, String)> = None;
    // Open parentheses and brackets, inside which a `;` (`[u8; 8]`) ends
    // nothing.
    let mut nest = 0usize;
    for (i, (_, t)) in toks.iter().enumerate() {
        let name = |k: usize| toks.get(k).map(|(_, w)| w.as_str()).unwrap_or("");
        let ident = |w: &str| w.chars().all(|c| c.is_alphanumeric() || c == '_') && !w.is_empty();
        if item.is_none() {
            if t == "fn" && ident(name(i + 1)) {
                pending = Some(name(i + 1).to_string());
            } else if (t == "const" || t == "static")
                && ident(name(i + 1))
                && name(i + 2) == ":"
                && !i
                    .checked_sub(1)
                    .is_some_and(|b| ["<", ",", "'", "*", "&", "("].contains(&name(b)))
            {
                // An item, not a lifetime (`&'static`), a raw pointer
                // (`*const`) or a const generic (`<const N: usize>`).
                item = Some((depth, format!("{t} {}", name(i + 1))));
            } else if t == "use" {
                let public = (0..i)
                    .rev()
                    .map(name)
                    .take_while(|w| ![";", "}", "{"].contains(w))
                    .any(|w| w == "pub");
                item = Some((depth, if public { "pub use" } else { "use" }.to_string()));
            }
        }
        let label = match (&item, fns.last()) {
            (Some((_, it)), _) => it.clone(),
            (None, Some((_, f))) => f.clone(),
            (None, None) => String::new(),
        };
        out.push(label);
        match t.as_str() {
            "{" => {
                if item.is_none()
                    && let Some(f) = pending.take()
                {
                    fns.push((depth, f));
                }
                depth += 1;
            }
            "}" => {
                depth = depth.saturating_sub(1);
                if fns.last().is_some_and(|(d, _)| *d == depth) {
                    fns.pop();
                }
            }
            "(" | "[" => nest += 1,
            ")" | "]" => nest = nest.saturating_sub(1),
            ";" if nest == 0 => {
                if item.as_ref().is_some_and(|(d, _)| *d == depth) {
                    item = None;
                }
                pending = None;
            }
            _ => {}
        }
    }
    out
}

/// The settlement core's gate constants: the fields of its parameters
/// (`proto::settle::params::Params`) that the core holds and no
/// configuration moves, the restart gates' floors, dampener, replay memory
/// and silent-session back-off. `silent`, the count of silent sessions
/// before a refusal, is left out: the node's records of a refusal in force
/// have a field of that name, which a read cannot be told from.
const GATES: &[&str] = &[
    "unheard",
    "interval",
    "replays",
    "silentbase",
    "silentcap",
    "horizon",
    "counted",
];

/// The node's functions that give it the settlement core's parameters.
const TAKERS: &[&str] = &["settle_params", "leg_params", "gate_params"];

/// The rekey machine's parameters a node could read a decision from: the
/// fields of its configuration (`proto::rekey::Config`) that set its
/// jitter, drain, holds, dampening, lifetimes, age floors and send limits.
const REKEYS: &[&str] = &[
    "jitter",
    "drain",
    "retention",
    "hold",
    "revert",
    "dampening",
    "ttl",
    "young",
    "link_age",
    "session_age",
    "floor_link",
    "floor_session",
    "floor_cutover",
    "soft",
    "hard",
];

/// The rekey machine's constants and the node's copies of its parameters:
/// the deployed session floor, the largest time trigger and the msg1
/// resend span the machine publishes, and the node's cap on a link rekey's
/// handshake and its rekey jitter.
const REKEY_NAMES: &[&str] = &[
    "DEPLOYED_SESSION_FLOOR",
    "MAX_AFTER",
    "msg1_span",
    "REKEY_HANDSHAKE",
    "REKEY_JITTER_SECS",
];

/// Whether `name` names a node address, as the root crate's code names
/// one: `local`, `peer`, `me`, `ours` or `theirs`, or a lower-case name
/// ending in `addr` (`our_addr`, `peer_addr`, `node_addr`).
fn addressed(name: &str) -> bool {
    ["local", "peer", "me", "ours", "theirs"].contains(&name)
        || (name.ends_with("addr") && !name.chars().any(|c| c.is_ascii_uppercase()))
}

/// The identifier that ends the operand before the token at `at`, past a
/// call's or an index's balanced brackets: `node_addr` in
/// `self.identity().node_addr() <`.
fn operand_before(toks: &[Token], at: usize) -> &str {
    let mut i = at;
    let mut depth = 0usize;
    while i > 0 {
        i -= 1;
        match toks[i].1.as_str() {
            ")" | "]" => depth += 1,
            "(" | "[" if depth > 0 => depth -= 1,
            t if depth == 0 => return t,
            _ => {}
        }
    }
    ""
}

/// The identifier that ends the operand from the token at `at` on, past
/// borrows, dereferences and parentheses before it and the field reads,
/// calls and path steps of its chain: `peer_addr` in `&peer_addr`,
/// `node_addr` in `self.identity().node_addr()`.
fn operand_after(toks: &[Token], at: usize) -> &str {
    let mut i = at;
    while toks
        .get(i)
        .is_some_and(|(_, t)| ["&", "*", "(", "!", "-", "mut"].contains(&t.as_str()))
    {
        i += 1;
    }
    let mut last = "";
    while let Some((_, t)) = toks.get(i) {
        if t.chars().all(|c| c.is_alphanumeric() || c == '_') {
            last = t;
            i += 1;
        } else if t == "." || (t == ":" && reads(toks, i + 1, &[":"])) {
            i += if t == "." { 1 } else { 2 };
        } else if t == "(" && reads(toks, i + 1, &[")"]) {
            i += 2;
        } else {
            break;
        }
    }
    last
}

/// The tokens of the statement that starts at `at`, up to its `;`.
fn statement(toks: &[Token], at: usize) -> impl Iterator<Item = &str> {
    toks[at..]
        .iter()
        .map(|(_, t)| t.as_str())
        .take_while(|t| *t != ";")
}

/// Whether the code of `toks` names the settlement core's parameters: a
/// `use` of `Params` from `settle::params`, the path
/// `settle::params::Params`, or a call of one of [`TAKERS`].
fn names_gates(toks: &[Token], scopes: &[String]) -> bool {
    (0..toks.len()).any(|i| {
        toks[i].1 == "settle"
            && if scopes[i].ends_with("use") {
                statement(toks, i).any(|t| t == "params")
                    && statement(toks, i).any(|t| t == "Params")
            } else {
                reads(toks, i + 1, &[":", ":", "params", ":", ":", "Params"])
            }
    }) || (0..toks.len())
        .any(|i| TAKERS.contains(&toks[i].1.as_str()) && reads(toks, i + 1, &["("]))
}

/// Whether the code of `toks` names the rekey machine's parameters: a `use`
/// of its `Config` or `Params` from `rekey`, or the path `rekey::Config` or
/// `rekey::Params`.
fn names_rekey(toks: &[Token], scopes: &[String]) -> bool {
    (0..toks.len()).any(|i| {
        toks[i].1 == "rekey"
            && if scopes[i].ends_with("use") {
                statement(toks, i).any(|t| t == "Config" || t == "Params")
            } else {
                reads(toks, i + 1, &[":", ":"])
                    && toks
                        .get(i + 3)
                        .is_some_and(|(_, t)| t == "Config" || t == "Params")
            }
    })
}

/// Each decision input in the code of `source`, as `(line, item, what)`,
/// leaving out a `use` that is not a re-export:
///
/// - `gate`: in a file that names the settlement core's parameters, a gate
///   constant read (`.interval`, any of [`GATES`], not a call), the
///   parameters built (a `Params { .. }` literal, `Params::default`), or
///   one of [`TAKERS`] called;
/// - `rekey`: one of [`REKEY_NAMES`]; and in a file that names the rekey
///   machine's parameters, its configuration or parameters built
///   (`Config::fmp`, `Config::fsp`, a `Config { .. }` literal,
///   `Params::new`, `Params::fmp`, `Params::fsp`) or one of [`REKEYS`]
///   read;
/// - `order`: `cross_connection_winner`; a comparison (`<`, `>`, `<=`,
///   `>=`) with an operand that names a node address ([`addressed`]); and
///   a `.cmp(`, `.partial_cmp(`, `.min(` or `.max(` whose receiver or
///   argument names one.
fn decision_inputs(source: &str) -> Vec<(usize, String, String)> {
    let toks = tokens(source);
    let gaps = gaps(source);
    let scopes = scope(&toks);
    let gates = names_gates(&toks, &scopes);
    let rekey = names_rekey(&toks, &scopes);
    let word = |k: usize| toks.get(k).map(|(_, w)| w.as_str()).unwrap_or("");
    let gap = |k: usize| gaps.get(k).copied().unwrap_or(true);
    let literal = |k: usize| {
        reads(&toks, k + 1, &["{"])
            && !k
                .checked_sub(1)
                .is_some_and(|b| [">", "impl", "struct", "enum", "for"].contains(&word(b)))
    };
    // The module a name at `k` is reached through, when it is written by
    // its path (`path::Config`), or none for a name the file imports.
    let module =
        |k: usize| (k >= 3 && word(k - 1) == ":" && word(k - 2) == ":").then(|| word(k - 3));
    let mut found = Vec::new();
    for (i, (n, t)) in toks.iter().enumerate() {
        if scopes[i] == "use" {
            continue;
        }
        let field = after(&toks, i, ".") && !reads(&toks, i + 1, &["("]);
        let path =
            |names: &[&str]| reads(&toks, i + 1, &[":", ":"]) && names.contains(&word(i + 3));
        let settled = module(i).is_none_or(|m| m == "params");
        let rekeyed = module(i).is_none_or(|m| m == "rekey");
        let what = if gates && GATES.contains(&t.as_str()) && field {
            Some(format!("gate .{t}"))
        } else if gates && t == "Params" && settled && literal(i) {
            Some("gate Params {".to_string())
        } else if gates && t == "Params" && settled && path(&["default"]) {
            Some("gate Params::default".to_string())
        } else if gates
            && TAKERS.contains(&t.as_str())
            && reads(&toks, i + 1, &["("])
            && !after(&toks, i, "fn")
        {
            Some(format!("gate {t}("))
        } else if REKEY_NAMES.contains(&t.as_str()) {
            Some(format!("rekey {t}"))
        } else if rekey && t == "Config" && rekeyed && literal(i) {
            Some("rekey Config {".to_string())
        } else if rekey
            && rekeyed
            && ((t == "Config" && path(&["fmp", "fsp"]))
                || (t == "Params" && path(&["new", "fmp", "fsp"])))
        {
            Some(format!("rekey {t}::{}", word(i + 3)))
        } else if rekey && REKEYS.contains(&t.as_str()) && field {
            Some(format!("rekey .{t}"))
        } else if t == "cross_connection_winner" {
            Some(format!("order {t}"))
        } else if (t == "<" || t == ">") && gap(i) {
            // A comparison, spaced as rustfmt writes one, and not a `->`,
            // `=>`, shift or generic, which it writes unspaced.
            let eq = word(i + 1) == "=" && !gap(i + 1);
            let right = i + 1 + usize::from(eq);
            (gap(right)
                && (addressed(operand_before(&toks, i)) || addressed(operand_after(&toks, right))))
            .then(|| format!("order {t}{}", if eq { "=" } else { "" }))
        } else if t == "."
            && ["cmp", "partial_cmp", "min", "max"].contains(&word(i + 1))
            && reads(&toks, i + 2, &["("])
        {
            (addressed(operand_before(&toks, i)) || addressed(operand_after(&toks, i + 3)))
                .then(|| format!("order .{}(", word(i + 1)))
        } else {
            None
        };
        if let Some(what) = what {
            found.push((*n, scopes[i].clone(), what));
        }
    }
    found
}

/// The items of the root crate where a decision input may appear, as
/// `(file, item, test builds only, why)`; an item of `*` is the whole file.
const INPUTS: &[(&str, &str, bool, &str)] = &[
    (
        "node/settle/params.rs",
        "*",
        false,
        "the configuration mapping: the settlement core's parameters with the \
         handshake timers, the cap on answers in flight and the max-peers cap \
         taken from the node's configuration, and the gate constants left at \
         the core's defaults or set to the XX flow's own",
    ),
    (
        "node/handlers/rekey.rs",
        "link_params",
        false,
        "the configuration mapping for a link's rekey machine",
    ),
    (
        "node/handlers/rekey.rs",
        "ladder_ms",
        false,
        "the span of a link rekey's msg1 resends, which the silence the node \
         keeps a link through allows for, taken from the machine so the two \
         cannot differ",
    ),
    (
        "node/handlers/rekey.rs",
        "const REKEY_HANDSHAKE",
        false,
        "the 30 s cap on a link rekey's handshake, which `link_params` applies \
         and the configuration's warning names",
    ),
    (
        "node/mod.rs",
        "pub use",
        false,
        "`REKEY_HANDSHAKE` re-exported for the configuration's warning",
    ),
    (
        "node/mod.rs",
        "const REKEY_JITTER_SECS",
        false,
        "the rekey jitter the configuration's validation reads, held to both \
         profiles' by compile-time assertions",
    ),
    (
        "node/session/mod.rs",
        "session_params",
        false,
        "the configuration mapping for a session's rekey machine, as \
         `link_params` is for a link's",
    ),
    (
        "node/session/mod.rs",
        "const _",
        false,
        "the compile-time assertion that the session profile's jitter is \
         `REKEY_JITTER_SECS`",
    ),
    (
        "peer/mod.rs",
        "const _",
        false,
        "the compile-time assertions that the link profile's jitter, drain \
         window and dampening are the deployed link shell's",
    ),
    (
        "peer/mod.rs",
        "test_link_params",
        true,
        "a test's link machine parameters, the link defaults",
    ),
    (
        "config/mod.rs",
        "validate_rendezvous",
        false,
        "the configuration's refusal of a rekey interval at or below the jitter",
    ),
    (
        "config/mod.rs",
        "test_validate_rekey_after_secs_at_or_below_jitter_rejected",
        true,
        "a test of that refusal",
    ),
    (
        "config/mod.rs",
        "test_validate_rekey_after_secs_just_above_jitter_accepted",
        true,
        "a test of that refusal",
    ),
    (
        "config/floors.rs",
        "warn_rekey",
        false,
        "the configuration's warning that link rekeys cap a handshake timeout \
         above 30 s",
    ),
    (
        "lib.rs",
        "pub use",
        false,
        "`cross_connection_winner` published for the crate's users, \
         re-exported from fips-core, where the ordering is",
    ),
    (
        "node/lifecycle/mod.rs",
        "poll_nostr_rendezvous",
        false,
        "NAT traversal's adopter of a dual cross-init: which end gives up its \
         dial to adopt the fresh traversal socket, before any handshake, which \
         the settlement core then settles",
    ),
    (
        "node/settle/exec/install.rs",
        "settle_link",
        false,
        "the transport's choice of which of two connections at a promoted \
         link's address to keep, below the link layer: the one the smaller \
         node dialled, by the rule that settles crossed handshakes, so both \
         ends keep the same one",
    ),
    (
        "node/settle/mod.rs",
        "leg_params",
        true,
        "a test's handshake legs' parameters, through the configuration mapping",
    ),
    (
        "nostr/traversal_machine.rs",
        "suppress_responder_for_own_initiator",
        false,
        "NAT traversal's choice of one traversal session of two, before any \
         link exists",
    ),
];

/// No settlement or rekey decision input appears in the root crate's code
/// outside its tests but on the list of [`INPUTS`], each with its reason:
/// the settlement core's gate constants, the rekey machine's parameters
/// and the node-address ordering stay in `fips-core`, and the node only
/// maps its configuration onto them. Each listed item still holds an
/// input, and each one listed for test builds only is `#[cfg(test)]`. The
/// planted lines show the scan finds each shape, in code and in its item,
/// and not a name in a comment, a string or a private `use`, a generic's
/// brackets, or a comparison of other values.
#[test]
fn the_gate_constants_rekey_parameters_and_address_order_appear_only_on_the_exempt_list() {
    let planted = "use crate::proto::settle::params::Params;\n\
                   use fips_core::proto::rekey::{Config, MAX_AFTER};\n\
                   pub use proto::fmp::cross_connection_winner;\n\
                   const FLOOR: u64 = MAX_AFTER;\n\
                   impl Node {\n\
                   \x20   fn shortcut(&self, peer_addr: &NodeAddr, local: NodeAddr) -> Vec<NodeAddr> {\n\
                   \x20       // params.interval in a comment reads nothing.\n\
                   \x20       let params = self.gate_params();\n\
                   \x20       let young = age < params.interval;\n\
                   \x20       let p = Params { unheard: ZERO, ..Params::default() };\n\
                   \x20       let c = Config::fmp();\n\
                   \x20       let floor = c.link_age;\n\
                   \x20       let wait = msg1_span(5);\n\
                   \x20       let wins = cross_connection_winner(a, b, true);\n\
                   \x20       if self.identity().node_addr() < peer_addr {}\n\
                   \x20       if local >= *peer_addr {}\n\
                   \x20       let first = local.cmp(&other);\n\
                   \x20       let lower = a.min(*peer_addr);\n\
                   \x20       let note = \"params.interval < peer_addr\";\n\
                   \x20       if count > 0 && x.len() <= limit {}\n\
                   \x20       let map: HashMap<NodeAddr, Vec<u8>> = HashMap::new();\n\
                   \x20       let q = fips_core::proto::path::Params::new(cfg);\n\
                   \x20       let steps = join::<LinkProfile, PeerClock>(*node_addr, event);\n\
                   \x20       let wide: Vec<String> = ours[..n].to_vec();\n\
                   \x20       Vec::new()\n\
                   \x20   }\n\
                   }\n\
                   fn tail<const N: usize>(p: *const u8) -> &'static str { if local < peer {} \"\" }\n";
    let at = |n: usize, f: &str, w: &str| (n, f.to_string(), w.to_string());
    assert_eq!(
        decision_inputs(planted),
        [
            at(3, "pub use", "order cross_connection_winner"),
            at(4, "const FLOOR", "rekey MAX_AFTER"),
            at(8, "shortcut", "gate gate_params("),
            at(9, "shortcut", "gate .interval"),
            at(10, "shortcut", "gate Params {"),
            at(10, "shortcut", "gate Params::default"),
            at(11, "shortcut", "rekey Config::fmp"),
            at(12, "shortcut", "rekey .link_age"),
            at(13, "shortcut", "rekey msg1_span"),
            at(14, "shortcut", "order cross_connection_winner"),
            at(15, "shortcut", "order <"),
            at(16, "shortcut", "order >="),
            at(17, "shortcut", "order .cmp("),
            at(18, "shortcut", "order .min("),
            at(28, "tail", "order <"),
        ],
        "the scan finds each shape of decision input in code, in its item, and \
         not one in a comment, a string or a private use, a generic, or another \
         comparison"
    );
    let elsewhere = "use crate::proto::settle::input::Input;\n\
                     use fips_core::proto::path::{Config, Params};\n\
                     fn build(c: Config) -> u64 {\n\
                     \x20   let p = Params::new(Config { probe: 1, ..c });\n\
                     \x20   p.interval + p.hold\n\
                     }\n";
    assert_eq!(
        decision_inputs(elsewhere),
        [],
        "a file that names the settlement core's inputs and another module's \
         parameters does not name the core's parameters or the rekey machine's"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    let mut listed = Vec::new();
    let mut found = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path).expect("the source file reads");
        let file = label(&root, path);
        for (n, item, what) in decision_inputs(&source) {
            match INPUTS
                .iter()
                .find(|(f, w, ..)| *f == file && (*w == item || *w == "*"))
            {
                Some(&(_, w, gated, _)) => {
                    assert!(
                        !gated || test_only(&source, &item),
                        "{file}'s `{item}` is listed as test-only code, and is not \
                         `#[cfg(test)]`"
                    );
                    listed.push((file.clone(), w.to_string()));
                }
                None => found.push(format!("{file}:{n}: {item}: {what}")),
            }
        }
    }
    assert!(
        found.is_empty(),
        "a settlement or rekey decision input appears outside the exempt list: {found:#?}"
    );
    let stale: Vec<String> = INPUTS
        .iter()
        .filter(|(f, w, ..)| !listed.iter().any(|(file, item)| file == f && item == w))
        .map(|(f, w, ..)| format!("{f}'s `{w}`"))
        .collect();
    assert!(
        stale.is_empty(),
        "these exemptions name no input any more: {stale:?}"
    );
    for want in [
        "lib.rs",
        "node/handlers/rekey.rs",
        "node/settle/params.rs",
        "node/lifecycle/mod.rs",
        "transport/ble/mod.rs",
    ] {
        assert!(files.iter().any(|p| p.ends_with(want)), "{want} is scanned");
    }
}
