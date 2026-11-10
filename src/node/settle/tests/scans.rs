//! The scans that hold every call of a peer's machines to the settlement
//! core's join and the executor: no code of the root crate outside its
//! tests builds, renews or closes a link's rekey or path machine itself,
//! only the active peer asks the join to build, move or close them, and
//! only the executor, or the move's site, asks the active peer.

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

/// Whether `function` in `source` carries `#[cfg(test)]` among the
/// attributes and comments directly above its `fn` line.
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
            .any(|l| l == "#[cfg(test)]")
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
const SITES: &[(&str, &str, &str, &str)] = &[(
    "node/handlers/handshake.rs",
    "msg2_body",
    "move_session",
    "a crossing's move, whose machine part a test may run alone: the site \
     calls it, then runs the rest of the move through the executor",
)];

/// Each call in the code of `source` of the active peer's functions that
/// ask the join for a change of machines, as `(line, function, callee)`:
/// `with_session(`, `move_session(`, and a `.stop()` that is not awaited,
/// which the node's and the transports' own stops are.
fn change_calls(source: &str) -> Vec<(usize, String, String)> {
    let toks = tokens(source);
    let fns = within(&toks);
    let mut found = Vec::new();
    for (i, (n, t)) in toks.iter().enumerate() {
        let after_fn = after(&toks, i, "fn");
        let called = (t == "with_session" || t == "move_session")
            && reads(&toks, i + 1, &["("])
            && !after_fn;
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
/// which its site calls before running the rest through the executor. The
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
