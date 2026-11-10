//! Tests for `../exec/remove.rs`: every way the node removes a peer runs the
//! one removal routine, which is the only code outside the tests that takes
//! a peer out of the peer map.

use crate::node::tests::survivors::{label, sources};
use std::path::Path;

/// Code that takes a peer out of the map other than the removal routine,
/// as `(file, function, why it is not a removal)`.
const EXEMPT: &[(&str, &str, &str)] = &[
    (
        "node/mod.rs",
        "remove_peer",
        "a public method every caller of which is a test, which hands the peer back unremoved",
    ),
    (
        "node/handlers/handshake.rs",
        "promote_connection",
        "its tie-break replacement of a held peer, which no handshake reaches: both callers' \
         decisions promote only with no peer held",
    ),
];

/// Each `peers.take` in the code of `source`, as `(line, function)`: the
/// function is the last one whose `fn` came before it.
fn takes(source: &str) -> Vec<(usize, String)> {
    let idents = fips_core::proto::rekey::code_idents(source);
    let mut within = String::new();
    let mut found = Vec::new();
    for (i, (n, w)) in idents.iter().enumerate() {
        let next = idents
            .get(i + 1)
            .filter(|(m, _)| m == n)
            .map(|(_, next)| next);
        if w == "fn"
            && let Some(name) = next
        {
            within.clone_from(name);
        }
        if w == "peers" && next.is_some_and(|next| next == "take") {
            found.push((*n, within.clone()));
        }
    }
    found
}

/// Outside the executor, nothing in the node's code takes a peer out of
/// the peer map but the one listed exemption, and inside it only the
/// removal routine does, once: so a disconnect, a dead or orphaned link, a
/// replacement, an ended link and the operator's disconnect all go through
/// it. The planted lines show the scan finds a take in code, names the
/// function it is in, and does not count one in a comment.
#[test]
fn every_remove_path_runs_one_routine() {
    let planted = "impl Node {\n\
                   \x20   fn evict(&mut self, addr: &NodeAddr) {\n\
                   \x20       // self.peers.take(addr) in a comment takes nothing.\n\
                   \x20       let mut peer = match self.peers.take(addr) {\n\
                   \x20           Some(p) => p,\n\
                   \x20           None => return,\n\
                   \x20       };\n\
                   \x20   }\n\
                   }\n";
    assert_eq!(
        takes(planted),
        [(4, "evict".to_string())],
        "the scan finds a planted take in code, in its function, and not one in a comment"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let node = root.join("node");
    let exec = node.join("settle").join("exec");
    let mut files = Vec::new();
    sources(&node, &mut files);
    let mut routine = Vec::new();
    let mut exempt = Vec::new();
    let mut found = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path).expect("the source file reads");
        let file = label(&root, path);
        for (n, within) in takes(&source) {
            let at = format!("{file}:{n}: {within}");
            if path.starts_with(&exec) {
                routine.push(at);
            } else if EXEMPT.iter().any(|(f, w, _)| *f == file && *w == within) {
                exempt.push(at);
            } else {
                found.push(at);
            }
        }
    }
    assert!(
        found.is_empty(),
        "a peer is taken out of the map outside the removal routine: {found:?}"
    );
    assert!(
        routine.len() == 1 && routine[0].starts_with("node/settle/exec/remove.rs:"),
        "the executor takes a peer out of the map once, in the removal routine: {routine:?}"
    );
    assert!(
        routine[0].ends_with(": remove"),
        "the executor's one take is in the removal routine: {routine:?}"
    );
    assert!(
        exempt.len() == EXEMPT.len(),
        "each exemption still names a take: {exempt:?} against {EXEMPT:?}"
    );
    // The scan reaches every site that removes a peer, and leaves the
    // node's tests out.
    for want in [
        "node/dataplane/dispatch.rs",
        "node/dataplane/peer_actions.rs",
        "node/handlers/mmp.rs",
        "node/handlers/rekey.rs",
        "node/lifecycle/mod.rs",
        "node/settle/exec/remove.rs",
    ] {
        assert!(files.iter().any(|p| p.ends_with(want)), "{want} is scanned");
    }
    assert!(
        !files.iter().any(|p| p.starts_with(node.join("tests"))),
        "the node's tests are not scanned"
    );
}
