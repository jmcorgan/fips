//! The settlement core explored against the models of deployed nodes:
//! the current node (`master.rs`) and the deployed one (`maint.rs`).
//!
//! Each run is a named start with the core at one node and a legacy model
//! at the others, explored to the start's depth and healed at each leaf.
//! Every start but the two paths runs, which the legacy models do not
//! know, with the core at node 0 and at node 1, and in both address
//! orders: a two-node start runs once as written and once with its
//! identities exchanged ([`flipped`]), so the core is the smaller and the
//! larger node in each role the start gives. The late second dial carries
//! both orders as its two variants already, and the three-node start is
//! not built as a pair, so neither is flipped.
//!
//! What must hold:
//!
//! - one session (`OneSession`) at every node, except on a path that
//!   showed a known shape, the two defects left for later included
//!   ([`by_any_shape`]);
//! - every other property at the core's node;
//! - at a legacy node, the other properties' breaches are that node's
//!   known defects and its named differences from the model, and are
//!   counted by property and printed, not asserted.
//!
//! A pairing that does not converge is a finding against the core or a
//! deployed node and is reported with its schedule, not fixed here: each
//! one found is listed in `not-converging.txt`, and the tests fail when a
//! run shows a breach the file does not list, or a listed one no longer
//! shows, so the list cannot go stale.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::super::model::history::Node;
use super::super::explore::Act;
use super::super::oracle::{Breach, Oracle, Swept, by_any_shape, sweep};
use super::super::party::Configured;
use super::super::starts::{Maker, Start, flipped, starts};
use super::super::stub::core;
use super::super::world::Party;
use super::maint::maint;
use super::master::master;

fn core_master(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    if ix == 0 {
        core(ix, me, configured)
    } else {
        master(ix, me, configured)
    }
}

fn master_core(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    if ix == 1 {
        core(ix, me, configured)
    } else {
        master(ix, me, configured)
    }
}

fn core_maint(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    if ix == 0 {
        core(ix, me, configured)
    } else {
        maint(ix, me, configured)
    }
}

fn maint_core(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    if ix == 1 {
        core(ix, me, configured)
    } else {
        maint(ix, me, configured)
    }
}

/// Which deployed node the core runs against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Legacy {
    /// The current node.
    Master,
    /// The deployed node.
    Maint,
}

impl Legacy {
    /// The maker with the core at node `at` and this model elsewhere.
    fn maker(self, at: usize) -> Maker {
        match (self, at) {
            (Self::Master, 0) => core_master,
            (Self::Master, _) => master_core,
            (Self::Maint, 0) => core_maint,
            (Self::Maint, _) => maint_core,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Master => "master",
            Self::Maint => "maint",
        }
    }
}

/// One run: a start with the core at node `at`, in the start's address
/// order or the other.
struct Run {
    st: Start,
    legacy: Legacy,
    at: usize,
    flip: bool,
}

impl Run {
    /// The run's name, as `not-converging.txt` lists it.
    fn name(&self) -> String {
        let order = if self.flip { "flipped" } else { "as written" };
        format!(
            "{}: core at n{} against {}, {order}",
            self.st.name,
            self.at,
            self.legacy.name()
        )
    }

    fn sweep(&self) -> Swept {
        let go = || sweep(&self.st, self.st.depth, &by_any_shape);
        if self.flip { flipped(go) } else { go() }
    }
}

/// The runs against `legacy` on the starts `numbers` admits, with the core
/// at each node of `ends`, in each address order when `orders`.
fn runs(legacy: Legacy, numbers: impl Fn(u8) -> bool, ends: &[usize], orders: bool) -> Vec<Run> {
    let mut out = Vec::new();
    for st in starts() {
        if st.number == 12 || !numbers(st.number) {
            continue;
        }
        let flips: &[bool] = if orders && !matches!(st.number, 5 | 6 | 11) {
            &[false, true]
        } else {
            &[false]
        };
        for &at in ends {
            for &flip in flips {
                let mut st = starts()
                    .into_iter()
                    .find(|s| s.name == st.name)
                    .expect("the start exists");
                st.maker = legacy.maker(at);
                out.push(Run {
                    st,
                    legacy,
                    at,
                    flip,
                });
            }
        }
    }
    out
}

/// What the runs found: the breaches that must not be there, by run, and
/// the legacy nodes' other breaches, counted by property.
struct Found {
    wrong: Vec<(String, Breach, Vec<Act>)>,
    known: Vec<(Oracle, usize)>,
}

/// Sweep every run on a thread of its own and sort what each found.
fn sweep_all(runs: &[Run]) -> Found {
    let report = std::thread::scope(|sc| {
        let hs: Vec<_> = runs
            .iter()
            .map(|r| {
                sc.spawn(move || {
                    let t = std::time::Instant::now();
                    let swept = r.sweep();
                    (swept, t.elapsed().as_millis())
                })
            })
            .collect();
        hs.into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect::<Vec<_>>()
    });
    let mut wrong = Vec::new();
    let mut known: Vec<(Oracle, usize)> = Vec::new();
    for (r, (swept, ms)) in runs.iter().zip(report) {
        std::eprintln!(
            "{}: {} states, {} leaves healed in {ms} ms, exempted {:?}",
            r.name(),
            swept.stats.states,
            swept.stats.leaves.len(),
            swept.exempted
        );
        for (b, path) in swept.found {
            if b.node != r.at && b.oracle != Oracle::OneSession {
                std::eprintln!(
                    "  known at the {} node n{}: {:?}: {}",
                    r.legacy.name(),
                    b.node,
                    b.oracle,
                    b.what
                );
                match known.iter_mut().find(|(o, _)| *o == b.oracle) {
                    Some((_, n)) => *n += 1,
                    None => known.push((b.oracle, 1)),
                }
            } else {
                wrong.push((r.name(), b, path));
            }
        }
    }
    known.sort();
    Found { wrong, known }
}

/// The pairings found not to converge, as `not-converging.txt` lists them:
/// the run, the property's name and the node.
fn not_converging() -> Vec<(&'static str, &'static str, usize)> {
    include_str!("not-converging.txt")
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut f = l.split('\t');
            let (Some(run), Some(oracle), Some(node), None) =
                (f.next(), f.next(), f.next(), f.next())
            else {
                panic!("not-converging.txt: a malformed line: {l:?}");
            };
            let node = node
                .parse()
                .unwrap_or_else(|_| panic!("not-converging.txt: a malformed node: {l:?}"));
            (run, oracle, node)
        })
        .collect()
}

/// Whether `list` holds the breach `b` of run `name`.
fn listed(list: &[(&str, &str, usize)], name: &str, b: &Breach) -> bool {
    let oracle = format!("{:?}", b.oracle);
    list.iter()
        .any(|&(n, o, x)| n == name && o == oracle && x == b.node)
}

/// Asserts that every wrong breach the runs found is listed, and that
/// every listed one for the runs made still shows.
fn check(found: &Found, runs: &[Run], label: &str) {
    std::eprintln!(
        "{label}: legacy-node breaches by property {:?}",
        found.known
    );
    let list = not_converging();
    let mut unlisted = Vec::new();
    for (name, b, path) in &found.wrong {
        std::eprintln!(
            "{name}: {:?} at n{}: {}\n  path {path:?}",
            b.oracle,
            b.node,
            b.what
        );
        if !listed(&list, name, b) {
            unlisted.push(format!("{name}: {:?} at n{}: {}", b.oracle, b.node, b.what));
        }
    }
    let names: Vec<String> = runs.iter().map(Run::name).collect();
    let stale: Vec<String> = list
        .iter()
        .filter(|(n, _, _)| names.iter().any(|m| m == n))
        .filter(|&&(n, o, x)| {
            !found
                .wrong
                .iter()
                .any(|(m, b, _)| m == n && format!("{:?}", b.oracle) == o && b.node == x)
        })
        .map(|(n, o, x)| format!("{n}: {o} at n{x}"))
        .collect();
    assert!(
        unlisted.is_empty() && stale.is_empty(),
        "{label}: not listed:\n{}\nlisted and no longer shown:\n{}",
        unlisted.join("\n"),
        stale.join("\n")
    );
}

#[test]
fn the_core_against_a_model_of_master_converges_on_every_start_in_both_address_orders() {
    let runs = runs(Legacy::Master, |_| true, &[0, 1], true);
    check(&sweep_all(&runs), &runs, "against master");
}

#[test]
fn the_core_against_a_model_of_maint_converges_on_every_start_in_both_address_orders() {
    let runs = runs(Legacy::Maint, |_| true, &[0, 1], true);
    check(&sweep_all(&runs), &runs, "against maint");
}
