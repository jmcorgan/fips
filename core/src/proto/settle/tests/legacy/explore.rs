//! A joint node explored against the models of deployed nodes: the current
//! node (`master.rs`), at either multipath setting, and the deployed one
//! (`maint.rs`), which has no setting.
//!
//! Each run is a named start with a joint node at one node and a model at
//! the others, explored to the start's depth and healed at each leaf, at
//! each pairing of a setting at the joint node with a model. Every start
//! runs, the ones on real bundles included: a model of the deployed node
//! never answers a capability probe, so its peer's link keeps its one path,
//! and the model of the current node does what its setting says. The joint
//! node runs at node 0 and at node 1, and in both address orders: a two-node
//! start runs once as written and once with its identities exchanged
//! ([`flipped`]), so the joint node is the smaller and the larger node in
//! each role the start gives. The late second dial carries both orders as
//! its two variants already, and the three-node start is not built as a
//! pair, so neither is flipped.
//!
//! What must hold:
//!
//! - one session (`OneSession`) at every node, except on a path that
//!   showed a known shape, the two defects left for later included
//!   ([`by_any_shape`]);
//! - every other property at the joint node, a proven path left with no
//!   connection aside ([`lapsed`], which `../joint/pins.rs` holds);
//! - at a legacy node, the other properties' breaches are that node's
//!   known defects and its named differences from the model, and are
//!   counted by property and printed, not asserted.
//!
//! A pairing that does not converge is a finding against the core or a
//! deployed node and is reported with its schedule, not fixed here: each
//! one found is listed in `not-converging.txt`, and the tests fail when a
//! run shows a breach the file does not list, or a listed one no longer
//! shows, so the list cannot go stale.
//!
//! A pairing's starts run one thread each, so a test takes as long as its
//! longest run on an idle host. At multipath on against the model at
//! multipath on, the links of [`CAPABLE`] and [`DOUBLED`] turn capable and
//! each healed leaf steps a minute of probes, so those run one test per
//! start group, and everything here is in the slow explorers' lane.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::super::model::history::Node;
use super::super::explore::Act;
use super::super::joint::explore::{CAPABLE, DOUBLED, lapsed};
use super::super::joint::starts::uncapped;
use super::super::joint::{self, Mode};
use super::super::oracle::{Breach, Oracle, Swept, by_any_shape, sweep};
use super::super::party::Configured;
use super::super::starts::{Maker, Start, flipped};
use super::super::world::{Party, World};
use super::maint::maint;
use super::master::{master, master_on};

/// Which deployed node the joint node runs against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Legacy {
    /// The current node, at its multipath setting.
    Master(Mode),
    /// The deployed node.
    Maint,
}

/// A joint node at node index `AT`, at multipath on when `ON`, and at every
/// other index the model `MODEL` names: 0 for the current node at multipath
/// off, 1 for it at multipath on, and otherwise the deployed node.
fn node<const ON: bool, const AT: usize, const MODEL: u8>(
    ix: usize,
    me: Node,
    configured: Vec<Configured>,
) -> Box<dyn Party> {
    if ix == AT {
        if ON {
            joint::on(ix, me, configured)
        } else {
            joint::off(ix, me, configured)
        }
    } else {
        match MODEL {
            0 => master(ix, me, configured),
            1 => master_on(ix, me, configured),
            _ => maint(ix, me, configured),
        }
    }
}

impl Legacy {
    /// The maker with a joint node at `mode` at node `at` and this model
    /// elsewhere.
    fn maker(self, mode: Mode, at: usize) -> Maker {
        match (self, mode, at) {
            (Self::Master(Mode::Off), Mode::Off, 0) => node::<false, 0, 0>,
            (Self::Master(Mode::Off), Mode::Off, _) => node::<false, 1, 0>,
            (Self::Master(Mode::Off), Mode::On, 0) => node::<true, 0, 0>,
            (Self::Master(Mode::Off), Mode::On, _) => node::<true, 1, 0>,
            (Self::Master(Mode::On), Mode::Off, 0) => node::<false, 0, 1>,
            (Self::Master(Mode::On), Mode::Off, _) => node::<false, 1, 1>,
            (Self::Master(Mode::On), Mode::On, 0) => node::<true, 0, 1>,
            (Self::Master(Mode::On), Mode::On, _) => node::<true, 1, 1>,
            (Self::Maint, Mode::Off, 0) => node::<false, 0, 2>,
            (Self::Maint, Mode::Off, _) => node::<false, 1, 2>,
            (Self::Maint, Mode::On, 0) => node::<true, 0, 2>,
            (Self::Maint, Mode::On, _) => node::<true, 1, 2>,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Master(Mode::Off) => "master off",
            Self::Master(Mode::On) => "master on",
            Self::Maint => "maint",
        }
    }
}

/// One run: a start with a joint node at node `at`, in the start's address
/// order or the other.
struct Run {
    st: Start,
    mode: Mode,
    legacy: Legacy,
    at: usize,
    flip: bool,
}

/// What a run exempts: what `by_any_shape` does, and the breach
/// `../joint/pins.rs` holds of a proven path left with no connection.
fn exempt(w: &World, b: &Breach) -> bool {
    by_any_shape(w, b) || lapsed(w, b)
}

impl Run {
    /// The run's name, as `not-converging.txt` lists it.
    fn name(&self) -> String {
        let order = if self.flip { "flipped" } else { "as written" };
        format!(
            "{}: joint {} at n{} against {}, {order}",
            self.st.name,
            self.mode.name(),
            self.at,
            self.legacy.name()
        )
    }

    fn sweep(&self) -> Swept {
        let go = || sweep(&self.st, self.st.depth, &exempt);
        if self.flip { flipped(go) } else { go() }
    }
}

/// The runs of a joint node at `mode` against `legacy` on the starts `keep`
/// takes, with the joint node at node 0 and at node 1, in each address
/// order.
fn runs(mode: Mode, legacy: Legacy, keep: impl Fn(&Start) -> bool) -> Vec<Run> {
    let mut out = Vec::new();
    for &at in &[0, 1] {
        let maker = legacy.maker(mode, at);
        for st in uncapped(maker).into_iter().filter(|s| keep(s)) {
            let flips: &[bool] = if matches!(st.number, 5 | 6 | 11) {
                &[false]
            } else {
                &[false, true]
            };
            for &flip in flips {
                let st = uncapped(maker)
                    .into_iter()
                    .find(|s| s.name == st.name)
                    .expect("the start exists");
                out.push(Run {
                    st,
                    mode,
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

/// Sweep and check `runs`, under the name `label`.
fn swept(runs: &[Run], label: &str) {
    check(&sweep_all(runs), runs, label);
}

/// A start whose sweep takes minutes at multipath on against the model at
/// multipath on, where [`CAPABLE`]'s and [`DOUBLED`]'s take longer.
fn quick(st: &Start) -> bool {
    !CAPABLE.contains(&st.name) && !DOUBLED.contains(&st.name)
}

#[test]
fn a_joint_node_off_against_a_model_of_maint_converges_on_every_start_in_both_address_orders() {
    let runs = runs(Mode::Off, Legacy::Maint, |_| true);
    swept(&runs, "off against maint");
}

#[test]
fn a_joint_node_on_against_a_model_of_maint_converges_on_every_start_in_both_address_orders() {
    let runs = runs(Mode::On, Legacy::Maint, |_| true);
    swept(&runs, "on against maint");
}

#[test]
fn a_joint_node_off_against_a_model_of_master_off_converges_on_every_start_in_both_address_orders()
{
    let runs = runs(Mode::Off, Legacy::Master(Mode::Off), |_| true);
    swept(&runs, "off against master off");
}

#[test]
fn a_joint_node_off_against_a_model_of_master_on_converges_on_every_start_in_both_address_orders() {
    let runs = runs(Mode::Off, Legacy::Master(Mode::On), |_| true);
    swept(&runs, "off against master on");
}

#[test]
fn a_joint_node_on_against_a_model_of_master_off_converges_on_every_start_in_both_address_orders() {
    let runs = runs(Mode::On, Legacy::Master(Mode::Off), |_| true);
    swept(&runs, "on against master off");
}

#[test]
fn a_joint_node_on_against_a_model_of_master_on_converges_on_the_quicker_starts() {
    let runs = runs(Mode::On, Legacy::Master(Mode::On), quick);
    swept(&runs, "on against master on, the quicker starts");
}

#[test]
fn a_joint_node_on_against_a_model_of_master_on_converges_on_a_crossing_of_two_transports() {
    let runs = runs(Mode::On, Legacy::Master(Mode::On), |s| s.name == CAPABLE[0]);
    swept(&runs, "on against master on, a crossing of two transports");
}

#[test]
fn a_joint_node_on_against_a_model_of_master_on_converges_on_a_connection_oriented_crossing() {
    let runs = runs(Mode::On, Legacy::Master(Mode::On), |s| s.name == CAPABLE[1]);
    swept(
        &runs,
        "on against master on, a connection-oriented crossing",
    );
}

#[test]
fn a_joint_node_on_against_a_model_of_master_on_converges_on_a_crossing_during_a_rekey() {
    let runs = runs(Mode::On, Legacy::Master(Mode::On), |s| s.name == CAPABLE[2]);
    swept(&runs, "on against master on, a crossing during a rekey");
}

#[test]
fn a_joint_node_on_against_a_model_of_master_on_converges_on_the_starts_on_real_bundles() {
    let runs = runs(Mode::On, Legacy::Master(Mode::On), |s| {
        DOUBLED.contains(&s.name)
    });
    swept(&runs, "on against master on, the starts on real bundles");
}
