//! The shared schedules (`../../parity.rs`) run in the world, on the model
//! of the node and on joint nodes, each compared with the committed trace.
//!
//! Each script's steps are translated one for one into the world's events:
//! a dial is the node's dial of its peer's home on the script's transport;
//! a connection opening resolves the node's first connect window, open; a
//! handshake message delivers the first deliverable one of its kind and
//! handshake to its reader; a heal settles the world and ages it a minute;
//! an advance runs the clock, losing what is in flight as the world does;
//! a restart and a rekey are the world's own. Node 0 is the smaller
//! identity where the script says so, and the larger otherwise. A node
//! that dials a peer in a script redials it there whenever it holds none,
//! as a configured peer is redialed.
//!
//! After each step each end's [`Mark`] is read from the party: whether it
//! holds the peer; whose dial its current session came from, by the
//! handshake that session was made by; its link record's direction and the
//! pair it was set up at; the peer's current address; and whether it
//! counts the peering heard. A pair is named by which of the peer's
//! addresses it is: its home, its second, or neither, which is the source
//! of a connection the peer opened.
//!
//! The model of the node must give the trace's lines, and joint nodes the
//! same lines with the trace's `core` lines applied. Both runs walk every
//! script and fail if they walked fewer, so neither passes on nothing.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::super::model::history::Addr;
use super::super::super::parity::{
    self, At, Dir, Holding, Line, Mark, Packet, Place, SCRIPTS, Script, Setting, Side, Step,
    Transport,
};
use super::super::explore::{Act, apply};
use super::super::legacy::master::{master, master_on};
use super::super::party::Configured;
use super::super::starts::{A, B, BLE, Maker, TCP, UDP, age, dial_home, home, second, settle};
use super::super::world::{self, Kind, Net, Pkt, State, World};

/// The world's transport number of a script's transport.
fn number(t: Transport) -> u8 {
    match t {
        Transport::Udp => UDP,
        Transport::Tcp => TCP,
        Transport::Ble => BLE,
    }
}

/// The script's transport of a world's transport number.
fn transport(t: u8) -> Transport {
    match t {
        UDP => Transport::Udp,
        TCP => Transport::Tcp,
        _ => Transport::Ble,
    }
}

/// The model of the node at `setting`.
fn modelled(setting: Setting) -> Maker {
    match setting {
        Setting::Off => master,
        Setting::On => master_on,
    }
}

/// A joint node at `setting`.
fn joint(setting: Setting) -> Maker {
    match setting {
        Setting::Off => super::off,
        Setting::On => super::on,
    }
}

/// The world a script starts from: its two nodes, node `smaller` the
/// smaller identity, each made by `make` at its setting, each configured
/// with the peer at the home its first dial in the script goes to.
fn build(script: &Script, make: fn(Setting) -> Maker) -> Result<World, String> {
    if script.settings.len() != 2 {
        return Err(format!(
            "{}: a script of {} nodes; a mark holds one peer",
            script.name,
            script.settings.len()
        ));
    }
    let ids = if script.smaller == 0 { [A, B] } else { [B, A] };
    let kinds = [(UDP, Kind::Datagram), (TCP, Kind::Stream), (BLE, Kind::Ble)];
    let addrs = (0..ids.len())
        .map(|i| {
            kinds
                .iter()
                .flat_map(|&(t, _)| [home(i, t), second(i, t)])
                .collect()
        })
        .collect();
    let net = Net::new(&kinds, addrs);
    let parties = (0..ids.len())
        .map(|i| {
            let configured = script
                .steps
                .iter()
                .find_map(|s| match *s {
                    Step::Dial {
                        from,
                        to,
                        transport,
                    } if from == i => Some(Configured {
                        peer: ids[to],
                        to: home(to, number(transport)),
                        from: None,
                    }),
                    Step::Dial { .. }
                    | Step::Connected { .. }
                    | Step::Handshake { .. }
                    | Step::Heal
                    | Step::Advance(_)
                    | Step::Restart { .. }
                    | Step::Rekey { .. } => None,
                })
                .into_iter()
                .collect();
            make(script.settings[i])(i, ids[i], configured)
        })
        .collect();
    Ok(World::new(parties, ids.to_vec(), net))
}

/// The handshake message of `kind` and handshake `nth` that the first
/// deliverable packet to `to` carries, by its flight number.
fn message(w: &World, to: usize, kind: Packet, nth: u32) -> Option<u64> {
    w.net
        .flight
        .iter()
        .find(|f| {
            f.to == to
                && w.net.deliverable(f)
                && match (kind, f.pkt) {
                    (Packet::Msg1, Pkt::Msg1 { hs, .. }) | (Packet::Msg2, Pkt::Msg2 { hs, .. }) => {
                        hs.0 & 0xffff == nth
                    }
                    (Packet::Msg1 | Packet::Msg2, _) => false,
                }
        })
        .map(|f| f.id)
}

/// Take one step of a script in the world.
fn take(w: &mut World, step: Step) -> Result<(), String> {
    match step {
        Step::Dial {
            from,
            to,
            transport,
        } => dial_home(w, from, to, number(transport)),
        Step::Connected { node } => {
            let c = w
                .net
                .conns
                .iter()
                .find(|c| c.state == State::Connecting && c.ends[0].node == node)
                .map(|c| c.id)
                .ok_or_else(|| format!("n{node} has no connection connecting"))?;
            apply(w, Act::Connect(c, true));
        }
        Step::Handshake { to, kind, nth } => {
            let id = message(w, to, kind, nth)
                .ok_or_else(|| format!("no {kind:?} of handshake {nth} can reach n{to}"))?;
            apply(w, Act::Deliver(id));
        }
        Step::Heal => {
            settle(w);
            age(w, 60_000);
        }
        Step::Advance(ms) => w.run_until(w.net.now + ms),
        Step::Restart { node } => apply(w, Act::Restart(node)),
        Step::Rekey { node } => apply(w, Act::Rekey(node, 1 - node)),
    }
    Ok(())
}

/// Which of node `ix`'s addresses `a` is, as a pair of its peer's.
fn place(ix: usize, a: Addr) -> Place {
    let t = a.transport;
    let at = if a == home(ix, t) {
        At::Home
    } else if a == second(ix, t) {
        At::Second
    } else {
        At::Accepted
    };
    Place {
        transport: transport(t),
        at,
    }
}

/// What node `x` of `w` holds of its peer.
fn mark(w: &World, x: usize) -> Result<Mark, String> {
    let y = 1 - x;
    let (me, peer) = (w.ids[x], w.ids[y]);
    let party = &w.parties[x];
    if !party.held().contains(&peer) {
        return Ok(Mark::Unheld);
    }
    let v = party
        .view()
        .peers
        .into_iter()
        .find(|p| p.peer == peer)
        .ok_or_else(|| format!("n{x} holds its peer and has no view of it"))?;
    let heard = party
        .heard(peer)
        .ok_or_else(|| format!("n{x} holds its peer and keeps no count of it heard"))?;
    let session = if v.cur.0 >> 24 == u32::from(me.0) {
        Side::Own
    } else {
        Side::Peer
    };
    let dir = match v.dir {
        world::Dir::Inbound => Dir::In,
        world::Dir::Outbound => Dir::Out,
    };
    Ok(Mark::Held(Holding {
        session,
        dir,
        setup: place(y, v.at),
        active: place(y, v.current),
        heard,
    }))
}

/// Run `script` with nodes made by `make`, and give what each end holds
/// after each step.
fn walk(script: &Script, make: fn(Setting) -> Maker) -> Result<Vec<Line>, String> {
    let mut w = build(script, make)?;
    let mut out = Vec::new();
    for (i, &step) in script.steps.iter().enumerate() {
        take(&mut w, step).map_err(|e| format!("{} step {}: {e}", script.name, i + 1))?;
        for node in 0..script.settings.len() {
            let mark =
                mark(&w, node).map_err(|e| format!("{} step {}: {e}", script.name, i + 1))?;
            out.push(Line {
                step: i + 1,
                node,
                mark,
            });
        }
    }
    Ok(out)
}

/// The lines of `got` that differ from `want`, each with the line wanted.
fn differences(got: &[Line], want: &[Line]) -> Vec<String> {
    let mut out = Vec::new();
    for g in got {
        match want.iter().find(|l| l.step == g.step && l.node == g.node) {
            Some(l) if l.mark == g.mark => {}
            Some(l) => out.push(format!("`{g}` where the trace has `{l}`")),
            None => out.push(format!("`{g}` has no line in the trace")),
        }
    }
    out
}

/// Walk every script with nodes made by `make`, comparing each end after
/// each step with `lines` of its trace; give the number of scripts walked
/// and every difference.
fn compare(
    make: fn(Setting) -> Maker,
    lines: fn(&parity::Trace) -> Result<Vec<Line>, String>,
) -> (usize, Vec<String>) {
    let mut walked = 0;
    let mut out = Vec::new();
    for script in SCRIPTS {
        let Some(trace) = parity::expected(script.name) else {
            out.push(format!("{} has no block in the trace", script.name));
            continue;
        };
        let want = match lines(&trace) {
            Ok(l) => l,
            Err(e) => {
                out.push(format!("{}: {e}", script.name));
                continue;
            }
        };
        match walk(script, make) {
            Ok(got) => {
                walked += 1;
                out.extend(
                    differences(&got, &want)
                        .into_iter()
                        .map(|d| format!("{}: {d}", script.name)),
                );
            }
            Err(e) => out.push(e),
        }
    }
    (walked, out)
}

/// The node's lines of a trace.
fn node(t: &parity::Trace) -> Result<Vec<Line>, String> {
    Ok(t.lines.clone())
}

/// A trace's lines with its `core` lines applied.
fn cored(t: &parity::Trace) -> Result<Vec<Line>, String> {
    t.cored()
}

/// Every shared schedule, at each setting its script states, gives the
/// trace's lines on the model of the node. Its breaks: a move that builds
/// from the session it leaves (`MoveBuildsStale`, the session field); a
/// move that skips its bundle's renewal on a connection-oriented crossing
/// (`RenewSkipped`, the active pair); a line of the trace changed, and a
/// script left out of the walk, each a scratch edit run by hand.
#[test]
fn every_shared_schedule_gives_its_trace_on_the_model_of_the_node() {
    let (walked, found) = compare(modelled, node);
    assert!(
        found.is_empty(),
        "the model of the node differs from the trace:\n{}",
        found.join("\n")
    );
    assert_eq!(
        walked,
        SCRIPTS.len(),
        "every shared schedule is walked on the model of the node"
    );
}

/// Every shared schedule, at each setting its script states, gives the
/// trace's lines with its `core` lines applied on joint nodes. Its breaks:
/// those of [`every_shared_schedule_gives_its_trace_on_the_model_of_the_node`],
/// and a `core` line removed, run by hand.
#[test]
fn every_shared_schedule_gives_its_trace_on_joint_nodes() {
    let (walked, found) = compare(joint, cored);
    assert!(
        found.is_empty(),
        "joint nodes differ from the trace:\n{}",
        found.join("\n")
    );
    assert_eq!(
        walked,
        SCRIPTS.len(),
        "every shared schedule is walked on joint nodes"
    );
}
