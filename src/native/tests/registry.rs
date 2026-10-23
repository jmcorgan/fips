//! Ephemeral port allocation does not tell a peer what else the node did.
//!
//! The local port travels to the peer as the source port of every flow, so a
//! peer that receives two flows from one node can compare their ports. If the
//! ports came from one cursor that only moves forward, the difference would
//! count the listens and connects every local program made in between,
//! including those to other peers. These tests compare ports the way such a
//! peer would.
//!
//! The first two are statistical. With a random start in the 16,384-port span,
//! the pattern they look for turns up with probability 1/16384 per trial, and
//! each asserts fewer than four matches, so a correct allocator fails one of
//! them about once in 2e12 runs.

use super::tests::{arrivals, key, limits, peer, sink};
use super::*;

/// The size of the ephemeral range, as the modulus a port difference is read in.
const SPAN: u32 = u16::MAX as u32 - PORT_EPHEMERAL_MIN as u32 + 1;

/// How far `b` is past `a`, counting forward and wrapping in the ephemeral span.
fn gap(a: u16, b: u16) -> u32 {
    (u32::from(b) + SPAN - u32::from(a)) % SPAN
}

#[test]
fn the_gap_between_two_ephemeral_ports_given_to_one_peer_does_not_count_the_allocations_made_for_others_between_them()
 {
    const TRIALS: usize = 32;
    const BETWEEN: u32 = 10;
    let mut registry = Registry::new(limits());
    let mut matches = 0;
    for _ in 0..TRIALS {
        let (tx, _rx) = sink();
        let (a, _) = registry.connect(key(1), 5000, None, tx, 0).unwrap();
        for _ in 0..BETWEEN {
            let (tx, _rx) = sink();
            let (other, _) = registry.connect(key(2), 5000, None, tx, 0).unwrap();
            registry.release(&FlowKey {
                peer: peer(2),
                remote: 5000,
                local: other,
            });
        }
        let (tx, _rx) = sink();
        let (b, _) = registry.connect(key(1), 5001, None, tx, 0).unwrap();
        if gap(a, b) == BETWEEN + 1 {
            matches += 1;
        }
        for (remote, local) in [(5000, a), (5001, b)] {
            registry.release(&FlowKey {
                peer: peer(1),
                remote,
                local,
            });
        }
    }
    assert!(
        matches < 4,
        "in {matches} of {TRIALS} trials the second port was exactly {} past the first, \
         counting the {BETWEEN} allocations made for another peer in between",
        BETWEEN + 1
    );
}

#[test]
fn a_listener_given_an_ephemeral_port_draws_it_independently_of_the_ports_given_before_it() {
    const ROUNDS: usize = 32;
    let mut registry = Registry::new(limits());
    let mut ports = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let (tx, _rx) = arrivals();
        let port = registry.listen(None, tx).unwrap();
        registry.release_listener(port);
        ports.push(port);
    }
    let successive = ports
        .windows(2)
        .filter(|pair| gap(pair[0], pair[1]) == 1)
        .count();
    assert!(
        successive < 4,
        "{successive} of {} successive listeners got the port one past the last: {ports:?}",
        ROUNDS - 1
    );
}

#[test]
fn with_every_ephemeral_port_but_one_held_an_ephemeral_request_gets_that_one_and_then_none_is_free()
{
    // The free port is the bottom of the span, so a probe from any random
    // start other than the bottom has to wrap to find it. Taking and releasing
    // it over many rounds makes a probe that lost its wrap fail all but about
    // one round in 16,384, rather than whenever the start happened to fall
    // past a port in the middle.
    const FREE: u16 = PORT_EPHEMERAL_MIN;
    const ROUNDS: usize = 64;
    let mut registry = Registry::new(limits());
    let (tx, _rx) = arrivals();
    for port in PORT_EPHEMERAL_MIN..=u16::MAX {
        if port != FREE {
            registry.listen(Some(port), tx.clone()).unwrap();
        }
    }
    for round in 0..ROUNDS {
        assert_eq!(
            registry.listen(None, tx.clone()),
            Ok(FREE),
            "round {round}: the one free port was not found"
        );
        registry.release_listener(FREE);
    }
    assert_eq!(registry.listen(None, tx.clone()).unwrap(), FREE);
    assert_eq!(
        registry.listen(None, tx).unwrap_err(),
        RegistryError::NoPort
    );
}
