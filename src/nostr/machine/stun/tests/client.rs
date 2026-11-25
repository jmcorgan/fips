//! Tests of the STUN client, stepped by hand on a test instant, with
//! transaction ids from a seeded entropy source.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use super::*;
use crate::nostr::machine::tests::{SeededEntropy, TestInstant};

type Client = Observation<TestInstant, SeededEntropy>;

const SERVER: &str = "stun:198.51.100.1:3478";
const SERVER_ADDR: &str = "198.51.100.1:3478";

fn at(ms: u64) -> TestInstant {
    TestInstant(ms)
}

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

/// A binding success for `txn` carrying `mapped` as XOR-MAPPED-ADDRESS.
fn success(txn: &[u8], mapped: SocketAddrV4) -> Vec<u8> {
    const COOKIE: u32 = 0x2112_a442;
    let mut packet = Vec::new();
    packet.extend_from_slice(&0x0101u16.to_be_bytes());
    packet.extend_from_slice(&12u16.to_be_bytes());
    packet.extend_from_slice(&COOKIE.to_be_bytes());
    packet.extend_from_slice(txn);
    packet.extend_from_slice(&0x0020u16.to_be_bytes());
    packet.extend_from_slice(&8u16.to_be_bytes());
    packet.push(0);
    packet.push(1);
    packet.extend_from_slice(&(mapped.port() ^ (COOKIE >> 16) as u16).to_be_bytes());
    for (octet, mask) in mapped.ip().octets().iter().zip(COOKIE.to_be_bytes()) {
        packet.push(octet ^ mask);
    }
    packet
}

/// The sends among `out`.
fn sends(out: &[Out]) -> Vec<(SocketAddr, Vec<u8>)> {
    out.iter()
        .filter_map(|o| match o {
            Out::Send { dst, bytes } => Some((*dst, bytes.clone())),
            _ => None,
        })
        .collect()
}

fn client(servers: &[&str], timeout_ms: u64) -> Client {
    SeededEntropy::seed(3);
    Observation::new(
        servers.iter().map(|s| s.to_string()).collect(),
        Duration::from_millis(timeout_ms),
        true,
    )
}

/// Run `c` with timeouts from now (`ms`) to `until_ms`, collecting what
/// each step asks for, with the instant it asked.
fn run_until(c: &mut Client, ms: &mut u64, until_ms: u64) -> Vec<(u64, Out)> {
    let mut seen = Vec::new();
    while let Some(due) = c.deadline().filter(|d| d.0 <= until_ms) {
        *ms = due.0;
        for out in c.timeout(at(*ms)) {
            seen.push((*ms, out));
        }
    }
    *ms = until_ms;
    seen
}

#[test]
fn a_binding_success_from_the_server_asked_ends_the_observation() {
    let mut c = client(&[SERVER], 5_000);
    let out = c.begin(at(0));
    let sent = sends(&out);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, addr(SERVER_ADDR));
    let mapped = SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 50_000);
    let out = c.datagram(
        addr(SERVER_ADDR),
        &success(&sent[0].1[8..20], mapped),
        at(10),
    );
    assert_eq!(
        out,
        vec![Out::Succeeded {
            server: SERVER.to_string(),
            mapped: SocketAddr::V4(mapped),
        }]
    );
    assert_eq!(c.deadline(), None, "the observation has ended");
}

#[test]
fn a_datagram_from_another_source_is_counted_and_ignored() {
    let mut c = client(&[SERVER], 2_000);
    let sent = sends(&c.begin(at(0)));
    let forged = success(
        &sent[0].1[8..20],
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 1),
    );
    let attacker = addr("198.51.100.66:3478");
    assert!(c.datagram(attacker, &forged, at(5)).is_empty());
    assert!(c.datagram(attacker, &forged, at(6)).is_empty());
    let mut ms = 6;
    let seen = run_until(&mut c, &mut ms, 2_000);
    let discarded: Vec<&Out> = seen
        .iter()
        .map(|(_, o)| o)
        .filter(|o| matches!(o, Out::Discarded { .. }))
        .collect();
    assert_eq!(
        discarded,
        vec![&Out::Discarded {
            server: SERVER.to_string(),
            expected: addr(SERVER_ADDR),
            rejected: 2,
            last_unexpected: Some(attacker),
        }]
    );
    assert!(
        seen.iter()
            .any(|(_, o)| matches!(o, Out::Failed { error: Some(e) }
        if e == "stun failed: timed out waiting for stun:198.51.100.1:3478"))
    );
}

#[test]
fn the_request_is_resent_at_500_ms_doubling_until_the_deadline() {
    for (timeout, expected) in [
        (5_000, vec![0, 500, 1_500, 3_500]),
        (2_000, vec![0, 500, 1_500]),
    ] {
        let mut c = client(&[SERVER], timeout);
        let first = sends(&c.begin(at(0)));
        let mut times = vec![0];
        let mut ms = 0;
        for (when, out) in run_until(&mut c, &mut ms, timeout) {
            if let Out::Send { dst, bytes } = out {
                assert_eq!(dst, addr(SERVER_ADDR));
                assert_eq!(bytes, first[0].1, "the same request each time");
                times.push(when);
            }
        }
        assert_eq!(times, expected, "with a {timeout} ms deadline");
    }
}

#[test]
fn a_server_that_times_out_falls_through_to_the_next() {
    let mut c = client(&[SERVER, "stun:198.51.100.2:3478"], 2_000);
    let first = sends(&c.begin(at(0)));
    let mut ms = 0;
    let seen = run_until(&mut c, &mut ms, 2_000);
    let next: Vec<SocketAddr> = seen
        .iter()
        .filter_map(|(when, o)| match o {
            Out::Send { dst, .. } if *when == 2_000 => Some(*dst),
            _ => None,
        })
        .collect();
    assert_eq!(next, vec![addr("198.51.100.2:3478")]);
    let second = sends(&seen.into_iter().map(|(_, o)| o).collect::<Vec<_>>());
    let request = &second.last().unwrap().1;
    assert_ne!(
        request[8..20],
        first[0].1[8..20],
        "each server gets a fresh transaction id"
    );
}

#[test]
fn a_host_name_is_resolved_and_the_first_ipv4_address_is_used() {
    let mut c = client(&["stun:stun.example:3478"], 2_000);
    let out = c.begin(at(0));
    assert_eq!(
        out,
        vec![Out::Resolve {
            host: "stun.example".to_string(),
            port: 3478,
        }]
    );
    let out = c.resolved(
        vec![
            addr("[2001:db8::1]:3478"),
            addr("198.51.100.3:3478"),
            addr("198.51.100.4:3478"),
        ],
        at(20),
    );
    assert_eq!(sends(&out)[0].0, addr("198.51.100.3:3478"));
}

#[test]
fn a_server_with_no_address_of_the_sockets_family_is_skipped() {
    let mut c = client(&["stun:stun.example:3478", SERVER], 2_000);
    c.begin(at(0));
    let out = c.resolved(vec![addr("[2001:db8::1]:3478")], at(20));
    assert_eq!(
        sends(&out)[0].0,
        addr(SERVER_ADDR),
        "the next server is tried"
    );
    let mut c = client(&["stun:stun.example:3478"], 2_000);
    c.begin(at(0));
    assert_eq!(
        c.resolved(vec![addr("[2001:db8::1]:3478")], at(20)),
        vec![Out::Failed {
            error: Some("stun failed: no address for stun:stun.example:3478".to_string())
        }]
    );
    let mut c = client(&["stun:stun.example:3478"], 2_000);
    c.begin(at(0));
    assert_eq!(
        c.resolve_failed("failed to lookup address".to_string(), at(20)),
        vec![Out::Failed {
            error: Some("io error: failed to lookup address".to_string())
        }]
    );
}

#[test]
fn an_unparsable_server_url_is_skipped_with_its_error() {
    let mut c = client(&["stun:no-port"], 2_000);
    assert_eq!(
        c.begin(at(0)),
        vec![Out::Failed {
            error: Some("stun failed: invalid STUN URL: stun:no-port".to_string())
        }]
    );
    let mut c = client(&["stun:no-port", SERVER], 2_000);
    assert_eq!(sends(&c.begin(at(0)))[0].0, addr(SERVER_ADDR));
}

#[test]
fn a_server_whose_first_send_fails_is_skipped_at_once_and_a_failed_resend_is_not() {
    let mut c = client(&[SERVER, "stun:198.51.100.2:3478"], 2_000);
    c.begin(at(0));
    let out = c.send_failed(
        addr(SERVER_ADDR),
        "Network is unreachable".to_string(),
        at(1),
    );
    assert_eq!(
        sends(&out)[0].0,
        addr("198.51.100.2:3478"),
        "skipped at once"
    );

    let mut c = client(&[SERVER], 2_000);
    c.begin(at(0));
    let mut ms = 0;
    let resent = run_until(&mut c, &mut ms, 500);
    assert_eq!(
        sends(&resent.into_iter().map(|(_, o)| o).collect::<Vec<_>>()).len(),
        1
    );
    assert!(
        c.send_failed(
            addr(SERVER_ADDR),
            "Network is unreachable".to_string(),
            at(501)
        )
        .is_empty(),
        "a failed resend leaves the earlier send in flight"
    );
    let mapped = SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 50_000);
    let request = create_stun_binding_request(c.txn);
    let out = c.datagram(
        addr(SERVER_ADDR),
        &success(&request[8..20], mapped),
        at(600),
    );
    assert!(matches!(out.as_slice(), [Out::Succeeded { .. }]));
}
