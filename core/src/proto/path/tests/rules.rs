//! Tests of path policy's functions (`proto::path::rules::tests::...`):
//! the scope of an address, a transport's fixed kind, each rule refusing
//! and naming itself in the checks it belongs to, and that no check
//! allocates.

use alloc::vec::Vec;

use super::*;
use crate::proto::path::Medium;
use crate::testutil::allocations;

/// Facts by transport: 1 clear with no fixed kind, 2 clear and fixed
/// Local, 3 Tor, 4 Nym, 5 role never, 6 refusing the peer's handshake, 7
/// not dialling the peer, 8 clear and fixed Internet.
struct Table;

impl Facts for Table {
    fn mtu(&self, _transport: TransportId, _addr: &TransportAddr) -> usize {
        1280
    }

    fn medium(&self, _transport: TransportId) -> Medium {
        Medium::Other
    }

    fn oriented(&self, _transport: TransportId) -> bool {
        false
    }

    fn class(&self, transport: TransportId) -> Class {
        match transport.as_u32() {
            3 => Class::Tor,
            4 => Class::Nym,
            _ => Class::Clear,
        }
    }

    fn kind(&self, transport: TransportId) -> Option<Kind> {
        match transport.as_u32() {
            1 => None,
            8 => Some(Kind::Internet),
            _ => Some(Kind::Local),
        }
    }

    fn role(&self, transport: TransportId) -> Role {
        if transport.as_u32() == 5 {
            Role::Never
        } else {
            Role::Normal
        }
    }

    fn accepts(&self, transport: TransportId) -> bool {
        transport.as_u32() != 6
    }

    fn dials(&self, transport: TransportId) -> bool {
        transport.as_u32() != 7
    }
}

/// Transport `n`.
fn t(n: u32) -> TransportId {
    TransportId::new(n)
}

/// The address `s`.
fn a(s: &str) -> TransportAddr {
    TransportAddr::from_string(s)
}

#[test]
fn address_scope_classifies_every_local_range_and_nothing_else() {
    let local = [
        "127.0.0.1:2121",
        "127.255.0.9:1",
        "10.1.2.3:2121",
        "172.16.0.1:1",
        "172.31.255.255:1",
        "192.168.1.1:2121",
        "169.254.3.4:2121",
        "[::1]:2121",
        "[fe80::1]:2121",
        "[fe80::1%3]:2121",
        "[febf::1]:2121",
        "[fd00::1]:2121",
        "[fc00::1]:2121",
        "[::ffff:192.168.1.1]:2121",
        "10.0.0.1",
        "fe80::1",
    ];
    let internet = [
        "8.8.8.8:53",
        "203.0.113.1:2121",
        "100.64.0.1:2121",
        "172.15.255.255:1",
        "172.32.0.1:1",
        "192.169.0.1:1",
        "169.255.0.1:1",
        "[2001:db8::1]:2121",
        "[fec0::1]:2121",
        "[fe00::1]:2121",
        "[::ffff:8.8.8.8]:53",
        "8.8.4.4",
        "example.com:443",
        "abcdefghijklmnop.onion:2121",
        "",
        "not an address",
    ];
    for s in local {
        assert_eq!(scope(&a(s)), Kind::Local, "{s}");
    }
    for s in internet {
        assert_eq!(scope(&a(s)), Kind::Internet, "{s}");
    }
    let mac = TransportAddr::from_mac([2, 0, 0, 0, 0, 1]);
    assert_eq!(scope(&mac), Kind::Internet, "a MAC address is not an IP");
}

#[test]
fn a_fixed_kind_wins_over_the_address() {
    let (lan, wan) = (a("10.0.0.2:1"), a("8.8.8.8:53"));
    assert_eq!(kind(&Table, t(2), &wan), Kind::Local);
    assert_eq!(kind(&Table, t(8), &lan), Kind::Internet);
    assert_eq!(kind(&Table, t(1), &wan), Kind::Internet);
    assert_eq!(kind(&Table, t(1), &lan), Kind::Local);
    let link = link(&Table, t(2), &wan);
    assert_eq!(
        link,
        Scope {
            class: Class::Clear,
            kind: Kind::Local
        }
    );
}

#[test]
fn each_rule_refuses_and_names_itself() {
    let clear = link(&Table, t(2), &a("10.0.0.1:1"));
    let tor = link(&Table, t(3), &a("abcdefghijklmnop.onion:1"));
    let ok = a("10.0.0.2:1");
    let wan = a("8.8.8.8:1");
    type Check = fn(&dyn Facts, Scope, bool, TransportId, &TransportAddr) -> Result<(), Rule>;
    let all: [(&str, Check); 3] = [("moves", moves), ("probe", probe), ("admit", admit)];
    let cases = [
        (clear, false, 1, &ok, Ok(())),
        // Class, whatever the kinds.
        (clear, false, 3, &ok, Err(Rule::Class)),
        (clear, true, 4, &ok, Err(Rule::Class)),
        (tor, true, 2, &ok, Err(Rule::Class)),
        (tor, false, 3, &ok, Ok(())),
        // Kind, unless mixed.
        (clear, false, 1, &wan, Err(Rule::Kind)),
        (clear, false, 8, &ok, Err(Rule::Kind)),
        (clear, true, 1, &wan, Ok(())),
        (clear, true, 8, &ok, Ok(())),
        // Role, mixed or not.
        (clear, false, 5, &ok, Err(Rule::Role)),
        (clear, true, 5, &ok, Err(Rule::Role)),
    ];
    for (name, check) in all {
        for (link, mix, n, x, want) in cases {
            let got = check(&Table, link, mix, t(n), x);
            assert_eq!(got, want, "{name} on {n} to {x:?}, mixed {mix}");
        }
    }
    // Accept on creating a path only, dial on probing only.
    assert_eq!(admit(&Table, clear, false, t(6), &ok), Err(Rule::Accept));
    assert_eq!(probe(&Table, clear, false, t(6), &ok), Ok(()));
    assert_eq!(moves(&Table, clear, false, t(6), &ok), Ok(()));
    assert_eq!(probe(&Table, clear, false, t(7), &ok), Err(Rule::Dial));
    assert_eq!(admit(&Table, clear, false, t(7), &ok), Ok(()));
    assert_eq!(moves(&Table, clear, false, t(7), &ok), Ok(()));
}

#[test]
fn the_rules_allocate_nothing() {
    let addrs = [
        a("10.0.0.2:1"),
        a("[fe80::1%3]:2121"),
        a("[::ffff:8.8.8.8]:53"),
        a("example.com:443"),
        TransportAddr::from_mac([2; 6]),
    ];
    let before = allocations();
    let link = link(&Table, t(2), &addrs[0]);
    for _ in 0..100 {
        for x in &addrs {
            for n in 1..=8 {
                let _ = scope(x);
                let _ = moves(&Table, link, false, t(n), x);
                let _ = probe(&Table, link, false, t(n), x);
                let _ = admit(&Table, link, true, t(n), x);
            }
        }
    }
    assert_eq!(allocations(), before, "a rule allocated");
    let v: Vec<u8> = Vec::with_capacity(1);
    assert!(allocations() > before, "the counter missed an allocation");
    drop(v);
}
