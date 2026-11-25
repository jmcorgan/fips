//! Tests of `stun.rs`'s neighbours in the machine that its reads feed: the
//! address-family filters on local candidates and resolved server
//! addresses (`offerable`, `pick_family`). The STUN exchange itself is the
//! machine's client, tested in `machine/stun/tests/client.rs`.

#[test]
fn only_local_candidates_of_the_sockets_family_are_offered() {
    let candidates = || {
        ["192.168.1.2", "fd00::1", "10.0.0.3", "2001:db8::1"]
            .map(String::from)
            .to_vec()
    };
    assert_eq!(
        super::offerable(candidates(), true),
        ["192.168.1.2", "10.0.0.3"],
        "IPv6 candidates offered with an IPv4 socket's port, which no peer can reach"
    );
    assert_eq!(
        super::offerable(candidates(), false),
        ["fd00::1", "2001:db8::1"]
    );
}

#[test]
fn a_stun_server_is_reached_at_a_resolved_address_of_the_sockets_family() {
    let v6: std::net::SocketAddr = "[::1]:3478".parse().unwrap();
    let v4: std::net::SocketAddr = "127.0.0.1:3478".parse().unwrap();
    assert_eq!(
        super::pick_family([v6, v4], true),
        Some(v4),
        "an IPv4 socket was sent to an IPv6 server address"
    );
    assert_eq!(super::pick_family([v4, v6], false), Some(v6));
    assert_eq!(super::pick_family([v6], true), None);
}
