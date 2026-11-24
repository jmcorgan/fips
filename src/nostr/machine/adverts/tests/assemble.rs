use super::*;

const WILDCARD_UDP: &str = "0.0.0.0:2121";
const PUBLIC_UDP: &str = "198.51.100.7:2121";
const EXTERNAL: &str = "203.0.113.9:4000";
const LEARNED: &str = "203.0.113.50:2121";

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

fn udp(
    is_public: bool,
    external: Option<&str>,
    local: Option<&str>,
    key: u32,
) -> AdvertTransportSnapshot {
    AdvertTransportSnapshot::Udp {
        advertise: true,
        is_public,
        external_addr: external.map(addr),
        local_addr: local.map(addr),
        transport_key: key,
    }
}

fn relays() -> Vec<String> {
    vec!["wss://relay.example".to_string()]
}

fn servers() -> Vec<String> {
    vec!["stun:stun.example:3478".to_string()]
}

fn endpoints(assembly: &Assembly) -> Vec<(OverlayTransportKind, String)> {
    assembly
        .advert
        .as_ref()
        .map(|advert| {
            advert
                .endpoints
                .iter()
                .map(|e| (e.transport.clone(), e.addr.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn nothing_learned() -> BTreeMap<u32, Option<SocketAddr>> {
    BTreeMap::new()
}

#[test]
fn an_explicit_external_address_is_advertised_without_a_learned_one() {
    let snapshot = [
        udp(true, Some(EXTERNAL), Some(WILDCARD_UDP), 1),
        udp(true, Some(EXTERNAL), Some(PUBLIC_UDP), 2),
        AdvertTransportSnapshot::Tcp {
            advertise: true,
            external_addr: Some(addr(EXTERNAL)),
            local_addr: Some(addr(PUBLIC_UDP)),
        },
    ];
    let assembly = assemble(&snapshot, &nothing_learned(), &relays(), &servers());
    assert_eq!(
        endpoints(&assembly),
        vec![
            (OverlayTransportKind::Udp, EXTERNAL.to_string()),
            (OverlayTransportKind::Udp, EXTERNAL.to_string()),
            (OverlayTransportKind::Tcp, EXTERNAL.to_string()),
        ]
    );
    assert!(assembly.notes.is_empty());
    assert!(
        learned_wanted(&snapshot).is_empty(),
        "an external address needs no learned one"
    );
}

#[test]
fn a_specific_public_bind_address_is_advertised_as_bound() {
    let snapshot = [
        udp(true, None, Some(PUBLIC_UDP), 1),
        AdvertTransportSnapshot::Tcp {
            advertise: true,
            external_addr: None,
            local_addr: Some(addr("198.51.100.8:443")),
        },
    ];
    let assembly = assemble(&snapshot, &nothing_learned(), &relays(), &servers());
    assert_eq!(
        endpoints(&assembly),
        vec![
            (OverlayTransportKind::Udp, PUBLIC_UDP.to_string()),
            (OverlayTransportKind::Tcp, "198.51.100.8:443".to_string()),
        ]
    );
    let advert = assembly.advert.unwrap();
    assert_eq!(advert.signal_relays, None);
    assert_eq!(advert.stun_servers, None);
}

#[test]
fn a_wildcard_public_udp_bind_is_advertised_at_its_learned_address_and_port() {
    let snapshot = [udp(true, None, Some(WILDCARD_UDP), 7)];
    let learned = BTreeMap::from([(7, Some(addr(LEARNED)))]);
    let assembly = assemble(&snapshot, &learned, &relays(), &servers());
    assert_eq!(
        endpoints(&assembly),
        vec![(OverlayTransportKind::Udp, LEARNED.to_string())]
    );
    assert!(assembly.notes.is_empty());
}

#[test]
fn a_wildcard_public_udp_bind_with_no_learned_address_is_left_out_with_a_note() {
    let snapshot = [
        udp(true, None, Some(WILDCARD_UDP), 7),
        udp(true, None, Some("0.0.0.0:2122"), 8),
    ];
    let learned = BTreeMap::from([(7, None)]);
    let assembly = assemble(&snapshot, &learned, &relays(), &servers());
    assert_eq!(
        assembly.advert, None,
        "no transport contributed an endpoint"
    );
    assert_eq!(
        assembly.notes,
        vec![
            AssemblyNote::UdpUnlearned {
                transport_id: 7,
                bind_addr: addr(WILDCARD_UDP),
            },
            AssemblyNote::UdpUnlearned {
                transport_id: 8,
                bind_addr: addr("0.0.0.0:2122"),
            },
        ]
    );
}

#[test]
fn a_non_public_udp_transport_is_advertised_as_nat_with_relays_and_stun_servers() {
    let snapshot = [udp(false, None, Some(WILDCARD_UDP), 1)];
    let assembly = assemble(&snapshot, &nothing_learned(), &relays(), &servers());
    assert_eq!(
        endpoints(&assembly),
        vec![(OverlayTransportKind::Udp, "nat".to_string())]
    );
    let advert = assembly.advert.unwrap();
    assert_eq!(advert.identifier, ADVERT_IDENTIFIER);
    assert_eq!(advert.version, ADVERT_VERSION);
    assert_eq!(advert.signal_relays, Some(relays()));
    assert_eq!(advert.stun_servers, Some(servers()));
}

#[test]
fn a_wildcard_tcp_bind_without_an_external_address_is_left_out_with_a_note() {
    let snapshot = [
        AdvertTransportSnapshot::Tcp {
            advertise: true,
            external_addr: None,
            local_addr: Some(addr("0.0.0.0:443")),
        },
        udp(true, None, Some(PUBLIC_UDP), 1),
    ];
    let assembly = assemble(&snapshot, &nothing_learned(), &relays(), &servers());
    assert_eq!(
        endpoints(&assembly),
        vec![(OverlayTransportKind::Udp, PUBLIC_UDP.to_string())]
    );
    assert_eq!(
        assembly.notes,
        vec![AssemblyNote::TcpWildcard {
            bind_addr: addr("0.0.0.0:443"),
        }]
    );
}

#[test]
fn a_tor_transport_is_advertised_by_onion_and_port_only_when_it_has_an_onion() {
    let onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
    let snapshot = [
        AdvertTransportSnapshot::Tor {
            advertise: true,
            onion_addr: None,
            advertised_port: 80,
        },
        AdvertTransportSnapshot::Tor {
            advertise: true,
            onion_addr: Some(onion.to_string()),
            advertised_port: 443,
        },
    ];
    let assembly = assemble(&snapshot, &nothing_learned(), &relays(), &servers());
    assert_eq!(
        endpoints(&assembly),
        vec![(OverlayTransportKind::Tor, format!("{onion}:443"))]
    );
    assert!(assembly.notes.is_empty());
}

#[test]
fn transports_that_do_not_advertise_contribute_nothing_and_no_endpoint_gives_no_advert() {
    let snapshot = [
        AdvertTransportSnapshot::Udp {
            advertise: false,
            is_public: false,
            external_addr: None,
            local_addr: Some(addr(WILDCARD_UDP)),
            transport_key: 1,
        },
        AdvertTransportSnapshot::Udp {
            advertise: false,
            is_public: true,
            external_addr: None,
            local_addr: Some(addr(WILDCARD_UDP)),
            transport_key: 2,
        },
        AdvertTransportSnapshot::Tcp {
            advertise: false,
            external_addr: None,
            local_addr: Some(addr("0.0.0.0:443")),
        },
        AdvertTransportSnapshot::Tor {
            advertise: false,
            onion_addr: Some("x.onion".to_string()),
            advertised_port: 443,
        },
    ];
    let learned = BTreeMap::from([(2, Some(addr(LEARNED)))]);
    let assembly = assemble(&snapshot, &learned, &relays(), &servers());
    assert_eq!(assembly.advert, None);
    assert!(assembly.notes.is_empty());
    assert_eq!(assemble(&[], &learned, &relays(), &servers()).advert, None);
}

#[test]
fn the_learned_addresses_wanted_are_the_advertised_wildcard_public_udp_binds_in_snapshot_order() {
    let snapshot = [
        udp(true, None, Some("0.0.0.0:3000"), 9),
        udp(false, None, Some(WILDCARD_UDP), 1),
        udp(true, Some(EXTERNAL), Some(WILDCARD_UDP), 2),
        udp(true, None, Some(PUBLIC_UDP), 3),
        udp(true, None, None, 4),
        AdvertTransportSnapshot::Udp {
            advertise: false,
            is_public: true,
            external_addr: None,
            local_addr: Some(addr("0.0.0.0:5000")),
            transport_key: 5,
        },
        udp(true, None, Some("[::]:2500"), 6),
        udp(true, None, Some(WILDCARD_UDP), 7),
    ];
    assert_eq!(
        learned_wanted(&snapshot),
        vec![(9, 3000), (6, 2500), (7, 2121)]
    );
}
