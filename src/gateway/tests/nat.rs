//! Tests that the NAT table matches the TUN by the name it is given.
//!
//! The daemon names its TUN from `tun.name`, so the gateway builds every
//! interface match on the TUN from that name rather than from `fips0`.

use super::*;
use rustables::expr::ExpressionVariant;
use std::net::SocketAddrV6;

/// A manager whose TUN is named `tun`, holding one mapping and one port
/// forward, so every rule that matches the TUN is emitted.
fn tun_manager(tun: &str) -> NatManager {
    let pool = (Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 0), 112);
    let mut mgr = NatManager::with_state("br-lan".to_string(), tun.to_string(), pool);
    let virtual_ip = Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 1);
    mgr.mappings.insert(
        virtual_ip,
        NatMapping {
            virtual_ip,
            mesh_addr: Ipv6Addr::new(0xfd02, 0, 0, 0, 0, 0, 0, 1),
        },
    );
    mgr.port_forwards = vec![PortForward {
        proto: Proto::Tcp,
        listen_port: 8080,
        target: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0),
    }];
    mgr
}

/// How many of the rules a rebuild of `mgr` emits compare an interface name
/// with `name`.
fn rules_naming(mgr: &NatManager, name: &str) -> usize {
    let mut bytes = name.as_bytes().to_vec();
    bytes.push(0);
    let matches = [
        ExpressionVariant::Cmp(Cmp::new(CmpOp::Eq, bytes.clone())),
        ExpressionVariant::Cmp(Cmp::new(CmpOp::Neq, bytes)),
    ];
    mgr.rebuild_batches()
        .into_iter()
        .flatten()
        .filter_map(|op| mgr.rule_for(op).expect("the rule builds"))
        .filter(|rule| {
            rule.get_expressions().is_some_and(|list| {
                list.iter()
                    .filter_map(|e| e.get_data())
                    .any(|e| matches.contains(e))
            })
        })
        .count()
}

/// With a TUN named `fipsx`, no rule matches `fips0`, and as many rules match
/// `fipsx` as match `fips0` when the TUN has the default name.
#[test]
fn every_tun_match_uses_the_configured_tun_name() {
    let default = rules_naming(&tun_manager("fips0"), "fips0");
    assert!(default > 0, "no rule matches the default TUN name");
    let renamed = tun_manager("fipsx");
    assert_eq!(
        rules_naming(&renamed, "fips0"),
        0,
        "a rule still matches fips0 when the TUN is named fipsx"
    );
    assert_eq!(
        rules_naming(&renamed, "fipsx"),
        default,
        "fewer rules match the configured TUN name than match the default one"
    );
}
