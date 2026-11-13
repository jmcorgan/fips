use super::*;
use crate::nostr::machine::adverts::tests::{advert, ep};

fn machine() -> Publisher {
    // advertise=true
    Publisher::new(true)
}

#[test]
fn set_local_advert_detects_change() {
    let mut m = machine();
    let a = advert(vec![ep("1.2.3.4:9000")]);
    assert!(m.set_local_advert(Some(a.clone())), "first set is a change");
    assert!(
        !m.set_local_advert(Some(a.clone())),
        "identical set is no change"
    );
    assert!(m.set_local_advert(None), "clearing is a change");
}

#[test]
fn plan_publish_strips_relays_for_non_nat_advert() {
    let mut m = machine();
    let mut a = advert(vec![ep("1.2.3.4:9000")]);
    a.signal_relays = Some(vec!["wss://relay".to_string()]);
    a.stun_servers = Some(vec!["stun:host:3478".to_string()]);
    m.set_local_advert(Some(a));
    match m.plan_publish().expect("plan ok") {
        PublishPlan::Publish(out) => {
            assert!(
                out.signal_relays.is_none(),
                "non-nat advert strips signalRelays"
            );
            assert!(
                out.stun_servers.is_none(),
                "non-nat advert strips stunServers"
            );
            assert_eq!(out.identifier, ADVERT_IDENTIFIER);
            assert_eq!(out.version, ADVERT_VERSION);
        }
        other => panic!("expected Publish, got {other:?}"),
    }
}

#[test]
fn plan_publish_keeps_relays_for_nat_advert() {
    let mut m = machine();
    let mut a = advert(vec![ep("nat")]);
    a.signal_relays = Some(vec!["wss://relay".to_string()]);
    a.stun_servers = Some(vec!["stun:host:3478".to_string()]);
    m.set_local_advert(Some(a));
    match m.plan_publish().expect("plan ok") {
        PublishPlan::Publish(out) => {
            assert!(out.has_udp_nat_endpoint());
            assert_eq!(out.signal_relays.as_deref().map(<[_]>::len), Some(1));
            assert_eq!(out.stun_servers.as_deref().map(<[_]>::len), Some(1));
        }
        other => panic!("expected Publish, got {other:?}"),
    }
}

#[test]
fn plan_publish_nat_without_relays_errors() {
    let mut m = machine();
    m.set_local_advert(Some(advert(vec![ep("nat")])));
    assert!(matches!(m.plan_publish(), Err(Error::InvalidAdvert(_))));
}

#[test]
fn plan_publish_nothing_when_no_local_advert() {
    let m = machine();
    assert!(matches!(m.plan_publish(), Ok(PublishPlan::Nothing)));
}

#[test]
fn plan_publish_nothing_when_advertising_disabled_even_with_a_local_advert() {
    let mut m = Publisher::new(false);
    m.set_local_advert(Some(advert(vec![ep("1.2.3.4:9000")])));
    assert!(matches!(m.plan_publish(), Ok(PublishPlan::Nothing)));
}
