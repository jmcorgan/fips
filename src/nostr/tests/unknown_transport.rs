//! Tests that an overlay advert naming an endpoint of a transport kind this
//! node does not know is not rejected whole: the receiver drops that endpoint
//! and uses the rest (`OverlayTransportKind::Unknown` in `types.rs`, filtered
//! by `NostrRendezvous::validate_overlay_advert` in `runtime.rs`). The JSON is
//! read the way the advert parser in `runtime.rs` reads an event's content.

use super::super::runtime::NostrRendezvous;
use super::super::types::BootstrapError;
use super::super::{
    ADVERT_IDENTIFIER, ADVERT_VERSION, OverlayAdvert, OverlayEndpointAdvert, OverlayTransportKind,
};

/// Advert JSON with the given endpoints, under this build's identifier and
/// version.
fn advert_json(endpoints: &str) -> String {
    format!(
        r#"{{"identifier":"{ADVERT_IDENTIFIER}","version":{ADVERT_VERSION},"endpoints":[{endpoints}]}}"#
    )
}

/// Parse and validate advert JSON as the advert parser does.
fn parse(json: &str) -> Result<OverlayAdvert, BootstrapError> {
    let advert: OverlayAdvert = serde_json::from_str(json)?;
    NostrRendezvous::validate_overlay_advert(advert)
}

#[test]
fn an_advert_with_an_endpoint_of_unknown_transport_keeps_its_known_endpoints() {
    let json = advert_json(
        r#"{"transport":"udp","addr":"8.8.4.4:2121"},{"transport":"quic","addr":"8.8.4.4:443"}"#,
    );
    let advert = parse(&json).expect("an unknown transport kind rejected the whole advert");
    assert_eq!(
        advert.endpoints,
        vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::Udp,
            addr: "8.8.4.4:2121".to_string(),
        }]
    );
}

#[test]
fn an_advert_whose_only_endpoint_is_of_unknown_transport_is_still_refused() {
    let json = advert_json(r#"{"transport":"quic","addr":"8.8.4.4:443"}"#);
    let err = parse(&json).expect_err("an advert with no usable endpoint was accepted");
    assert!(
        err.to_string()
            .contains("missing publicly routable endpoints"),
        "{err}"
    );
}

#[test]
fn an_endpoint_of_unknown_transport_cannot_be_serialized() {
    let unknown = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Unknown,
        addr: "8.8.4.4:443".to_string(),
    };
    assert!(serde_json::to_string(&unknown).is_err());
    let udp = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: "8.8.4.4:2121".to_string(),
    };
    assert!(serde_json::to_string(&udp).is_ok());
}
