//! Helpers the advert tests share.

use crate::nostr::machine::types::{
    ADVERT_IDENTIFIER, ADVERT_VERSION, OverlayAdvert, OverlayEndpointAdvert, OverlayTransportKind,
};

pub(crate) fn ep(addr: &str) -> OverlayEndpointAdvert {
    OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: addr.to_string(),
    }
}

pub(crate) fn advert(endpoints: Vec<OverlayEndpointAdvert>) -> OverlayAdvert {
    OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints,
        signal_relays: None,
        stun_servers: None,
    }
}
