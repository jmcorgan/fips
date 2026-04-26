#![cfg(feature = "nostr-discovery")]

mod runtime;
mod signal;
mod stun;
mod traversal;
mod types;

#[cfg(test)]
mod tests;

pub use runtime::NostrDiscovery;
pub use types::{
    ADVERT_IDENTIFIER, ADVERT_KIND, ADVERT_VERSION, BootstrapError, BootstrapEvent,
    CachedOverlayAdvert, OverlayAdvert, OverlayEndpointAdvert, OverlayTransportKind,
    PROTOCOL_VERSION, PUNCH_ACK_MAGIC, PUNCH_MAGIC, PunchHint, PunchPacket, PunchPacketKind,
    SIGNAL_KIND, TraversalAddress, TraversalAnswer, TraversalOffer,
};
