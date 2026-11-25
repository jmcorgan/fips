mod classify;
mod driver;
mod log;
pub(crate) mod machine;
mod pump;
mod relay;
mod runtime;
#[cfg(test)]
mod signal;
mod signal_route;
mod sockets;
mod stun;
mod traversal;
mod types;

#[cfg(test)]
mod tests;

pub(crate) use machine::signal::FRESHNESS_SKEW_TOLERANCE_MS;

pub use crate::node::handoff::{BootstrapHandoffResult, EstablishedTraversal};
pub use classify::{classify_datagram, is_punch_packet};
pub use driver::{AdvertTransportSnapshot, BootstrapPeer, MismatchEvidence, RendezvousDriver};
pub use runtime::NostrRendezvous;
pub use types::{
    ADVERT_IDENTIFIER, ADVERT_KIND, ADVERT_VERSION, BootstrapError, BootstrapEvent,
    CachedOverlayAdvert, FailureReply, NostrFailureDecision, NostrPeerFailureView,
    NostrRefetchOutcome, OverlayAdvert, OverlayEndpointAdvert, OverlayTransportKind,
    PROTOCOL_VERSION, PUNCH_ACK_MAGIC, PUNCH_MAGIC, PunchHint, PunchPacket, PunchPacketKind,
    SIGNAL_KIND, TraversalAddress, TraversalAnswer, TraversalOffer,
};
