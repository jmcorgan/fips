//! Golden text for every machine error, as the machine prints it and as the
//! shell's `BootstrapError` prints it after the mapping. The shell matches on
//! that text (`adversarial_offer_reject`) and logs it, so a change here is a
//! change to what operators and peers see.

use super::Error;
use crate::nostr::BootstrapError;

#[test]
fn every_machine_error_maps_to_the_same_bootstrap_variant_and_text() {
    let cases = [
        (
            Error::Protocol("session-mismatch".into()),
            "protocol error: session-mismatch",
        ),
        (
            Error::Stun("invalid STUN URL: x".into()),
            "stun failed: invalid STUN URL: x",
        ),
        (
            Error::InvalidAdvert("missing required endpoints".into()),
            "invalid overlay advert: missing required endpoints",
        ),
    ];
    for (error, text) in cases {
        assert_eq!(error.to_string(), text);
        let mapped = BootstrapError::from(error.clone());
        assert_eq!(mapped.to_string(), text);
        match (&error, &mapped) {
            (Error::Protocol(a), BootstrapError::Protocol(b)) => assert_eq!(a, b),
            (Error::Stun(a), BootstrapError::Stun(b)) => assert_eq!(a, b),
            (Error::InvalidAdvert(a), BootstrapError::InvalidAdvert(b)) => assert_eq!(a, b),
            _ => panic!("{error:?} mapped to {mapped:?}"),
        }
    }
}
