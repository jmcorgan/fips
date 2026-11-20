//! The digest of the ephemeral a msg1 carries, by which the settlement
//! core's restart gates count silent sessions and remember replays.

use crate::proto::fmp::EphemeralDigest;
use alloc::vec;

#[test]
fn a_msg1_too_short_to_carry_an_ephemeral_has_no_ephemeral_digest() {
    let short = vec![0u8; crate::noise::PUBKEY_SIZE - 1];
    assert_eq!(EphemeralDigest::of_noise_msg1(&short), None);
}

#[test]
fn msg1s_carrying_one_ephemeral_digest_equal_whatever_follows_it() {
    let mut first = vec![0u8; crate::noise::PUBKEY_SIZE];
    first[0] = 1;
    let mut second = first.clone();
    first.extend_from_slice(&[1u8; 16]);
    second.extend_from_slice(&[2u8; 16]);
    let digest = EphemeralDigest::of_noise_msg1(&first);
    assert!(digest.is_some());
    assert_eq!(digest, EphemeralDigest::of_noise_msg1(&second));
    let mut other = first.clone();
    other[0] = 2;
    assert_ne!(digest, EphemeralDigest::of_noise_msg1(&other));
}
