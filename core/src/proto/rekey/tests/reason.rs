//! Tests of `reason.rs`.

use super::*;

#[test]
fn local_faults_are_never_attributed_to_the_peer_and_unauthenticated_causes_are_rate_limited() {
    for r in [
        Reason::IndexExhausted,
        Reason::HandshakeWrite,
        Reason::NotRekey,
        Reason::StaleTag,
    ] {
        assert_eq!(r.attribution(), Attribution::Local, "{r:?}");
        assert!(!r.unauthenticated_reachable(), "{r:?}");
    }
    for r in [
        Reason::FrameUnauthenticated,
        Reason::Replay,
        Reason::ReplyUnauthenticated,
        Reason::FinalUnauthenticated,
        Reason::SetupMalformed,
        Reason::CandidatesFull,
        Reason::TieBreakKept,
    ] {
        assert!(
            r.unauthenticated_reachable(),
            "{r:?} can be caused by a forgery"
        );
    }
    for r in [Reason::KeyMismatch, Reason::OffLink] {
        assert_ne!(
            r.attribution(),
            Attribution::Peer,
            "{r:?}: a third party or a replayed copy causes it"
        );
        assert!(r.unauthenticated_reachable(), "{r:?}");
    }
}
