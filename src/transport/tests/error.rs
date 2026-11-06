//! Tests of `TransportError`'s unreachable class (`src/transport/mod.rs`):
//! which failures say the destination cannot be reached, and how a
//! transport's send error keeps its text while taking that class.

use super::*;
use std::io::{Error, ErrorKind};

/// Only an unreachable network or host, or a network that is down, is
/// unreachable; a missing connection, a refusal, a timeout or another send
/// failure is not.
#[test]
fn only_an_unreachable_destination_is_unreachable() {
    let unreachable = [
        TransportError::Unreachable("Network is unreachable".into()),
        TransportError::Io(Error::from(ErrorKind::NetworkUnreachable)),
        TransportError::Io(Error::from(ErrorKind::HostUnreachable)),
        TransportError::Io(Error::from(ErrorKind::NetworkDown)),
    ];
    for e in unreachable {
        assert!(e.is_unreachable(), "{e:?}");
    }
    let others = [
        TransportError::NotConnected,
        TransportError::ConnectionRefused,
        TransportError::Timeout,
        TransportError::SendFailed("ENOBUFS".into()),
        TransportError::Io(Error::from(ErrorKind::PermissionDenied)),
    ];
    for e in others {
        assert!(!e.is_unreachable(), "{e:?}");
    }
}

/// A send error for an unreachable destination reads as the send failure it was
/// and is unreachable, a permission error stays a send failure that is not, and
/// neither is transient.
#[test]
fn a_send_error_keeps_its_text_and_its_class() {
    let unreachable = Error::from(ErrorKind::NetworkUnreachable);
    let text = unreachable.to_string();
    let e = send_error(unreachable);
    assert!(e.is_unreachable(), "{e:?}");
    assert_eq!(
        e.to_string(),
        TransportError::SendFailed(text).to_string(),
        "it reads as the send failure it was"
    );
    assert!(!e.is_transient());
    let denied = send_error(Error::from(ErrorKind::PermissionDenied));
    assert!(
        matches!(denied, TransportError::SendFailed(_)),
        "{denied:?}"
    );
    assert!(!denied.is_unreachable());
    assert!(!denied.is_transient());
    // The kernel's own errors, as a UDP or Ethernet send reports them.
    #[cfg(unix)]
    for errno in [libc::ENETUNREACH, libc::EHOSTUNREACH, libc::ENETDOWN] {
        let e = send_error(Error::from_raw_os_error(errno));
        assert!(e.is_unreachable(), "errno {errno}: {e:?}");
    }
    #[cfg(unix)]
    assert!(!send_error(Error::from_raw_os_error(libc::EPERM)).is_unreachable());
}
