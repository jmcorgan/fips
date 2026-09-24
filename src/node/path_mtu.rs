//! Per-destination path MTU state shared with the TCP MSS clamp.
//!
//! Every writer, the release paths and the expiry pass live in the node;
//! the TUN reader and writer threads only read the map.

use crate::FipsAddress;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// One `path_mtu_lookup` entry: the MTU the TCP MSS clamp reads, plus how
/// the entry is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathMtuEntry {
    /// Path MTU in bytes.
    pub mtu: u16,
    /// Unix ms at which a discovery `LookupResponse` supplied this value, or
    /// `None` for an entry that some event releases instead of a timer.
    ///
    /// The discovery carrier is the one with no release path: it writes an
    /// entry for a destination this node may never open a session with, and
    /// all three callers of `path_mtu_lookup_release` fire on session state.
    /// A link MTU this node derived from its own transport, and a value
    /// learned inside a session, are both released by an event that says the
    /// thing they describe is gone, so they carry no deadline.
    pub learned_ms: Option<u64>,
}

impl PathMtuEntry {
    /// An entry released by an event rather than a timer: a locally derived
    /// link MTU, or a value learned inside a session.
    pub fn held(mtu: u16) -> Self {
        Self {
            mtu,
            learned_ms: None,
        }
    }

    /// A remote party's claim stored at `at_ms` for a destination with no
    /// other release path. Expires.
    pub fn learned(mtu: u16, at_ms: u64) -> Self {
        Self {
            mtu,
            learned_ms: Some(at_ms),
        }
    }
}

/// Read-only handle to the per-destination path MTU map. Populated by
/// the discovery handler on `LookupResponse`; read by the TUN reader
/// (outbound clamp) and writer (inbound clamp) at TCP MSS clamp time.
/// Keyed by [`FipsAddress`] (16 bytes, the IPv6 form of a fips peer
/// address).
pub type PathMtuLookup = Arc<RwLock<HashMap<FipsAddress, PathMtuEntry>>>;
