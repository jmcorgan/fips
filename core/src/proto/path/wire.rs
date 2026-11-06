//! Path messages of multipath v1: `PathProbe` (0x52), `PathAck` (0x53) and
//! `PathClose` (0x54), with the extension block the first two may carry.
//!
//! The layouts are those of the multipath v1 draft, Sections 7.1 to 7.5, and
//! the flag, capability, close-reason and extension registries of its Sections
//! 13.2 to 13.5. Offsets in the draft start at the link message type byte.
//! As with the other link messages, `encode` writes the type byte and
//! `decode` takes the bytes after it, which the caller has already consumed
//! to dispatch.
//!
//! This is the codec only. When to send a path message, and what a node does
//! with one it receives, belong to the handler; a decode error means the
//! message is dropped without an answer.

use crate::proto::Error;
use crate::proto::codec::{Reader, Writer};
use crate::proto::fmp::wire::FRAME_OVERHEAD;
use crate::proto::link::LinkMessageType;
use alloc::vec::Vec;

/// Smallest `PathProbe`, counted from its type byte and including padding.
/// Equal to a `PathAck`'s fixed part, so an answer never needs to be larger
/// than its probe. A probe shorter than this is not answered.
pub const PATH_PROBE_MIN_SIZE: usize = 27;

/// Fixed part of a `PathProbe`: type, `probe_id`, `flags`, `path_id`, `caps`.
pub const PATH_PROBE_FIXED_SIZE: usize = 11;

/// Fixed part of a `PathAck`: the probe's fields plus `echo_path_id` and the
/// three receive counts.
pub const PATH_ACK_FIXED_SIZE: usize = 27;

/// Size of a `PathClose`. Bytes after it are ignored on receipt.
pub const PATH_CLOSE_SIZE: usize = 7;

/// Criticality bit of an extension TLV's type field.
pub const TLV_CRITICAL: u16 = 0x8000;

/// The `flags` byte of `PathProbe` and `PathAck` (path message flags registry).
///
/// The received byte is kept whole, so a later amendment can read a bit this
/// version leaves reserved; this version reads only the named bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathFlags(u8);

impl PathFlags {
    /// The sender sends data on this path.
    pub const ACTIVE: u8 = 0x01;
    /// An extension block follows the fixed part.
    pub const EXT: u8 = 0x02;

    /// Flags as received, reserved bits included.
    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Flags with only `ACTIVE` set or clear.
    pub fn with_active(active: bool) -> Self {
        Self(if active { Self::ACTIVE } else { 0 })
    }

    /// The byte as received or constructed.
    pub fn bits(self) -> u8 {
        self.0
    }

    /// Whether the sender sends data on this path.
    pub fn active(self) -> bool {
        self.0 & Self::ACTIVE != 0
    }

    /// Whether an extension block follows the fixed part.
    pub fn ext(self) -> bool {
        self.0 & Self::EXT != 0
    }

    /// The byte a sender puts on the wire: `ACTIVE` only. Reserved bits are
    /// sent as zero, and `EXT` is never set because no extension is defined.
    fn wire(self) -> u8 {
        self.0 & Self::ACTIVE
    }
}

/// The `caps` byte of `PathProbe` and `PathAck` (path capability registry).
///
/// Kept whole on receipt for the same reason as [`PathFlags`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathCaps(u8);

impl PathCaps {
    /// The sender offers aggregation on this link.
    pub const AGGREGATE: u8 = 0x01;

    /// Capabilities as received, reserved bits included.
    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Capabilities with only `AGGREGATE` set or clear.
    pub fn with_aggregate(aggregate: bool) -> Self {
        Self(if aggregate { Self::AGGREGATE } else { 0 })
    }

    /// The byte as received or constructed.
    pub fn bits(self) -> u8 {
        self.0
    }

    /// Whether the sender offers aggregation.
    pub fn aggregate(self) -> bool {
        self.0 & Self::AGGREGATE != 0
    }

    /// The byte a sender puts on the wire, reserved bits zero.
    fn wire(self) -> u8 {
        self.0 & Self::AGGREGATE
    }
}

/// `PathProbe` (0x52): proves a path in both directions when answered.
///
/// | Offset | Field      | Size | Notes                                   |
/// |--------|------------|------|-----------------------------------------|
/// | 0      | type       | 1    | 0x52                                    |
/// | 1      | probe_id   | 4    | LE; per-path sequence from a random start |
/// | 5      | flags      | 1    | [`PathFlags`]                           |
/// | 6      | path_id    | 4    | LE; the sender's id for the path. Not 0 |
/// | 10     | caps       | 1    | [`PathCaps`]                            |
/// | 11     | extension  | var  | only if `EXT` is set                    |
/// | after  | padding    | rest | zero; whole probe at least 27 bytes     |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathProbe {
    /// The sender's sequence number for this path.
    pub probe_id: u32,
    /// Path message flags.
    pub flags: PathFlags,
    /// The sender's own identifier for the path the probe travels on.
    pub path_id: u32,
    /// Path capability bits.
    pub caps: PathCaps,
    /// Whole length from the type byte, padding included. Set by `decode`
    /// from the bytes received; on encode, the length to pad to, raised to
    /// [`PATH_PROBE_MIN_SIZE`] when smaller.
    pub len: usize,
}

impl PathProbe {
    /// A probe of the smallest size. Use [`Self::with_len`] to pad it, for
    /// example to the link MTU when it tests a new path.
    pub fn new(probe_id: u32, path_id: u32, flags: PathFlags, caps: PathCaps) -> Self {
        Self {
            probe_id,
            flags,
            path_id,
            caps,
            len: PATH_PROBE_MIN_SIZE,
        }
    }

    /// The same probe padded to `len` bytes (never fewer than the minimum).
    pub fn with_len(mut self, len: usize) -> Self {
        self.len = len;
        self
    }

    /// Whether the probe is long enough to be answered.
    pub fn answerable(&self) -> bool {
        self.len >= PATH_PROBE_MIN_SIZE
    }

    /// Encode as a link message (type byte included), zero-padded to
    /// `max(len, PATH_PROBE_MIN_SIZE)` bytes.
    pub fn encode(&self) -> Vec<u8> {
        let len = self.len.max(PATH_PROBE_MIN_SIZE);
        let mut w = Writer::with_capacity(len);
        w.write_u8(LinkMessageType::PathProbe.to_byte());
        w.write_u32_le(self.probe_id);
        w.write_u8(self.flags.wire());
        w.write_u32_le(self.path_id);
        w.write_u8(self.caps.wire());
        let mut out = w.into_vec();
        out.resize(len, 0);
        out
    }

    /// Decode from the bytes after the type byte.
    ///
    /// Fails if the fixed part is incomplete, if `path_id` is 0, or if the
    /// extension block is malformed or carries an unknown critical TLV. Every
    /// failure means: drop the probe and do not answer it.
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(payload);
        r.require(PATH_PROBE_FIXED_SIZE - 1)?;
        let probe_id = r.read_u32_le()?;
        let flags = PathFlags::from_bits(r.read_u8()?);
        let path_id = r.read_u32_le()?;
        let caps = PathCaps::from_bits(r.read_u8()?);
        if path_id == 0 {
            return Err(Error::Malformed("path_id is zero"));
        }
        if flags.ext() {
            check_extension(r.rest())?;
        }
        Ok(Self {
            probe_id,
            flags,
            path_id,
            caps,
            len: payload.len() + 1,
        })
    }
}

/// `PathAck` (0x53): answers one `PathProbe` on the transport it arrived on.
///
/// | Offset | Field        | Size | Notes                                  |
/// |--------|--------------|------|----------------------------------------|
/// | 0      | type         | 1    | 0x53                                   |
/// | 1      | probe_id     | 4    | LE; copied from the probe              |
/// | 5      | flags        | 1    | [`PathFlags`], for the answerer's use  |
/// | 6      | path_id      | 4    | LE; the answerer's id for the path     |
/// | 10     | echo_path_id | 4    | LE; the probe's `path_id`              |
/// | 14     | caps         | 1    | [`PathCaps`]                           |
/// | 15     | rx_time_us   | 4    | LE; answerer's clock at receipt        |
/// | 19     | rx_frames    | 4    | LE; frames attributed to the path      |
/// | 23     | rx_bytes     | 4    | LE; their length                       |
/// | 27     | extension    | var  | only if `EXT` is set                   |
/// | after  | padding      | rest | zero; see [`ack_len`]                  |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathAck {
    /// Copied from the probe answered.
    pub probe_id: u32,
    /// Path message flags for the answerer's own use of this path.
    pub flags: PathFlags,
    /// The answerer's own identifier for this path.
    pub path_id: u32,
    /// The `path_id` of the probe answered.
    pub echo_path_id: u32,
    /// Path capability bits.
    pub caps: PathCaps,
    /// The answerer's monotonic clock at receipt, microseconds mod 2^32.
    pub rx_time_us: u32,
    /// Authenticated frames the answerer attributed to this path, mod 2^32.
    pub rx_frames: u32,
    /// Total length of those frames, mod 2^32.
    pub rx_bytes: u32,
    /// Whole length from the type byte, padding included. Set by `decode`;
    /// on encode, the length to pad to, raised to the fixed part when
    /// smaller.
    pub len: usize,
}

impl PathAck {
    /// Encode as a link message (type byte included), zero-padded to
    /// `max(len, PATH_ACK_FIXED_SIZE)` bytes.
    pub fn encode(&self) -> Vec<u8> {
        let len = self.len.max(PATH_ACK_FIXED_SIZE);
        let mut w = Writer::with_capacity(len);
        w.write_u8(LinkMessageType::PathAck.to_byte());
        w.write_u32_le(self.probe_id);
        w.write_u8(self.flags.wire());
        w.write_u32_le(self.path_id);
        w.write_u32_le(self.echo_path_id);
        w.write_u8(self.caps.wire());
        w.write_u32_le(self.rx_time_us);
        w.write_u32_le(self.rx_frames);
        w.write_u32_le(self.rx_bytes);
        let mut out = w.into_vec();
        out.resize(len, 0);
        out
    }

    /// Decode from the bytes after the type byte.
    ///
    /// Fails on the same conditions as [`PathProbe::decode`]; every failure
    /// means the ack is dropped.
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(payload);
        r.require(PATH_ACK_FIXED_SIZE - 1)?;
        let probe_id = r.read_u32_le()?;
        let flags = PathFlags::from_bits(r.read_u8()?);
        let path_id = r.read_u32_le()?;
        let echo_path_id = r.read_u32_le()?;
        let caps = PathCaps::from_bits(r.read_u8()?);
        let rx_time_us = r.read_u32_le()?;
        let rx_frames = r.read_u32_le()?;
        let rx_bytes = r.read_u32_le()?;
        if path_id == 0 {
            return Err(Error::Malformed("path_id is zero"));
        }
        if flags.ext() {
            check_extension(r.rest())?;
        }
        Ok(Self {
            probe_id,
            flags,
            path_id,
            echo_path_id,
            caps,
            rx_time_us,
            rx_frames,
            rx_bytes,
            len: payload.len() + 1,
        })
    }
}

/// Length of the `PathAck` answering a probe of `probe_len` bytes: the smaller
/// of the probe's length and the answerer's own transport link MTU for the
/// path, and never less than the ack's fixed part.
///
/// `probe_len` and the result count link-message bytes from the type byte.
/// `transport_mtu` is the transport's link MTU in frame bytes, as the draft
/// states the rule; this function subtracts the established frame's
/// overhead ([`FRAME_OVERHEAD`]) to get the largest ack that fits.
pub fn ack_len(probe_len: usize, transport_mtu: usize) -> usize {
    probe_len
        .min(transport_mtu.saturating_sub(FRAME_OVERHEAD))
        .max(PATH_ACK_FIXED_SIZE)
}

/// Why a path is being closed (path close reason registry). Advisory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PathCloseReason {
    /// No reason given, or one this node does not implement.
    Unspecified = 0,
    /// The local transport or its interface was removed.
    InterfaceGone = 1,
    /// The local transport reports loss of carrier.
    CarrierLost = 2,
    /// Closed by local policy or the operator.
    Operator = 3,
}

impl PathCloseReason {
    /// Read a reason byte; a value not assigned reads as `Unspecified`.
    pub fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::InterfaceGone,
            2 => Self::CarrierLost,
            3 => Self::Operator,
            _ => Self::Unspecified,
        }
    }
}

/// `PathClose` (0x54): the sender is closing the path it names.
///
/// | Offset | Field   | Size | Notes                                  |
/// |--------|---------|------|----------------------------------------|
/// | 0      | type    | 1    | 0x54                                   |
/// | 1      | path_id | 4    | LE; the **receiver's** id for the path |
/// | 5      | reason  | 1    | [`PathCloseReason`]                    |
/// | 6      | flags   | 1    | reserved; zero, ignored on receipt     |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathClose {
    /// The receiver's identifier for the path, as it carried in its own
    /// probes and answers.
    pub path_id: u32,
    /// Why the path is closed.
    pub reason: PathCloseReason,
}

impl PathClose {
    /// Encode as a link message (type byte included).
    pub fn encode(&self) -> [u8; PATH_CLOSE_SIZE] {
        let mut out = [0u8; PATH_CLOSE_SIZE];
        out[0] = LinkMessageType::PathClose.to_byte();
        out[1..5].copy_from_slice(&self.path_id.to_le_bytes());
        out[5] = self.reason as u8;
        out
    }

    /// Decode from the bytes after the type byte. The reserved `flags` byte
    /// must be present and is ignored, as are any bytes after it.
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(payload);
        r.require(PATH_CLOSE_SIZE - 1)?;
        let path_id = r.read_u32_le()?;
        let reason = PathCloseReason::from_byte(r.read_u8()?);
        Ok(Self { path_id, reason })
    }
}

/// Check an extension block (`ext_len u16le`, then TLVs) at the start of
/// `rest`; anything after the block is padding.
///
/// No TLV type is defined yet, so every TLV is unknown: a non-critical one is
/// skipped and a critical one rejects the message.
fn check_extension(rest: &[u8]) -> Result<(), Error> {
    if rest.len() < 2 {
        return Err(Error::Malformed(
            "path extension block overruns the message",
        ));
    }
    let ext_len = u16::from_le_bytes([rest[0], rest[1]]) as usize;
    let Some(block) = rest.get(2..2 + ext_len) else {
        return Err(Error::Malformed(
            "path extension block overruns the message",
        ));
    };
    let mut r = Reader::new(block);
    while r.remaining() > 0 {
        if r.remaining() < 4 {
            return Err(Error::Malformed("path extension TLV overruns the block"));
        }
        let tlv_type = r.read_u16_le()?;
        let tlv_len = r.read_u16_le()? as usize;
        if tlv_len > r.remaining() {
            return Err(Error::Malformed("path extension TLV overruns the block"));
        }
        if tlv_type & TLV_CRITICAL != 0 {
            return Err(Error::Malformed("unknown critical path extension TLV"));
        }
        r.advance(tlv_len);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/wire.rs"]
mod tests;
