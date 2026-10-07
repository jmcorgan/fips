//! Wire protocol between the daemon and the BLE agent.
//!
//! macOS gives CoreBluetooth only to processes in a user's login session,
//! never to a root launchd daemon, so on macOS the radio can live in a
//! per-user agent (see [`super::agent`]) while the transport lives in the
//! daemon (see [`super::agent_server`]). This is what crosses the Unix
//! socket between them.
//!
//! It is the [`BleRadio`](super::super::io_radio::BleRadio) command surface
//! and the bridge's `deliver_*` callbacks, flattened into frames, plus the
//! channel bytes the embedder would otherwise move itself:
//!
//! - daemon → agent: the radio commands, and outbound bytes ([`Frame::Send`]);
//! - agent → daemon: [`Frame::Hello`] once, then accepted and dialled
//!   channels, adverts, inbound bytes ([`Frame::Recv`]) and closures.
//!
//! Channels are named on the wire by the agent's identifier for them, never
//! the bridge's: the agent allocates it when the channel opens, before the
//! daemon has registered anything.
//!
//! # Framing
//!
//! `len: u32 BE | tag: u8 | payload`, where `len` counts the tag and payload.
//! Integers are big-endian. A link address is its six device bytes; both
//! ends are radio-bridge backends and share one adapter label.

use std::io;

use super::super::addr::BleAddr;
use super::super::io_radio::RADIO_ADAPTER;

/// Protocol version carried in [`Frame::Hello`].
pub const VERSION: u8 = 1;

/// Largest frame accepted, tag included. Comfortably above the largest data
/// frame either end builds — a channel identifier and one read or packet of
/// at most a 16-bit MTU — so a length beyond it is a corrupt or hostile
/// stream.
pub const MAX_FRAME: usize = 128 * 1024;

/// One message on the agent socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    // --- daemon → agent ------------------------------------------------
    /// Dial `addr` on `psm`; answered by [`Frame::ConnectResult`].
    Connect {
        id: i64,
        addr: BleAddr,
        psm: u16,
    },
    /// Advertise the FIPS service.
    StartAdvertising {
        psm: u16,
    },
    StopAdvertising,
    StartScanning,
    StopScanning,
    /// The daemon dropped channel `ch`.
    Close {
        ch: u32,
    },
    /// Bytes to write to channel `ch`.
    Send {
        ch: u32,
        data: Vec<u8>,
    },

    // --- agent → daemon ------------------------------------------------
    /// First frame of every connection: who is speaking, and the PSM its
    /// listener is on.
    Hello {
        version: u8,
        psm: u16,
    },
    /// A peer opened channel `ch` to us.
    Inbound {
        ch: u32,
        addr: BleAddr,
        mtu: u16,
    },
    /// The outcome of [`Frame::Connect`] `id`. `ch` and `mtu` are meaningful
    /// only when `ok`.
    ConnectResult {
        id: i64,
        ok: bool,
        ch: u32,
        addr: BleAddr,
        mtu: u16,
    },
    /// An advert; `psm` and `rssi` as the scanner reported them.
    Scan {
        addr: BleAddr,
        psm: Option<u16>,
        rssi: Option<i16>,
    },
    /// Bytes read from channel `ch`.
    Recv {
        ch: u32,
        data: Vec<u8>,
    },
    /// Channel `ch` ended on the radio side.
    Closed {
        ch: u32,
    },
}

mod tag {
    pub const CONNECT: u8 = 1;
    pub const START_ADVERTISING: u8 = 2;
    pub const STOP_ADVERTISING: u8 = 3;
    pub const START_SCANNING: u8 = 4;
    pub const STOP_SCANNING: u8 = 5;
    pub const CLOSE: u8 = 6;
    pub const SEND: u8 = 7;
    pub const HELLO: u8 = 16;
    pub const INBOUND: u8 = 17;
    pub const CONNECT_RESULT: u8 = 18;
    pub const SCAN: u8 = 19;
    pub const RECV: u8 = 20;
    pub const CLOSED: u8 = 21;
}

/// Wire value for "no PSM in the advert".
const NO_PSM: u16 = 0;
/// Wire value for "no RSSI reading".
const NO_RSSI: i16 = i16::MIN;

impl Frame {
    /// Encode as one length-prefixed frame.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; 4];
        match self {
            Frame::Connect { id, addr, psm } => {
                out.push(tag::CONNECT);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&addr.device);
                out.extend_from_slice(&psm.to_be_bytes());
            }
            Frame::StartAdvertising { psm } => {
                out.push(tag::START_ADVERTISING);
                out.extend_from_slice(&psm.to_be_bytes());
            }
            Frame::StopAdvertising => out.push(tag::STOP_ADVERTISING),
            Frame::StartScanning => out.push(tag::START_SCANNING),
            Frame::StopScanning => out.push(tag::STOP_SCANNING),
            Frame::Close { ch } => {
                out.push(tag::CLOSE);
                out.extend_from_slice(&ch.to_be_bytes());
            }
            Frame::Send { ch, data } => {
                out.push(tag::SEND);
                out.extend_from_slice(&ch.to_be_bytes());
                out.extend_from_slice(data);
            }
            Frame::Hello { version, psm } => {
                out.push(tag::HELLO);
                out.push(*version);
                out.extend_from_slice(&psm.to_be_bytes());
            }
            Frame::Inbound { ch, addr, mtu } => {
                out.push(tag::INBOUND);
                out.extend_from_slice(&ch.to_be_bytes());
                out.extend_from_slice(&addr.device);
                out.extend_from_slice(&mtu.to_be_bytes());
            }
            Frame::ConnectResult {
                id,
                ok,
                ch,
                addr,
                mtu,
            } => {
                out.push(tag::CONNECT_RESULT);
                out.extend_from_slice(&id.to_be_bytes());
                out.push(u8::from(*ok));
                out.extend_from_slice(&ch.to_be_bytes());
                out.extend_from_slice(&addr.device);
                out.extend_from_slice(&mtu.to_be_bytes());
            }
            Frame::Scan { addr, psm, rssi } => {
                out.push(tag::SCAN);
                out.extend_from_slice(&addr.device);
                out.extend_from_slice(&psm.unwrap_or(NO_PSM).to_be_bytes());
                out.extend_from_slice(&rssi.unwrap_or(NO_RSSI).to_be_bytes());
            }
            Frame::Recv { ch, data } => {
                out.push(tag::RECV);
                out.extend_from_slice(&ch.to_be_bytes());
                out.extend_from_slice(data);
            }
            Frame::Closed { ch } => {
                out.push(tag::CLOSED);
                out.extend_from_slice(&ch.to_be_bytes());
            }
        }
        let len = (out.len() - 4) as u32;
        out[..4].copy_from_slice(&len.to_be_bytes());
        out
    }

    /// Decode a frame body: the tag and payload that followed the length.
    pub fn decode(body: &[u8]) -> io::Result<Frame> {
        let (&tag, payload) = body.split_first().ok_or_else(|| bad("empty frame"))?;
        let mut r = Reader(payload);
        let frame = match tag {
            tag::CONNECT => Frame::Connect {
                id: r.i64()?,
                addr: r.addr()?,
                psm: r.u16()?,
            },
            tag::START_ADVERTISING => Frame::StartAdvertising { psm: r.u16()? },
            tag::STOP_ADVERTISING => Frame::StopAdvertising,
            tag::START_SCANNING => Frame::StartScanning,
            tag::STOP_SCANNING => Frame::StopScanning,
            tag::CLOSE => Frame::Close { ch: r.u32()? },
            tag::SEND => Frame::Send {
                ch: r.u32()?,
                data: r.rest(),
            },
            tag::HELLO => Frame::Hello {
                version: r.u8()?,
                psm: r.u16()?,
            },
            tag::INBOUND => Frame::Inbound {
                ch: r.u32()?,
                addr: r.addr()?,
                mtu: r.u16()?,
            },
            tag::CONNECT_RESULT => Frame::ConnectResult {
                id: r.i64()?,
                ok: r.u8()? != 0,
                ch: r.u32()?,
                addr: r.addr()?,
                mtu: r.u16()?,
            },
            tag::SCAN => Frame::Scan {
                addr: r.addr()?,
                psm: Some(r.u16()?).filter(|&p| p != NO_PSM),
                rssi: Some(r.i16()?).filter(|&v| v != NO_RSSI),
            },
            tag::RECV => Frame::Recv {
                ch: r.u32()?,
                data: r.rest(),
            },
            tag::CLOSED => Frame::Closed { ch: r.u32()? },
            other => return Err(bad(&format!("unknown frame tag {other}"))),
        };
        Ok(frame)
    }
}

/// Read one frame from a blocking reader. `Ok(None)` is a clean end of
/// stream between frames.
pub fn read_frame(r: &mut impl io::Read) -> io::Result<Option<Frame>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut body = vec![0u8; checked_len(len)?];
    r.read_exact(&mut body)?;
    Frame::decode(&body).map(Some)
}

/// Read one frame from an async reader. `Ok(None)` is a clean end of stream
/// between frames.
pub async fn read_frame_async(
    r: &mut (impl tokio::io::AsyncRead + Unpin),
) -> io::Result<Option<Frame>> {
    use tokio::io::AsyncReadExt;
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut body = vec![0u8; checked_len(len)?];
    r.read_exact(&mut body).await?;
    Frame::decode(&body).map(Some)
}

fn checked_len(len: [u8; 4]) -> io::Result<usize> {
    match u32::from_be_bytes(len) as usize {
        0 => Err(bad("empty frame")),
        n if n > MAX_FRAME => Err(bad(&format!("frame of {n} bytes exceeds {MAX_FRAME}"))),
        n => Ok(n),
    }
}

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}

/// A cursor over a frame payload.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        if self.0.len() < N {
            return Err(bad("truncated frame"));
        }
        let (head, rest) = self.0.split_at(N);
        self.0 = rest;
        Ok(head.try_into().expect("split at N"))
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take::<1>()?[0])
    }
    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.take()?))
    }
    fn i16(&mut self) -> io::Result<i16> {
        Ok(i16::from_be_bytes(self.take()?))
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.take()?))
    }
    fn i64(&mut self) -> io::Result<i64> {
        Ok(i64::from_be_bytes(self.take()?))
    }
    fn addr(&mut self) -> io::Result<BleAddr> {
        Ok(BleAddr {
            adapter: RADIO_ADAPTER.to_string(),
            device: self.take()?,
        })
    }
    fn rest(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> BleAddr {
        BleAddr {
            adapter: RADIO_ADAPTER.to_string(),
            device: [0x02, 1, 2, 3, 4, n],
        }
    }

    fn every_frame() -> Vec<Frame> {
        vec![
            Frame::Connect {
                id: -7,
                addr: addr(1),
                psm: 0x00C1,
            },
            Frame::StartAdvertising { psm: 0x0085 },
            Frame::StopAdvertising,
            Frame::StartScanning,
            Frame::StopScanning,
            Frame::Close { ch: 9 },
            Frame::Send {
                ch: 9,
                data: b"out".to_vec(),
            },
            Frame::Send {
                ch: 9,
                data: vec![],
            },
            Frame::Hello {
                version: VERSION,
                psm: 0x00C0,
            },
            Frame::Inbound {
                ch: 3,
                addr: addr(2),
                mtu: 2048,
            },
            Frame::ConnectResult {
                id: 42,
                ok: true,
                ch: 4,
                addr: addr(3),
                mtu: 512,
            },
            Frame::ConnectResult {
                id: 43,
                ok: false,
                ch: 0,
                addr: addr(3),
                mtu: 0,
            },
            Frame::Scan {
                addr: addr(4),
                psm: Some(0x0080),
                rssi: Some(-71),
            },
            Frame::Scan {
                addr: addr(4),
                psm: None,
                rssi: None,
            },
            Frame::Recv {
                ch: 3,
                data: vec![0; 2048],
            },
            Frame::Closed { ch: 3 },
        ]
    }

    #[test]
    fn every_frame_round_trips() {
        for frame in every_frame() {
            let wire = frame.encode();
            let len = u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize;
            assert_eq!(len, wire.len() - 4, "{frame:?}");
            assert_eq!(Frame::decode(&wire[4..]).unwrap(), frame);
        }
    }

    #[test]
    fn a_stream_of_frames_reads_back_in_order() {
        let wire: Vec<u8> = every_frame().iter().flat_map(Frame::encode).collect();
        let mut r = std::io::Cursor::new(wire);
        for frame in every_frame() {
            assert_eq!(read_frame(&mut r).unwrap(), Some(frame));
        }
        assert_eq!(read_frame(&mut r).unwrap(), None, "clean end of stream");
    }

    #[tokio::test]
    async fn the_async_reader_agrees() {
        let wire: Vec<u8> = every_frame().iter().flat_map(Frame::encode).collect();
        let mut r = std::io::Cursor::new(wire);
        for frame in every_frame() {
            assert_eq!(read_frame_async(&mut r).await.unwrap(), Some(frame));
        }
        assert_eq!(read_frame_async(&mut r).await.unwrap(), None);
    }

    #[test]
    fn truncated_and_unknown_frames_are_rejected() {
        assert!(Frame::decode(&[]).is_err());
        assert!(Frame::decode(&[tag::CLOSE, 0, 0]).is_err());
        assert!(Frame::decode(&[0xEE]).is_err());
    }

    #[test]
    fn an_oversized_length_is_rejected_before_allocating() {
        let mut r = std::io::Cursor::new(u32::MAX.to_be_bytes().to_vec());
        assert_eq!(
            read_frame(&mut r).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn a_stream_cut_mid_frame_is_an_error_not_a_clean_end() {
        let mut wire = Frame::Closed { ch: 1 }.encode();
        wire.truncate(wire.len() - 1);
        assert!(read_frame(&mut std::io::Cursor::new(wire)).is_err());
    }
}
