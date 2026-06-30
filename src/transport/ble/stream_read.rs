//! `AsyncRead` adapter over a datagram-shaped [`BleStream`].
//!
//! L2CAP delivers different boundary guarantees per platform:
//!
//! - **BlueZ** (`SOCK_SEQPACKET`) preserves SDU boundaries — one `recv` is
//!   exactly one FIPS packet.
//! - **Android** (`BluetoothSocket` input stream) and **CoreBluetooth** are
//!   byte-stream oriented — a `recv` may return a fragment of a packet, or
//!   several packets coalesced.
//!
//! FIPS packets are self-delimiting via the 4-byte FMP common prefix, so the
//! shared framer [`crate::transport::tcp::stream::read_fmp_packet`] can recover
//! boundaries from any byte stream. This adapter turns a [`BleStream`] (whose
//! `recv` fills a `&mut [u8]`) into the [`AsyncRead`] that framer expects. On a
//! SeqPacket backend it's a no-op pass-through; on a stream backend it
//! reassembles. Either way the layer above sees one whole packet per read.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

use super::io::BleStream;

/// An in-flight `recv`: owns its scratch buffer and yields an owned `Vec`, so
/// the future is `'static` and can live across `poll_read` calls.
type PendingRecv = Pin<Box<dyn Future<Output = std::io::Result<Vec<u8>>> + Send>>;

/// Buffers a [`BleStream`] into an [`AsyncRead`] byte stream.
pub struct BleStreamRead<S: BleStream + 'static> {
    stream: Arc<S>,
    /// Per-`recv` scratch size; also the framer's MTU bound.
    mtu: u16,
    /// Bytes from the last `recv` not yet consumed by the framer.
    leftover: Vec<u8>,
    /// Read cursor into `leftover`.
    pos: usize,
    /// In-flight `recv`, if one is underway.
    pending: Option<PendingRecv>,
}

impl<S: BleStream + 'static> BleStreamRead<S> {
    /// Wrap a stream. `mtu` is the per-`recv` scratch size (use the channel's
    /// recv MTU).
    pub fn new(stream: Arc<S>, mtu: u16) -> Self {
        Self {
            stream,
            mtu: mtu.max(1),
            leftover: Vec::new(),
            pos: 0,
            pending: None,
        }
    }

    /// The wrapped stream, for sending on the same channel (e.g. the pubkey
    /// exchange writes here while reads come through the buffer).
    pub fn stream(&self) -> &S {
        &self.stream
    }
}

impl<S: BleStream + 'static> AsyncRead for BleStreamRead<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // BleStreamRead is Unpin (all fields are), so get_mut is sound.
        let this = self.get_mut();
        loop {
            // Serve buffered bytes first.
            if this.pos < this.leftover.len() {
                let avail = &this.leftover[this.pos..];
                let n = avail.len().min(dst.remaining());
                dst.put_slice(&avail[..n]);
                this.pos += n;
                return Poll::Ready(Ok(()));
            }

            // Buffer drained: pull the next datagram. The future owns its
            // scratch and returns it truncated, so it captures only `Arc<S>`.
            if this.pending.is_none() {
                let stream = Arc::clone(&this.stream);
                let mtu = this.mtu as usize;
                this.pending = Some(Box::pin(async move {
                    let mut scratch = vec![0u8; mtu];
                    let n = stream
                        .recv(&mut scratch)
                        .await
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    scratch.truncate(n);
                    Ok(scratch)
                }));
            }

            match this.pending.as_mut().unwrap().as_mut().poll(cx) {
                Poll::Ready(Ok(buf)) => {
                    this.pending = None;
                    // A zero-length recv is the BleStream peer-closed signal;
                    // leaving `dst` unfilled surfaces as EOF to the framer.
                    if buf.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    this.leftover = buf;
                    this.pos = 0;
                    // loop to copy out
                }
                Poll::Ready(Err(e)) => {
                    this.pending = None;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ble::addr::BleAddr;
    use crate::transport::ble::io::MockBleStream;
    use tokio::io::AsyncReadExt;

    fn addr(n: u8) -> BleAddr {
        BleAddr {
            adapter: "hci0".to_string(),
            device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
        }
    }

    /// Several small recvs reassemble into one read_exact.
    #[tokio::test]
    async fn reassembles_fragmented_recv() {
        let (a, b) = MockBleStream::pair(addr(1), addr(2), 2048);
        // Peer sends three fragments that together form one 10-byte message.
        a.send(b"abc").await.unwrap();
        a.send(b"defg").await.unwrap();
        a.send(b"hij").await.unwrap();

        let mut reader = BleStreamRead::new(Arc::new(b), 2048);
        let mut out = [0u8; 10];
        reader.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"abcdefghij");
    }

    /// A recv carrying several packets is served across multiple reads without
    /// dropping the tail (the coalescing case).
    #[tokio::test]
    async fn serves_coalesced_recv_in_pieces() {
        let (a, b) = MockBleStream::pair(addr(1), addr(2), 2048);
        a.send(b"0123456789").await.unwrap();

        let mut reader = BleStreamRead::new(Arc::new(b), 2048);
        let mut first = [0u8; 4];
        reader.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"0123");
        let mut rest = [0u8; 6];
        reader.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"456789");
    }

    /// A closed stream surfaces as EOF (read_exact errors with UnexpectedEof).
    #[tokio::test]
    async fn closed_stream_is_eof() {
        let (a, b) = MockBleStream::pair(addr(1), addr(2), 2048);
        drop(a); // peer closes
        let mut reader = BleStreamRead::new(Arc::new(b), 2048);
        let mut out = [0u8; 4];
        let err = reader.read_exact(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
