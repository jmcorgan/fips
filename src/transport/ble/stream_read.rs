//! `AsyncRead` adapter over a `BleStream`.
//!
//! The BLE receive path used to treat one `recv()` as one whole FIPS
//! packet. That is a property of a *SeqPacket* socket, not of L2CAP: a
//! stream-oriented backend may return a fragment of a packet, or several
//! packets coalesced, from a single read. This adapter turns the
//! datagram-shaped [`BleStream`] into the [`AsyncRead`] that
//! `crate::transport::framing::read_fmp_packet` expects, buffering bytes
//! left over from one read into the next so packet boundaries are recovered
//! from the FMP length prefix rather than trusted to the OS.
//!
//! Nothing here is backend-specific. On a boundary-preserving backend the
//! adapter is a transparent pass-through: one `recv` fills the buffer, the
//! framer consumes exactly it, and the next read hits the underlying stream
//! again.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

use crate::transport::TransportError;

use super::io::BleStream;

/// Smallest scratch buffer used for a single `recv`.
///
/// Guards against a backend reporting a degenerate receive MTU, which would
/// otherwise make every `recv` return zero bytes and look like EOF.
const MIN_RECV_CHUNK: usize = 64;

/// A pending `recv` that owns its scratch buffer and yields an owned `Vec`.
///
/// Owning the buffer is what makes the future `'static`, which is what lets
/// it be held across `poll_read` calls when a read returns `Pending`.
type RecvFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>, TransportError>> + Send>>;

/// Buffered [`AsyncRead`] view of a [`BleStream`].
pub struct BleStreamRead<S: BleStream + 'static> {
    stream: Arc<S>,
    /// Bytes received but not yet handed to the reader.
    chunk: Vec<u8>,
    /// Read cursor into `chunk`.
    pos: usize,
    /// Scratch size for one underlying `recv`.
    capacity: usize,
    /// In-flight `recv`, kept across polls.
    pending: Option<RecvFuture>,
    /// Set once the peer has closed the connection.
    eof: bool,
}

impl<S: BleStream + 'static> BleStreamRead<S> {
    /// Wrap a stream, sizing the scratch buffer from its receive MTU.
    pub fn new(stream: Arc<S>, recv_mtu: u16) -> Self {
        Self {
            stream,
            chunk: Vec::new(),
            pos: 0,
            capacity: (recv_mtu as usize).max(MIN_RECV_CHUNK),
            pending: None,
            eof: false,
        }
    }

    /// Number of bytes already received but not yet consumed.
    ///
    /// Non-zero after a peer coalesces data behind an earlier message; the
    /// hand-off from the pubkey exchange to the framer must preserve them.
    #[cfg(test)]
    pub fn buffered(&self) -> usize {
        self.chunk.len() - self.pos
    }

    fn start_recv(&self) -> RecvFuture {
        let stream = Arc::clone(&self.stream);
        let capacity = self.capacity;
        Box::pin(async move {
            let mut scratch = vec![0u8; capacity];
            let n = stream.recv(&mut scratch).await?;
            scratch.truncate(n);
            Ok(scratch)
        })
    }
}

/// Map a transport error onto the `io::Error` `AsyncRead` must report.
fn to_io(e: TransportError) -> std::io::Error {
    match e {
        TransportError::Io(e) => e,
        other => std::io::Error::other(other.to_string()),
    }
}

impl<S: BleStream + 'static> AsyncRead for BleStreamRead<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Serve from the leftover buffer first.
            if this.pos < this.chunk.len() {
                let n = (this.chunk.len() - this.pos).min(buf.remaining());
                buf.put_slice(&this.chunk[this.pos..this.pos + n]);
                this.pos += n;
                if this.pos == this.chunk.len() {
                    this.chunk.clear();
                    this.pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // A closed connection stays closed: report EOF (a filled length
            // of zero) rather than re-polling a dead stream forever.
            if this.eof {
                return Poll::Ready(Ok(()));
            }

            let mut fut = match this.pending.take() {
                Some(f) => f,
                None => this.start_recv(),
            };
            match fut.as_mut().poll(cx) {
                Poll::Pending => {
                    this.pending = Some(fut);
                    return Poll::Pending;
                }
                Poll::Ready(Ok(chunk)) => {
                    // `recv` returning zero bytes is the peer-closed signal,
                    // not an empty packet.
                    if chunk.is_empty() {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.chunk = chunk;
                    this.pos = 0;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(to_io(e))),
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ble::addr::BleAddr;
    use crate::transport::ble::io::MockBleStream;
    use tokio::io::AsyncReadExt;
    use tokio::sync::Mutex as TokioMutex;

    fn test_addr(n: u8) -> BleAddr {
        BleAddr {
            adapter: "hci0".to_string(),
            device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
        }
    }

    /// A stream that replays a fixed script of `recv` results and then
    /// returns `Ok(0)` forever — the "peer closed but socket still open"
    /// shape a channel-backed mock cannot produce.
    struct ScriptedStream {
        addr: BleAddr,
        chunks: TokioMutex<std::collections::VecDeque<Vec<u8>>>,
    }

    impl ScriptedStream {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                addr: test_addr(9),
                chunks: TokioMutex::new(chunks.into()),
            }
        }
    }

    impl BleStream for ScriptedStream {
        async fn send(&self, _data: &[u8]) -> Result<(), TransportError> {
            Ok(())
        }

        async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
            match self.chunks.lock().await.pop_front() {
                Some(chunk) => {
                    let n = chunk.len().min(buf.len());
                    buf[..n].copy_from_slice(&chunk[..n]);
                    Ok(n)
                }
                None => Ok(0),
            }
        }

        fn send_mtu(&self) -> u16 {
            2048
        }

        fn recv_mtu(&self) -> u16 {
            2048
        }

        fn remote_addr(&self) -> &BleAddr {
            &self.addr
        }
    }

    #[tokio::test]
    async fn test_fragmented_delivery_is_reassembled() {
        let (peer, local) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        peer.send(b"abc").await.unwrap();
        peer.send(b"defg").await.unwrap();
        peer.send(b"hij").await.unwrap();

        let mut reader = BleStreamRead::new(Arc::new(local), 2048);
        let mut out = [0u8; 10];
        reader.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"abcdefghij");
    }

    #[tokio::test]
    async fn test_coalesced_delivery_keeps_the_tail() {
        let (peer, local) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        peer.send(b"0123456789").await.unwrap();

        let mut reader = BleStreamRead::new(Arc::new(local), 2048);
        let mut head = [0u8; 4];
        reader.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"0123");
        assert_eq!(reader.buffered(), 6);

        let mut tail = [0u8; 6];
        reader.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"456789");
    }

    #[tokio::test]
    async fn test_peer_drop_surfaces_as_unexpected_eof() {
        let (peer, local) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        peer.send(b"ab").await.unwrap();
        drop(peer);

        let mut reader = BleStreamRead::new(Arc::new(local), 2048);
        let mut out = [0u8; 4];
        let err = reader.read_exact(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn test_zero_length_recv_is_eof_not_readiness() {
        let stream = ScriptedStream::new(vec![b"xy".to_vec()]);
        let mut reader = BleStreamRead::new(Arc::new(stream), 2048);

        let mut out = [0u8; 8];
        let n = reader.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"xy");

        // The scripted stream now returns Ok(0) forever. That must read as
        // EOF once and stay EOF, not as a spurious zero-length packet.
        assert_eq!(reader.read(&mut out).await.unwrap(), 0);
        assert_eq!(reader.read(&mut out).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_read_smaller_than_chunk_leaves_remainder() {
        let stream = ScriptedStream::new(vec![b"abcdef".to_vec()]);
        let mut reader = BleStreamRead::new(Arc::new(stream), 2048);

        let mut one = [0u8; 1];
        reader.read_exact(&mut one).await.unwrap();
        assert_eq!(&one, b"a");
        assert_eq!(reader.buffered(), 5);

        let mut rest = [0u8; 5];
        reader.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"bcdef");
        assert_eq!(reader.buffered(), 0);
    }

    #[tokio::test]
    async fn test_degenerate_recv_mtu_still_reads() {
        let (peer, local) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        peer.send(b"hello").await.unwrap();

        let mut reader = BleStreamRead::new(Arc::new(local), 0);
        let mut out = [0u8; 5];
        reader.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"hello");
    }
}
