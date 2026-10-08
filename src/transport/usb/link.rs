//! What a USB link is to the transport, and how one is handed to it.
//!
//! A link is a reliable, ordered byte stream to exactly one other node, with
//! no address either side could dial. Whatever produced it — the host backend
//! that switched a phone into accessory mode, or an embedder that opened the
//! accessory on the phone — hands it over as a pair of channels, and the
//! transport neither knows nor cares which role this end plays.
//!
//! Channels rather than a trait over the device keep each backend's I/O
//! model its own: the accessory device is read with blocking calls on
//! dedicated threads, a host backend submits bulk transfers, and a test wires
//! two links back to back.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::{Notify, mpsc};

/// Largest single transfer either direction may carry.
///
/// The Android accessory driver moves data through 16 KiB buffers, and a
/// host transfer larger than the reader's buffer is lost in part on some
/// devices. Every write a link is asked to make, and every read buffer a
/// backend uses, is held to this.
pub const USB_TRANSFER_MAX: usize = 16 * 1024;

/// Writes or reads a link may have queued between the transport and its
/// backend before the producer waits.
const LINK_QUEUE_DEPTH: usize = 8;

/// One USB link, as handed to the transport.
pub struct UsbLink {
    /// Label for this link, unique among the links currently attached. Used
    /// as the link's transport address and in logs; carries no meaning.
    pub label: String,
    /// Bytes read from the link, in order, in chunks of any size. Closed
    /// when the link is gone.
    pub rx: mpsc::Receiver<Vec<u8>>,
    /// Bytes to write, one transfer per message, each at most
    /// [`USB_TRANSFER_MAX`]. Dropping the sender ends the link's writer.
    pub tx: mpsc::Sender<Vec<u8>>,
}

impl UsbLink {
    /// Two links wired to each other, for tests and in-process use.
    pub fn pair(a: &str, b: &str) -> (UsbLink, UsbLink) {
        let (a_tx, b_rx) = mpsc::channel(LINK_QUEUE_DEPTH);
        let (b_tx, a_rx) = mpsc::channel(LINK_QUEUE_DEPTH);
        (
            UsbLink {
                label: a.to_string(),
                rx: a_rx,
                tx: a_tx,
            },
            UsbLink {
                label: b.to_string(),
                rx: b_rx,
                tx: b_tx,
            },
        )
    }

    /// A link over an opened Android Open Accessory device (or anything else
    /// that reads and writes like one), taking ownership of `fd`.
    ///
    /// The accessory device is not known to support readiness polling, so it
    /// is driven by two blocking threads. A read error — the accessory driver
    /// returns `EIO` the moment the cable is pulled — or end of file closes
    /// the link.
    ///
    /// A link the transport drops leaves its reader blocked until the device
    /// errors, which on an accessory is the next unplug; the descriptor is
    /// closed when both threads have ended.
    #[cfg(unix)]
    pub fn from_fd(fd: std::os::fd::OwnedFd, label: impl Into<String>) -> UsbLink {
        use std::io::{Read, Write};

        let label = label.into();
        let file = Arc::new(std::fs::File::from(fd));
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(LINK_QUEUE_DEPTH);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(LINK_QUEUE_DEPTH);

        let reader = Arc::clone(&file);
        let reader_label = label.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("fips-usb-rd-{label}"))
            .spawn(move || {
                loop {
                    let mut buf = vec![0u8; USB_TRANSFER_MAX];
                    match (&*reader).read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.truncate(n);
                            if in_tx.blocking_send(buf).is_err() {
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            tracing::debug!(link = %reader_label, error = %e, "USB link read ended");
                            break;
                        }
                    }
                }
            });
        if let Err(e) = spawned {
            tracing::warn!(link = %label, error = %e, "could not start USB link reader");
        }

        let writer = file;
        let writer_label = label.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("fips-usb-wr-{label}"))
            .spawn(move || {
                let mut carried = None;
                while let Some(first) = carried.take().or_else(|| out_rx.blocking_recv()) {
                    let chunk = gather(first, &mut out_rx, &mut carried);
                    if let Err(e) = (&*writer).write_all(&chunk) {
                        tracing::debug!(link = %writer_label, error = %e, "USB link write ended");
                        break;
                    }
                }
            });
        if let Err(e) = spawned {
            tracing::warn!(link = %label, error = %e, "could not start USB link writer");
        }

        UsbLink {
            label,
            rx: in_rx,
            tx: out_tx,
        }
    }
}

/// Join `first` with whatever is already queued behind it, up to one
/// [`USB_TRANSFER_MAX`] transfer.
///
/// Called by a link's device writer right before each write, so a transfer
/// carries everything that queued up while the previous one was on the wire.
/// A USB transfer costs about the same whatever its size, so this, not the
/// packet size, is what sets a link's throughput. A chunk that would overflow
/// the transfer is left in `carried` to start the next one. Chunk boundaries
/// carry no meaning on a link — it is a byte stream — so joining is safe.
pub(crate) fn gather(
    first: Vec<u8>,
    queue: &mut mpsc::Receiver<Vec<u8>>,
    carried: &mut Option<Vec<u8>>,
) -> Vec<u8> {
    let mut transfer = first;
    while transfer.len() < USB_TRANSFER_MAX {
        match queue.try_recv() {
            Ok(next) if transfer.len() + next.len() <= USB_TRANSFER_MAX => {
                transfer.extend_from_slice(&next)
            }
            Ok(next) => {
                *carried = Some(next);
                break;
            }
            Err(_) => break,
        }
    }
    transfer
}

/// Where attached links wait for the transport to take them.
///
/// Links can arrive before the transport exists or while it is stopped — an
/// accessory attach is what starts the embedding app on a phone, before its
/// node does — so they queue here and the transport drains the queue when it
/// starts, and as they arrive after that.
#[derive(Default)]
pub struct UsbLinkQueue {
    links: Mutex<VecDeque<UsbLink>>,
    arrived: Notify,
}

impl UsbLinkQueue {
    /// An empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a link for the transport.
    pub fn push(&self, link: UsbLink) {
        self.links
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(link);
        self.arrived.notify_one();
    }

    /// Take the next link, waiting until one is queued.
    pub(crate) async fn next(&self) -> UsbLink {
        loop {
            // Register interest before looking, so a push between the look
            // and the wait is not missed.
            let arrived = self.arrived.notified();
            if let Some(link) = self
                .links
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop_front()
            {
                return link;
            }
            arrived.await;
        }
    }
}

/// The embedder's handle for giving USB links to a node, from
/// [`Node::enable_app_owned_usb`](crate::Node::enable_app_owned_usb).
///
/// Cheap to clone, usable from any thread, and valid whether or not the node
/// has started.
#[derive(Clone)]
pub struct UsbAttach {
    queue: Arc<UsbLinkQueue>,
}

impl UsbAttach {
    pub(crate) fn new(queue: Arc<UsbLinkQueue>) -> Self {
        Self { queue }
    }

    /// Hand over a link built by the embedder.
    pub fn link(&self, link: UsbLink) {
        self.queue.push(link);
    }

    /// Hand over an opened Android Open Accessory device. The node owns the
    /// descriptor from here and closes it when the link ends.
    #[cfg(unix)]
    pub fn accessory(&self, fd: std::os::fd::OwnedFd, label: impl Into<String>) {
        self.queue.push(UsbLink::from_fd(fd, label));
    }
}

/// [`AsyncRead`] over a link's receive channel, so the framer can pull whole
/// packets out of chunks that split and join them arbitrarily.
pub(crate) struct LinkRead {
    rx: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    offset: usize,
}

impl LinkRead {
    pub(crate) fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            pending: Vec::new(),
            offset: 0,
        }
    }
}

impl AsyncRead for LinkRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        while this.offset >= this.pending.len() {
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    this.pending = chunk;
                    this.offset = 0;
                }
                // Closed: end of stream, reported as a zero-length read.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = (this.pending.len() - this.offset).min(buf.remaining());
        buf.put_slice(&this.pending[this.offset..this.offset + n]);
        this.offset += n;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn link_read_joins_and_splits_chunks() {
        let (tx, rx) = mpsc::channel(4);
        let mut reader = LinkRead::new(rx);
        tx.send(vec![1, 2]).await.unwrap();
        tx.send(vec![]).await.unwrap();
        tx.send(vec![3, 4, 5]).await.unwrap();
        drop(tx);

        let mut first = [0u8; 3];
        reader.read_exact(&mut first).await.unwrap();
        assert_eq!(first, [1, 2, 3]);
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, [4, 5]);
    }

    #[tokio::test]
    async fn gather_fills_a_transfer_and_carries_the_overflow() {
        let (tx, mut rx) = mpsc::channel(8);
        for len in [6000, 6000, 6000, 100] {
            tx.send(vec![0u8; len]).await.unwrap();
        }
        let mut carried = None;
        let first = rx.recv().await.unwrap();
        // 6000 + 6000 fit; the third 6000 would pass 16 KiB and is carried.
        assert_eq!(gather(first, &mut rx, &mut carried).len(), 12000);
        let next = carried.take().unwrap();
        assert_eq!(gather(next, &mut rx, &mut carried).len(), 6100);
        assert!(carried.is_none());
    }

    #[tokio::test]
    async fn a_queued_link_is_taken_once_and_waits_otherwise() {
        let queue = Arc::new(UsbLinkQueue::new());
        let (a, _b) = UsbLink::pair("a", "b");
        queue.push(a);
        assert_eq!(queue.next().await.label, "a");

        let waiter = tokio::spawn({
            let queue = Arc::clone(&queue);
            async move { queue.next().await.label }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        let (c, _d) = UsbLink::pair("c", "d");
        UsbAttach::new(Arc::clone(&queue)).link(c);
        assert_eq!(waiter.await.unwrap(), "c");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_fd_link_carries_bytes_both_ways_and_closes_with_the_peer() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let link = UsbLink::from_fd(ours.into(), "acc0");

        link.tx.send(b"ping".to_vec()).await.unwrap();
        // The far end answers and hangs up, which must close our side.
        tokio::task::spawn_blocking(move || {
            let mut got = [0u8; 4];
            theirs.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"ping");
            theirs.write_all(b"pong").unwrap();
        })
        .await
        .unwrap();

        let mut reader = LinkRead::new(link.rx);
        let mut back = Vec::new();
        reader.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"pong");
    }
}
