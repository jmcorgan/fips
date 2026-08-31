//! Raw Ethernet socket abstraction.
//!
//! Platform-specific implementations live in `io_linux.rs` (AF_PACKET)
//! and `io_macos.rs` (BPF). This module re-exports `PacketSocket` and
//! provides `AsyncPacketSocket`.

use crate::transport::TransportError;

/// Broadcast MAC address.
pub const ETHERNET_BROADCAST: [u8; 6] = [0xff; 6];

/// Whether the named interface exists and is administratively up.
///
/// Presence is `IFF_UP` — the interface exists and the operator has enabled
/// it — and deliberately **not** `IFF_RUNNING`.
///
/// Carrier is a different question from bindability, and only the second one
/// belongs in a bind gate. An `AF_PACKET` socket on a carrier-less bridge is
/// perfectly valid and starts carrying traffic the instant a member port comes
/// up, with no rebind: the socket outlives the carrier. Gating on `IFF_RUNNING`
/// bought nothing and cost three things —
///
/// - `br-lan` on a router with nothing plugged into its LAN ports is `UP` with
///   `NO-CARRIER`, so a perfectly healthy wifi-only router reported `Degraded`
///   forever;
/// - every carrier flap the socket would have survived became an unbind /
///   rebind cycle, which is churn the presence machine then has to damp;
/// - an 802.11s mesh interface that reports `RUNNING` only once it has peered
///   cannot peer, because peering needs beacons, which need a bound socket,
///   which the gate refuses. A deadlock reachable on shipped hardware.
///
/// The signal `IFF_RUNNING` does carry — "is anything plugged in" — is not
/// lost; it is reported alongside presence by [`interface_carrier`] and
/// surfaced in `show_transports`, where an operator can read it without it
/// steering the daemon.
///
/// `getifaddrs` rather than an `SIOCGIFFLAGS` ioctl: it needs no socket, so
/// the presence watcher can poll before any file descriptor exists, and it is
/// spelled the same on Linux and the BSDs.
#[cfg(unix)]
pub fn interface_present(interface: &str) -> bool {
    interface_has_flags(interface, libc::IFF_UP as u32)
}

/// The kernel's index for the named interface, or `None` if it does not exist.
///
/// A name is not a device, and neither is a name that is still there. Both
/// backends bind by index — `AF_PACKET` stores `sll_ifindex`, and a BPF
/// descriptor follows the device it was attached to — so an interface deleted
/// and recreated under the same name leaves the socket attached to a device
/// that no longer exists while the *name* resolves perfectly well. Comparing
/// the live index against the one captured at bind is what tells those apart.
#[cfg(unix)]
pub fn interface_index(interface: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(interface).ok()?;
    // Cheaper than `getifaddrs`: one syscall, no allocation, no walk.
    match unsafe { libc::if_nametoindex(c_name.as_ptr()) } {
        0 => None,
        idx => Some(idx),
    }
}

/// Whether the named interface currently has carrier (`IFF_RUNNING`).
///
/// Reported, never acted on — see [`interface_present`]. `false` for an
/// interface that does not exist, which keeps "no carrier" and "no interface"
/// from being told apart here; presence answers that.
#[cfg(unix)]
pub fn interface_carrier(interface: &str) -> bool {
    interface_has_flags(interface, (libc::IFF_UP | libc::IFF_RUNNING) as u32)
}

/// Whether the named interface exists and has every flag in `wanted` set.
#[cfg(unix)]
fn interface_has_flags(interface: &str, wanted: u32) -> bool {
    let Ok(c_name) = std::ffi::CString::new(interface) else {
        return false;
    };

    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return false;
    }

    let mut matched = false;
    let mut cur = addrs;
    while !cur.is_null() {
        let entry = unsafe { &*cur };
        if !entry.ifa_name.is_null()
            && unsafe { libc::strcmp(entry.ifa_name, c_name.as_ptr()) } == 0
            && entry.ifa_flags & wanted == wanted
        {
            matched = true;
            break;
        }
        cur = entry.ifa_next;
    }

    unsafe { libc::freeifaddrs(addrs) };
    matched
}

// Platform-specific PacketSocket implementation.
#[cfg(target_os = "linux")]
#[path = "io_linux.rs"]
mod platform;

#[cfg(target_os = "macos")]
#[path = "io_macos.rs"]
mod platform;

#[cfg(unix)]
pub use platform::PacketSocket;

/// Outcome of `send_frame`.
#[cfg(unix)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) enum SendOutcome {
    Sent,
    Stop,
}

/// Retry iterations spent yielding before the send loop starts sleeping.
///
/// A transiently full channel drains in microseconds, so yielding keeps the
/// saturated-path handoff rate uncapped, which is the whole reason this
/// module has a dedicated reader thread. Raising it burns more CPU against a
/// genuinely stuck consumer; lowering it puts a sleep in the common case.
#[cfg(unix)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const SEND_YIELD_SPINS: u32 = 64;

/// Longest the send loop sleeps between attempts on a full channel.
///
/// This bounds only how quickly a parked send notices a shutdown request that
/// closing the receiver has not already covered. Raising it delays that
/// notice; lowering it costs more wakeups under sustained backpressure.
#[cfg(unix)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const SEND_RETRY_MAX: std::time::Duration = std::time::Duration::from_millis(1);

/// Send one item, waiting out a full channel but waking on `shutdown_fd`.
///
/// Returns `Stop` when the receiver is gone or shutdown has been requested,
/// which is the reader thread's cue to exit. Unlike `blocking_send` this
/// cannot park past a shutdown request, so the `join()` in `Drop` always
/// returns. The caller must keep the socket owning `shutdown_fd` alive across
/// the call; `poll` on a closed fd reports `POLLNVAL` rather than `POLLIN`, so
/// even a lifetime mistake degrades to waiting rather than to a false stop.
///
/// Compiled on every unix so Linux CI exercises the tests below; only the
/// macOS reader thread calls it.
#[cfg(unix)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn send_frame<T>(
    tx: &tokio::sync::mpsc::Sender<T>,
    item: T,
    shutdown_fd: std::os::unix::io::RawFd,
) -> SendOutcome {
    use tokio::sync::mpsc::error::TrySendError;

    let mut item = item;
    let mut spins = 0u32;
    let mut backoff = std::time::Duration::from_micros(50);
    loop {
        match tx.try_send(item) {
            Ok(()) => return SendOutcome::Sent,
            Err(TrySendError::Closed(_)) => return SendOutcome::Stop,
            Err(TrySendError::Full(returned)) => {
                if fd_is_readable(shutdown_fd) {
                    return SendOutcome::Stop;
                }
                item = returned;
                if spins < SEND_YIELD_SPINS {
                    spins += 1;
                    std::thread::yield_now();
                } else {
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(SEND_RETRY_MAX);
                }
            }
        }
    }
}

/// True if `fd` has data ready, tested without blocking.
#[cfg(unix)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn fd_is_readable(fd: std::os::unix::io::RawFd) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
    ret > 0 && (pfd.revents & libc::POLLIN) != 0
}

// =============================================================================
// Linux: AsyncFd-based async wrapper
// =============================================================================

#[cfg(target_os = "linux")]
mod async_impl {
    use super::PacketSocket;
    use crate::transport::TransportError;
    use tokio::io::unix::AsyncFd;

    pub struct AsyncPacketSocket {
        inner: AsyncFd<PacketSocket>,
    }

    impl AsyncPacketSocket {
        pub fn new(socket: PacketSocket) -> Result<Self, TransportError> {
            let async_fd = AsyncFd::new(socket)
                .map_err(|e| TransportError::StartFailed(format!("AsyncFd::new failed: {}", e)))?;
            Ok(Self { inner: async_fd })
        }

        pub async fn send_to(
            &self,
            data: &[u8],
            dest_mac: &[u8; 6],
        ) -> Result<usize, TransportError> {
            loop {
                let mut guard = self
                    .inner
                    .writable()
                    .await
                    .map_err(|e| TransportError::SendFailed(format!("writable wait: {}", e)))?;

                match guard.try_io(|inner| inner.get_ref().send_to(data, dest_mac)) {
                    Ok(Ok(n)) => return Ok(n),
                    Ok(Err(e)) => return Err(TransportError::SendFailed(format!("{}", e))),
                    Err(_would_block) => continue,
                }
            }
        }

        pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, [u8; 6]), TransportError> {
            loop {
                let mut guard = self
                    .inner
                    .readable()
                    .await
                    .map_err(|e| TransportError::RecvFailed(format!("readable wait: {}", e)))?;

                match guard.try_io(|inner| inner.get_ref().recv_from(buf)) {
                    Ok(Ok(result)) => return Ok(result),
                    Ok(Err(e)) => return Err(TransportError::RecvFailed(format!("{}", e))),
                    Err(_would_block) => continue,
                }
            }
        }

        pub fn get_ref(&self) -> &PacketSocket {
            self.inner.get_ref()
        }

        /// Shut down the socket, unblocking any pending recv.
        ///
        /// On Linux this is a no-op — aborting the tokio task suffices
        /// since AsyncFd is cancellation-aware.
        pub fn shutdown(&self) {}
    }
}

// =============================================================================
// macOS: dedicated reader thread with async channel
//
// BPF fds don't support kqueue, so we can't use AsyncFd. Instead of
// spawn_blocking per packet (which was the bottleneck causing 84 Mbps),
// we spawn a single dedicated reader thread that loops on blocking
// read() and feeds frames through a tokio mpsc channel.
// =============================================================================

#[cfg(target_os = "macos")]
mod async_impl {
    use super::PacketSocket;
    use crate::transport::TransportError;
    use std::os::unix::io::AsRawFd;
    use std::sync::Arc;

    /// A received frame: (payload, source_mac).
    type Frame = (Vec<u8>, [u8; 6]);

    pub struct AsyncPacketSocket {
        inner: Arc<PacketSocket>,
        /// `None` once shutdown has taken the receiver, which is what makes
        /// a reader thread parked on a full channel return at once.
        rx: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Frame>>>,
        reader_thread: Option<std::thread::JoinHandle<()>>,
    }

    impl AsyncPacketSocket {
        pub fn new(socket: PacketSocket) -> Result<Self, TransportError> {
            // Channel capacity: buffer up to 1024 frames to decouple
            // the blocking reader from the async consumer.
            let (tx, rx) = tokio::sync::mpsc::channel::<Frame>(1024);
            let inner = Arc::new(socket);
            let reader_socket = Arc::clone(&inner);

            let reader_thread = std::thread::Builder::new()
                .name("bpf-reader".into())
                .spawn(move || {
                    let bpf_fd = reader_socket.as_raw_fd();
                    let shutdown_fd = reader_socket.shutdown_read_fd();
                    let bpf_buflen = reader_socket.bpf_buflen();
                    let mut read_buf = vec![0u8; bpf_buflen];
                    let mut parse_buf = vec![0u8; bpf_buflen];
                    let mut parse_offset: usize = 0;
                    let mut parse_len: usize = 0;
                    let nfds = bpf_fd.max(shutdown_fd) + 1;

                    loop {
                        // Drain any buffered frames from the previous read
                        while let Some(result) = super::platform::parse_next_frame(
                            &parse_buf,
                            &mut parse_offset,
                            parse_len,
                            &mut read_buf,
                        ) {
                            match result {
                                Ok((n, mac)) => {
                                    let data = read_buf[..n].to_vec();
                                    // Not blocking_send: a send parked on a
                                    // full channel must still notice shutdown,
                                    // or Drop's join() never returns.
                                    if matches!(
                                        super::send_frame(&tx, (data, mac), shutdown_fd),
                                        super::SendOutcome::Stop
                                    ) {
                                        return;
                                    }
                                }
                                Err(_) => break,
                            }
                        }

                        // Wait for BPF data or shutdown signal via select()
                        unsafe {
                            let mut read_fds: libc::fd_set = std::mem::zeroed();
                            libc::FD_ZERO(&mut read_fds);
                            libc::FD_SET(bpf_fd, &mut read_fds);
                            libc::FD_SET(shutdown_fd, &mut read_fds);

                            let ret = libc::select(
                                nfds,
                                &mut read_fds,
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                            );
                            if ret < 0 {
                                let err = std::io::Error::last_os_error();
                                if err.kind() == std::io::ErrorKind::Interrupted {
                                    continue;
                                }
                                break;
                            }
                            if libc::FD_ISSET(shutdown_fd, &read_fds) {
                                break; // shutdown signal
                            }
                        }

                        // BPF fd is readable
                        let ret = unsafe {
                            libc::read(
                                bpf_fd,
                                parse_buf.as_mut_ptr() as *mut libc::c_void,
                                bpf_buflen,
                            )
                        };
                        if ret <= 0 {
                            if ret < 0 {
                                let err = std::io::Error::last_os_error();
                                if err.raw_os_error() == Some(libc::EBADF) {
                                    break;
                                }
                            }
                            parse_len = 0;
                            parse_offset = 0;
                            continue;
                        }
                        parse_len = ret as usize;
                        parse_offset = 0;
                    }
                })
                .map_err(|e| TransportError::StartFailed(format!("reader thread: {}", e)))?;

            Ok(Self {
                inner,
                rx: tokio::sync::Mutex::new(Some(rx)),
                reader_thread: Some(reader_thread),
            })
        }

        pub async fn send_to(
            &self,
            data: &[u8],
            dest_mac: &[u8; 6],
        ) -> Result<usize, TransportError> {
            let socket = Arc::clone(&self.inner);
            let data = data.to_vec();
            let dest = *dest_mac;
            tokio::task::spawn_blocking(move || {
                socket
                    .send_to(&data, &dest)
                    .map_err(|e| TransportError::SendFailed(format!("{}", e)))
            })
            .await
            .map_err(|e| TransportError::SendFailed(format!("spawn_blocking: {}", e)))?
        }

        pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, [u8; 6]), TransportError> {
            let mut guard = self.rx.lock().await;
            let Some(rx) = guard.as_mut() else {
                return Err(TransportError::RecvFailed("reader thread stopped".into()));
            };
            match rx.recv().await {
                Some((data, mac)) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok((n, mac))
                }
                None => Err(TransportError::RecvFailed("reader thread stopped".into())),
            }
        }

        pub fn get_ref(&self) -> &PacketSocket {
            &self.inner
        }

        /// Signal the reader thread to stop.
        ///
        /// Drops the receiver where it can, which makes a send parked on a
        /// full channel fail immediately, then writes the shutdown pipe that
        /// the thread's `select()` and `send_frame` both watch. The receiver
        /// is unavailable while a `recv_from` holds the lock; `Drop` takes it
        /// unconditionally, so the pipe is what covers that window.
        pub fn shutdown(&self) {
            if let Ok(mut guard) = self.rx.try_lock() {
                guard.take();
            }
            self.inner.request_shutdown();
        }
    }

    impl Drop for AsyncPacketSocket {
        fn drop(&mut self) {
            // Drop the receiver before joining: a send parked on a full
            // channel then returns at once, with no polling and no latency
            // added to the steady-state path.
            self.rx.get_mut().take();
            self.inner.request_shutdown();
            if let Some(handle) = self.reader_thread.take() {
                let _ = handle.join();
            }
        }
    }
}

#[cfg(unix)]
pub use async_impl::AsyncPacketSocket;

#[cfg(unix)]
impl PacketSocket {
    /// Wrap this socket in an async wrapper for tokio integration.
    pub fn into_async(self) -> Result<AsyncPacketSocket, TransportError> {
        AsyncPacketSocket::new(self)
    }
}

// =============================================================================
// Windows: stub types (Ethernet not supported on Windows)
// =============================================================================

#[cfg(windows)]
pub struct PacketSocket;

#[cfg(windows)]
pub struct AsyncPacketSocket;

// =============================================================================
// Tests
// =============================================================================

#[cfg(all(test, unix))]
mod tests {
    use super::{SendOutcome, fd_is_readable, send_frame};
    use std::sync::mpsc;
    use std::time::Duration;

    /// A pipe, as the shutdown signal, returned as (read fd, write fd).
    ///
    /// Leaked deliberately: these live for the length of one test and closing
    /// them mid-poll is exactly the confusion the test is meant to avoid.
    fn shutdown_pipe() -> (std::os::unix::io::RawFd, std::os::unix::io::RawFd) {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "pipe() failed");
        (fds[0], fds[1])
    }

    fn signal(write_fd: std::os::unix::io::RawFd) {
        let byte = [1u8];
        let ret = unsafe { libc::write(write_fd, byte.as_ptr() as *const libc::c_void, 1) };
        assert_eq!(ret, 1, "write() to shutdown pipe failed");
    }

    #[test]
    fn fd_is_readable_is_false_for_an_unwritten_pipe_and_true_after_a_write() {
        let (read_fd, write_fd) = shutdown_pipe();
        assert!(!fd_is_readable(read_fd));
        signal(write_fd);
        assert!(fd_is_readable(read_fd));
    }

    #[test]
    fn send_frame_delivers_when_the_channel_has_room() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let (read_fd, _write_fd) = shutdown_pipe();

        assert!(matches!(
            send_frame(&tx, vec![1u8, 2, 3], read_fd),
            SendOutcome::Sent
        ));
        assert_eq!(rx.try_recv().unwrap(), vec![1u8, 2, 3]);
    }

    #[test]
    fn send_frame_returns_stop_when_the_receiver_is_gone() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let (read_fd, _write_fd) = shutdown_pipe();
        drop(rx);

        assert!(matches!(
            send_frame(&tx, vec![0u8], read_fd),
            SendOutcome::Stop
        ));
    }

    #[test]
    fn send_frame_returns_stop_when_the_receiver_is_dropped_while_the_channel_is_full() {
        // The mechanism `Drop` relies on: closing the channel releases a
        // sender that is waiting for room.
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let (read_fd, _write_fd) = shutdown_pipe();
        tx.try_send(vec![0u8]).unwrap();

        let (done_tx, done_rx) = mpsc::channel();
        let sender = std::thread::spawn(move || {
            let outcome = send_frame(&tx, vec![1u8], read_fd);
            done_tx.send(matches!(outcome, SendOutcome::Stop)).unwrap();
        });
        // The send is parked on a full channel; only the drop frees it.
        assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
        drop(rx);

        let stopped = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("send_frame did not return after the receiver was dropped");
        sender.join().unwrap();
        assert!(stopped);
    }

    #[test]
    fn send_frame_returns_stop_when_shutdown_is_requested_and_the_channel_is_full() {
        // The defect: `blocking_send` on a full channel nobody is draining
        // parks forever, so the reader thread never sees shutdown and the
        // `join()` in `Drop` never returns. See the ignored test below for
        // the same fixture against `blocking_send`.
        let (tx, _rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let (read_fd, write_fd) = shutdown_pipe();
        tx.try_send(vec![0u8]).unwrap();
        signal(write_fd);

        let (done_tx, done_rx) = mpsc::channel();
        let sender = std::thread::spawn(move || {
            let outcome = send_frame(&tx, vec![1u8], read_fd);
            done_tx.send(matches!(outcome, SendOutcome::Stop)).unwrap();
        });

        let stopped = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("send_frame parked past a shutdown request");
        sender.join().unwrap();
        assert!(stopped);
    }

    #[test]
    #[ignore = "demonstrates the defect: blocking_send never returns, so this hangs"]
    fn blocking_send_parks_past_a_shutdown_request_when_the_channel_is_full() {
        // Run with `--ignored` to watch the old send site hang. Kept as the
        // observed red-before for the test above, which cannot itself fail
        // against the old code because `send_frame` did not exist then.
        let (tx, _rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let (_read_fd, write_fd) = shutdown_pipe();
        tx.try_send(vec![0u8]).unwrap();
        signal(write_fd);

        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.blocking_send(vec![1u8]);
            done_tx.send(()).unwrap();
        });

        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("blocking_send returned, so the send site was already cancellable");
    }
}
