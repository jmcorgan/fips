//! Raw Ethernet socket abstraction.
//!
//! Platform-specific implementations live in `socket_linux.rs` (AF_PACKET)
//! and `socket_macos.rs` (BPF). This module re-exports `PacketSocket` and
//! provides `AsyncPacketSocket`.

use crate::transport::TransportError;

/// Broadcast MAC address.
pub const ETHERNET_BROADCAST: [u8; 6] = [0xff; 6];

// Platform-specific PacketSocket implementation.
#[cfg(target_os = "linux")]
#[path = "socket_linux.rs"]
mod platform;

#[cfg(target_os = "macos")]
#[path = "socket_macos.rs"]
mod platform;

pub use platform::PacketSocket;

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
        rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Frame>>,
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
                                    if tx.blocking_send((data, mac)).is_err() {
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
                rx: tokio::sync::Mutex::new(rx),
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
            let mut rx = self.rx.lock().await;
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
        /// Sets the shutdown flag; the reader thread checks it after
        /// each BPF read timeout (~250ms) and exits.
        pub fn shutdown(&self) {
            self.inner.request_shutdown();
        }
    }

    impl Drop for AsyncPacketSocket {
        fn drop(&mut self) {
            self.inner.request_shutdown();
            if let Some(handle) = self.reader_thread.take() {
                let _ = handle.join();
            }
        }
    }
}

pub use async_impl::AsyncPacketSocket;

impl PacketSocket {
    /// Wrap this socket in an async wrapper for tokio integration.
    pub fn into_async(self) -> Result<AsyncPacketSocket, TransportError> {
        AsyncPacketSocket::new(self)
    }
}
