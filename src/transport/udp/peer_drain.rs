// Paired with `connected_peer.rs`: dormant in this PR until the
// activation handler is wired into the node tick (follow-up).
#![allow(dead_code)]

//! Recv-side drain thread for a per-peer connected UDP socket.
//!
//! Once a UDP socket is `connect()`-ed to a peer, Linux and Darwin
//! UDP demux preferentially route inbound packets matching the peer's
//! 5-tuple to that socket (most-specific match wins over the wildcard
//! listen socket under `SO_REUSEPORT`). So a connected socket **must**
//! be drained, or packets pile up in its recv buffer until it overflows
//! and the kernel drops them silently.
//!
//! This module owns the drain side: spawn one OS thread per connected
//! socket, drain into a fixed-size batch (`recvmmsg(2)` on Linux,
//! repeated nonblocking `recv(2)` on Darwin), push each packet into
//! the existing `packet_tx` (the same channel that the wildcard listen
//! socket feeds), and exit cleanly when the parent signals shutdown
//! via a self-pipe.
//!
//! Future: when the full data-plane shard lands, this per-peer thread
//! becomes a `epoll_wait` arm inside the shard's event loop instead
//! of a dedicated OS thread. The drain *function* `drain_loop` stays
//! useful in either shape; only the wakeup mechanism differs.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use super::super::{ReceivedPacket, TransportAddr, TransportId};
use super::PacketTx;
use super::connected_peer::ConnectedPeerSocket;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, trace, warn};

/// Handle to a running per-peer drain thread. Drops the thread (and
/// closes its self-pipe) on drop; the thread exits next time it
/// returns from `poll(2)`.
#[derive(Debug)]
pub(crate) struct PeerRecvDrain {
    /// Write end of the shutdown self-pipe. Write a single byte to
    /// wake the drain thread out of `poll(2)` so it sees the stop
    /// flag and exits.
    stop_pipe_tx: RawFd,
    /// Atomic stop signal — primary mechanism for the drain thread
    /// to know it should exit. Set before writing to `stop_pipe_tx`
    /// so the thread observes the flag once woken.
    stop: Arc<AtomicBool>,
    /// Joined on drop; the thread is cheap (just exits after the
    /// next `poll` returns) so the wait is bounded.
    join: Option<std::thread::JoinHandle<()>>,
}

impl PeerRecvDrain {
    /// Spawn a drain thread for the given connected socket.
    ///
    /// The thread holds an `Arc<ConnectedPeerSocket>` to keep the
    /// kernel fd alive while it's running. When this handle drops,
    /// the stop pipe fires; the thread exits; its `Arc` releases.
    /// If the parent also releases its `Arc`, the socket's `Drop`
    /// closes the kernel fd.
    pub fn spawn(
        socket: Arc<ConnectedPeerSocket>,
        transport_id: TransportId,
        peer_addr: SocketAddr,
        packet_tx: PacketTx,
    ) -> io::Result<Self> {
        // Self-pipe for shutdown signaling. The drain thread polls
        // (socket_fd | pipe_rx) so a write to pipe_tx wakes it.
        let (pipe_rx, pipe_tx) = make_pipe()?;

        let stop = Arc::new(AtomicBool::new(false));

        let stop_clone = stop.clone();
        let socket_clone = socket.clone();
        let thread = std::thread::Builder::new()
            .name(format!("fips-peer-drain-{}", socket.peer_addr()))
            .spawn(move || {
                drain_loop(
                    socket_clone,
                    transport_id,
                    peer_addr,
                    packet_tx,
                    pipe_rx,
                    stop_clone,
                );
                // Drain thread cleans up the read end of the pipe on exit.
                unsafe { libc::close(pipe_rx) };
            });

        match thread {
            Ok(join) => Ok(Self {
                stop_pipe_tx: pipe_tx,
                stop,
                join: Some(join),
            }),
            Err(e) => {
                unsafe {
                    libc::close(pipe_rx);
                    libc::close(pipe_tx);
                }
                Err(io::Error::other(format!(
                    "failed to spawn peer drain thread: {e}"
                )))
            }
        }
    }
}

impl Drop for PeerRecvDrain {
    fn drop(&mut self) {
        // 1. Set the stop flag.
        self.stop.store(true, Ordering::Release);
        // 2. Wake the drain thread by writing to the self-pipe. One
        //    byte is enough; the thread's poll will return on
        //    POLLIN, observe the stop flag, and exit.
        let byte = 1u8;
        let _ = unsafe { libc::write(self.stop_pipe_tx, &byte as *const _ as *const _, 1) };
        // 3. Join — bounded wait, the thread exits within one
        //    poll-iteration of seeing the stop flag.
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
        // 4. Close the write end of the pipe.
        unsafe { libc::close(self.stop_pipe_tx) };
    }
}

/// The drain thread's main loop. Runs until `stop` is set + the
/// stop-pipe is written to (Drop does both in order).
fn drain_loop(
    socket: Arc<ConnectedPeerSocket>,
    transport_id: TransportId,
    peer_addr: SocketAddr,
    packet_tx: PacketTx,
    stop_pipe_rx: RawFd,
    stop: Arc<AtomicBool>,
) {
    let socket_fd = socket.as_raw_fd();
    trace!(
        transport_id = %transport_id,
        peer_addr = %peer_addr,
        "fips-peer-drain: starting"
    );

    const BATCH: usize = 32;
    const BUF_SIZE: usize = 1600; // covers any practical FIPS MTU.
    let mut backing: Vec<Vec<u8>> = (0..BATCH).map(|_| vec![0u8; BUF_SIZE]).collect();
    let mut lens: [usize; BATCH] = [0; BATCH];
    let packet_addr = TransportAddr::from_socket_addr(peer_addr);

    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }

        // poll(2) on the socket + stop pipe. -1 timeout = block
        // until at least one is readable; the stop pipe wake-up
        // guarantees forward progress under Drop.
        let mut pfds = [
            libc::pollfd {
                fd: socket_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stop_pipe_rx,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let r = unsafe { libc::poll(pfds.as_mut_ptr(), 2, -1) };
        if r < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            warn!(error = %err, "fips-peer-drain: poll failed; exiting");
            break;
        }
        if pfds[1].revents != 0 {
            // Stop pipe fired. We may or may not also have data on
            // the socket; check the flag and exit if set.
            if stop.load(Ordering::Acquire) {
                break;
            }
        }
        if pfds[0].revents & libc::POLLIN == 0 {
            continue;
        }

        // Drain whatever is currently queued in the kernel.
        let n = drain_packets(socket_fd, &mut backing, &mut lens);
        let count = match n {
            Ok(c) => c,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => {
                debug!(error = %err, "fips-peer-drain: recv failed; exiting");
                break;
            }
        };

        for i in 0..count {
            let len = lens[i];
            if len == 0 {
                continue;
            }
            // Move the filled buffer out, refill the slot with a
            // fresh one. Same zero-copy pattern the wildcard listen
            // socket uses (see `transport/udp/mod.rs::run_receive_loop`).
            let mut data = std::mem::replace(&mut backing[i], vec![0u8; BUF_SIZE]);
            data.truncate(len);
            let packet = ReceivedPacket::new(transport_id, packet_addr.clone(), data);
            // Drain runs on a std::thread, packet_tx is tokio::mpsc::Sender;
            // `send` returns a Future. `blocking_send` blocks the OS thread
            // until the channel has capacity — exactly what we want here.
            if packet_tx.blocking_send(packet).is_err() {
                trace!("fips-peer-drain: packet channel closed; exiting");
                return;
            }
        }
    }

    trace!(
        transport_id = %transport_id,
        peer_addr = %peer_addr,
        "fips-peer-drain: stopped"
    );
}

fn make_pipe() -> io::Result<(RawFd, RawFd)> {
    let mut pipe_fds = [0i32; 2];
    #[cfg(target_os = "linux")]
    {
        let r = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let r = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        if let Err(err) = set_nonblocking_cloexec(pipe_fds[0]) {
            unsafe {
                libc::close(pipe_fds[0]);
                libc::close(pipe_fds[1]);
            }
            return Err(err);
        }
        if let Err(err) = set_nonblocking_cloexec(pipe_fds[1]) {
            unsafe {
                libc::close(pipe_fds[0]);
                libc::close(pipe_fds[1]);
            }
            return Err(err);
        }
    }
    Ok((pipe_fds[0], pipe_fds[1]))
}

#[cfg(not(target_os = "linux"))]
fn set_nonblocking_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if fd_flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn drain_packets(fd: RawFd, backing: &mut [Vec<u8>], lens: &mut [usize]) -> io::Result<usize> {
    recvmmsg_drain(fd, backing, lens)
}

#[cfg(not(target_os = "linux"))]
fn drain_packets(fd: RawFd, backing: &mut [Vec<u8>], lens: &mut [usize]) -> io::Result<usize> {
    recv_drain(fd, backing, lens)
}

/// One-shot `recvmmsg(2)` on a non-blocking fd. Returns the number of
/// datagrams received (0 on no data ready). Same minimal-overhead
/// shape as the wildcard listen socket's `recv_batch` helper but
/// without the kernel-drop counter cmsg (the listen socket samples
/// that for the congestion detector; per-peer sockets share the
/// kernel-wide UDP socket-buffer accounting already).
#[cfg(target_os = "linux")]
fn recvmmsg_drain(fd: RawFd, backing: &mut [Vec<u8>], lens: &mut [usize]) -> io::Result<usize> {
    const BATCH: usize = 32;
    let n = backing.len().min(lens.len()).min(BATCH);
    if n == 0 {
        return Ok(0);
    }

    let mut iovs: [libc::iovec; BATCH] = unsafe { std::mem::zeroed() };
    let mut storages: [libc::sockaddr_storage; BATCH] = unsafe { std::mem::zeroed() };
    let mut msgs: [libc::mmsghdr; BATCH] = unsafe { std::mem::zeroed() };
    for i in 0..n {
        iovs[i].iov_base = backing[i].as_mut_ptr() as *mut libc::c_void;
        iovs[i].iov_len = backing[i].len();
        msgs[i].msg_hdr.msg_name = &mut storages[i] as *mut _ as *mut libc::c_void;
        msgs[i].msg_hdr.msg_namelen =
            std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msgs[i].msg_hdr.msg_iov = &mut iovs[i];
        // `msg_iovlen` is `usize` on glibc / `i32` on musl.
        msgs[i].msg_hdr.msg_iovlen = 1 as _;
        msgs[i].msg_len = 0;
    }

    // `MSG_DONTWAIT` is `c_int` (i32) on glibc but `u32` on musl;
    // `as _` resolves to whichever the recvmmsg signature wants.
    let r = unsafe {
        libc::recvmmsg(
            fd,
            msgs.as_mut_ptr(),
            n as libc::c_uint,
            libc::MSG_DONTWAIT as _,
            std::ptr::null_mut(),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    let count = r as usize;
    for i in 0..count {
        lens[i] = msgs[i].msg_len as usize;
    }
    Ok(count)
}

#[cfg(not(target_os = "linux"))]
fn recv_drain(fd: RawFd, backing: &mut [Vec<u8>], lens: &mut [usize]) -> io::Result<usize> {
    let n = backing.len().min(lens.len());
    if n == 0 {
        return Ok(0);
    }

    let mut count = 0usize;
    while count < n {
        let r = unsafe {
            libc::recv(
                fd,
                backing[count].as_mut_ptr() as *mut libc::c_void,
                backing[count].len(),
                0,
            )
        };
        if r < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == io::ErrorKind::WouldBlock && count > 0 {
                return Ok(count);
            }
            return Err(err);
        }
        lens[count] = r as usize;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::time::Duration;
    use tokio::sync::mpsc;

    /// End-to-end: open a ConnectedPeerSocket, spawn a drain thread
    /// on it, send packets at it from a remote, verify they land in
    /// the packet_tx mpsc with the correct transport_id + peer_addr.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_delivers_packets_to_packet_tx() {
        // Peer (remote) — sends packets at our connected socket.
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        let peer_addr = peer.local_addr().expect("peer local_addr");

        // Our connected socket. Use an ephemeral local port so we
        // don't conflict with anything else on the test host.
        let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = Arc::new(
            ConnectedPeerSocket::open(local_addr, peer_addr, 1 << 20, 1 << 20)
                .expect("ConnectedPeerSocket::open"),
        );

        // packet_tx for the drain thread to push into.
        let (tx, mut rx) = mpsc::channel::<ReceivedPacket>(64);
        let transport_id = TransportId::new(42);

        // Find out what local_addr the kernel assigned to our socket
        // so the peer can sendto() it. Use getsockname; cast the
        // returned sockaddr_storage to sockaddr_in (we only test on
        // IPv4 loopback here, so this is safe).
        let our_local_addr: SocketAddr = {
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            let r = unsafe {
                libc::getsockname(
                    socket.as_raw_fd(),
                    &mut storage as *mut _ as *mut libc::sockaddr,
                    &mut len,
                )
            };
            assert!(r >= 0, "getsockname failed");
            assert_eq!(
                storage.ss_family as i32,
                libc::AF_INET,
                "test assumes IPv4 loopback"
            );
            let sin: &libc::sockaddr_in =
                unsafe { &*(&storage as *const _ as *const libc::sockaddr_in) };
            let port = u16::from_be(sin.sin_port);
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            SocketAddr::from((ip, port))
        };

        // Spawn the drain.
        let _drain = PeerRecvDrain::spawn(socket.clone(), transport_id, peer_addr, tx)
            .expect("PeerRecvDrain::spawn");

        // Send a couple of packets from the peer to our socket.
        for i in 0u8..5 {
            let payload = [i, 0xAA, 0xBB, 0xCC];
            peer.send_to(&payload, our_local_addr).expect("peer sendto");
        }

        // Verify the drain picked them up.
        for i in 0u8..5 {
            let pkt = tokio::time::timeout(Duration::from_millis(500), rx.recv())
                .await
                .unwrap_or_else(|_| panic!("timeout waiting for packet {i}"))
                .expect("packet channel closed");
            assert_eq!(pkt.transport_id, transport_id);
            assert_eq!(pkt.data.len(), 4);
            assert_eq!(pkt.data[0], i, "packet {i} payload mismatch");
        }
        // Drop the drain handle — should stop the thread within one
        // poll iteration.
    }
}
