//! UDP socket wrapper with platform-specific receive implementations.
//!
//! The public surface is two types, `UdpRawSocket` and `AsyncUdpSocket`,
//! supplied by whichever backend this target compiles:
//!
//! - `unix` is shared by every Unix target and holds the socket
//!   lifecycle, the synchronous calls and the `AsyncFd` wrapper. Where
//!   behaviour genuinely differs per OS it defers to `linux`, `macos`
//!   or `unix_other`: `SO_RXQ_OVFL` drop counting on Linux, `recvmsg_x`
//!   batching on Darwin, neither elsewhere.
//! - `windows` is a separate backend over `tokio::net::UdpSocket`. It
//!   shares no implementation with the Unix side — there is no fd, no
//!   `AsyncFd`, no drop counting and no batching — only the type names.
//!
//! `connected` holds the per-peer connected-socket fast path — the fd
//! construction, the owning handle and its drain thread — which exists on
//! Linux and macOS only, and `macos_sockopts` the Darwin service-type
//! tuning it applies. Module names are written plainly rather than as
//! intra-doc links because each one is `cfg`-gated out on some target, so
//! no single configuration can resolve them all.
//!
//! Follows the pattern established by `transport/ethernet/socket.rs`.

#[cfg(unix)]
mod bind_device;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod macos_sockopts;
#[cfg(unix)]
mod unix;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
mod unix_other;
#[cfg(windows)]
mod windows;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod connected;

#[cfg(unix)]
pub use unix::{AsyncUdpSocket, UdpRawSocket};
#[cfg(windows)]
pub use windows::{AsyncUdpSocket, UdpRawSocket};

#[cfg(target_os = "macos")]
pub(crate) use macos::recvmsg_x_drain;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use connected::{ConnectedPeerSocket, PeerRecvDrain, open_connected_fd};

#[cfg(test)]
mod tests {
    use super::UdpRawSocket;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::net::SocketAddr;

    #[test]
    fn test_udp_socket_bind() {
        // Bind to an ephemeral port
        let sock = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
            .expect("failed to bind UDP socket");

        let addr = sock.local_addr();
        assert!(addr.port() > 0, "should be assigned an ephemeral port");
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn test_udp_socket_buffer_sizes() {
        let sock = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
            .expect("failed to bind UDP socket");

        let recv_buf = sock.recv_buffer_size().expect("get recv buffer");
        let send_buf = sock.send_buffer_size().expect("get send buffer");
        assert!(recv_buf > 0, "recv buffer should be non-zero");
        assert!(send_buf > 0, "send buffer should be non-zero");
    }

    /// The listen socket's reuse flags go on after its own bind, so they
    /// never license the kernel to hand this socket a port someone else
    /// holds. The visible consequence is that a second bind of an occupied
    /// port fails loudly instead of silently sharing it and splitting the
    /// inbound datagrams between the two recv loops.
    #[cfg(unix)]
    #[test]
    fn a_second_open_of_an_occupied_port_fails_instead_of_sharing_it() {
        let holder = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
            .expect("failed to bind the holding socket");
        let addr = holder.local_addr();

        // `UdpRawSocket` is not `Debug`, so this cannot be `expect_err`.
        let Err(err) = UdpRawSocket::open(addr, 65536, 65536) else {
            panic!("the port is already held, so the second bind must fail");
        };

        assert!(
            err.to_string().contains("bind failed"),
            "the failure must come from bind, not from a later step: {err}",
        );
    }

    /// The traversal path binds its socket plainly on port zero, so the
    /// socket reaches `adopt` carrying neither reuse flag. Adoption has to
    /// add them after the fact, or the per-peer connected socket's bind to
    /// the same address is refused with `EADDRINUSE`. Either flag on the
    /// holder admits that bind on Linux, so the successful open cannot tell
    /// whether both were set; each flag is also read back.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_adopted_plain_socket_carries_both_reuse_flags_and_admits_a_connected_socket_on_its_port()
    {
        use std::os::fd::{AsRawFd, BorrowedFd};

        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("failed to bind the peer");
        let peer_addr = peer.local_addr().expect("peer local address");

        let plain = std::net::UdpSocket::bind(("0.0.0.0", 0)).expect("failed to bind the holder");
        {
            let probe = socket2::SockRef::from(&plain);
            assert!(
                !probe.reuse_address().expect("read SO_REUSEADDR"),
                "precondition: a plain bind must arrive without SO_REUSEADDR",
            );
            assert!(
                !probe.reuse_port().expect("read SO_REUSEPORT"),
                "precondition: a plain bind must arrive without SO_REUSEPORT",
            );
        }

        let adopted = UdpRawSocket::adopt(plain, 65536, 65536).expect("failed to adopt the holder");

        let joined = super::open_connected_fd(adopted.local_addr(), peer_addr, 65536, 65536);
        // SAFETY: `adopted` owns this fd and outlives every use of the borrow.
        let fd = unsafe { BorrowedFd::borrow_raw(adopted.as_raw_fd()) };
        let flags = socket2::SockRef::from(&fd);
        let reuse_address = flags.reuse_address().expect("read SO_REUSEADDR");
        let reuse_port = flags.reuse_port().expect("read SO_REUSEPORT");

        if let Err(err) = &joined {
            panic!("a connected socket must be able to bind the adopted socket's port: {err}");
        }
        assert!(reuse_address, "the adopted socket must carry SO_REUSEADDR");
        assert!(reuse_port, "the adopted socket must carry SO_REUSEPORT");
    }

    #[tokio::test]
    async fn test_async_udp_socket_send_recv() {
        let sock1 = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
            .expect("failed to bind socket 1");
        let addr1 = sock1.local_addr();
        let async1 = sock1.into_async().expect("into_async 1");

        let sock2 = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
            .expect("failed to bind socket 2");
        let addr2 = sock2.local_addr();
        let async2 = sock2.into_async().expect("into_async 2");

        // Send from socket 1 to socket 2
        let payload = b"hello fips";
        let sent = async1.send_to(payload, &addr2).await.expect("send_to");
        assert_eq!(sent, payload.len());

        // Receive on socket 2
        let mut buf = [0u8; 1024];
        let (n, src, _drops) = async2.recv_from(&mut buf).await.expect("recv_from");
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], payload);
        assert_eq!(src, addr1);
    }

    /// Measurement: duplicate local ports among many concurrently held
    /// port-zero UDP binds, with reuse flags set before the bind and with
    /// reuse flags set after it by `adopt`.
    ///
    /// A reuse flag set before a port-zero bind lets the kernel hand out a
    /// port another flagged socket already holds; set after the bind it only
    /// lets a later socket join. Three arms, each run over several trials:
    ///
    /// - `pre` flags each socket and then binds it, which is the ordering
    ///   that must not be used for a traversal socket. It is built here from
    ///   socket2 because no such helper exists in the tree. It must show
    ///   duplicates: if it shows none, this run could not have seen the
    ///   hazard, and the measurement fails rather than passing.
    /// - `post` binds exactly as the traversal path does and then adopts,
    ///   so `adopt` flags each socket while other threads are still binding.
    /// - `orphan` holds sockets flagged before their bind, as a connected
    ///   socket is, and counts later plain binds handed one of their ports.
    ///
    /// Coverage gap: nothing that gates runs this, because the port
    /// allocator is probabilistic. It measures the kernel behaviour the
    /// adoption path relies on, not the traversal binds themselves, so a
    /// change that flagged those binds before binding would not turn it red.
    ///
    /// Run with:
    ///   cargo test --lib transport::udp::io::tests::measure_duplicate_ephemeral_ports -- --ignored --nocapture
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "probabilistic kernel port-allocator measurement; run explicitly with --ignored --nocapture"]
    fn measure_duplicate_ephemeral_ports_for_reuse_flags_set_before_and_after_bind() {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::collections::HashSet;
        use std::sync::Barrier;

        const N: usize = 500;
        const TRIALS: usize = 5;
        const THREADS: usize = 8;
        const HELD: usize = 200;
        const BUF: usize = 65536;

        fn plain_bind() -> std::net::UdpSocket {
            std::net::UdpSocket::bind(("0.0.0.0", 0)).expect("plain port-zero bind")
        }

        fn flagged_bind() -> std::net::UdpSocket {
            let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("socket");
            sock.set_reuse_port(true).expect("set SO_REUSEPORT");
            sock.set_reuse_address(true).expect("set SO_REUSEADDR");
            let any: SocketAddr = "0.0.0.0:0".parse().unwrap();
            sock.bind(&any.into()).expect("flagged port-zero bind");
            sock.into()
        }

        /// Bind `n` sockets across `THREADS` threads released together,
        /// adopting each one as soon as it is bound, and hold every socket
        /// until all the threads have finished.
        fn bind_concurrently(n: usize, bind: fn() -> std::net::UdpSocket) -> Vec<UdpRawSocket> {
            let barrier = Barrier::new(THREADS);
            std::thread::scope(|s| {
                let handles: Vec<_> = (0..THREADS)
                    .map(|t| {
                        let share = n / THREADS + usize::from(t < n % THREADS);
                        let barrier = &barrier;
                        s.spawn(move || {
                            barrier.wait();
                            (0..share)
                                .map(|_| UdpRawSocket::adopt(bind(), BUF, BUF).expect("adopt"))
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|h| h.join().expect("bind thread panicked"))
                    .collect()
            })
        }

        fn duplicates(socks: &[UdpRawSocket]) -> usize {
            let distinct: HashSet<u16> = socks.iter().map(|s| s.local_addr().port()).collect();
            socks.len() - distinct.len()
        }

        let mut pre = Vec::with_capacity(TRIALS);
        let mut post = Vec::with_capacity(TRIALS);
        let mut orphan = Vec::with_capacity(TRIALS);
        for _ in 0..TRIALS {
            pre.push(duplicates(&bind_concurrently(N, flagged_bind)));
            post.push(duplicates(&bind_concurrently(N, plain_bind)));

            let held: Vec<std::net::UdpSocket> = (0..HELD).map(|_| flagged_bind()).collect();
            let held_ports: HashSet<u16> = held
                .iter()
                .map(|s| s.local_addr().expect("held local address").port())
                .collect();
            let later = bind_concurrently(N, plain_bind);
            orphan.push(
                later
                    .iter()
                    .filter(|s| held_ports.contains(&s.local_addr().port()))
                    .count(),
            );
        }

        eprintln!("duplicate ports per {N} binds, {THREADS} threads, {TRIALS} trials");
        eprintln!("  pre    (flags before bind): {pre:?}");
        eprintln!("  post   (flags after bind):  {post:?}");
        eprintln!("  orphan ({HELD} held pre-flagged, later plain binds): {orphan:?}");

        assert!(
            pre.iter().sum::<usize>() > 0,
            "the before-bind arm showed no duplicates, so this run could not have seen the \
             hazard at N = {N}; raise N rather than reading the other arms as clean",
        );
        assert_eq!(
            post.iter().sum::<usize>(),
            0,
            "flags set after bind: {post:?}"
        );
        assert_eq!(
            orphan.iter().sum::<usize>(),
            0,
            "orphan collisions: {orphan:?}"
        );
    }

    /// Microbench: compare per-packet `recv_from` (single recvmsg syscall +
    /// task wakeup per datagram — the macOS pre-recvmsg_x baseline) vs
    /// `recv_batch` (the new recvmsg_x path, up to 32 datagrams per syscall).
    /// Both modes run back-to-back in this binary on loopback so the only
    /// thing that varies is the receive-syscall strategy. Sender is a tight
    /// `socket.send_to()` loop in a separate task; receiver counts datagrams
    /// drained over a fixed wall-clock window per mode.
    ///
    /// Run with:
    ///   cargo test --release -p fips --lib transport::udp::io::tests::bench_udp_recv_amortization -- --ignored --nocapture
    ///
    /// Sender runs on a dedicated *blocking* OS thread (std::net::UdpSocket
    /// in default blocking mode) so it always saturates the kernel rx queue
    /// regardless of how the tokio receiver schedules. That's the scenario
    /// where recvmmsg / recvmsg_x is meant to win: the receiver wakes up to
    /// find N packets already buffered, and one syscall reaps the burst.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "microbenchmark; run explicitly with --ignored --nocapture"]
    async fn bench_udp_recv_amortization() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};

        const RECV_BUF: usize = 4 * 1024 * 1024;
        const SEND_BUF: usize = 1024 * 1024;
        const PAYLOAD_LEN: usize = 100;
        const WINDOW: Duration = Duration::from_secs(3);
        const WARMUP: Duration = Duration::from_millis(500);

        async fn run_mode(
            label: &str,
            batched: bool,
            sender_threads: usize,
        ) -> (u64, u64, Duration) {
            let rx_sock = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), RECV_BUF, SEND_BUF)
                .expect("rx bind");
            let rx_addr = rx_sock.local_addr();
            let rx = rx_sock.into_async().expect("rx into_async");

            // Senders: N dedicated blocking std threads. More threads → deeper
            // kernel rx queue → larger amortization opportunity for recv_batch.
            // ENOBUFS / EAGAIN just yield and retry; we want saturation, not
            // perfect accounting. Sent count is best-effort.
            let stop = Arc::new(AtomicBool::new(false));
            let mut sender_handles = Vec::with_capacity(sender_threads);
            for _ in 0..sender_threads {
                let stop_tx = stop.clone();
                sender_handles.push(std::thread::spawn(move || {
                    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("tx bind");
                    sock.connect(rx_addr).expect("tx connect");
                    let payload = vec![0xABu8; PAYLOAD_LEN];
                    let mut sent: u64 = 0;
                    while !stop_tx.load(Ordering::Relaxed) {
                        match sock.send(&payload) {
                            Ok(_) => sent += 1,
                            Err(_) => std::thread::yield_now(),
                        }
                    }
                    sent
                }));
            }

            // Warm-up: let the sender thread reach steady state and the
            // kernel rx queue start filling.
            tokio::time::sleep(WARMUP).await;

            let start = Instant::now();
            let deadline = start + WINDOW;
            let mut recv_count: u64 = 0;
            let mut last_drops: u32 = 0;

            if batched {
                const BATCH: usize = 32;
                let mut backing: Vec<Vec<u8>> =
                    (0..BATCH).map(|_| vec![0u8; PAYLOAD_LEN + 64]).collect();
                let mut addrs: [Option<SocketAddr>; BATCH] = std::array::from_fn(|_| None);
                let mut lens: [usize; BATCH] = [0; BATCH];
                let mut batch_sum: u64 = 0;
                let mut batch_calls: u64 = 0;

                while Instant::now() < deadline {
                    let mut bufs: [&mut [u8]; BATCH] = {
                        let mut iter = backing.iter_mut();
                        std::array::from_fn(|_| iter.next().unwrap().as_mut_slice())
                    };
                    match rx.recv_batch(&mut bufs, &mut addrs, &mut lens).await {
                        Ok((n, drops)) => {
                            recv_count += n as u64;
                            batch_sum += n as u64;
                            batch_calls += 1;
                            last_drops = drops;
                        }
                        Err(_) => break,
                    }
                }
                let avg_batch = if batch_calls > 0 {
                    batch_sum as f64 / batch_calls as f64
                } else {
                    0.0
                };
                eprintln!(
                    "[{:>10}] avg_batch_per_call={:.2} ({} calls)",
                    label, avg_batch, batch_calls
                );
            } else {
                let mut buf = vec![0u8; PAYLOAD_LEN + 64];
                while Instant::now() < deadline {
                    match rx.recv_from(&mut buf).await {
                        Ok((_n, _src, drops)) => {
                            recv_count += 1;
                            last_drops = drops;
                        }
                        Err(_) => break,
                    }
                }
            }
            let elapsed = start.elapsed();

            stop.store(true, Ordering::Relaxed);
            drop(rx);
            let sent: u64 = sender_handles
                .into_iter()
                .map(|h| h.join().unwrap_or(0))
                .sum();

            let pps = (recv_count as f64) / elapsed.as_secs_f64();
            let mbps =
                (recv_count as f64) * (PAYLOAD_LEN as f64) * 8.0 / 1e6 / elapsed.as_secs_f64();
            eprintln!(
                "[{:>10}] recv={:>10} sent={:>10} elapsed={:?} pps={:>12.0} mbps={:>7.1} kdrops={}",
                label, recv_count, sent, elapsed, pps, mbps, last_drops
            );
            (recv_count, sent, elapsed)
        }

        eprintln!("--- udp recv amortization bench ---");
        eprintln!(
            "payload={}B window={:?} warmup={:?} runtime=multi_thread(2)",
            PAYLOAD_LEN, WINDOW, WARMUP
        );

        // Sweep sender concurrency. Each level shows how the win scales as
        // the rx queue gets deeper (more amortization opportunity).
        for senders in [1usize, 2, 4, 8] {
            eprintln!("\n=== sender_threads = {} ===", senders);
            let (b_recv, _, b_el) = run_mode(" recv_from", false, senders).await;
            let (x_recv, _, x_el) = run_mode("recv_batch", true, senders).await;
            let (x_recv2, _, x_el2) = run_mode("recv_batch", true, senders).await;
            let (b_recv2, _, b_el2) = run_mode(" recv_from", false, senders).await;

            let baseline_pps =
                (b_recv as f64 / b_el.as_secs_f64() + b_recv2 as f64 / b_el2.as_secs_f64()) / 2.0;
            let batched_pps =
                (x_recv as f64 / x_el.as_secs_f64() + x_recv2 as f64 / x_el2.as_secs_f64()) / 2.0;
            let speedup = batched_pps / baseline_pps;
            eprintln!(
                "--- senders={}: baseline={:.0} pps  batched={:.0} pps  speedup={:.2}x ---",
                senders, baseline_pps, batched_pps, speedup
            );
        }
    }
}
