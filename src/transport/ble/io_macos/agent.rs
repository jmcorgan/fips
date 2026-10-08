//! The BLE agent: a radio, lent to the daemon over a Unix socket.
//!
//! macOS gives CoreBluetooth only to processes in a user's login session. The
//! agent is the `fips` binary run in that session (`fips --ble-agent`, as a
//! per-user LaunchAgent): it owns the radio, connects to the daemon's
//! [`super::agent_server`], and proxies between them in the
//! [`super::agent_proto`] protocol — commands in, adverts, channels and bytes
//! out.
//!
//! The proxy is written against [`BleIo`], not CoreBluetooth: on macOS it
//! runs over `RadioIo` and the in-process CoreBluetooth radio, and in tests
//! over the in-memory `MockBleIo`, which is how it is tested end to end on
//! any host.
//!
//! The radio is the agent's for its whole life. Listening starts once, the
//! scanner once, at first request; a daemon that disconnects and reconnects
//! finds them still running. What a session owns is its channels, which end
//! with it.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::super::addr::BleAddr;
use super::super::io::{BleAcceptor, BleIo, BleScanner, BleStream};
use super::agent_proto::{Frame, VERSION, read_frame_async};

/// How long a dial may run before the agent reports it failed. The daemon's
/// transport gives up sooner and ignores a late answer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait between attempts to reach the daemon.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// How often to check whether the radio has come up, before connecting.
const RADIO_POLL: Duration = Duration::from_millis(200);

/// Depth of each channel's outbound queue, towards the radio.
const CHANNEL_QUEUE: usize = 32;

/// Run the agent forever: start the radio's listener, then serve whichever
/// daemon is listening at the path `socket` yields, reconnecting whenever it
/// goes away.
///
/// `socket` is asked again before every attempt. The default path depends on
/// which runtime directories exist, and an agent started at login can come
/// up before the daemon has created its own; resolving once would pin the
/// agent to a fallback path no daemon ever listens on.
///
/// `radio_psm` is the PSM the radio's listener bound, `Some(0)` for a radio
/// that is up with no listener, and `None` while the radio is not up. It is
/// read before every connection, and the agent does not connect until the
/// radio is up: `listen` reports only the requested fallback until then, and
/// the hello would hand the daemon a PSM nothing listens on. Reading it per
/// connection also carries the new PSM across a Bluetooth toggle, which
/// republishes the listener.
pub async fn run<I: BleIo>(
    io: Arc<I>,
    socket: impl Fn() -> PathBuf,
    requested_psm: u16,
    radio_psm: impl Fn() -> Option<u16>,
) -> io::Result<()> {
    let (mut acceptor, _) = io
        .listen(requested_psm)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    let (inbound_tx, mut inbound) = mpsc::channel::<I::Stream>(16);
    tokio::spawn(async move {
        loop {
            match acceptor.accept().await {
                Ok(stream) => {
                    if inbound_tx.send(stream).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "BLE agent: accept failed");
                    tokio::time::sleep(RECONNECT_DELAY).await;
                }
            }
        }
    });
    let mut scans = ScanFeed::default();

    loop {
        let psm = wait_for_radio(&radio_psm).await;
        let socket = socket();
        match UnixStream::connect(&socket).await {
            Ok(stream) => {
                info!(path = %socket.display(), "BLE agent: connected to the daemon");
                if let Err(e) = serve(&io, stream, psm, &mut inbound, &mut scans).await {
                    debug!(error = %e, "BLE agent: session ended");
                }
                info!("BLE agent: daemon gone");
                let _ = io.stop_advertising().await;
                let _ = io.stop_scanning().await;
            }
            Err(e) => {
                debug!(path = %socket.display(), error = %e, "BLE agent: daemon not reachable")
            }
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// The PSM to report in the hello, once the radio is up.
async fn wait_for_radio(radio_psm: &impl Fn() -> Option<u16>) -> u16 {
    loop {
        if let Some(psm) = radio_psm() {
            return psm;
        }
        tokio::time::sleep(RADIO_POLL).await;
    }
}

/// The scanner's adverts, started on the first scan request and kept for the
/// agent's life.
#[derive(Default)]
struct ScanFeed {
    rx: Option<mpsc::Receiver<super::super::io::ScanAdvert>>,
}

impl ScanFeed {
    async fn start<I: BleIo>(&mut self, io: &Arc<I>) {
        let scanner = io.start_scanning().await;
        if self.rx.is_some() {
            // Already feeding: the call above was only to resume the radio.
            return;
        }
        match scanner {
            Ok(mut scanner) => {
                let (tx, rx) = mpsc::channel(64);
                tokio::spawn(async move {
                    while let Some(advert) = scanner.next().await {
                        if tx.send(advert).await.is_err() {
                            return;
                        }
                    }
                });
                self.rx = Some(rx);
            }
            Err(e) => warn!(error = %e, "BLE agent: scan failed to start"),
        }
    }

    async fn next(&mut self) -> Option<super::super::io::ScanAdvert> {
        match self.rx.as_mut() {
            Some(rx) => rx.recv().await,
            None => std::future::pending().await,
        }
    }
}

/// A channel this session has handed to the daemon.
struct Channel {
    tx: mpsc::Sender<Vec<u8>>,
    tasks: [JoinHandle<()>; 2],
}

impl Drop for Channel {
    /// Ending both tasks drops the last references to the stream, which
    /// closes it on the radio.
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// What the session's own tasks report back to it.
enum Event<S> {
    Dialled {
        id: i64,
        addr: BleAddr,
        result: Result<S, String>,
    },
    Ended {
        ch: u32,
    },
}

/// Serve one daemon connection until it ends.
async fn serve<I: BleIo>(
    io: &Arc<I>,
    stream: UnixStream,
    psm: u16,
    inbound: &mut mpsc::Receiver<I::Stream>,
    scans: &mut ScanFeed,
) -> io::Result<()> {
    // Inbound channels that arrived with no daemon to take them are stale.
    while inbound.try_recv().is_ok() {}

    let (mut rd, mut wr) = stream.into_split();
    let (out, mut out_rx) = mpsc::channel::<Frame>(256);
    let writer = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if wr.write_all(&frame.encode()).await.is_err() {
                return;
            }
        }
    });
    let _writer = AbortOnDrop(writer);
    send(
        &out,
        Frame::Hello {
            version: VERSION,
            psm,
        },
    )
    .await?;

    let (events_tx, mut events) = mpsc::channel::<Event<I::Stream>>(64);
    let mut channels: HashMap<u32, Channel> = HashMap::new();
    let mut next_ch: u32 = 1;

    loop {
        tokio::select! {
            frame = read_frame_async(&mut rd) => {
                let Some(frame) = frame? else { return Ok(()) };
                match frame {
                    Frame::Connect { id, addr, psm } => {
                        let io = Arc::clone(io);
                        let events = events_tx.clone();
                        tokio::spawn(async move {
                            let result = match tokio::time::timeout(CONNECT_TIMEOUT, io.connect(&addr, psm)).await {
                                Ok(Ok(stream)) => Ok(stream),
                                Ok(Err(e)) => Err(e.to_string()),
                                Err(_) => Err("timed out".into()),
                            };
                            let _ = events.send(Event::Dialled { id, addr, result }).await;
                        });
                    }
                    Frame::StartAdvertising { psm } => {
                        if let Err(e) = io.start_advertising(psm).await {
                            warn!(error = %e, "BLE agent: advertising failed");
                        }
                    }
                    Frame::StopAdvertising => {
                        let _ = io.stop_advertising().await;
                    }
                    Frame::StartScanning => scans.start(io).await,
                    Frame::StopScanning => {
                        let _ = io.stop_scanning().await;
                    }
                    Frame::Send { ch, data } => {
                        let tx = channels.get(&ch).map(|c| c.tx.clone());
                        if let Some(tx) = tx {
                            // Waits for room, so a slow radio pushes back on the
                            // daemon rather than the agent buffering without
                            // bound.
                            let _ = tx.send(data).await;
                        }
                    }
                    Frame::Close { ch } => {
                        channels.remove(&ch);
                    }
                    other => debug!(frame = ?other, "BLE agent: unexpected frame"),
                }
            }
            Some(stream) = inbound.recv() => {
                let ch = allocate(&mut next_ch);
                let frame = Frame::Inbound {
                    ch,
                    addr: stream.remote_addr().clone(),
                    mtu: stream.recv_mtu(),
                };
                channels.insert(ch, open_channel(stream, ch, &out, &events_tx));
                send(&out, frame).await?;
            }
            Some(advert) = scans.next() => {
                send(&out, Frame::Scan { addr: advert.addr, psm: advert.psm, rssi: advert.rssi }).await?;
            }
            Some(event) = events.recv() => match event {
                Event::Dialled { id, addr, result: Ok(stream) } => {
                    let ch = allocate(&mut next_ch);
                    let mtu = stream.recv_mtu();
                    channels.insert(ch, open_channel(stream, ch, &out, &events_tx));
                    send(&out, Frame::ConnectResult { id, ok: true, ch, addr, mtu }).await?;
                }
                Event::Dialled { id, addr, result: Err(e) } => {
                    debug!(addr = %addr, error = %e, "BLE agent: dial failed");
                    send(&out, Frame::ConnectResult { id, ok: false, ch: 0, addr, mtu: 0 }).await?;
                }
                Event::Ended { ch } => {
                    if channels.remove(&ch).is_some() {
                        send(&out, Frame::Closed { ch }).await?;
                    }
                }
            },
        }
    }
}

fn allocate(next: &mut u32) -> u32 {
    let ch = *next;
    *next = next.wrapping_add(1).max(1);
    ch
}

async fn send(out: &mpsc::Sender<Frame>, frame: Frame) -> io::Result<()> {
    out.send(frame)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
}

/// Start the two tasks carrying channel `ch`'s bytes.
fn open_channel<S: BleStream + 'static>(
    stream: S,
    ch: u32,
    out: &mpsc::Sender<Frame>,
    events: &mpsc::Sender<Event<S>>,
) -> Channel {
    let stream = Arc::new(stream);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_QUEUE);

    let reader = {
        let stream = Arc::clone(&stream);
        let out = out.clone();
        let events = events.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; usize::from(stream.recv_mtu()).max(64)];
            loop {
                match stream.recv(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let data = buf[..n].to_vec();
                        if out.send(Frame::Recv { ch, data }).await.is_err() {
                            return;
                        }
                    }
                }
            }
            let _ = events.send(Event::Ended { ch }).await;
        })
    };
    let writer = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if stream.send(&data).await.is_err() {
                return;
            }
        }
    });
    Channel {
        tx,
        tasks: [reader, writer],
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// ============================================================================
// Tests — daemon server and agent, end to end, over MockBleIo
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::agent_server::AgentServer;
    use super::*;
    use crate::transport::ble::io::{MockBleIo, MockBleStream, ScanAdvert};
    use crate::transport::ble::io_radio::{BleRadioSlot, RADIO_ADAPTER, RadioIo};
    use std::time::Instant;

    fn addr(n: u8) -> BleAddr {
        BleAddr {
            adapter: RADIO_ADAPTER.to_string(),
            device: [0x02, 0, 0, 0, 0, n],
        }
    }

    /// A daemon-side `RadioIo` and an agent over a mock radio, joined by a
    /// real Unix socket.
    struct Rig {
        daemon: RadioIo,
        radio: Arc<MockBleIo>,
        slot: Arc<BleRadioSlot>,
        agent: JoinHandle<()>,
        _server: Arc<AgentServer>,
        _dir: tempfile::TempDir,
    }

    async fn rig() -> Rig {
        let rig = rig_with(|| Some(0x00C0)).await;
        wait_installed(&rig.slot).await;
        rig
    }

    async fn wait_installed(slot: &BleRadioSlot) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !slot.is_installed() {
            assert!(Instant::now() < deadline, "agent never connected");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The rig, with the agent's radio reporting `radio_psm`, not yet
    /// waited on.
    async fn rig_with(radio_psm: impl Fn() -> Option<u16> + Send + Sync + 'static) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ble-agent.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let slot = Arc::new(BleRadioSlot::new());
        let server = AgentServer::serve_for_test(Arc::clone(&slot), listener, &path);

        let radio = Arc::new(MockBleIo::new(RADIO_ADAPTER, addr(0)));
        radio.set_bound_psm(0x00C0);
        let agent_io = Arc::clone(&radio);
        let agent_path = path.clone();
        let agent = tokio::spawn(async move {
            let _ = run(agent_io, move || agent_path.clone(), 0x0085, radio_psm).await;
        });

        Rig {
            daemon: RadioIo::new(Arc::clone(&slot)),
            radio,
            slot,
            agent,
            _server: server,
            _dir: dir,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_agent_reports_its_listener_psm() {
        let rig = rig().await;
        let (_acceptor, psm) = rig.daemon.listen(0x0085).await.unwrap();
        assert_eq!(psm, 0x00C0, "the agent radio's bound PSM, not the request");
    }

    /// An agent that starts before its radio is up waits for it, and then
    /// reports the PSM the radio bound rather than the fallback `listen`
    /// gave it beforehand.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_agent_waits_for_its_radio_and_reports_its_real_psm() {
        let radio_psm = Arc::new(std::sync::Mutex::new(None));
        let source = Arc::clone(&radio_psm);
        let rig = rig_with(move || *source.lock().unwrap()).await;

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!rig.slot.is_installed(), "no hello before the radio is up");

        *radio_psm.lock().unwrap() = Some(0x00C5);
        wait_installed(&rig.slot).await;
        let (_acceptor, psm) = rig.daemon.listen(0x0085).await.unwrap();
        assert_eq!(
            psm, 0x00C5,
            "the radio's PSM, not the fallback or the mock's"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn advertising_reaches_the_agents_radio() {
        let rig = rig().await;
        let (_acceptor, psm) = rig.daemon.listen(0x0085).await.unwrap();
        rig.daemon.start_advertising(psm).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while rig.radio.advertised_psm() != Some(0x00C0) {
            assert!(
                Instant::now() < deadline,
                "advertising never reached the radio"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn adverts_reach_the_daemons_scanner() {
        let rig = rig().await;
        let mut scanner = rig.daemon.start_scanning().await.unwrap();
        // Let the scan request reach the agent before the radio hears anything.
        tokio::time::sleep(Duration::from_millis(100)).await;
        rig.radio
            .inject_scan_advert(ScanAdvert {
                addr: addr(7),
                psm: Some(0x0080),
                rssi: Some(-60),
            })
            .await;
        let advert = tokio::time::timeout(Duration::from_secs(5), scanner.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(advert.addr, addr(7));
        assert_eq!(advert.psm, Some(0x0080));
        assert_eq!(advert.rssi, Some(-60));
    }

    /// A dial from the daemon is made by the agent's radio, and bytes cross
    /// both ways over the resulting channel.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_dialled_channel_carries_bytes_both_ways() {
        let rig = rig().await;
        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel();
        rig.radio.set_connect_handler(move |remote, psm| {
            assert_eq!(psm, 0x00C1);
            let (local, peer) = MockBleStream::pair(addr(0), remote.clone(), 512);
            peer_tx.send(peer).unwrap();
            Ok(local)
        });

        let stream =
            tokio::time::timeout(Duration::from_secs(5), rig.daemon.connect(&addr(9), 0x00C1))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(stream.remote_addr(), &addr(9));
        let peer = peer_rx.recv().await.unwrap();

        stream.send(b"to the peer").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), peer.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"to the peer");

        peer.send(b"to the daemon").await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(5), stream.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"to the daemon");

        // The peer hanging up reads as end of stream at the daemon.
        drop(peer);
        let n = tokio::time::timeout(Duration::from_secs(5), stream.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_refused_dial_fails_at_the_daemon() {
        let rig = rig().await;
        let result =
            tokio::time::timeout(Duration::from_secs(5), rig.daemon.connect(&addr(9), 0x00C1))
                .await
                .unwrap();
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_inbound_channel_is_accepted_by_the_daemon() {
        let rig = rig().await;
        let (mut acceptor, _) = rig.daemon.listen(0x0085).await.unwrap();
        let (local, peer) = MockBleStream::pair(addr(0), addr(5), 512);
        rig.radio.inject_inbound(local).await;

        let stream = tokio::time::timeout(Duration::from_secs(5), acceptor.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stream.remote_addr(), &addr(5));

        peer.send(b"hello").await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"hello");

        // The daemon dropping the stream closes it on the agent's radio.
        drop(stream);
        let n = tokio::time::timeout(Duration::from_secs(5), peer.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);
    }

    /// A connection that never says hello is not an agent: the live one keeps
    /// the radio.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_silent_connection_does_not_displace_the_agent() {
        let rig = rig().await;
        let live = rig.slot.current().unwrap();
        let _silent =
            std::os::unix::net::UnixStream::connect(rig._dir.path().join("ble-agent.sock"))
                .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let current = rig.slot.current().expect("the live agent was dropped");
        assert!(Arc::ptr_eq(&current, &live), "the radio was replaced");
    }

    /// The agent going away is the radio going away: the slot empties, and
    /// the transport waits for the next one.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_lost_agent_empties_the_slot() {
        let rig = rig().await;
        rig.agent.abort();
        let deadline = Instant::now() + Duration::from_secs(5);
        while rig.slot.is_installed() {
            assert!(Instant::now() < deadline, "slot still holds the lost agent");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
