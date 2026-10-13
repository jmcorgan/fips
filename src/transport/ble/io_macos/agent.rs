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
//! with it. A session lasts only while the radio is up on the PSM its hello
//! reported: the radio going down, or coming back on another PSM, ends it, so
//! the daemon never holds a radio that is not there.
//!
//! The session loop never waits on a channel. Outbound bytes are queued per
//! channel and bounded by the send credit the agent grants (see
//! [`super::agent_proto`]), so one peer that stops taking bytes stalls only
//! its own channel.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::super::addr::BleAddr;
use super::super::io::{BleAcceptor, BleIo, BleScanner, BleStream};
use super::agent_proto::{Frame, MAX_FRAME, VERSION, read_frame_async};

/// How long a dial may run before the agent reports it failed. The daemon's
/// transport gives up sooner and ignores a late answer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait between attempts to reach the daemon.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Longest wait between attempts once the daemon keeps turning the agent
/// away — another agent holds the radio, or it speaks another version.
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(60);

/// A session that lasted this long was accepted, and resets the backoff.
const STABLE_SESSION: Duration = Duration::from_secs(30);

/// How often to check whether the radio is up, before connecting and during
/// a session.
const RADIO_POLL: Duration = Duration::from_millis(200);

/// The send credit each channel starts with, in bytes: how much the daemon
/// may have queued at the agent for one channel before it must wait for the
/// radio to take some.
///
/// Small, like the bridge's own send queue, because a BLE link's
/// bandwidth-delay product is about a packet and a deeper queue only adds
/// latency.
pub const CHANNEL_WINDOW: u32 = 32 * 1024;

/// Bytes queued on one channel beyond which the daemon has overrun its
/// credit. The daemon may spend its last credit on a packet larger than what
/// remained, so one frame of slack.
const CHANNEL_OVERRUN: usize = CHANNEL_WINDOW as usize + MAX_FRAME;

/// Depth of the queue of channel bytes and adverts towards the daemon.
const DATA_QUEUE: usize = 256;

/// Run the agent forever: start the radio's listener, then serve the daemon
/// listening at `socket`, reconnecting whenever it goes away.
///
/// `daemon_uid`, when given, is the only user the agent will serve: a socket
/// answered by anyone else is not the daemon and is dropped before the hello.
///
/// `radio_psm` is the PSM the radio's listener bound, `Some(0)` for a radio
/// that is up with no listener, and `None` while the radio is not up. The
/// agent does not connect until the radio is up — `listen` reports only the
/// requested fallback until then, and the hello would hand the daemon a PSM
/// nothing listens on — and ends the session when it goes down or comes back
/// on another PSM, then says hello again with the new one.
pub async fn run<I: BleIo>(
    io: Arc<I>,
    socket: PathBuf,
    daemon_uid: Option<u32>,
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
    let mut backoff = RECONNECT_DELAY;

    loop {
        let psm = wait_for_radio(&radio_psm).await;
        match UnixStream::connect(&socket).await {
            Ok(stream) => {
                if let Err(e) = check_peer(&stream, daemon_uid) {
                    warn!(path = %socket.display(), error = %e, "BLE agent: not the daemon; not serving it");
                    backoff = (backoff * 2).min(MAX_RECONNECT_DELAY);
                    tokio::time::sleep(backoff).await;
                    continue;
                }
                info!(path = %socket.display(), "BLE agent: connected to the daemon");
                let started = Instant::now();
                let outcome = serve(&io, stream, psm, &radio_psm, &mut inbound, &mut scans).await;
                let _ = io.stop_advertising().await;
                let _ = io.stop_scanning().await;
                match outcome {
                    Ok(Outcome::Busy) => {
                        backoff = (backoff * 2).min(MAX_RECONNECT_DELAY);
                        info!(
                            retry_in = ?backoff,
                            "BLE agent: another agent lends the daemon its radio; standing by"
                        );
                    }
                    Ok(Outcome::RadioChanged) => {
                        info!("BLE agent: radio went down or changed PSM; reconnecting");
                        backoff = RECONNECT_DELAY;
                    }
                    Ok(Outcome::Ended) | Err(_) => {
                        if let Err(e) = &outcome {
                            debug!(error = %e, "BLE agent: session ended");
                        }
                        info!("BLE agent: daemon gone");
                        // A session the daemon cut short at once — another
                        // version, say — backs off; one that ran a while is
                        // a daemon restart, and is retried promptly.
                        backoff = if started.elapsed() >= STABLE_SESSION {
                            RECONNECT_DELAY
                        } else {
                            (backoff * 2).min(MAX_RECONNECT_DELAY)
                        };
                    }
                }
                tokio::time::sleep(backoff).await;
            }
            Err(e) => {
                debug!(path = %socket.display(), error = %e, "BLE agent: daemon not reachable");
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        }
    }
}

/// Refuse a socket not answered by `daemon_uid`.
///
/// The socket's directory is the daemon's, but the agent runs as an ordinary
/// user and would otherwise hand its radio, and every peer's bytes, to
/// whoever got there first.
fn check_peer(stream: &UnixStream, daemon_uid: Option<u32>) -> io::Result<()> {
    let Some(expected) = daemon_uid else {
        return Ok(());
    };
    let uid = stream.peer_cred()?.uid();
    if uid != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("socket owned by uid {uid}, expected {expected}"),
        ));
    }
    Ok(())
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
    /// Outbound bytes, towards the radio. Unbounded as a queue, bounded by
    /// the credit the daemon holds, which `queued` checks.
    tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Bytes in `tx` not yet taken by the radio.
    queued: Arc<AtomicUsize>,
    tasks: [JoinHandle<()>; 2],
}

impl Channel {
    /// Queue `data` for the radio, without waiting. `false` means the daemon
    /// has sent past its credit.
    fn queue(&self, data: Vec<u8>) -> bool {
        let queued = self.queued.fetch_add(data.len(), Ordering::Relaxed) + data.len();
        if queued > CHANNEL_OVERRUN {
            return false;
        }
        // A writer that has stopped has met a dead stream, and the reader
        // will report the channel ended.
        let _ = self.tx.send(data);
        true
    }
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

/// How a session ended without an error.
enum Outcome {
    /// The daemon hung up.
    Ended,
    /// The daemon already has an agent.
    Busy,
    /// The radio went down, or came back on another PSM.
    RadioChanged,
}

/// The two queues towards the daemon.
///
/// Control frames — channel openings and closings, dial results, credit —
/// go first and are never refused, so the session loop never waits on them;
/// they are few and small. Channel bytes and adverts share a bounded queue
/// behind them: a reader waits for room, an advert is dropped.
#[derive(Clone)]
struct ToDaemon {
    control: mpsc::UnboundedSender<Frame>,
    data: mpsc::Sender<Frame>,
}

impl ToDaemon {
    fn control(&self, frame: Frame) -> io::Result<()> {
        self.control
            .send(frame)
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

/// Serve one daemon connection until it ends.
async fn serve<I: BleIo>(
    io: &Arc<I>,
    stream: UnixStream,
    psm: u16,
    radio_psm: &impl Fn() -> Option<u16>,
    inbound: &mut mpsc::Receiver<I::Stream>,
    scans: &mut ScanFeed,
) -> io::Result<Outcome> {
    // Inbound channels that arrived with no daemon to take them are stale.
    while inbound.try_recv().is_ok() {}

    let (mut rd, mut wr) = stream.into_split();
    // Frames are read on a task of their own: a read is not cancel-safe, and
    // in the loop's `select!` any other branch firing mid-frame would drop
    // the bytes read so far and desynchronise the stream.
    let (frames_tx, mut frames) = mpsc::channel::<io::Result<Frame>>(1);
    let _reader = AbortOnDrop(tokio::spawn(async move {
        loop {
            let frame = match read_frame_async(&mut rd).await {
                Ok(Some(frame)) => Ok(frame),
                Ok(None) => return,
                Err(e) => Err(e),
            };
            let failed = frame.is_err();
            if frames_tx.send(frame).await.is_err() || failed {
                return;
            }
        }
    }));
    let (control_tx, mut control_rx) = mpsc::unbounded_channel::<Frame>();
    let (data_tx, mut data_rx) = mpsc::channel::<Frame>(DATA_QUEUE);
    let writer = tokio::spawn(async move {
        loop {
            let frame = tokio::select! {
                biased;
                Some(frame) = control_rx.recv() => frame,
                Some(frame) = data_rx.recv() => frame,
                else => return,
            };
            if wr.write_all(&frame.encode()).await.is_err() {
                return;
            }
        }
    });
    let _writer = AbortOnDrop(writer);
    let out = ToDaemon {
        control: control_tx,
        data: data_tx,
    };
    out.control(Frame::Hello {
        version: VERSION,
        psm,
    })?;

    let (events_tx, mut events) = mpsc::channel::<Event<I::Stream>>(64);
    let mut channels: HashMap<u32, Channel> = HashMap::new();
    let mut next_ch: u32 = 1;
    let mut radio_check = tokio::time::interval(RADIO_POLL);
    radio_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            frame = frames.recv() => {
                let Some(frame) = frame.transpose()? else { return Ok(Outcome::Ended) };
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
                        if let Some(channel) = channels.get(&ch)
                            && !channel.queue(data)
                        {
                            warn!(ch, "BLE agent: daemon sent past its credit; closing the channel");
                            channels.remove(&ch);
                            out.control(Frame::Closed { ch })?;
                        }
                    }
                    Frame::Close { ch } => {
                        channels.remove(&ch);
                    }
                    Frame::Busy => return Ok(Outcome::Busy),
                    other => debug!(frame = ?other, "BLE agent: unexpected frame"),
                }
            }
            Some(stream) = inbound.recv() => {
                let ch = allocate(&mut next_ch);
                // Announced before its reader starts, so the daemon knows
                // the channel by the time its first bytes arrive.
                out.control(Frame::Inbound {
                    ch,
                    addr: stream.remote_addr().clone(),
                    mtu: stream.recv_mtu(),
                })?;
                out.control(Frame::Credit { ch, bytes: CHANNEL_WINDOW })?;
                channels.insert(ch, open_channel(stream, ch, &out, &events_tx));
            }
            Some(advert) = scans.next() => {
                // Adverts repeat; one dropped while the daemon is behind is
                // heard again in a second.
                let _ = out.data.try_send(Frame::Scan { addr: advert.addr, psm: advert.psm, rssi: advert.rssi });
            }
            Some(event) = events.recv() => match event {
                Event::Dialled { id, addr, result: Ok(stream) } => {
                    let ch = allocate(&mut next_ch);
                    let mtu = stream.recv_mtu();
                    out.control(Frame::ConnectResult { id, ok: true, ch, addr, mtu })?;
                    out.control(Frame::Credit { ch, bytes: CHANNEL_WINDOW })?;
                    channels.insert(ch, open_channel(stream, ch, &out, &events_tx));
                }
                Event::Dialled { id, addr, result: Err(e) } => {
                    debug!(addr = %addr, error = %e, "BLE agent: dial failed");
                    out.control(Frame::ConnectResult { id, ok: false, ch: 0, addr, mtu: 0 })?;
                }
                Event::Ended { ch } => {
                    // The reader has already queued `Closed` behind its
                    // last bytes.
                    channels.remove(&ch);
                }
            },
            _ = radio_check.tick() => {
                if radio_psm() != Some(psm) {
                    return Ok(Outcome::RadioChanged);
                }
            }
        }
    }
}

fn allocate(next: &mut u32) -> u32 {
    let ch = *next;
    *next = next.wrapping_add(1).max(1);
    ch
}

/// Start the two tasks carrying channel `ch`'s bytes.
fn open_channel<S: BleStream + 'static>(
    stream: S,
    ch: u32,
    out: &ToDaemon,
    events: &mpsc::Sender<Event<S>>,
) -> Channel {
    let stream = Arc::new(stream);
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let queued = Arc::new(AtomicUsize::new(0));

    let reader = {
        let stream = Arc::clone(&stream);
        let data = out.data.clone();
        let events = events.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; usize::from(stream.recv_mtu()).max(64)];
            loop {
                match stream.recv(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let frame = Frame::Recv {
                            ch,
                            data: buf[..n].to_vec(),
                        };
                        if data.send(frame).await.is_err() {
                            return;
                        }
                    }
                }
            }
            // On the data queue, behind the bytes read before the peer hung
            // up: on the control queue it would overtake them, and the
            // daemon would drop them as belonging to a closed channel.
            if data.send(Frame::Closed { ch }).await.is_err() {
                return;
            }
            let _ = events.send(Event::Ended { ch }).await;
        })
    };
    let writer = {
        let queued = Arc::clone(&queued);
        let control = out.control.clone();
        tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if stream.send(&data).await.is_err() {
                    return;
                }
                queued.fetch_sub(data.len(), Ordering::Relaxed);
                // The radio has the bytes: the daemon may send as many more.
                if !data.is_empty() {
                    let bytes = data.len() as u32;
                    if control.send(Frame::Credit { ch, bytes }).is_err() {
                        return;
                    }
                }
            }
        })
    };
    Channel {
        tx,
        queued,
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
            let _ = run(agent_io, agent_path, None, 0x0085, radio_psm).await;
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

    /// A peer that stops taking bytes stalls only its own channel: the
    /// session keeps carrying every other channel's bytes, and still acts on
    /// the daemon closing the stalled one.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalled_channel_does_not_stall_the_others() {
        let rig = rig().await;
        let (mut acceptor, _) = rig.daemon.listen(0x0085).await.unwrap();

        let (stalled_local, stalled_peer) = MockBleStream::pair(addr(0), addr(5), 512);
        rig.radio.inject_inbound(stalled_local).await;
        let stalled = Arc::new(
            tokio::time::timeout(Duration::from_secs(5), acceptor.accept())
                .await
                .unwrap()
                .unwrap(),
        );
        let (live_local, live_peer) = MockBleStream::pair(addr(0), addr(6), 512);
        rig.radio.inject_inbound(live_local).await;
        let live = tokio::time::timeout(Duration::from_secs(5), acceptor.accept())
            .await
            .unwrap()
            .unwrap();

        // Far more than the stalled peer will ever take; the send blocks.
        let flood = {
            let stalled = Arc::clone(&stalled);
            tokio::spawn(async move {
                let packet = vec![0x5Au8; 1024];
                loop {
                    if stalled.send(&packet).await.is_err() {
                        return;
                    }
                }
            })
        };
        tokio::time::sleep(Duration::from_millis(500)).await;

        live.send(b"still flowing").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), live_peer.recv(&mut buf))
            .await
            .expect("the live channel stalled behind the stalled one")
            .unwrap();
        assert_eq!(&buf[..n], b"still flowing");

        // The daemon giving up on the stalled channel reaches the agent,
        // which closes it on the radio: past what the peer had buffered, it
        // reads end of stream.
        flood.abort();
        let _ = flood.await;
        drop(Arc::into_inner(stalled).unwrap());
        let mut buf = [0u8; 2048];
        let ended = tokio::time::timeout(Duration::from_secs(5), async {
            while stalled_peer.recv(&mut buf).await.unwrap() > 0 {}
        })
        .await;
        assert!(ended.is_ok(), "the close never reached the radio");
    }

    /// A peer that sends and then hangs up has every byte delivered before
    /// the daemon sees the channel end.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_closing_peers_last_bytes_arrive_before_the_close() {
        let rig = rig().await;
        let (mut acceptor, _) = rig.daemon.listen(0x0085).await.unwrap();
        let (local, peer) = MockBleStream::pair(addr(0), addr(5), 512);
        rig.radio.inject_inbound(local).await;
        let stream = tokio::time::timeout(Duration::from_secs(5), acceptor.accept())
            .await
            .unwrap()
            .unwrap();

        const TOTAL: usize = 750 * 1024;
        tokio::spawn(async move {
            let packet = vec![0x3Cu8; 512];
            for _ in 0..TOTAL / packet.len() {
                peer.send(&packet).await.unwrap();
            }
            // Dropping the peer hangs up.
        });

        let mut received = 0;
        let mut buf = [0u8; 2048];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(10), stream.recv(&mut buf))
                .await
                .expect("the channel stalled")
                .unwrap();
            if n == 0 {
                break;
            }
            received += n;
        }
        assert_eq!(received, TOTAL, "bytes lost to an early close");
    }

    /// A second agent is refused while one is live, and the live one keeps
    /// the radio.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_second_agent_is_refused_and_the_first_keeps_the_radio() {
        use tokio::io::AsyncWriteExt;
        let rig = rig().await;
        let live = rig.slot.current().unwrap();

        let mut second = UnixStream::connect(rig._dir.path().join("ble-agent.sock"))
            .await
            .unwrap();
        second
            .write_all(
                &Frame::Hello {
                    version: VERSION,
                    psm: 0x00C9,
                }
                .encode(),
            )
            .await
            .unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(5), read_frame_async(&mut second))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(answer, Some(Frame::Busy));

        let current = rig.slot.current().expect("the live agent was dropped");
        assert!(Arc::ptr_eq(&current, &live), "the radio was replaced");
    }

    /// An agent whose radio goes down hangs up, so the daemon's slot empties;
    /// when the radio is back on a new PSM, it says hello again with it.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_agent_hangs_up_while_its_radio_is_down() {
        let radio_psm = Arc::new(std::sync::Mutex::new(Some(0x00C0)));
        let source = Arc::clone(&radio_psm);
        let rig = rig_with(move || *source.lock().unwrap()).await;
        wait_installed(&rig.slot).await;

        *radio_psm.lock().unwrap() = None;
        let deadline = Instant::now() + Duration::from_secs(5);
        while rig.slot.is_installed() {
            assert!(
                Instant::now() < deadline,
                "the daemon still holds a downed radio"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        *radio_psm.lock().unwrap() = Some(0x00C7);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if rig.slot.is_installed() {
                let (_acceptor, psm) = rig.daemon.listen(0x0085).await.unwrap();
                if psm == 0x00C7 {
                    break;
                }
            }
            assert!(
                Instant::now() < deadline,
                "the agent never came back on the new PSM"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// A daemon that sends past its credit has the channel closed on it,
    /// rather than the agent queueing without bound.
    #[tokio::test(flavor = "multi_thread")]
    async fn sending_past_the_credit_closes_the_channel() {
        use tokio::io::AsyncWriteExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ble-agent.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let radio = Arc::new(MockBleIo::new(RADIO_ADAPTER, addr(0)));
        let agent_io = Arc::clone(&radio);
        let _agent = AbortOnDrop(tokio::spawn(async move {
            let _ = run(agent_io, path, None, 0x0085, || Some(0x00C0)).await;
        }));

        let (mut daemon, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(next(&mut daemon).await, Frame::Hello { .. }));

        // A peer that never reads: the agent's queue for it only grows.
        let (local, _peer) = MockBleStream::pair(addr(0), addr(5), 512);
        radio.inject_inbound(local).await;
        let Frame::Inbound { ch, .. } = next(&mut daemon).await else {
            panic!("expected the inbound channel");
        };
        assert_eq!(
            next(&mut daemon).await,
            Frame::Credit {
                ch,
                bytes: CHANNEL_WINDOW
            }
        );

        let packet = vec![0u8; 4096];
        for _ in 0..(CHANNEL_OVERRUN / packet.len() + 128) {
            daemon
                .write_all(
                    &Frame::Send {
                        ch,
                        data: packet.clone(),
                    }
                    .encode(),
                )
                .await
                .unwrap();
        }
        loop {
            match next(&mut daemon).await {
                Frame::Credit { .. } => continue,
                frame => {
                    assert_eq!(frame, Frame::Closed { ch });
                    break;
                }
            }
        }
    }

    async fn next(daemon: &mut UnixStream) -> Frame {
        tokio::time::timeout(Duration::from_secs(5), read_frame_async(daemon))
            .await
            .expect("the agent went quiet")
            .unwrap()
            .unwrap()
    }

    /// The agent serves only the user it was told the daemon runs as.
    #[tokio::test]
    async fn a_socket_answered_by_another_user_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ble-agent.sock");
        let _listener = tokio::net::UnixListener::bind(&path).unwrap();
        let stream = UnixStream::connect(&path).await.unwrap();
        let me = unsafe { libc::getuid() };
        assert!(check_peer(&stream, None).is_ok());
        assert!(check_peer(&stream, Some(me)).is_ok());
        assert_eq!(
            check_peer(&stream, Some(me.wrapping_add(1)))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
