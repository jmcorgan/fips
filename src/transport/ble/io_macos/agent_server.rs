//! The daemon's end of the BLE agent socket.
//!
//! When CoreBluetooth refuses the daemon (see the module docs of
//! [`super`]), the daemon listens on a Unix socket for a [`super::agent`]
//! running in a user's login session, and treats that agent as its radio:
//! each connection becomes a [`BleRadioBridge`] over an [`AgentLink`],
//! installed into the transport's slot exactly as an Android embedder's or
//! the in-process CoreBluetooth radio's would be. The transport cannot tell
//! the difference. An agent that disconnects is a radio switched off; one
//! that reconnects is a radio replaced.
//!
//! Plain threads, like the in-process radio's pumps: one accepting, one
//! reading each connection, one writing its control frames, and one pulling
//! each open channel's outbound bytes.

use std::collections::HashMap;
use std::io::{self, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use tracing::{debug, info, warn};

use super::super::io_radio::{BleRadio, BleRadioBridge, BleRadioSlot};
use super::agent_proto::{Frame, VERSION, read_frame};

/// How long a channel's pump waits for an outbound packet before checking
/// whether the channel has closed.
const PUMP_IDLE_POLL: Duration = Duration::from_millis(100);

/// How long a new connection has to say hello. One that never does would
/// otherwise hold its thread for the life of the daemon.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// The live agent's socket, shut down when another agent replaces it or the
/// server stops: one radio at a time.
type LiveAgent = Arc<Mutex<Option<UnixStream>>>;

/// Listens for the agent and installs each connection as the radio.
pub struct AgentServer {
    path: PathBuf,
    stopped: Arc<AtomicBool>,
    live: LiveAgent,
}

impl AgentServer {
    /// Bind `path` and start accepting agents into `slot`.
    ///
    /// Bound under the FIPS socket policy (group `fips`, mode `0770`), so an
    /// agent run by a member of the `fips` group can connect. Must be called
    /// inside a tokio runtime context: the policy helper binds through tokio
    /// before the listener is handed to a plain thread.
    pub fn start(slot: Arc<BleRadioSlot>, path: &Path) -> io::Result<Arc<Self>> {
        let listener = crate::utils::sockbind::bind(path, "BLE agent")?.into_std()?;
        listener.set_nonblocking(false)?;
        Ok(Self::serve(slot, listener, path))
    }

    /// Accept agents on an already-bound listener.
    fn serve(slot: Arc<BleRadioSlot>, listener: UnixListener, path: &Path) -> Arc<Self> {
        let server = Arc::new(Self {
            path: path.to_owned(),
            stopped: Arc::new(AtomicBool::new(false)),
            live: LiveAgent::default(),
        });
        info!(path = %path.display(), "BLE: waiting for the fips BLE agent");
        let stopped = Arc::clone(&server.stopped);
        let live = Arc::clone(&server.live);
        let spawned = std::thread::Builder::new()
            .name("fips-ble-agent-accept".into())
            .spawn(move || accept_loop(slot, listener, stopped, live));
        if let Err(e) = spawned {
            warn!(error = %e, "BLE: could not start the agent listener");
        }
        server
    }
}

impl Drop for AgentServer {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        // Wake the blocked accept so the thread sees `stopped` and exits.
        let _ = UnixStream::connect(&self.path);
        // End the live agent's session too, so its threads and bridge do not
        // outlive the transport that owned them.
        if let Some(agent) = lock_live(&self.live).take() {
            let _ = agent.shutdown(std::net::Shutdown::Both);
        }
        crate::utils::sockbind::cleanup(&self.path, "BLE agent");
    }
}

fn lock_live(live: &LiveAgent) -> std::sync::MutexGuard<'_, Option<UnixStream>> {
    live.lock().unwrap_or_else(|e| e.into_inner())
}

fn accept_loop(
    slot: Arc<BleRadioSlot>,
    listener: UnixListener,
    stopped: Arc<AtomicBool>,
    live: LiveAgent,
) {
    for conn in listener.incoming() {
        if stopped.load(Ordering::Relaxed) {
            break;
        }
        let stream = match conn {
            Ok(stream) => stream,
            Err(e) => {
                warn!(error = %e, "BLE: agent accept failed");
                continue;
            }
        };
        let slot = Arc::clone(&slot);
        let live = Arc::clone(&live);
        let spawned = std::thread::Builder::new()
            .name("fips-ble-agent-rx".into())
            .spawn(move || {
                if let Err(e) = serve_agent(slot, stream, &live) {
                    debug!(error = %e, "BLE: agent connection ended");
                }
            });
        if let Err(e) = spawned {
            warn!(error = %e, "BLE: could not serve the agent");
        }
    }
}

/// Serve one agent connection until it ends.
///
/// The connection displaces the live agent only once it has said a valid
/// hello, so a connection that never does cannot take the radio down.
fn serve_agent(slot: Arc<BleRadioSlot>, stream: UnixStream, live: &LiveAgent) -> io::Result<()> {
    let mut reader = stream.try_clone()?;
    reader.set_read_timeout(Some(HELLO_TIMEOUT))?;
    let hello = read_frame(&mut reader)?;
    reader.set_read_timeout(None)?;
    let psm = match hello {
        Some(Frame::Hello { version, psm }) if version == VERSION => psm,
        Some(Frame::Hello { version, .. }) => {
            warn!(
                version,
                expected = VERSION,
                "BLE: agent speaks another protocol version"
            );
            return Ok(());
        }
        other => {
            warn!(frame = ?other, "BLE: agent did not say hello");
            return Ok(());
        }
    };

    let previous = lock_live(live).replace(stream.try_clone()?);
    if let Some(old) = previous {
        let _ = old.shutdown(std::net::Shutdown::Both);
    }

    let link = AgentLink::new(stream, psm)?;
    let bridge = BleRadioBridge::new(Arc::clone(&link) as Arc<dyn BleRadio>);
    info!(psm, "BLE: fips BLE agent connected; radio up");
    slot.install(Arc::clone(&bridge));

    let result = (|| {
        while let Some(frame) = read_frame(&mut reader)? {
            link.dispatch(&bridge, frame);
        }
        Ok(())
    })();

    info!("BLE: fips BLE agent disconnected; radio down");
    link.alive.store(false, Ordering::Relaxed);
    if slot
        .current()
        .is_some_and(|current| Arc::ptr_eq(&current, &bridge))
    {
        slot.clear();
    }
    for ch in link.channels().drain_bridge_ids() {
        bridge.channel_closed(ch);
    }
    result
}

// ============================================================================
// AgentLink — the BleRadio a bridge drives
// ============================================================================

/// Channel identifiers in both directions.
#[derive(Default)]
struct ChannelMap {
    /// Agent channel → bridge channel.
    to_bridge: HashMap<u32, i64>,
    /// Bridge channel → agent channel.
    to_agent: HashMap<i64, u32>,
}

impl ChannelMap {
    fn insert(&mut self, agent: u32, bridge: i64) {
        self.to_bridge.insert(agent, bridge);
        self.to_agent.insert(bridge, agent);
    }

    fn remove_agent(&mut self, agent: u32) -> Option<i64> {
        let bridge = self.to_bridge.remove(&agent)?;
        self.to_agent.remove(&bridge);
        Some(bridge)
    }

    fn remove_bridge(&mut self, bridge: i64) -> Option<u32> {
        let agent = self.to_agent.remove(&bridge)?;
        self.to_bridge.remove(&agent);
        Some(agent)
    }

    fn drain_bridge_ids(&mut self) -> Vec<i64> {
        self.to_bridge.clear();
        self.to_agent.drain().map(|(bridge, _)| bridge).collect()
    }
}

/// One agent connection, as the radio its bridge drives.
struct AgentLink {
    psm: u16,
    /// Data frames are written straight onto the socket by each channel's
    /// pump thread, which may block; control frames go through `control` to
    /// a writer thread, so a [`BleRadio`] call — made from the transport's
    /// async tasks — never does.
    socket: Arc<Mutex<UnixStream>>,
    control: Mutex<mpsc::Sender<Frame>>,
    channels: Mutex<ChannelMap>,
    alive: AtomicBool,
}

impl AgentLink {
    fn new(stream: UnixStream, psm: u16) -> io::Result<Arc<Self>> {
        let socket = Arc::new(Mutex::new(stream));
        let (control, rx) = mpsc::channel::<Frame>();
        let writer = Arc::clone(&socket);
        std::thread::Builder::new()
            .name("fips-ble-agent-tx".into())
            .spawn(move || {
                for frame in rx {
                    if write_frame(&writer, &frame).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Arc::new(Self {
            psm,
            socket,
            control: Mutex::new(control),
            channels: Mutex::new(ChannelMap::default()),
            alive: AtomicBool::new(true),
        }))
    }

    fn channels(&self) -> std::sync::MutexGuard<'_, ChannelMap> {
        self.channels.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn command(&self, frame: Frame) {
        let _ = self
            .control
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send(frame);
    }

    /// Act on one frame from the agent.
    fn dispatch(self: &Arc<Self>, bridge: &Arc<BleRadioBridge>, frame: Frame) {
        match frame {
            Frame::Inbound { ch, addr, mtu } => {
                let id = bridge.deliver_inbound(addr, mtu, mtu);
                self.adopt(bridge, ch, id);
            }
            Frame::ConnectResult {
                id,
                ok,
                ch,
                addr,
                mtu,
            } => {
                let bridge_ch = bridge.deliver_connect_result(id, ok, addr, mtu, mtu);
                if ok {
                    self.adopt(bridge, ch, bridge_ch);
                }
            }
            Frame::Scan { addr, psm, rssi } => {
                bridge.deliver_scan(addr, psm.unwrap_or(0), rssi);
            }
            Frame::Recv { ch, data } => {
                let bridge_ch = self.channels().to_bridge.get(&ch).copied();
                if let Some(bridge_ch) = bridge_ch {
                    // Waits rather than drops: the agent's bytes are a byte
                    // stream, and a hole in one breaks its framing.
                    bridge.deliver_recv_blocking(bridge_ch, &data);
                }
            }
            Frame::Closed { ch } => {
                let bridge_ch = self.channels().remove_agent(ch);
                if let Some(bridge_ch) = bridge_ch {
                    bridge.channel_closed(bridge_ch);
                }
            }
            Frame::Hello { .. } => {}
            other => debug!(frame = ?other, "BLE: unexpected frame from the agent"),
        }
    }

    /// Take agent channel `ch` that the bridge registered as `bridge_ch`, or
    /// tell the agent to close it if the bridge did not want it (`0`).
    fn adopt(self: &Arc<Self>, bridge: &Arc<BleRadioBridge>, ch: u32, bridge_ch: i64) {
        if bridge_ch == 0 {
            self.command(Frame::Close { ch });
            return;
        }
        self.channels().insert(ch, bridge_ch);
        let link = Arc::clone(self);
        let pumped = Arc::clone(bridge);
        let spawned = std::thread::Builder::new()
            .name(format!("fips-ble-agent-ch-{bridge_ch}"))
            .spawn(move || link.pump(&pumped, ch, bridge_ch));
        if let Err(e) = spawned {
            warn!(error = %e, "BLE: could not start an agent channel pump");
            self.channels().remove_agent(ch);
            bridge.channel_closed(bridge_ch);
            self.command(Frame::Close { ch });
        }
    }

    /// Carry channel `bridge_ch`'s outbound bytes to the agent until it
    /// closes.
    fn pump(&self, bridge: &BleRadioBridge, ch: u32, bridge_ch: i64) {
        while self.alive.load(Ordering::Relaxed) {
            match bridge.next_send(bridge_ch, PUMP_IDLE_POLL) {
                Some(data) => {
                    if write_frame(&self.socket, &Frame::Send { ch, data }).is_err() {
                        bridge.channel_closed(bridge_ch);
                        return;
                    }
                }
                None if !bridge.channel_open(bridge_ch) => return,
                None => {}
            }
        }
    }
}

fn write_frame(socket: &Mutex<UnixStream>, frame: &Frame) -> io::Result<()> {
    socket
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .write_all(&frame.encode())
}

impl BleRadio for AgentLink {
    /// The PSM the agent's listener reported in its hello.
    fn listen(&self) -> u16 {
        self.psm
    }

    fn connect(&self, connect_id: i64, addr: &super::super::addr::BleAddr, psm: u16) {
        self.command(Frame::Connect {
            id: connect_id,
            addr: addr.clone(),
            psm,
        });
    }

    fn start_advertising(&self, psm: u16) {
        self.command(Frame::StartAdvertising { psm });
    }

    fn stop_advertising(&self) {
        self.command(Frame::StopAdvertising);
    }

    fn start_scanning(&self) {
        self.command(Frame::StartScanning);
    }

    fn stop_scanning(&self) {
        self.command(Frame::StopScanning);
    }

    fn close_channel(&self, ch_id: i64) {
        let agent_ch = self.channels().remove_bridge(ch_id);
        if let Some(ch) = agent_ch {
            self.command(Frame::Close { ch });
        }
    }
}

#[cfg(test)]
impl AgentServer {
    /// Serve agents on `listener` without the socket policy, for tests.
    pub(super) fn serve_for_test(
        slot: Arc<BleRadioSlot>,
        listener: UnixListener,
        path: &Path,
    ) -> Arc<Self> {
        Self::serve(slot, listener, path)
    }
}
