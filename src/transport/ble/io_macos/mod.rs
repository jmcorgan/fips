//! CoreBluetooth backend for the BLE transport.
//!
//! macOS has no BlueZ, but unlike Android its radio *is* reachable from Rust:
//! CoreBluetooth, through `objc2`. It is delegate-driven, though — every
//! outcome arrives later as a callback — and an L2CAP channel's bytes move
//! through Foundation streams. That is exactly the shape [`super::io_radio`]
//! already adapts for the Android embedder, so this backend does not
//! implement [`BleIo`](super::io::BleIo) itself. It plays the embedder's part
//! in process: [`corebluetooth::MacRadio`] implements
//! [`BleRadio`](super::io_radio::BleRadio), installs a bridge into a
//! [`BleRadioSlot`](super::io_radio::BleRadioSlot) whenever Bluetooth comes
//! up, and the transport runs over [`RadioIo`](super::io_radio::RadioIo).
//! A Bluetooth toggle is then the radio-replaced case the slot was built for.
//!
//! # No main run loop
//!
//! Both managers deliver their delegate callbacks on a private serial
//! dispatch queue, and channel bytes are pumped by two plain threads per
//! channel doing blocking stream I/O — the same reader/writer model the
//! Android embedder runs. Nothing is scheduled on a run loop, so the daemon
//! does not have to give its main thread to `CFRunLoopRun()`.
//!
//! # What lives where
//!
//! This file is platform-neutral and compiled under `cfg(test)` on every
//! host: the dial's PSM decision, peer address mapping, advert throttling and
//! the stream pumps. Only [`corebluetooth`] speaks Objective-C, and it holds
//! as little logic as it can.
//!
//! # Platform constraints
//!
//! - **PSM.** The listener's PSM is assigned by the OS and cannot be put in
//!   the advert, so a Mac also serves it over GATT and reads a Mac peer's PSM
//!   the same way. See the GATT section of [`super::psm`].
//! - **Addressing.** CoreBluetooth hides link addresses and names each peer
//!   by a per-host identifier instead. [`peer_addr`] maps that onto the six
//!   bytes a [`BleAddr`] carries. The identifier for a peer we dial may differ
//!   from the one it presents when it dials us, and address rotation can mint
//!   a new one; duplicate links are settled by node address above this layer,
//!   so both are tolerated. A configured static peer (`hci0/AA:…`) cannot be
//!   dialled from a Mac — only a scan-discovered one.

#[cfg(target_os = "macos")]
pub mod corebluetooth;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::addr::BleAddr;
use super::io_radio::{BleRadioBridge, RADIO_ADAPTER};
use super::psm;

/// The FIPS service UUID, in the string form CoreBluetooth parses.
///
/// The same UUID `io_linux` advertises and filters on.
pub const FIPS_SERVICE_UUID: &str = "9C90B790-2CC5-42C0-9F87-C9CC40648F4C";

/// The Bluetooth base UUID's trailing 96 bits, for recognising a 16-bit UUID
/// that arrives expanded to 128.
const BASE_UUID_TAIL: [u8; 12] = [
    0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
];

/// The 16-bit form of a UUID given as CoreBluetooth's big-endian bytes, if it
/// has one.
///
/// CoreBluetooth reports a base-range UUID as its 2-byte short form, but
/// nothing promises it will not hand back the 16-byte expansion; both are
/// recognised. Anything else is not a 16-bit UUID.
pub fn uuid16(bytes: &[u8]) -> Option<u16> {
    match bytes.len() {
        2 => Some(u16::from_be_bytes([bytes[0], bytes[1]])),
        16 if bytes[..2] == [0, 0] && bytes[4..] == BASE_UUID_TAIL => {
            Some(u16::from_be_bytes([bytes[2], bytes[3]]))
        }
        _ => None,
    }
}

/// Whether a service-data key, as CoreBluetooth's bytes, is the one the PSM
/// is advertised under.
pub fn is_psm_service_data_key(bytes: &[u8]) -> bool {
    uuid16(bytes) == Some(psm::PSM_SERVICE_DATA_UUID16)
}

/// The link address this transport uses for a CoreBluetooth peer.
///
/// A stable function of the peer's identifier, so the same peer maps to the
/// same address across scans and across daemon restarts — which the probe
/// cooldown and the learned-PSM map both key on. The sixteen identifier bytes
/// are hashed (64-bit FNV-1a) down to six, and the result is marked locally
/// administered and unicast, so it can never collide with a real public MAC
/// that another backend reports.
pub fn peer_addr(identifier: [u8; 16]) -> BleAddr {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let hash = identifier.iter().fold(FNV_OFFSET, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(FNV_PRIME)
    });
    let mut device = [0u8; 6];
    device.copy_from_slice(&hash.to_be_bytes()[..6]);
    device[0] = (device[0] | 0x02) & !0x01;
    BleAddr {
        adapter: RADIO_ADAPTER.to_string(),
        device,
    }
}

/// Parse a UUID in its canonical string form into its sixteen bytes.
pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let hex: Vec<u8> = s.bytes().filter(|&b| b != b'-').collect();
    if hex.len() != 32 || s.len() != 36 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in hex.chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

// ============================================================================
// Dial PSM decision
// ============================================================================

/// The next thing a dial does once its peer is connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialStep {
    /// Discover the FIPS GATT service.
    DiscoverService,
    /// Discover the PSM characteristic in it.
    DiscoverCharacteristic,
    /// Read the PSM characteristic.
    ReadPsm,
    /// Open the L2CAP channel on this PSM.
    Open(u16),
}

/// Which PSM a dial ends up on, decided one GATT step at a time.
///
/// `requested` is what the transport asked for: the PSM the peer advertised,
/// or the configured fallback when it advertised none. A peer that advertised
/// a PSM is dialled there directly. One that did not is asked over GATT
/// (see [`super::psm`]), and every way that can fail — no FIPS service, no
/// characteristic, a failed or malformed read — ends on `requested`, which
/// is what a legacy UUID-only advertiser such as an older BlueZ peer listens
/// on.
#[derive(Debug, Clone, Copy)]
pub struct DialPlan {
    requested: u16,
    advertised: Option<u16>,
}

impl DialPlan {
    /// Plan a dial at `requested` to a peer whose latest advert carried
    /// `advertised`.
    pub fn new(requested: u16, advertised: Option<u16>) -> Self {
        Self {
            requested,
            advertised,
        }
    }

    /// The PSM the transport asked for.
    pub fn requested(&self) -> u16 {
        self.requested
    }

    /// The peer is connected.
    pub fn on_connected(&self) -> DialStep {
        match self.advertised {
            Some(_) => DialStep::Open(self.requested),
            None => DialStep::DiscoverService,
        }
    }

    /// Service discovery finished; `found` is whether the FIPS service is
    /// among the results.
    pub fn on_service(&self, found: bool) -> DialStep {
        if found {
            DialStep::DiscoverCharacteristic
        } else {
            DialStep::Open(self.requested)
        }
    }

    /// Characteristic discovery finished; `found` is whether the PSM
    /// characteristic is among the results.
    pub fn on_characteristic(&self, found: bool) -> DialStep {
        if found {
            DialStep::ReadPsm
        } else {
            DialStep::Open(self.requested)
        }
    }

    /// The read finished; `value` is what was read, `None` if it failed.
    pub fn on_psm_read(&self, value: Option<&[u8]>) -> DialStep {
        DialStep::Open(
            value
                .and_then(psm::decode_gatt_psm)
                .unwrap_or(self.requested),
        )
    }
}

// ============================================================================
// Advert throttling
// ============================================================================

/// How often one peer's adverts are passed on when nothing in them changed.
pub const ADVERT_REPORT_INTERVAL: Duration = Duration::from_secs(1);

/// Entries beyond this prompt a sweep of ones not heard from in a while.
const THROTTLE_SWEEP_THRESHOLD: usize = 256;

/// Rate-limits the adverts passed up to the transport.
///
/// The scan runs with duplicates allowed, so a peer that restarts with a new
/// PSM is heard the moment it re-advertises rather than never: without
/// duplicates CoreBluetooth reports each peer once per scan. That is several
/// reports per peer per second, and the transport needs one. An advert whose
/// PSM differs from the last one passed on goes straight through.
pub struct AdvertThrottle {
    interval: Duration,
    last: HashMap<BleAddr, (Instant, Option<u16>)>,
}

impl AdvertThrottle {
    /// A throttle passing each unchanged peer at most once per `interval`.
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: HashMap::new(),
        }
    }

    /// Whether to pass on an advert from `addr` carrying `psm`, seen at `now`.
    pub fn admit(&mut self, addr: &BleAddr, psm: Option<u16>, now: Instant) -> bool {
        if let Some(&(at, last_psm)) = self.last.get(addr)
            && last_psm == psm
            && now.saturating_duration_since(at) < self.interval
        {
            return false;
        }
        if self.last.len() >= THROTTLE_SWEEP_THRESHOLD {
            // Rotating private addresses mint a new entry per rotation; drop
            // the ones that have gone quiet.
            let horizon = self.interval * 60;
            self.last
                .retain(|_, (at, _)| now.saturating_duration_since(*at) < horizon);
        }
        self.last.insert(addr.clone(), (now, psm));
        true
    }
}

// ============================================================================
// Stream pumps
// ============================================================================

/// How long the writer waits for an outbound packet before checking whether
/// its channel has closed.
const WRITER_IDLE_POLL: Duration = Duration::from_millis(100);

/// The reading half of a platform channel, read on a dedicated thread.
pub trait ChannelRead: Send + 'static {
    /// Block until bytes arrive and read some into `buf`. `Ok(0)` is the end
    /// of the stream.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

/// The writing half of a platform channel, written on a dedicated thread.
pub trait ChannelWrite: Send + 'static {
    /// Block until some of `data` is written, and report how much.
    fn write(&mut self, data: &[u8]) -> io::Result<usize>;
}

/// Start the reader and writer threads for channel `ch_id`.
///
/// The reader pushes whatever the platform stream yields into the bridge,
/// waiting for room rather than dropping (see
/// [`BleRadioBridge::deliver_recv_blocking`]), and reports the channel closed
/// when the stream ends. The writer pulls outbound packets and writes each
/// one whole, since a byte stream may accept less than it was offered; it
/// exits once the bridge says the channel is closed. Neither thread closes
/// the platform stream: whoever owns the channel does that, which is also
/// what unblocks a reader parked in `read`.
pub fn spawn_pumps<R: ChannelRead, W: ChannelWrite>(
    bridge: Arc<BleRadioBridge>,
    ch_id: i64,
    mut reader: R,
    mut writer: W,
    read_chunk: usize,
) -> io::Result<()> {
    let rx_bridge = Arc::clone(&bridge);
    std::thread::Builder::new()
        .name(format!("fips-ble-rx-{ch_id}"))
        .spawn(move || {
            let mut buf = vec![0u8; read_chunk.max(1)];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if !rx_bridge.deliver_recv_blocking(ch_id, &buf[..n]) {
                            break;
                        }
                    }
                }
            }
            rx_bridge.channel_closed(ch_id);
        })?;
    std::thread::Builder::new()
        .name(format!("fips-ble-tx-{ch_id}"))
        .spawn(move || {
            loop {
                match bridge.next_send(ch_id, WRITER_IDLE_POLL) {
                    Some(packet) => {
                        if write_all(&mut writer, &packet).is_err() {
                            bridge.channel_closed(ch_id);
                            break;
                        }
                    }
                    None => {
                        if !bridge.channel_open(ch_id) {
                            break;
                        }
                    }
                }
            }
        })?;
    Ok(())
}

/// Write all of `data`, however many writes that takes.
fn write_all<W: ChannelWrite>(writer: &mut W, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        match writer.write(data)? {
            0 => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            n => data = &data[n..],
        }
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ble::io::{BleAcceptor, BleIo, BleStream};
    use crate::transport::ble::io_radio::{BleRadio, BleRadioSlot, RadioIo};
    use std::sync::Mutex;
    use std::sync::mpsc;

    // --- address mapping -------------------------------------------------

    #[test]
    fn a_peer_maps_to_the_same_address_every_time() {
        let id = *b"\x12\x34\x56\x78\x9a\xbc\xde\xf0\x0f\xed\xcb\xa9\x87\x65\x43\x21";
        assert_eq!(peer_addr(id), peer_addr(id));
        assert_eq!(peer_addr(id).adapter, RADIO_ADAPTER);
    }

    /// Pinned, because the mapping must not drift between releases: after an
    /// upgrade every peer would reappear under a new address, and the
    /// learned-PSM and cooldown state keyed on the old one would be lost.
    #[test]
    fn the_mapping_is_pinned() {
        let id: [u8; 16] = std::array::from_fn(|i| i as u8);
        assert_eq!(peer_addr(id).device, [0x7E, 0x84, 0xDC, 0x94, 0x77, 0x85]);
    }

    #[test]
    fn a_uuid_string_parses_to_its_bytes() {
        assert_eq!(
            parse_uuid("00010203-0405-0607-0809-0A0B0C0D0E0F"),
            Some(std::array::from_fn(|i| i as u8))
        );
        assert_eq!(
            parse_uuid(&FIPS_SERVICE_UUID.to_lowercase()).map(u128::from_be_bytes),
            Some(0x9c90_b790_2cc5_42c0_9f87_c9cc_4064_8f4c)
        );
    }

    #[test]
    fn a_malformed_uuid_string_does_not_parse() {
        assert_eq!(parse_uuid(""), None);
        assert_eq!(parse_uuid("00010203-0405-0607-0809-0A0B0C0D0E"), None);
        assert_eq!(parse_uuid("000102030405060708090A0B0C0D0E0F"), None);
        assert_eq!(parse_uuid("0G010203-0405-0607-0809-0A0B0C0D0E0F"), None);
    }

    #[test]
    fn distinct_peers_map_to_distinct_addresses() {
        let a = peer_addr([1; 16]);
        let mut other = [1; 16];
        other[15] = 2;
        assert_ne!(a, peer_addr(other));
    }

    #[test]
    fn a_mapped_address_is_locally_administered_unicast() {
        for seed in [0u8, 1, 0x55, 0xFF] {
            let device = peer_addr([seed; 16]).device;
            assert_eq!(device[0] & 0x02, 0x02, "locally administered");
            assert_eq!(device[0] & 0x01, 0x00, "unicast");
        }
    }

    // --- UUID handling ---------------------------------------------------

    #[test]
    fn the_psm_key_is_recognised_in_short_and_expanded_form() {
        assert!(is_psm_service_data_key(&[0x9C, 0x90]));
        let mut expanded = [0u8; 16];
        expanded[2..4].copy_from_slice(&[0x9C, 0x90]);
        expanded[4..].copy_from_slice(&BASE_UUID_TAIL);
        assert!(is_psm_service_data_key(&expanded));
    }

    #[test]
    fn other_uuids_are_not_the_psm_key() {
        assert!(
            !is_psm_service_data_key(&[0x90, 0x9C]),
            "byte order matters"
        );
        assert!(!is_psm_service_data_key(&[0x18, 0x0F]));
        // The FIPS service UUID itself starts 9C90 but is not base-range.
        let fips: Vec<u8> = (0..16)
            .map(|i| {
                u8::from_str_radix(&FIPS_SERVICE_UUID.replace('-', "")[i * 2..i * 2 + 2], 16)
                    .unwrap()
            })
            .collect();
        assert!(!is_psm_service_data_key(&fips));
        assert!(!is_psm_service_data_key(&[0x9C]));
    }

    #[test]
    fn the_service_uuid_matches_the_one_bluez_advertises() {
        assert_eq!(
            u128::from_str_radix(&FIPS_SERVICE_UUID.replace('-', ""), 16).unwrap(),
            0x9c90_b790_2cc5_42c0_9f87_c9cc_4064_8f4c
        );
    }

    // --- dial PSM decision -----------------------------------------------

    /// A peer that advertised its PSM is dialled straight away, with no GATT
    /// round trip.
    #[test]
    fn an_advertised_psm_skips_gatt() {
        let plan = DialPlan::new(0x00C1, Some(0x00C1));
        assert_eq!(plan.on_connected(), DialStep::Open(0x00C1));
    }

    /// The transport may have forgotten a refused advertised PSM and fallen
    /// back; what it asks for is what is dialled.
    #[test]
    fn an_advertised_psm_still_dials_what_the_transport_asked_for() {
        let plan = DialPlan::new(0x0085, Some(0x00C1));
        assert_eq!(plan.on_connected(), DialStep::Open(0x0085));
    }

    /// The Mac ↔ Mac path: no PSM in the advert, so it is read over GATT and
    /// the read value wins over the requested fallback.
    #[test]
    fn no_advertised_psm_reads_it_over_gatt() {
        let plan = DialPlan::new(0x0085, None);
        assert_eq!(plan.on_connected(), DialStep::DiscoverService);
        assert_eq!(plan.on_service(true), DialStep::DiscoverCharacteristic);
        assert_eq!(plan.on_characteristic(true), DialStep::ReadPsm);
        assert_eq!(
            plan.on_psm_read(Some(&psm::encode_psm(0x00C3))),
            DialStep::Open(0x00C3)
        );
    }

    /// A legacy UUID-only advertiser serves no FIPS GATT service.
    #[test]
    fn a_peer_without_the_service_is_dialled_at_the_requested_psm() {
        let plan = DialPlan::new(0x0085, None);
        assert_eq!(plan.on_service(false), DialStep::Open(0x0085));
    }

    #[test]
    fn a_service_without_the_characteristic_falls_back() {
        let plan = DialPlan::new(0x0085, None);
        assert_eq!(plan.on_characteristic(false), DialStep::Open(0x0085));
    }

    #[test]
    fn a_failed_read_falls_back() {
        let plan = DialPlan::new(0x0085, None);
        assert_eq!(plan.on_psm_read(None), DialStep::Open(0x0085));
    }

    #[test]
    fn a_malformed_or_zero_read_falls_back() {
        let plan = DialPlan::new(0x0085, None);
        assert_eq!(plan.on_psm_read(Some(&[0xC3])), DialStep::Open(0x0085));
        assert_eq!(plan.on_psm_read(Some(&[0, 0])), DialStep::Open(0x0085));
    }

    // --- advert throttling -----------------------------------------------

    #[test]
    fn an_unchanged_advert_is_passed_once_per_interval() {
        let mut t = AdvertThrottle::new(Duration::from_secs(1));
        let a = peer_addr([7; 16]);
        let t0 = Instant::now();
        assert!(t.admit(&a, Some(0x00C1), t0));
        assert!(!t.admit(&a, Some(0x00C1), t0 + Duration::from_millis(500)));
        assert!(t.admit(&a, Some(0x00C1), t0 + Duration::from_millis(1000)));
    }

    /// A restarted peer re-advertises on a new PSM. Holding that back for the
    /// rest of the interval would have the transport dial the dead one.
    #[test]
    fn a_changed_psm_is_passed_at_once() {
        let mut t = AdvertThrottle::new(Duration::from_secs(1));
        let a = peer_addr([7; 16]);
        let t0 = Instant::now();
        assert!(t.admit(&a, Some(0x00C1), t0));
        assert!(t.admit(&a, Some(0x00C5), t0 + Duration::from_millis(10)));
        assert!(t.admit(&a, None, t0 + Duration::from_millis(20)));
    }

    #[test]
    fn peers_are_throttled_independently() {
        let mut t = AdvertThrottle::new(Duration::from_secs(1));
        let t0 = Instant::now();
        assert!(t.admit(&peer_addr([1; 16]), None, t0));
        assert!(t.admit(&peer_addr([2; 16]), None, t0));
    }

    #[test]
    fn quiet_peers_are_swept() {
        let mut t = AdvertThrottle::new(Duration::from_secs(1));
        let t0 = Instant::now();
        for i in 0..THROTTLE_SWEEP_THRESHOLD {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            t.admit(&peer_addr(id), None, t0);
        }
        t.admit(&peer_addr([0xEE; 16]), None, t0 + Duration::from_secs(3600));
        assert_eq!(t.last.len(), 1);
    }

    // --- stream pumps ----------------------------------------------------

    /// A radio that does nothing; the pumps only touch the bridge.
    struct IdleRadio;

    impl BleRadio for IdleRadio {
        fn listen(&self) -> u16 {
            0x00C1
        }
        fn connect(&self, _: i64, _: &BleAddr, _: u16) {}
        fn start_advertising(&self, _: u16) {}
        fn stop_advertising(&self) {}
        fn start_scanning(&self) {}
        fn stop_scanning(&self) {}
        fn close_channel(&self, _: i64) {}
    }

    /// Reads chunks fed by the test; the end of the feed is end of stream.
    struct FedReader(mpsc::Receiver<Vec<u8>>);

    impl ChannelRead for FedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.recv() {
                Ok(chunk) => {
                    buf[..chunk.len()].copy_from_slice(&chunk);
                    Ok(chunk.len())
                }
                Err(_) => Ok(0),
            }
        }
    }

    /// Accepts at most `per_write` bytes per call, like a byte stream with
    /// little room, and records what it was given.
    struct ShortWriter {
        per_write: usize,
        out: Arc<Mutex<Vec<u8>>>,
    }

    impl ChannelWrite for ShortWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let n = data.len().min(self.per_write);
            self.out.lock().unwrap().extend_from_slice(&data[..n]);
            Ok(n)
        }
    }

    async fn accepted_channel() -> (
        Arc<BleRadioBridge>,
        i64,
        crate::transport::ble::io_radio::RadioStream,
    ) {
        let bridge = BleRadioBridge::new(Arc::new(IdleRadio));
        let slot = Arc::new(BleRadioSlot::new());
        slot.install(Arc::clone(&bridge));
        let io = RadioIo::new(slot);
        let (mut acceptor, _) = io.listen(0x0085).await.unwrap();
        let ch_id = bridge.deliver_inbound(peer_addr([3; 16]), 512, 512);
        let stream = acceptor.accept().await.unwrap();
        (bridge, ch_id, stream)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pumps_carry_bytes_both_ways_and_write_short_writes_whole() {
        let (bridge, ch_id, stream) = accepted_channel().await;
        let (feed, rx) = mpsc::channel();
        let out = Arc::new(Mutex::new(Vec::new()));
        spawn_pumps(
            Arc::clone(&bridge),
            ch_id,
            FedReader(rx),
            ShortWriter {
                per_write: 3,
                out: Arc::clone(&out),
            },
            512,
        )
        .unwrap();

        feed.send(b"inbound".to_vec()).unwrap();
        let mut buf = [0u8; 64];
        let n = stream.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"inbound");

        stream.send(b"outbound bytes").await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while out.lock().unwrap().len() < 14 {
            assert!(Instant::now() < deadline, "writer never finished");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(out.lock().unwrap().as_slice(), b"outbound bytes");
    }

    /// The platform stream ending is the peer closing: the transport must see
    /// end of stream, not a link that has merely gone quiet.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_stream_ending_reads_as_end_of_stream() {
        let (bridge, ch_id, stream) = accepted_channel().await;
        let (feed, rx) = mpsc::channel::<Vec<u8>>();
        spawn_pumps(
            Arc::clone(&bridge),
            ch_id,
            FedReader(rx),
            ShortWriter {
                per_write: 64,
                out: Arc::default(),
            },
            512,
        )
        .unwrap();

        drop(feed);
        let mut buf = [0u8; 8];
        assert_eq!(stream.recv(&mut buf).await.unwrap(), 0);
        assert!(!bridge.channel_open(ch_id));
    }

    /// Dropping the stream must stop the writer rather than leave it polling
    /// a dead channel for the life of the process.
    #[tokio::test(flavor = "multi_thread")]
    async fn dropping_the_stream_stops_the_writer() {
        let (bridge, ch_id, stream) = accepted_channel().await;
        let (_feed, rx) = mpsc::channel::<Vec<u8>>();
        spawn_pumps(
            Arc::clone(&bridge),
            ch_id,
            FedReader(rx),
            ShortWriter {
                per_write: 64,
                out: Arc::default(),
            },
            512,
        )
        .unwrap();

        drop(stream);
        let deadline = Instant::now() + Duration::from_secs(5);
        // The writer holds the bridge; once it exits only the test's own
        // handle and the reader's remain.
        while Arc::strong_count(&bridge) > 2 {
            assert!(Instant::now() < deadline, "writer still running");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// A writer that cannot make progress fails the channel instead of
    /// spinning on it.
    #[test]
    fn a_zero_length_write_is_an_error() {
        struct Stuck;
        impl ChannelWrite for Stuck {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Ok(0)
            }
        }
        assert_eq!(
            write_all(&mut Stuck, b"x").unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
    }
}
