//! BlueZ backend for the BLE transport.
//!
//! The Linux implementation of the [`BleIo`](super::io::BleIo) seam, over the
//! `bluer` crate's D-Bus binding to BlueZ. Everything platform-neutral lives
//! in [`super::io`] and the modules beside it; this file holds only what
//! speaks to BlueZ.

use super::io::*;
use crate::transport::TransportError;

use bluer::l2cap::{SeqPacket, SeqPacketListener, Socket, SocketAddr};
use bluer::{AdapterEvent, AddressType, DiscoveryFilter, DiscoveryTransport, adv::Advertisement};
use futures::StreamExt;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::pin::Pin;
use tokio::sync::Mutex;
use tracing::{debug, trace};

use super::addr::BleAddr;
use super::psm;

/// FIPS BLE service UUID.
///
/// Derived from SHA-256("FIPS: welcome to cryptoanarchy") with UUID v4
/// version/variant bits applied.
pub const FIPS_SERVICE_UUID: bluer::Uuid =
    bluer::Uuid::from_u128(0x9c90_b790_2cc5_42c0_9f87_c9cc_4064_8f4c);

/// The PSM service-data key as a whole UUID.
///
/// BlueZ speaks in full UUIDs, so [`psm::PSM_SERVICE_DATA_UUID16`] is
/// expanded through the Bluetooth base UUID
/// (`00009C90-0000-1000-8000-00805F9B34FB`). The controller emits it
/// back on the air as the 16-bit Service Data AD structure the wire
/// layout in [`psm`] specifies.
pub const PSM_SERVICE_DATA_UUID: bluer::Uuid = bluer::Uuid::from_u128(
    ((psm::PSM_SERVICE_DATA_UUID16 as u128) << 96) | 0x0000_0000_0000_1000_8000_0080_5F9B_34FB,
);

/// Map a bluer error to a TransportError.
fn map_err(context: &str, e: bluer::Error) -> TransportError {
    TransportError::Io(std::io::Error::other(format!("{}: {}", context, e)))
}

/// Map a std::io::Error to a TransportError.
fn map_io_err(context: &str, e: std::io::Error) -> TransportError {
    TransportError::Io(std::io::Error::new(e.kind(), format!("{}: {}", context, e)))
}

// ----------------------------------------------------------------
// BluerStream
// ----------------------------------------------------------------

/// BLE stream wrapping a bluer L2CAP SeqPacket connection.
pub struct BluerStream {
    conn: SeqPacket,
    remote: BleAddr,
    send_mtu: u16,
    recv_mtu: u16,
}

impl BluerStream {
    /// Construct from a connected SeqPacket, querying MTU values.
    pub fn new(conn: SeqPacket, remote: BleAddr) -> Result<Self, TransportError> {
        let send_mtu = conn.send_mtu().map_err(|e| map_io_err("send_mtu", e))? as u16;
        let recv_mtu = conn.recv_mtu().map_err(|e| map_io_err("recv_mtu", e))? as u16;

        // Log negotiated PHY for diagnostics (2M vs 1M)
        match conn.as_ref().phy() {
            Ok(phy) => {
                debug!(addr = %remote, phy, send_mtu, recv_mtu, "BLE connection established")
            }
            Err(_) => {
                debug!(addr = %remote, send_mtu, recv_mtu, "BLE connection established (PHY query unsupported)")
            }
        }

        Ok(Self {
            conn,
            remote,
            send_mtu,
            recv_mtu,
        })
    }
}

impl BleStream for BluerStream {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        self.conn
            .send(data)
            .await
            .map(|_| ())
            .map_err(|e| TransportError::SendFailed(format!("{}", e)))
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.conn
            .recv(buf)
            .await
            .map_err(|e| TransportError::RecvFailed(format!("{}", e)))
    }

    fn send_mtu(&self) -> u16 {
        self.send_mtu
    }

    fn recv_mtu(&self) -> u16 {
        self.recv_mtu
    }

    fn remote_addr(&self) -> &BleAddr {
        &self.remote
    }
}

// ----------------------------------------------------------------
// BluerAcceptor
// ----------------------------------------------------------------

/// Acceptor wrapping a bluer L2CAP SeqPacketListener.
pub struct BluerAcceptor {
    listener: SeqPacketListener,
    adapter_name: String,
}

impl BleAcceptor for BluerAcceptor {
    type Stream = BluerStream;

    async fn accept(&mut self) -> Result<BluerStream, TransportError> {
        let (conn, peer_sa) = self
            .listener
            .accept()
            .await
            .map_err(|e| map_io_err("accept", e))?;

        let remote = BleAddr::from_bluer(peer_sa.addr, &self.adapter_name);
        BluerStream::new(conn, remote)
    }
}

// ----------------------------------------------------------------
// BluerScanner
// ----------------------------------------------------------------

/// Scanner wrapping a bluer discovery event stream.
pub struct BluerScanner {
    events: Pin<Box<dyn futures::Stream<Item = AdapterEvent> + Send>>,
    adapter: bluer::Adapter,
    adapter_name: String,
}

impl BleScanner for BluerScanner {
    /// Yields adverts with the PSM and RSSI when BlueZ can supply them.
    ///
    /// The PSM comes out of the peer's Service Data AD structure (see
    /// `super::super::psm`); a peer that advertises none — a legacy
    /// UUID-only advertiser — yields `psm: None` and is dialled at the
    /// configured PSM, exactly as before.
    async fn next(&mut self) -> Option<ScanAdvert> {
        loop {
            match self.events.next().await {
                Some(AdapterEvent::DeviceAdded(addr)) => {
                    // Check if device advertises FIPS UUID
                    if let Ok(device) = self.adapter.device(addr) {
                        match device.uuids().await {
                            Ok(Some(uuids)) if uuids.contains(&FIPS_SERVICE_UUID) => {
                                let ble_addr = BleAddr::from_bluer(addr, &self.adapter_name);
                                let psm =
                                    device.service_data().await.ok().flatten().and_then(|sd| {
                                        sd.get(&PSM_SERVICE_DATA_UUID)
                                            .and_then(|data| psm::decode_psm(data))
                                    });
                                let rssi = device.rssi().await.ok().flatten();
                                debug!(addr = %ble_addr, ?psm, ?rssi, "BLE scanner: FIPS peer found");
                                return Some(ScanAdvert {
                                    addr: ble_addr,
                                    psm,
                                    rssi,
                                });
                            }
                            Ok(_) => {
                                trace!(addr = %addr, "BLE scanner: device without FIPS UUID");
                            }
                            Err(e) => {
                                trace!(addr = %addr, error = %e, "BLE scanner: failed to read UUIDs");
                            }
                        }
                    }
                }
                Some(_) => continue,
                None => return None,
            }
        }
    }
}

// ----------------------------------------------------------------
// BluerIo
// ----------------------------------------------------------------

/// Production BLE I/O implementation via BlueZ D-Bus (bluer crate).
pub struct BluerIo {
    #[allow(dead_code)] // Session must be kept alive for the adapter.
    session: bluer::Session,
    adapter: bluer::Adapter,
    adapter_name: String,
    adv_handle: Mutex<Option<bluer::adv::AdvertisementHandle>>,
    mtu: u16,
}

impl BluerIo {
    /// Create a new BluerIo for the given adapter.
    ///
    /// Connects to BlueZ via D-Bus and powers on the adapter.
    pub async fn new(adapter_name: &str, mtu: u16) -> Result<Self, TransportError> {
        let session = bluer::Session::new()
            .await
            .map_err(|e| map_err("Session::new", e))?;

        let adapter = if adapter_name == "default" {
            session
                .default_adapter()
                .await
                .map_err(|e| map_err("default_adapter", e))?
        } else {
            session
                .adapter(adapter_name)
                .map_err(|e| map_err("adapter", e))?
        };

        adapter
            .set_powered(true)
            .await
            .map_err(|e| map_err("set_powered", e))?;

        let name = adapter.name().to_string();
        debug!(adapter = %name, "BluerIo initialized");

        Ok(Self {
            session,
            adapter,
            adapter_name: name,
            adv_handle: Mutex::new(None),
            mtu,
        })
    }
}

impl BleIo for BluerIo {
    type Stream = BluerStream;
    type Acceptor = BluerAcceptor;
    type Scanner = BluerScanner;

    /// Binds the requested PSM and reports it back unchanged.
    ///
    /// BlueZ lets an application choose the PSM it binds, so the bound
    /// PSM is always the requested one. Backends whose platform assigns
    /// the PSM report something else; that is the reason for the return
    /// value, not anything BlueZ does.
    async fn listen(&self, psm: u16) -> Result<(Self::Acceptor, u16), TransportError> {
        let local_addr = self
            .adapter
            .address()
            .await
            .map_err(|e| map_err("address", e))?;

        let sa = SocketAddr::new(local_addr, AddressType::LePublic, psm);
        let listener = SeqPacketListener::bind(sa)
            .await
            .map_err(|e| map_io_err("bind", e))?;

        // Request high MTU for accepted connections
        listener
            .as_ref()
            .set_recv_mtu(self.mtu)
            .map_err(|e| map_io_err("set_recv_mtu", e))?;

        // Prevent sniff mode to reduce latency during data transfer
        if let Err(e) = listener.as_ref().set_power_forced_active(true) {
            debug!(error = %e, "BLE listener: set_power_forced_active not supported");
        }

        debug!(psm, mtu = self.mtu, "BLE listener bound");

        Ok((
            BluerAcceptor {
                listener,
                adapter_name: self.adapter_name.clone(),
            },
            psm,
        ))
    }

    async fn connect(&self, addr: &BleAddr, psm: u16) -> Result<Self::Stream, TransportError> {
        let target_sa = addr.to_socket_addr(psm);

        let socket =
            Socket::<SeqPacket>::new_seq_packet().map_err(|e| map_io_err("new_seq_packet", e))?;
        socket
            .bind(SocketAddr::any_le())
            .map_err(|e| map_io_err("bind", e))?;
        socket
            .set_recv_mtu(self.mtu)
            .map_err(|e| map_io_err("set_recv_mtu", e))?;

        // Prevent sniff mode to reduce latency during data transfer
        if let Err(e) = socket.set_power_forced_active(true) {
            debug!(error = %e, "BLE connect: set_power_forced_active not supported");
        }

        let conn = socket
            .connect(target_sa)
            .await
            .map_err(|e| map_io_err("connect", e))?;

        let remote = addr.clone();
        BluerStream::new(conn, remote)
    }

    /// Advertises the FIPS service UUID and the listener PSM.
    ///
    /// The PSM rides the Service Data AD structure specified in
    /// `super::super::psm`. Emitting it costs the `local_name`: flags
    /// (3) + 128-bit UUID list (18) + service data (6) fill 27 of the
    /// 31-byte legacy PDU, and a name no longer fits. Peers that read
    /// the service data dial the advertised PSM; legacy peers keep
    /// dialling their configured one, which BlueZ listeners still bind.
    ///
    /// `super::super::psm` requires the PSM to ride the primary
    /// advertisement, never the scan response, so a passive scanner
    /// still sees it. Nothing here enforces that: BlueZ takes a set of
    /// AD structures and chooses their placement itself. What keeps the
    /// requirement holding is the arithmetic above — 27 of 31 bytes
    /// used, so BlueZ has no reason to spill into the scan response —
    /// and dropping the name is what makes it hold.
    async fn start_advertising(&self, psm: u16) -> Result<(), TransportError> {
        let adv = Advertisement {
            advertisement_type: bluer::adv::Type::Peripheral,
            service_uuids: {
                let mut s = BTreeSet::new();
                s.insert(FIPS_SERVICE_UUID);
                s
            },
            service_data: {
                let mut m = BTreeMap::new();
                m.insert(PSM_SERVICE_DATA_UUID, psm::encode_psm(psm).to_vec());
                m
            },
            min_interval: Some(std::time::Duration::from_millis(400)),
            max_interval: Some(std::time::Duration::from_millis(600)),
            ..Default::default()
        };

        let handle = self
            .adapter
            .advertise(adv)
            .await
            .map_err(|e| map_err("advertise", e))?;

        *self.adv_handle.lock().await = Some(handle);
        debug!(psm, "BLE advertising started");
        Ok(())
    }

    async fn stop_advertising(&self) -> Result<(), TransportError> {
        let _ = self.adv_handle.lock().await.take();
        debug!("BLE advertising stopped");
        Ok(())
    }

    /// A no-op: BlueZ discovery ends when [`BluerScanner`]'s event stream is
    /// dropped, which happens when the transport drops the scanner. There is
    /// no separate adapter-level stop to issue.
    async fn stop_scanning(&self) -> Result<(), TransportError> {
        debug!("BLE scanning stops with the scanner");
        Ok(())
    }

    async fn start_scanning(&self) -> Result<Self::Scanner, TransportError> {
        // Clear cached devices so BlueZ fires DeviceAdded for every
        // advertisement. Without this, already-known devices only
        // produce PropertyChanged events (which bluer doesn't expose
        // at the device level), causing the scanner to miss peers
        // after a daemon restart.
        if let Ok(cached) = self.adapter.device_addresses().await {
            let count = cached.len();
            for addr in cached {
                let _ = self.adapter.remove_device(addr).await;
            }
            if count > 0 {
                debug!(count, "BLE scanner: cleared cached devices");
            }
        }

        // Set discovery filter for LE transport with FIPS UUID
        let filter = DiscoveryFilter {
            transport: DiscoveryTransport::Le,
            uuids: {
                let mut s = HashSet::new();
                s.insert(FIPS_SERVICE_UUID);
                s
            },
            ..Default::default()
        };

        self.adapter
            .set_discovery_filter(filter)
            .await
            .map_err(|e| map_err("set_discovery_filter", e))?;

        let events = self
            .adapter
            .discover_devices()
            .await
            .map_err(|e| map_err("discover_devices", e))?;

        debug!("BLE scanning started");

        Ok(BluerScanner {
            events: Box::pin(events),
            adapter: self.adapter.clone(),
            adapter_name: self.adapter_name.clone(),
        })
    }

    fn local_addr(&self) -> Result<BleAddr, TransportError> {
        // Use futures::executor::block_on since this is a sync method
        // but needs an async call. The adapter address is cached so
        // the D-Bus call is fast.
        let addr = futures::executor::block_on(self.adapter.address())
            .map_err(|e| map_err("address", e))?;
        Ok(BleAddr::from_bluer(addr, &self.adapter_name))
    }

    fn adapter_name(&self) -> &str {
        &self.adapter_name
    }
}

// Compile-time assertion that BluerIo satisfies Send + Sync.
#[allow(dead_code)]
fn _assert_bluer_io_send_sync() {
    fn require<T: Send + Sync>() {}
    require::<BluerIo>();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wrong shift in the base-UUID expansion would yield a plausible
    /// UUID that simply never matches any peer — silent discovery
    /// failure, not a build error. Companion to psm.rs's
    /// `test_key_is_the_leading_16_bits_of_the_fips_uuid`.
    #[test]
    fn psm_service_data_uuid_expands_the_key_over_the_base_uuid() {
        assert_eq!(
            PSM_SERVICE_DATA_UUID,
            "00009C90-0000-1000-8000-00805F9B34FB"
                .parse::<bluer::Uuid>()
                .unwrap()
        );
    }
}
