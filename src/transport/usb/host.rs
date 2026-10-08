//! The USB host side: find phones, switch them into Android Open Accessory
//! mode, and turn each accessory into a [`UsbLink`].
//!
//! Runs where this node can be USB host — a desktop, or a phone holding the
//! host role of a USB-C cable — over [`nusb`]. The phone needs nothing but an
//! app that answers the accessory: AOA is driven entirely from this side with
//! vendor control requests on the default endpoint, and the phone re-appears
//! on the bus as a Google accessory device (`18d1:2d00`–`2d05`) with one
//! vendor interface carrying a bulk IN and a bulk OUT endpoint.
//!
//! ## Which devices are asked
//!
//! Only devices that look like a phone: one exposing an MTP or PTP interface
//! (still-image class, or Android's vendor-class MTP interface) or adb. An
//! Android phone exposes one of these in every USB mode, "No data transfer"
//! included, while keyboards, hubs, disks and serial adapters do not, so
//! nothing else is sent vendor requests it never asked for. A device that
//! does not answer the AOA protocol query is left alone until it is next
//! plugged in.
//!
//! ## Zero-length packets
//!
//! The phone reads the accessory in 16 KiB buffers, and a read completes on a
//! full buffer or a short packet. A transfer that is an exact multiple of the
//! packet size but shorter than the buffer ends on neither, so it is followed
//! by a zero-length packet. A full 16 KiB transfer is not: it fills the
//! buffer, and a zero-length packet after it would surface on the phone as an
//! empty read.

#[cfg(not(target_os = "android"))]
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(target_os = "android"))]
use futures::StreamExt;
use nusb::descriptors::TransferType;
#[cfg(not(target_os = "android"))]
use nusb::hotplug::HotplugEvent;
use nusb::transfer::{
    Buffer, Bulk, ControlIn, ControlOut, ControlType, Direction, In, Out, Recipient,
};
#[cfg(not(target_os = "android"))]
use nusb::{DeviceId, DeviceInfo};
use tokio::sync::mpsc;
#[cfg(not(target_os = "android"))]
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use super::link::{USB_TRANSFER_MAX, UsbLink, UsbLinkQueue, gather};

/// Google's vendor id, which every device in accessory mode presents.
const AOA_VID: u16 = 0x18d1;

/// Accessory-mode product ids: accessory, with adb, and the audio variants.
const AOA_PIDS: std::ops::RangeInclusive<u16> = 0x2d00..=0x2d05;

/// AOA vendor requests.
const AOA_GET_PROTOCOL: u8 = 51;
const AOA_SEND_STRING: u8 = 52;
const AOA_START: u8 = 53;

/// The identity this host announces. An app accepts the accessory by
/// matching manufacturer and model in its accessory filter, so these are
/// fixed for every FIPS host: any FIPS node can link with any FIPS app.
pub const AOA_MANUFACTURER: &str = "FIPS";
/// See [`AOA_MANUFACTURER`].
pub const AOA_MODEL: &str = "fips-link";
const AOA_DESCRIPTION: &str = "FIPS mesh link";
const AOA_VERSION: &str = "1";
const AOA_SERIAL: &str = "fips";

/// Timeout for each AOA control request. A phone answers in milliseconds.
const CONTROL_TIMEOUT: Duration = Duration::from_millis(1000);

/// Bulk IN transfers kept queued, so the phone never waits on this side to
/// ask for the next one.
const IN_FLIGHT: usize = 4;

/// Bulk OUT transfers allowed in flight before the writer waits.
const OUT_IN_FLIGHT: usize = 2;

/// Link queue depth between the pumps and the transport.
const PUMP_QUEUE_DEPTH: usize = 8;

#[cfg(not(target_os = "android"))]
/// Watch the bus for phones and accessories until the task is aborted,
/// queueing a link for every accessory that comes up.
///
/// `uri` is announced in the AOA handshake: a phone with no app that accepts
/// the accessory offers it to the user, so it should say where to get one.
pub(crate) async fn run(links: Arc<UsbLinkQueue>, uri: String) {
    // Watch before listing, so a device plugged in between the two is seen.
    let mut watch = match nusb::watch_devices() {
        Ok(watch) => watch,
        Err(e) => {
            warn!(error = %e, "USB host: cannot watch for devices; host role disabled");
            return;
        }
    };
    let mut tasks = JoinSet::new();
    // Devices already handled since they were plugged in: being switched,
    // linked, or found not to speak AOA. Forgotten when they go away.
    let mut handled: HashSet<DeviceId> = HashSet::new();

    match nusb::list_devices().await {
        Ok(devices) => {
            for device in devices {
                consider(device, &mut handled, &mut tasks, &links, &uri);
            }
        }
        Err(e) => warn!(error = %e, "USB host: cannot list devices"),
    }
    info!("USB host: watching for phones");

    loop {
        tokio::select! {
            event = watch.next() => match event {
                Some(HotplugEvent::Connected(device)) => {
                    consider(device, &mut handled, &mut tasks, &links, &uri);
                }
                Some(HotplugEvent::Disconnected(id)) => {
                    handled.remove(&id);
                }
                None => break,
            },
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

#[cfg(not(target_os = "android"))]
/// Act on a device: open it as a link if it is an accessory, ask it to
/// become one if it looks like a phone, otherwise nothing.
fn consider(
    device: DeviceInfo,
    handled: &mut HashSet<DeviceId>,
    tasks: &mut JoinSet<()>,
    links: &Arc<UsbLinkQueue>,
    uri: &str,
) {
    if handled.contains(&device.id()) {
        return;
    }
    if is_accessory(&device) {
        handled.insert(device.id());
        let links = Arc::clone(links);
        tasks.spawn(async move {
            let label = label_of(&device);
            match open_accessory(&device, &label).await {
                Ok(link) => {
                    info!(link = %label, "USB host: accessory opened");
                    links.push(link);
                }
                Err(e) => warn!(link = %label, error = %e, "USB host: cannot open accessory"),
            }
        });
    } else if looks_like_phone(&device) {
        handled.insert(device.id());
        let uri = uri.to_string();
        tasks.spawn(async move {
            let label = label_of(&device);
            match switch_to_accessory(&device, &uri).await {
                Ok(true) => {
                    debug!(device = %label, "USB host: asked device to become an accessory")
                }
                Ok(false) => debug!(device = %label, "USB host: device does not speak AOA"),
                Err(e) => debug!(device = %label, error = %e, "USB host: AOA switch failed"),
            }
        });
    }
}

#[cfg(not(target_os = "android"))]
fn is_accessory(device: &DeviceInfo) -> bool {
    device.vendor_id() == AOA_VID && AOA_PIDS.contains(&device.product_id())
}

#[cfg(not(target_os = "android"))]
/// Whether `device` exposes an interface only a phone-like device has: MTP
/// or PTP (still-image class, or Android's vendor-class MTP interface) or
/// adb. A vendor-class interface with protocol `ff` — a serial adapter's,
/// typically — does not count.
fn looks_like_phone(device: &DeviceInfo) -> bool {
    device.interfaces().any(|i| {
        let (class, subclass, protocol) = (i.class(), i.subclass(), i.protocol());
        class == 0x06
            || (class == 0xff && subclass == 0x42)
            || (class == 0xff && subclass == 0xff && protocol == 0x00)
    })
}

#[cfg(not(target_os = "android"))]
/// A stable name for the device's position on the bus: bus id and port path.
fn label_of(device: &DeviceInfo) -> String {
    let ports: Vec<String> = device.port_chain().iter().map(|p| p.to_string()).collect();
    format!("host/{}-{}", device.bus_id(), ports.join("."))
}

#[cfg(not(target_os = "android"))]
/// Run the AOA handshake. `Ok(false)` when the device does not support AOA.
async fn switch_to_accessory(device: &DeviceInfo, uri: &str) -> Result<bool, String> {
    let dev = device.open().await.map_err(|e| format!("open: {e}"))?;
    switch_device(&dev, uri).await
}

/// Take a device the embedder opened as USB host — on Android, through
/// `UsbDeviceConnection` — and link with it: open it if it is already an
/// accessory, otherwise ask it to become one. A device that switches leaves
/// the bus and comes back as an accessory, which the embedder hands over
/// again.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) async fn adopt(
    fd: std::os::fd::OwnedFd,
    label: String,
    links: Arc<UsbLinkQueue>,
    uri: String,
) {
    let dev = match nusb::Device::from_fd(fd).await {
        Ok(dev) => dev,
        Err(e) => {
            warn!(device = %label, error = %e, "USB host: cannot use handed-over device");
            return;
        }
    };
    let desc = dev.device_descriptor();
    if desc.vendor_id() == AOA_VID && AOA_PIDS.contains(&desc.product_id()) {
        match open_link(dev, &label).await {
            Ok(link) => {
                info!(link = %label, "USB host: accessory opened");
                links.push(link);
            }
            Err(e) => warn!(link = %label, error = %e, "USB host: cannot open accessory"),
        }
    } else {
        match switch_device(&dev, &uri).await {
            Ok(true) => info!(device = %label, "USB host: asked device to become an accessory"),
            Ok(false) => debug!(device = %label, "USB host: device does not speak AOA"),
            Err(e) => debug!(device = %label, error = %e, "USB host: AOA switch failed"),
        }
    }
}

/// Run the AOA handshake on an opened device. `Ok(false)` when it does not
/// support AOA.
async fn switch_device(dev: &nusb::Device, uri: &str) -> Result<bool, String> {
    let version = dev
        .control_in(
            ControlIn {
                control_type: ControlType::Vendor,
                recipient: Recipient::Device,
                request: AOA_GET_PROTOCOL,
                value: 0,
                index: 0,
                length: 2,
            },
            CONTROL_TIMEOUT,
        )
        .await
        .map_err(|e| format!("get protocol: {e}"))?;
    let protocol = match version.as_slice() {
        [lo, hi, ..] => u16::from_le_bytes([*lo, *hi]),
        _ => 0,
    };
    if protocol < 1 {
        return Ok(false);
    }

    let strings = [
        AOA_MANUFACTURER,
        AOA_MODEL,
        AOA_DESCRIPTION,
        AOA_VERSION,
        uri,
        AOA_SERIAL,
    ];
    for (index, string) in strings.iter().enumerate() {
        let mut data = string.as_bytes().to_vec();
        data.push(0);
        dev.control_out(
            ControlOut {
                control_type: ControlType::Vendor,
                recipient: Recipient::Device,
                request: AOA_SEND_STRING,
                value: 0,
                index: index as u16,
                data: &data,
            },
            CONTROL_TIMEOUT,
        )
        .await
        .map_err(|e| format!("send string {index}: {e}"))?;
    }
    dev.control_out(
        ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: AOA_START,
            value: 0,
            index: 0,
            data: &[],
        },
        CONTROL_TIMEOUT,
    )
    .await
    .map_err(|e| format!("start: {e}"))?;
    Ok(true)
}

#[cfg(not(target_os = "android"))]
/// Open an accessory-mode device and wrap its bulk pipe as a link.
async fn open_accessory(device: &DeviceInfo, label: &str) -> Result<UsbLink, String> {
    let dev = device.open().await.map_err(|e| format!("open: {e}"))?;
    open_link(dev, label).await
}

/// Claim the accessory interface of an opened device and start the pumps
/// that carry its bulk endpoints to and from a link.
///
/// The accessory interface is the vendor-class one with a bulk endpoint each
/// way; an accessory with adb also has adb's, which is told apart by its
/// subclass.
pub(crate) async fn open_link(dev: nusb::Device, label: &str) -> Result<UsbLink, String> {
    let (number, ep_in, ep_out) = {
        let config = dev
            .active_configuration()
            .map_err(|e| format!("configuration: {e}"))?;
        let mut found = None;
        for interface in config.interfaces() {
            for alt in interface.alt_settings() {
                if alt.class() != 0xff || alt.subclass() == 0x42 {
                    continue;
                }
                let bulk = |dir: Direction| {
                    alt.endpoints()
                        .find(|ep| {
                            ep.transfer_type() == TransferType::Bulk && ep.direction() == dir
                        })
                        .map(|ep| ep.address())
                };
                if let (Some(i), Some(o)) = (bulk(Direction::In), bulk(Direction::Out)) {
                    found = Some((alt.interface_number(), i, o));
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
        found.ok_or("no accessory interface")?
    };

    #[cfg(any(target_os = "linux", target_os = "android"))]
    let interface = dev.detach_and_claim_interface(number).await;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let interface = dev.claim_interface(number).await;
    let interface = interface.map_err(|e| format!("claim interface {number}: {e}"))?;

    let ep_in = interface
        .endpoint::<Bulk, In>(ep_in)
        .map_err(|e| format!("bulk in: {e}"))?;
    let ep_out = interface
        .endpoint::<Bulk, Out>(ep_out)
        .map_err(|e| format!("bulk out: {e}"))?;

    let (in_tx, in_rx) = mpsc::channel(PUMP_QUEUE_DEPTH);
    let (out_tx, out_rx) = mpsc::channel(PUMP_QUEUE_DEPTH);
    tokio::spawn(pump_in(ep_in, in_tx, label.to_string()));
    tokio::spawn(pump_out(ep_out, out_rx, label.to_string()));
    Ok(UsbLink {
        label: label.to_string(),
        rx: in_rx,
        tx: out_tx,
    })
}

/// Keep [`IN_FLIGHT`] reads queued on the bulk IN endpoint and pass what
/// each brings to the link, until the device goes or the link is dropped.
async fn pump_in(mut ep: nusb::Endpoint<Bulk, In>, to_link: mpsc::Sender<Vec<u8>>, label: String) {
    for _ in 0..IN_FLIGHT {
        ep.submit(Buffer::new(USB_TRANSFER_MAX));
    }
    loop {
        let done = ep.next_complete().await;
        if let Err(e) = done.status {
            debug!(link = %label, error = %e, "USB host: bulk in ended");
            break;
        }
        if done.actual_len > 0
            && to_link
                .send(done.buffer[..done.actual_len].to_vec())
                .await
                .is_err()
        {
            break;
        }
        ep.submit(Buffer::new(USB_TRANSFER_MAX));
    }
    ep.cancel_all();
}

/// Write what the link queues to the bulk OUT endpoint, joined into transfers
/// of up to 16 KiB, with a zero-length packet where the phone's read would
/// otherwise not complete.
async fn pump_out(
    mut ep: nusb::Endpoint<Bulk, Out>,
    mut from_link: mpsc::Receiver<Vec<u8>>,
    label: String,
) {
    let packet = ep.max_packet_size();
    let mut carried = None;
    loop {
        let first = match carried.take() {
            Some(chunk) => chunk,
            None => match from_link.recv().await {
                Some(chunk) => chunk,
                None => break,
            },
        };
        let transfer = gather(first, &mut from_link, &mut carried);
        let len = transfer.len();
        ep.submit(Buffer::from(transfer));
        if needs_zlp(len, packet) {
            ep.submit(Buffer::new(0));
        }
        while ep.pending() > OUT_IN_FLIGHT {
            if let Err(e) = ep.next_complete().await.status {
                debug!(link = %label, error = %e, "USB host: bulk out ended");
                return;
            }
        }
    }
    while ep.pending() > 0 {
        if ep.next_complete().await.status.is_err() {
            return;
        }
    }
}

/// Whether a transfer of `len` bytes must be followed by a zero-length
/// packet: it ends on a packet boundary but does not fill the phone's read.
fn needs_zlp(len: usize, max_packet_size: usize) -> bool {
    len > 0 && len.is_multiple_of(max_packet_size) && len < USB_TRANSFER_MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_length_packet_follows_only_short_aligned_transfers() {
        assert!(needs_zlp(512, 512));
        assert!(needs_zlp(1024, 512));
        assert!(needs_zlp(USB_TRANSFER_MAX - 512, 512));
        assert!(!needs_zlp(USB_TRANSFER_MAX, 512));
        assert!(!needs_zlp(513, 512));
        assert!(!needs_zlp(37, 512));
        assert!(!needs_zlp(0, 512));
    }

    /// Hardware check against a real phone running an app that accepts the
    /// FIPS accessory and echoes every byte back. Not part of the suite:
    ///
    /// ```text
    /// cargo test --features usb-host --lib aoa_echo_against_a_phone -- --ignored --nocapture
    /// ```
    ///
    /// Plug the phone in first. It is switched into accessory mode, every
    /// transfer size that needs (or must not get) a zero-length packet is
    /// echoed, and then a pipelined stream measures throughput.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a phone on USB running an echoing accessory app"]
    async fn aoa_echo_against_a_phone() {
        let links = Arc::new(UsbLinkQueue::new());
        let host = tokio::spawn(run(Arc::clone(&links), "https://example.invalid".into()));
        let mut link = tokio::time::timeout(Duration::from_secs(15), links.next_link())
            .await
            .expect("no accessory came up within 15 s");
        println!("linked: {}", link.label);

        async fn echo(link: &mut UsbLink, payload: Vec<u8>) {
            let len = payload.len();
            link.tx.send(payload.clone()).await.unwrap();
            let mut got = Vec::with_capacity(len);
            while got.len() < len {
                let chunk = tokio::time::timeout(Duration::from_secs(3), link.rx.recv())
                    .await
                    .unwrap_or_else(|_| panic!("echo of {len} B stalled at {} B", got.len()))
                    .expect("link closed");
                got.extend_from_slice(&chunk);
            }
            assert_eq!(got, payload, "echo of {len} B differs");
        }

        // Sizes around every boundary the pumps treat specially.
        for len in [
            1,
            37,
            511,
            512,
            513,
            1024,
            4096,
            16000,
            USB_TRANSFER_MAX - 512,
            USB_TRANSFER_MAX,
        ] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 7 + len) as u8).collect();
            echo(&mut link, payload).await;
            println!("echoed {len} B");
        }

        // Pipelined: the writer keeps sending while the reader drains.
        let transfers = 2000usize;
        let size = USB_TRANSFER_MAX;
        let tx = link.tx.clone();
        let start = std::time::Instant::now();
        let writer = tokio::spawn(async move {
            for i in 0..transfers {
                tx.send(vec![i as u8; size]).await.unwrap();
            }
        });
        let mut received = 0usize;
        while received < transfers * size {
            let chunk = tokio::time::timeout(Duration::from_secs(3), link.rx.recv())
                .await
                .expect("pipelined echo stalled")
                .expect("link closed");
            received += chunk.len();
        }
        writer.await.unwrap();
        let secs = start.elapsed().as_secs_f64();
        let mb = (transfers * size) as f64 / 1e6;
        println!(
            "pipelined: {mb:.1} MB each way in {secs:.2} s = {:.1} MB/s per direction",
            mb / secs
        );
        host.abort();
    }
}
