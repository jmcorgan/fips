# macOS BLE Transport Design

## Background

FIPS uses BLE L2CAP Connection-Oriented Channels (CoC) in SeqPacket mode for
peer communication. The Linux implementation (`BluerIo`) uses the `bluer` crate
(BlueZ bindings) and binds to a fixed PSM (`0x0085`). Both sides know the PSM,
so connection is straightforward: `listen(0x0085)` / `connect(addr, 0x0085)`.

macOS supports L2CAP CoC via CoreBluetooth's `CBL2CAPChannel` (since macOS
10.13), but with a fundamental protocol difference that shapes the entire
implementation.

## The PSM problem

Linux (BlueZ) lets you bind an L2CAP listener to a specific PSM in the dynamic
range (`0x0080`–`0x00FF`). FIPS uses `0x0085`.

macOS (CoreBluetooth) **dynamically assigns** the PSM when you call
`publishL2CAPChannelWithEncryption`. You cannot choose a specific PSM. The
assigned PSM must be communicated to the connecting peer, typically via a GATT
characteristic.

### Interoperability matrix

| Scenario         | Status  | Notes                                                      |
|------------------|---------|------------------------------------------------------------|
| macOS → Linux    | Works   | macOS central connects to Linux's known PSM `0x0085`       |
| macOS → macOS    | Works   | Both sides exchange PSM via GATT characteristic            |
| Linux → macOS    | Blocked | Linux doesn't know macOS's dynamic PSM without reading GATT|

Linux → macOS requires the Linux `BluerIo::connect()` to read the PSM from a
GATT characteristic before opening the L2CAP channel. This is a protocol
enhancement that can be addressed as a follow-up.

## Crate selection

| Crate                    | L2CAP on macOS | Notes                                              |
|--------------------------|----------------|----------------------------------------------------|
| `bluest`                 | Yes            | Async, wraps CoreBluetooth, L2CAP added June 2025  |
| `btleplug`               | No             | GATT only, maintainer confirmed no L2CAP plans     |
| `objc2-core-bluetooth`   | Yes (raw)      | Low-level Objective-C bindings, all L2CAP APIs bound|
| `core_bluetooth`          | No             | Central role only, no L2CAP, appears unmaintained   |

**Recommendation: `bluest`**

It is the only Rust crate with a working async L2CAP CoC implementation over
CoreBluetooth. Pre-1.0 but actively maintained (174 commits, 140+ stars). Uses
`objc2-core-bluetooth` internally. API:

- `Device::open_l2cap_channel(psm, secure)` → `L2capChannel`
- `L2capChannel` provides `read()`, `write()`, `close()`, `split()`

Note: the `bluest` docs may still say "L2CAP not supported on macOS" — this is
outdated. The implementation landed in PR #33 (June 2025).

## Architecture

### Trait implementation

The existing `BleIo` trait abstracts all platform-specific BLE operations:

```rust
pub trait BleIo: Send + Sync + 'static {
    type Stream: BleStream + 'static;
    type Acceptor: BleAcceptor<Stream = Self::Stream> + 'static;
    type Scanner: BleScanner + 'static;

    async fn listen(&self, psm: u16) -> Result<Self::Acceptor, TransportError>;
    async fn connect(&self, addr: &BleAddr, psm: u16) -> Result<Self::Stream, TransportError>;
    async fn start_advertising(&self) -> Result<(), TransportError>;
    async fn stop_advertising(&self) -> Result<(), TransportError>;
    async fn start_scanning(&self) -> Result<Self::Scanner, TransportError>;
    fn local_addr(&self) -> Result<BleAddr, TransportError>;
    fn adapter_name(&self) -> &str;
}
```

A new `BluestIo` struct implements this trait using `bluest`. All higher-level
logic (connection pool, discovery buffer, accept/scan loops, pubkey exchange,
cross-probe tie-breaking) remains unchanged.

### GATT PSM exchange

Since macOS cannot listen on a fixed PSM, the implementation adds a thin GATT
layer to advertise the dynamically-assigned PSM:

**Peripheral side (`listen` + `start_advertising`):**

1. Call `publishL2CAPChannel` → receive dynamic PSM via delegate callback
2. Create a GATT service with the FIPS service UUID
3. Add a read-only characteristic containing the 2-byte PSM (little-endian)
4. Start advertising the GATT service

**Central side (`connect`):**

1. Connect to the peripheral's GATT server
2. Discover the FIPS service
3. Read the PSM characteristic
4. Open L2CAP channel with the discovered PSM
5. Disconnect GATT (L2CAP channel persists independently)

For macOS → Linux: skip the GATT read and connect directly to PSM `0x0085`.
This can be determined by whether the peer advertises the FIPS GATT service
(macOS) or only the FIPS service UUID in scan response data (Linux).

### Stream adapter

`bluest`'s `L2capChannel` exposes byte-stream semantics (`read`/`write`), while
`BleStream` expects datagram semantics (each `send` is one message). On BLE
L2CAP CoC, the underlying transport preserves message boundaries at the
controller level, but CoreBluetooth's NSStream abstraction may coalesce reads.

Options:
- **Length-prefix framing**: prepend a 2-byte length header to each message.
  Simple, reliable, adds 2 bytes overhead per packet.
- **Rely on MTU-sized reads**: if each write is ≤ MTU and reads always return
  exactly one L2CAP SDU, no framing is needed. Needs validation with `bluest`.

### Feature gating

```toml
# Cargo.toml
[features]
default = ["tui", "ble"]
ble = ["dep:bluer"]
ble-macos = ["dep:bluest"]

[target.'cfg(target_os = "linux")'.dependencies]
bluer = { version = "0.17", features = ["bluetoothd", "l2cap"], optional = true }

[target.'cfg(target_os = "macos")'.dependencies]
bluest = { version = "0.3", optional = true }
```

```rust
// src/transport/ble/io.rs
#[cfg(all(feature = "ble", target_os = "linux"))]
pub type DefaultBleIo = BluerIo;

#[cfg(all(feature = "ble-macos", target_os = "macos"))]
pub type DefaultBleIo = BluestIo;
```

Alternatively, unify under the `ble` feature and use target-specific deps:

```toml
[features]
default = ["tui", "ble"]
ble = []

[target.'cfg(target_os = "linux")'.dependencies]
bluer = { version = "0.17", features = ["bluetoothd", "l2cap"], optional = true }

[target.'cfg(target_os = "macos")'.dependencies]
bluest = { version = "0.3", optional = true }
```

With cfg guards on `target_os` + dependency availability throughout the BLE code.

## Estimated scope

| Component                         | Lines | Complexity |
|-----------------------------------|-------|------------|
| `BluestIo` struct + `BleIo` impl | ~200  | Medium     |
| `BluestStream` (`BleStream`)     | ~80   | Low        |
| `BluestAcceptor` (`BleAcceptor`) | ~60   | Low        |
| `BluestScanner` (`BleScanner`)   | ~80   | Low        |
| GATT PSM service (peripheral)    | ~120  | Medium     |
| GATT PSM discovery (central)     | ~80   | Medium     |
| Feature gating + type selection   | ~40   | Low        |
| **Total**                         | ~660  |            |

## Open questions

1. **`bluest` maturity**: the L2CAP implementation is ~1 year old. Should we
   vendor/fork it, or depend on crates.io and pin the version?

2. **Stream framing**: does `bluest`'s `L2capChannel::read()` preserve L2CAP
   SDU boundaries, or do we need length-prefix framing? Requires testing.

3. **Linux → macOS interop**: should the Linux `BluerIo::connect()` be extended
   to read PSM from GATT as part of this work, or deferred?

4. **Adapter naming**: Linux uses `hci0`, macOS uses `default` (there's
   typically one adapter). The `BleAddr` format (`adapter/AA:BB:CC:DD:EE:FF`)
   should work with `default` as the adapter name. CoreBluetooth doesn't expose
   adapter names, so this is a synthetic identifier.

5. **Testing**: macOS BLE testing requires physical hardware. CI can only verify
   compilation, not runtime behavior. The existing `MockBleIo` test
   infrastructure covers the transport logic above the I/O layer.
