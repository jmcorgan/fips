# BLE L2CAP Framing: Byte-Stream Coalescing and the Length-Prefix Solution

## The Problem

BLE L2CAP Connection-Oriented Channels (CoC) are specified as message-oriented
(each SDU is a discrete unit), but platform APIs expose them differently:

| Platform | API | Semantics |
|----------|-----|-----------|
| Linux (BlueZ) | `SeqPacket` socket | Message-oriented — one `recv()` returns exactly one SDU |
| macOS (CoreBluetooth) | `NSInputStream` / `NSOutputStream` | Byte-stream — reads may coalesce or fragment SDUs |

CoreBluetooth's `NSInputStream` buffers incoming L2CAP SDUs internally and
delivers them as a continuous byte stream. A single `read()` call may return:

- Part of one SDU (fragmentation under load)
- Exactly one SDU (the common case at low throughput)
- Multiple SDUs concatenated together (coalescing under burst traffic)

FIPS's BLE transport sends FMP (FIPS Mesh Protocol) packets as individual
L2CAP SDUs. Each FMP packet starts with a version byte and is
self-contained. When CoreBluetooth coalesces two SDUs into one `read()`,
the receiver sees what looks like a single oversized packet with a corrupt
body — leading to:

- "Unknown FMP version" errors (second packet's version byte interpreted as
  payload of the first)
- AEAD decryption failures (ciphertext includes bytes from the next packet)
- Session establishment failures (probe/response framing corrupted)

This issue is invisible on Linux-to-Linux links because `SeqPacket` preserves
message boundaries. It only manifests when at least one endpoint uses
CoreBluetooth (macOS or iOS).

## The Solution: Length-Prefix Framing

All BLE stream implementations (`BluerStream`, `BluestStream`, `MockBleStream`)
now wrap every message in a 2-byte big-endian length prefix:

```
Wire format:  [len_hi][len_lo][payload...]
               └─ 2 bytes ──┘└─ len bytes ─┘
```

**Sender** prepends the payload length before writing:

```rust
let mut framed = Vec::with_capacity(2 + data.len());
framed.extend_from_slice(&(data.len() as u16).to_be_bytes());
framed.extend_from_slice(data);
writer.write(&framed).await?;
```

**Receiver** buffers raw bytes and extracts complete frames:

```rust
loop {
    // Try to parse a complete frame from the buffer
    if buf.len() >= 2 {
        let payload_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if buf.len() >= 2 + payload_len {
            // Extract frame, drain buffer, return
        }
    }
    // Not enough data — read more bytes from the channel
    let n = reader.read(&mut tmp).await?;
    buf.extend_from_slice(&tmp[..n]);
}
```

On Linux (BlueZ), where `SeqPacket` already delivers one SDU per `recv()`,
the framing is redundant but harmless — it adds 2 bytes of overhead per
message and ensures both platforms speak the same wire format.

### Trade-offs

| | Pro | Con |
|---|-----|-----|
| **Correctness** | Works on all platforms regardless of stream vs message semantics | — |
| **Simplicity** | ~20 lines of code per stream impl, easy to reason about | — |
| **Overhead** | 2 bytes per message (negligible vs BLE MTU of 512+) | — |
| **Compatibility** | Breaking change — both peers must use framed protocol | Requires coordinated rollout |
| **Max message size** | 65535 bytes (u16 limit) | Sufficient for BLE MTU range |

## Alternative Approaches Considered

### 1. FMP-Aware Packet Splitting

Parse FMP headers at the BLE transport layer to determine packet boundaries.
FMP packets have a known header structure with enough information to
determine total length.

- **Pro**: No wire format change; backward compatible with unframed peers
- **Con**: Violates layer separation (transport must understand FMP internals);
  fragile if FMP format evolves; complex to implement correctly for all
  packet types (probe, data, control)

### 2. Assume One-SDU-Per-Read (No Framing)

Trust that CoreBluetooth will not coalesce SDUs in practice, since each SDU
triggers a separate delegate callback.

- **Pro**: Zero overhead; no code changes needed
- **Con**: Wrong. Observed coalescing under real traffic. Even if it works
  today, it relies on undocumented behavior that Apple can change in any
  macOS update. This was the original approach and it failed in testing.

### 3. GATT-Based Framing (Write Characteristics)

Instead of L2CAP CoC, use GATT write characteristics with
`CBCharacteristicWriteWithResponse`. Each GATT write is a discrete
operation with guaranteed boundaries.

- **Pro**: Message boundaries preserved by GATT; works on all BLE versions
- **Con**: ~10x slower than L2CAP CoC (GATT writes are serialized, limited
  to ATT_MTU - 3 bytes per write); throughput drops from ~1 Mbps to
  ~100 Kbps; requires complete rewrite of the BLE transport

### 4. Use `CBL2CAPChannel` Directly (Skip bluest)

Write a custom CoreBluetooth binding that accesses `CBL2CAPChannel`
directly, handling the `NSStream` delegate callbacks manually to
preserve per-SDU delivery.

- **Pro**: Full control over buffering; could potentially preserve SDU
  boundaries if each delegate callback is processed individually
- **Con**: Enormous implementation effort (Objective-C/Swift bridge,
  manual delegate management, run loop scheduling); still no guarantee
  that `NSInputStream` won't buffer internally; `bluest` already does
  this correctly at the Objective-C level — the coalescing happens inside
  `NSInputStream.read()`

### 5. Sentinel / Delimiter Framing

Use a magic byte sequence to delimit messages (like SLIP or COBS encoding).

- **Pro**: Self-synchronizing after corruption
- **Con**: Requires byte-stuffing (escaping the delimiter in payload),
  which inflates message size unpredictably; more complex than length
  prefix; COBS adds ~0.4% overhead but significant implementation
  complexity

## Chosen Approach Rationale

Length-prefix framing was chosen because:

1. It is the simplest correct solution
2. The overhead is negligible (2 bytes on 200-1500 byte messages)
3. It works identically on all platforms (Linux framing is redundant but
   compatible)
4. It is a well-understood pattern (TCP-based protocols universally use it)
5. The breaking change is acceptable because BLE transport was not deployed
   in production — all peers can be updated simultaneously
