# FIPS State Machine Design

This document describes the phase-based state machine pattern used throughout
FIPS, where different lifecycle phases are represented by distinct struct types
wrapped in an enum rather than a single struct with a state field.

## Pattern Overview

### Traditional Approach (Single Struct + State Enum)

```rust
enum PeerState {
    Connecting,
    Authenticating,
    Active,
    Disconnected,
}

struct Peer {
    identity: PeerIdentity,
    state: PeerState,
    // Fields needed by ALL states
    ephemeral_key: Option<Keypair>,      // Only used during auth
    session_keys: Option<SessionKeys>,    // Only valid when Active
    tree_coords: Option<TreeCoordinate>,  // Only valid when Active
    // ...
}

impl Peer {
    fn handle_packet(&mut self, packet: &[u8]) {
        match self.state {
            PeerState::Connecting => { /* must check we're not Active */ }
            PeerState::Active => { /* must check session_keys.is_some() */ }
            // ...
        }
    }
}
```

**Problems:**

- Fields that only apply to certain states are `Option<T>` or uninitialized
- Methods must check state before operating (runtime errors possible)
- Auth-phase secrets (ephemeral keys) persist in memory after auth completes
- Single struct grows to accommodate all phases

### Phase-Based Approach (Enum of Structs)

```rust
/// What the Node stores per peer slot
enum PeerSlot {
    Connecting(PeerConnection),
    Active(ActivePeer),
}

/// Handles authentication handshake only
struct PeerConnection {
    identity: PeerIdentity,
    link_id: LinkId,
    direction: Direction,
    // Handshake-specific state
    ephemeral_keypair: Keypair,
    remote_ephemeral: Option<PublicKey>,
    handshake_hash: [u8; 32],
    attempts: u32,
    last_sent: Instant,
}

/// Fully authenticated peer
struct ActivePeer {
    identity: PeerIdentity,
    link_id: LinkId,
    session: SessionKeys,
    // Routing state
    declaration: Option<ParentDeclaration>,
    coords: Option<TreeCoordinate>,
    inbound_filter: Option<BloomFilter>,
    last_seen: Instant,
}
```

**Benefits:**

- Each struct only contains fields relevant to that phase
- Methods can't be called in wrong state (compile-time safety)
- Ephemeral keys automatically dropped when `PeerConnection` → `ActivePeer`
- Each phase struct is smaller, simpler, independently testable

## Transition Pattern

Phase transitions return the new phase, consuming the old:

```rust
impl PeerConnection {
    /// Handle incoming packet during handshake
    fn handle_packet(self, packet: &[u8]) -> ConnectionResult {
        // Parse and validate...
        match self.state {
            HandshakeState::WaitingForResponse => {
                // Verify response, derive session keys
                let session = self.derive_session_keys(&response);
                ConnectionResult::Authenticated {
                    peer: ActivePeer {
                        identity: self.identity,
                        link_id: self.link_id,
                        session,
                        declaration: None,
                        coords: None,
                        inbound_filter: None,
                        last_seen: Instant::now(),
                    },
                }
            }
            // ...
        }
    }
}

enum ConnectionResult {
    /// Stay in connecting phase, send this response
    Continue(Vec<u8>),
    /// Auth complete, here's the active peer
    Authenticated { peer: ActivePeer },
    /// Auth failed
    Failed(String),
}
```

The Node's event loop handles the transition:

```rust
fn handle_packet(&mut self, link_id: LinkId, packet: &[u8]) {
    let slot = self.peers.get_mut(&link_id);

    match slot {
        PeerSlot::Connecting(conn) => {
            // Note: take() to move ownership for transition
            let conn = std::mem::take(conn);
            match conn.handle_packet(packet) {
                ConnectionResult::Continue(response) => {
                    *slot = PeerSlot::Connecting(conn);
                    self.send(link_id, response);
                }
                ConnectionResult::Authenticated { peer } => {
                    *slot = PeerSlot::Active(peer);
                    self.on_peer_active(link_id);
                }
                ConnectionResult::Failed(reason) => {
                    self.peers.remove(&link_id);
                    warn!(%reason, "Peer auth failed");
                }
            }
        }
        PeerSlot::Active(peer) => {
            let actions = peer.handle_packet(packet);
            self.execute(actions);
        }
    }
}
```

## Timeout Handling

Each phase struct tracks its own timing. The Node's event loop periodically
scans for timeouts:

```rust
impl PeerConnection {
    fn check_timeout(&mut self, now: Instant) -> TimeoutResult {
        if now.duration_since(self.last_sent) < HANDSHAKE_TIMEOUT {
            return TimeoutResult::Ok;
        }

        self.attempts += 1;
        if self.attempts > MAX_HANDSHAKE_ATTEMPTS {
            return TimeoutResult::GiveUp;
        }

        self.last_sent = now;
        TimeoutResult::Retry(self.build_retry_packet())
    }
}

enum TimeoutResult {
    Ok,
    Retry(Vec<u8>),
    GiveUp,
}
```

Node event loop (simple periodic scan):

```rust
loop {
    select! {
        packet = packet_rx.recv() => { /* dispatch */ }

        _ = interval.tick() => {
            let now = Instant::now();
            let mut to_remove = vec![];

            for (id, slot) in &mut self.peers {
                if let PeerSlot::Connecting(conn) = slot {
                    match conn.check_timeout(now) {
                        TimeoutResult::Retry(packet) => {
                            self.send(conn.link_id, packet);
                        }
                        TimeoutResult::GiveUp => {
                            to_remove.push(*id);
                        }
                        TimeoutResult::Ok => {}
                    }
                }
            }

            for id in to_remove {
                self.peers.remove(&id);
            }
        }
    }
}
```

## Application in FIPS

### Peer Lifecycle

```text
PeerSlot::Connecting(PeerConnection)
    │
    │ Noise IK handshake (2 messages)
    ▼
PeerSlot::Active(ActivePeer)
    │
    │ Disconnect message (0x50) / link failure / timeout
    ▼
[removed from peers map, index freed, link cleaned up]
```

**PeerConnection** contains:

- Noise IK handshake state (ephemeral keys, handshake hash)
- Expected identity (for outbound) or discovered identity (for inbound)
- Direction (Inbound vs Outbound)

**ActivePeer** contains:

- NoiseSession (symmetric keys for encrypt/decrypt)
- Tree position (declaration, coordinates)
- Bloom filter (what's reachable through this peer)
- Statistics (last_seen, link_stats)

### Link Lifecycle (Connection-Oriented Transports)

For transports like Tor that require connection setup:

```rust
enum LinkSlot {
    Connecting(LinkConnection),
    Established(EstablishedLink),
}

struct LinkConnection {
    transport_id: TransportId,
    remote_addr: TransportAddr,
    connect_started: Instant,
    // Tor circuit build state, etc.
}

struct EstablishedLink {
    transport_id: TransportId,
    remote_addr: TransportAddr,
    // I/O handles
    writer: TorWriter,
    // Stats
    established_at: Instant,
}
```

For connectionless transports (UDP), links are immediately "established" -
no `LinkConnection` phase needed.

### Node Lifecycle

```rust
enum NodePhase {
    Created(CreatedNode),
    Starting(StartingNode),
    Running(RunningNode),
    Stopping(StoppingNode),
}
```

Currently the Node uses a simpler `NodeState` enum because startup/shutdown
are brief and don't need complex per-phase logic. Phase-based approach would
be useful if startup involved multi-step async operations with retries.

### Transport Lifecycle

```rust
enum TransportPhase {
    Configured(ConfiguredTransport),
    Starting(StartingTransport),
    Up(UpTransport),
    Failed(FailedTransport),
}
```

Again, currently simpler because transport startup is straightforward.
Would be valuable for transports with complex initialization (Tor bootstrap).

## When to Use This Pattern

**Use phase-based structs when:**

- Different phases have different fields (auth secrets vs session keys)
- Phase-specific logic is complex enough to benefit from isolation
- Security-sensitive data should be dropped after phase completion
- You want compile-time enforcement of valid operations per phase

**Use simple state enum when:**

- All phases share the same fields
- Phase transitions are simple (just flip a flag)
- The struct is small and phase logic is trivial

## Lookup Tables

When using `PeerSlot` enum, need reverse lookups for packet dispatch:

```rust
struct Node {
    // Primary storage
    peers: HashMap<NodeAddr, PeerSlot>,

    // Reverse lookup: (transport, remote_addr) → NodeAddr
    // Needed because ReceivedPacket has addr, not NodeAddr
    addr_to_peer: HashMap<(TransportId, TransportAddr), NodeAddr>,
}
```

For inbound connections from unknown addresses:

1. Receive Noise IK msg1 → decrypt to extract sender's static key (identity)
2. Create new PeerConnection with discovered identity
3. Add to `connections` (by LinkId) and `addr_to_link`
4. After handshake completes, promote to ActivePeer (indexed by NodeAddr)

## Summary

The phase-based state machine pattern provides:

1. **Type safety** - Can't call auth methods on active peer
2. **Memory efficiency** - Phase-specific data dropped on transition
3. **Clarity** - Each struct is focused and comprehensible
4. **Security** - Ephemeral keys don't linger after auth
5. **Testability** - Each phase testable in isolation

The cost is slightly more complex transition handling in the event loop,
but this is offset by simpler per-phase logic.
