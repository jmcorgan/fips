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
    Connecting(Box<PeerConnection>),
    Active(Box<ActivePeer>),
}

/// Handles authentication handshake only
struct PeerConnection {
    link_id: LinkId,
    direction: LinkDirection,
    // Handshake-specific state
    handshake_state: HandshakeState,
    expected_identity: Option<PeerIdentity>,
    noise_handshake: Option<noise::HandshakeState>,
    noise_session: Option<NoiseSession>,
    // Timing
    started_at: u64,
    last_activity: u64,
}

/// Fully authenticated peer
struct ActivePeer {
    identity: PeerIdentity,
    link_id: LinkId,
    connectivity: ConnectivityState,
    noise_session: Option<NoiseSession>,
    // Routing state
    declaration: Option<ParentDeclaration>,
    ancestry: Option<TreeCoordinate>,
    inbound_filter: Option<BloomFilter>,
    last_seen: u64,
}
```

**Benefits:**

- Each struct only contains fields relevant to that phase
- Methods can't be called in wrong state (compile-time safety)
- Noise handshake state automatically dropped when `PeerConnection` → `ActivePeer`
- Each phase struct is smaller, simpler, independently testable

## Transition Pattern

In FIPS, connections and peers are stored in separate maps rather than a
unified `PeerSlot` map (though `PeerSlot` exists for cases where either phase
is needed). PeerConnection uses `&mut self` methods for handshake steps, and
the Node orchestrates promotion when the handshake completes:

```rust
impl PeerConnection {
    /// Start handshake as initiator, returns msg1 to send.
    fn start_handshake(&mut self, our_keypair: Keypair, current_time_ms: u64)
        -> Result<Vec<u8>, NoiseError>;

    /// Process incoming msg1 (responder), returns msg2 to send.
    fn receive_handshake_init(&mut self, our_keypair: Keypair, message: &[u8],
        current_time_ms: u64) -> Result<Vec<u8>, NoiseError>;

    /// Complete handshake by processing msg2 (initiator).
    fn complete_handshake(&mut self, message: &[u8], current_time_ms: u64)
        -> Result<(), NoiseError>;

    /// Take the completed NoiseSession for use in ActivePeer.
    fn take_session(&mut self) -> Option<NoiseSession>;
}

/// Result of promoting a connection to active peer.
enum PromotionResult {
    /// New peer created successfully.
    Promoted(NodeAddr),
    /// Cross-connection detected, this connection lost tie-breaker.
    CrossConnectionLost { winner_link_id: LinkId },
    /// Cross-connection detected, this connection won, old one replaced.
    CrossConnectionWon { loser_link_id: LinkId, node_addr: NodeAddr },
}
```

The Node promotes a completed connection by moving data between maps:

```rust
// In the Node's handshake completion handler:
// 1. Remove from connections map
let conn = self.connections.remove(&link_id).unwrap();

// 2. Extract session and identity from completed connection
let session = conn.take_session().unwrap();
let identity = conn.expected_identity().unwrap().clone();

// 3. Create active peer with the session
let peer = ActivePeer::with_session(
    identity, link_id, current_time_ms,
    session, our_index, their_index,
    transport_id, source_addr, conn.link_stats().clone(),
);

// 4. Insert into peers map (checking for cross-connections)
self.peers.insert(*peer.node_addr(), peer);
```

## Timeout Handling

Each phase struct tracks its own timing using Unix milliseconds (`u64`).
PeerConnection provides a simple boolean timeout check:

```rust
impl PeerConnection {
    /// Check if the connection has timed out.
    fn is_timed_out(&self, current_time_ms: u64, timeout_ms: u64) -> bool {
        self.idle_time(current_time_ms) > timeout_ms
    }

    /// Time since last activity.
    fn idle_time(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.last_activity)
    }
}
```

The Node's event loop periodically scans the connections map for timeouts:

```rust
// In the Node's periodic maintenance:
let now_ms = current_time_ms();
let mut timed_out = vec![];

for (link_id, conn) in &self.connections {
    if conn.is_timed_out(now_ms, HANDSHAKE_TIMEOUT_MS) {
        timed_out.push(*link_id);
    }
}

for link_id in timed_out {
    self.connections.remove(&link_id);
    // Clean up link, free index, etc.
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

- Noise IK handshake state (`noise_handshake`, `handshake_state`)
- Expected identity (known for outbound, learned for inbound)
- Direction (`LinkDirection::Inbound` vs `LinkDirection::Outbound`)
- Session index tracking (`our_index`, `their_index`)
- Timing (`started_at`, `last_activity` in Unix milliseconds)

**ActivePeer** contains:

- `NoiseSession` (symmetric keys for encrypt/decrypt)
- `ConnectivityState` (Connected, Stale, Reconnecting, Disconnected)
- Tree position (`declaration`, `ancestry`)
- Bloom filter (`inbound_filter`, with sequence tracking)
- Session indices and transport address (for wire protocol dispatch)
- Statistics (`last_seen`, `link_stats`, `authenticated_at`)

### Link Lifecycle (Connection-Oriented Transports)

Links use a simple state enum rather than phase-based structs, since link
state transitions are straightforward:

```rust
enum LinkState {
    Connecting,    // Connection in progress (connection-oriented only)
    Connected,     // Ready for traffic
    Disconnected,  // Was connected, now gone
    Failed,        // Connection attempt failed
}

struct Link {
    link_id: LinkId,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    direction: LinkDirection,
    state: LinkState,
    stats: LinkStats,
    // ...
}
```

For connectionless transports (UDP), links are immediately `Connected` -
no `Connecting` phase needed. A phase-based approach (separate structs for
connecting vs established) would be valuable for transports with complex
connection setup like Tor circuit building.

### Node Lifecycle

```rust
enum NodeState {
    Created,
    Starting,
    Running,
    Stopping,
    Stopped,
}
```

The Node uses a simple state enum because startup/shutdown are brief and
don't need complex per-phase logic. A phase-based approach (separate structs
per phase) would be useful if startup involved multi-step async operations
with retries.

### Transport Lifecycle

```rust
enum TransportState {
    Configured,
    Starting,
    Up,
    Down,
    Failed,
}
```

Like `NodeState`, this uses a simple state enum because transport startup is
straightforward. A phase-based approach would be valuable for transports with
complex initialization (e.g., Tor bootstrap with multi-step circuit building).

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

Rather than a unified `PeerSlot` map, the Node stores connections and peers
in separate maps optimized for their phase:

```rust
struct Node {
    // Handshake phase: indexed by LinkId (identity not yet known)
    connections: HashMap<LinkId, PeerConnection>,

    // Active phase: indexed by NodeAddr (verified identity)
    peers: HashMap<NodeAddr, ActivePeer>,

    // Reverse lookup: (transport_id, remote_addr) → LinkId
    addr_to_link: HashMap<AddrKey, LinkId>,

    // Wire protocol dispatch: (transport_id, our_index) → NodeAddr
    peers_by_index: HashMap<(TransportId, u32), NodeAddr>,
}
```

For inbound connections from unknown addresses:

1. Receive Noise IK msg1 → decrypt to extract sender's static key (identity)
2. Create new PeerConnection with discovered identity
3. Add to `connections` (by LinkId) and `addr_to_link`
4. After handshake completes, promote to `peers` (indexed by NodeAddr) and
   `peers_by_index` (for session index dispatch)

## Summary

The phase-based state machine pattern provides:

1. **Type safety** - Can't call auth methods on active peer
2. **Memory efficiency** - Phase-specific data dropped on transition
3. **Clarity** - Each struct is focused and comprehensible
4. **Security** - Handshake state (ephemeral keys) dropped after auth
5. **Testability** - Each phase testable in isolation

The cost is slightly more complex transition handling in the event loop,
but this is offset by simpler per-phase logic.
