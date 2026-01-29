# FIPS Architecture Document Review

**Date**: 2025-01-29
**Document reviewed**: fips-architecture.md

This file captures critique and open issues identified during architecture review.
Items should be addressed before implementation begins or marked as intentionally
deferred.

---

## High Priority (Implementation Blockers)

### 1. Coordinate Ordering Inconsistency

**Issue**: Architecture says `[self, parent, ..., root]` but spanning-tree-dynamics.md
sometimes uses `[root, ..., self]` ordering.

**Location**: fips-architecture.md line 165, spanning-tree-dynamics.md line 346-349

**Resolution needed**: Standardize on one ordering across all documents.

**Status**: OPEN

---

### 2. Authentication Protocol Not Referenced

**Issue**: Architecture references "FIPS auth handshake" but doesn't define it or
reference where it's defined.

**Location**: fips-architecture.md line 285

**Resolution needed**: Add reference to fips-design.md lines 115-205, or include
summary in architecture document.

**Status**: OPEN

---

### 3. Concurrency Model Unspecified

**Issue**: Document doesn't specify whether implementation should be:
- Single-threaded async
- Multi-threaded with message passing
- How state machines are driven (polling, callbacks, async/await)
- Whether transports run in separate threads/tasks

**Location**: Entire document

**Resolution needed**: Add "Concurrency Model" section specifying the expected
runtime architecture.

**Status**: OPEN

---

### 4. Keepalive Message Format Unspecified

**Issue**: Configuration specifies `peer.keepalive.interval` but no message type
is defined for keepalives. RTT measurement mechanism is unclear.

**Location**: fips-architecture.md line 762

**Resolution needed**: Clarify whether Dummy (0x00) message from fips-design.md
is used, and how RTT is measured (request/response probing or passive observation).

**Status**: OPEN

---

### 5. Cache Naming Confusion

**Issue**: Multiple cache references that may or may not be the same thing:
- `coord_cache: CoordCache` on Node (line 35)
- `coord_cache: HashMap<Ipv6Addr, CachedCoords>` on TreeState (line 167)
- `discovery.cache.max_entries` configuration (line 745)
- `session.cache.max_entries` configuration (line 751)

**Resolution needed**: Clarify whether these are the same cache or different caches.
If different, explain the distinction.

**Status**: OPEN

---

## Medium Priority (Design Clarity)

### 6. Peer vs Link Relationship

**Issue**: Document states "one-to-one mapping between peers and links" (line 148)
but Links can exist before authentication completes, meaning Links exist without
Peers temporarily.

**Resolution needed**: Clarify the relationship lifecycle:
- Link created on connection (before auth)
- Peer created on successful auth
- Peer always references exactly one Link
- Link can exist without Peer (during auth or after auth failure)

**Status**: OPEN

---

### 7. Error Handling Strategy Absent

**Issue**: No systematic error handling definitions:
- Signature verification failure handling
- Malformed packet handling
- Error codes and response formats
- Logging/reporting strategy

**Resolution needed**: Add "Error Handling" section or reference to protocol spec.

**Status**: OPEN

---

### 8. Memory Bounds Missing

**Issue**: Configuration specifies cache sizes but no limits for:
- Maximum peers
- Maximum transports
- Maximum pending operations/queues
- Overall memory budget

**Resolution needed**: Add resource limit configuration or document that these
are implementation-defined.

**Status**: OPEN

---

### 9. Timer Management at Scale

**Issue**: Multiple timers per peer (auth timeout, keepalive, reconnect delay,
filter debounce). For 100 peers, this could be hundreds of timers.

**Resolution needed**: Note that timer wheel or hierarchical timing wheel may
be needed for efficient implementation at scale.

**Status**: OPEN

---

### 10. Initialization/Shutdown Sequences

**Issue**: No startup sequence defined:
- Transport start order
- TUN interface initialization relative to peering
- Behavior when configured peers are unreachable
- When node is "ready" to route

No shutdown procedure defined:
- Should nodes announce departure?
- Session termination
- TUN interface cleanup

**Resolution needed**: Add "Initialization" and "Shutdown" sections.

**Status**: OPEN

---

## Lower Priority (Polish)

### 11. Configuration Validation Rules

**Issue**: No validation rules specified:
- What if `filter.size` is not a power of 2?
- What if `peer.keepalive.timeout` < `peer.keepalive.interval`?
- What if `timeout.adaptive.min` > `timeout.adaptive.max`?

**Status**: OPEN

---

### 12. Default Value Rationales

**Issue**: Several defaults lack rationale:
- `filter.scope = 2`: Why 2?
- `tree.parent.hold_time = 10s`: Why 10 seconds?
- `filter.stale.threshold = 300s`: Based on what analysis?

**Status**: OPEN

---

### 13. Terminology Inconsistency Across Documents

**Issue**: "Link" and "Transport" meanings differ between documents:
- fips-links.md uses "link" to mean underlying transport protocol
- fips-architecture.md uses "Link" to mean connection over Transport
- fips-design.md has `FipsLink` trait which is really a transport interface

**Resolution needed**: Standardize terminology or add glossary.

**Status**: OPEN

---

### 14. Gateway/Subnet Routing Details Incomplete

**Issue**: Document mentions `leaf_dependents` but doesn't explain:
- How a node becomes a gateway for a subnet
- How gateway prefixes are advertised in Bloom filters
- Configuration for gateway mode

**Status**: OPEN

---

### 15. DiscoveredPeer Hint Field Mismatch

**Issue**: Transport trait shows `discover() -> Result<Vec<DiscoveredPeer>>` but
event shows `DiscoveredPeer { transport_id, addr, hint: Option<PublicKey> }`.
The discover() return type doesn't show the hint field.

**Resolution needed**: Align trait signature with event structure.

**Status**: OPEN

---

## Edge Cases Not Addressed

### Root Node Failure
- How long until new root is elected?
- How are in-flight sessions affected?
- Any proactive root backup mechanism?

### Rapid Peer Churn
- Debounce (500ms) may not be sufficient
- Could lead to Bloom filter oscillation or announcement storms

### Network Partition Healing
- What happens to sessions that existed in both partitions?
- How do routers with stale cache entries recover?

### Transport Startup Timing
- If Tor takes 180s but UDP is instant, what's node status during window?
- Are Tor-only peers unreachable during Tor bootstrap?

### MTU Mismatch Across Path
- Path includes links with different MTUs (Ethernet 1500 vs LoRa 222)
- No path MTU discovery or fragmentation strategy defined

### Clock Skew
- TreeAnnounce timestamps with significant clock skew
- 5-minute tolerance in auth (fips-design.md) should be reflected here

### Resource Exhaustion Attacks
- Memory exhaustion via many fake peers
- CPU exhaustion via signature verification flooding
- Bandwidth exhaustion via Bloom filter spam

### Conflicting Peer Configurations
- Two configured peers with same npub but different addresses
- Discovered peer conflicts with configured peer

### TUN Interface Unavailable
- TUN creation fails (permissions, kernel module)
- Can node run in "relay-only" mode without TUN?

---

## Resolution Tracking

| # | Issue | Priority | Status | Resolution |
|---|-------|----------|--------|------------|
| 1 | Coordinate ordering | High | OPEN | |
| 2 | Auth protocol reference | High | OPEN | |
| 3 | Concurrency model | High | OPEN | |
| 4 | Keepalive format | High | OPEN | |
| 5 | Cache naming | High | OPEN | |
| 6 | Peer/Link relationship | Medium | OPEN | |
| 7 | Error handling | Medium | OPEN | |
| 8 | Memory bounds | Medium | OPEN | |
| 9 | Timer management | Medium | OPEN | |
| 10 | Init/shutdown | Medium | OPEN | |
| 11 | Config validation | Low | OPEN | |
| 12 | Default rationales | Low | OPEN | |
| 13 | Terminology | Low | OPEN | |
| 14 | Gateway details | Low | OPEN | |
| 15 | DiscoveredPeer hint | Low | OPEN | |
