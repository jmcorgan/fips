# FIPS Architecture Document Review

**Document reviewed**: fips-architecture.md
**Last updated**: 2025-01-29

This document tracks open issues and deferred items for the FIPS architecture.
Issues are organized by priority. Resolved items have been archived.

---

## Summary

| #  | Issue                  | Priority | Status   | Notes                |
| -- | ---------------------- | -------- | -------- | -------------------- |
| 11 | Config validation      | Low      | OPEN     | Add validation rules |
| 12 | Default rationales     | Low      | OPEN     | Document reasoning   |
| 14 | Gateway details        | Low      | OPEN     | Incomplete spec      |
| 15 | DiscoveredPeer hint    | Low      | OPEN     | Type mismatch        |
| 2  | Auth protocol ref      | High     | DEFERRED | Wire protocol work   |
| 3  | Concurrency model      | High     | DEFERRED | Future iteration     |
| 4  | Keepalive format       | High     | DEFERRED | Wire protocol work   |
| 7  | Error handling         | Medium   | DEFERRED | Future iteration     |
| 10 | Init/shutdown          | Medium   | DEFERRED | Future iteration     |

**Resolved (archived):** 1, 5, 6, 8, 9, 13

---

## Open Issues - Low Priority

### 11. Configuration Validation Rules

**Issue**: No validation rules specified:

- What if `filter.size` is not a power of 2?
- What if `peer.keepalive.timeout` < `peer.keepalive.interval`?
- What if `timeout.adaptive.min` > `timeout.adaptive.max`?

**Resolution needed**: Add validation rules or defer to implementation.

---

### 12. Default Value Rationales

**Issue**: Several defaults lack rationale:

- `filter.scope = 2`: Why 2?
- `tree.parent.hold_time = 10s`: Why 10 seconds?
- `filter.stale.threshold = 300s`: Based on what analysis?

**Resolution needed**: Add brief rationale comments or design rationale document.

---

### 14. Gateway/Subnet Routing Details Incomplete

**Issue**: Document mentions `leaf_dependents` but doesn't explain:

- How a node becomes a gateway for a subnet
- How gateway prefixes are advertised in Bloom filters
- Configuration for gateway mode

**Resolution needed**: Expand gateway section or reference future gateway
design document.

---

### 15. DiscoveredPeer Hint Field Mismatch

**Issue**: Transport trait shows `discover() -> Result<Vec<DiscoveredPeer>>` but
event shows `DiscoveredPeer { transport_id, addr, hint: Option<PublicKey> }`.
The discover() return type doesn't show the hint field.

**Resolution needed**: Align trait signature with event structure.

---

## Deferred Items

### Wire Protocol (Future Work)

These items will be addressed when the wire protocol section is developed:

| #   | Issue                   | Description                                                                               |
| --- | ----------------------- | ----------------------------------------------------------------------------------------- |
| 2   | Auth protocol reference | Architecture references "FIPS auth handshake" but doesn't define or reference fips-design |
| 4   | Keepalive format        | `peer.keepalive.interval` configured but no message type defined; RTT measurement unclear |

### Future Architecture Iterations

These items are deferred to future design iterations:

| #   | Issue             | Description                                                                                  |
| --- | ----------------- | -------------------------------------------------------------------------------------------- |
| 3   | Concurrency model | No specification for threading model, state machine driving, or transport isolation          |
| 7   | Error handling    | No systematic error handling definitions for signature failures, malformed packets, or codes |
| 10  | Init/shutdown     | Startup sequence, transport ordering, shutdown procedure, departure announcement             |

---

## Edge Cases for Future Consideration

### Network Dynamics

- **Root node failure**: Election timing, in-flight session impact, proactive backup
- **Rapid peer churn**: 500ms debounce may cause filter oscillation
- **Network partition healing**: Session conflicts, stale cache recovery

### Transport Edge Cases

- **Startup timing**: Tor takes 30s-2min while UDP is instant; node status during window
- **MTU mismatch**: Path includes links with different MTUs (Ethernet 1500 vs LoRa 222)
- **Clock skew**: TreeAnnounce timestamps; 5-minute tolerance from fips-design.md

### Security Considerations

- **Memory exhaustion**: Many fake peers
- **CPU exhaustion**: Signature verification flooding
- **Bandwidth exhaustion**: Bloom filter spam

### Configuration Edge Cases

- **Conflicting peers**: Same npub with different addresses; discovered vs configured conflict
- **TUN unavailable**: Permissions, kernel module; relay-only mode possibility

---

## Resolved Items (Archived)

| #   | Issue               | Resolution                                                                             |
| --- | ------------------- | -------------------------------------------------------------------------------------- |
| 1   | Coordinate ordering | Standardized on `[self, parent, ..., root]` (node→root) in all documents               |
| 5   | Cache naming        | Removed misplaced `coord_cache` from TreeState; clarified config sections              |
| 6   | Peer/Link lifecycle | Clarified: transports static, links on-demand driven by peer lifecycle                 |
| 8   | Memory bounds       | Added Resource Limits config: max_peers, max_transports, pending limits, memory budget  |
| 9   | Timer management    | Non-issue: async runtimes (tokio) handle hundreds of timers efficiently at this scale  |
| 13  | Terminology         | Standardized Transport/Link terminology in fips-design.md and fips-transports.md       |
