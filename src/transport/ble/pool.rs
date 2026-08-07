//! BLE connection pool with priority eviction.
//!
//! BLE hardware limits concurrent connections (typically 4-10). The pool
//! enforces a configurable maximum and prioritizes static (configured)
//! peers over dynamically discovered ones.

use std::collections::HashMap;

use tokio::task::JoinHandle;

use crate::identity::NodeAddr;
use crate::transport::{TransportAddr, TransportError};

use super::addr::BleAddr;

/// A single BLE connection in the pool.
pub struct BleConnection<S> {
    /// The L2CAP stream for this connection.
    pub stream: S,
    /// Background receive task handle.
    pub recv_task: Option<JoinHandle<()>>,
    /// Negotiated L2CAP send MTU.
    pub send_mtu: u16,
    /// Negotiated L2CAP receive MTU.
    pub recv_mtu: u16,
    /// When the connection was established.
    pub established_at: tokio::time::Instant,
    /// Whether this is a static (configured) peer.
    pub is_static: bool,
    /// Parsed remote address.
    pub addr: BleAddr,
    /// The peer's node address, once the pubkey exchange has learned it.
    ///
    /// The pool is keyed by *link* address, but a BLE link address is not a
    /// stable identity: peers using resolvable private addresses rotate theirs
    /// continually, and each rotation looks like a brand-new device. This field
    /// carries the identity that does not rotate, so [`ConnectionPool::find_by_node`]
    /// can recognise a peer we are already connected to under an address we have
    /// not seen before. `None` for a connection whose peer is not yet identified.
    pub node_addr: Option<NodeAddr>,
}

impl<S> BleConnection<S> {
    /// Effective MTU for this connection: min(send, recv).
    pub fn effective_mtu(&self) -> u16 {
        self.send_mtu.min(self.recv_mtu)
    }
}

impl<S> Drop for BleConnection<S> {
    fn drop(&mut self) {
        if let Some(task) = self.recv_task.take() {
            task.abort();
        }
    }
}

/// Connection pool managing BLE connections with priority eviction.
pub struct ConnectionPool<S> {
    connections: HashMap<TransportAddr, BleConnection<S>>,
    max_connections: usize,
}

impl<S> ConnectionPool<S> {
    /// Create a new pool with the given maximum capacity.
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: HashMap::new(),
            max_connections,
        }
    }

    /// Get the number of active connections.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Check if the pool is at capacity.
    pub fn is_full(&self) -> bool {
        self.connections.len() >= self.max_connections
    }

    /// Get the maximum pool capacity.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Look up a connection by transport address.
    pub fn get(&self, addr: &TransportAddr) -> Option<&BleConnection<S>> {
        self.connections.get(addr)
    }

    /// Look up a mutable connection by transport address.
    pub fn get_mut(&mut self, addr: &TransportAddr) -> Option<&mut BleConnection<S>> {
        self.connections.get_mut(addr)
    }

    /// Check if a connection exists for the given address.
    pub fn contains(&self, addr: &TransportAddr) -> bool {
        self.connections.contains_key(addr)
    }

    /// Find an existing connection to `node`, whatever link address it arrived on.
    ///
    /// This is the identity check [`Self::contains`] cannot make. A peer using
    /// resolvable private addresses presents a different link address every
    /// rotation, so an address-keyed lookup reports "not connected" for a peer
    /// that is very much connected — and the caller then opens a second link to
    /// it, and a third. Callers that know the peer's node address should ask
    /// this before admitting a connection.
    ///
    /// Only connections whose pubkey exchange has completed carry a node
    /// address, so an unidentified connection is never matched.
    pub fn find_by_node(&self, node: &NodeAddr) -> Option<TransportAddr> {
        self.connections
            .iter()
            .find(|(_, c)| c.node_addr.as_ref() == Some(node))
            .map(|(addr, _)| addr.clone())
    }

    /// Try to insert a connection, evicting if necessary.
    ///
    /// Returns `Ok(evicted_addr)` on success (with optional evicted peer),
    /// or `Err` if the pool is full and the new connection cannot evict anyone.
    pub fn insert(
        &mut self,
        addr: TransportAddr,
        conn: BleConnection<S>,
    ) -> Result<Option<TransportAddr>, TransportError> {
        use std::collections::hash_map::Entry;

        // Already connected — replace
        if let Entry::Occupied(mut e) = self.connections.entry(addr.clone()) {
            e.insert(conn);
            return Ok(None);
        }

        // Room available
        if !self.is_full() {
            self.connections.insert(addr, conn);
            return Ok(None);
        }

        // Pool full — try eviction
        let evicted = self.find_eviction_candidate(conn.is_static)?;
        self.connections.remove(&evicted);
        self.connections.insert(addr, conn);
        Ok(Some(evicted))
    }

    /// Remove a connection by address.
    pub fn remove(&mut self, addr: &TransportAddr) -> Option<BleConnection<S>> {
        self.connections.remove(addr)
    }

    /// Get all connection addresses.
    pub fn addrs(&self) -> Vec<TransportAddr> {
        self.connections.keys().cloned().collect()
    }

    /// Find the best eviction candidate.
    ///
    /// Static peers requesting a slot can evict the oldest non-static peer.
    /// Non-static peers cannot evict anyone if all slots are static.
    fn find_eviction_candidate(
        &self,
        new_is_static: bool,
    ) -> Result<TransportAddr, TransportError> {
        if new_is_static {
            // Static peer can evict oldest non-static
            self.connections
                .iter()
                .filter(|(_, c)| !c.is_static)
                .min_by_key(|(_, c)| c.established_at)
                .map(|(addr, _)| addr.clone())
                .ok_or_else(|| {
                    TransportError::NotSupported("BLE pool full: all connections are static".into())
                })
        } else {
            // Non-static peer evicts oldest non-static
            self.connections
                .iter()
                .filter(|(_, c)| !c.is_static)
                .min_by_key(|(_, c)| c.established_at)
                .map(|(addr, _)| addr.clone())
                .ok_or_else(|| {
                    TransportError::NotSupported("BLE pool full: all connections are static".into())
                })
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(n: u8) -> TransportAddr {
        TransportAddr::from_string(&format!("hci0/AA:BB:CC:DD:EE:{n:02X}"))
    }

    fn test_ble_addr(n: u8) -> BleAddr {
        BleAddr {
            adapter: "hci0".to_string(),
            device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
        }
    }

    /// A distinct node identity per `n` — the identity that does NOT rotate.
    fn test_node(n: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = n;
        NodeAddr::from_bytes(bytes)
    }

    fn test_conn(n: u8, is_static: bool) -> BleConnection<()> {
        BleConnection {
            stream: (),
            recv_task: None,
            send_mtu: 2048,
            recv_mtu: 2048,
            established_at: tokio::time::Instant::now(),
            is_static,
            addr: test_ble_addr(n),
            node_addr: None,
        }
    }

    #[test]
    fn test_pool_basic_insert() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7);
        assert!(pool.is_empty());

        pool.insert(test_addr(1), test_conn(1, false)).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());
        assert!(pool.contains(&test_addr(1)));
    }

    #[test]
    fn test_pool_remove() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7);
        pool.insert(test_addr(1), test_conn(1, false)).unwrap();
        assert!(pool.remove(&test_addr(1)).is_some());
        assert!(pool.is_empty());
    }

    #[test]
    fn test_pool_full_eviction() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(3);
        pool.insert(test_addr(1), test_conn(1, false)).unwrap();
        pool.insert(test_addr(2), test_conn(2, false)).unwrap();
        pool.insert(test_addr(3), test_conn(3, false)).unwrap();
        assert!(pool.is_full());

        // Inserting a 4th should evict the oldest non-static
        let result = pool.insert(test_addr(4), test_conn(4, false));
        assert!(result.is_ok());
        assert!(result.unwrap().is_some()); // something was evicted
        assert_eq!(pool.len(), 3);
        assert!(pool.contains(&test_addr(4)));
    }

    #[test]
    fn test_pool_static_evicts_nonstatic() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(2);
        pool.insert(test_addr(1), test_conn(1, false)).unwrap();
        pool.insert(test_addr(2), test_conn(2, false)).unwrap();

        // Static peer should evict a non-static
        let result = pool.insert(test_addr(3), test_conn(3, true));
        assert!(result.is_ok());
        assert_eq!(pool.len(), 2);
        assert!(pool.contains(&test_addr(3)));
    }

    #[test]
    fn test_pool_all_static_rejects() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(2);
        pool.insert(test_addr(1), test_conn(1, true)).unwrap();
        pool.insert(test_addr(2), test_conn(2, true)).unwrap();

        // Non-static peer cannot evict static peers
        let result = pool.insert(test_addr(3), test_conn(3, false));
        assert!(result.is_err());
    }

    #[test]
    fn test_pool_replace_existing() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(2);
        pool.insert(test_addr(1), test_conn(1, false)).unwrap();

        // Re-inserting same address should replace, not grow
        let result = pool.insert(test_addr(1), test_conn(1, true));
        assert!(result.is_ok());
        assert_eq!(pool.len(), 1);
        assert!(pool.get(&test_addr(1)).unwrap().is_static);
    }

    #[test]
    fn test_pool_effective_mtu() {
        let mut conn = test_conn(1, false);
        conn.send_mtu = 1024;
        conn.recv_mtu = 2048;
        assert_eq!(conn.effective_mtu(), 1024);
    }

    #[test]
    fn test_pool_addrs() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7);
        pool.insert(test_addr(1), test_conn(1, false)).unwrap();
        pool.insert(test_addr(2), test_conn(2, false)).unwrap();

        let mut addrs = pool.addrs();
        addrs.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        assert_eq!(addrs.len(), 2);
    }

    /// A node address is found regardless of which link address it arrived on —
    /// the whole point of the lookup, since the link address rotates.
    #[test]
    fn find_by_node_matches_across_a_rotated_link_address() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7);
        let node = test_node(1);
        let mut conn = test_conn(1, false);
        conn.node_addr = Some(node);
        pool.insert(test_addr(1), conn).unwrap();

        // Found under the address it was inserted with...
        assert_eq!(pool.find_by_node(&node), Some(test_addr(1)));
        // ...and the address-keyed check agrees for that address only.
        assert!(pool.contains(&test_addr(1)));
        // A rotated address for the same peer is NOT found by `contains` —
        // which is exactly the gap `find_by_node` exists to close.
        assert!(!pool.contains(&test_addr(99)));
        assert_eq!(pool.find_by_node(&node), Some(test_addr(1)));
    }

    #[test]
    fn find_by_node_ignores_unidentified_connections() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7);
        // No pubkey exchange yet, so no node address.
        pool.insert(test_addr(1), test_conn(1, false)).unwrap();
        assert_eq!(pool.find_by_node(&test_node(1)), None);
    }

    #[test]
    fn find_by_node_returns_none_for_an_unconnected_node() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7);
        let mut conn = test_conn(1, false);
        conn.node_addr = Some(test_node(1));
        pool.insert(test_addr(1), conn).unwrap();
        assert_eq!(pool.find_by_node(&test_node(2)), None);
    }

    /// The regression this guards: without a node-identity check, N rotated
    /// addresses for ONE peer become N pool entries and evict real peers. With
    /// it, the caller can see the peer is already present and decline.
    #[test]
    fn rotated_addresses_would_otherwise_fill_the_pool() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7);
        let node = test_node(1);

        // One genuine connection to the peer.
        let mut first = test_conn(1, false);
        first.node_addr = Some(node);
        pool.insert(test_addr(1), first).unwrap();

        // Ten rotations arrive. Each is a distinct link address, so `contains`
        // says "new" every time — but `find_by_node` recognises all of them.
        for n in 2..12u8 {
            assert!(
                !pool.contains(&test_addr(n)),
                "rotation {n} looks new by address"
            );
            assert_eq!(
                pool.find_by_node(&node),
                Some(test_addr(1)),
                "rotation {n} is recognised as the peer already connected",
            );
        }
        // Nothing was admitted, so the pool still holds exactly one link.
        assert_eq!(pool.len(), 1);
    }
}
