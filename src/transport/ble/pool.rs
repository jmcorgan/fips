//! BLE connection pool with priority eviction.
//!
//! BLE hardware limits concurrent connections (typically 4-10). The pool
//! enforces a configurable maximum and prioritizes static (configured)
//! peers over dynamically discovered ones.

use std::collections::HashMap;

use tokio::task::JoinHandle;

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

    fn test_conn(n: u8, is_static: bool) -> BleConnection<()> {
        BleConnection {
            stream: (),
            recv_task: None,
            send_mtu: 2048,
            recv_mtu: 2048,
            established_at: tokio::time::Instant::now(),
            is_static,
            addr: test_ble_addr(n),
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
}
