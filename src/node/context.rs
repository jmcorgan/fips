//! Shared immutable context bundle.
//!
//! [`NodeContext`] groups the [`Node`](super::Node)'s effectively-immutable
//! fields behind a single `Arc` so that handlers can eventually borrow a
//! cheap `&NodeContext` clone instead of `&self`.
//!
//! During the migration it is a *parallel, authoritative* copy of the
//! corresponding `Node` fields: both are kept in lockstep at the only three
//! mutation points — the constructor, [`update_peers`](super::Node::update_peers),
//! and the test-only `set_max_*` setters — via
//! [`Node::rebuild_context`](super::Node::rebuild_context). Readers migrate
//! onto the bundle incrementally; the duplicated `Node` fields are removed
//! once the last reader has moved over.

use std::sync::Arc;

use crate::{Config, Identity};

/// Effectively-immutable `Node` state, shared via `Arc<NodeContext>`.
#[derive(Clone)]
pub(crate) struct NodeContext {
    /// Loaded configuration. A static snapshot: replaced wholesale (never
    /// interior-mutated) when `update_peers` rebuilds the runtime peer list.
    pub config: Arc<Config>,

    /// This node's cryptographic identity.
    pub identity: Identity,

    /// Random epoch generated at startup for peer restart detection.
    // Consumed by readers migrating in a later sub-PR.
    #[allow(dead_code)]
    pub startup_epoch: [u8; 8],

    /// Instant when the node was created, for uptime reporting.
    pub started_at: std::time::Instant,

    /// Whether this is a leaf-only node.
    pub is_leaf_only: bool,

    /// Maximum connections (0 = unlimited).
    // Consumed by readers migrating in a later sub-PR.
    #[allow(dead_code)]
    pub max_connections: usize,

    /// Maximum peers (0 = unlimited).
    // Consumed by readers migrating in a later sub-PR.
    #[allow(dead_code)]
    pub max_peers: usize,

    /// Maximum links (0 = unlimited).
    // Consumed by readers migrating in a later sub-PR.
    #[allow(dead_code)]
    pub max_links: usize,
}

impl NodeContext {
    /// Build a context bundle from the individual values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<Config>,
        identity: Identity,
        startup_epoch: [u8; 8],
        started_at: std::time::Instant,
        is_leaf_only: bool,
        max_connections: usize,
        max_peers: usize,
        max_links: usize,
    ) -> Self {
        Self {
            config,
            identity,
            startup_epoch,
            started_at,
            is_leaf_only,
            max_connections,
            max_peers,
            max_links,
        }
    }
}
