//! Shared immutable context bundle.
//!
//! [`NodeContext`] groups the [`Node`](super::Node)'s effectively-immutable
//! fields behind a single `Arc` so that handlers can borrow a cheap
//! `&NodeContext` clone instead of `&self`.
//!
//! It is the **sole store** of these fields: the `Node` no longer keeps
//! duplicate copies. The bundle itself is immutable; the rare mutation of a
//! bundled field (the constructors, [`leaf_only`](super::Node::leaf_only),
//! and [`update_peers`](super::Node::update_peers)) is done by building a fresh
//! `NodeContext` and swapping the whole `Arc` via
//! [`Node::replace_context`](super::Node::replace_context). Readers reach the
//! fields through the `Node` accessors (`config()`, `identity()`,
//! `startup_epoch()`, `is_leaf_only()`, `max_*()`, `uptime()`).

use std::sync::Arc;

use crate::protocol::NodeProfile;
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
    pub startup_epoch: [u8; 8],

    /// Instant when the node was created, for uptime reporting.
    pub started_at: std::time::Instant,

    /// Whether this is a leaf-only node.
    pub is_leaf_only: bool,

    /// This node's routing profile (Full, NonRouting, Leaf).
    pub node_profile: NodeProfile,

    /// Maximum connections (0 = unlimited).
    pub max_connections: usize,

    /// Maximum peers (0 = unlimited).
    pub max_peers: usize,

    /// Maximum links (0 = unlimited).
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
        node_profile: NodeProfile,
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
            node_profile,
            max_connections,
            max_peers,
            max_links,
        }
    }
}
