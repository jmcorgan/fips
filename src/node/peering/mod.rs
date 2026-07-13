//! Peering homeostasis — the desired-state controller for the node's peer set.
//!
//! This module is the home for the peering-reconciler concept: config defines a
//! desired peer set; the reconciler converges the observed set toward it
//! (auto-connect floor, overlay pool, transport-neighbor growth) under the
//! `node.limits` ceiling. Startup and steady-state are the same loop.
//!
//! The cross-attempt retry schedule (`retry.rs`) lives here because a fresh
//! connection is created per re-dial, so the escalating backoff count must
//! persist in the reconciler, not per-connection.

pub(in crate::node) mod retry;
