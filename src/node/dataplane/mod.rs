//! Data plane: the RX `select!` loop and the per-packet forwarding path.
//!
//! Holds the whole hot path in one home: the `select!` run loop
//! (`rx_loop`), transit/local datagram forwarding (`forwarding`), the
//! link-message router (`dispatch`), the RX decrypt path including responder
//! K-bit cutover and address-roam writes (`encrypted`), and the per-peer
//! connected-UDP fast-path socket activation (`connected_udp`). Each module
//! contributes `impl Node` methods driven by the run loop.

#[cfg(unix)]
pub(crate) mod connected_udp;
mod dispatch;
mod encrypted;
mod forwarding;
mod peer_actions;
mod rx_loop;
