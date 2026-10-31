//! The floor on declaring a link dead: a node must not declare a link dead
//! sooner than 30 s after the last frame that authenticated on it, whatever
//! its own link-dead timeout (FRC-1201, Section 6.4).
//!
//! A node given a timeout below the floor runs at the floor, so a peer that
//! falls silent for less than 30 s keeps its link.

use super::rekey_parity::linked_pair;
use super::spanning_tree::cleanup_nodes;
use super::*;

/// A configuration whose link-dead timeout is `secs` and is otherwise
/// stock.
fn with_link_dead(secs: u64) -> Config {
    let mut config = Config::new();
    config.node.link_dead_timeout_secs = secs;
    config
}

/// Whether node 0 still holds node 1 after node 1 has been silent for
/// `silent` and node 0 has run its link-dead check.
async fn held_after_silence(config: Config, silent: Duration) -> bool {
    let mut nodes = linked_pair(config, Config::new()).await;
    let peer = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&peer).is_some_and(|p| p.heard()),
        "control: node 0 has heard node 1 before the silence"
    );
    crate::time::advance(silent);
    nodes[0].node.check_link_heartbeats().await;
    let held = nodes[0].node.get_peer(&peer).is_some();
    cleanup_nodes(&mut nodes).await;
    held
}

/// A node configured with a 10 s link-dead timeout runs at 30 s, so it still
/// holds a peer that has been silent for 11 s.
#[tokio::test]
async fn a_link_dead_timeout_below_30_s_never_declares_a_link_dead_11_s_after_its_last_frame() {
    assert!(
        held_after_silence(with_link_dead(10), Duration::from_secs(11)).await,
        "a node given `node.link_dead_timeout_secs` = 10 declared the link dead \
         11 s after the peer's last frame, inside the 30 s floor"
    );
}

/// Healthy path, and the control that the reaper the test above relies on is
/// alive: at the stock 30 s timeout a peer silent for 29 s is held, and one
/// silent for 31 s is declared dead.
#[tokio::test]
async fn at_the_stock_30_s_timeout_a_peer_is_held_at_29_s_of_silence_and_reaped_at_31_s() {
    assert!(
        held_after_silence(Config::new(), Duration::from_secs(29)).await,
        "the stock timeout declared a link dead inside 30 s"
    );
    assert!(
        !held_after_silence(Config::new(), Duration::from_secs(31)).await,
        "control: the stock timeout must reap a peer silent for 31 s"
    );
}
