//! The Nostr startup sweep's delay is measured on the monotonic clock: a
//! wall-clock step neither runs the sweep before its delay nor holds it
//! after. Each test freezes the monotonic clock and moves the two clocks
//! apart with `crate::time::advance` and `crate::time::step_wall`.

use crate::config::NostrRendezvousPolicy;
use crate::nostr::{NostrRendezvous, OverlayEndpointAdvert, OverlayTransportKind};
use std::sync::Arc;
use std::time::Duration;

const DELAY_SECS: u64 = 60;

async fn setup() -> (crate::Node, Arc<NostrRendezvous>) {
    let mut config = crate::Config::new();
    config.node.rendezvous.nostr.enabled = true;
    config.node.rendezvous.nostr.policy = NostrRendezvousPolicy::Open;
    config.node.rendezvous.nostr.startup_sweep_delay_secs = DELAY_SECS;
    let mut node = crate::Node::new(config).unwrap();
    node.supervisor.state = crate::node::NodeState::Running;
    let peer = crate::Identity::generate();
    let npub = crate::encode_npub(&peer.pubkey());
    let bootstrap = Arc::new(NostrRendezvous::new_for_test());
    let endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: "203.0.113.7:2121".to_string(),
    };
    let advert = NostrRendezvous::cached_advert_for_test(
        npub.clone(),
        endpoint,
        crate::time::wall_ms() / 1000,
    );
    bootstrap.insert_advert_for_test(npub, advert).await;
    crate::time::freeze();
    // The stamp the overlay start writes; it reads its own clock.
    node.supervisor.nostr_rendezvous.mark_started();
    (node, bootstrap)
}

#[tokio::test]
async fn startup_sweep_waits_out_its_delay_when_no_time_passes() {
    let (mut node, bootstrap) = setup().await;
    node.maybe_run_startup_open_discovery_sweep(&bootstrap)
        .await;
    assert!(!node.supervisor.nostr_rendezvous.startup_sweep_done());
}

#[tokio::test]
async fn startup_sweep_runs_once_the_delay_passes_on_both_clocks() {
    let (mut node, bootstrap) = setup().await;
    crate::time::advance(Duration::from_secs(DELAY_SECS + 1));
    crate::time::step_wall(((DELAY_SECS + 1) * 1000) as i64);
    node.maybe_run_startup_open_discovery_sweep(&bootstrap)
        .await;
    assert!(node.supervisor.nostr_rendezvous.startup_sweep_done());
    assert_eq!(node.peering.reconciler.retry_pending.len(), 1);
}

/// A forward wall step with no monotonic time passed must not run the sweep.
#[tokio::test]
async fn startup_sweep_does_not_run_early_after_a_forward_wall_step() {
    let (mut node, bootstrap) = setup().await;
    crate::time::step_wall(((DELAY_SECS * 2) * 1000) as i64);
    node.maybe_run_startup_open_discovery_sweep(&bootstrap)
        .await;
    assert!(
        !node.supervisor.nostr_rendezvous.startup_sweep_done(),
        "a forward wall-clock step ran the startup sweep before its delay"
    );
    assert!(node.peering.reconciler.retry_pending.is_empty());
}

/// A backward wall step must not hold the sweep once the delay has passed
/// on the monotonic clock.
#[tokio::test]
async fn startup_sweep_runs_after_its_delay_despite_a_backward_wall_step() {
    let (mut node, bootstrap) = setup().await;
    crate::time::step_wall(-(((DELAY_SECS * 10) * 1000) as i64));
    crate::time::advance(Duration::from_secs(DELAY_SECS + 1));
    crate::time::step_wall(((DELAY_SECS + 1) * 1000) as i64);
    node.maybe_run_startup_open_discovery_sweep(&bootstrap)
        .await;
    assert!(
        node.supervisor.nostr_rendezvous.startup_sweep_done(),
        "a backward wall-clock step held the startup sweep past its delay"
    );
}
