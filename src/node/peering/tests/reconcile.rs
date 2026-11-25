//! Claims of a node's key in the reconciler: what the layers do with
//! [`Observed::claims_in_flight_by_peer`].
//!
//! A dial made on a transport neighbour's claim is unproven, so the driver
//! leaves it out of `connecting` and `in_flight_by_peer` and counts it only
//! in `claims_in_flight_by_peer`. These tests hold the layers to that: claims
//! in flight never stop the config floor, the overlay or the LAN layer, and
//! at the peer limit they bound further claims of a connected peer.

use super::*;
use crate::identity::Identity;
use crate::node::peering::retry::peering_at;

/// A distinct random peer: its resolved identity, node address and npub.
fn peer() -> (PeerIdentity, NodeAddr, String) {
    let identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey(identity.pubkey());
    (peer, *peer.node_addr(), peer.npub())
}

/// An auto-connect configuration for `npub` at one UDP address.
fn configured(npub: &str) -> PeerConfig {
    PeerConfig {
        npub: npub.to_string(),
        alias: None,
        addresses: vec![PeerAddress::new("udp", "203.0.113.1:2121")],
        connect_policy: ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        via_nostr: false,
    }
}

/// Default-sized policy with nothing configured and open discovery off.
fn policy() -> Policy {
    Policy {
        auto_connect_peers: Vec::new(),
        max_peers: 0,
        max_connections: 0,
        max_links: 0,
        retry_base_interval_ms: 1_000,
        retry_max_backoff_ms: 60_000,
        retry_max_retries: 5,
        handshake_timeout_ms: 5_000,
        open_discovery_enabled: false,
        open_discovery_max_pending: 32,
        open_discovery_expires_ms: 600_000,
    }
}

/// Room for everything, the per-peer cap at its default of 4.
fn budget() -> Budget {
    Budget {
        handshake_slots: 1_000,
        link_slots: 1_000,
        peer_slots: 1_000,
        admission_ok: true,
        discovery_per_tick: 16,
        retry_per_tick: 16,
        per_peer_cap: 4,
    }
}

/// [`budget`] at the peer limit: admission closed for new peers.
fn at_peer_limit() -> Budget {
    Budget {
        admission_ok: false,
        peer_slots: 0,
        ..budget()
    }
}

/// `claims` claim dials in flight for `addr` and nothing else.
fn claims_for(addr: NodeAddr, claims: usize) -> Observed {
    Observed {
        claims_in_flight_by_peer: [(addr, claims)].into_iter().collect(),
        ..Observed::default()
    }
}

/// The `Connect` actions in `actions` whose candidate expects `addr`.
fn connects_to(actions: &[PeeringAction], addr: NodeAddr) -> usize {
    actions
        .iter()
        .filter(|action| {
            matches!(action, PeeringAction::Connect(c)
                if c.identity.is_some_and(|id| *id.node_addr() == addr))
        })
        .count()
}

/// A transport-neighbour candidate claiming `identity` at BLE address `n`.
fn neighbour(identity: PeerIdentity, n: u8) -> Candidate {
    Candidate {
        transport_id: TransportId::new(1),
        remote_addr: TransportAddr::from_string(&format!("hci0/AA:BB:CC:DD:EE:{n:02X}")),
        identity: Some(identity),
        active_refresh: false,
    }
}

/// The opportunistic layer's actions for `pools`.
fn opportunistic(
    budget: &Budget,
    observed: &Observed,
    pools: &DiscoveryPools,
) -> Vec<PeeringAction> {
    PeeringReconciler::default().reconcile_opportunistic(
        &policy(),
        observed,
        budget,
        pools,
        peering_at(1_000),
        Gate::Reconciling,
    )
}

// ---- Claims of a connected peer at the peer limit -------------------------

/// `count` distinct transport-neighbour paths all claiming `identity`, with
/// a discovery budget large enough that it does not bind.
fn many_claims(identity: PeerIdentity, count: u8) -> (DiscoveryPools, Budget) {
    let pools = DiscoveryPools {
        transport_neighbors: (1..=count).map(|n| neighbour(identity, n)).collect(),
        ..DiscoveryPools::default()
    };
    let budget = Budget {
        discovery_per_tick: 64,
        ..at_peer_limit()
    };
    (pools, budget)
}

#[test]
fn claims_of_a_connected_peer_at_the_peer_limit_are_held_to_the_per_peer_cap() {
    let (id, addr, _) = peer();
    let (pools, budget) = many_claims(id, 20);
    let observed = Observed {
        connected: [addr].into_iter().collect(),
        ..Observed::default()
    };
    assert_eq!(
        connects_to(&opportunistic(&budget, &observed, &pools), addr),
        4,
        "twenty claims of a connected peer at the peer limit are all dialled"
    );
}

#[test]
fn claims_of_a_connected_peer_at_the_peer_limit_wait_while_four_are_in_flight() {
    let (id, addr, _) = peer();
    let (pools, budget) = many_claims(id, 20);
    let mut observed = claims_for(addr, 4);
    observed.connected.insert(addr);
    assert_eq!(
        connects_to(&opportunistic(&budget, &observed, &pools), addr),
        0
    );
    // One finished: one more claim may go out.
    let mut observed = claims_for(addr, 3);
    observed.connected.insert(addr);
    assert_eq!(
        connects_to(&opportunistic(&budget, &observed, &pools), addr),
        1
    );
}

/// The cap counts claims only: addressed legs to the peer do not use it up.
#[test]
fn addressed_legs_to_a_connected_peer_do_not_use_up_its_claim_cap() {
    let (id, addr, _) = peer();
    let (pools, budget) = many_claims(id, 20);
    let observed = Observed {
        connected: [addr].into_iter().collect(),
        in_flight_by_peer: [(addr, 4)].into_iter().collect(),
        ..Observed::default()
    };
    assert_eq!(
        connects_to(&opportunistic(&budget, &observed, &pools), addr),
        4
    );
}

/// The cap is per claimed key: claims of a second connected peer get their
/// own four.
#[test]
fn the_claim_cap_at_the_peer_limit_is_per_claimed_key() {
    let (a, a_addr, _) = peer();
    let (b, b_addr, _) = peer();
    let pools = DiscoveryPools {
        transport_neighbors: (1..=10)
            .map(|n| neighbour(a, n))
            .chain((11..=20).map(|n| neighbour(b, n)))
            .collect(),
        ..DiscoveryPools::default()
    };
    let budget = Budget {
        discovery_per_tick: 64,
        ..at_peer_limit()
    };
    let observed = Observed {
        connected: [a_addr, b_addr].into_iter().collect(),
        ..Observed::default()
    };
    let actions = opportunistic(&budget, &observed, &pools);
    assert_eq!(connects_to(&actions, a_addr), 4);
    assert_eq!(connects_to(&actions, b_addr), 4);
}

/// While admission is open, claims are not counted against each other, as
/// before: the discovery budget is the bound.
#[test]
fn claims_with_admission_open_are_bounded_by_the_discovery_budget_only() {
    let (id, addr, _) = peer();
    let pools = DiscoveryPools {
        transport_neighbors: (1..=20).map(|n| neighbour(id, n)).collect(),
        ..DiscoveryPools::default()
    };
    assert_eq!(
        connects_to(
            &opportunistic(&budget(), &claims_for(addr, 4), &pools),
            addr
        ),
        16
    );
}

// ---- Claims in flight do not hold back other paths ------------------------

/// The config floor dials a configured peer whose only in-flight dials are
/// claims.
#[test]
fn the_config_floor_dials_a_configured_peer_while_claims_of_it_are_in_flight() {
    let (_, addr, npub) = peer();
    let mut policy = policy();
    policy.auto_connect_peers = vec![configured(&npub)];
    let actions = PeeringReconciler::default().reconcile(
        &policy,
        &claims_for(addr, 4),
        &budget(),
        &DiscoveryPools::default(),
        peering_at(10_000),
        10_000,
        Gate::Reconciling,
    );
    assert_eq!(connects_to(&actions, addr), 1);
}

/// The overlay enqueues an advertised node whose only in-flight dials are
/// claims, rather than skipping it as connecting.
#[test]
fn the_overlay_enqueues_an_advertised_node_while_claims_of_it_are_in_flight() {
    let (_, addr, npub) = peer();
    let mut policy = policy();
    policy.open_discovery_enabled = true;
    let pools = DiscoveryPools {
        overlay: vec![OverlayRow {
            npub,
            addresses: vec![
                PeerAddress::with_priority("udp", "203.0.113.7:2121", 120).with_seen_at_ms(10_000),
            ],
            created_at_secs: 0,
        }],
        ..DiscoveryPools::default()
    };
    let mut reconciler = PeeringReconciler::default();
    let (_, tally) = reconciler.reconcile_overlay(
        &policy,
        &claims_for(addr, 4),
        &budget(),
        &pools,
        peering_at(10_000),
        10_000,
        Gate::Reconciling,
    );
    assert_eq!(tally.skipped_connecting, 0);
    assert_eq!(tally.enqueued, 1);
    assert!(reconciler.retry_pending.contains_key(&addr));
}

/// The overlay expedites a configured peer's pending retry while its only
/// in-flight dials are claims.
#[test]
fn the_overlay_expedites_a_configured_peers_retry_while_claims_of_it_are_in_flight() {
    let (_, addr, npub) = peer();
    let mut policy = policy();
    policy.open_discovery_enabled = true;
    let pools = DiscoveryPools {
        overlay: vec![OverlayRow {
            npub: npub.clone(),
            addresses: Vec::new(),
            created_at_secs: 0,
        }],
        configured_npubs: [npub.clone()].into_iter().collect(),
        ..DiscoveryPools::default()
    };
    let mut reconciler = PeeringReconciler::default();
    let mut state = RetryState::new(configured(&npub));
    state.retry_after = Some(peering_at(50_000));
    reconciler.retry_pending.insert(addr, state);
    let _ = reconciler.reconcile_overlay(
        &policy,
        &claims_for(addr, 4),
        &budget(),
        &pools,
        peering_at(10_000),
        10_000,
        Gate::Reconciling,
    );
    assert_eq!(
        reconciler.retry_pending[&addr].retry_after,
        Some(peering_at(10_000))
    );
}

/// The LAN layer dials a node's held candidate while its only in-flight
/// dials are claims, however many.
#[test]
fn the_lan_layer_dials_a_candidate_while_claims_of_its_node_are_in_flight() {
    let (id, addr, _) = peer();
    let pools = DiscoveryPools {
        lan: vec![Candidate {
            transport_id: TransportId::new(2),
            remote_addr: TransportAddr::from_string("127.0.0.1:9"),
            identity: Some(id),
            active_refresh: false,
        }],
        ..DiscoveryPools::default()
    };
    assert_eq!(
        connects_to(
            &opportunistic(&budget(), &claims_for(addr, 20), &pools),
            addr
        ),
        1
    );
}
