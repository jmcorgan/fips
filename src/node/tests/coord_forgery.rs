//! Forged routing signals against a destination whose coordinates a lookup
//! verified.
//!
//! The attack these tests describe: a `PathBroken` naming a destination this
//! node has a session with, followed by a forged `SessionSetup` carrying a
//! different position for that destination under the same root. Every packet
//! is driven through `handle_session_datagram`, the entry point a real one
//! reaches, and the observable is the next hop `find_next_hop` picks.

use super::*;
use crate::node::tests::spanning_tree::{TestNode, cleanup_nodes, run_tree_test};
use crate::proto::fsp::SessionSetup;
use crate::proto::link::SessionDatagram;
use crate::proto::routing::PathBroken;
use crate::proto::stp::TreeCoordinate;

/// Index of the victim in the fixture's node vector.
const V: usize = 0;
/// Index of the peer the destination genuinely sits under.
const P1: usize = 1;
/// Index of the peer the forged coordinates point at.
const P2: usize = 2;

/// The victim, its two tree peers, and a destination it holds a session
/// with whose real and forged coordinates differ in the peer they hang off.
struct Fixture {
    nodes: Vec<TestNode>,
    dest: NodeAddr,
    p1: NodeAddr,
    p2: NodeAddr,
    real: TreeCoordinate,
    forged: TreeCoordinate,
}

/// Wall-clock milliseconds, the clock `handle_path_broken` and
/// `find_next_hop` read. A verification stamped on any other clock reads as
/// aged out to the handler.
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// `dest` hung directly under `parent`, sharing its root.
fn coords_under(dest: NodeAddr, parent: &TreeCoordinate) -> TreeCoordinate {
    let mut addrs = vec![dest];
    addrs.extend(parent.node_addrs().copied());
    TreeCoordinate::from_addrs(addrs).unwrap()
}

/// Install the entry `initiate_session` creates for `remote`, which is what
/// makes the admission gate accept a signal naming it.
fn install_initiating(node: &mut Node, remote: &Identity) {
    let entry = crate::node::session::SessionEntry::opened_for_test(
        &remote.pubkey_full(),
        node.identity().keypair(),
        crate::node::session::session_at(1000),
    );
    node.sessions.insert(*remote.node_addr(), entry);
}

/// Build the fixture and assert the two preconditions every test relies on.
async fn fixture() -> Fixture {
    let mut nodes = run_tree_test(3, &[(V, P1), (V, P2)], false).await;
    let p1 = *nodes[P1].node.node_addr();
    let p2 = *nodes[P2].node.node_addr();

    let remote = Identity::generate();
    let dest = *remote.node_addr();
    install_initiating(&mut nodes[V].node, &remote);

    let real = coords_under(dest, nodes[P1].node.tree_state().my_coords());
    let forged = coords_under(dest, nodes[P2].node.tree_state().my_coords());
    nodes[V]
        .node
        .coord_cache_mut()
        .insert_verified(dest, real.clone(), wall_ms());

    let mut fx = Fixture {
        nodes,
        dest,
        p1,
        p2,
        real,
        forged,
    };
    assert_eq!(
        fx.next_hop(),
        Some(fx.p1),
        "precondition: the verified coordinates route via P1"
    );
    let forged_hop = fx.nodes[V]
        .node
        .tree_state()
        .find_next_hop(&fx.forged, &std::collections::BTreeSet::new());
    assert_eq!(
        forged_hop,
        Some(fx.p2),
        "precondition: the forged coordinates would route via P2, so a \
         successful plant is visible as a flip"
    );
    fx
}

impl Fixture {
    /// The next hop the victim picks toward the destination.
    fn next_hop(&mut self) -> Option<NodeAddr> {
        let dest = self.dest;
        self.nodes[V]
            .node
            .find_next_hop(&dest)
            .map(|p| *p.node_addr())
    }

    /// The victim's cache entry for the destination: its value and whether it
    /// is still verified on the handler's clock.
    fn entry(&self) -> Option<(TreeCoordinate, bool)> {
        self.nodes[V]
            .node
            .coord_cache()
            .get_entry(&self.dest)
            .map(|e| (e.coords().clone(), e.is_verified(wall_ms())))
    }

    /// Deliver a `PathBroken` naming the destination, claiming `reporter` as
    /// both the datagram source and the body's reporter, arriving over the
    /// link to `link_peer`.
    async fn path_broken(&mut self, reporter: NodeAddr, link_peer: NodeAddr) {
        self.path_broken_from(reporter, reporter, link_peer).await;
    }

    /// Deliver a `PathBroken` naming the destination from datagram source
    /// `src`, whose body names `reporter`, arriving over the link to
    /// `link_peer`. Both identities are the sender's to choose.
    async fn path_broken_from(&mut self, src: NodeAddr, reporter: NodeAddr, link_peer: NodeAddr) {
        let victim = *self.nodes[V].node.node_addr();
        let payload = PathBroken::new(self.dest, reporter).encode();
        let encoded = SessionDatagram::new(src, victim, payload).encode();
        self.nodes[V]
            .node
            .handle_session_datagram(&link_peer, &encoded[1..], false)
            .await;
    }

    /// Deliver a forged `SessionSetup` in transit, claiming to be from the
    /// destination and carrying the forged coordinates for it, over the link
    /// to P2.
    async fn forged_setup(&mut self) {
        let payload = SessionSetup::new(self.forged.clone(), self.forged.clone()).encode();
        let encoded = SessionDatagram::new(self.dest, self.dest, payload).encode();
        let p2 = self.p2;
        self.nodes[V]
            .node
            .handle_session_datagram(&p2, &encoded[1..], false)
            .await;
    }
}

/// One forged warm against a verified destination changes nothing: the
/// precedence rule refuses the hint, and the route stays on P1.
#[tokio::test]
async fn a_forged_same_root_warm_does_not_move_the_route_to_a_verified_destination() {
    let mut fx = fixture().await;
    let rejected = fx.nodes[V]
        .node
        .metrics()
        .forwarding
        .coord_hint_rejected
        .get();

    fx.forged_setup().await;

    assert_eq!(fx.next_hop(), Some(fx.p1), "a forged warm moved the route");
    assert!(
        fx.nodes[V]
            .node
            .metrics()
            .forwarding
            .coord_hint_rejected
            .get()
            > rejected,
        "the refused hint should be counted"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// One forged `PathBroken` followed by one forged warm: the two-packet attack.
/// The signal must not strip the verification that refuses the warm.
#[tokio::test]
async fn a_forged_path_broken_then_a_forged_warm_does_not_move_the_route_to_a_verified_destination()
{
    let mut fx = fixture().await;
    let p2 = fx.p2;

    fx.path_broken(make_node_addr(0xB1), p2).await;
    fx.forged_setup().await;

    assert_eq!(
        fx.next_hop(),
        Some(fx.p1),
        "the forged warm moved the route"
    );
    assert_eq!(
        fx.entry(),
        Some((fx.real.clone(), true)),
        "the verified entry must survive one PathBroken with its value and \
         its verification"
    );
    let errors = &fx.nodes[V].node.metrics().errors;
    assert_eq!(errors.broken_below_quorum.get(), 1);
    assert_eq!(errors.broken_demoted.get(), 0);
    cleanup_nodes(&mut fx.nodes).await;
}

/// A direct forger on one link inventing two reporters is still one vote: the
/// entry stays verified and the forged warm that follows is refused. Keyed on
/// the body's reporter, the two invented names would have reached the quorum
/// and the warm would have moved the route.
#[tokio::test]
async fn a_forger_inventing_two_reporters_over_one_link_does_not_demote_a_verified_entry() {
    let mut fx = fixture().await;
    let p2 = fx.p2;

    fx.path_broken(make_node_addr(0xB1), p2).await;
    fx.path_broken(make_node_addr(0xB2), p2).await;
    fx.forged_setup().await;

    assert_eq!(
        fx.entry(),
        Some((fx.real.clone(), true)),
        "two invented reporters over one link demoted the verified entry"
    );
    assert_eq!(
        fx.next_hop(),
        Some(fx.p1),
        "the forged warm moved the route"
    );
    let errors = &fx.nodes[V].node.metrics().errors;
    assert_eq!(errors.broken_below_quorum.get(), 2);
    assert_eq!(errors.broken_demoted.get(), 0);
    cleanup_nodes(&mut fx.nodes).await;
}

/// Two genuinely different reporters whose signals both arrive over one link
/// are one vote too: what counts is the authenticated link, not the
/// reporter, nor the pair of the two.
#[tokio::test]
async fn two_reporters_over_the_same_link_do_not_reach_the_quorum() {
    let mut fx = fixture().await;
    let (p1, p2) = (fx.p1, fx.p2);

    fx.path_broken(p1, p1).await;
    fx.path_broken(p2, p1).await;

    assert_eq!(fx.entry(), Some((fx.real.clone(), true)));
    let errors = &fx.nodes[V].node.metrics().errors;
    assert_eq!(errors.broken_below_quorum.get(), 2);
    assert_eq!(errors.broken_demoted.get(), 0);
    cleanup_nodes(&mut fx.nodes).await;
}

/// Reports arriving over two different links reach the quorum and demote the
/// entry, and the forged warm that follows then moves the route. This is the
/// residual the quorum leaves: forged reports demote the entry once they
/// arrive over two different links, as a genuine failure reported from two
/// directions does. Asserted so that it stays visible.
#[tokio::test]
async fn reports_over_two_different_links_demote_a_verified_entry_and_a_following_warm_then_moves_the_route()
 {
    let mut fx = fixture().await;
    let (p1, p2) = (fx.p1, fx.p2);

    fx.path_broken(make_node_addr(0xB1), p1).await;
    fx.path_broken(make_node_addr(0xB2), p2).await;

    assert_eq!(
        fx.entry(),
        Some((fx.real.clone(), false)),
        "a demoted entry keeps its value and loses its verification"
    );
    assert_eq!(
        fx.nodes[V]
            .node
            .coord_cache()
            .get_entry(&fx.dest)
            .map(|e| e.source()),
        Some(crate::cache::CoordSource::Hint)
    );
    assert_eq!(
        fx.next_hop(),
        Some(fx.p1),
        "demotion alone does not move the route"
    );
    let errors = &fx.nodes[V].node.metrics().errors;
    assert_eq!(errors.broken_demoted.get(), 1);
    assert_eq!(errors.broken_below_quorum.get(), 1);

    fx.forged_setup().await;

    assert_eq!(
        fx.next_hop(),
        Some(fx.p2),
        "once demoted, the entry is a hint and a forged warm replaces it"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// A node with a single peer receives every report over one link, so it never
/// demotes by quorum, however many reporters the reports name. What bounds a
/// stale verified entry there is its verification age: one still inside
/// `VERIFIED_TTL_MS` is kept, one past it is removed by the next report like
/// any hint.
#[tokio::test]
async fn on_a_single_link_node_only_the_verification_age_bounds_a_verified_entry() {
    use crate::cache::VERIFIED_TTL_MS;

    // V - P1, and V holds a session with a destination beyond P1.
    let mut nodes = run_tree_test(2, &[(V, P1)], false).await;
    let p1 = *nodes[P1].node.node_addr();
    let victim = *nodes[V].node.node_addr();
    let remote = Identity::generate();
    let dest = *remote.node_addr();
    install_initiating(&mut nodes[V].node, &remote);
    let coords = coords_under(dest, nodes[P1].node.tree_state().my_coords());

    let report = |reporter: NodeAddr| {
        let payload = PathBroken::new(dest, reporter).encode();
        SessionDatagram::new(reporter, victim, payload).encode()
    };
    let verified = |node: &Node| {
        node.coord_cache()
            .get_entry(&dest)
            .map(|e| e.is_verified(wall_ms()))
    };

    // A cache TTL long enough that expiry never removes the entry, so every
    // removal below is the handler's. Ten seconds of margin inside the
    // bound, so the test's own run time cannot age the entry out before the
    // reports land.
    let cache = nodes[V].node.coord_cache_mut();
    cache.set_default_ttl_ms(4 * VERIFIED_TTL_MS);
    cache.insert_verified(dest, coords.clone(), wall_ms() - VERIFIED_TTL_MS + 10_000);
    for r in 0..5u8 {
        let encoded = report(make_node_addr(0xB0 + r));
        nodes[V]
            .node
            .handle_session_datagram(&p1, &encoded[1..], false)
            .await;
    }
    assert_eq!(
        verified(&nodes[V].node),
        Some(true),
        "reports over one link demoted or removed an entry still inside its \
         verification"
    );
    let errors = &nodes[V].node.metrics().errors;
    assert_eq!(errors.broken_below_quorum.get(), 5);
    assert_eq!(errors.broken_demoted.get(), 0);

    // Past the bound the entry no longer refuses anything, and the next
    // report removes it.
    nodes[V].node.coord_cache_mut().insert_verified(
        dest,
        coords,
        wall_ms() - VERIFIED_TTL_MS - 1_000,
    );
    assert_eq!(
        verified(&nodes[V].node),
        Some(false),
        "precondition: the entry is present and its verification has aged out"
    );
    let encoded = report(make_node_addr(0xC0));
    nodes[V]
        .node
        .handle_session_datagram(&p1, &encoded[1..], false)
        .await;
    assert_eq!(
        verified(&nodes[V].node),
        None,
        "an aged-out entry is removed"
    );
    cleanup_nodes(&mut nodes).await;
}

/// One reporter repeating itself over one link is one vote: the entry stays
/// verified and the forged warm is still refused.
#[tokio::test]
async fn one_reporter_repeating_a_path_broken_does_not_reach_the_quorum() {
    let mut fx = fixture().await;
    let p2 = fx.p2;

    fx.path_broken(make_node_addr(0xB1), p2).await;
    fx.path_broken(make_node_addr(0xB1), p2).await;
    fx.forged_setup().await;

    assert_eq!(fx.next_hop(), Some(fx.p1));
    assert_eq!(fx.entry(), Some((fx.real.clone(), true)));
    let errors = &fx.nodes[V].node.metrics().errors;
    assert_eq!(errors.broken_below_quorum.get(), 2);
    assert_eq!(errors.broken_demoted.get(), 0);
    cleanup_nodes(&mut fx.nodes).await;
}

/// A verification that has aged out protects nothing, so the entry is
/// removed as a hint would be.
#[tokio::test]
async fn a_path_broken_removes_a_verified_entry_whose_verification_has_aged_out() {
    let mut fx = fixture().await;
    let dest = fx.dest;
    let real = fx.real.clone();
    let p1 = fx.p1;
    let cache = fx.nodes[V].node.coord_cache_mut();
    // A TTL long enough that the entry is still live when its verification
    // is not, so the removal below is the handler's and not expiry's.
    cache.set_default_ttl_ms(4 * crate::cache::VERIFIED_TTL_MS);
    cache.insert_verified(
        dest,
        real,
        wall_ms() - crate::cache::VERIFIED_TTL_MS - 1_000,
    );
    assert_eq!(
        fx.entry().map(|(_, verified)| verified),
        Some(false),
        "precondition: the entry is present and no longer verified"
    );

    fx.path_broken(make_node_addr(0xB1), p1).await;

    assert!(fx.entry().is_none(), "an unverified entry is removed");
    let errors = &fx.nodes[V].node.metrics().errors;
    assert_eq!(errors.broken_below_quorum.get(), 0);
    assert_eq!(errors.broken_demoted.get(), 0);
    cleanup_nodes(&mut fx.nodes).await;
}

/// When the path-MTU release fires, a kept entry forgets the MTU the lookup
/// stored with it, so it does not go on displaying a released value.
#[tokio::test]
async fn a_kept_entry_forgets_its_path_mtu_when_the_release_fires() {
    let mut fx = fixture().await;
    let dest = fx.dest;
    let real = fx.real.clone();
    let p2 = fx.p2;
    fx.nodes[V]
        .node
        .coord_cache_mut()
        .insert_verified_with_path_mtu(dest, real, wall_ms(), 1200);

    fx.path_broken(make_node_addr(0xB1), p2).await;

    let entry = fx.nodes[V].node.coord_cache().get_entry(&dest).unwrap();
    assert!(
        entry.is_verified(wall_ms()),
        "precondition: the entry was kept"
    );
    assert_eq!(entry.path_mtu(), None);
    cleanup_nodes(&mut fx.nodes).await;
}

/// When the path-MTU release is rate limited, a kept entry keeps its MTU, as
/// the path-MTU map does: the two describe the same path and must not
/// disagree.
#[tokio::test]
async fn a_kept_entry_keeps_its_path_mtu_when_the_release_is_rate_limited() {
    let mut fx = fixture().await;
    let dest = fx.dest;
    let real = fx.real.clone();
    let p2 = fx.p2;
    let fips = crate::Ipv6Address::from_node_addr(&dest);

    // The first report spends the release budget for this destination.
    fx.path_broken(make_node_addr(0xB1), p2).await;

    // A value learned again since, in both stores.
    fx.nodes[V]
        .node
        .coord_cache_mut()
        .insert_verified_with_path_mtu(dest, real, wall_ms(), 1200);
    fx.nodes[V].node.path_mtu_lookup_insert(fips, 1200);

    // A second report inside the release interval (same link, so it stays
    // below the quorum and the entry is kept).
    fx.path_broken(make_node_addr(0xB2), p2).await;

    let node = &fx.nodes[V].node;
    let entry = node.coord_cache().get_entry(&dest).unwrap();
    assert!(
        entry.is_verified(wall_ms()),
        "precondition: the entry was kept"
    );
    assert_eq!(
        node.path_mtu_lookup_get(&fips),
        Some(1200),
        "precondition: the release was rate limited"
    );
    assert_eq!(
        entry.path_mtu(),
        Some(1200),
        "a rate-limited release cleared the kept entry's MTU but not the map's"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// The sum of the lookup counters `maybe_initiate_lookup` moves on every
/// outcome, so a test can see that it ran whatever it decided.
fn lookup_attempts(node: &Node) -> u64 {
    let l = &node.metrics().lookup;
    l.req_initiated.get()
        + l.req_bloom_miss.get()
        + l.req_deduplicated.get()
        + l.req_backoff_suppressed.get()
}

/// An admitted `PathBroken` re-validates the destination by lookup even when
/// its identity is not cached, which is the fixture's state: the session entry
/// alone does not register the identity.
#[tokio::test]
async fn an_admitted_path_broken_starts_a_lookup_without_a_cached_identity() {
    let mut fx = fixture().await;
    let dest = fx.dest;
    assert!(
        !fx.nodes[V].node.has_cached_identity(&dest),
        "precondition: the destination's identity is not cached"
    );
    let before = lookup_attempts(&fx.nodes[V].node);
    let p1 = fx.p1;

    fx.path_broken(make_node_addr(0xB1), p1).await;

    assert!(
        lookup_attempts(&fx.nodes[V].node) > before,
        "the PathBroken should have run the lookup path"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// The lookup a PathBroken starts must be answerable when the destination's
/// identity is not cached. The established session holds the key its
/// handshake authenticated, so the lookup's answer can be verified with it:
/// the position is learned, the lookup does not run to its timeout, and
/// packets queued for the destination are not dropped as unreachable when it
/// would have.
#[tokio::test]
async fn a_path_broken_without_a_cached_identity_starts_a_lookup_this_node_can_verify() {
    // V - P1 - D, with D a real node V has an established session with but
    // whose identity V has not cached.
    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
    let p1 = *nodes[1].node.node_addr();
    let dest = *nodes[2].node.node_addr();
    let _dest_pubkey = nodes[2].node.identity().pubkey_full();
    let real: Vec<NodeAddr> = nodes[2]
        .node
        .tree_state()
        .my_coords()
        .node_addrs()
        .copied()
        .collect();
    let session =
        super::session::make_noise_session(nodes[0].node.identity(), nodes[2].node.identity());
    nodes[0].node.sessions.insert(
        dest,
        crate::node::session::SessionEntry::keyed(
            dest,
            session,
            crate::node::session::session_at(1000),
            true,
        ),
    );
    assert!(
        !nodes[0].node.has_cached_identity(&dest),
        "precondition: the destination's identity is not cached"
    );
    nodes[0]
        .node
        .queue_pending_tun_packet_for_test(dest, vec![0x60; 40]);

    let lookup = &nodes[0].node.metrics().lookup;
    let (accepted, miss, timed_out) = (
        lookup.resp_accepted.get(),
        lookup.resp_identity_miss.get(),
        lookup.resp_timed_out.get(),
    );

    let victim = *nodes[0].node.node_addr();
    let payload = PathBroken::new(dest, p1).encode();
    let encoded = SessionDatagram::new(p1, victim, payload).encode();
    let start = wall_ms();
    nodes[0]
        .node
        .handle_session_datagram(&p1, &encoded[1..], false)
        .await;
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        crate::node::tests::spanning_tree::process_available_packets(&mut nodes).await;
    }

    let lookup = &nodes[0].node.metrics().lookup;
    assert_eq!(
        lookup.resp_identity_miss.get(),
        miss,
        "the lookup's answer could not be verified for want of an identity"
    );
    assert!(
        lookup.resp_accepted.get() > accepted,
        "the lookup's answer must be verified and accepted"
    );
    let entry = nodes[0].node.coord_cache().get_entry(&dest).unwrap();
    assert_eq!(
        entry.coords().node_addrs().copied().collect::<Vec<_>>(),
        real
    );
    assert!(entry.is_verified(wall_ms()));

    // Run the lookup schedule well past its end: an answered lookup has
    // nothing left to time out, so the queued packet survives.
    for step in 1..=6 {
        nodes[0]
            .node
            .check_pending_lookups(start + step * 20_000)
            .await;
    }
    assert_eq!(
        nodes[0].node.metrics().lookup.resp_timed_out.get(),
        timed_out,
        "the lookup ran to its timeout"
    );
    assert_eq!(
        nodes[0].node.pending_tun_total_packets(),
        1,
        "the packet queued for the destination was dropped"
    );
    cleanup_nodes(&mut nodes).await;
}

/// The healthy path for keeping a verified entry below quorum: a genuine
/// failure reported once is still recovered, because the lookup the report
/// starts replaces the stale value with the destination's real position.
#[tokio::test]
async fn a_genuine_path_broken_still_replaces_stale_verified_coordinates_by_lookup() {
    // V - P1 - D, with D a real node V has a session with, and a second peer
    // P2 on its own, so a later report can arrive over a different link.
    let mut nodes = run_tree_test(4, &[(0, 1), (1, 2), (0, 3)], false).await;
    let p1 = *nodes[1].node.node_addr();
    let p2 = *nodes[3].node.node_addr();
    let dest = *nodes[2].node.node_addr();
    let dest_pubkey = nodes[2].node.identity().pubkey_full();
    let real: Vec<NodeAddr> = nodes[2]
        .node
        .tree_state()
        .my_coords()
        .node_addrs()
        .copied()
        .collect();
    nodes[0].node.register_identity(dest, dest_pubkey);
    let keypair = nodes[0].node.identity().keypair();
    nodes[0].node.sessions.insert(
        dest,
        crate::node::session::SessionEntry::opened_for_test(
            &dest_pubkey,
            keypair,
            crate::node::session::session_at(1000),
        ),
    );

    // D "moved": V holds a verified position for it that is no longer true.
    let stale = coords_under(dest, nodes[0].node.tree_state().my_coords());
    assert_ne!(stale.node_addrs().copied().collect::<Vec<_>>(), real);
    nodes[0]
        .node
        .coord_cache_mut()
        .insert_verified(dest, stale, wall_ms());

    let lookup = &nodes[0].node.metrics().lookup;
    let (initiated, accepted) = (lookup.req_initiated.get(), lookup.resp_accepted.get());

    let victim = *nodes[0].node.node_addr();
    let payload = PathBroken::new(dest, p1).encode();
    let encoded = SessionDatagram::new(p1, victim, payload).encode();
    nodes[0]
        .node
        .handle_session_datagram(&p1, &encoded[1..], false)
        .await;
    assert_eq!(nodes[0].node.metrics().errors.broken_below_quorum.get(), 1);

    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        crate::node::tests::spanning_tree::process_available_packets(&mut nodes).await;
    }

    let lookup = &nodes[0].node.metrics().lookup;
    assert!(
        lookup.req_initiated.get() > initiated,
        "the report must start a lookup"
    );
    assert!(
        lookup.resp_accepted.get() > accepted,
        "the lookup must be answered"
    );
    let entry = nodes[0].node.coord_cache().get_entry(&dest).unwrap();
    assert_eq!(
        entry.coords().node_addrs().copied().collect::<Vec<_>>(),
        real,
        "the lookup must replace the stale position with the real one"
    );
    assert!(entry.is_verified(wall_ms()));

    // The lookup verified the destination again, so the report about the old
    // path no longer counts: a report over a second link now starts a new
    // quorum rather than completing the old one.
    let payload = PathBroken::new(dest, make_node_addr(0xB2)).encode();
    let encoded = SessionDatagram::new(make_node_addr(0xB2), victim, payload).encode();
    nodes[0]
        .node
        .handle_session_datagram(&p2, &encoded[1..], false)
        .await;
    let errors = &nodes[0].node.metrics().errors;
    assert_eq!(
        errors.broken_demoted.get(),
        0,
        "a report from before the re-verification combined with one after it"
    );
    assert_eq!(errors.broken_below_quorum.get(), 2);
    cleanup_nodes(&mut nodes).await;
}

/// A PathBroken arriving off the forward link is counted and still acted on
/// in full: the advisory check refuses nothing.
#[tokio::test]
async fn a_path_broken_off_the_forward_link_is_counted_and_still_acted_on() {
    let mut fx = fixture().await;
    let dest = fx.dest;
    let p2 = fx.p2;
    fx.nodes[V]
        .node
        .sessions
        .get_mut(&dest)
        .unwrap()
        .set_coords_warmup_remaining(0);
    let lookups = lookup_attempts(&fx.nodes[V].node);

    fx.path_broken(make_node_addr(0xB1), p2).await;

    let node = &fx.nodes[V].node;
    assert_eq!(node.metrics().errors.broken_link_mismatch.get(), 1);
    assert_eq!(
        node.sessions.get(&dest).unwrap().coords_warmup_remaining(),
        node.config().node.session.coords_warmup_packets,
        "the warmup counter is reset whatever the link"
    );
    assert!(
        node.config().node.session.coords_warmup_packets > 0,
        "precondition: a reset is distinguishable from the zero set above"
    );
    assert!(
        lookup_attempts(node) > lookups,
        "the lookup runs whatever the link"
    );
    assert_eq!(node.metrics().errors.broken_below_quorum.get(), 1);
    cleanup_nodes(&mut fx.nodes).await;
}

/// The same report over the forward link is not counted.
#[tokio::test]
async fn a_path_broken_over_the_forward_link_is_not_counted_as_a_mismatch() {
    let mut fx = fixture().await;
    let p1 = fx.p1;

    fx.path_broken(make_node_addr(0xB1), p1).await;

    let errors = &fx.nodes[V].node.metrics().errors;
    assert_eq!(errors.broken_link_mismatch.get(), 0);
    assert_eq!(
        errors.broken_below_quorum.get(),
        1,
        "the signal was admitted and handled, so the zero above is a real zero"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// The reporter-mismatch count after one PathBroken naming the fixture's
/// destination, reported by the address `pick` chooses, over the forward link.
async fn reporter_mismatches(pick: impl FnOnce(&Fixture) -> NodeAddr) -> u64 {
    mismatches_from(|fx| {
        let reporter = pick(fx);
        (reporter, reporter)
    })
    .await
}

/// The reporter-mismatch count after one PathBroken naming the fixture's
/// destination over the forward link, with the datagram source and the
/// body's reporter that `pick` returns, in that order.
async fn mismatches_from(pick: impl FnOnce(&Fixture) -> (NodeAddr, NodeAddr)) -> u64 {
    let mut fx = fixture().await;
    let (src, reporter) = pick(&fx);
    let p1 = fx.p1;
    fx.path_broken_from(src, reporter, p1).await;
    let errors = &fx.nodes[V].node.metrics().errors;
    assert_eq!(
        errors.broken_below_quorum.get(),
        1,
        "precondition: the signal reached the handler's verified-entry path, \
         so the count below observed it"
    );
    let n = errors.broken_reporter_mismatch.get();
    cleanup_nodes(&mut fx.nodes).await;
    n
}

#[tokio::test]
async fn a_reporter_farther_from_the_destination_than_this_node_is_counted() {
    // P2 is a direct peer on the far side of this node from P1, under which
    // the destination sits.
    assert_eq!(reporter_mismatches(|fx| fx.p2).await, 1);
}

#[tokio::test]
async fn a_reporter_closer_to_the_destination_than_this_node_is_not_counted() {
    assert_eq!(reporter_mismatches(|fx| fx.p1).await, 0);
}

#[tokio::test]
async fn a_reporter_with_unknown_coordinates_is_not_counted() {
    assert_eq!(reporter_mismatches(|_| make_node_addr(0xB1)).await, 0);
}

#[tokio::test]
async fn this_node_named_as_the_reporter_is_counted() {
    assert_eq!(
        reporter_mismatches(|fx| *fx.nodes[V].node.node_addr()).await,
        1
    );
}

/// The destination named as its own reporter cannot be reporting a broken
/// path to itself. The datagram source differs from the reporter here,
/// because a datagram claiming to come from the destination is refused by the
/// admission gate before this check is reached.
#[tokio::test]
async fn the_destination_named_as_the_reporter_is_counted() {
    assert_eq!(
        mismatches_from(|fx| (make_node_addr(0xB1), fx.dest)).await,
        1
    );
}
