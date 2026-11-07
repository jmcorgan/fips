//! What the operator is shown of a link's paths at the node, and the pin:
//! the link cost a peer row carries while a change of active path holds
//! it, the `paths` array of each peer row, on the loop and in the published
//! snapshot, and the control socket's `path_show`, `path_pin` and
//! `path_unpin`, called on the node and, once, through the control
//! protocol over an in-memory stream. Loopback nodes only, and no socket.

use super::paths::{
    active_of, carrier, disabled, enabled, loopback_mut, report_body, same_transport,
    same_transport_with, second_transport, shut_p, state_at, t2, two_transports,
};
use super::rekey_parity::{deliver, linked_pair};
use super::spanning_tree::{TestNode, cleanup_nodes, process_available_packets};
use super::*;
use crate::control::protocol::Request;
use crate::control::queries::{show_peers, show_peers_from_handle};
use crate::control::read_handle::snapshot_dispatch;
use crate::node::handlers::path::PATH_TICK;
use crate::peer::{PathState, peer_now};
use crate::time::deadline;
use crate::transport::TransportType;
use fips_core::proto::path::wire::{PathClose, PathCloseReason};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};

/// The path requests `fipsctl` builds, with their command lines, which
/// `fipsctl`'s own test reads too: `<npub>` stands for the peer and
/// `<addr>` for the peer's address on the second transport.
const REQUESTS: &str = include_str!("../../control/snapshots/fipsctl_path_requests.json");

/// The keys of a one-path peer's `show_peers` row before the `paths`
/// array, as the base renders them, both on the loop and off it.
const BASE_KEYS: [&str; 27] = [
    "authenticated_at_ms",
    "connectivity",
    "consecutive_decrypt_failures",
    "current_k_bit",
    "direction",
    "display_name",
    "effective_depth",
    "filter_sequence",
    "has_bloom_filter",
    "has_tree_position",
    "ipv6_addr",
    "is_child",
    "is_parent",
    "last_seen_ms",
    "link_id",
    "mmp",
    "node_addr",
    "noise",
    "nostr_traversal",
    "npub",
    "our_session_index",
    "replay_suppressed",
    "replay_suppressed_total",
    "stats",
    "transport_addr",
    "transport_type",
    "tree_depth",
];

/// A switch dwell far longer than any run of these tests, so that only
/// simulated time ends a cost hold, never a stall of the host.
const LONG_DWELL: Duration = Duration::from_secs(3_600);

/// A configuration with multipath enabled and a switch dwell of
/// [`LONG_DWELL`].
fn long_dwell() -> Config {
    let mut config = enabled();
    config.node.path.switch.dwell_secs = LONG_DWELL.as_secs();
    config
}

/// The row of the peer `npub` at `tn`, rendered on the loop and from the
/// snapshot the node publishes, which is published first.
fn rows(tn: &mut TestNode, npub: &str) -> (Value, Value) {
    tn.node.record_stats_history();
    let on = show_peers(&tn.node);
    let off = show_peers_from_handle(&tn.node.control_read_handle());
    let pick = |all: &Value| {
        all["peers"]
            .as_array()
            .expect("show_peers lists its peers")
            .iter()
            .find(|row| row["npub"] == npub)
            .cloned()
            .expect("the peer has a row")
    };
    (pick(&on), pick(&off))
}

/// Set the measured ETX of A's (node 0) link to `peer` to `etx`, with a
/// 20 ms round trip.
fn measure(nodes: &mut [TestNode], peer: &NodeAddr, etx: f64) {
    let mmp = nodes[0].node.get_peer_mut(peer).unwrap().mmp_mut().unwrap();
    mmp.metrics.etx = etx;
    mmp.metrics.srtt.update(20_000);
}

/// While a change of active path holds the link's cost, the peer row the
/// loop renders and the one the snapshot publishes both rank the peer on
/// the cost from before the change, and agree, at a moment when only the
/// dwell, an instant in time, still holds it.
#[tokio::test]
async fn the_loop_and_the_snapshot_show_the_cost_held_across_a_switch() {
    let (mut nodes, b, b2) = same_transport_with(long_dwell()).await;
    let t1 = nodes[0].transport_id;
    let npub = nodes[1].node.npub();
    measure(&mut nodes, &b, 1.0);
    let before = nodes[0].node.get_peer(&b).unwrap().link_cost();

    shut_p(&mut nodes, &b, &b2).await;
    assert_eq!(active_of(&nodes[0], &b), (t1, b2), "A moved to q");
    measure(&mut nodes, &b, 3.0);
    let a = &mut nodes[0].node;
    a.handle_receiver_report(&b, &report_body(1_000_000)).await;
    a.handle_receiver_report(&b, &report_body(2_000_000)).await;

    let peer = nodes[0].node.get_peer(&b).unwrap();
    let live = peer.live_cost();
    assert_eq!(peer.link_cost(), before, "precondition: the cost is held");
    assert_ne!(live, before, "precondition: the measured cost moved");
    let past = deadline(peer_now(), LONG_DWELL + Duration::from_secs(1));
    assert_eq!(
        peer.bundle().unwrap().cost(past, live),
        live,
        "precondition: both reports are in, so only the dwell holds the cost"
    );

    let (on, off) = rows(&mut nodes[0], &npub);
    let depth = on["tree_depth"]
        .as_u64()
        .expect("precondition: B has a tree position at A");
    let held = depth as f64 + before;
    assert_eq!(
        on["effective_depth"].as_f64(),
        Some(held),
        "the loop shows the held cost"
    );
    assert_eq!(
        off["effective_depth"].as_f64(),
        Some(held),
        "the snapshot shows the held cost"
    );
    assert_eq!(on, off, "the two renders agree");
    cleanup_nodes(&mut nodes).await;
}

/// The sorted keys of a row.
fn keys(row: &Value) -> Vec<String> {
    let mut keys: Vec<String> = row.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

/// The `paths` entries of a row.
fn paths_of(row: &Value) -> &Vec<Value> {
    row["paths"].as_array().expect("the row lists its paths")
}

/// A peer on a link of one path, as with multipath off, keeps every field
/// of its row and lists that one path, with the link's transport and
/// address, live, active and unpinned, the same on the loop and off it.
#[tokio::test]
async fn a_one_path_peer_row_keeps_every_field_and_lists_its_one_path() {
    let mut nodes = linked_pair(disabled(), disabled()).await;
    let npub = nodes[1].node.npub();
    let t1 = nodes[0].transport_id;
    let (on, off) = rows(&mut nodes[0], &npub);
    let mut expected: Vec<String> = BASE_KEYS.iter().map(|k| k.to_string()).collect();
    expected.push("paths".to_string());
    expected.sort();
    for (render, row) in [("on the loop", &on), ("off the loop", &off)] {
        assert_eq!(keys(row), expected, "the row's keys {render}");
        let paths = paths_of(row);
        assert_eq!(paths.len(), 1, "one path {render}");
        let path = &paths[0];
        assert_eq!(path["transport_id"], t1.as_u32(), "{render}");
        assert_eq!(path["addr"], row["transport_addr"], "{render}");
        assert_eq!(path["transport_type"], row["transport_type"], "{render}");
        assert_eq!(path["state"], "live", "{render}");
        assert_eq!(path["active"], true, "{render}");
        assert_eq!(path["role"], "normal", "{render}");
        assert_eq!(path["pinned"], false, "{render}");
    }
    assert_eq!(on, off, "the two renders agree");
    cleanup_nodes(&mut nodes).await;
}

/// A peer on a link of two paths lists both in its row, on the loop and
/// off it: both live, one active, each with its transport and a score,
/// and the path the peer sends on marked as the peer's.
#[tokio::test]
async fn show_peers_lists_every_path_on_and_off_loop() {
    let (mut nodes, _b, _a2, _b2) = two_transports(1280).await;
    let npub = nodes[1].node.npub();
    let t1 = nodes[0].transport_id;
    let (on, off) = rows(&mut nodes[0], &npub);
    for (render, row) in [("on the loop", &on), ("off the loop", &off)] {
        let paths = paths_of(row);
        assert_eq!(paths.len(), 2, "two paths {render}: {paths:?}");
        let mut ids: Vec<u64> = paths
            .iter()
            .map(|p| p["transport_id"].as_u64().unwrap())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, [1, 2], "{render}");
        let active: Vec<&Value> = paths.iter().filter(|p| p["active"] == true).collect();
        assert_eq!(active.len(), 1, "one active path {render}");
        assert_eq!(active[0]["transport_id"], t1.as_u32(), "{render}");
        for path in paths {
            assert_eq!(path["state"], "live", "{render}: {path}");
            assert_eq!(path["transport_type"], "loopback", "{render}: {path}");
            assert!(path["score"].is_number(), "{render}: {path}");
        }
        let p = paths
            .iter()
            .find(|p| p["transport_id"] == t1.as_u32())
            .unwrap();
        assert_eq!(p["remote_active"], true, "B sends on p, {render}");
    }
    assert_eq!(on, off, "the two renders agree");
    cleanup_nodes(&mut nodes).await;
}

/// A peer row's `transport_type` is the type of the link's own transport:
/// after the link moves to a path on another transport it still names the
/// first, beside the active path's address, and once that transport and
/// its handle are removed the row has no `transport_type` at all, while
/// the `paths` entry names each path's own type.
#[tokio::test]
async fn a_peer_rows_transport_type_is_the_links_after_a_switch_and_absent_once_its_transport_is_gone()
 {
    let (mut nodes, b, _a2, b2) = two_transports(1280).await;
    let npub = nodes[1].node.npub();
    let t1 = nodes[0].transport_id;
    carrier(&mut nodes, t1, true).await;
    carrier(&mut nodes, t1, false).await;
    assert_eq!(
        active_of(&nodes[0], &b),
        (t2(), b2.clone()),
        "precondition: carrier loss moved A to q"
    );
    loopback_mut(&mut nodes[0], t2()).typed(TransportType::UDP);
    let (on, off) = rows(&mut nodes[0], &npub);
    for (render, row) in [("on the loop", &on), ("off the loop", &off)] {
        assert_eq!(row["transport_type"], "loopback", "the link's, {render}");
        assert_eq!(row["transport_addr"], b2.to_string(), "q's, {render}");
        let q = paths_of(row)
            .iter()
            .find(|p| p["transport_id"] == t2().as_u32())
            .expect("q is listed");
        assert_eq!(q["transport_type"], "udp", "q's own, {render}");
    }

    nodes[0].node.path_removed(t1).await;
    if let Some(mut handle) = nodes[0].node.transports.remove(&t1) {
        let _ = handle.stop().await;
    }
    let (on, off) = rows(&mut nodes[0], &npub);
    for (render, row) in [("on the loop", &on), ("off the loop", &off)] {
        assert!(row.get("transport_type").is_none(), "{render}: {row}");
        assert_eq!(row["direction"], "outbound", "{render}");
        assert_eq!(row["transport_addr"], b2.to_string(), "q's, {render}");
    }
    cleanup_nodes(&mut nodes).await;
}

/// B (node 1) closes A's path to `to` on `transport`, sending the
/// `PathClose` on its own active path, and A handles it.
async fn close_at_a(nodes: &mut [TestNode], transport: TransportId, to: &TransportAddr) {
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    let paths = nodes[0]
        .node
        .get_peer(&b)
        .unwrap()
        .bundle()
        .unwrap()
        .paths();
    let path_id = paths
        .get(paths.find(transport, to).unwrap())
        .unwrap()
        .path_id();
    let close = PathClose {
        path_id,
        reason: PathCloseReason::Operator,
    };
    nodes[1]
        .node
        .send_encrypted_link_message(&a, &close.encode())
        .await
        .expect("B's close goes out");
    deliver(&mut nodes[0]).await;
}

/// Run both nodes' path ticks in steps of five ticks of simulated time,
/// handing every frame across after each, until A's path to `to` on
/// `transport` is Live again; at most 90 s of simulated time, a setup
/// bound that covers the Dead path's probe cadence.
async fn revive(nodes: &mut [TestNode], transport: TransportId, to: &TransportAddr) {
    let b = *nodes[1].node.node_addr();
    let mut waited = Duration::ZERO;
    while state_at(&nodes[0], &b, transport, to) != Some(PathState::Live) {
        assert!(
            waited < Duration::from_secs(90),
            "setup bound: the path is not Live again after {waited:?}"
        );
        let step = PATH_TICK * 5;
        crate::time::advance(step);
        waited += step;
        nodes[0].node.path_tick().await;
        nodes[1].node.path_tick().await;
        let mut passes = 0;
        while process_available_packets(nodes).await > 0 {
            passes += 1;
            assert!(passes < 16, "setup bound: the frames do not settle");
        }
    }
}

/// The pin `path_show` reports for `npub` at `tn`.
fn shown_pin(tn: &TestNode, npub: &str) -> Value {
    tn.node.show_paths(npub).expect("path_show")["pin"].clone()
}

/// A pin naming one path by its transport and address takes the link to
/// it at once; while that path is Dead the pin is kept, suspended, and the
/// link runs on the other path; once it is Live again the pin applies
/// again and the link goes back to it.
#[tokio::test]
async fn a_pin_by_pair_takes_the_link_to_that_path_is_suspended_while_it_is_down_and_applies_again()
{
    let (mut nodes, b, b2) = same_transport().await;
    let npub = nodes[1].node.npub();
    let t1 = nodes[0].transport_id;
    let b1 = nodes[1].addr.clone();
    assert_eq!(active_of(&nodes[0], &b), (t1, b1.clone()), "precondition");

    let reply = nodes[0]
        .node
        .pin_path(&npub, "1", Some(&b2.to_string()))
        .await
        .expect("the pin is taken");
    assert_eq!(reply["pinned"]["in_force"], true, "{reply}");
    assert_eq!(active_of(&nodes[0], &b), (t1, b2.clone()), "A on q at once");
    assert_eq!(reply["pinned"]["addr"], b2.to_string(), "{reply}");
    let shown = nodes[0].node.show_paths(&npub).unwrap();
    for path in shown["paths"].as_array().unwrap() {
        let q = path["addr"] == b2.to_string();
        assert_eq!(path["pinned"], q, "only q is pinned: {path}");
    }

    close_at_a(&mut nodes, t1, &b2).await;
    assert_eq!(state_at(&nodes[0], &b, t1, &b2), Some(PathState::Dead));
    assert_eq!(active_of(&nodes[0], &b), (t1, b1.clone()), "A on p");
    let pin = shown_pin(&nodes[0], &npub);
    assert_eq!(pin["addr"], b2.to_string(), "the pin is kept: {pin}");
    assert_eq!(pin["in_force"], false, "and suspended: {pin}");

    revive(&mut nodes, t1, &b2).await;
    assert_eq!(active_of(&nodes[0], &b), (t1, b2), "A back on q");
    assert_eq!(shown_pin(&nodes[0], &npub)["in_force"], true);
    cleanup_nodes(&mut nodes).await;
}

/// A pin naming a transport is suspended while no path on it is Live, and
/// is lifted when the transport is removed.
#[tokio::test]
async fn a_pin_by_transport_ends_when_its_transport_is_removed() {
    let (mut nodes, b, _a2, b2) = two_transports(1280).await;
    let npub = nodes[1].node.npub();
    let t1 = nodes[0].transport_id;
    let b1 = nodes[1].addr.clone();

    nodes[0]
        .node
        .pin_path(&npub, "2", None)
        .await
        .expect("the pin is taken");
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2.clone()), "A on q");
    assert_eq!(
        shown_pin(&nodes[0], &npub),
        json!({"transport_id": 2, "transport": null, "addr": null, "in_force": true})
    );

    close_at_a(&mut nodes, t2(), &b2).await;
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), Some(PathState::Dead));
    assert_eq!(active_of(&nodes[0], &b), (t1, b1.clone()), "A on p");
    assert_eq!(
        shown_pin(&nodes[0], &npub),
        json!({"transport_id": 2, "transport": null, "addr": null, "in_force": false}),
        "the transport's pin is kept, suspended"
    );

    nodes[0].node.path_removed(t2()).await;
    if let Some(mut handle) = nodes[0].node.transports.remove(&t2()) {
        let _ = handle.stop().await;
    }
    assert_eq!(
        shown_pin(&nodes[0], &npub),
        Value::Null,
        "the pin ends with its transport"
    );
    assert_eq!(active_of(&nodes[0], &b), (t1, b1), "A on p");
    let reply = nodes[0].node.unpin_path(&npub).await.unwrap();
    assert_eq!(reply, json!({"pinned": null}));
    cleanup_nodes(&mut nodes).await;
}

/// A pin takes a transport by its instance name. Names are per transport
/// type, so transports of two types can carry one name; a pin by that
/// name is refused, naming the ids that carry it, and sets no pin, and a
/// pin by one of those ids is taken.
#[tokio::test]
async fn a_pin_by_name_takes_that_transport_and_a_name_two_transports_share_is_refused_for_an_id() {
    let (mut nodes, b, _a2, b2) = two_transports(1280).await;
    let npub = nodes[1].node.npub();
    let t1 = nodes[0].transport_id;
    let b1 = nodes[1].addr.clone();
    loopback_mut(&mut nodes[0], t1).typed(TransportType::UDP);
    loopback_mut(&mut nodes[0], t1).set_name("main");
    loopback_mut(&mut nodes[0], t2()).typed(TransportType::TCP);
    loopback_mut(&mut nodes[0], t2()).set_name("spare");

    let reply = nodes[0]
        .node
        .pin_path(&npub, "spare", None)
        .await
        .expect("the pin by a name one transport carries is taken");
    assert_eq!(reply["pinned"]["transport_id"], 2, "{reply}");
    assert_eq!(reply["pinned"]["transport"], "spare", "{reply}");
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2), "A on q");
    nodes[0].node.unpin_path(&npub).await.unwrap();

    loopback_mut(&mut nodes[0], t2()).set_name("main");
    assert_eq!(
        nodes[0].node.pin_path(&npub, "main", None).await,
        Err(
            "transport name 'main' is shared by transports 1 (udp), 2 (tcp); give one by id"
                .to_string()
        ),
        "a name two transports carry is refused"
    );
    assert!(
        nodes[0]
            .node
            .get_peer(&b)
            .unwrap()
            .bundle()
            .unwrap()
            .pin()
            .is_none(),
        "a refused name sets no pin"
    );

    let reply = nodes[0]
        .node
        .pin_path(&npub, "1", None)
        .await
        .expect("the pin by one of its ids is taken");
    assert_eq!(
        reply["pinned"],
        json!({"transport_id": 1, "transport": "main", "addr": null, "in_force": true})
    );
    assert_eq!(active_of(&nodes[0], &b), (t1, b1), "A on p");
    cleanup_nodes(&mut nodes).await;
}

/// A name transports share that is itself the id of one of them takes
/// that transport, which no other text could select; a shared name that
/// is not one of their ids, numeric or not, is still refused and sets no
/// pin, even when it is the id of another transport the node holds.
#[tokio::test]
async fn a_shared_name_that_is_one_of_its_transports_ids_takes_it_and_any_other_is_refused() {
    let (mut nodes, b, _a2, b2) = two_transports(1280).await;
    let npub = nodes[1].node.npub();
    let t1 = nodes[0].transport_id;
    let b1 = nodes[1].addr.clone();
    loopback_mut(&mut nodes[0], t1).typed(TransportType::UDP);
    loopback_mut(&mut nodes[0], t2()).typed(TransportType::TCP);
    let name_both = |a: &mut TestNode, name: &str| {
        loopback_mut(a, t1).set_name(name);
        loopback_mut(a, t2()).set_name(name);
    };

    name_both(&mut nodes[0], "2");
    let reply = nodes[0]
        .node
        .pin_path(&npub, "2", None)
        .await
        .expect("a shared name that is transport 2's id takes transport 2");
    assert_eq!(
        reply["pinned"],
        json!({"transport_id": 2, "transport": "2", "addr": null, "in_force": true})
    );
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2), "A on q");
    nodes[0].node.unpin_path(&npub).await.unwrap();

    name_both(&mut nodes[0], "1");
    let reply = nodes[0]
        .node
        .pin_path(&npub, "1", None)
        .await
        .expect("a shared name that is transport 1's id takes transport 1");
    assert_eq!(
        reply["pinned"],
        json!({"transport_id": 1, "transport": "1", "addr": null, "in_force": true})
    );
    assert_eq!(active_of(&nodes[0], &b), (t1, b1), "A on p");
    nodes[0].node.unpin_path(&npub).await.unwrap();

    for name in ["7", "main"] {
        name_both(&mut nodes[0], name);
        assert_eq!(
            nodes[0].node.pin_path(&npub, name, None).await,
            Err(format!(
                "transport name '{name}' is shared by transports 1 (udp), 2 (tcp); give one by id"
            )),
            "a shared name that is not one of their ids is refused"
        );
        assert!(
            nodes[0]
                .node
                .get_peer(&b)
                .unwrap()
                .bundle()
                .unwrap()
                .pin()
                .is_none(),
            "a refused name sets no pin"
        );
    }

    let t3 = TransportId::new(3);
    second_transport(&mut nodes[0], t3, 1280);
    loopback_mut(&mut nodes[0], t3).typed(TransportType::ETHERNET);
    loopback_mut(&mut nodes[0], t1).set_name("2");
    loopback_mut(&mut nodes[0], t2()).set_name("spare");
    loopback_mut(&mut nodes[0], t3).set_name("2");
    assert_eq!(
        nodes[0].node.pin_path(&npub, "2", None).await,
        Err(
            "transport name '2' is shared by transports 1 (udp), 3 (ethernet); give one by id"
                .to_string()
        ),
        "a shared name that is the id of a transport not carrying it is refused"
    );
    assert!(
        nodes[0]
            .node
            .get_peer(&b)
            .unwrap()
            .bundle()
            .unwrap()
            .pin()
            .is_none(),
        "a refused name sets no pin"
    );
    cleanup_nodes(&mut nodes).await;
}

/// The path commands refuse a malformed npub, a peer not held and a
/// transport not held, and refuse to pin or unpin on a node with
/// multipath off, where a pin would do nothing.
#[tokio::test]
async fn the_path_commands_refuse_an_unknown_peer_or_transport_and_a_pin_with_multipath_off() {
    let (mut nodes, _b, _b2) = same_transport().await;
    let npub = nodes[1].node.npub();
    let a = &mut nodes[0].node;
    let err = a.show_paths("npub1nonsense").unwrap_err();
    assert!(err.starts_with("invalid npub 'npub1nonsense'"), "{err}");
    let stranger = crate::Identity::generate().npub();
    assert_eq!(
        a.show_paths(&stranger).unwrap_err(),
        format!("peer not found: {stranger}")
    );
    assert_eq!(
        a.pin_path(&npub, "no-such-transport", None)
            .await
            .unwrap_err(),
        "transport not found: no-such-transport"
    );
    cleanup_nodes(&mut nodes).await;

    let mut nodes = linked_pair(disabled(), disabled()).await;
    let b = *nodes[1].node.node_addr();
    let npub = nodes[1].node.npub();
    let a = &mut nodes[0].node;
    let refused = "multipath is disabled on this node".to_string();
    assert_eq!(a.pin_path(&npub, "1", None).await, Err(refused.clone()));
    assert_eq!(a.unpin_path(&npub).await, Err(refused));
    assert!(
        a.get_peer(&b).unwrap().bundle().unwrap().pin().is_none(),
        "no pin is set"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Send `line` through the control protocol as the node's socket serves
/// it, off the loop from the read handle when it can be and otherwise on
/// the loop, over an in-memory stream, and return the reply as `fipsctl`
/// parses it.
async fn round_trip(node: &mut Node, line: &str) -> Value {
    let handle = node.control_read_handle();
    let dispatch = move |request: Request| async move {
        if let Some(reply) = snapshot_dispatch(&request, &handle) {
            return reply;
        }
        crate::control::commands::dispatch(node, &request.command, request.params.as_ref()).await
    };
    let (mut client, server) = duplex(64 * 1024);
    client.write_all(line.as_bytes()).await.unwrap();
    let (served, reply) = tokio::join!(crate::control::serve(server, dispatch), async {
        let mut reply = String::new();
        BufReader::new(&mut client)
            .read_line(&mut reply)
            .await
            .unwrap();
        reply
    });
    assert!(served.unwrap(), "the reply is written");
    serde_json::from_str(&reply).expect("the reply is one JSON line")
}

/// The path requests `fipsctl` builds are taken by the node through the
/// control protocol, on the loop, and answered as `fipsctl` reads them:
/// the pin, the link's paths with every key, the pin lifted, and then
/// `show_peers`, off the loop, lists the peer's two paths.
#[tokio::test]
async fn fipsctls_path_and_peer_requests_round_trip_through_the_control_protocol() {
    let (mut nodes, _b, _a2, b2) = two_transports(1280).await;
    let npub = nodes[1].node.npub();
    let fixture = REQUESTS
        .replace("<npub>", &npub)
        .replace("<addr>", &b2.to_string());
    let cases: Vec<Value> = serde_json::from_str(&fixture).unwrap();
    let mut replies = Vec::new();
    let handle = nodes[0].node.control_read_handle();
    for case in &cases {
        let request: Request = serde_json::from_value(case["request"].clone()).unwrap();
        assert!(
            snapshot_dispatch(&request, &handle).is_none(),
            "{} is served on the loop",
            request.command
        );
        let line = format!("{}\n", case["request"]);
        let reply = round_trip(&mut nodes[0].node, &line).await;
        assert_eq!(reply["status"], "ok", "{line}: {reply}");
        replies.push((request.command, reply["data"].clone()));
    }
    let commands: Vec<&str> = replies.iter().map(|(c, _)| c.as_str()).collect();
    assert_eq!(commands, ["path_pin", "path_show", "path_unpin"]);

    let pinned = &replies[0].1["pinned"];
    assert_eq!(pinned["addr"], b2.to_string(), "{pinned}");
    assert_eq!(pinned["in_force"], true, "{pinned}");

    let shown = &replies[1].1;
    assert_eq!(shown["peer"], npub);
    assert_eq!(shown["enabled"], true, "{shown}");
    assert_eq!(shown["capable"], true, "{shown}");
    assert_eq!(
        shown["link_cost_held"], true,
        "the pin's switch holds the cost"
    );
    assert!(shown["link_cost"].is_number(), "{shown}");
    assert_eq!(shown["pin"]["in_force"], true, "{shown}");
    let paths = shown["paths"].as_array().expect("data.paths");
    assert_eq!(paths.len(), 2, "{shown}");
    let mut keys: Vec<&str> = [
        "transport_id",
        "transport",
        "transport_type",
        "addr",
        "state",
        "active",
        "remote_active",
        "role",
        "pinned",
        "last_rtt_ms",
        "min_rtt_ms",
        "rtt_samples",
        "etx",
        "score",
        "path_id",
        "acked",
        "heard_ms_ago",
        "unanswered",
        "mtu",
        "rx_frames",
        "rx_bytes",
        "auth_failures",
    ]
    .to_vec();
    keys.sort_unstable();
    for path in paths {
        let mut have: Vec<&str> = path
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        have.sort_unstable();
        assert_eq!(have, keys, "{path}");
        assert_eq!(path["state"], "live", "{path}");
        assert_eq!(path["acked"], true, "{path}");
    }

    assert_eq!(replies[2].1, json!({"pinned": null}));

    nodes[0].node.record_stats_history();
    let peers = round_trip(&mut nodes[0].node, "{\"command\":\"show_peers\"}\n").await;
    let row = peers["data"]["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["npub"] == npub)
        .expect("B's row");
    assert_eq!(paths_of(row).len(), 2, "{row}");
    cleanup_nodes(&mut nodes).await;
}

/// A node left at the default setting, multipath on, answers `path_show`
/// through the control protocol: the link is shown with multipath enabled,
/// the peer not yet capable, and its one path, the one the handshake made,
/// active. A node with multipath off states it and is shown the same way
/// with multipath disabled. A peer held with no path machine would be shown
/// with no paths at all, so the one path tells the two apart.
#[tokio::test]
async fn path_show_at_the_default_shows_multipath_on_and_when_off_the_links_one_active_path() {
    assert!(
        Config::new().node.path.enabled,
        "precondition: multipath is on by default"
    );
    for (config, enabled) in [(Config::new(), true), (disabled(), false)] {
        let mut nodes = linked_pair(config.clone(), config).await;
        let npub = nodes[1].node.npub();
        let b1 = nodes[1].addr.clone();
        let t1 = nodes[0].transport_id;
        let line = format!(
            "{}\n",
            json!({ "command": "path_show", "params": { "npub": npub } })
        );
        let reply = round_trip(&mut nodes[0].node, &line).await;
        assert_eq!(reply["status"], "ok", "{reply}");
        let shown = &reply["data"];
        assert_eq!(shown["peer"], npub, "{shown}");
        assert_eq!(shown["enabled"], enabled, "{shown}");
        assert_eq!(shown["capable"], false, "{shown}");
        assert!(shown["pin"].is_null(), "{shown}");
        let paths = shown["paths"].as_array().expect("data.paths");
        assert_eq!(paths.len(), 1, "the link's one path: {shown}");
        let path = &paths[0];
        assert_eq!(path["active"], true, "{path}");
        assert_eq!(path["transport_id"], json!(t1.as_u32()), "{path}");
        assert_eq!(path["addr"], b1.to_string(), "{path}");
        cleanup_nodes(&mut nodes).await;
    }
}
