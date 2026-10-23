//! What the node tells its DNS responder about the mesh side.

use super::*;
use crate::upper::dns::MeshSide;

/// With an application-supplied TUN the mesh interface's index is unknown,
/// so the responder is given the node's own mesh address to recognise mesh
/// queries by.
#[test]
fn a_node_with_an_app_owned_tun_arms_the_dns_mesh_filter_with_its_own_address() {
    let mut node = make_node();
    let _tun = node.enable_app_owned_tun();
    let own = crate::FipsAddress::from_node_addr(node.node_addr()).to_ipv6();
    assert_eq!(
        node.dns_mesh_side(),
        MeshSide {
            ifindex: None,
            addr: Some(own),
        }
    );
}

/// With no TUN there is no mesh interface and no mesh address, so the
/// responder filters nothing.
#[test]
fn a_node_without_a_tun_leaves_the_dns_mesh_filter_off() {
    let node = make_node();
    assert_eq!(node.dns_mesh_side(), MeshSide::default());
}
