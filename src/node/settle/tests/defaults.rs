//! The link rekey and path settings the node derives at the default
//! configuration against the ones the shared schedules state
//! (`fips_core::proto::settle::parity`), which the joint world's nodes
//! run with: a schedule compares a real node with joint nodes only while
//! the two run alike.

use crate::config::NodeConfig;
use crate::node::handlers::path::path_params;
use crate::node::handlers::rekey::link_params;
use fips_core::proto::settle::parity;

#[test]
fn the_node_defaults_are_the_stated_link_and_path_settings() {
    let mut differ = Vec::new();
    for on in [false, true] {
        let mut node = NodeConfig::default();
        node.path.enabled = on;
        if link_params(&node) != parity::rekey(on) {
            differ.push(format!(
                "multipath {on}: the link rekey settings are {:?}, stated {:?}",
                link_params(&node),
                parity::rekey(on)
            ));
        }
        if path_params(&node) != parity::path(on) {
            differ.push(format!(
                "multipath {on}: the path settings are {:?}, stated {:?}",
                path_params(&node),
                parity::path(on)
            ));
        }
    }
    assert!(
        differ.is_empty(),
        "the node's defaults are not the settings the shared schedules state: {differ:#?}"
    );
}
