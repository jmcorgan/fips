//! Tests for the internal buffer sizes (`node.buffers.*`) in
//! `Config::validate`.

use super::*;

#[test]
fn a_host_channel_of_zero_is_refused_naming_the_key() {
    // Zero makes the queue toward the host a rendezvous channel, which drops
    // every packet its reader is not already waiting in `recv` for.
    let mut config = Config::default();
    config.node.buffers.host_channel = 0;

    let err = config
        .validate()
        .expect_err("a zero host queue must be refused");
    let msg = err.to_string();
    assert!(msg.contains("node.buffers.host_channel"), "got: {msg}");
}

#[test]
fn a_host_channel_of_one_validates_and_the_default_is_4096() {
    // The floor itself validates, or it would refuse a working node.
    let mut config = Config::default();
    assert_eq!(config.node.buffers.host_channel, 4096);
    config.node.buffers.host_channel = 1;
    config
        .validate()
        .expect("a host queue of one packet is valid");
}

#[test]
fn a_file_that_does_not_name_the_host_channel_loads_with_the_default() {
    let config: Config = serde_yaml::from_str("node:\n  buffers:\n    tun_channel: 512\n")
        .expect("a buffers section without host_channel parses");
    assert_eq!(config.node.buffers.tun_channel, 512);
    assert_eq!(config.node.buffers.host_channel, 4096);
    config.validate().expect("and validates");
}
