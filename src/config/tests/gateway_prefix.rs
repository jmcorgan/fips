//! Tests for `gateway.global_prefix`, the key the OpenWrt init script reads.

use super::GatewayConfig;

const WITHOUT_KEY: &str = "pool: \"fd01::/112\"\nlan_interface: \"br-lan\"\n";

#[test]
fn global_prefix_is_off_when_the_key_is_absent() {
    let config: GatewayConfig = serde_yaml::from_str(WITHOUT_KEY).unwrap();
    assert!(!config.global_prefix);
}

#[test]
fn global_prefix_reads_true_and_false() {
    for (value, expected) in [("true", true), ("false", false)] {
        let yaml = format!("{WITHOUT_KEY}global_prefix: {value}\n");
        let config: GatewayConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(config.global_prefix, expected, "global_prefix: {value}");
    }
}

#[test]
fn global_prefix_survives_being_written_back() {
    let yaml = format!("{WITHOUT_KEY}global_prefix: true\n");
    let config: GatewayConfig = serde_yaml::from_str(&yaml).unwrap();
    let written = serde_yaml::to_string(&config).unwrap();
    let reread: GatewayConfig = serde_yaml::from_str(&written).unwrap();
    assert!(reread.global_prefix);
}

#[test]
fn global_prefix_refuses_a_value_that_is_not_a_boolean() {
    let yaml = format!("{WITHOUT_KEY}global_prefix: \"2001:2:f1b5::1/64\"\n");
    assert!(serde_yaml::from_str::<GatewayConfig>(&yaml).is_err());
}
