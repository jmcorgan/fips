//! The Ethernet transport's kernel drop counter.

use super::*;

#[test]
fn kernel_drop_readings_add_up_to_a_running_total() {
    let stats = EthernetStats::new();
    stats.record_kernel_drops(3);
    stats.record_kernel_drops(0);
    stats.record_kernel_drops(40);
    assert_eq!(stats.snapshot().kernel_drops, 43);
}

#[test]
fn the_kernel_drop_total_is_reported_in_the_stats_json() {
    // show_transports serializes the snapshot, and the chaos harness reads
    // this key from it; a renamed field would leave the harness reading null.
    let stats = EthernetStats::new();
    stats.record_kernel_drops(5);
    let json = serde_json::to_value(stats.snapshot()).unwrap();
    assert_eq!(json["kernel_drops"], 5);
}
