//! Tests of the bounded queue toward the host.

use super::*;

#[test]
fn a_full_queue_drops_and_counts_what_it_cannot_hold_without_waiting() {
    let (tx, rx) = TunTx::bounded(2);
    for byte in 0..5u8 {
        tx.send(vec![byte]).expect("the reader is still there");
    }
    assert_eq!(rx.try_iter().collect::<Vec<_>>(), vec![vec![0], vec![1]]);
    assert_eq!(tx.dropped(), 3);
}

#[test]
fn a_queue_with_room_again_takes_packets_and_keeps_its_count() {
    let (tx, rx) = TunTx::bounded(1);
    tx.send(vec![1]).unwrap();
    tx.send(vec![2]).unwrap();
    assert_eq!(rx.try_recv().unwrap(), vec![1]);
    tx.clone().send(vec![3]).unwrap();
    assert_eq!(rx.try_recv().unwrap(), vec![3]);
    assert_eq!(tx.dropped(), 1, "clones share one count");
}

#[test]
fn a_queue_whose_reader_has_gone_is_an_error_and_counts_nothing() {
    let (tx, rx) = TunTx::bounded(4);
    drop(rx);
    let err = tx.send(vec![7]).unwrap_err();
    assert_eq!(err.0, vec![7]);
    assert_eq!(tx.dropped(), 0);
}

#[test]
fn a_full_queue_warns_at_the_first_drop_and_at_each_doubling_under_the_queue_target() {
    const MESSAGE: &str = "Host not reading; dropping packets toward it";
    let (tx, _rx) = TunTx::bounded(1);
    let ((), logs) = crate::testutil::capture_logs(|| {
        for byte in 0..10u8 {
            tx.send(vec![byte]).expect("the reader is still there");
        }
    });
    let counts: Vec<_> = logs
        .lines_with(MESSAGE)
        .iter()
        .map(|line| {
            assert!(line.starts_with("WARN"), "{line}");
            crate::testutil::log_field(line, "dropped")
                .expect("the line carries the count")
                .to_owned()
        })
        .collect();
    assert_eq!(counts, ["1", "2", "4", "8"], "{:#?}", logs.lines());
    assert_eq!(logs.targets(MESSAGE), ["fips::ipv6tun::queue"; 4]);
    assert_eq!(tx.dropped(), 9);
}

#[test]
fn a_sender_formats_for_debugging_with_its_drop_count() {
    let (tx, _rx) = TunTx::bounded(1);
    tx.send(vec![1]).unwrap();
    tx.send(vec![2]).unwrap();
    assert_eq!(format!("{tx:?}"), "TunTx { dropped: 1, .. }");
}
