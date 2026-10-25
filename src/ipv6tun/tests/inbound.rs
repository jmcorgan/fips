//! Tests of the host-side half of delivering a peer's datagram.

use super::*;

#[test]
fn mark_ce_marks_only_ect() {
    // ECT(0): TC low bits 0b10. Byte1 high nibble carries TC[3:0].
    let mut ect0 = [0x60, 0x20, 0, 0];
    mark_ce(&mut ect0);
    assert_eq!(ect0[1] & 0x30, 0x30, "ECN bits set to CE");

    // Not-ECT (ECN 0b00) is never marked.
    let mut not_ect = [0x60, 0x00, 0, 0];
    mark_ce(&mut not_ect);
    assert_eq!(not_ect[1] & 0x30, 0x00, "Not-ECT stays unmarked");

    // Too short → no panic, no change.
    let mut short = [0x60];
    mark_ce(&mut short);
    assert_eq!(short, [0x60]);
}
