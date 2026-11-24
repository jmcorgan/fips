use super::RefusalWarnGate;
use crate::nostr::machine::tests::TestInstant;

#[test]
fn a_stranger_sending_refused_offers_gets_one_warning_a_minute() {
    let mut gate = RefusalWarnGate::default();
    assert_eq!(gate.admit(TestInstant(0)), Some(0));
    assert_eq!(gate.admit(TestInstant(1)), None);
    assert_eq!(gate.admit(TestInstant(59_999)), None);
    assert_eq!(gate.admit(TestInstant(60_000)), Some(2));
    assert_eq!(gate.admit(TestInstant(60_001)), None);
}
