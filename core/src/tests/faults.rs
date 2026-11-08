//! Tests for `faults.rs`: the reading of `FIPS_NODE_FAULTS`.
//!
//! The process's own set is read once, so these call the pure functions
//! it is built from rather than setting the variable.

use super::*;

#[test]
fn a_list_of_known_names_parses_to_its_switches_in_order() {
    assert_eq!(
        parse("MoveKeepsOldPair,PlantedRed"),
        Ok(alloc::vec![Fault::MoveKeepsOldPair, Fault::PlantedRed])
    );
}

#[test]
fn an_empty_list_and_empty_entries_name_no_switch() {
    assert_eq!(parse(""), Ok(Vec::new()));
    assert_eq!(
        parse(",PlantedGreen,"),
        Ok(alloc::vec![Fault::PlantedGreen])
    );
}

#[test]
#[should_panic(expected = "FIPS_NODE_FAULTS names no switch \"NoSuchSwitch\"")]
fn an_unknown_fault_name_panics() {
    let _ = load("MoveKeepsOldPair,NoSuchSwitch");
}

#[test]
fn every_switch_is_named_by_its_own_name_and_no_other() {
    for &f in Fault::ALL {
        assert_eq!(Fault::named(f.name()), Some(f));
        assert_eq!(
            Fault::ALL.iter().filter(|g| g.name() == f.name()).count(),
            1
        );
    }
}
