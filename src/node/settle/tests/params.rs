//! The settlement core's parameters as the node's configuration gives
//! them, against the core's defaults and against the node's own resend
//! schedule.

use super::*;
use crate::proto::fmp::{ConnAction, ConnSnapshot, Fmp};
use crate::proto::rekey::IndexLease;
use crate::proto::settle::legs::{LegOut, Legs, Start};
use crate::proto::settle::links::{Dir, Holder, Links, Pair};
use crate::transport::{LinkId, TransportAddr, TransportId};

/// Milliseconds on a test clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Ms(u64);

impl fips_core::time::Instant for Ms {
    fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_millis(self.0.saturating_sub(earlier.0))
    }

    fn checked_add(self, d: Duration) -> Option<Self> {
        let ms = u64::try_from(d.as_millis()).ok()?;
        self.0.checked_add(ms).map(Ms)
    }

    fn checked_sub(self, d: Duration) -> Option<Self> {
        let ms = u64::try_from(d.as_millis()).ok()?;
        self.0.checked_sub(ms).map(Ms)
    }
}

#[test]
fn the_default_configuration_gives_the_settlement_cores_defaults() {
    assert_eq!(settle_params(&NodeConfig::default()), Params::default());
}

/// The instants, from a dial at 0, of the resends the core's leg makes
/// under `p`, each reported sent at once.
fn core_resends(p: &Params) -> Vec<u64> {
    let mut links = Links::new();
    let mut legs: Legs<Ms> = Legs::new();
    let pair = Pair {
        transport: TransportId::new(1),
        addr: TransportAddr::from_string("10.0.0.1:2121"),
    };
    let link = links.open(pair, Dir::Outbound, Holder::Leg);
    let start = Start {
        link,
        peer: None,
        msg1: b"msg1".to_vec(),
        lease: IndexLease::for_test(1),
        resends: None,
        held: None,
    };
    assert!(legs.dial(start, Ms(0), p).is_none());
    let mut times = Vec::new();
    while let Some(wake) = legs.next_wake() {
        assert!(times.len() < 20, "the leg is still held after 20 resends");
        for o in legs.poll(wake, &mut links) {
            match o {
                LegOut::Resend { .. } => {
                    times.push(wake.0);
                    legs.resent(link, wake, p);
                }
                LegOut::Reaped { lease, .. } => {
                    lease.release();
                }
            }
        }
    }
    times
}

/// The instants, from a dial at 0, of the resends the node makes when
/// configured as `node`: the first one resend interval after the dial
/// (`prepare_outbound_msg1`), each later one where `Fmp::poll_resends`
/// schedules it, up to the configured count, within the handshake timeout.
fn node_resends(node: &NodeConfig) -> Vec<u64> {
    let rl = &node.rate_limit;
    let deadline = rl.handshake_timeout_secs * 1000;
    let mut at = rl.handshake_resend_interval_ms;
    let mut times = Vec::new();
    for count in 0..rl.handshake_max_resends {
        if at >= deadline {
            break;
        }
        times.push(at);
        let snap = ConnSnapshot {
            link: LinkId::new(1),
            is_outbound: true,
            retry_addr: None,
            resend_count: count,
            msg1: Vec::new(),
        };
        let actions = Fmp::new().poll_resends(
            vec![snap],
            at,
            rl.handshake_resend_interval_ms,
            rl.handshake_resend_backoff,
        );
        assert_eq!(actions.len(), 1, "one resend is scheduled");
        let Some(ConnAction::ResendMsg1 {
            next_resend_at_ms, ..
        }) = actions.first()
        else {
            panic!("the action is a resend");
        };
        at = *next_resend_at_ms;
    }
    times
}

#[test]
fn a_configured_backoff_gives_the_nodes_resend_schedule() {
    for multiplier in [1.3333, 1.5, 2.0, 2.5005] {
        let mut node = NodeConfig::default();
        node.rate_limit.handshake_resend_backoff = multiplier;
        node.rate_limit.handshake_timeout_secs = 120;
        let want = node_resends(&node);
        assert_eq!(
            want.len(),
            5,
            "precondition: all five resends fall inside the timeout at {multiplier}"
        );
        assert_eq!(
            core_resends(&settle_params(&node)),
            want,
            "defect: at a multiplier of {multiplier} the core's resends are not where the node sends them"
        );
    }
}
