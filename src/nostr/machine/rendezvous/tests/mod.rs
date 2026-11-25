//! Tests of the rendezvous machine, stepped by hand: every input is given
//! at a scripted monotonic instant and Unix time, randomness comes from a
//! seeded source, and every assertion is on the actions the machine queues.
//! The keys are FRC-1601 Appendix C.1's.

use std::collections::BTreeSet;

use nostr::event::Event;
use nostr::key::{PublicKey, SecretKey};
use nostr::nips::nip19::ToBech32;

use super::super::tests::{SeededEntropy, TestInstant};
use super::super::types::OverlayAdvert;
use super::log::Log;
use super::*;

mod adverts;
mod auth;
mod queries;
mod startup;
mod traversal;

/// Node A's secret key, FRC-1601 C.1: the machine's own node.
pub(super) const NODE_A_SECRET: &str =
    "0000000000000000000000000000000000000000000000000000000000000003";
/// Node B's secret key, FRC-1601 C.1: a peer.
pub(super) const NODE_B_SECRET: &str =
    "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef";
/// A third key, for a foreign author or another peer.
pub(super) const NODE_C_SECRET: &str =
    "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9";
/// Unix time at the harness's start: FRC-1601 C.1's time of publication.
pub(super) const T0_MS: u64 = 1_830_297_600_000;

/// The application name adverts carry.
pub(super) const APP: &str = "fips-overlay-v1";

/// The signer for the secret key written as `hex`.
pub(super) fn signer(hex: &str) -> NodeSigner {
    NodeSigner::new(SecretKey::from_hex(hex).expect("a secret key"))
}

/// The public key for the secret key written as `hex`.
pub(super) fn pubkey(hex: &str) -> PublicKey {
    signer(hex).public_key()
}

/// The npub for the secret key written as `hex`.
pub(super) fn npub(hex: &str) -> String {
    pubkey(hex).to_bech32().expect("bech32")
}

/// The peer key for the secret key written as `hex`.
pub(super) fn key(hex: &str) -> PeerKey {
    PeerKey {
        pubkey: pubkey(hex),
        npub: npub(hex),
    }
}

/// The settings the tests run with: two DM relays, two advert relays, one
/// STUN server, a 100 s advert refresh, a 3600 s advert lifetime and room
/// for `cap` cached adverts.
pub(super) fn params(cap: usize) -> Params {
    Params {
        failure_streak_threshold: 3,
        extended_cooldown_secs: 600,
        warn_log_interval_secs: 60,
        failure_state_max_entries: 100,
        replay_window_secs: 300,
        seen_sessions_max_entries: 100,
        advertise: true,
        advert_cache_max_entries: cap,
        advert_refresh_secs: 100,
        app: APP.to_string(),
        advert_relays: vec![
            "wss://adverts-1.example".to_string(),
            "wss://adverts-2.example".to_string(),
        ],
        dm_relays: vec![
            "wss://dm-1.example".to_string(),
            "wss://dm-2.example".to_string(),
        ],
        stun_servers: vec!["stun:stun.example:3478".to_string()],
        advert_ttl_secs: 3_600,
        signal_ttl_secs: 120,
        attempt_timeout_secs: 10,
        punch_start_delay_ms: 2_000,
        punch_interval_ms: 200,
        punch_duration_ms: 10_000,
        share_local_candidates: false,
        protocol_mismatch_cooldown_secs: 86_400,
        max_concurrent_incoming_offers: 16,
        max_concurrent_offers_per_npub: 4,
    }
}

/// A machine for node A, and the clock it is stepped on.
pub(super) struct Harness {
    pub(super) m: Rendezvous<TestInstant, SeededEntropy>,
    /// Milliseconds since the harness started, on both clocks.
    pub(super) ms: u64,
    next_reply: u64,
}

impl Harness {
    /// A machine for node A with `params`.
    pub(super) fn new(params: Params) -> Self {
        SeededEntropy::seed(7);
        Self::with_key(params, NODE_A_SECRET)
    }

    /// A machine for the node whose secret key is `hex`, with `params`.
    pub(super) fn with_key(params: Params, hex: &str) -> Self {
        let now = Now {
            mono: TestInstant(0),
            unix_ms: T0_MS,
        };
        Self {
            m: Rendezvous::new(params, signer(hex), npub(hex), now),
            ms: 0,
            next_reply: 1,
        }
    }

    /// The step's clock readings.
    pub(super) fn now(&self) -> Now<TestInstant> {
        Now {
            mono: TestInstant(self.ms),
            unix_ms: T0_MS + self.ms,
        }
    }

    /// Unix time now, in seconds.
    pub(super) fn unix_secs(&self) -> u64 {
        (T0_MS + self.ms) / 1000
    }

    /// A fresh reply id.
    pub(super) fn reply(&mut self) -> ReplyId {
        let reply = ReplyId(self.next_reply);
        self.next_reply += 1;
        reply
    }

    /// Every action queued so far.
    pub(super) fn drain(&mut self) -> Vec<Action> {
        std::iter::from_fn(|| self.m.poll_action()).collect()
    }

    /// Hand the machine `input` now, and return the actions it queued.
    pub(super) fn input(&mut self, input: Input) -> Vec<Action> {
        let now = self.now();
        self.m.handle(input, now);
        self.drain()
    }

    /// Move both clocks on by `ms`, running every deadline that falls on
    /// the way at its own instant, and return the actions queued.
    pub(super) fn advance(&mut self, ms: u64) -> Vec<Action> {
        let target = self.ms + ms;
        let mut actions = Vec::new();
        while let Some(at) = self.m.poll_timeout().filter(|at| at.0 <= target) {
            self.ms = self.ms.max(at.0);
            let now = self.now();
            self.m.handle_timeout(now);
            actions.extend(self.drain());
        }
        self.ms = target;
        actions
    }
}

/// The relays and filters of `action` if it is a subscribe, with its
/// request and subscription ids.
pub(super) fn subscribe_of(action: &Action) -> Option<(ReqId, Vec<SubId>)> {
    match action {
        Action::Subscribe { req, subs, .. } => {
            Some((*req, subs.iter().map(|(sub, _, _)| *sub).collect()))
        }
        _ => None,
    }
}

/// The publishes among `actions`, as request, relays and event.
pub(super) fn publishes(actions: &[Action]) -> Vec<(ReqId, Vec<String>, Event, Option<Duration>)> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Publish {
                req,
                relays,
                event,
                timeout,
            } => Some((*req, relays.clone(), event.clone(), *timeout)),
            _ => None,
        })
        .collect()
}

/// The fetches among `actions`.
pub(super) fn fetches(actions: &[Action]) -> Vec<(ReqId, Vec<String>, nostr::filter::Filter)> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Fetch {
                req,
                relays,
                filter,
                ..
            } => Some((*req, relays.clone(), filter.clone())),
            _ => None,
        })
        .collect()
}

/// The log lines among `actions`.
pub(super) fn logs(actions: &[Action]) -> Vec<Log> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Log(line) => Some(line.clone()),
            _ => None,
        })
        .collect()
}

/// The sockets `actions` bind.
pub(super) fn binds(actions: &[Action]) -> Vec<SocketId> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Bind { socket } => Some(*socket),
            _ => None,
        })
        .collect()
}

/// The address the test STUN server resolves to.
pub(super) const STUN_SERVER_ADDR: &str = "198.51.100.1:3478";

/// A STUN binding success for transaction `txn` carrying `mapped` as its
/// XOR-MAPPED-ADDRESS.
pub(super) fn binding_success(txn: &[u8], mapped: std::net::SocketAddrV4) -> Vec<u8> {
    const COOKIE: u32 = 0x2112_a442;
    let mut packet = Vec::new();
    packet.extend_from_slice(&0x0101u16.to_be_bytes());
    packet.extend_from_slice(&12u16.to_be_bytes());
    packet.extend_from_slice(&COOKIE.to_be_bytes());
    packet.extend_from_slice(txn);
    packet.extend_from_slice(&0x0020u16.to_be_bytes());
    packet.extend_from_slice(&8u16.to_be_bytes());
    packet.push(0);
    packet.push(1);
    packet.extend_from_slice(&(mapped.port() ^ (COOKIE >> 16) as u16).to_be_bytes());
    for (octet, mask) in mapped.ip().octets().iter().zip(COOKIE.to_be_bytes()) {
        packet.push(octet ^ mask);
    }
    packet
}

/// Run the public-address observation on `socket` to its end: the socket
/// is bound, the test server resolved, and the first binding request
/// answered with `reflexive`, or, with `None`, the first send fails. The
/// actions of the last step.
pub(super) fn complete(
    h: &mut Harness,
    socket: SocketId,
    reflexive: Option<std::net::Ipv4Addr>,
) -> Vec<Action> {
    let mut actions = h.input(Input::SocketBound {
        socket,
        local: "0.0.0.0:40000".parse().unwrap(),
    });
    if let Some(req) = actions.iter().find_map(|action| match action {
        Action::Resolve { req, .. } => Some(*req),
        _ => None,
    }) {
        actions = h.input(Input::Resolved {
            req,
            addrs: vec![STUN_SERVER_ADDR.parse().unwrap()],
        });
    }
    let (dst, bytes) = actions
        .iter()
        .find_map(|action| match action {
            Action::Send { dst, bytes, .. } => Some((*dst, bytes.clone())),
            _ => None,
        })
        .expect("a binding request");
    match reflexive {
        Some(ip) => h.input(Input::Datagram {
            socket,
            src: dst,
            bytes: binding_success(&bytes[8..20], std::net::SocketAddrV4::new(ip, 50_000)),
        }),
        None => h.input(Input::SendFailed {
            socket,
            dst,
            error: "Network is unreachable".to_string(),
        }),
    }
}

/// The reply to `reply` among `actions`, and where it stands in them.
pub(super) fn reply_to(actions: Vec<Action>, reply: ReplyId) -> Option<(usize, Reply)> {
    actions
        .into_iter()
        .enumerate()
        .find_map(|(i, action)| match action {
            Action::Reply { reply: r, payload } if r == reply => Some((i, payload)),
            _ => None,
        })
}

/// An advert body with one TCP endpoint at a public address.
pub(super) fn body(addr: &str) -> OverlayAdvert {
    OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: super::super::types::ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport: super::super::types::OverlayTransportKind::Tcp,
            addr: addr.to_string(),
        }],
        signal_relays: None,
        stun_servers: None,
    }
}

/// The advert of the node whose secret key is `hex`, created at
/// `created_secs`, carrying `advert`, expiring an hour after it.
pub(super) fn advert_by(hex: &str, created_secs: u64, advert: &OverlayAdvert) -> Event {
    super::super::event::advert::advert_event(
        &signer(hex),
        serde_json::to_string(advert).unwrap(),
        ADVERT_IDENTIFIER,
        APP,
        3_600,
        created_secs * 1000,
        [0u8; 32],
    )
    .expect("an advert")
}

/// `event` as a relay delivers it.
pub(super) fn delivered(event: Event) -> Input {
    Input::RelayEvent {
        relay: nostr::types::RelayUrl::parse("wss://adverts-1.example").unwrap(),
        event: Box::new(event),
    }
}

/// The cached `created_at` of `npub`, and the protected set.
pub(super) fn inspect(h: &mut Harness, npub: &str) -> io::Inspection {
    let reply = h.reply();
    let actions = h.input(Input::Inspect {
        npub: npub.to_string(),
        reply,
    });
    match reply_to(actions, reply) {
        Some((_, Reply::Inspected(inspection))) => inspection,
        other => panic!("no inspection: {other:?}"),
    }
}

/// Cache `advert` under its author, as fetched.
pub(super) fn insert(h: &mut Harness, event: &Event) {
    let checked = super::super::adverts::ingest::check(
        event,
        APP,
        super::super::adverts::ingest::max_age_ms(3_600),
        h.now().unix_ms,
    )
    .expect("a valid advert");
    let reply = h.reply();
    h.input(Input::InsertAdvert {
        npub: checked.author_npub.clone(),
        advert: CachedOverlayAdvert {
            author_npub: checked.author_npub,
            advert: checked.advert,
            created_at: checked.created_at,
            valid_until_ms: checked.valid_until_ms,
        },
        reply,
    });
}

/// A protection set of `npubs`.
pub(super) fn protect(npubs: &[String]) -> Input {
    Input::Protection(npubs.iter().cloned().collect::<BTreeSet<_>>())
}
