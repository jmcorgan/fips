//! Read-side classifier for the `inet fips` baseline filter.
//!
//! For the fipstop "Listening on fips0" panel, we need to tell the
//! operator whether a given (proto, port) listener is actually
//! reachable on fips0 or whether it would be silently dropped by the
//! shipped baseline. We answer that question by shelling out to
//! `nft -j list table inet fips` (stable JSON output) and walking the
//! `inbound` chain's rules.
//!
//! Linux-only. Non-Linux callers (the daemon doesn't ship the
//! firewall on macOS / Windows) get [`FilterClassifier::no_firewall`].
//!
//! Three terminal states per (proto, port) pair:
//!
//! - [`FilterState::NoFirewall`] — `inet fips` table does not exist
//!   (the operator hasn't enabled `fips-firewall.service`). The UI
//!   surfaces this via a yellow banner above the panel rather than
//!   per-row.
//! - [`FilterState::Accept`] — the chain has a canonical-shape rule
//!   that accepts traffic to (proto, port) without any source or
//!   other restriction.
//! - [`FilterState::Drop`] — no rule matches; the chain falls through
//!   to its trailing `counter drop`.
//! - [`FilterState::Unknown`] — at least one rule references the
//!   (proto, port) pair but uses matchers we don't fully interpret
//!   (saddr filters, daddr filters, set/range right-hand sides we
//!   can't decompose, jumps to other chains). The operator should
//!   `nft list table inet fips` to confirm; the UI dims and tags `?`.
//!
//! Conntrack-related accepts (`ct state established,related accept`)
//! and the ICMPv6-echo-request accept are not classified — they
//! don't pertain to listening TCP/UDP ports the operator binds.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use serde_json::Value;

use crate::control::listening::Proto;

/// Classification of a (proto, port) pair against the inbound chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterState {
    NoFirewall,
    Accept,
    Drop,
    Unknown,
}

impl FilterState {
    pub fn as_str(self) -> &'static str {
        match self {
            FilterState::NoFirewall => "no_firewall",
            FilterState::Accept => "accept",
            FilterState::Drop => "drop",
            FilterState::Unknown => "unknown",
        }
    }
}

/// Cached snapshot of the `inet fips` inbound chain at the moment
/// the panel was queried. Build once per `show_listening_sockets`
/// call and consult per row.
pub struct FilterClassifier {
    /// Parsed rule list for the `inbound` chain, in order. `None`
    /// when the table does not exist (`fips-firewall.service` not
    /// active) — every classification call returns `NoFirewall`.
    rules: Option<Vec<Rule>>,
}

#[derive(Debug, Clone)]
struct Rule {
    /// All `match` expressions in order, plus a single terminal verdict.
    matches: Vec<MatchExpr>,
    verdict: Verdict,
}

/// Subset of `match` expressions we recognize. Anything we don't
/// recognize forces the rule into the [`Verdict::Unknown`] bucket
/// when classifying.
#[derive(Debug, Clone)]
enum MatchExpr {
    /// `meta iifname == "fips0"` / `!= "fips0"`.
    /// The shipped baseline returns immediately when iifname is not
    /// fips0; rules after that line apply only to fips0 traffic, so we
    /// don't need to model this. We just recognize the shape so we
    /// don't bucket these lines into [`MatchExpr::Unrecognized`].
    Iifname,
    /// `meta l4proto == tcp/udp`.
    L4Proto(Proto),
    /// `tcp dport == N` / `udp dport == N` / dport in set / dport in range.
    Dport(Proto, PortMatch),
    /// Any other match expression we don't decompose (saddr, daddr,
    /// ct state we don't care about, complex right-hand sides).
    Unrecognized,
}

#[derive(Debug, Clone)]
enum PortMatch {
    /// `dport == 22`
    Single(u16),
    /// `dport { 22, 80, 443 }`
    Set(Vec<u16>),
    /// `dport 22-25`
    Range(u16, u16),
}

impl PortMatch {
    fn matches(&self, port: u16) -> bool {
        match self {
            PortMatch::Single(p) => *p == port,
            PortMatch::Set(ps) => ps.contains(&port),
            PortMatch::Range(lo, hi) => *lo <= port && port <= *hi,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Accept,
    Drop,
    /// `return`, `continue`, `jump`, `goto`, `reject`, `queue`, etc.
    /// We don't follow control-flow verdicts — anything that isn't a
    /// terminal accept/drop forces classification to [`FilterState::Unknown`]
    /// when the rule otherwise references the port.
    Other,
}

impl FilterClassifier {
    /// No-firewall classifier (used on non-Linux targets).
    pub fn no_firewall() -> Self {
        Self { rules: None }
    }

    /// Build a classifier by querying the running kernel for the
    /// current `inet fips` inbound chain. Returns a [`Self::no_firewall`]
    /// classifier when the table is absent.
    #[cfg(target_os = "linux")]
    pub fn query() -> Self {
        let json = match run_nft_list() {
            Some(j) => j,
            None => return Self::no_firewall(),
        };
        let rules = parse_inbound_rules(&json);
        Self { rules: Some(rules) }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn query() -> Self {
        Self::no_firewall()
    }

    /// True iff the `inet fips` table is currently loaded — i.e.
    /// `fips-firewall.service` is active.
    pub fn is_active(&self) -> bool {
        self.rules.is_some()
    }

    /// Classify a single (proto, port) pair.
    pub fn classify(&self, proto: Proto, port: u16) -> FilterState {
        let rules = match &self.rules {
            None => return FilterState::NoFirewall,
            Some(r) => r,
        };

        let mut saw_unknown_for_port = false;

        for rule in rules {
            // Does this rule reference our (proto, port)?
            let mut references_port = false;
            let mut canonical_for_port = true;
            let mut has_proto_match = None;

            for m in &rule.matches {
                match m {
                    MatchExpr::Iifname => {
                        // The `iifname != "fips0" return` rule is
                        // structurally the table's iif scoping. Skip
                        // it — it shouldn't affect classification of
                        // rules that come after.
                    }
                    MatchExpr::L4Proto(p) => {
                        has_proto_match = Some(*p);
                        if *p != proto {
                            canonical_for_port = false;
                        }
                    }
                    MatchExpr::Dport(p, pm) => {
                        if *p == proto && pm.matches(port) {
                            references_port = true;
                        } else if pm.matches(port) {
                            // dport match for a different proto —
                            // the rule references our port number but
                            // not under our proto.
                        } else {
                            canonical_for_port = false;
                        }
                    }
                    MatchExpr::Unrecognized => {
                        // Source filters, daddr filters, anything
                        // else — rule is not the canonical
                        // unrestricted accept.
                        if rule_might_reference_port(rule, proto, port) {
                            saw_unknown_for_port = true;
                        }
                        canonical_for_port = false;
                    }
                }
            }

            if !references_port {
                continue;
            }

            // Rule references our (proto, port). Decide based on
            // verdict and whether the rule had any unrecognized matches.
            if !canonical_for_port {
                saw_unknown_for_port = true;
                continue;
            }

            // Optional l4proto match must agree with our proto
            // (already checked above) or be absent.
            if let Some(p) = has_proto_match
                && p != proto
            {
                continue;
            }

            match rule.verdict {
                Verdict::Accept => return FilterState::Accept,
                Verdict::Drop => {
                    // Explicit drop — clearly Drop, no need to keep
                    // looking. Operator wrote a deny.
                    return FilterState::Drop;
                }
                Verdict::Other => {
                    saw_unknown_for_port = true;
                }
            }
        }

        if saw_unknown_for_port {
            FilterState::Unknown
        } else {
            FilterState::Drop
        }
    }
}

/// Heuristic: does this rule, taken as a whole, reference our port?
/// Used to decide whether unrecognized matches warrant Unknown vs.
/// being ignored. Avoids flagging every rule with an unrecognized
/// matcher as Unknown for every port in the system.
fn rule_might_reference_port(rule: &Rule, proto: Proto, port: u16) -> bool {
    rule.matches.iter().any(|m| match m {
        MatchExpr::Dport(p, pm) => *p == proto && pm.matches(port),
        _ => false,
    })
}

// ---------- nft -j shell-out + JSON parsing ----------

#[cfg(target_os = "linux")]
fn run_nft_list() -> Option<Value> {
    use std::process::Command;

    let output = Command::new("nft")
        .args(["-j", "list", "table", "inet", "fips"])
        .output()
        .ok()?;

    if !output.status.success() {
        // Common case: table doesn't exist (fips-firewall.service not
        // active) → exit code 1, stderr "Error: No such file or directory".
        // Less common: nft binary missing (we already returned None
        // above). Either way, no firewall data to classify against.
        return None;
    }

    serde_json::from_slice::<Value>(&output.stdout).ok()
}

fn parse_inbound_rules(json: &Value) -> Vec<Rule> {
    let arr = match json.get("nftables").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };

    arr.iter()
        .filter_map(|entry| entry.get("rule"))
        .filter(|rule| {
            rule.get("chain").and_then(|v| v.as_str()) == Some("inbound")
                && rule.get("table").and_then(|v| v.as_str()) == Some("fips")
        })
        .map(parse_rule)
        .collect()
}

fn parse_rule(rule: &Value) -> Rule {
    let exprs = rule
        .get("expr")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut matches = Vec::new();
    let mut verdict = Verdict::Other;

    for e in &exprs {
        if let Some(m) = e.get("match") {
            matches.push(parse_match(m));
        } else if e.get("accept").is_some() {
            verdict = Verdict::Accept;
        } else if e.get("drop").is_some() {
            verdict = Verdict::Drop;
        } else if e.get("counter").is_some() {
            // Bare counter is observational; preserve any earlier
            // verdict (the counter usually precedes the verdict).
            // The trailing `counter drop` rule has only `counter` +
            // `drop` exprs, which is handled above.
        } else if e.get("return").is_some()
            || e.get("jump").is_some()
            || e.get("goto").is_some()
            || e.get("continue").is_some()
            || e.get("reject").is_some()
            || e.get("queue").is_some()
        {
            verdict = Verdict::Other;
        }
        // Unknown expression types fall through silently — they don't
        // affect verdict, but parse_match already pushes Unrecognized
        // for unknown match shapes.
    }

    Rule { matches, verdict }
}

fn parse_match(m: &Value) -> MatchExpr {
    let op = m.get("op").and_then(|v| v.as_str()).unwrap_or("==");
    let left = m.get("left").cloned().unwrap_or(Value::Null);
    let right = m.get("right").cloned().unwrap_or(Value::Null);

    // meta iifname
    if let Some(meta) = left.get("meta")
        && meta.get("key").and_then(|v| v.as_str()) == Some("iifname")
        && right.as_str().is_some()
    {
        let _ = op; // op is informational here; we don't use negation.
        return MatchExpr::Iifname;
    }

    // meta l4proto
    if let Some(meta) = left.get("meta")
        && meta.get("key").and_then(|v| v.as_str()) == Some("l4proto")
        && let Some(proto_str) = right.as_str()
        && let Some(proto) = parse_proto(proto_str)
        && op == "=="
    {
        return MatchExpr::L4Proto(proto);
    }

    // tcp/udp dport
    if let Some(payload) = left.get("payload")
        && payload.get("field").and_then(|v| v.as_str()) == Some("dport")
        && let Some(proto_str) = payload.get("protocol").and_then(|v| v.as_str())
        && let Some(proto) = parse_proto(proto_str)
        && op == "=="
    {
        if let Some(p) = right.as_u64() {
            return MatchExpr::Dport(proto, PortMatch::Single(p as u16));
        }
        if let Some(set) = right.get("set").and_then(|v| v.as_array()) {
            let ports: Vec<u16> = set
                .iter()
                .filter_map(|v| v.as_u64().map(|n| n as u16))
                .collect();
            // Bail if the set contained anything we couldn't read as
            // a plain integer (e.g. a named-set reference or nested
            // range/prefix).
            if ports.len() == set.len() {
                return MatchExpr::Dport(proto, PortMatch::Set(ports));
            }
        }
        if let Some(range) = right.get("range").and_then(|v| v.as_array())
            && range.len() == 2
            && let (Some(lo), Some(hi)) = (range[0].as_u64(), range[1].as_u64())
        {
            return MatchExpr::Dport(proto, PortMatch::Range(lo as u16, hi as u16));
        }
    }

    MatchExpr::Unrecognized
}

fn parse_proto(s: &str) -> Option<Proto> {
    match s {
        "tcp" => Some(Proto::Tcp),
        "udp" => Some(Proto::Udp),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_classifier(rules_json: Value) -> FilterClassifier {
        let nft_json = json!({
            "nftables": rules_json
                .as_array()
                .unwrap()
                .iter()
                .map(|r| json!({"rule": {
                    "family": "inet",
                    "table": "fips",
                    "chain": "inbound",
                    "expr": r,
                }}))
                .collect::<Vec<_>>(),
        });
        FilterClassifier {
            rules: Some(parse_inbound_rules(&nft_json)),
        }
    }

    #[test]
    fn no_firewall_means_no_firewall() {
        let c = FilterClassifier::no_firewall();
        assert_eq!(c.classify(Proto::Tcp, 22), FilterState::NoFirewall);
        assert_eq!(c.classify(Proto::Udp, 5353), FilterState::NoFirewall);
    }

    #[test]
    fn empty_chain_drops_everything() {
        let c = make_classifier(json!([]));
        assert_eq!(c.classify(Proto::Tcp, 22), FilterState::Drop);
        assert_eq!(c.classify(Proto::Udp, 5353), FilterState::Drop);
    }

    #[test]
    fn canonical_tcp_dport_accept() {
        // tcp dport 22 accept
        let c = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 22
                }},
                {"accept": null}
            ]
        ]));
        assert_eq!(c.classify(Proto::Tcp, 22), FilterState::Accept);
        assert_eq!(c.classify(Proto::Tcp, 80), FilterState::Drop);
        assert_eq!(c.classify(Proto::Udp, 22), FilterState::Drop);
    }

    #[test]
    fn canonical_udp_dport_accept() {
        // udp dport 5353 accept
        let c = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "udp", "field": "dport"}},
                    "right": 5353
                }},
                {"accept": null}
            ]
        ]));
        assert_eq!(c.classify(Proto::Udp, 5353), FilterState::Accept);
        assert_eq!(c.classify(Proto::Tcp, 5353), FilterState::Drop);
    }

    #[test]
    fn dport_set_accept() {
        // tcp dport { 22, 80, 443 } accept
        let c = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": {"set": [22, 80, 443]}
                }},
                {"accept": null}
            ]
        ]));
        assert_eq!(c.classify(Proto::Tcp, 22), FilterState::Accept);
        assert_eq!(c.classify(Proto::Tcp, 80), FilterState::Accept);
        assert_eq!(c.classify(Proto::Tcp, 443), FilterState::Accept);
        assert_eq!(c.classify(Proto::Tcp, 25), FilterState::Drop);
    }

    #[test]
    fn dport_range_accept() {
        // tcp dport 22-25 accept
        let c = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": {"range": [22, 25]}
                }},
                {"accept": null}
            ]
        ]));
        assert_eq!(c.classify(Proto::Tcp, 22), FilterState::Accept);
        assert_eq!(c.classify(Proto::Tcp, 25), FilterState::Accept);
        assert_eq!(c.classify(Proto::Tcp, 26), FilterState::Drop);
    }

    #[test]
    fn saddr_restricted_is_unknown() {
        // ip6 saddr fd97::/64 tcp dport 22 accept — the saddr filter
        // means we can't tell from the rule alone whether mesh peers
        // can reach the port.
        let c = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "ip6", "field": "saddr"}},
                    "right": {"prefix": {"addr": "fd97::", "len": 64}}
                }},
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 22
                }},
                {"accept": null}
            ]
        ]));
        assert_eq!(c.classify(Proto::Tcp, 22), FilterState::Unknown);
        // Other ports unaffected.
        assert_eq!(c.classify(Proto::Tcp, 80), FilterState::Drop);
    }

    #[test]
    fn jump_verdict_is_unknown() {
        // tcp dport 22 jump some_chain — we don't follow chains, so
        // surface to operator.
        let c = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 22
                }},
                {"jump": {"target": "some_chain"}}
            ]
        ]));
        assert_eq!(c.classify(Proto::Tcp, 22), FilterState::Unknown);
    }

    #[test]
    fn explicit_drop_classifies_as_drop() {
        // tcp dport 22 drop — operator explicitly denying.
        let c = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 22
                }},
                {"drop": null}
            ]
        ]));
        assert_eq!(c.classify(Proto::Tcp, 22), FilterState::Drop);
    }

    #[test]
    fn unrelated_rules_dont_affect_port() {
        // Common shipped baseline rules: iifname-scoping, ct state,
        // icmpv6 echo. Should not affect (tcp, 22) classification.
        let c = make_classifier(json!([
            // iifname != "fips0" return
            [
                {"match": {
                    "op": "!=",
                    "left": {"meta": {"key": "iifname"}},
                    "right": "fips0"
                }},
                {"return": null}
            ],
            // ct state {established, related} accept
            [
                {"match": {
                    "op": "in",
                    "left": {"ct": {"key": "state"}},
                    "right": ["established", "related"]
                }},
                {"accept": null}
            ],
            // icmpv6 type echo-request accept
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "icmpv6", "field": "type"}},
                    "right": "echo-request"
                }},
                {"accept": null}
            ],
        ]));
        assert_eq!(c.classify(Proto::Tcp, 22), FilterState::Drop);
        assert_eq!(c.classify(Proto::Udp, 5353), FilterState::Drop);
    }

    #[test]
    fn l4proto_then_dport_accept() {
        // meta l4proto tcp tcp dport 22 accept — rare but valid
        let c = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"meta": {"key": "l4proto"}},
                    "right": "tcp"
                }},
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 22
                }},
                {"accept": null}
            ]
        ]));
        assert_eq!(c.classify(Proto::Tcp, 22), FilterState::Accept);
        assert_eq!(c.classify(Proto::Udp, 22), FilterState::Drop);
    }

    #[test]
    fn first_accept_match_wins() {
        // If both an accept and a Unknown rule reference the same
        // port, the explicit accept wins (operator wanted it open).
        let c = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 22
                }},
                {"accept": null}
            ],
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "ip6", "field": "saddr"}},
                    "right": "fd00::1"
                }},
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 22
                }},
                {"drop": null}
            ]
        ]));
        assert_eq!(c.classify(Proto::Tcp, 22), FilterState::Accept);
    }
}
