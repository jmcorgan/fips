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
//!
//! The chain is scoped to one interface by its opening
//! `iifname != "<name>" return` rule ([`Scope`]). A loaded table
//! protects the node only when that name is the live TUN's
//! ([`FilterClassifier::polices`]); a scope that cannot be read is
//! treated as not protecting it. The first rule that returns or that
//! matches on the input interface by any key decides the scope, so a
//! chain scoped some other way is unreadable rather than unscoped.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use serde_json::Value;

use super::listening::Proto;

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

/// Which interfaces the loaded `inbound` chain polices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// No rule returns or matches on the input interface: the chain sees
    /// every interface.
    Unscoped,
    /// The first such rule is exactly `iifname != "<name>" return` with a
    /// literal name: the chain polices only that interface.
    Iface(String),
    /// The first such rule has any other shape (a set, a wildcard, `==`,
    /// another interface key such as `iif` or `iifgroup`, a verdict map, a
    /// verdict other than `return`, further matches). Which interfaces it
    /// polices is not read, so it is not taken to police the TUN.
    Unreadable,
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
    /// A match or verdict map on the input interface (`meta iifname`,
    /// `iif`, `iifgroup`, `iiftype`, `iifkind`). `name` is the right-hand
    /// side only for `iifname` against a literal name; it is `None` for
    /// another key, a set, a named set (`@name`), a wildcard (`*`) or any
    /// other shape. The shipped baseline's `iifname != "fips0" return`
    /// sets the chain's [`Scope`]. Port classification skips a literal
    /// match and treats any other shape like [`MatchExpr::Unrecognized`].
    Iifname { op: String, name: Option<String> },
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
    /// `return`. Classified like [`Verdict::Other`]; kept apart only so
    /// the scoping rule can be recognized.
    Return,
    /// `continue`, `jump`, `goto`, `reject`, `queue`, etc.
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

    /// Build a classifier from captured `nft -j list table inet fips`
    /// output, as [`Self::query`] would from the live kernel.
    #[cfg(test)]
    pub(crate) fn from_nft_json(json: &Value) -> Self {
        Self {
            rules: Some(parse_inbound_rules(json)),
        }
    }

    /// True iff the `inet fips` table is currently loaded — i.e.
    /// `fips-firewall.service` is active.
    pub fn is_active(&self) -> bool {
        self.rules.is_some()
    }

    /// The interface scope of the loaded chain, `None` when no table is
    /// loaded. Read from the first rule that returns or that matches on
    /// the input interface.
    pub fn scope(&self) -> Option<Scope> {
        let rules = self.rules.as_ref()?;
        let Some(rule) = rules.iter().find(|r| {
            r.verdict == Verdict::Return
                || r.matches
                    .iter()
                    .any(|m| matches!(m, MatchExpr::Iifname { .. }))
        }) else {
            return Some(Scope::Unscoped);
        };
        let scope = match (rule.matches.as_slice(), rule.verdict) {
            (
                [
                    MatchExpr::Iifname {
                        op,
                        name: Some(name),
                    },
                ],
                Verdict::Return,
            ) if op == "!=" => Scope::Iface(name.clone()),
            _ => Scope::Unreadable,
        };
        Some(scope)
    }

    /// True only when the table is loaded and polices `tun`: the chain is
    /// unscoped, or scoped to exactly `tun`. A missing table, a chain
    /// scoped to another interface and an unreadable scope are all false,
    /// so the caller reports the TUN as unprotected rather than assuming
    /// it is filtered.
    pub fn polices(&self, tun: &str) -> bool {
        match self.scope() {
            Some(Scope::Unscoped) => true,
            Some(Scope::Iface(name)) => name == tun,
            Some(Scope::Unreadable) | None => false,
        }
    }

    /// The interface the loaded chain is scoped to, when that is a single
    /// interface other than `tun`. This is the case the startup warning
    /// names; an unreadable scope is reported only by [`Self::polices`].
    pub fn foreign_scope(&self, tun: &str) -> Option<String> {
        match self.scope() {
            Some(Scope::Iface(name)) if name != tun => Some(name),
            _ => None,
        }
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
                    MatchExpr::Iifname { name: Some(_), .. } => {
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
                    MatchExpr::Iifname { name: None, .. } | MatchExpr::Unrecognized => {
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
                Verdict::Return | Verdict::Other => {
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

/// Check off the async thread whether the loaded `inet fips` table is
/// scoped to an interface other than the TUN just brought up, and warn
/// once naming both when it is. Called once per TUN bring-up; the `nft`
/// query blocks, so it runs on the blocking pool in a detached task.
#[cfg(target_os = "linux")]
pub fn spawn_scope_check(tun: &str) {
    let tun = tun.to_string();
    tokio::spawn(async move {
        let Ok(classifier) = tokio::task::spawn_blocking(FilterClassifier::query).await else {
            return;
        };
        warn_scope(&classifier, &tun);
    });
}

/// Warn when `classifier`'s table polices another interface than `tun`.
#[cfg(target_os = "linux")]
fn warn_scope(classifier: &FilterClassifier, tun: &str) {
    if let Some(scope) = classifier.foreign_scope(tun) {
        // Kept on the target it had in the control module, so log
        // filters written for it still match.
        tracing::warn!(
            target: "fips::control::firewall_state",
            tun = %tun,
            firewall_iface = %scope,
            "The inet fips firewall polices {scope}, not the TUN {tun}: \
             listeners on {tun} are reachable from the mesh. Set fips_if \
             in /etc/fips/fips.nft to the tun.name and reload the firewall"
        );
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
        } else if let Some(map) = e.get("vmap") {
            // A verdict map picks the verdict per packet. Only one keyed on
            // the input interface is recorded, as an unreadable scope.
            if let Some(key) = map.get("key").and_then(input_iface_key) {
                matches.push(MatchExpr::Iifname {
                    op: format!("vmap {key}"),
                    name: None,
                });
            }
            verdict = Verdict::Other;
        } else if e.get("accept").is_some() {
            verdict = Verdict::Accept;
        } else if e.get("drop").is_some() {
            verdict = Verdict::Drop;
        } else if e.get("counter").is_some() {
            // Bare counter is observational; preserve any earlier
            // verdict (the counter usually precedes the verdict).
            // The trailing `counter drop` rule has only `counter` +
            // `drop` exprs, which is handled above.
        } else if e.get("return").is_some() {
            verdict = Verdict::Return;
        } else if e.get("jump").is_some()
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

    // The input interface, by any key and with any right-hand side
    if let Some(key) = input_iface_key(&left) {
        let name = right
            .as_str()
            .filter(|n| key == "iifname" && !n.starts_with('@') && !n.contains('*'))
            .map(str::to_string);
        return MatchExpr::Iifname {
            op: op.to_string(),
            name,
        };
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

/// The `meta` key of `left` when it names the input interface.
fn input_iface_key(left: &Value) -> Option<&str> {
    let key = left.get("meta")?.get("key")?.as_str()?;
    matches!(key, "iif" | "iifname" | "iifgroup" | "iiftype" | "iifkind").then_some(key)
}

fn parse_proto(s: &str) -> Option<Proto> {
    match s {
        "tcp" => Some(Proto::Tcp),
        "udp" => Some(Proto::Udp),
        _ => None,
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "tests/firewall_state.rs"]
mod target_tests;

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

    /// The shipped baseline's inbound chain as `nft -j` reports it with
    /// `define fips_if = "fips0"` (nft 1.0.9 stores the expanded literal),
    /// with the scoping rule's right-hand side replaced by `scope_rhs`.
    fn baseline_chain(scope_rhs: Value) -> FilterClassifier {
        make_classifier(json!([
            [
                {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": scope_rhs}},
                {"return": null}
            ],
            [
                {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}},
                {"accept": null}
            ],
            [
                {"match": {"op": "==", "left": {"payload": {"protocol": "icmpv6", "field": "type"}}, "right": "echo-request"}},
                {"accept": null}
            ],
            [
                {"counter": {"packets": 0, "bytes": 0}},
                {"drop": null}
            ],
        ]))
    }

    #[test]
    fn inet_fips_scoped_to_fips0_does_not_police_a_tun_named_mesh0() {
        let c = baseline_chain(json!("fips0"));
        assert!(c.is_active());
        assert_eq!(c.scope(), Some(Scope::Iface("fips0".into())));
        assert!(!c.polices("mesh0"));
        assert_eq!(c.foreign_scope("mesh0").as_deref(), Some("fips0"));
    }

    #[test]
    fn inet_fips_scoped_to_fips0_polices_a_tun_named_fips0() {
        let c = baseline_chain(json!("fips0"));
        assert!(c.polices("fips0"));
        assert_eq!(c.foreign_scope("fips0"), None);
        assert_eq!(c.classify(Proto::Tcp, 22), FilterState::Drop);
        assert_eq!(c.classify(Proto::Udp, 5353), FilterState::Drop);
    }

    #[test]
    fn chain_with_no_iifname_return_polices_every_tun() {
        let c = make_classifier(json!([
            [
                {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}},
                {"accept": null}
            ],
            [
                {"counter": {"packets": 0, "bytes": 0}},
                {"drop": null}
            ],
        ]));
        assert_eq!(c.scope(), Some(Scope::Unscoped));
        assert!(c.polices("fips0"));
        assert!(c.polices("mesh0"));
        assert_eq!(c.foreign_scope("mesh0"), None);
    }

    #[test]
    fn scoping_rule_with_a_set_is_reported_as_not_policing() {
        // `iifname != { "fips0", "mesh0" } return`, in the shape nft 1.0.9
        // reports it.
        let c = baseline_chain(json!({"set": ["mesh0", "fips0"]}));
        assert_eq!(c.scope(), Some(Scope::Unreadable));
        assert!(!c.polices("fips0"));
        assert!(!c.polices("mesh0"));
        // Not a single other interface, so the startup warning stays quiet;
        // the listener report still shows the TUN unprotected.
        assert_eq!(c.foreign_scope("mesh0"), None);
    }

    #[test]
    fn scoping_rule_that_matches_the_name_rather_than_excluding_it_is_unreadable() {
        // `iifname "fips0" return` (op `==`) would exempt the mesh instead
        // of scoping to it.
        let c = make_classifier(json!([
            [
                {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "fips0"}},
                {"return": null}
            ],
        ]));
        assert_eq!(c.scope(), Some(Scope::Unreadable));
        assert!(!c.polices("fips0"));
    }

    #[test]
    fn no_table_polices_nothing() {
        let c = FilterClassifier::no_firewall();
        assert_eq!(c.scope(), None);
        assert!(!c.polices("fips0"));
        assert_eq!(c.foreign_scope("fips0"), None);
    }

    /// A chain whose only scoping rule is `scope_rule`, followed by the
    /// baseline's trailing drop.
    fn scoped_by(scope_rule: Value) -> FilterClassifier {
        make_classifier(json!([
            scope_rule,
            [
                {"counter": {"packets": 0, "bytes": 0}},
                {"drop": null}
            ],
        ]))
    }

    #[test]
    fn scoping_by_iifname_vmap_is_unreadable_not_unscoped() {
        // `iifname vmap { "fips0" : continue, * : return }`, as nft 1.0.9
        // reports it: the chain returns everything not on fips0.
        let c = scoped_by(json!([
            {"vmap": {
                "key": {"meta": {"key": "iifname"}},
                "data": {"set": [["fips0", {"continue": null}], ["*", {"return": null}]]}
            }}
        ]));
        assert_eq!(c.scope(), Some(Scope::Unreadable));
        assert!(!c.polices("mesh0"));
        assert!(!c.polices("fips0"));
        assert_eq!(c.foreign_scope("mesh0"), None);
    }

    #[test]
    fn scoping_by_meta_iif_is_unreadable_not_unscoped() {
        // `meta iif != "fips0" return`, as nft 1.0.9 reports it.
        let c = scoped_by(json!([
            {"match": {"op": "!=", "left": {"meta": {"key": "iif"}}, "right": "fips0"}},
            {"return": null}
        ]));
        assert_eq!(c.scope(), Some(Scope::Unreadable));
        assert!(!c.polices("mesh0"));
        assert_eq!(c.foreign_scope("mesh0"), None);
    }

    #[test]
    fn scoping_by_iifgroup_is_unreadable_not_unscoped() {
        let c = scoped_by(json!([
            {"match": {"op": "!=", "left": {"meta": {"key": "iifgroup"}}, "right": 7}},
            {"return": null}
        ]));
        assert_eq!(c.scope(), Some(Scope::Unreadable));
        assert!(!c.polices("mesh0"));
    }

    #[test]
    fn return_on_a_non_interface_match_is_unreadable_not_unscoped() {
        // An early return keyed on anything else also exempts traffic from
        // the trailing drop, so the chain is not taken to police the TUN.
        let c = scoped_by(json!([
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}}, "right": "fd00::1"}},
            {"return": null}
        ]));
        assert_eq!(c.scope(), Some(Scope::Unreadable));
        assert!(!c.polices("fips0"));
    }

    #[test]
    fn wildcard_scope_is_unreadable_and_does_not_name_a_foreign_interface() {
        // `iifname != "fips*" return`: nft reports the wildcard as a plain
        // string. It covers fips0, so naming it as another interface would
        // make the startup warning false.
        let c = baseline_chain(json!("fips*"));
        assert_eq!(c.scope(), Some(Scope::Unreadable));
        assert_eq!(c.foreign_scope("fips0"), None);
        assert!(!c.polices("fips0"));
    }

    #[test]
    fn named_set_scope_is_unreadable_not_an_interface_called_at_set() {
        // `iifname != @meshifs return`: nft reports the set reference as the
        // string "@meshifs".
        let c = baseline_chain(json!("@meshifs"));
        assert_eq!(c.scope(), Some(Scope::Unreadable));
        assert_eq!(c.foreign_scope("fips0"), None);
        assert!(!c.polices("fips0"));
    }

    #[test]
    fn scoping_rule_with_a_counter_still_reads_as_the_interface() {
        // `iifname != "fips0" counter return`: a counter is not a match, so
        // the rule keeps the exact scoping shape.
        let c = scoped_by(json!([
            {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "fips0"}},
            {"counter": {"packets": 0, "bytes": 0}},
            {"return": null}
        ]));
        assert_eq!(c.scope(), Some(Scope::Iface("fips0".into())));
        assert!(c.polices("fips0"));
        assert!(!c.polices("mesh0"));
    }

    #[test]
    fn allow_rule_with_an_iifname_set_classifies_as_unknown() {
        // A set-shaped iifname match on an allow rule is not decomposed,
        // so the port it opens is reported as needing inspection.
        let c = make_classifier(json!([
            [
                {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": {"set": ["fips0", "mesh0"]}}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
                {"accept": null}
            ],
        ]));
        assert_eq!(c.classify(Proto::Tcp, 22), FilterState::Unknown);
    }
}
