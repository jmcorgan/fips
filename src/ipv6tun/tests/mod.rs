//! Tests of the IPv6 adapter as a whole: its decision modules read no clock
//! and reach no async runtime, channel, thread, OS, I/O, socket or name
//! lookup. They take the time from their caller and return what to do rather
//! than doing it.
//!
//! The check is a scan of each decision module's source, with its comments,
//! string and char literals, and test-only items removed. It is a check of
//! names: a decision module may still import the link's message types from
//! `link.rs`, which also defines the channel ends, so this does not make the
//! decision modules compile without tokio, and an item reached under a name
//! not on its lists passes.
//!
//! The DNS responder (`dns.rs`) is a driver here: its query decisions
//! (`reply_path`, `mesh_query`, `returns_by`, `screened`,
//! `Answering::receive` and `answer`) share the file with its sockets, so
//! the scan does not read them, and a clock read or socket call added to one
//! of them would pass.

pub(super) mod scan;

use scan::{close, ident, literal_end};

/// The adapter's decision modules, which decide and return what to do,
/// taking the time as an argument.
const DECISIONS: &[(&str, &str)] = &[
    ("config.rs", include_str!("../config.rs")),
    ("core.rs", include_str!("../core.rs")),
    ("exthdr.rs", include_str!("../exthdr.rs")),
    ("icmp.rs", include_str!("../icmp.rs")),
    ("icmp_rate_limit.rs", include_str!("../icmp_rate_limit.rs")),
    ("inbound.rs", include_str!("../inbound.rs")),
    ("ipv6_shim.rs", include_str!("../ipv6_shim.rs")),
    ("mss.rs", include_str!("../mss.rs")),
    ("mtu.rs", include_str!("../mtu.rs")),
    ("outbound.rs", include_str!("../outbound.rs")),
    ("tcp_mss.rs", include_str!("../tcp_mss.rs")),
];

/// The adapter's other modules, which run the decisions or reach the
/// runtime, the OS or sockets, and which the scan leaves alone.
const DRIVERS: &[&str] = &[
    "bsdnet",
    "dns",
    "firewall_state",
    "lifecycle",
    "link",
    "listening",
    "queue",
    "status",
    "tun",
    "winnet",
];

/// Names a decision module may not use anywhere outside its comments,
/// literals and test-only items.
const NAMES: &[&str] = &[
    // The async runtime and its combinators.
    "tokio",
    "futures",
    "block_on",
    "spawn",
    "async",
    "await",
    // Channels and the adapter's own channel ends.
    "mpsc",
    "crossbeam",
    "crossbeam_channel",
    "Sender",
    "SyncSender",
    "Receiver",
    "UnboundedSender",
    "UnboundedReceiver",
    "TunTx",
    "MeshLink",
    "HostLink",
    "DatagramRx",
    "LearnedRx",
    // Threads.
    "thread",
    "sleep",
    // Clocks.
    "SystemTime",
    "UNIX_EPOCH",
    "HostClock",
    "mono_ms",
    "wall_ms",
    "elapsed",
    // The OS and its devices.
    "libc",
    "nix",
    "rtnetlink",
    "netlink_packet_route",
    "wintun",
    // Sockets.
    "socket2",
    "UdpSocket",
    "TcpStream",
    "TcpListener",
    "UnixStream",
    "UnixListener",
    "UnixDatagram",
    // Name lookups.
    "ToSocketAddrs",
    "to_socket_addrs",
];

/// Path segments a decision module may not name a path through: the OS and
/// I/O modules of `std`, the `tun` and Windows crates, and the adapter's own
/// driver modules.
const PATHS: &[&str] = &[
    "fs",
    "io",
    "process",
    "os",
    "env",
    "tun",
    "windows",
    "windows_sys",
    "bsdnet",
    "dns",
    "firewall_state",
    "lifecycle",
    "listening",
    "queue",
    "status",
    "winnet",
];

/// Functions a decision module may not call or name as a path: the clock
/// read `now`, counted against [`CLOCK_READS`], and the link's `pair`, which
/// makes channels.
const CALLS: &[&str] = &["now", "pair"];

/// The clock reads a decision module may make, by file: the limiter's
/// public `should_send`, which reads the clock for a caller outside the
/// adapter. Nothing in the adapter calls it.
const CLOCK_READS: &[(&str, usize)] = &[("icmp_rate_limit.rs", 1)];

/// `source` with comments removed and every string and char literal left as
/// `""`; attributes are kept.
fn uncommented(source: &str) -> Vec<char> {
    let chars: Vec<char> = source.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if let Some(end) = literal_end(&chars, i) {
            out.extend(['"', '"']);
            i = end;
            continue;
        }
        match (chars[i], chars.get(i + 1).copied()) {
            ('/', Some('/')) => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            ('/', Some('*')) => {
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Whether the attribute text between `#[` and `]` compiles its item only in
/// a test build: `cfg(test)` or `cfg(all(test, ..))`.
fn test_only(attribute: &str) -> bool {
    let compact: String = attribute.chars().filter(|c| !c.is_whitespace()).collect();
    compact == "cfg(test)" || compact.starts_with("cfg(all(test,")
}

/// The index just past the item that starts at `at`: through its braced
/// body, or its `;`, or up to the `,` or closing bracket that ends a field
/// or a match arm.
fn item_end(chars: &[char], at: usize) -> usize {
    let mut i = at;
    while i < chars.len() {
        match chars[i] {
            '"' => i += 2,
            '#' if chars.get(i + 1) == Some(&'[') => i = close(chars, i + 1) + 1,
            '(' | '[' => i = close(chars, i) + 1,
            '{' => return close(chars, i) + 1,
            ';' | ',' => return i + 1,
            ')' | ']' | '}' => return i,
            _ => i += 1,
        }
    }
    chars.len()
}

/// `source` with comments, literals and test-only items removed: the code a
/// normal build of the module compiles.
fn shipped(source: &str) -> String {
    let chars = uncommented(source);
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '#' && chars.get(i + 1) == Some(&'[') {
            let end = close(&chars, i + 1);
            let attribute: String = chars[i + 2..end.min(chars.len())].iter().collect();
            if test_only(&attribute) {
                i = item_end(&chars, end + 1);
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Each name in `source` that a decision module may not use, as it appears:
/// a name from [`NAMES`]; a name from [`CALLS`] called or reached as a path;
/// or a segment of [`PATHS`] in a path or renamed by `as`.
fn forbidden(source: &str) -> Vec<String> {
    let chars: Vec<char> = shipped(source).chars().collect();
    let mut found = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if !ident(chars[i]) || chars[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && ident(chars[i]) {
            i += 1;
        }
        let name: String = chars[start..i].iter().collect();
        let mut next = i;
        while next < chars.len() && chars[next].is_whitespace() {
            next += 1;
        }
        let mut back = start;
        while back > 0 && chars[back - 1].is_whitespace() {
            back -= 1;
        }
        let after = chars.get(next) == Some(&':') && chars.get(next + 1) == Some(&':');
        let before = back >= 2 && chars[back - 1] == ':' && chars[back - 2] == ':';
        let renamed = chars.get(next) == Some(&'a')
            && chars.get(next + 1) == Some(&'s')
            && !chars.get(next + 2).is_some_and(|c| ident(*c));
        let called = chars.get(next) == Some(&'(') || before;
        if NAMES.contains(&name.as_str()) || (called && CALLS.contains(&name.as_str())) {
            found.push(name);
        } else if (after || before || renamed) && PATHS.contains(&name.as_str()) {
            found.push(format!("{name}::"));
        }
    }
    found
}

/// The clock reads [`CLOCK_READS`] allows in `file`.
fn allowed_reads(file: &str) -> usize {
    CLOCK_READS
        .iter()
        .find(|(name, _)| *name == file)
        .map_or(0, |(_, n)| *n)
}

/// No decision module names a runtime, channel, thread, clock, OS, I/O,
/// socket or name lookup item outside its comments, literals and test-only
/// items, and only the limiter's public wrapper reads the clock.
#[test]
fn no_decision_module_names_a_runtime_channel_thread_clock_os_or_socket_item() {
    for (file, source) in DECISIONS {
        let found = forbidden(source);
        let reads = found.iter().filter(|name| *name == "now").count();
        let others: Vec<&String> = found.iter().filter(|name| *name != "now").collect();
        assert!(others.is_empty(), "{file} names {others:?}");
        assert_eq!(
            reads,
            allowed_reads(file),
            "{file} reads the clock {reads} times, not the {} allowed",
            allowed_reads(file)
        );
    }
}

/// Every module the adapter declares is classed as a decision module or a
/// driver, and only one of them, so a new module is classed before it is
/// left unscanned.
#[test]
fn every_module_of_the_adapter_is_either_a_decision_module_or_a_driver() {
    let root: String = shipped(include_str!("../mod.rs"));
    let words: Vec<&str> = root
        .split(|c| !ident(c))
        .filter(|w| !w.is_empty())
        .collect();
    let declared: Vec<String> = words
        .windows(2)
        .filter(|pair| pair[0] == "mod")
        .map(|pair| pair[1].to_string())
        .collect();
    assert!(
        declared.len() >= 20,
        "the scan reads the declarations: {declared:?}"
    );
    for name in &declared {
        let decision = DECISIONS
            .iter()
            .any(|(file, _)| file.strip_suffix(".rs") == Some(name.as_str()));
        let driver = DRIVERS.contains(&name.as_str());
        assert!(
            decision != driver,
            "{name} must be exactly one of a decision module or a driver"
        );
    }
    assert_eq!(
        declared.len(),
        DECISIONS.len() + DRIVERS.len(),
        "every listed module is declared: {declared:?}"
    );
}

/// A copy of `outbound.rs` with `line` added at its end.
fn planted(line: &str) -> String {
    format!("{}\n{line}\n", include_str!("../outbound.rs"))
}

/// The scan finds each kind of runtime item planted in a decision module
/// that, as it stands, names none.
#[test]
fn the_scan_finds_a_runtime_item_planted_in_a_decision_module() {
    assert_eq!(
        forbidden(include_str!("../outbound.rs")),
        Vec::<String>::new()
    );
    for (line, name) in [
        ("use tokio::sync::mpsc::Sender;", "tokio"),
        ("use std::sync::mpsc;", "mpsc"),
        ("use super::tun::TunTx;", "tun::"),
        ("use super::queue::TunTx;", "queue::"),
        ("use std::thread;", "thread"),
        (
            "fn tick() -> std::time::Instant { std::time::Instant::now() }",
            "now",
        ),
        ("fn tick() -> u64 { crate::time::mono_ms() }", "mono_ms"),
        ("fn raw() -> i32 { unsafe { libc::getpid() } }", "libc"),
        ("fn out() { let _ = std::io::stdout(); }", "io::"),
        ("use std::io::{self, Write};", "io::"),
        (
            "fn any<T: std::net::ToSocketAddrs>(_: T) {}",
            "ToSocketAddrs",
        ),
        (
            "fn resolve() { use std::net::*; let _ = \"localhost:53\".to_socket_addrs(); }",
            "to_socket_addrs",
        ),
        (
            "fn read() { let _ = std::fs::read(\"/etc/hosts\"); }",
            "fs::",
        ),
        (
            "fn probe() { let _ = std::net::UdpSocket::bind(\"[::]:0\"); }",
            "UdpSocket",
        ),
        (
            "fn old(t: std::time::Instant) -> bool { t.elapsed().as_secs() > 1 }",
            "elapsed",
        ),
        (
            "fn at(t: Option<Instant>) -> Instant { t.unwrap_or_else(Instant::now) }",
            "now",
        ),
        (
            "async fn drain() { std::future::pending::<()>().await; }",
            "async",
        ),
        (
            "async fn drain() { std::future::pending::<()>().await; }",
            "await",
        ),
        ("use super::link::DatagramRx;", "DatagramRx"),
        ("use super::link::LearnedRx;", "LearnedRx"),
        (
            "fn wire() { let _ = crossbeam_channel::bounded::<u8>(1); }",
            "crossbeam_channel",
        ),
        ("fn wire() { let _ = super::link::pair(1, 1); }", "pair"),
        ("use crate::ipv6tun::lifecycle as driver;", "lifecycle::"),
        (
            "use super::{lifecycle as driver, link::Datagram};",
            "lifecycle::",
        ),
    ] {
        assert!(
            forbidden(&planted(line)).iter().any(|found| found == name),
            "{line} must be found as {name}: {:?}",
            forbidden(&planted(line))
        );
    }
}

/// The scan does not count a name in a comment, a string literal or a
/// test-only item, but does count one in an item a feature also compiles.
#[test]
fn the_scan_ignores_names_in_comments_literals_and_test_only_items() {
    for line in [
        "// The reader thread hands tokio a TunTx.",
        "/* std::thread::spawn */",
        "/// Not a clock read: Instant::now().",
        "const NOTE: &str = \"tokio::spawn and std::fs\";",
        "const RAW: &str = r#\"a \"quoted\" libc::close\"#;",
        "#[cfg(test)]\nmod probe {\n    use std::thread;\n    fn now() {}\n}",
        "#[cfg(test)]\nfn tick() -> std::time::Instant { std::time::Instant::now() }",
        "#[cfg(all(test, target_os = \"linux\"))]\nuse std::sync::mpsc;",
    ] {
        assert_eq!(forbidden(&planted(line)), Vec::<String>::new(), "{line}");
    }
    let shared = "#[cfg(any(test, feature = \"test-hooks\"))]\nuse std::thread;";
    assert_eq!(forbidden(&planted(shared)), vec!["thread".to_string()]);
}
