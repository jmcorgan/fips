//! The requests `fipsctl path show`, `pin` and `unpin` send, checked
//! against the request fixture the control socket's round trip test also
//! sends, so the client and the daemon are tested against one source.
//! Builds requests only and opens no socket, so it runs on every platform.

use super::*;
use serde_json::Value;

/// The request fixture shared with the control socket's round trip test.
const FIXTURE: &str = include_str!("../../control/snapshots/fipsctl_path_requests.json");

/// A peer identifier `resolve_peer` passes through unchanged.
const NPUB: &str = "npub1pathtestpeer";

/// The address put in place of the fixture's `<addr>`.
const ADDR: &str = "10.0.1.2:2121";

/// The request `fipsctl` sends for `args`, parsed back into JSON.
fn request_for(args: &[&str]) -> Value {
    let cli = Cli::try_parse_from(std::iter::once("fipsctl").chain(args.iter().copied()))
        .unwrap_or_else(|e| panic!("fipsctl {args:?} does not parse: {e}"));
    let Commands::Path { what } = &cli.command else {
        panic!("fipsctl {args:?} is not a path command");
    };
    let line = path_request(what);
    assert!(line.ends_with('\n'), "a request is one line");
    serde_json::from_str(line.trim_end()).expect("the request is JSON")
}

#[test]
fn the_path_commands_build_the_requests_the_daemon_takes() {
    let fixture = FIXTURE.replace("<npub>", NPUB).replace("<addr>", ADDR);
    let cases: Vec<Value> = serde_json::from_str(&fixture).expect("the fixture is JSON");
    assert_eq!(cases.len(), 3, "pin, show and unpin");
    for case in &cases {
        let args: Vec<&str> = case["args"]
            .as_array()
            .expect("args")
            .iter()
            .map(|a| a.as_str().expect("an arg is a string"))
            .collect();
        assert_eq!(
            request_for(&args),
            case["request"],
            "fipsctl {args:?} sends the fixture's request"
        );
    }

    let bare = request_for(&["path", "pin", NPUB, "cable"]);
    assert_eq!(bare["command"], "path_pin");
    assert_eq!(bare["params"]["transport"], "cable");
    assert_eq!(bare["params"]["npub"], NPUB);
    assert!(
        bare["params"].get("address").is_none(),
        "a pin without an address names the whole transport"
    );
}
