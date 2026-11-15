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

/// A `path_pin` reply as the control socket sends it, carrying `pinned`.
fn pin_reply(pinned: Value) -> Value {
    serde_json::json!({"status": "ok", "data": {"pinned": pinned}})
}

#[test]
fn a_pin_not_in_force_is_warned_about_and_names_why() {
    let reply = pin_reply(serde_json::json!({
        "transport_id": 3, "transport": "wifi", "addr": null, "in_force": false
    }));
    let warning = pin_warning(&reply).expect("a pin not in force is warned about");
    assert!(warning.contains("not in force"), "{warning}");
    assert!(warning.contains("wifi"), "names the transport: {warning}");
    assert!(warning.contains("live to the peer"), "says why: {warning}");
    assert!(
        warning.contains("as if unpinned"),
        "says what happens: {warning}"
    );

    let path = pin_reply(serde_json::json!({
        "transport_id": 3, "transport": null, "addr": "10.0.1.2:2121", "in_force": false
    }));
    let warning = pin_warning(&path).expect("a path pin not in force is warned about");
    assert!(
        warning.contains("10.0.1.2:2121"),
        "names the path: {warning}"
    );
    assert!(
        warning.contains('3'),
        "names the transport by id: {warning}"
    );
}

#[test]
fn a_pin_in_force_or_cleared_gets_no_warning() {
    let in_force = pin_reply(serde_json::json!({
        "transport_id": 1, "transport": "main", "addr": null, "in_force": true
    }));
    assert_eq!(pin_warning(&in_force), None);
    assert_eq!(pin_warning(&pin_reply(Value::Null)), None, "an unpin reply");
    let error = serde_json::json!({"status": "error", "message": "no such peer"});
    assert_eq!(pin_warning(&error), None, "an error reply");
}
