//! Tests for `Config::validate_tor_auth`: a Tor `control_auth` password with
//! a line break is refused when the config is validated.

use super::*;

fn tor_config(yaml: &str) -> Config {
    serde_yaml::from_str(yaml).expect("config parses")
}

#[test]
fn validate_refuses_a_tor_password_with_a_line_feed_without_echoing_it() {
    let config = tor_config(
        "transports:\n  tor:\n    mode: control_port\n    control_auth: \"password:pw\\nGETINFO version\"\n",
    );
    let msg = config
        .validate()
        .expect_err("validation should fail")
        .to_string();
    assert!(msg.contains("transports.tor.control_auth"), "got: {msg}");
    assert!(msg.contains("line break"), "got: {msg}");
    assert!(!msg.contains("GETINFO"), "defect: password echoed: {msg}");
}

#[test]
fn validate_refuses_a_carriage_return_in_a_named_tor_instance_password() {
    let config = tor_config(
        "transports:\n  tor:\n    onion:\n      mode: control_port\n      control_auth: \"password:pw\\rsecret\"\n",
    );
    let msg = config
        .validate()
        .expect_err("validation should fail")
        .to_string();
    assert!(
        msg.contains("transports.tor.onion.control_auth"),
        "got: {msg}"
    );
    assert!(!msg.contains("secret"), "defect: password echoed: {msg}");
}

#[test]
fn validate_accepts_an_ordinary_tor_password_and_cookie_auth() {
    for auth in [
        "password:correct horse \\\"battery\\\"",
        "cookie",
        "cookie:/run/tor/cookie",
    ] {
        let config = tor_config(&format!(
            "transports:\n  tor:\n    mode: control_port\n    control_auth: \"{auth}\"\n"
        ));
        config
            .validate()
            .unwrap_or_else(|e| panic!("{auth} should validate: {e}"));
    }
}
