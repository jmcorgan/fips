//! Every refusal the native API sends stays small, whatever the client wrote.
//!
//! A refusal can echo client text: an unknown command's name, or serde's
//! reason for refusing a parameter, which quotes the value. A command line may
//! be up to `MAX_COMMAND` bytes, and serde_json writes a control character as
//! a six-byte `\u00XX`, so without a bound the reply grows past what the setup
//! socket takes in one send. On macOS a local stream socket splits a send over
//! 2048 bytes, and the daemon ends the connection on a short write. These
//! tests hold every refusal under that size, measured as the bytes the daemon
//! writes: the serialised reply and its newline.
//!
//! Runs through the inline suite's harness in `mod.rs`.

use super::tests::{PEER, call, connect, send_line, serve_socket};
use super::unix_impl::{MAX_COMMAND, MAX_MESSAGE, clip};
use std::io::Read;

/// The size every reply must stay under: xnu's send low-water mark for a
/// local stream socket, below which a non-blocking send is never split.
const SPLIT: usize = 2048;

/// A command line of exactly `MAX_COMMAND` bytes naming an unknown command,
/// its name made of `unit` (a JSON-escaped character or a plain one) repeated.
fn unknown_command(unit: &str) -> String {
    let frame = r#"{"command":""}"#.len();
    let room = MAX_COMMAND - frame;
    let mut name = unit.repeat(room / unit.len());
    name.push_str(&"x".repeat(room - name.len()));
    let line = format!(r#"{{"command":"{name}"}}"#);
    assert_eq!(line.len(), MAX_COMMAND);
    line
}

/// A `connect` line whose `remote_port` is a long string, so serde refuses it
/// and quotes the value in its reason.
fn connect_with_long_port(unit: &str) -> String {
    let frame = format!(r#"{{"command":"connect","params":{{"peer":"{PEER}","remote_port":""}}}}"#);
    let room = MAX_COMMAND - frame.len();
    let mut value = unit.repeat(room / unit.len());
    value.push_str(&"x".repeat(room - value.len()));
    let line =
        format!(r#"{{"command":"connect","params":{{"peer":"{PEER}","remote_port":"{value}"}}}}"#);
    assert_eq!(line.len(), MAX_COMMAND);
    line
}

/// Answer one line and return the bytes the daemon would write for it, with
/// the reply as JSON for the failure message.
async fn written(line: &str) -> (usize, serde_json::Value) {
    let (mut connection, _outbound) = connect();
    let (response, fd) = connection.answer(line.as_bytes()).await;
    assert!(fd.is_none(), "a refusal carries no descriptor");
    let bytes = serde_json::to_string(&response).unwrap().len() + 1;
    (bytes, serde_json::to_value(response).unwrap())
}

/// Assert a reply is a refusal and fits under [`SPLIT`].
fn assert_small_refusal(bytes: usize, value: &serde_json::Value) {
    assert_eq!(value["status"], "error", "expected a refusal: {value}");
    assert_eq!(value["data"]["errno"], "EINVAL", "{value}");
    assert!(
        bytes < SPLIT,
        "the refusal is {bytes} bytes on the wire, not under {SPLIT}"
    );
}

#[tokio::test]
async fn a_refusal_of_an_oversized_unknown_command_stays_under_2048_bytes() {
    let (bytes, value) = written(&unknown_command("x")).await;
    assert_small_refusal(bytes, &value);
}

#[tokio::test]
async fn a_refusal_of_an_unknown_command_made_of_control_characters_stays_under_2048_bytes() {
    let (bytes, value) = written(&unknown_command(r"\u0001")).await;
    assert_small_refusal(bytes, &value);
}

#[tokio::test]
async fn a_refusal_of_bad_params_quoting_a_long_value_stays_under_2048_bytes() {
    for unit in ["x", r"\u0001"] {
        let (bytes, value) = written(&connect_with_long_port(unit)).await;
        let message = value["message"].as_str().unwrap_or_default();
        assert!(
            message.starts_with("invalid params for 'connect'"),
            "expected serde's refusal of the port: {value}"
        );
        assert_small_refusal(bytes, &value);
    }
}

#[tokio::test]
async fn a_connection_answers_a_valid_command_after_an_oversized_refusal() {
    let (connection, _outbound) = connect();
    let (client, task) = serve_socket(&connection);

    // Longer than the client socket holds, so it goes in pieces the serving
    // task drains in between; a blocking write here wedged the runtime on
    // macOS.
    send_line(&client, unknown_command(r"\u0001").as_bytes()).await;
    super::tests::readable(&client).await;
    let mut reply = Vec::new();
    let mut reader = &client;
    let mut buf = [0u8; 4096];
    while !reply.ends_with(b"\n") {
        let n = reader
            .read(&mut buf)
            .expect("the refusal should arrive whole on a connection that stays open");
        assert!(n > 0, "the connection closed after the refusal");
        reply.extend_from_slice(&buf[..n]);
    }
    let value: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(value["status"], "error", "{value}");

    let (value, fd) = call(
        &client,
        r#"{"command":"listen","params":{"local_port":4242}}"#,
    )
    .await;
    assert_eq!(value["status"], "ok", "{value}");
    assert!(
        fd.is_some(),
        "a listen reply carries the listener's descriptor"
    );
    assert!(!task.is_finished(), "the serving task ended");
}

/// The clip's width table is checked against serde_json's own serialiser, so
/// if the two ever disagree on how a character is escaped, this goes red.
#[test]
fn clip_keeps_the_serialised_width_within_the_bound_for_every_ascii_byte_and_multibyte_text() {
    let mut samples: Vec<String> = (0u8..=0x7f)
        .map(|byte| char::from(byte).to_string().repeat(MAX_MESSAGE + 1))
        .collect();
    samples.push("\u{e9}".repeat(MAX_MESSAGE));
    samples.push("\u{1f980}".repeat(MAX_MESSAGE));
    samples.push(format!("{}\u{1}", "x".repeat(MAX_MESSAGE - 5)));

    for sample in samples {
        let clipped = clip(sample.clone());
        let width = serde_json::to_string(&clipped).unwrap().len();
        assert!(
            width <= MAX_MESSAGE + 2,
            "{:?}... serialises to {width} bytes after the clip, over {}",
            sample.chars().next(),
            MAX_MESSAGE + 2
        );
        assert!(clipped.ends_with('\u{2026}'), "a clipped message is marked");
    }

    let short = "unknown command 'teleport'".to_string();
    assert_eq!(
        clip(short.clone()),
        short,
        "a message that fits is unchanged"
    );
    let exact = "x".repeat(MAX_MESSAGE);
    assert_eq!(
        clip(exact.clone()),
        exact,
        "a message at the bound is unchanged"
    );
}
