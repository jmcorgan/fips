//! One peer flooding a listener leaves the node able to connect and to hear
//! from other peers.
//!
//! Runs the whole request and reply path over a real registry, through the
//! inline suite's harness in `mod.rs`. Each arrival is accepted and its client
//! half dropped without a write, which is the case the daemon pins until the
//! listener closes, so every flow the peer is given stays counted.

use super::tests::{NODE, PEER, accept, arrival_from, ask, connect, limits, listen, readable};

#[tokio::test]
async fn one_peer_that_floods_a_listener_with_refused_flows_leaves_the_node_able_to_connect_and_to_hear_other_peers()
 {
    let (mut connection, _outbound) = connect();
    let (value, listener) = listen(&mut connection, 4242).await;
    assert_eq!(value["status"], "ok", "{value}");

    let mut announced = 0;
    for src in 5000..5000 + limits().max_flows as u16 {
        let value = ask(&mut connection, &arrival_from(PEER, src, 4242, "00")).await;
        assert_eq!(value["status"], "ok", "{value}");
        if value["data"]["outcome"] == "announced" {
            announced += 1;
            readable(&listener).await;
            let (_message, client) = accept(&listener);
            drop(client);
        }
    }

    // Not `ask`: a connect that succeeds carries a descriptor.
    let line = format!(
        r#"{{"command":"connect","params":{{"peer":"{PEER}","remote_port":4243,"local_port":6000}}}}"#
    );
    let (response, _fd) = connection.answer(line.as_bytes()).await;
    let value = serde_json::to_value(response).unwrap();
    assert_eq!(
        value["status"], "ok",
        "after one peer was given {announced} flows, a local connect was refused: {value}"
    );

    let value = ask(&mut connection, &arrival_from(NODE, 5000, 4242, "00")).await;
    assert_eq!(
        value["data"]["outcome"], "announced",
        "after one peer was given {announced} flows, another peer was not heard: {value}"
    );
    drop(listener);
}
