//! The packet socket's kernel drop count.

use super::*;

#[test]
fn frames_a_full_receive_buffer_turns_away_are_counted_and_the_count_resets_when_read() {
    // An ethertype of its own, so no other test's socket on lo shares the
    // frames.
    let Ok(socket) = PacketSocket::open("lo", 0x88b6) else {
        // Unprivileged: the socket cannot be opened at all. Loud on a runner
        // that claims privilege, so this cannot go quiet.
        assert!(
            std::env::var_os("FIPS_TEST_PRIVILEGED").is_none(),
            "this runner declares FIPS_TEST_PRIVILEGED but cannot open a \
             raw socket on lo: the drop count went unexercised"
        );
        return;
    };
    // The smallest buffer the kernel allows, never read: lo hands every
    // frame sent here back to this socket, and all but the first few find
    // it full.
    socket.set_recv_buffer_size(0).unwrap();
    let mac = socket.local_mac().unwrap();
    let payload = [0u8; 1000];
    for _ in 0..200 {
        socket.send_to(&payload, &mac).unwrap();
    }
    let drops = socket.take_drops().unwrap();
    assert!(
        drops > 100,
        "200 frames into a buffer of a few: only {drops} counted as dropped"
    );
    assert_eq!(socket.take_drops().unwrap(), 0, "the read must reset it");
}
