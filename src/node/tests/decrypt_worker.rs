//! The memory a decrypt worker's queue holds, and what the queue does when it
//! is full.
//!
//! Each worker's crossbeam channel allocates every slot when it is created,
//! and each slot is the size of the largest [`WorkerMsg`] plus crossbeam's
//! one-word stamp, so a node holds `WORKER_CHANNEL_CAP` slots per worker from
//! startup, idle or not. These tests guard both factors: the slot type stays
//! the size of a packet job, and the depth times the slot stays within a
//! budget, checked by arithmetic and by the resident memory a pool makes when
//! it starts. They also check that a full queue still drops rather than
//! blocks, and that a boxed registration still reaches the worker's table.
//!
//! Child of `decrypt_worker`, so it reaches the module's private items.

use super::*;
use ring::aead::{CHACHA20_POLY1305, UnboundKey};
use std::mem::size_of;

/// Most bytes one decrypt worker's idle channel may hold: the next whole MiB
/// above 1.25 times `WORKER_CHANNEL_CAP` slots of 136 bytes (a 128-byte
/// message and an 8-byte stamp).
const CHANNEL_BUDGET: usize = 3 << 20;

/// The key every test session seals and opens under.
const KEY: [u8; 32] = [7u8; 32];

fn cipher() -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &KEY).unwrap())
}

fn session() -> OwnedSessionState {
    OwnedSessionState {
        fmp_cipher: cipher(),
        fmp_replay: ReplayWindow::new(),
        source_npub: None,
        replay_total: Default::default(),
    }
}

/// A job carrying one frame sealed under [`KEY`] at `counter`, for the session
/// `cache_key` names.
fn sealed_job(
    seal: &LessSafeKey,
    cache_key: u32,
    counter: u64,
    fallback_tx: UnboundedSender<DecryptWorkerEvent>,
) -> DecryptJob {
    const HDR: usize = crate::proto::fmp::wire::ESTABLISHED_HEADER_SIZE;
    let header = [0u8; HDR];
    let mut wire = Vec::with_capacity(HDR + 5 + 16);
    wire.extend_from_slice(&header);
    wire.extend_from_slice(&[0u8; 4]);
    wire.push(0xAB);
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    let tag = seal
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&header),
            &mut wire[HDR..],
        )
        .unwrap();
    wire.extend_from_slice(tag.as_ref());
    DecryptJob {
        packet_data: wire,
        cache_key,
        _transport_id: TransportId::new(1),
        _remote_addr: TransportAddr::from_string("127.0.0.1:1234"),
        timestamp_ms: 1_000,
        source_node_addr: NodeAddr::from_bytes([1u8; 16]),
        fmp_counter: counter,
        fmp_flags: 0,
        fmp_header: header,
        fmp_ciphertext_offset: HDR,
        fallback_tx,
    }
}

/// Every slot of the queue is the size of the largest message, so no message
/// may be much larger than the per-packet job. The sizes are printed; run
/// with `--nocapture` to see them.
#[test]
fn a_decrypt_channel_slot_is_no_larger_than_a_packet_job_plus_a_tag_word() {
    let msg = size_of::<WorkerMsg>();
    let job = size_of::<DecryptJob>();
    eprintln!(
        "size_of WorkerMsg {msg} B, DecryptJob {job} B, OwnedSessionState {} B",
        size_of::<OwnedSessionState>()
    );
    assert!(
        msg <= job + size_of::<usize>(),
        "a decrypt queue slot holds {msg} B where a packet job needs {job} B: a large \
         message variant sets the size of every slot of every worker's queue"
    );
}

/// The memory a worker's queue holds from startup is its depth times its slot,
/// and stays within the budget.
#[test]
fn a_decrypt_workers_idle_channel_fits_its_memory_budget() {
    let bytes = WORKER_CHANNEL_CAP * (size_of::<WorkerMsg>() + size_of::<usize>());
    assert!(
        bytes <= CHANNEL_BUDGET,
        "a decrypt worker's queue of {WORKER_CHANNEL_CAP} slots holds {bytes} B from \
         startup, over its budget of {CHANNEL_BUDGET} B"
    );
}

/// The resident memory of this process, in KiB.
#[cfg(target_os = "linux")]
fn vm_rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status reads");
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("/proc/self/status carries VmRSS in kB")
}

/// Starting a pool of eight workers makes no more memory resident than eight
/// queue budgets. The measurement runs in a child process running only this
/// test, so no other test's threads allocate meanwhile and no memory another
/// test freed is reused. It measures the start, holding each pool, rather
/// than a drop, since freed memory can stay resident. The child starts three
/// pools and reports the least that any of them added.
#[cfg(target_os = "linux")]
#[test]
fn spawning_eight_decrypt_workers_makes_at_most_the_budgeted_memory_resident() {
    const CHILD: &str = "FIPS_TEST_RSS_CHILD";
    const WORKERS: usize = 8;
    const MARK: &str = "RSS_DELTA_KIB=";
    if std::env::var_os(CHILD).is_some() {
        let mut pools = Vec::new();
        let mut least = u64::MAX;
        for _ in 0..3 {
            let before = vm_rss_kib();
            pools.push(DecryptWorkerPool::spawn(WORKERS));
            least = least.min(vm_rss_kib().saturating_sub(before));
        }
        println!("{MARK}{least}");
        return;
    }

    let path = module_path!();
    let module = path.split_once("::").map_or(path, |(_, rest)| rest);
    let name = format!(
        "{module}::spawning_eight_decrypt_workers_makes_at_most_the_budgeted_memory_resident"
    );
    let out = std::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .expect("precondition: the test binary runs again as a child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "precondition: the child measurement ran\n{stdout}\n{stderr}"
    );
    // libtest prints a test's output after its name on the same line.
    let kib: u64 = stdout
        .lines()
        .find_map(|line| line.split_once(MARK))
        .and_then(|(_, figure)| figure.split_whitespace().next())
        .unwrap_or_else(|| panic!("precondition: the child reported {MARK}\n{stdout}\n{stderr}"))
        .parse()
        .expect("precondition: the child's figure parses");
    let budget = (WORKERS * CHANNEL_BUDGET / 1024) as u64;
    eprintln!("{WORKERS} decrypt workers made {kib} KiB resident; budget {budget} KiB");
    assert!(
        kib <= budget,
        "starting {WORKERS} decrypt workers made {kib} KiB resident, over the {budget} KiB \
         their queues are budgeted"
    );
}

/// A worker that has not started holds what it is sent. Its queue takes the
/// registration and then jobs until it is full; every job past that is
/// dropped and reported full, and dispatch never waits for the worker. Once
/// started, the worker decrypts every job its queue took.
#[cfg(unix)]
#[test]
fn a_held_decrypt_worker_handles_what_its_channel_holds_and_drops_the_rest() {
    const OVER: usize = 10;
    let (start, held) = std::sync::mpsc::channel();
    let pool = DecryptWorkerPool::held(held);
    let release = HeldRelease::arm(start.clone());
    let key = 5u32;
    assert!(
        pool.register_session(key, session()),
        "precondition: the empty queue took the registration"
    );
    let (fallback_tx, mut fallback_rx) = tokio::sync::mpsc::unbounded_channel();
    let seal = cipher();
    let mut full = 0;
    for counter in 1..=(WORKER_CHANNEL_CAP + OVER) as u64 {
        match pool.dispatch_job(sealed_job(&seal, key, counter, fallback_tx.clone())) {
            Dispatched::Queued => {}
            Dispatched::Full => full += 1,
            Dispatched::Refused => panic!("precondition: the held worker is live"),
        }
    }
    assert!(
        !release.disarm(),
        "dispatch waited on the held worker's full queue until it was released"
    );
    assert_eq!(
        full,
        OVER + 1,
        "a queue of {WORKER_CHANNEL_CAP} holding one registration takes \
         {WORKER_CHANNEL_CAP} - 1 jobs and refuses the rest"
    );

    start.send(()).expect("precondition: the held worker waits");
    pool.barrier();
    let mut plaintext = 0;
    while let Ok(event) = fallback_rx.try_recv() {
        match event {
            DecryptWorkerEvent::Plaintext(_) => plaintext += 1,
            DecryptWorkerEvent::DecryptFailure(_) => panic!("a sealed job failed to open"),
        }
    }
    assert_eq!(
        plaintext,
        WORKER_CHANNEL_CAP - 1,
        "every job the queue took is decrypted"
    );
}

/// A registration carries its session boxed; the worker installs it, and a
/// job for that session then opens and is passed back as plaintext.
#[test]
fn a_boxed_session_registration_is_installed_and_decrypts_the_sessions_frames() {
    let key = 9u32;
    let mut sessions = HashMap::new();
    handle_msg(
        0,
        &mut sessions,
        WorkerMsg::RegisterSession {
            cache_key: key,
            state: Box::new(session()),
        },
    );
    assert!(sessions.contains_key(&key), "the session was installed");

    let (fallback_tx, mut fallback_rx) = tokio::sync::mpsc::unbounded_channel();
    handle_msg(
        0,
        &mut sessions,
        WorkerMsg::Job(sealed_job(&cipher(), key, 1, fallback_tx)),
    );
    match fallback_rx.try_recv() {
        Ok(DecryptWorkerEvent::Plaintext(fallback)) => assert_eq!(fallback.receiver_idx, key),
        Ok(DecryptWorkerEvent::DecryptFailure(_)) => panic!("the installed session failed to open"),
        Err(error) => panic!("the job produced no event: {error:?}"),
    }
}
