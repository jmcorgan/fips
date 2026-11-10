//! Tests for `testutil.rs`: the bounded runner the explorers use, whose
//! bound `.config/nextest.toml` declares to nextest.

use alloc::vec::Vec;
use core::cell::Cell;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use super::*;

/// The most jobs `bounded` runs at once on this host.
fn most() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().min(WORKERS))
}

#[test]
fn bounded_runs_its_most_jobs_at_once_and_never_more_and_returns_them_in_order() {
    let most = most();
    // (jobs running now, the most seen running at once)
    let live = (Mutex::new((0usize, 0usize)), Condvar::new());
    let items: Vec<usize> = (0..most * 3).collect();
    let out = bounded(&items, |&i| {
        let (m, cv) = &live;
        let mut g = m.lock().unwrap();
        g.0 += 1;
        g.1 = g.1.max(g.0);
        cv.notify_all();
        if i < most {
            // The first jobs start with no place to wait for, so each
            // waits for all of them: a runner that ran fewer at once ends
            // here. Then they hold their places a while, so the count
            // shows a job a runner started beyond them.
            let (g2, waited) = cv
                .wait_timeout_while(g, Duration::from_secs(60), |g| g.0 < most)
                .unwrap();
            assert!(!waited.timed_out(), "job {i} never saw {most} running");
            let (g2, _) = cv
                .wait_timeout_while(g2, Duration::from_millis(200), |g| g.0 <= most)
                .unwrap();
            g = g2;
        }
        g.0 -= 1;
        i * 10
    });
    assert_eq!(out, items.iter().map(|i| i * 10).collect::<Vec<_>>());
    assert_eq!(
        live.0.lock().unwrap().1,
        most,
        "the most jobs running at once"
    );
}

#[test]
fn jobs_that_panic_free_their_places_and_a_panic_is_raised_after_every_job_ran() {
    let most = most();
    let items: Vec<usize> = (0..most * 3).collect();
    let (sent, got) = std::sync::mpsc::channel();
    // On a thread of its own, so a runner whose failed jobs kept their
    // places, and so never started the rest, fails this test rather than
    // holding it.
    std::thread::spawn(move || {
        let ran = AtomicUsize::new(0);
        let caught = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
            bounded(&items, |&i| {
                ran.fetch_add(1, Ordering::SeqCst);
                // Every place's first job fails.
                assert!(i >= most, "job {i} fails");
            })
        }));
        let _ = sent.send((caught.is_err(), ran.load(Ordering::SeqCst), items.len()));
    });
    let (raised, ran, all) = got
        .recv_timeout(Duration::from_secs(60))
        .expect("the run ends once its failed jobs end");
    assert!(raised, "a job's panic is raised");
    assert_eq!(ran, all, "every job ran");
}

std::thread_local! {
    /// Whether a job has run on this thread.
    static USED: Cell<bool> = const { Cell::new(false) };
}

#[test]
fn each_job_starts_on_a_fresh_thread_with_its_own_thread_locals() {
    let items: Vec<usize> = (0..most() * 3).collect();
    let reused = bounded(&items, |_| USED.with(|u| u.replace(true)));
    assert_eq!(reused, alloc::vec![false; items.len()]);
}
