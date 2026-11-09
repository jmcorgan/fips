//! The `fips` group lookup behind every socket bind.

use super::fips_group_id;

/// Threads looking the group up at once.
const THREADS: usize = 8;

/// Lookups each of those threads makes.
const LOOKUPS: usize = 200;

/// Lookups from many threads at once all agree with one made alone, and
/// leave the heap intact.
///
/// Every socket bind looks the group up, and a process running several nodes
/// binds from several threads at once. A lookup through libc's static
/// buffers, as `getgrnam` makes, corrupts musl's heap under this load, so on
/// musl a regression fails this test by killing the test binary (a crash in
/// `free`) rather than by an assertion. glibc locks its static buffers, so
/// there the test guards only the agreement.
#[test]
fn group_lookups_on_many_threads_at_once_agree_and_leave_the_heap_intact() {
    let alone = fips_group_id();
    let start = std::sync::Barrier::new(THREADS);
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                start.wait();
                for _ in 0..LOOKUPS {
                    assert_eq!(fips_group_id(), alone);
                }
            });
        }
    });
}
