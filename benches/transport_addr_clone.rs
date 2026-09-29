//! Compare shared addresses with the former Vec backing, including the receive
//! constructor and a producer cloning while a consumer drops on another thread.
//! The cross-thread case includes bounded-channel overhead in both measurements;
//! it is not an isolated measurement of the atomic reference count.

use std::hint::black_box;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Barrier, mpsc};
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fips::TransportAddr;

const ADDRESS_BYTES: [usize; 3] = [6, 18, 58];

fn former_from_socket_addr(addr: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(56);
    write!(&mut buf, "{addr}").expect("Vec<u8>::write_fmt is infallible");
    buf
}

fn bench_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("transport_addr_clone");
    for len in ADDRESS_BYTES {
        let former = vec![0x5a; len];
        let shared = TransportAddr::from_bytes(&former);
        group.bench_with_input(BenchmarkId::new("former_vec", len), &former, |b, addr| {
            b.iter(|| black_box(addr.clone()))
        });
        group.bench_with_input(BenchmarkId::new("shared", len), &shared, |b, addr| {
            b.iter(|| black_box(addr.clone()))
        });
    }
    group.finish();
}

fn bench_socket_addr_and_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("transport_addr_socket_and_clone");
    for (name, text) in [
        ("ipv4", "192.168.1.1:2121"),
        ("ipv6", "[2001:db8::1]:2121"),
        (
            "scoped_ipv6",
            "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535",
        ),
    ] {
        let socket: SocketAddr = text.parse().unwrap();
        group.bench_with_input(BenchmarkId::new("former_vec", name), &socket, |b, addr| {
            b.iter(|| {
                let addr = former_from_socket_addr(black_box(*addr));
                black_box((addr.clone(), addr))
            })
        });
        group.bench_with_input(BenchmarkId::new("shared", name), &socket, |b, addr| {
            b.iter(|| {
                let addr = TransportAddr::from_socket_addr(black_box(*addr));
                black_box((addr.clone(), addr))
            })
        });
    }
    group.finish();
}

fn cross_thread_clone_drop<T: Clone + Send + Sync>(addr: &T, iterations: u64) -> Duration {
    let (tx, rx) = mpsc::sync_channel::<T>(256);
    let ready = Barrier::new(2);
    std::thread::scope(|scope| {
        let consumer = scope.spawn(|| {
            ready.wait();
            for value in rx {
                drop(black_box(value));
            }
        });
        // Thread startup is outside the timed interval; completion is included.
        ready.wait();
        let start = Instant::now();
        for _ in 0..iterations {
            tx.send(black_box(addr.clone())).unwrap();
        }
        drop(tx);
        consumer.join().unwrap();
        start.elapsed()
    })
}

fn bench_cross_thread(c: &mut Criterion) {
    let mut group = c.benchmark_group("transport_addr_cross_thread");
    for len in ADDRESS_BYTES {
        let former = vec![0x5a; len];
        let shared = TransportAddr::from_bytes(&former);
        group.bench_with_input(BenchmarkId::new("former_vec", len), &former, |b, addr| {
            b.iter_custom(|iterations| cross_thread_clone_drop(addr, iterations))
        });
        group.bench_with_input(BenchmarkId::new("shared", len), &shared, |b, addr| {
            b.iter_custom(|iterations| cross_thread_clone_drop(addr, iterations))
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_clone, bench_socket_addr_and_clone, bench_cross_thread
}
criterion_main!(benches);
