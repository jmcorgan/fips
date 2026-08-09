//! Clone-cost comparison for transport address backing storage.
//!
//! The `Vec<u8>` case preserves the former `TransportAddr` clone operation;
//! the shared case calls the current public `TransportAddr::clone` directly.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fips::TransportAddr;

const ADDRESS_BYTES: [usize; 3] = [6, 18, 58];

fn bench_transport_addr_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("transport_addr_clone");

    for len in ADDRESS_BYTES {
        let bytes = vec![0x5a; len];
        let former_vec_backed = bytes.clone();
        let current_shared = TransportAddr::from_bytes(&bytes);

        group.bench_with_input(BenchmarkId::new("former_vec_backed", len), &len, |b, _| {
            b.iter(|| black_box(former_vec_backed.clone()))
        });
        group.bench_with_input(BenchmarkId::new("current_shared", len), &len, |b, _| {
            b.iter(|| black_box(current_shared.clone()))
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_transport_addr_clone
}
criterion_main!(benches);
