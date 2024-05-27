use criterion::{criterion_group, criterion_main, Criterion};
use rust_kzg_bn254::kzg::Kzg;
use std::time::Duration;

fn bench_kzg_setup(c: &mut Criterion) {
    c.bench_function("bench_kzg_setup", |b| {
        b.iter(|| Kzg::setup(true).unwrap());

        b.iter(|| Kzg::setup(false).unwrap());
    });
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(5)) // Warm-up time
        .measurement_time(Duration::from_secs(10)) // Measurement time
        .sample_size(10) // Number of samples to take
}

criterion_group!(
    name = benches;
    config = criterion_config();
    targets = bench_kzg_setup
);
criterion_main!(benches);
