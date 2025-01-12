use criterion::{criterion_group, criterion_main, Criterion};
use rust_kzg_bn254::kzg::KZG;
use std::time::Duration;

fn bench_kzg_setup(c: &mut Criterion) {
    c.bench_function("bench_kzg_setup", |b| {
        b.iter(|| KZG::setup("tests/test-files/g1.point", 3000, 3000).unwrap());

        b.iter(|| {
            KZG::setup(
                "tests/test-files/mainnet-data/g1.131072.point",
                268435456,
                131072,
            )
            .unwrap()
        });
    });
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(5))  // Warm-up time
        .measurement_time(Duration::from_secs(10))  // Measurement time
        .sample_size(10) // Number of samples to take
}

criterion_group!(
    name = benches;
    config = criterion_config();
    targets = bench_kzg_setup
);
criterion_main!(benches);
