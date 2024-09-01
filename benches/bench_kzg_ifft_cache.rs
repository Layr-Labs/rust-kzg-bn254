use criterion::{criterion_group, criterion_main, Criterion};
use rust_kzg_bn254::kzg::Kzg;
use std::time::Duration;

fn bench_kzg_ifft_cache(c: &mut Criterion) {
    let kzg = Kzg::setup(
        "tests/test-files/mainnet-data/g1.32mb.point",
        "",
        "tests/test-files/mainnet-data/g2.point.powerOf2",
        268435456,
        524288,
        "/tmp".to_owned(),
    )
    .unwrap();

    c.bench_function("bench_kzg_ifft_cache", |b| {
        b.iter(|| kzg.initialize_cache(true).unwrap());
    });
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(5))  // Warm-up time
        .measurement_time(Duration::from_secs(70))  // Measurement time
        .sample_size(10) // Number of samples to take
}

criterion_group!(
    name = benches;
    config = criterion_config();
    targets = bench_kzg_ifft_cache
);
criterion_main!(benches);
