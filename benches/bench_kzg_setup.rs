use std::time::Duration;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rust_kzg_bn254::kzg::Kzg;

fn bench_kzg_setup(c: &mut Criterion) {
    c.bench_function("bench_kzg_setup", |b| {
        b.iter(|| {
            Kzg::setup(
                "src/test-files/g1.point", 
                "src/test-files/g2.point",
                "src/test-files/g2.point.powerOf2",
                black_box(3000),
                black_box(3000)
            ).unwrap()
        });
    });
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(5))  // Warm-up time
        .measurement_time(Duration::from_secs(10))  // Measurement time
        .sample_size(10)  // Number of samples to take
}


criterion_group!(
    name = benches;
    config = criterion_config();
    targets = bench_kzg_setup
);
criterion_main!(benches);