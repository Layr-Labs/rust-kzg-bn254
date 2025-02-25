use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rust_kzg_bn254_prover::{kzg::KZG, srs::SRS};
use std::time::Duration;

fn generate_powers_of_2(limit: u64) -> Vec<usize> {
    let mut powers_of_2 = Vec::new();
    let mut value: usize = 1;

    while value <= limit.try_into().unwrap() {
        powers_of_2.push(value);
        value *= 2;
    }

    powers_of_2
}

fn bench_g1_ifft(c: &mut Criterion) {
    c.bench_function("bench_g1_ifft", |b| {
        let kzg = KZG::new();
        let srs = SRS::new(
            "tests/test-files/mainnet-data/g1.131072.point",
            268435456,
            131072,
        )
        .unwrap();

        b.iter(|| {
            for power in &generate_powers_of_2(3000) {
                kzg.g1_ifft(black_box(*power), &srs).unwrap();
            }
        });
    });
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(5))  // Warm-up time
        .measurement_time(Duration::from_secs(15))  // Measurement time
        .sample_size(10) // Number of samples to take
}

criterion_group!(
    name = benches;
    config = criterion_config();
    targets = bench_g1_ifft
);
criterion_main!(benches);
