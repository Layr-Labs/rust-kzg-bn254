use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;
use rust_kzg_bn254::{blob::Blob, consts::BYTES_PER_FIELD_ELEMENT, errors::KzgError, kzg::Kzg, polynomial::PolynomialFormat};
use std::time::Duration;

fn bench_kzg_commit_with_cache(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let cache_dir = "/tmp";
    let mut kzg = Kzg::setup(
        "tests/test-files/mainnet-data/g1.32mb.point",
        "",
        "tests/test-files/mainnet-data/g2.point.powerOf2",
        268435456,
        524288,
        cache_dir.to_owned(),
    )
    .unwrap();
    kzg.initialize_cache(false).unwrap();

    c.bench_function("bench_kzg_commit_with_cache_8mb", |b| {
        let random_blob: Vec<u8> = (0..8000000)
            .map(|_| rng.gen_range(32..=126) as u8)
            .collect();
        let input = Blob::from_bytes_and_pad(&random_blob);
        let input_poly = input
            .to_polynomial(PolynomialFormat::InCoefficientForm)
            .unwrap();
        
        b.iter(|| Kzg::commit_with_cache(&input_poly, cache_dir).unwrap());
    });

    c.bench_function("bench_kzg_commit_with_cache_16mb", |b| {
        let random_blob: Vec<u8> = (0..16000000)
            .map(|_| rng.gen_range(32..=126) as u8)
            .collect();
        let input = Blob::from_bytes_and_pad(&random_blob);
        let input_poly = input
            .to_polynomial(PolynomialFormat::InCoefficientForm)
            .unwrap();
        
        b.iter(|| Kzg::commit_with_cache(&input_poly, cache_dir).unwrap());
    });
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(5))  // Warm-up time
        .measurement_time(Duration::from_secs(25))  // Measurement time
        .sample_size(10) // Number of samples to take
}

criterion_group!(
    name = benches;
    config = criterion_config();
    targets = bench_kzg_commit_with_cache
);
criterion_main!(benches);
