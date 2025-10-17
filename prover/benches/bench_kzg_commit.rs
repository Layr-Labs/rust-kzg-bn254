use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;
use rust_kzg_bn254_primitives::blob::Blob;
use rust_kzg_bn254_prover::{kzg::KZG, srs::SRS};
use std::time::Duration;

fn bench_kzg_commit(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let mut kzg = KZG::new();
    let srs = SRS::new(
        "tests/test-files/mainnet-data/g1.32mb.point",
        268435456,
        524288,
    )
    .unwrap();

    c.bench_function("bench_kzg_commit_10000", |b| {
        let random_blob: Vec<u8> = (0..10000).map(|_| rng.gen_range(32..=126) as u8).collect();
        let input = Blob::from_raw_data(&random_blob);
        let input_poly = input.to_polynomial_coeff_form().unwrap();
        kzg.calculate_and_store_roots_of_unity(input.len().try_into().unwrap())
            .unwrap();
        b.iter(|| kzg.commit_coeff_form(&input_poly, &srs).unwrap());
    });

    c.bench_function("bench_kzg_commit_30000", |b| {
        let random_blob: Vec<u8> = (0..30000).map(|_| rng.gen_range(32..=126) as u8).collect();
        let input = Blob::from_raw_data(&random_blob);
        let input_poly = input.to_polynomial_coeff_form().unwrap();
        kzg.calculate_and_store_roots_of_unity(input.len().try_into().unwrap())
            .unwrap();
        b.iter(|| kzg.commit_coeff_form(&input_poly, &srs).unwrap());
    });

    c.bench_function("bench_kzg_commit_50000", |b| {
        let random_blob: Vec<u8> = (0..50000).map(|_| rng.gen_range(32..=126) as u8).collect();
        let input = Blob::from_raw_data(&random_blob);
        let input_poly = input.to_polynomial_coeff_form().unwrap();
        kzg.calculate_and_store_roots_of_unity(input.len().try_into().unwrap())
            .unwrap();
        b.iter(|| kzg.commit_coeff_form(&input_poly, &srs).unwrap());
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
    targets = bench_kzg_commit
);
criterion_main!(benches);
