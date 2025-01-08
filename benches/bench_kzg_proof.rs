use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;
use rust_kzg_bn254::{blob::Blob, kzg::KZG};
use std::time::Duration;

fn bench_kzg_proof(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let mut kzg = KZG::setup(
        "tests/test-files/mainnet-data/g1.131072.point",
        "",
        "tests/test-files/mainnet-data/g2.point.powerOf2",
        268435456,
        131072,
    )
    .unwrap();

    c.bench_function("bench_kzg_proof_10000", |b| {
        let random_blob: Vec<u8> = (0..10000).map(|_| rng.gen_range(32..=126) as u8).collect();
        let input = Blob::from_raw_data(&random_blob);
        let input_poly = input.to_polynomial_eval_form();
        kzg.data_setup_custom(1, input.len().try_into().unwrap())
            .unwrap();
        let index =
            rand::thread_rng().gen_range(0..input_poly.len_underlying_blob_field_elements());
        b.iter(|| {
            kzg.compute_kzg_proof_with_known_z_fr_index(&input_poly, index.try_into().unwrap())
                .unwrap()
        });
    });

    c.bench_function("bench_kzg_proof_30000", |b| {
        let random_blob: Vec<u8> = (0..30000).map(|_| rng.gen_range(32..=126) as u8).collect();
        let input = Blob::from_raw_data(&random_blob);
        let input_poly = input.to_polynomial_eval_form();
        kzg.data_setup_custom(1, input.len().try_into().unwrap())
            .unwrap();
        let index =
            rand::thread_rng().gen_range(0..input_poly.len_underlying_blob_field_elements());
        b.iter(|| {
            kzg.compute_kzg_proof_with_known_z_fr_index(&input_poly, index.try_into().unwrap())
                .unwrap()
        });
    });

    c.bench_function("bench_kzg_proof_50000", |b| {
        let random_blob: Vec<u8> = (0..50000).map(|_| rng.gen_range(32..=126) as u8).collect();
        let input = Blob::from_raw_data(&random_blob);
        let input_poly = input.to_polynomial_eval_form();
        kzg.data_setup_custom(1, input.len().try_into().unwrap())
            .unwrap();
        let index =
            rand::thread_rng().gen_range(0..input_poly.len_underlying_blob_field_elements());
        b.iter(|| {
            kzg.compute_kzg_proof_with_known_z_fr_index(&input_poly, index.try_into().unwrap())
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
    targets = bench_kzg_proof
);
criterion_main!(benches);
