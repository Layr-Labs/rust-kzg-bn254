use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;
use rust_kzg_bn254::{blob::Blob, kzg::Kzg, polynomial::PolynomialFormat};
use std::time::Duration;

fn bench_kzg_verify(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let mut kzg = Kzg::setup(
        "tests/test-files/mainnet-data/g1.131072.point",
        "",
        "tests/test-files/mainnet-data/g2.point.powerOf2",
        268435456,
        131072,
        "".to_owned(),
    )
    .unwrap();

    c.bench_function("bench_kzg_verify_10000", |b| {
        let random_blob: Vec<u8> = (0..10000).map(|_| rng.gen_range(32..=126) as u8).collect();
        let input = Blob::from_bytes_and_pad(&random_blob);
        let input_poly = input
            .to_polynomial(PolynomialFormat::InCoefficientForm)
            .unwrap();
        kzg.data_setup_custom(1, input.len().try_into().unwrap())
            .unwrap();
        let index =
            rand::thread_rng().gen_range(0..input_poly.get_length_of_padded_blob_as_fr_vector());
        let commitment = kzg.commit(&input_poly.clone()).unwrap();
        let proof = kzg
            .compute_kzg_proof_with_roots_of_unity(&input_poly, index.try_into().unwrap())
            .unwrap();
        let value_fr = input_poly.get_at_index(index).unwrap();
        let z_fr = kzg.get_nth_root_of_unity(index).unwrap();
        b.iter(|| kzg.verify_kzg_proof(commitment, proof, *value_fr, *z_fr));
    });

    c.bench_function("bench_kzg_verify_30000", |b| {
        let random_blob: Vec<u8> = (0..30000).map(|_| rng.gen_range(32..=126) as u8).collect();
        let input = Blob::from_bytes_and_pad(&random_blob);
        let input_poly = input
            .to_polynomial(PolynomialFormat::InCoefficientForm)
            .unwrap();
        kzg.data_setup_custom(1, input.len().try_into().unwrap())
            .unwrap();
        let index =
            rand::thread_rng().gen_range(0..input_poly.get_length_of_padded_blob_as_fr_vector());
        let commitment = kzg.commit(&input_poly.clone()).unwrap();
        let proof = kzg
            .compute_kzg_proof_with_roots_of_unity(&input_poly, index.try_into().unwrap())
            .unwrap();
        let value_fr = input_poly.get_at_index(index).unwrap();
        let z_fr = kzg.get_nth_root_of_unity(index).unwrap();
        b.iter(|| kzg.verify_kzg_proof(commitment, proof, *value_fr, *z_fr));
    });

    c.bench_function("bench_kzg_verify_50000", |b| {
        let random_blob: Vec<u8> = (0..50000).map(|_| rng.gen_range(32..=126) as u8).collect();
        let input = Blob::from_bytes_and_pad(&random_blob);
        let input_poly = input
            .to_polynomial(PolynomialFormat::InCoefficientForm)
            .unwrap();
        kzg.data_setup_custom(1, input.len().try_into().unwrap())
            .unwrap();
        let index =
            rand::thread_rng().gen_range(0..input_poly.get_length_of_padded_blob_as_fr_vector());
        let commitment = kzg.commit(&input_poly.clone()).unwrap();
        let proof = kzg
            .compute_kzg_proof_with_roots_of_unity(&input_poly, index.try_into().unwrap())
            .unwrap();
        let value_fr = input_poly.get_at_index(index).unwrap();
        let z_fr = kzg.get_nth_root_of_unity(index).unwrap();
        b.iter(|| kzg.verify_kzg_proof(commitment, proof, *value_fr, *z_fr));
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
    targets = bench_kzg_verify
);
criterion_main!(benches);
