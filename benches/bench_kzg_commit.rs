use std::time::Duration;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;
use rust_kzg_bn254::{blob::Blob, kzg::Kzg};

fn bench_kzg_commit(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let mut kzg = Kzg::setup(
        "src/test-files/mainnet-data/g1.point", 
        "",
        "src/test-files/mainnet-data/g2.point.powerOf2",
        268435456,
        131072
    ).unwrap();

    c.bench_function("bench_kzg_commit_10000", |b| {
        let random_blob: Vec<u8> = (0..10000).map(|_| rng.gen_range(32..=126) as u8).collect();
        let input = Blob::from_bytes_and_pad(&random_blob);
        let input_poly = input.to_polynomial().unwrap();
        kzg.data_setup_custom(1, input.len().try_into().unwrap()).unwrap();
        b.iter(|| {
            kzg.commit(&input_poly).unwrap()
        });
    });

    c.bench_function("bench_kzg_commit_30000", |b| {
        let random_blob: Vec<u8> = (0..30000).map(|_| rng.gen_range(32..=126) as u8).collect();
        let input = Blob::from_bytes_and_pad(&random_blob);
        let input_poly = input.to_polynomial().unwrap();
        kzg.data_setup_custom(1, input.len().try_into().unwrap()).unwrap();
        b.iter(|| {
            kzg.commit(&input_poly).unwrap()
        });
    });

    c.bench_function("bench_kzg_commit_50000", |b| {
        let random_blob: Vec<u8> = (0..50000).map(|_| rng.gen_range(32..=126) as u8).collect();
        let input = Blob::from_bytes_and_pad(&random_blob);
        let input_poly = input.to_polynomial().unwrap();
        kzg.data_setup_custom(1, input.len().try_into().unwrap()).unwrap();
        b.iter(|| {
            kzg.commit(&input_poly).unwrap()
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
    targets = bench_kzg_commit
);
criterion_main!(benches);