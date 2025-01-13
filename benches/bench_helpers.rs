use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rust_kzg_bn254::helpers::{
    remove_empty_byte_from_padded_bytes_unchecked,
    remove_empty_byte_from_padded_bytes_unchecked_fast,
    remove_empty_byte_from_padded_bytes_unchecked_functional,
    remove_empty_byte_from_padded_bytes_unchecked_functional_fast,
};

fn create_test_data(size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| if i % 32 == 0 { 0 } else { (i % 255) as u8 + 1 })
        .collect()
}

fn bench_remove_empty_byte_from_padded_bytes(c: &mut Criterion) {
    let sizes = [32, 32_000, 32_000_000];
    for size in sizes {
        let input = create_test_data(size);
        let mut group = c.benchmark_group(format!("remove_empty_byte_{}", size));
        group.bench_function("original", |b| {
            b.iter(|| remove_empty_byte_from_padded_bytes_unchecked(black_box(&input)));
        });
        group.bench_function("fast", |b| {
            b.iter(|| remove_empty_byte_from_padded_bytes_unchecked_fast(black_box(&input)));
        });
        group.bench_function("functional", |b| {
            b.iter(|| remove_empty_byte_from_padded_bytes_unchecked_functional(black_box(&input)));
        });
        group.bench_function("functional_fast", |b| {
            b.iter(|| {
                remove_empty_byte_from_padded_bytes_unchecked_functional_fast(black_box(&input))
            });
        });
        group.finish();
    }
}

criterion_group!(benches, bench_remove_empty_byte_from_padded_bytes,);
criterion_main!(benches);
